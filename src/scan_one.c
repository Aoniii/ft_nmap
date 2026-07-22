#include "ft_nmap.h"
#include "network.h"
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

/**
 * @brief interpret_tcp - Maps a captured TCP reply to a port state, per scan type.
 * SYN:            SYN/ACK -> open,  RST -> closed
 * NULL/FIN/XMAS:  RST -> closed     (no reply handled by caller -> open|filtered)
 * ACK:            RST -> unfiltered (no reply -> filtered)
 */
static t_state  interpret_tcp(int scan_type, struct tcp_hdr *tcp) {
    bool has_rst = tcp->flags & TH_RST;
    bool has_syn = tcp->flags & TH_SYN;
    bool has_ack = tcp->flags & TH_ACK;

    switch (scan_type) {
        case SCAN_SYN:
            if (has_syn && has_ack)
                return (STATE_OPEN);
            if (has_rst)
                return (STATE_CLOSED);
            break;

        case SCAN_NULL:
        case SCAN_FIN:
        case SCAN_XMAS:
            // any RST means closed; an open port stays silent (handled on timeout)
            if (has_rst)
                return (STATE_CLOSED);
            break;

        case SCAN_ACK:
            // a RST coming back means the probe reached the host: unfiltered
            if (has_rst)
                return (STATE_UNFILTERED);
            break;
    }
    return (STATE_UNKNOWN);   // reply that doesn't fit -> let caller decide
}

/**
 * @brief no_reply_state - Port state when no reply arrives within the timeout,
 * which depends on the scan type.
 * SYN:            filtered
 * NULL/FIN/XMAS:  open|filtered (silence means open OR filtered, can't tell)
 * ACK:            filtered
 */
static t_state  no_reply_state(int scan_type) {
    switch (scan_type) {
        case SCAN_NULL:
        case SCAN_FIN:
        case SCAN_XMAS:
            return (STATE_OPEN_FILTERED);
        case SCAN_SYN:
        case SCAN_ACK:
        default:
            return (STATE_FILTERED);
    }
}

/**
 * @brief scan_one - Scans a single port with a single scan type.
 * Sends the forged probe, captures the reply with pcap, and interprets it.
 * For SYN: SYN/ACK -> open, RST -> closed, no reply -> filtered.
 * Returns the resulting port state.
 */
t_state scan_one(t_net *net, struct in_addr target, uint16_t port, int scan_type) {
    char                buffer[PACKET_SIZE];
    struct pcap_pkthdr  *header;
    const u_char        *packet;
    uint8_t             flags;
    uint16_t            src_port;
    time_t              start;
    t_state             st;

    // 1. forge and send the probe (capture is already listening via the filter)
    flags = scan_type_to_flags(scan_type);
    src_port = SRC_PORT + scan_type;
    forge_packet(buffer, net->src_ip, target, src_port, port, flags, net->ttl);
    if (send_packet(net->sock, buffer, PACKET_SIZE, target, port) == -1)
        return (STATE_UNKNOWN);

    // 2. capture loop with a timeout: wait for a reply to THIS port
    start = time(NULL);
    while (time(NULL) - start < SCAN_TIMEOUT) {
        if (pcap_next_ex(net->handle, &header, &packet) != 1)
            continue ;

        // locate the TCP header inside the captured frame
        struct tcp_hdr *tcp = get_tcp_header(net, packet, header->caplen);
        if (!tcp)
            continue ;

        // is this the reply to the port we just probed?
        if (ntohs(tcp->source) != port || ntohs(tcp->dest) != src_port)
            continue ;   // reply for another port, keep waiting

        st = interpret_tcp(scan_type, tcp);
        if (st != STATE_UNKNOWN)
            return (st);
        // an unexpected reply: keep listening (could be noise)
    }

    // no conclusive reply within the timeout
    return (no_reply_state(scan_type));
}

/**
 * @brief scan_one_udp - Scans a single port with a UDP probe.
 * Sends a UDP datagram and waits for a reply:
 *   - ICMP type 3 code 3 (port unreachable)    -> closed
 *   - a UDP reply                              -> open
 *   - no reply within the timeout              -> open|filtered
 */
t_state scan_one_udp(t_net *net, struct in_addr target, uint16_t port) {
    char                buffer[UDP_PACKET_SIZE];
    struct pcap_pkthdr  *header;
    const u_char        *packet;
    time_t              start;

    for (int attempt = 0; attempt < UDP_RETY; attempt++) {
        forge_udp_packet(buffer, net->src_ip, target, port, net->ttl);
        if (send_packet(net->sock, buffer, UDP_PACKET_SIZE, target, port) == -1)
            return (STATE_UNKNOWN);

        start = time(NULL);
        while (time(NULL) - start < UDP_TIMEOUT) {
            if (pcap_next_ex(net->handle, &header, &packet) != 1)
                continue ;

            int caplen = (int)header->caplen;
            if (caplen < net->link_hdr_len + (int)sizeof(struct ip_hdr))
                continue ;

            // read the IP header to know the protocol of the reply
            struct ip_hdr *ip = (struct ip_hdr *)(packet + net->link_hdr_len);
            int ip_hdr_len = ip->ihl * 4;
            if (ip_hdr_len < (int)sizeof(struct ip_hdr))
                continue ;

            if (ip->protocol == 17) {   // direct UDP reply -> open
                if (caplen < net->link_hdr_len + ip_hdr_len + (int)sizeof(struct udp_hdr))
                    continue ;

                // check it's addressed to OUR udp source port
                struct udp_hdr *udp = (struct udp_hdr *)(packet + net->link_hdr_len + ip_hdr_len);
                if (ntohs(udp->dest) != SRC_PORT + SCAN_UDP)
                    continue ;          // reply for another thread
                // and that it comes from the port we scanned
                if (ntohs(udp->source) != port)
                    continue ;
                return (STATE_OPEN);
            } else if (ip->protocol == 1) {     // ICMP
                if (caplen < net->link_hdr_len + ip_hdr_len + (int)sizeof(struct icmp_hdr))
                    continue ;

                struct icmp_hdr *icmp = (struct icmp_hdr *)(packet + net->link_hdr_len + ip_hdr_len);
                if (caplen < net->link_hdr_len + ip_hdr_len + (int)sizeof(struct icmp_hdr) + (int)sizeof(struct ip_hdr))
                    continue ;

                struct ip_hdr   *orig_ip = (struct ip_hdr *)(packet + net->link_hdr_len + ip_hdr_len + sizeof(struct icmp_hdr));
                int             orig_ip_len = orig_ip->ihl * 4;

                if (orig_ip_len < (int)sizeof(struct ip_hdr))
                    continue ;
                if (caplen < net->link_hdr_len + ip_hdr_len + (int)sizeof(struct icmp_hdr) + orig_ip_len + (int)sizeof(struct udp_hdr))
                    continue ;

                struct udp_hdr  *orig_udp = (struct udp_hdr *)((char *)orig_ip + orig_ip_len);

                // is this ICMP about OUR probe? (copied UDP dest = the port we scanned)
                if (ntohs(orig_udp->dest) != port)
                    continue ;  // ICMP for another port, keep listening

                // type 3 = destination unreachable, code 3 = port unreachable
                if (icmp->type == 3 && icmp->code == 3)
                    return (STATE_CLOSED);

                // other ICMP unreachable codes (1,2,9,10,13) -> filtered
                if (icmp->type == 3)
                    return (STATE_FILTERED);
            }
        }
    }

    // no reply -> can't tell open from filtered
    return (STATE_OPEN_FILTERED);
}
