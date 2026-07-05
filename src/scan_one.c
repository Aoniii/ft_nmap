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
    time_t              start;
    t_state             st;

    // 1. forge and send the probe (capture is already listening via the filter)
    flags = scan_type_to_flags(scan_type);
    forge_packet(buffer, net->src_ip, target, port, flags);
    if (send_packet(net->sock, buffer, target, port) == -1)
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
        if (ntohs(tcp->source) != port)
            continue ;   // reply for another port, keep waiting

        st = interpret_tcp(scan_type, tcp);
        if (st != STATE_UNKNOWN)
            return (st);
        // an unexpected reply: keep listening (could be noise)
    }

    // no conclusive reply within the timeout
    return (no_reply_state(scan_type));
}
