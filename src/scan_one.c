#include "ft_nmap.h"
#include "network.h"
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

/**
 * @brief scan_one - Scans a single port with a single scan type.
 * Sends the forged probe, captures the reply with pcap, and interprets it.
 * For SYN: SYN/ACK -> open, RST -> closed, no reply -> filtered.
 * Returns the resulting port state.
 */
t_state scan_one(t_net *net, struct in_addr target, uint16_t port, uint8_t flags) {
    char                buffer[PACKET_SIZE];
    struct pcap_pkthdr  *header;
    const u_char        *packet;
    int                 ret;
    time_t              start;

    // 1. forge and send the probe (capture is already listening via the filter)
    forge_packet(buffer, net->src_ip, target, port, flags);
    if (send_packet(net->sock, buffer, target, port) == -1)
        return (STATE_UNKNOWN);

    // 2. capture loop with a timeout: wait for a reply to THIS port
    start = time(NULL);
    while (time(NULL) - start < SCAN_TIMEOUT) {
        ret = pcap_next_ex(net->handle, &header, &packet);

        if (ret == 1) {     // a packet matched the filter
            // locate the TCP header inside the captured frame
            struct tcp_hdr *tcp = get_tcp_header(net, packet, header->caplen);
            if (!tcp)
                continue;

            // is this the reply to the port we just probed?
            if (ntohs(tcp->source) != port)
                continue;   // reply for another port, keep waiting

            // interpret the TCP flags (SYN scan logic)
            if ((tcp->flags & TH_SYN) && (tcp->flags & TH_ACK))
                return (STATE_OPEN);        // SYN/ACK -> open
            if (tcp->flags & TH_RST)
                return (STATE_CLOSED);      // RST -> closed
        }
        // ret == 0 -> timeout on this read, loop again until SCAN_TIMEOUT
    }

    // 3. no reply within the timeout -> filtered
    return (STATE_FILTERED);
}
