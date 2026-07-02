# include "network.h"
# include <netinet/in.h>
# include <string.h>

/**
 * @brief forge_packet - Builds a full IP+TCP packet into buffer.
 * Fills the IP and TCP headers, then computes the TCP checksum over a
 * temporary pseudo-header + the TCP header. The IP checksum is left at 0
 * (the kernel fills it thanks to IP_HDRINCL).
 */
void    forge_packet(char *buffer, struct in_addr src, struct in_addr dest, uint16_t port, uint8_t flags) {
    struct ip_hdr       *ip = (struct ip_hdr *)buffer;
    struct tcp_hdr      *tcp = (struct tcp_hdr *)(buffer + sizeof(struct ip_hdr));
    struct pseudo_hdr   pseudo;
    char                pseudo_buf[sizeof(struct pseudo_hdr) + sizeof(struct tcp_hdr)];

    memset(buffer, 0, PACKET_SIZE);

    // ---- IP header ----
    ip->version     = 4;
    ip->ihl         = 5;
    ip->tos         = 0;
    ip->tot_len     = htons(PACKET_SIZE);
    ip->id          = htons(0);
    ip->frag_off    = 0;
    ip->ttl         = 64;
    ip->protocol    = 6;               // TCP
    ip->check       = 0;               // kernel fills it (IP_HDRINCL)
    ip->saddr       = src.s_addr;      // already network byte order
    ip->daddr       = dest.s_addr;

    // ---- TCP header ----
    tcp->source     = htons(SRC_PORT);
    tcp->dest       = htons(port);     // the scanned port
    tcp->seq        = htonl(0);
    tcp->ack_seq    = 0;
    tcp->doff       = 5;
    tcp->reserved   = 0;
    tcp->flags      = flags;           // the scan type
    tcp->window     = htons(1024);
    tcp->check      = 0;               // must be 0 while computing the checksum
    tcp->urg_ptr    = 0;

    // ---- TCP checksum over pseudo-header + TCP header ----
    pseudo.saddr    = src.s_addr;
    pseudo.daddr    = dest.s_addr;
    pseudo.zero     = 0;
    pseudo.protocol = 6;
    pseudo.tcp_len  = htons(sizeof(struct tcp_hdr));

    memcpy(pseudo_buf, &pseudo, sizeof(pseudo));
    memcpy(pseudo_buf + sizeof(pseudo), tcp, sizeof(struct tcp_hdr));
    tcp->check = checksum(pseudo_buf, sizeof(pseudo_buf));
}
