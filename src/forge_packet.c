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
    ip->version     = 4;                                // IPv4 (the only version we handle)
    ip->ihl         = 5;                                // 5 words = 20 bytes, header without options
    ip->tos         = 0;                                // no special priority/handling requested
    ip->tot_len     = htons(PACKET_SIZE);               // total size
    ip->id          = htons(0);                         // no fragmentation
    ip->frag_off    = 0;                                // not fragmenting, no offset
    ip->ttl         = 64;                               // standard hop limit; high enough to reach any host
    ip->protocol    = 6;                                // TCP
    ip->check       = 0;                                // kernel fills it (IP_HDRINCL)
    ip->saddr       = src.s_addr;                       // our IP, so the reply knows where to come back
    ip->daddr       = dest.s_addr;                      // the target, used to routing

    // ---- TCP header ----
    tcp->source     = htons(SRC_PORT);                  // our port; replies come back here
    tcp->dest       = htons(port);                      // the scanned port
    tcp->seq        = htonl(0);                         // initial sequence
    tcp->ack_seq    = 0;                                // no acknowledgment
    tcp->doff       = 5;                                // 5 words = 20 bytes, TCP header without options
    tcp->reserved   = 0;                                // reserved bits must be 0
    tcp->flags      = flags;                            // the scan type
    tcp->window     = htons(1024);                      // advertised window; any plausible value works for a probe
    tcp->check      = 0;                                // must be 0 while computing the checksum
    tcp->urg_ptr    = 0;                                // no urgent data

    // ---- TCP checksum over pseudo-header + TCP header ----
    pseudo.saddr    = src.s_addr;                       // pseudo-header ties the checksum to the real IPs...
    pseudo.daddr    = dest.s_addr;                      // ...so a misrouted packet is detected and rejected
    pseudo.zero     = 0;                                // mandatory padding byte
    pseudo.protocol = 6;                                // TCP, must be match IP protocol field
    pseudo.tcp_len  = htons(sizeof(struct tcp_hdr));    // length coverred by the checksum

    memcpy(pseudo_buf, &pseudo, sizeof(pseudo));
    memcpy(pseudo_buf + sizeof(pseudo), tcp, sizeof(struct tcp_hdr));
    tcp->check = checksum(pseudo_buf, sizeof(pseudo_buf));
}

/**
 * @brief forge_udp_packet - Builds an IP+UDP packet into buffer.
 * UDP checksum is optional in IPv4 so we leave it at 0. The IP checksum is
 * filled by the kernel (IP_HDRINCL).
 */
void forge_udp_packet(char *buffer, struct in_addr src, struct in_addr dest, uint16_t port) {
    struct ip_hdr  *ip = (struct ip_hdr *)buffer;
    struct udp_hdr *udp = (struct udp_hdr *)(buffer + sizeof(struct ip_hdr));

    memset(buffer, 0, UDP_PACKET_SIZE);
    ip->version  = 4;                               // IPv4
    ip->ihl      = 5;                               // 5 words = 20 bytes header with no options
    ip->tot_len  = htons(UDP_PACKET_SIZE);          // IP + UDP total size
    ip->ttl      = 64;                              // standard hop limit
    ip->protocol = 17;                              // UDP
    ip->saddr    = src.s_addr;                      // our IP
    ip->daddr    = dest.s_addr;                     // the target

    udp->source = htons(SRC_PORT);                  // our port
    udp->dest   = htons(port);                      // the port we are probing
    udp->len    = htons(sizeof(struct udp_hdr));    // header only, no payload
    udp->check  = 0;                                // optional in IPv4
}
