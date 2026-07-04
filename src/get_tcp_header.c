#include "network.h"

/**
 * @brief get_tcp_header - Locates the TCP header inside a captured frame.
 * Skips the link-layer header (size known from the handle) and the IP header
 * (variable length via ihl) to reach the TCP part. Returns NULL if the frame
 * is too short or isn't TCP.
 */
struct tcp_hdr  *get_tcp_header(t_net *net, const u_char *packet, int caplen) {
    struct ip_hdr   *ip;
    int              ip_hdr_len;
    int              offset;

    // enough bytes for link header + minimal IP header?
    if (caplen < net->link_hdr_len + (int)sizeof(struct ip_hdr))
        return (NULL);

    // skip the link-layer header to reach the IP header
    ip = (struct ip_hdr *)(packet + net->link_hdr_len);

    // make sure it's really TCP (protocol 6)
    if (ip->protocol != 6)
        return (NULL);

    // IP header length is variable: ihl counts 32-bit words
    ip_hdr_len = ip->ihl * 4;
    offset = net->link_hdr_len + ip_hdr_len;

    // enough bytes for the TCP header too?
    if (caplen < offset + (int)sizeof(struct tcp_hdr))
        return (NULL);

    return ((struct tcp_hdr *)(packet + offset));
}
