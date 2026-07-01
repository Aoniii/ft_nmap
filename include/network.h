#ifndef NETWORK_H
# define NETWORK_H

# include <stddef.h>
# include <stdint.h>

typedef struct  s_net {
    int         sock;
}               t_net;

/*
 * IP header (20 bytes).
 * __attribute__((packed)) forbids the compiler from adding padding between
 * fields. Without it the struct wouldn't map the exact binary packet layout
 * (sizeof must be exactly 20).
 */
struct          ip_hdr {
    /* version and ihl share the first byte (4 bits each).
       On little-endian (x86), the low-order field is declared FIRST:
       ihl before version, otherwise the two would be swapped in the
       actual byte. */
    uint8_t     ihl:4;
    uint8_t     version:4;
    uint8_t     tos;
    uint16_t    tot_len;
    uint16_t    id;
    uint16_t    frag_off;
    uint8_t     ttl;
    uint8_t     protocol;
    uint16_t    check;
    uint32_t    saddr;
    uint32_t    daddr;
} __attribute__((packed));

/*
 * TCP header (20 bytes).
 * packed for the same reason: exact match of the wire format.
 */
struct          tcp_hdr {
    uint16_t    source;
    uint16_t    dest;
    uint32_t    seq;
    uint32_t    ack_seq;
    /* reserved and doff share one byte (4 bits each).
       Same little-endian rule: reserved (low-order) declared before doff. */
    uint8_t     reserved:4;
    uint8_t     doff:4;
    /* all flags in ONE byte: lets us forge any scan by assigning a mask
       (TH_SYN, TH_FIN|TH_PSH|TH_URG, ...) instead of separate bitfields.
       This is what makes the forge generic. */
    uint8_t     flags;
    uint16_t    window;
    uint16_t    check;
    uint16_t    urg_ptr;
} __attribute__((packed));

/*
 * Pseudo-header (12 bytes).
 * Exists ONLY to compute the TCP checksum: we build it in memory, checksum
 * over (pseudo-header + TCP header), then discard it. It NEVER goes on the
 * wire. Including it in the checksum guarantees the packet reached the right
 * IP/protocol.
 */
struct          pseudo_hdr {
    uint32_t    saddr;
    uint32_t    daddr;
    uint8_t     zero;
    uint8_t     protocol;
    uint16_t    tcp_len;
} __attribute__((packed));

/* TCP flag masks: one bit per flag, combined with OR for the scans */
# define TH_FIN  0x01
# define TH_SYN  0x02
# define TH_RST  0x04
# define TH_PSH  0x08
# define TH_ACK  0x10
# define TH_URG  0x20

int         setup_network(t_net *net);
void        cleanup_network(t_net *net);
uint16_t    checksum(const void *data, size_t len);

#endif
