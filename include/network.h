#ifndef NETWORK_H
# define NETWORK_H

# include <netinet/in.h>
# include <stddef.h>
# include <stdint.h>
# include <pcap.h>

typedef enum e_state    t_state;

typedef struct      s_net {
    int             sock;           // raw socket
    struct in_addr  src_ip;         // local source IP
    pcap_t          *handle;        // pcap capture handle (reopened per target)
    char            *device;        // default interface name (for non-loopback targets)
    int             link_hdr_len;   // datalink header size (14 Ethernet, 4 loopback, 16 cooked...)
}                   t_net;

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
    uint8_t     ihl:4;      // header length in 32-bit words (5 = 20 bytes)
    uint8_t     version:4;  // IP version (4 = IPv4)
    uint8_t     tos;        // type of service (0, no special handling)
    uint16_t    tot_len;    // total packet length: IP + payload
    uint16_t    id;         // packet identifier (used for fragment reassembly)
    uint16_t    frag_off;   // fragment offset + flags (0, no fragmentation)
    uint8_t     ttl;        // time to live: max hops before the packet dies (default: 64)
    uint8_t     protocol;   // next protocol: 6 = TCP, 17 = UDP, 1 = ICMP
    uint16_t    check;      // checksum
    uint32_t    saddr;      // source IP address
    uint32_t    daddr;      // destination IP address
} __attribute__((packed));

/*
 * TCP header (20 bytes).
 * packed for the same reason: exact match of the wire format.
 */
struct          tcp_hdr {
    uint16_t    source;         // source port (local SRC_PORT)
    uint16_t    dest;           // destination port (the port being scanned)
    uint32_t    seq;            // sequence number
    uint32_t    ack_seq;        // acknowledgment number (0, no ACK)
    /* reserved and doff share one byte (4 bits each).
       Same little-endian rule: reserved (low-order) declared before doff. */
    uint8_t     reserved:4;     // reserved bits (must be 0)
    uint8_t     doff:4;         // data offset: TCP header length in 32-bit words (5 = 20 bits)
    /* all flags in ONE byte: lets us forge any scan by assigning a mask
       (TH_SYN, TH_FIN|TH_PSH|TH_URG, ...) instead of separate bitfields.
       This is what makes the forge generic. */
    uint8_t     flags;          // TCP flags (FIN/SYN/RST/PSH/ACK/URG), set per scan type
    uint16_t    window;         // advertised window size
    uint16_t    check;          // TCP checksum
    uint16_t    urg_ptr;        // urgent pointer (0, unused)
} __attribute__((packed));

/*
 * Pseudo-header (12 bytes).
 * Exists ONLY to compute the TCP checksum: we build it in memory, checksum
 * over (pseudo-header + TCP header), then discard it. It NEVER goes on the
 * wire. Including it in the checksum guarantees the packet reached the right
 * IP/protocol.
 */
struct          pseudo_hdr {
    uint32_t    saddr;      // source IP
    uint32_t    daddr;      // destination IP
    uint8_t     zero;       // padding byte, always 0 (spec-mandated)
    uint8_t     protocol;   // transport protocol (6 = TCP)
    uint16_t    tcp_len;    // length of the TCP header (+ data if any)
} __attribute__((packed));

/* UDP header (8 bytes) */
struct          udp_hdr {
    uint16_t    source;     /* source port */
    uint16_t    dest;       /* destination port (the scanned port) */
    uint16_t    len;        /* length: UDP header + data */
    uint16_t    check;      /* checksum (optional for IPv4, can be 0) */
} __attribute__((packed));

/* ICMP header (8 bytes) - only need the first fields to read type/code */
struct          icmp_hdr {
    uint8_t     type;       /* 3 = destination unreachable */
    uint8_t     code;       /* 3 = port unreachable */
    uint16_t    check;      /* checksum */
    uint32_t    rest;       /* unused */
} __attribute__((packed));

/* TCP flag masks: one bit per flag, combined with OR for the scans */
# define TH_FIN  0x01
# define TH_SYN  0x02
# define TH_RST  0x04
# define TH_PSH  0x08
# define TH_ACK  0x10
# define TH_URG  0x20

# define PACKET_SIZE        (sizeof(struct ip_hdr) + sizeof(struct tcp_hdr))
# define UDP_PACKET_SIZE    (sizeof(struct ip_hdr) + sizeof(struct udp_hdr))
# define SRC_PORT           49152       // port source local (éphémère)
# define SCAN_TIMEOUT       2           // seconds to wait for a reply before "filtered"
# define UDP_TIMEOUT        5           // UDP needs longer: ICMP replies are rate-limited
# define UDP_RETY           5           // retransmit to beat ICMP rate-limiting

/* checksum.c */
uint16_t    checksum(const void *data, size_t len);

/* forge_packet.c */
void    forge_packet(char *buffer, struct in_addr src, struct in_addr dest, uint16_t src_port, uint16_t port, uint8_t flags);
void    forge_udp_packet(char *buffer, struct in_addr src, struct in_addr dest, uint16_t port);

/* get_link_hdr_len.c */
int get_link_hdr_len(pcap_t *handle);

/* get_source_ip.c */
int get_source_ip(struct in_addr target, struct in_addr *out);

/* get_tcp_header.c */
struct tcp_hdr  *get_tcp_header(t_net *net, const u_char *packet, int caplen);

/* network.c */
int         open_pcap(t_net *net, const char *iface);
const char  *iface_for_target(t_net *net, struct in_addr target);
int         find_default_device(t_net *net);
int         setup_network(t_net *net);
void        cleanup_network(t_net *net);

/* scan_one.c */
t_state scan_one(t_net *net, struct in_addr target, uint16_t port, int scan_type);
t_state scan_one_udp(t_net *net, struct in_addr target, uint16_t port);

/* scan_type_to_flags.c */
uint8_t scan_type_to_flags(int scan_type);

/* send_packet.c */
int send_packet(int sock, char *buffer, size_t size, struct in_addr dest, uint16_t port);

/* set_filter.c */
int set_filter(t_net *net, struct in_addr target);

#endif
