#include "network.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <sys/socket.h>

/**
 * @brief set_filter - Applies a BPF filter to capture only responses to our
 * probes: TCP packets coming from the target, destined to our source port.
 * Must be called before sending, so the capture is ready when replies arrive.
 */
int set_filter(t_net *net, struct in_addr target) {
    struct bpf_program  fp;
    char                filter[256];
    char                ip[INET_ADDRSTRLEN];

    // build the filter expression for this target
    inet_ntop(AF_INET, &target, ip, sizeof(ip));
    snprintf(filter, sizeof(filter), "(tcp and src host %s and dst port %d) or (udp and src host %s and dst port %d) or (icmp and src host %s)", ip, SRC_PORT, ip, SRC_PORT, ip);

    // compile the text expression into a BPF program
    if (pcap_compile(net->handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "ft_nmap: error: pcap_compile: %s\n", pcap_geterr(net->handle));
        return (-1);
    }

    // apply the compiled filter to the capture handle
    if (pcap_setfilter(net->handle, &fp) == -1) {
        fprintf(stderr, "ft_nmap: error: pcap_setfilter: %s\n", pcap_geterr(net->handle));
        pcap_freecode(&fp);
        return (-1);
    }

    pcap_freecode(&fp);
    return (0);
}
