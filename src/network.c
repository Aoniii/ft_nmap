#include "network.h"
#include <errno.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/**
 * @brief open_pcap - Opens (or reopens) the pcap handle on a given interface.
 * Closes any previous handle first. Sets the link header length and applies
 * non-blocking mode so captures don't hang on silent ports.
 */
int open_pcap(t_net *net, const char *iface) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // close a previous handle if we're switching interface
    if (net->handle) {
        pcap_close(net->handle);
        net->handle = NULL;
    }

    net->handle = pcap_open_live(iface, 65535, 0, 100, errbuf);
    if (net->handle == NULL) {
        fprintf(stderr, "ft_nmap: error: pcap_open_live(%s): %s\n", iface, errbuf);
        return (-1);
    }

    // determine the datalink header length for THIS interface
    net->link_hdr_len = get_link_hdr_len(net->handle);
    if (net->link_hdr_len == -1) {
        fprintf(stderr, "ft_nmap: error: unsupported datalink type\n");
        pcap_close(net->handle);
        net->handle = NULL;
        return (-1);
    }

    // non-blocking: pcap_next_ex returns 0 instead of hanging on silence
    if (pcap_setnonblock(net->handle, 1, errbuf) == -1) {
        fprintf(stderr, "ft_nmap: error: pcap_setnonblock: %s\n", errbuf);
        pcap_close(net->handle);
        net->handle = NULL;
        return (-1);
    }

    return (0);
}

/**
 * @brief iface_for_target - Returns the interface to capture on for a target.
 * Loopback targets (127.0.0.0/8) need "lo"; everything else uses the default.
 */
const char  *iface_for_target(t_net *net, struct in_addr target) {
    // 127.x.x.x -> loopback
    if ((ntohl(target.s_addr) & 0xFF000000) == 0x7F000000)
        return ("lo");
    return (net->device);
}

/**
 * @brief find_default_device - Finds the default capture interface name.
 * Stores it in net->device (used for non-loopback targets).
 */
int find_default_device(t_net *net) {
    char        errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t   *alldevs;

    if (pcap_findalldevs(&alldevs, errbuf) == -1 || alldevs == NULL) {
        fprintf(stderr, "ft_nmap: error: no capture device found\n");
        return (-1);
    }
    net->device = strdup(alldevs->name);
    pcap_freealldevs(alldevs);
    if (net->device == NULL) {
        fprintf(stderr, "ft_nmap: error: memory allocation failed\n");
        return (-1);
    }
    return (0);
}

int setup_network(t_net *net) {
    int on = 1;

    net->handle = NULL;
    net->device = NULL;
    net->sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (net->sock < 0) {
        if (errno == EPERM || errno == EACCES)
            fprintf(stderr, "ft_nmap: error: root privileges required (raw socket)\n");
        else
            fprintf(stderr, "ft_nmap: error: socket: %s\n", strerror(errno));
        return (-1);
    }

    if (setsockopt(net->sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        fprintf(stderr, "ft_nmap: error: setsockopt IP_HDRINCL: %s\n", strerror(errno));
        close(net->sock);
        return (-1);
    }

    if (find_default_device(net) == -1) {
        close(net->sock);
        return (-1);
    }

    return (0);
}

void cleanup_network(t_net *net) {
    if (net->handle)
        pcap_close(net->handle);
    if (net->sock >= 0)
        close(net->sock);
    free(net->device);
    net->sock = -1;
    net->handle = NULL;
    net->device = NULL;
}
