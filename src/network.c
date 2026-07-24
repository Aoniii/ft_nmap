#include "network.h"
#include "ft_nmap.h"
#include <errno.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <ifaddrs.h>

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
 * @brief iface_for_source - Interface name whose IPv4 address equals src.
 * Returns 0 and fills out on success, -1 if no interface carries that address.
 */
static int  iface_for_source(struct in_addr src, char *out, size_t outlen) {
    struct ifaddrs  *ifap;
    struct ifaddrs  *ifa;

    if (getifaddrs(&ifap) == -1)
        return (-1);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
            continue ;
        if (((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr == src.s_addr) {
            strncpy(out, ifa->ifa_name, outlen - 1);
            out[outlen - 1] = 0;
            freeifaddrs(ifap);
            return (0);
        }
    }
    freeifaddrs(ifap);
    return (-1);
}

/**
 * @brief set_device_for_source - Points net->device at the interface that
 * actually routes to a target (matched via its source IP), instead of the
 * first device pcap happened to list. Best effort: on no match, the current
 * device is kept as fallback.
 */
void    set_device_for_source(t_net *net, struct in_addr src) {
    char    ifname[64];
    char    *dev;

    if (iface_for_source(src, ifname, sizeof(ifname)) != 0)
        return ;
    dev = strdup(ifname);
    if (!dev)
        return ;
    free(net->device);
    net->device = dev;
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

/**
 * @brief setup_network - Sets up the shared network resources for the scan.
 * Creates the raw TCP socket (requires root), enables IP_HDRINCL so we provide
 * our own IP header, and finds the default capture interface. The pcap handle
 * itself is opened later, per target, since the interface may differ.
 */
int setup_network(t_net *net, t_config *cfg) {
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
    net->ttl = cfg->ttl;

    return (0);
}

/**
 * @brief cleanup_network - Releases all network resources.
 * Closes the pcap handle and the raw socket, frees the device name, and resets
 * the fields so a second call is safe (no double free / double close).
 */
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
