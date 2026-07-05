#include "network.h"
#include <pcap/pcap.h>
#include <string.h>

/**
 * @brief setup_pcap - Opens a pcap capture handle on the default interface.
 * Finds the device, opens it for live capture with a short read timeout so
 * capture calls don't block forever. Stores handle and device name in net.
 */
int setup_pcap(t_net *net) {
    char        errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t   *alldevs;

    // list all capture devices (modern replacement for pcap_lookupdev)
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "ft_nmap: error: pcap_findalldevs: %s\n", errbuf);
        return (-1);
    }
    if (!alldevs) {
        fprintf(stderr, "ft_nmap: error: no capture device found\n");
        return (-1);
    }

    net->device = strdup(alldevs->name);
    pcap_freealldevs(alldevs);
    if (!net->device) {
        fprintf(stderr, "ft_nmap: error: memory allocation failed\n");
        return (-1);
    }

    // open the device for live capture:
    //   snaplen = 65535  capture full packets
    //   promisc = 0      no promiscuous mode needed
    //   to_ms   = 100    read timeout in ms (so captures don't block forever)
    net->handle = pcap_open_live(net->device, 65535, 0, 100, errbuf);
    if (!net->handle) {
        fprintf(stderr, "ft_nmap: error: pcap_open_live: %s\n", errbuf);
        return (-1);
    }
    pcap_setnonblock(net->handle, 1, errbuf);

    net->link_hdr_len = get_link_hdr_len(net->handle);
    if (net->link_hdr_len == -1) {
        fprintf(stderr, "ft_nmap: error: unsupported datalink type\n");
        pcap_close(net->handle);
        return (-1);
    }

    return (0);
}
