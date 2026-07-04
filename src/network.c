#include "network.h"
#include <errno.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int setup_network(t_net *net) {
    int on;

    on = 1;
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

    if (setup_pcap(net) == -1) {
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
