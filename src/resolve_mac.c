#include "network.h"
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

/**
 * @brief get_if_mac - Reads the hardware (MAC) address of an interface.
 * Uses a throwaway socket + ioctl(SIOCGIFHWADDR); the socket family/type
 * doesn't matter, ioctl only needs a valid fd. Fills mac[6], returns 0 / -1.
 */
int get_if_mac(const char *iface, uint8_t mac[6]) {
    struct ifreq    ifr;
    int             fd;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return (-1);

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return (-1);
    }
    close(fd);

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return (0);
}

/**
 * @brief get_gateway_ip - Finds the default gateway (next hop) IPv4 address.
 * Parses /proc/net/route: the line whose Destination is 00000000 is the
 * default route, and its Gateway field is the next-hop IP in hex. The kernel
 * prints it little-endian, so the parsed value maps directly onto s_addr
 * (network byte order) on a little-endian host. Returns 0 / -1.
 */
static int  get_gateway_ip(struct in_addr *out) {
    FILE            *f;
    char            line[256];
    char            iface[64];
    unsigned long   dest;
    unsigned long   gw;

    f = fopen("/proc/net/route", "r");
    if (!f)
        return (-1);

    // skip the header line
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return (-1);
    }

    while (fgets(line, sizeof(line), f)) {
        // Iface  Destination  Gateway  Flags ...
        if (sscanf(line, "%63s %lx %lx", iface, &dest, &gw) != 3)
            continue ;
        if (dest == 0) {                    // default route
            out->s_addr = (uint32_t)gw;     // already network byte order (LE host)
            fclose(f);
            return (0);
        }
    }

    fclose(f);
    return (-1);
}

/**
 * @brief parse_hw - Parses "aa:bb:cc:dd:ee:ff" into mac[6]. Returns 0 / -1.
 */
static int  parse_hw(const char *s, uint8_t mac[6]) {
    if (sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6)
        return (-1);
    return (0);
}

/**
 * @brief get_mac_for_ip - Looks up the MAC of an IPv4 address in the kernel
 * ARP cache (/proc/net/arp). Skips incomplete entries (Flags 0x0). The cache
 * is normally already populated for the gateway thanks to active traffic.
 * Returns 0 / -1.
 */
static int  get_mac_for_ip(struct in_addr ip, uint8_t mac[6]) {
    FILE    *f;
    char    line[256];
    char    ipstr[64];
    char    hwtype[16];
    char    flags[16];
    char    hwaddr[64];
    char    want[INET_ADDRSTRLEN];

    if (!inet_ntop(AF_INET, &ip, want, sizeof(want)))
        return (-1);

    f = fopen("/proc/net/arp", "r");
    if (!f)
        return (-1);

    // skip the header line
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return (-1);
    }

    while (fgets(line, sizeof(line), f)) {
        // IP address  HW type  Flags  HW address  Mask  Device
        if (sscanf(line, "%63s %15s %15s %63s", ipstr, hwtype, flags, hwaddr) != 4)
            continue ;
        if (strcmp(flags, "0x0") == 0)      // incomplete entry, no MAC yet
            continue ;
        if (strcmp(ipstr, want) == 0) {
            fclose(f);
            return (parse_hw(hwaddr, mac));
        }
    }

    fclose(f);
    return (-1);
}

/**
 * @brief get_gateway_mac - Resolves the next-hop (default gateway) MAC address.
 * Combines the default route lookup and the ARP cache lookup. Fills mac[6],
 * returns 0 on success, -1 if the gateway or its MAC couldn't be found (e.g.
 * ARP cache not warmed yet, or an on-link target with no gateway).
 */
int get_gateway_mac(uint8_t mac[6]) {
    struct in_addr  gw;

    if (get_gateway_ip(&gw) != 0)
        return (-1);
    return (get_mac_for_ip(gw, mac));
}
