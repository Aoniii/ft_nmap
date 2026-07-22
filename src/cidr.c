#include "ft_nmap.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief parse_cidr - Parses "A.B.C.D/prefix" into its network address and
 * the number of addresses it covers. Fills net_addr (host byte order) and
 * count. Returns 0 on success, -1 if the string isn't a valid CIDR.
 */
static int parse_cidr(const char *str, uint32_t *net_addr, uint32_t *count) {
    char            buf[64];
    char            *slash;
    int             prefix;
    struct in_addr  addr;
    uint32_t        ip;
    uint32_t        mask;

    strncpy(buf, str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    slash = strchr(buf, '/');
    if (!slash)
        return (-1);                                                // no '/' -> not a CIDR
    if (*(slash + 1) == '\0')
        return (-1);                                                // slash without prefix
    *slash = '\0';
    prefix = atoi(slash + 1);
    if (prefix < 0 || prefix > 32)
        return (-1);                                                // invalid prefix length
    if (inet_pton(AF_INET, buf, &addr) != 1)
        return (-1);                                                // invalid base IP

    ip   = ntohl(addr.s_addr);                                      // host byte order for arithmetic
    mask = (prefix == 0) ? 0 : (0xFFFFFFFF << (32 - prefix));
    *net_addr = ip & mask;                                          // network address (first in range)
    *count    = (prefix == 32) ? 1 : (1u << (32 - prefix));
    return (0);
}

/**
 * @brief add_cidr - Expands a CIDR block and adds every address as a target.
 * Builds each IP from the network base + offset and inserts it via add_target.
 */
int add_cidr(t_target **last, t_config *cfg, const char *str, char **err_ptr) {
    uint32_t    net_addr;
    uint32_t    count;
    char        ip_str[INET_ADDRSTRLEN];

    if (parse_cidr(str, &net_addr, &count) == -1) {
        snprintf(*err_ptr, 1024, "invalid CIDR notation (%s)", str);
        return (-1);                                                // not a CIDR, caller falls back to normal target
    }

    if (count > 65536) {   // max /16
        snprintf(*err_ptr, 1024, "CIDR range too large (%u addresses, max 65536)", count);
        return (-1);
    }

    for (uint32_t i = 0; i < count; i++) {
        struct in_addr a;
        a.s_addr = htonl(net_addr + i);
        inet_ntop(AF_INET, &a, ip_str, sizeof(ip_str));
        if (add_target(last, cfg, ip_str, err_ptr) == -1)
            return (-1);
    }
    return (0);
}
