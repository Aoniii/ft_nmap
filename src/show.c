#include "ft_nmap.h"
#include <arpa/inet.h>
#include <stdio.h>

/**
 * @brief show_target_ip - Prints the target IP(s) for the scan header.
 * Single target  -> inline: "Target Ip-Address: 1.2.3.4"
 * Several targets -> bullet list, one IP per line.
 */
void show_target_ip(t_config cfg) {
    t_target    *target;
    char        ip[INET_ADDRSTRLEN];

    printf("Target Ip-Address: ");
    if (cfg.targets && !cfg.targets->next) {
        inet_ntop(AF_INET, &cfg.targets->ip, ip, sizeof(ip));
        printf("%s\n", ip);
        return;
    }
    for (target = cfg.targets; target; target = target->next) {
        inet_ntop(AF_INET, &target->ip, ip, sizeof(ip));
        printf("\n\t- %s", ip);
    }
    printf("\n");
}

/**
 * @brief show_scan - Prints the scan types to perform, decoded from the bitmask.
 * Each set bit in scan_flags maps to its name; types are '/'-separated
 * (e.g. "SYN/UDP/ACK").
 */

void show_scan(t_config cfg) {
    static const uint8_t    type_flag[] = {F_SYN, F_NULL, F_ACK, F_FIN, F_XMAS, F_UDP};
    static const char       *str_flag[] = {"SYN", "NULL", "ACK", "FIN", "XMAS", "UDP"};

    int     i;
    bool    is_first;

    printf("Scans to be performed:");
    i = 0;
    is_first = true;
    while (i < 6) {
        if (cfg.scan_flags & type_flag[i])
            printf("%c%s", (is_first ? ' ' : '/'), str_flag[i]);
        i++;
        is_first = false;
    }
    printf("\n");
}
