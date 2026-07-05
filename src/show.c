#include "ft_nmap.h"
#include <arpa/inet.h>
#include <netdb.h>
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
        if (cfg.scan_flags & type_flag[i]) {
            printf("%c%s", (is_first ? ' ' : '/'), str_flag[i]);
            is_first = false;
        }
        i++;
    }
    printf("\n");
}

/**
 * @brief state_to_str - Returns the display string for a port state.
 */
static const char   *state_to_str(t_state state) {
    switch (state) {
        case STATE_OPEN:          return ("Open");
        case STATE_CLOSED:        return ("Closed");
        case STATE_FILTERED:      return ("Filtered");
        case STATE_UNFILTERED:    return ("Unfiltered");
        case STATE_OPEN_FILTERED: return ("Open|Filtered");
        default:                  return ("Unknown");
    }
}

/**
 * @brief get_conclusion - Aggregates the per-scan results into a final state.
 * A port is Open if any scan reports it open (or open|filtered); otherwise
 * it takes the most meaningful non-unknown state found.
 */
static t_state  get_conclusion(t_port_result *pr, uint8_t scan_flags) {
    t_state result;

    result = STATE_UNKNOWN;
    for (int s = 0; s < SCAN_COUNT; s++) {
        if (!(scan_flags & (1 << s)))
            continue;
        t_state st = pr->results[s];
        // open wins over everything
        if (st == STATE_OPEN)
            return (STATE_OPEN);
        // otherwise remember the first meaningful state
        if (result == STATE_UNKNOWN)
            result = st;
    }
    return (result);
}

/**
 * @brief print_results_line - Prints one port row: number, service, per-scan
 * results, and the final conclusion.
 */
static void print_results_line(t_port_result *pr, uint16_t port, uint8_t scan_flags, t_state conclusion) {
    static const char *scan_names[] = {"SYN", "NULL", "ACK", "FIN", "XMAS", "UDP"};
    struct servent    *serv;
    const char        *service;

    // service name lookup (type only, not version)
    serv = getservbyport(htons(port), "tcp");
    service = serv ? serv->s_name : "Unassigned";

    printf("%-8d %-18s ", port, service);

    // per-scan results, e.g. "SYN(Open) NULL(Closed)"
    for (int s = 0; s < SCAN_COUNT; s++) {
        if (!(scan_flags & (1 << s)))
            continue;
        printf("%s(%s) ", scan_names[s], state_to_str(pr->results[s]));
    }

    printf("  %s\n", state_to_str(conclusion));
}

/**
 * @brief show_results - Prints the two result tables for one target:
 * open ports first, then closed/filtered/unfiltered ports.
 */
void show_results(t_target *target, t_config *cfg) {
    char    buff[INET_ADDRSTRLEN];
    t_state concl;

    inet_ntop(AF_INET, &target->ip, buff, sizeof(buff));
    printf("IP address: %s\n", buff);

    // ---- Open ports ----
    printf("\nOpen ports:\n");
    printf("Port     Service Name       Results / Conclusion\n");
    printf("--------------------------------------------------------------\n");
    for (int i = 0; i < cfg->nb_ports; i++) {
        concl = get_conclusion(&target->ports[i], cfg->scan_flags);
        if (concl == STATE_OPEN)
            print_results_line(&target->ports[i], cfg->ports[i], cfg->scan_flags, concl);
    }

    // ---- Closed / Filtered / Unfiltered ports ----
    printf("\nClosed/Filtered/Unfiltered ports:\n");
    printf("Port     Service Name       Results / Conclusion\n");
    printf("--------------------------------------------------------------\n");
    for (int i = 0; i < cfg->nb_ports; i++) {
        concl = get_conclusion(&target->ports[i], cfg->scan_flags);
        if (concl != STATE_OPEN)
            print_results_line(&target->ports[i], cfg->ports[i], cfg->scan_flags, concl);
    }
}
