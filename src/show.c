#include "ft_nmap.h"
#include "display.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/**
 * @brief show_target_ip - Prints the target IP(s) for the scan header.
 * Single target  -> inline: "Target Ip-Address: 1.2.3.4"
 * Several targets -> bullet list, one IP per line.
 */
static void show_target_ip(t_config cfg) {
    t_target    *target;
    char        ip[INET_ADDRSTRLEN];

    printf(" ➔ Target: ");
    if (cfg.targets && !cfg.targets->next) {
        inet_ntop(AF_INET, &cfg.targets->ip, ip, sizeof(ip));
        printf("%s (%s)\n", ip, cfg.targets->name);
        return;
    }
    for (target = cfg.targets; target; target = target->next) {
        inet_ntop(AF_INET, &target->ip, ip, sizeof(ip));
        printf("\n\t- %s (%s)", ip, target->name);
    }
    printf("\n");
}

/**
 * @brief show_scan - Prints the scan types to perform, decoded from the bitmask.
 * Each set bit in scan_flags maps to its name; types are '/'-separated
 * (e.g. "SYN/UDP/ACK").
 */

static void show_scan(t_config cfg) {
    static const uint8_t    type_flag[] = {F_SYN, F_NULL, F_ACK, F_FIN, F_XMAS, F_UDP};
    static const char       *str_flag[] = {"SYN", "NULL", "ACK", "FIN", "XMAS", "UDP"};

    int     i;
    bool    is_first;

    printf(" ➔ Scans:");
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

void    show_config(t_config cfg) {
    printf("Scan Configuration:\n");
    show_target_ip(cfg);
    printf(" ➔ Ports: %d\n", cfg.nb_ports);
    show_scan(cfg);
    printf(" ➔ Threads: %d\n", cfg.speedup); 
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
 * @brief state_color - ANSI color for a state (green open, red closed, yellow rest).
 */
static const char *state_color(t_state s) {
    switch (s) {
        case STATE_OPEN:       return (C_GREEN);
        case STATE_UNFILTERED: return (C_BLUE);
        case STATE_CLOSED:     return (C_RED);
        default:               return (C_YELLOW);
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
 * @brief print_details - Prints per-scan results, grouping consecutive
 * requested scans that share the same state (e.g. "FIN/XMAS:Open|Filtered").
 */
static void print_details(t_port_result *pr, uint8_t flags, bool version) {
    static const char *names[] = {"SYN", "NULL", "ACK", "FIN", "XMAS", "UDP"};
    int done[SCAN_COUNT] = {0};
    int first = 1;

    version &= pr->version[0] != '\0';

    printf("       %s%s──%s ", C_DIM, version ? "├" : "└", C_RESET);
    for (int s = 0; s < SCAN_COUNT; s++) {
        if (!(flags & (1 << s)) || done[s])
            continue ;

        // start a group with scan s, then gather every other requested scan
        // that shares the same state, regardless of position
        char group[64];
        strcpy(group, names[s]);
        done[s] = 1;
        for (int i = s + 1; i < SCAN_COUNT; i++) {
            if (!(flags & (1 << i)) || done[i])
                continue ;

            if (pr->results[i] == pr->results[s]) {
                strcat(group, "/");
                strcat(group, names[i]);
                done[i] = 1;
            }
        }
        if (!first)
            printf(" %s|%s ", C_DIM, C_RESET);
        printf("%s:%s%s%s", group, state_color(pr->results[s]), state_to_str(pr->results[s]), C_RESET);
        first = 0;
    }
    printf("\n");

    if (version)
        printf("       %s└──%s Version: %s\n", C_DIM, C_RESET, pr->version);
}

/**
 * @brief print_duration - Prints an elapsed time in a readable unit.
 * Under 1 second -> milliseconds, otherwise seconds with 2 decimals.
 */
static void print_duration(long ms) {
    if (ms < 1000)
        printf("%ldms", ms);
    else
        printf("%.2fs", ms / 1000.0);
}

/**
 * @brief show_results - Prints the scan results for one target: a summary
 * line, then one line per port with its per-scan details. Colors are enabled
 * only when stdout is a terminal (isatty), so redirection stays clean.
 */
void show_results(long elapsed, t_target *target, t_config *cfg) {
    char    buff[INET_ADDRSTRLEN];
    char    host[NI_MAXHOST];
    int     n_open = 0, n_closed = 0, n_other = 0;

    for (int i = 0; i < cfg->nb_ports; i++) {
        t_state c = get_conclusion(&target->ports[i], cfg->scan_flags);
        if (c == STATE_OPEN) n_open++;
        else if (c == STATE_CLOSED) n_closed++;
        else n_other++;
    }

    inet_ntop(AF_INET, &target->ip, buff, sizeof(buff));
    printf("%s%s════════════════════════════════════════════════════════════════%s\n", cfg->progress ? C_CUT(4) : C_CUT(1), C_DIM, C_RESET);

    if (cfg->dns && reverse_dns(target->ip, host, sizeof(host)))
        printf("%s %s%s%s (%s)\n", C_CLEAR, C_BOLD, buff, C_RESET, host);
    else
        printf("%s %s%s%s (%s)\n", C_CLEAR, C_BOLD, buff, C_RESET, target->name);

    printf(" %s%d open%s · %s%d closed%s · %s%d filtered/other%s · %s", C_GREEN, n_open, C_RESET, C_RED, n_closed, C_RESET, C_YELLOW, n_other, C_RESET, C_BLUE);
    print_duration(elapsed);
    printf("%s\n", C_RESET);
    printf("%s────────────────────────────────────────────────────────────────%s\n", C_DIM, C_RESET);

    for (int i = 0; i < cfg->nb_ports; i++) {
        t_state         concl = get_conclusion(&target->ports[i], cfg->scan_flags);
        struct servent  *serv = getservbyport(htons(cfg->ports[i]), "tcp");
        const char      *service = serv ? serv->s_name : "Unassigned";
        const char      *mark = (concl == STATE_OPEN) ? "[+]" : "[-]";

        if (concl != STATE_OPEN && cfg->open)
            continue ;

        printf(" %s%s%s   %-6d   %-15s %s→%s %s%s%s%s\n",
               state_color(concl), mark, C_RESET,
               cfg->ports[i], service,
               C_DIM, C_RESET,
               C_BOLD, state_color(concl), state_to_str(concl), C_RESET);
        print_details(&target->ports[i], cfg->scan_flags, cfg->version);
    }
}
