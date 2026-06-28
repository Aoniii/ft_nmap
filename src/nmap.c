#include "ft_nmap.h"

#include <unistd.h>

static void show_target_ip(t_config cfg) {
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

static void show_scan(t_config cfg) {
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

int nmap(t_raw_data *raw, char **args) {
    t_config    cfg;
    t_target    *target;
    char        buff[INET_ADDRSTRLEN];

    if (build_config(raw, &cfg) == -1)
        return (-1);

    if (build_target(raw, &cfg, args) == -1) {
        free_target(&cfg);
        return (-1);
    }

    printf("Scan Configurations\n");
    show_target_ip(cfg);
    printf("No of Ports to scan: %d\n", cfg.nb_ports);
    show_scan(cfg);
    printf("No of threads: %d\n", cfg.speedup);
    target = cfg.targets;
    while (target) {
        inet_ntop(AF_INET, &target->ip, buff, sizeof(buff));
        printf("Scanning...\n");
        sleep(1);
        printf("\033[A\033[KScan took: \n");    // TODO: print time
        printf("IP address: %s\n", buff);
        target = target->next;
    }

    free_target(&cfg);
    return (0);
}
