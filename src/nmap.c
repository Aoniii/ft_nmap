#include "ft_nmap.h"

int nmap(t_raw_data *raw, char **args) {
    t_config    cfg;
    t_net       net;
    t_target    *target;
    char        buff[INET_ADDRSTRLEN];
    long        start_time;

    if (build_config(raw, &cfg) == -1)
        return (-1);

    if (build_target(raw, &cfg, args) == -1) {
        free_target(&cfg);
        return (-1);
    }

    if (setup_network(&net) == -1) {
        free_target(&cfg);
        return (-1);
    }

    printf("Scan Configurations\n");
    show_target_ip(cfg);
    printf("No of Ports to scan: %d\n", cfg.nb_ports);
    show_scan(cfg);
    printf("No of threads: %d\n\n", cfg.speedup);

    target = cfg.targets;
    while (target) {
        start_time = now_ms();
        printf("Scanning...\n");
        // TODO: scan
        printf("\033[A\033[KScan took: %.5f secs\n", (double)((now_ms() - start_time) / 1000.0));
        inet_ntop(AF_INET, &target->ip, buff, sizeof(buff));
        printf("IP address: %s\n", buff);
        target = target->next;
    }

    cleanup_network(&net);
    free_target(&cfg);
    return (0);
}
