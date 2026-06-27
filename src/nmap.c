#include "ft_nmap.h"
#include <stdio.h>

int nmap(t_raw_data *raw, char **args) {
    t_config    cfg;
    //t_target    *target;
    //char        buff[INET_ADDRSTRLEN];

    if (build_config(raw, &cfg) == -1)
        return (-1);

    if (build_target(raw, &cfg, args) == -1) {
        free_target(&cfg);
        return (-1);
    }

    printf("Scan Configurations\n");
    printf("Target Ip-Address: \n");
    printf("No of Ports to scan: %d", cfg.nb_ports);
    printf("Scans to be performed: \n");
    printf("No of threads: %d\n", cfg.speedup);
    printf("Scanning...\n");
    //while (target) {
        //inet_ntop(AF_INET, &target->ip, buff, sizeof(buff));
        //target = target->next;
    //}

    free_target(&cfg);
    return (0);
}
