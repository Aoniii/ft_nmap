#include "ft_nmap.h"
#include "network.h"
#include "config.h"
#include "display.h"
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>

int nmap(t_raw_data *raw, char **args) {
    t_config    cfg;
    t_net       net;
    t_target    *target;
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

    show_config(cfg);
    target = cfg.targets;
    while (target) {
        start_time = now_ms();
        printf("\nScanning: %s\n", target->name);

        //  1. IP source for this target
        if (get_source_ip(target->ip, &net.src_ip) != 0) {
            fprintf(stderr, "ft_nmap: warning: cannot reach %s, skipping\n", target->name);
            target = target->next;
            continue ;
        }

        // 2. open pcap on the right interface for this target (lo vs default)
        if (open_pcap(&net, iface_for_target(&net, target->ip)) == -1) {
            cleanup_network(&net);
            free_target(&cfg);
            return (-1);
        }

        //  3. capture filter for this target
        if (set_filter(&net, target->ip) == -1) {
            fprintf(stderr, "ft_nmap: error: failed to set capture filter, aborting scan\n");
            cleanup_network(&net);
            free_target(&cfg);
            return (-1);
        }

        //  4. scan every port with every requested scan type
        for (int i = 0; i < cfg.nb_ports; i++) {
            uint16_t port = cfg.ports[i];

            for (int s = 0; s < SCAN_COUNT; s++) {
                if (!(cfg.scan_flags & (1 << s)))
                    continue ;
                if (s == SCAN_UDP)
                    target->ports[i].results[s] = scan_one_udp(&net, target->ip, port);
                else
                    target->ports[i].results[s] = scan_one(&net, target->ip, port, s);;
            }
        }

        show_results(now_ms() - start_time, target, &cfg);
        target = target->next;
    }

    cleanup_network(&net);
    free_target(&cfg);
    return (0);
}
