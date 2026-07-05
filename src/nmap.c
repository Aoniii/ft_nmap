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

    printf("Scan Configurations\n");
    show_target_ip(cfg);
    printf("No of Ports to scan: %d\n", cfg.nb_ports);
    show_scan(cfg);
    printf("No of threads: %d\n", cfg.speedup);

    target = cfg.targets;
    while (target) {
        start_time = now_ms();
        printf("\nScanning: %s\n", target->name);

        //  1. IP source for this target
        if (get_source_ip(target->ip, &net.src_ip) != 0) {
            fprintf(stderr, "ft_nmap: warning: cannot reach %s, skipping\n", target->name);
            target = target->next;
            continue;
        }

        //  2. capture filter for this target
        if (set_filter(&net, target->ip) == -1) {
            fprintf(stderr, "ft_nmap: error: failed to set capture filter, aborting scan\n");
            cleanup_network(&net);
            free_target(&cfg);
            return (-1);
        }

        //  3. for each port and each scan type, do a scan
        for (int i = 0; i < cfg.nb_ports; i++) {
            uint16_t port = cfg.ports[i];

            for (int s = 0; s < SCAN_COUNT; s++) {
                // Is this scan requested? (bit set in the bitmask)
                if (!(cfg.scan_flags & (1 << s)))
                    continue;

                uint8_t flags = scan_type_to_flags(s);   // SCAN_SYN -> TH_SYN, etc.
                t_state state = scan_one(&net, target->ip, port, flags);

                target->ports[i].results[s] = state;
            }
        }

        printf("Scan took: %.5f secs\n", (double)((now_ms() - start_time) / 1000.0));
        show_results(target, &cfg);

        target = target->next;
    }

    cleanup_network(&net);
    free_target(&cfg);
    return (0);
}
