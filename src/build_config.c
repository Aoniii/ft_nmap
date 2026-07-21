#include "ft_nmap.h"
#include "config.h"
#include <stdio.h>
#include <string.h>

/**
 * @brief build_config - Builds the usable config from the raw parser data.
 * Validates and converts each raw argument once: speedup bounds, port list,
 * and scan bitmask. On any failure, prints the error and returns -1 so the
 * caller can stop before allocating targets or touching the network.
 */
int build_config(t_raw_data *raw, t_config *cfg) {
    char    err[1024];
    char    *err_ptr;

    err_ptr = err;
    // start from a clean, zeroed config
    memset(cfg, 0, sizeof(*cfg));

    // speedup: number of threads, 0 (mono-thread) to 250 (subject bounds)
    if (raw->speedup < 0 || raw->speedup > 250) {
        fprintf(stderr, "ft_nmap: error: speedup must be between 0 and 250\n");
        return (-1);
    }
    cfg->speedup = raw->speedup;

    // ports: "1-1024" / "1,2,3" / "1,5-15" -> cfg->ports[], cfg->nb_ports
    if (parse_port(raw, cfg, &err_ptr) == -1) {
        fprintf(stderr, "ft_nmap: error: ports: %s\n", err);
        return (-1);
    }

    // scans: "SYN/UDP" -> cfg->scan_flags bitmask (all types if absent)
    if (parse_scan(raw, cfg, &err_ptr) == -1) {
        fprintf(stderr, "ft_nmap: error: scans: %s\n", err);
        return (-1);
    }

    cfg->dns = raw->dns;
    cfg->open = raw->open;
    cfg->version = raw->version;
    cfg->progress = raw->progress;
    return (0);
}
