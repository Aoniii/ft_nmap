#include "ft_nmap.h"

int build_config(t_raw_data *raw, t_config *cfg) {
    char    err[1024];
    char    *err_ptr;

    err_ptr = err;
    memset(cfg, 0, sizeof(*cfg));

    if (raw->speedup < 0 || raw->speedup > 250) {
        fprintf(stderr, "ft_nmap: error: speedup must be between 0 and 250\n");
        return (-1);
    }
    cfg->speedup = raw->speedup;

    if (parse_port(raw, cfg, &err_ptr) == -1) {
        fprintf(stderr, "ft_nmap: error: ports: %s\n", err);
        return (-1);
    }

    if (parse_scan(raw, cfg, &err_ptr) == -1) {
        fprintf(stderr, "ft_nmap: error: scans: %s\n", err);
        return (-1);
    }

    return (0);
}
