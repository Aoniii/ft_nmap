#include "ft_nmap.h"

int build_config(t_raw_data *raw, t_config *cfg) {
    memset(cfg, 0, sizeof(*cfg));

    if (raw->speedup < 0 || raw->speedup > 250) {
        fprintf(stderr, "ft_nmap: error: speedup must be between 0 and 250\n");
        return (-1);
    }
    cfg->speedup = raw->speedup;

    if (parse_port(raw, cfg) == -1) {
        fprintf(stderr, "ft_nmap: error: ports\n");
        // TODO: create multiple msg
        return (-1);
    }

    return (0);
}
