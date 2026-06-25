#include "ft_nmap.h"

int nmap(t_raw_data *raw, char **args) {
    t_config    cfg;

    if (build_config(raw, &cfg) == -1)
        return (-1);

    if (build_target(raw, &cfg, args) == -1) {
        free_target(&cfg);
        return (-1);
    }

    free_target(&cfg);
    return (0);
}
