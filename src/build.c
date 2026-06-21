#include "ft_nmap.h"

int build_config(t_raw_data *raw, t_config *cfg) {
    if (raw->speedup < 0 || raw->speedup > 250) {
        printf("ft_nmap: error: speedup must be between 0 and 250\n");
        return (-1);
    }
    cfg->speedup = raw->speedup;

    return (0);
}
