#include "ft_nmap.h"

int parse_scan(t_raw_data *raw, t_config *cfg, char **err) {
    static const uint8_t    type_flag[] = {F_SYN, F_NULL, F_ACK, F_FIN, F_XMAS, F_UDP};
    static const char       *str_flag[] = {"SYN", "NULL", "ACK", "FIN", "XMAS", "UDP"};

    char    *token;
    char    *str;
    int     i;

    if (!raw->scan) {
        cfg->scan_flags = F_ALL;
        return (0);
    }

    str = strdup(raw->scan);
    if (!str) {
        snprintf(*err, 1024, "Memory allocation failed");
        return (-1);
    }

    token = strtok(str, "/");
    while (token != NULL) {
        i = 0;
        while (i <= 6) {
            if (i == 6) {
                snprintf(*err, 1024, "Invalid scan type (%s), use SYN/NULL/ACK/FIN/XMAS/UDP", token);
                free(str);
                return (-1);
            }

            if (strcmp(str_flag[i], token) == 0) {
                if (cfg->scan_flags & type_flag[i]) {
                    snprintf(*err, 1024, "Duplicate scan type (%s)", token);
                    free(str);
                    return (-1);
                }

                cfg->scan_flags |= type_flag[i];
                break ;
            }
            i++;
        }
        token = strtok(NULL, "/");
    }

    free(str);
    return (0);
}
