#include "ft_nmap.h"
#include <string.h>

int parse_scan(t_raw_data *raw, t_config *cfg, char **err) {
    static const uint8_t    type_flag[] = {F_SYN, F_NULL, F_ACK, F_FIN, F_XMAS, F_UDP};
    static const char       *str_flag[] = {"SYN", "NULL", "ACK", "FIN", "XMAS", "UDP"};

    char    *str;
    char    *start;
    char    token[8];
    int     len;
    int     i;

    if (!raw->scan) {
        cfg->scan_flags = F_ALL;
        return (0);
    }

    str = raw->scan;
    if (*str == '\0') {
        snprintf(*err, 1024, "Empty scan type");
        return (-1);
    }

    while (1) {
        start = str;
        while (*str && *str != '/')
            str++;
        len = str - start;

        if (len == 0) {
            snprintf(*err, 1024, "Empty scan type");
            return (-1);
        }

        i = 0;
        strncpy(token, start, len);
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

        if (*str == '\0')
            break;
        if (*str == '/')
            str++;
    }

    return (0);
}
