#include "ft_nmap.h"
#include <stdio.h>
#include <string.h>

/**
 * @brief parse_scan - Parses the --scan argument into a bitmask.
 * Splits the string on '/', validates each token against the known scan
 * types, and sets the matching bit in cfg->scan_flags. Rejects empty
 * tokens (e.g. "SYN//UDP"), unknown types, and duplicates.
 * If --scan is absent, all scan types are enabled.
 */
int parse_scan(t_raw_data *raw, t_config *cfg, char **err) {
    static const uint8_t    type_flag[] = {F_SYN, F_NULL, F_ACK, F_FIN, F_XMAS, F_UDP};
    static const char       *str_flag[] = {"SYN", "NULL", "ACK", "FIN", "XMAS", "UDP"};

    char    *str;
    char    *start;
    char    token[8];
    int     len;
    int     i;

    // no --scan given: enable every scan type (subject default)
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
        // read one token: advance until the next '/' or end of string
        start = str;
        while (*str && *str != '/')
            str++;
        len = str - start;

        // empty token means a misplaced '/' (leading, trailing or doubled)
        if (len == 0) {
            snprintf(*err, 1024, "Empty scan type");
            return (-1);
        }
        // longest valid name is 4 chars ("XMAS"/"NULL"); longer can't match
        if (len > 4) {
            snprintf(*err, 1024, "Invalid scan type (too long), use SYN/NULL/ACK/FIN/XMAS/UDP");
            return (-1);
        }

        // copy the token into a null-terminated buffer for strcmp
        memcpy(token, start, len);
        token[len] = '\0';

        // look up the token among the known scan names
        i = 0;
        while (i <= 6) {
            // reached the end without a match: unknown scan type
            if (i == 6) {
                snprintf(*err, 1024, "Invalid scan type (%s), use SYN/NULL/ACK/FIN/XMAS/UDP", token);
                return (-1);
            }

            if (strcmp(str_flag[i], token) == 0) {
                // already requested: reject the duplicate
                if (cfg->scan_flags & type_flag[i]) {
                    snprintf(*err, 1024, "Duplicate scan type (%s)", token);
                    return (-1);
                }

                // turn the bit on
                cfg->scan_flags |= type_flag[i];
                break ;
            }
            i++;
        }

        // end of string: done. otherwise skip the '/' and parse next token
        if (*str == '\0')
            break;
        if (*str == '/')
            str++;
    }

    return (0);
}
