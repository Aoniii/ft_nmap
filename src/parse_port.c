#include "ft_nmap.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

int parse_port(t_raw_data *raw, t_config *cfg, char **err) {
    char    *str;
    char    *before;
    long    value;
    int     i;
    bool    is_range;

    if (!raw->port) {
        i = 1;
        while (i <= 1024) {
            cfg->ports[i - 1] = i;
            i++;
        }
        cfg->nb_ports = 1024;
        return (0);
    }

    str = raw->port;
    is_range = false;
    if (!str[0] || str[0] < '0' || str[0] > '9') {
        snprintf(*err, 1024, "The port value is invalid (%s)", str);
        return (-1);
    }

    while (1) {
        errno = 0;
        before = str;
        value = strtol(str, &str, 10);

        if (str == before) {
            snprintf(*err, 1024, "Missing port number");
            return (-1);
        }
        if (errno == ERANGE || value <= 0 || value > 65535) {
            snprintf(*err, 1024, "The port value is incorrect (%ld)", value);
            return (-1);
        }

        if (is_range) {
            i = cfg->ports[cfg->nb_ports - 1] + 1;
            if (i >= value) {
                snprintf(*err, 1024, "Invalid range start must be lower than end");
                return (-1);
            }

            while (i <= value) {
                if (cfg->nb_ports >= 1024) {
                    snprintf(*err, 1024, "Too many ports (max 1024)");
                    return (-1);
                }

                cfg->ports[cfg->nb_ports] = i;
                i++;
                cfg->nb_ports++;
            }

            is_range = false;
        } else {
            if (cfg->nb_ports >= 1024) {
                snprintf(*err, 1024, "Too many ports (max 1024)");
                return (-1);
            }

            if (cfg->nb_ports > 0) {
                if (cfg->ports[cfg->nb_ports - 1] >= value) {
                    snprintf(*err, 1024, "Ports must be in ascending order");
                    return (-1);
                }
            }

            cfg->ports[cfg->nb_ports] = value;
            cfg->nb_ports++;
        }

        if (*str == '\0')
            break ;

        if (*str == '-') {
            is_range = true;
            str++;
        } else if (*str == ',') {
            str++;
        } else {
            snprintf(*err, 1024, "Invalid delimiters: %c (use ',' or '-')", *str);
            return (-1);
        }
    }

    return (0);
}

