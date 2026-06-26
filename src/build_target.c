#include "ft_nmap.h"
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

void    free_target(t_config *cfg) {
    t_target    *next;
    t_target    *tmp;

    next = cfg->targets;
    while (next) {
        tmp = next;
        next = next->next;

        if (tmp) {
            free(tmp->name);
            free(tmp->ports);
            free(tmp);
        }
    }
}

static int  resolve_target(char *target, struct in_addr *out) {
    struct addrinfo hints;
    struct addrinfo *res;

    if (inet_pton(AF_INET, target, out) == 1)
        return (0);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family     = AF_INET;
    hints.ai_socktype   = SOCK_RAW;

    if (getaddrinfo(target, NULL, &hints, &res) != 0)
        return (-1);

    *out = ((struct sockaddr_in *)res->ai_addr)->sin_addr;

    freeaddrinfo(res);
    return (0);
}

static int  add_target(t_target **last, t_config *cfg, char *ip, char **err) {
    t_target    *node;

    node = malloc(sizeof(t_target));
    if (!node) {
        snprintf(*err, 1024, "Memory allocation failed");
        return (-1);
    }

    node->name = NULL;
    node->ports = NULL;
    node->next = NULL;

    if (*last)
        (*last)->next = node;
    else
        cfg->targets = node;
    *last = node;

    node->name = strdup(ip);
    if (!node->name) {
        snprintf(*err, 1024, "Memory allocation failed");
        return (-1);
    }

    if (resolve_target(node->name, &node->ip) != 0) {
        snprintf(*err, 1024, "Cannot resolve target (%s)", node->name);
        return (-1);
    }

    node->ports = malloc(sizeof(t_port_result) * cfg->nb_ports);
    if (!node->ports) {
        snprintf(*err, 1024, "Memory allocation failed");
        return (-1);
    }

    return (0);
}

static int  file_target(t_target **last, t_config *cfg, char *file, char **err) {
    FILE    *fp;
    char    *line;
    char    *saveptr;
    char    *token;
    size_t  cap;
    ssize_t n;

    fp = fopen(file, "r");
    if (!fp) {
        snprintf(*err, 1024, "cannot open file (%s)", file);
        return (-1);
    }

    line = NULL;
    cap = 0;
    while ((n = getline(&line, &cap, fp)) != -1) {
        token = strtok_r(line, " \t\n\r\f\v", &saveptr);
        while (token) {
            if (add_target(last, cfg, token, err) == -1) {
                free(line);
                fclose(fp);
                return (-1);
            }
            token = strtok_r(NULL, " \t\n\r\f\v", &saveptr);
        }
    }

    free(line);
    fclose(fp);
    return (0);
}

int build_target(t_raw_data *raw, t_config *cfg, char **args) {
    char        err[1024];
    char        *err_ptr;
    t_target    *last;
    int         i;

    err_ptr = err;
    cfg->targets = NULL;
    last = NULL;

    if ((!args || !args[0]) && !raw->file) {
        fprintf(stderr, "ft_nmap: error: No target specified. Use an IP/hostname or --file.\n");
        return (-1);
    }

    i = 0;
    while (args && args[i]) {
        if (add_target(&last, cfg, args[i], &err_ptr) == -1) {
            fprintf(stderr, "ft_nmap: error: %s\n", err);
            return (-1);
        }
        i++;
    }

    if (raw->file) {
        if (file_target(&last, cfg, raw->file, &err_ptr) == -1) {
            fprintf(stderr, "ft_nmap: error: %s\n", err);
            return (-1);
        }
    }

    if (!cfg->targets) {
        fprintf(stderr, "ft_nmap: error: No target specified.\n");
        return (-1);
    }

    return (0);
}
