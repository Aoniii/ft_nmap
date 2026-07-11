#include "ft_nmap.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief free_target - Frees the whole target list and its contents.
 * Walks the linked list, freeing each node's name, port results, and the
 * node itself. Safe to call on a partially built list (NULL fields are
 * handled by free).
 */
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

/**
 * @brief resolve_target - Resolves an IP or hostname into a struct in_addr.
 * Tries inet_pton first (already a dotted IPv4, no DNS). Falls back to
 * getaddrinfo for hostnames, taking the first IPv4 result. We do not
 * implement DNS ourselves, we delegate to the system resolver.
 */
static int  resolve_target(char *target, struct in_addr *out) {
    struct addrinfo hints;
    struct addrinfo *res;

    // already a dotted IPv4: take it directly, no resolution needed
    if (inet_pton(AF_INET, target, out) == 1)
        return (0);

    // hostname: let the system resolve it (IPv4 only)
    memset(&hints, 0, sizeof(hints));
    hints.ai_family     = AF_INET;
    hints.ai_socktype   = SOCK_RAW;

    if (getaddrinfo(target, NULL, &hints, &res) != 0)
        return (-1);

    *out = ((struct sockaddr_in *)res->ai_addr)->sin_addr;

    // getaddrinfo allocates, must free
    freeaddrinfo(res);
    return (0);
}

/**
 * @brief add_target - Builds one target node and appends it to the list.
 * Inserts the node into the list immediately after malloc (with NULL fields)
 * so that free_target can always clean it up, even if a later step fails.
 * Then fills name, resolves the IP, and allocates the per-port results.
 */
static int  add_target(t_target **last, t_config *cfg, char *ip, char **err) {
    t_target    *node;

    node = malloc(sizeof(t_target));
    if (!node) {
        snprintf(*err, 1024, "Memory allocation failed");
        return (-1);
    }

    // init + insert BEFORE anything that can fail, so cleanup always works
    node->name = NULL;
    node->ports = NULL;
    node->next = NULL;

    if (*last)
        (*last)->next = node;   // append in tail (keeps input order)
    else
        cfg->targets = node;    // first node
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

    // one result slot per port to scan
    node->ports = malloc(sizeof(t_port_result) * cfg->nb_ports);
    if (!node->ports) {
        snprintf(*err, 1024, "Memory allocation failed");
        return (-1);
    }

    for (int i = 0; i < cfg->nb_ports; i++)
        node->ports[i].version[0] = '\0';

    return (0);
}

/**
 * @brief file_target - Reads targets from a file, one or more per line.
 * Splits each line on whitespace and feeds every token to add_target.
 * Empty lines and blank-only lines yield no token and are skipped.
 */
static int  file_target(t_target **last, t_config *cfg, char *file, char **err) {
    FILE    *fp;
    char    *line;
    char    *token;
    size_t  cap;
    ssize_t n;

    fp = fopen(file, "r");
    if (!fp) {
        snprintf(*err, 1024, "cannot open file (%s)", file);
        return (-1);
    }

    // getline allocates the buffer on first call
    line = NULL;
    cap = 0;
    while ((n = getline(&line, &cap, fp)) != -1) {
        // split the line on any whitespace
        token = strtok(line, " \t\n\r\f\v");
        while (token) {
            if (add_target(last, cfg, token, err) == -1) {
                free(line);
                fclose(fp);
                return (-1);
            }
            token = strtok(NULL, " \t\n\r\f\v");
        }
    }

    // getline's buffer, freed once after the loop
    free(line);
    fclose(fp);
    return (0);
}

/**
 * @brief check_ip_mode - Validates target input when POSITIONAL_TARGET is 0.
 * In this mode targets come from --ip or --file only:
 *   - positional arguments are rejected
 *   - exactly one of --ip / --file must be given (not both, not none)
 * Then adds the --ip target to the list. Returns 0 on success, -1 on error.
 */
#if !POSITIONAL_TARGET
static int check_ip_mode(t_raw_data *raw, t_config *cfg, char **args, t_target **last, char **err_ptr) {
    // 1. no positional arguments allowed in this mode
    if (args && args[0]) {
        fprintf(stderr, "ft_nmap: error: unexpected argument '%s'. Use --ip to specify a target.\n", args[0]);
        return (-1);
    }

    // 2. exactly one of --ip / --file must be provided
    if (!raw->ip && !raw->file) {
        fprintf(stderr, "ft_nmap: error: no target specified. Use --ip or --file.\n");
        return (-1);
    }
    if (raw->ip && raw->file) {
        fprintf(stderr, "ft_nmap: error: --ip and --file are mutually exclusive.\n");
        return (-1);
    }

    // 3. add the --ip target (if that's the one given)
    if (raw->ip) {
        if (add_target(last, cfg, raw->ip, err_ptr) == -1) {
            fprintf(stderr, "ft_nmap: error: %s\n", *err_ptr);
            return (-1);
        }
    }
    return (0);
}
#endif

/**
 * @brief build_target - Builds the target list from positionals and/or file.
 * Adds positional arguments (IP/hostnames) first, then targets from --file.
 * Requires at least one valid target. On any failure the caller is expected
 * to call free_target to release the partially built list.
 */
int build_target(t_raw_data *raw, t_config *cfg, char **args) {
    char        err[1024];
    char        *err_ptr;
    t_target    *last;

    err_ptr = err;
    cfg->targets = NULL;
    last = NULL;

    #if POSITIONAL_TARGET
    // nothing to scan at all
    if ((!args || !args[0]) && !raw->file) {
        fprintf(stderr, "ft_nmap: error: No target specified. Use an IP/hostname or --file.\n");
        return (-1);
    }

    // positional targets (IP/hostnames, nmap-style)
    int i = 0;
    while (args && args[i]) {
        if (add_target(&last, cfg, args[i], &err_ptr) == -1) {
            fprintf(stderr, "ft_nmap: error: %s\n", err);
            return (-1);
        }
        i++;
    }
    #else
    // mode --ip / --file only
    if (check_ip_mode(raw, cfg, args, &last, &err_ptr) == -1)
        return (-1);
    #endif

    // targets from --file
    if (raw->file) {
        if (file_target(&last, cfg, raw->file, &err_ptr) == -1) {
            fprintf(stderr, "ft_nmap: error: %s\n", err);
            return (-1);
        }
    }

    // a --file may exist but contain no valid target (empty file)
    if (!cfg->targets) {
        fprintf(stderr, "ft_nmap: error: No target specified.\n");
        return (-1);
    }

    return (0);
}
