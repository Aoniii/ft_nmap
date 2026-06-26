#include "ft_nmap.h"

int nmap(t_raw_data *raw, char **args) {
    t_config    cfg;

    if (build_config(raw, &cfg) == -1)
        return (-1);

    if (build_target(raw, &cfg, args) == -1) {
        free_target(&cfg);
        return (-1);
    }

    t_target    *node = cfg.targets;
    char        buf[INET_ADDRSTRLEN];
    while (node) {
        inet_ntop(AF_INET, &node->ip, buf, sizeof(buf));
        printf("name: %s, ip: %s\n", node->name, buf);
        node = node->next;
    }

    free_target(&cfg);
    return (0);
}
