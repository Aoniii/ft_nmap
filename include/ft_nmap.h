#ifndef FT_NMAP_H
# define FT_NMAP_H

# include <stdlib.h>
# include <stdio.h>
# include <netinet/in.h>

typedef struct  s_raw_data {
    char        *file;
    char        *port;
    char        *scan;
    int         speedup;
}               t_raw_data;

typedef enum    e_state {
    STATE_OPEN,
    STATE_CLOSED,
    STATE_FILTERED,
    STATE_UNFILTERED,
    STATE_OPEN_FILTERED,
    STATE_UNKNOWN
}               t_state;

typedef struct  s_port_result {
    uint16_t    port;
    t_state     results[6];
    t_state     conclusion;
}               t_port_result;

typedef struct      s_target {
    char            *name;
    struct in_addr  ip;
    t_port_result   *ports;
    int             nb_ports;
    struct s_target *next;
}                   t_target;

typedef struct  s_config {
    t_target    *targets;
    int         nb_targets;
    uint16_t    ports[1024];
    int         nb_ports;
    uint8_t     scan_flags;
    int         speedup;
}               t_config;

//  build.c
int build_config(t_raw_data *raw, t_config *cfg);

#endif
