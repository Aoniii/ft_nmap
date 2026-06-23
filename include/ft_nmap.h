#ifndef FT_NMAP_H
# define FT_NMAP_H

# include <stdlib.h>
# include <stdbool.h>
# include <stdio.h>
# include <string.h>
# include <errno.h>
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

enum    e_scan_type {
    SCAN_SYN    = 0,
    SCAN_NULL   = 1,
    SCAN_ACK    = 2,
    SCAN_FIN    = 3,
    SCAN_XMAS   = 4,
    SCAN_UDP    = 5,
    SCAN_COUNT  = 6
};

# define F_SYN  (1 << SCAN_SYN)
# define F_NULL (1 << SCAN_NULL)
# define F_ACK  (1 << SCAN_ACK)
# define F_FIN  (1 << SCAN_FIN)
# define F_XMAS (1 << SCAN_XMAS)
# define F_UDP  (1 << SCAN_UDP)
# define F_ALL  (F_SYN|F_NULL|F_ACK|F_FIN|F_XMAS|F_UDP)

int build_config(t_raw_data *raw, t_config *cfg);
int parse_port(t_raw_data *data, t_config *cfg);

#endif
