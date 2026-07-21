#ifndef FT_NMAP_H
# define FT_NMAP_H

# define POSITIONAL_TARGET  1

# include <stdbool.h>
# include <stdint.h>
# include <netinet/in.h>

typedef struct  s_raw_data {
    char        *ip;
    char        *file;
    char        *port;
    char        *scan;
    int         speedup;
    bool        dns;
    bool        open;
    bool        version;
    bool        progress;
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
    t_state     results[6];
    t_state     conclusion;
    char        version[128];       // service banner, "unknown" if none
}               t_port_result;

typedef struct      s_target {
    char            *name;
    struct in_addr  ip;
    t_port_result   *ports;
    struct s_target *next;
}                   t_target;

typedef struct  s_config {
    t_target    *targets;
    uint16_t    ports[1024];
    int         nb_ports;
    uint8_t     scan_flags;
    int         speedup;
    bool        dns;
    bool        open;
    bool        version;
    bool        progress;
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

int nmap(t_raw_data *raw, char **args);

int     reverse_dns(struct in_addr ip, char *host, size_t hostlen);
void    grab_version(struct in_addr ip, int port, char *out, size_t outlen);

#endif
