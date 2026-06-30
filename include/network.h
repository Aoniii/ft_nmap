#ifndef NETWORK_H
# define NETWORK_H

# include <stddef.h>
# include <stdint.h>

typedef struct  s_net {
    int         sock;
}               t_net;

int         setup_network(t_net *net);
void        cleanup_network(t_net *net);
uint16_t    checksum(const void *data, size_t len);

#endif
