#include "network.h"
#include <netinet/in.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>

/**
 * @brief send_packet - Sends a forged packet of the given size to a target port over the raw socket.
 * The sockaddr_in destination carries the target IP; the kernel routes the
 * packet using it (and the daddr already set in the IP header). Returns 0 / -1.
 */
int send_packet(int sock, char *buffer, size_t size, struct in_addr dest, uint16_t port) {
    struct sockaddr_in  addr;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr   = dest;
    addr.sin_port   = htons(port);

    if (sendto(sock, buffer, size, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        return (-1);
    return (0);
}
