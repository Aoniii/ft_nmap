#include <netinet/in.h>
#include <string.h>
#include <unistd.h>

/**
 * @brief get_source_ip - Finds the local source IP used to reach a target.
 * "UDP connect trick": connect() on a UDP socket sends nothing on the wire
 * but makes the kernel pick the source IP/interface from its routing table.
 * getsockname() then reads back that chosen source address.
 */
int get_source_ip(struct in_addr target, struct in_addr *out) {
    struct sockaddr_in  addr;
    socklen_t           len;
    int                 sock;

    // a UDP socket: connect() on it triggers no real traffic
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return (-1);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr   = target;
    addr.sin_port   = htons(42);   // arbitrary port, unused for UDP connect

    // connect just resolves the route; no packet is sent
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return (-1);
    }

    // read back which local address the kernel picked
    len = sizeof(addr);
    if (getsockname(sock, (struct sockaddr *)&addr, &len) < 0) {
        close(sock);
        return (-1);
    }

    *out = addr.sin_addr;
    close(sock);
    return (0);
}
