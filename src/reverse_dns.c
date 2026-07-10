#include <netdb.h>
#include <netinet/in.h>
#include <string.h>

/**
 * @brief reverse_dns - Resolves an IPv4 address to its hostname (PTR record).
 * Fills host with the name and returns 1 if a reverse record exists, else 0.
 * NI_NAMEREQD makes getnameinfo fail (rather than echo the IP) when no name.
 */
int reverse_dns(struct in_addr ip, char *host, size_t hostlen) {
    struct sockaddr_in sa;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr   = ip;

    if (getnameinfo((struct sockaddr *)&sa, sizeof(sa), host, hostlen, NULL, 0, NI_NAMEREQD) == 0)
        return (1);
    return (0);
}
