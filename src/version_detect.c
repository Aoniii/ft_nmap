#define _GNU_SOURCE
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>

/**
 * @brief grab_version - Connects to an open TCP port and reads the service
 * banner to identify the software and version. Sends a probe for protocols
 * that stay silent (HTTP). Writes a cleaned one-line result into out; on any
 * failure writes "unknown". out is always a valid NUL-terminated string.
 */
void    grab_version(struct in_addr ip, int port, char *out, size_t outlen) {
    int                 sock;
    struct sockaddr_in  addr;
    struct timeval      tv;
    char                buf[512];
    char                *start;
    size_t              i;
    int                 n;

    // default result if anything fails
    strncpy(out, "unknown", outlen - 1);
    out[outlen - 1] = '\0';

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        return;

    // timeouts so a slow/silent service never hangs the scan
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    addr.sin_addr   = ip;

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return ;
    }

    // HTTP-like ports need a nudge to reveal their Server: header
    if (port == 80 || port == 8080 || port == 8000) {
        const char *req = "HEAD / HTTP/1.0\r\n\r\n";
        if (write(sock, req, strlen(req)) < 0) {
            close(sock);
            return ;
        }
    }

    n = read(sock, buf, sizeof(buf) - 1);
    close(sock);
    if (n <= 0)
        return ;        // no banner -> stays "unknown"
    buf[n] = '\0';

    // for HTTP prefer the "Server:" line; otherwise take the first line
    start = strcasestr(buf, "Server:");
    if (!start)
        start = buf;
    while (*start == ' ' || *start == '\r' || *start == '\n')
        start++;

    // copy one clean printable line
    i = 0;
    while (start[i] && start[i] != '\r' && start[i] != '\n' && i < outlen - 1) {
        out[i] = (start[i] >= 32 && start[i] < 127) ? start[i] : '.';
        i++;
    }
    if (i > 0)
        out[i] = '\0';
    else {
        strncpy(out, "unknown", outlen - 1);   // nothing printable
        out[outlen - 1] = '\0';
    }
}
