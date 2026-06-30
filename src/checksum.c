#include <stdint.h>
#include <stddef.h>

/**
 * @brief checksum - Internet checksum (RFC 1071).
 * Used to verify integrity of IP/TCP/UDP/ICMP headers.
 * Sums the buffer in 16-bit words, folds carries, returns one's complement.
 * Return value goes directly into the checksum field (do NOT apply htons).
 */
uint16_t    checksum(const void *data, size_t len) {
    const uint16_t  *ptr = data;
    uint32_t        sum = 0;

    // sum the buffer 16 bits at a time, accumulating in 32 bits to keep carries
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    // if the buffer has an odd length, add the last lone byte
    if (len == 1)
        sum += *(const uint8_t *)ptr;

    // fold the carries (high 16 bits) back into the low 16 bits
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    // one's complement: flip all bits
    return ((uint16_t)~sum);
}
