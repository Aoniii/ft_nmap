#include "ft_nmap.h"
#include "network.h"
#include <stdint.h>

/**
 * @brief scan_type_to_flags - Maps a scan type index to its TCP flags.
 */
uint8_t scan_type_to_flags(int scan_type) {
    switch (scan_type) {
        case SCAN_SYN:  return (TH_SYN);
        case SCAN_NULL: return (0);                          // no flags
        case SCAN_ACK:  return (TH_ACK);
        case SCAN_FIN:  return (TH_FIN);
        case SCAN_XMAS: return (TH_FIN | TH_PSH | TH_URG);
        // SCAN_UDP is handled separately (not TCP flags)
        default:        return (0);
    }
}
