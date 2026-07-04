#include <pcap/pcap.h>

/**
 * @brief get_link_hdr_len - Returns the datalink header size for the handle.
 * The link-layer header sits before the IP header in every captured frame,
 * and its size depends on the interface type. Getting this wrong shifts all
 * header parsing, so we query it from pcap instead of assuming Ethernet.
 */
int get_link_hdr_len(pcap_t *handle) {
    switch (pcap_datalink(handle)) {
        case DLT_EN10MB:                    // standard Ethernet
            return (14);
        case DLT_LINUX_SLL:                 // Linux "cooked" (the 'any' device)
            return (16);
        case DLT_NULL:                      // loopback (BSD)
        case DLT_LOOP:
            return (4);
        case DLT_RAW:                       // raw IP, no link header
            return (0);
        default:
            return (-1);                    // unsupported link type
    }
}
