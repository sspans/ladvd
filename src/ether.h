
#ifndef _ether_h
#define _ether_h

#if HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif

// IEEE 802.3 Ethernet
struct ether_hdr {
    uint8_t dst[ETHER_ADDR_LEN];
    uint8_t src[ETHER_ADDR_LEN];
    union {
	uint8_t type[ETHER_TYPE_LEN];
	uint8_t length[ETHER_TYPE_LEN];
    };
} __attribute__ ((__packed__));

// IEEE 802.2 LLC
struct ether_llc {
    struct ether_hdr ether;
    uint8_t dsap;
    uint8_t ssap;
    uint8_t control;
    uint8_t org[3];
    uint16_t protoid;
} __attribute__ ((__packed__));

#endif /* _common_h */
