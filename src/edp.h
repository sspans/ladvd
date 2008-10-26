
#ifndef _edp_h
#define _edp_h

#define EDP_MULTICAST_ADDR { 0x00, 0xe0, 0x2b, 0x00, 0x00, 0x00 }
#define LLC_ORG_EXTREME { 0x00, 0xe0, 0x2b }
#define LLC_PID_EDP 0x00bb

struct edp_header {
    uint8_t version;
    uint8_t reserved;
    uint16_t length;
    uint16_t checksum;
    uint16_t sequence;
    uint16_t id_type; /* currently 2 0 octets */
    uint8_t hwaddr[ETHER_ADDR_LEN];
} __attribute__ ((__packed__));

// EDP Types
#define EDP_TYPE_NULL	    0x00
#define EDP_TYPE_DISPLAY    0x01
#define EDP_TYPE_INFO	    0x02
#define EDP_TYPE_VLAN	    0x05
#define EDP_TYPE_ESRP	    0x08

#endif /* _edp_h */
