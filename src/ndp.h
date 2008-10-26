
#ifndef _ndp_h
#define _ndp_h

#define NDP_MULTICAST_ADDR { 0x01, 0x00, 0x81, 0x00, 0x01, 0x00 }
#define LLC_ORG_NORTEL { 0x00, 0x00, 0x81 }
#define LLC_PID_NDP_HELLO 0x01a2

struct ndp_header {
    uint32_t addr;
    uint8_t seg[3];
    uint8_t chassis;
    uint8_t backplane;
    uint8_t state;
    uint8_t links;
} __attribute__ ((__packed__));

#define NDP_CHASSIS_OTHER	1

#define NDP_BACKPLANE_OTHER		1
#define NDP_BACKPLANE_ETH		2
#define NDP_BACKPLANE_ETH_TR		3
#define NDP_BACKPLANE_ETH_FDDI		4
#define NDP_BACKPLANE_ETH_TR_FDDI	5
#define NDP_BACKPLANE_ETH_TR_RP		6
#define NDP_BACKPLANE_ETH_TR_FDDI_RP	7
#define NDP_BACKPLANE_TR		8
#define NDP_BACKPLANE_ETH_TR_FE		9
#define NDP_BACKPLANE_ETH_FE		10
#define NDP_BACKPLANE_ETH_TR_FE_RP	11
#define NDP_BACKPLANE_ETH_FE_GE		12

#define NDP_TOPOLOGY_CHANGED	1
#define NDP_TOPOLOGY_UNCHANGED  2
#define NDP_TOPOLOGY_NEW	3

#endif /* _ndp_h */
