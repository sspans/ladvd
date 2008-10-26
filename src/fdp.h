
#ifndef _fdp_h
#define _fdp_h

#define FDP_VERSION 1
#define FDP_MULTICAST_ADDR { 0x01, 0xe0, 0x52, 0xcc, 0xcc, 0xcc }
#define LLC_ORG_FOUNDRY { 0x00, 0xe0, 0x52 }
#define LLC_PID_FDP 0x2000

struct fdp_header {
    uint8_t version;
    uint8_t ttl;
    uint16_t checksum;
} __attribute__ ((__packed__));

// FDP TLV Types
#define FDP_TYPE_DEVICE_ID	0x0001
#define FDP_TYPE_ADDRESS	0x0002
#define FDP_TYPE_PORT_ID	0x0003
#define FDP_TYPE_CAPABILITIES	0x0004
#define FDP_TYPE_SW_VERSION	0x0005
#define FDP_TYPE_PLATFORM	0x0006
#define FDP_TYPE_FILLER		0x0101
#define FDP_TYPE_UNKNOWN_102	0x0102

#endif /* _fdp_h */
