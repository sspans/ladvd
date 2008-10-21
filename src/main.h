
#ifndef _main_h
#define _main_h

#define SLEEPTIME   30

struct proto {
    const char *name;
    uint8_t enabled;
    uint8_t received;
    size_t (*build_packet) (struct packet *, struct netif *, struct sysinfo *);
};

#define PROTO_LLDP  0
#define PROTO_CDP   1
#define PROTO_EDP   2
#define PROTO_FDP   3
#define PROTO_SONMP 4

// supported protocols
struct proto protos[] = {
    { "LLDP", 1, 0, &lldp_packet },
    { "CDP",  0, 0, &cdp_packet },
//  { "EDP",  0, 0, &edp_packet },
//  { "FDP",  0, 0, &fdp_packet },
//  { "SONMP",0, 0, &sonmp_packet },
    { NULL, 0, 0, NULL },
};

#endif /* _main_h */
