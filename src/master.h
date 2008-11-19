
#ifndef _master_h
#define _master_h

#include <pwd.h>

#define MASTER_SEND	0
#define MASTER_RECV	1
#define MASTER_ETHTOOL	2

struct master_request {
    uint32_t index;
    char name[IFNAMSIZ];
    uint8_t cmd;
    uint8_t completed;
    char msg[ETHER_MAX_LEN];
    size_t len;
};

#define MASTER_REQ_SIZE   sizeof(struct master_request)

struct master_rfd {
    uint32_t index;
    char name[IFNAMSIZ];
    int fd;
};

void master_init(struct netif *, uint16_t netifc, int ac,
		 struct passwd *pwd, int cmdfd);
int master_rcheck(struct master_request *mreq);
int master_rsocket(struct master_rfd *rfd);
size_t master_rsend(int s, struct master_request *mreq);
#if HAVE_LINUX_ETHTOOL_H
size_t master_ethtool(int s, struct master_request *mreq);
#endif /* HAVE_LINUX_ETHTOOL_H */

#define PCAP_MAGIC	0xA1B2C3D4

typedef struct pcap_hdr_s {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
} __attribute__ ((__packed__)) pcap_hdr_t;

typedef struct pcaprec_hdr_s {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
} __attribute__ ((__packed__)) pcaprec_hdr_t;

#endif /* _master_h */
