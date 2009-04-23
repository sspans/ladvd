
#ifndef _master_h
#define _master_h

#include <sys/time.h>
#include <event.h>

#define MASTER_SEND	0
#define MASTER_RECV	1
#define MASTER_ETHTOOL	2
#define MASTER_DESCR	3

struct master_msg {
    uint32_t index;
    char name[IFNAMSIZ];
    uint8_t cmd;
    uint8_t completed;
    char msg[ETHER_MAX_LEN];
    size_t len;
    uint8_t proto;
    time_t ttl;
    TAILQ_ENTRY(master_msg) entries;
};

TAILQ_HEAD(mhead, master_msg);
#define MASTER_MSG_SIZE   sizeof(struct master_msg)

struct master_rfd {
    uint32_t index;
    char name[IFNAMSIZ];
    uint8_t hwaddr[ETHER_ADDR_LEN];
    int fd;
    int cfd;
    struct event event;
};

void master_init(struct nhead *, uint16_t netifc, int ac,
		 int cmdfd, int msgfd);
void master_signal(int fd, short event, void *p);
void master_cmd(int fd, short event, int *rawfd);
void master_recv(int fd, short event, struct master_rfd *rfd);
int master_rcheck(struct master_msg *mreq);
int master_rsocket(struct master_rfd *rfd, int mode);
void master_rconf(struct master_rfd *rfd, struct proto *protos);
size_t master_rsend(int s, struct master_msg *mreq);
#if HAVE_LINUX_ETHTOOL_H
size_t master_ethtool(int s, struct master_msg *mreq);
#endif /* HAVE_LINUX_ETHTOOL_H */
#ifdef SIOCSIFDESCR
size_t master_descr(int s, struct master_msg *mreq);
#endif /* SIOCSIFDESCR */

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
