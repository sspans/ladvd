
#ifndef _master_h
#define _master_h

#include <sys/ioctl.h>

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

struct rawfd {
    uint32_t index;
    char name[IFNAMSIZ];
    int fd;
    struct event event;

#ifdef HAVE_NET_BPF_H
    struct {
	unsigned int len;
	char *data;
    } bpf_buf;
#endif /* HAVE_NET_BPF_H */

    // should be last
    TAILQ_ENTRY(rawfd) entries;
};

TAILQ_HEAD(rfdhead, rawfd);

void master_signal(int fd, short event, void *pid);
void master_cmd(int fd, short event);
void master_recv(int fd, short event, struct rawfd *rfd);

ssize_t master_send(struct master_msg *mreq);
void master_open(struct master_msg *mreq);
#if HAVE_LINUX_ETHTOOL_H
ssize_t master_ethtool(struct master_msg *mreq);
#endif /* HAVE_LINUX_ETHTOOL_H */
#ifdef SIOCSIFDESCR
ssize_t master_descr(struct master_msg *mreq);
#endif /* SIOCSIFDESCR */
#ifdef HAVE_SYSFS
ssize_t master_device(struct master_msg *mreq);
#endif /* HAVE_SYSFS */
void master_close(struct rawfd *rfd);

int master_check(struct master_msg *mreq);
int master_socket(struct rawfd *rfd);
void master_multi(struct rawfd *rfd, struct proto *protos, int op);
inline struct rawfd *rfd_byindex(struct rfdhead *, uint32_t index);
inline void rfd_closeall(struct rfdhead *);

#endif /* _master_h */
