
#ifndef _master_h
#define _master_h

#include <sys/ioctl.h>

#ifdef HAVE_LINUX_FILTER_H
#include <linux/types.h>
#include <linux/filter.h>
#endif /* HAVE_LINUX_FILTER_H */
#ifdef HAVE_NET_BPF_H
#include <net/bpf.h>
#endif /* HAVE_NET_BPF_H */

#ifdef HAVE_NET_BPF_H
#define SOCKET_FILTER	    struct bpf_isn
#elif defined HAVE_LINUX_FILTER_H
#define SOCKET_FILTER	    struct sock_filter
#endif

SOCKET_FILTER reject_filter[] = {
    // reject
    BPF_STMT(BPF_RET+BPF_K, 0)
};
SOCKET_FILTER proto_filter[] = {
    // lldp
    // ether 01:80:c2:00:00:0e
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 0),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x0180C200, 0, 5),
    BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 4),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x0000000E, 0, 3),
    // ether proto 
    BPF_STMT(BPF_LD+BPF_H+BPF_ABS, ETHER_ADDR_LEN * 2),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_LLDP, 0, 1),
    // accept
    BPF_STMT(BPF_RET+BPF_K, (u_int)-1),

    // llc dsap & ssap
    BPF_STMT(BPF_LD+BPF_H+BPF_ABS, ETHER_HDR_LEN),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0xAAAA, 1, 0),
    // reject
    BPF_STMT(BPF_RET+BPF_K, 0),

    // cdp
    // ether dst 01:00:0c:cc:cc:cc
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 0),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x01000CCC, 0, 7),
    BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 4),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x0000CCCC, 0, 5),
    // llc control + org
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, ETH_LLC_CONTROL),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x0300000C, 0, 3),
    // llc protoid
    BPF_STMT(BPF_LD+BPF_H+BPF_ABS, ETH_LLC_PROTOID),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, LLC_PID_CDP, 0, 1),
    // accept
    BPF_STMT(BPF_RET+BPF_K, (u_int)-1),

    // edp
    // ether dst 00:0e:2b:cc:cc:cc
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 0),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x000E2B00, 0, 7),
    BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 4),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x00000000, 0, 5),
    // llc control + org
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, ETH_LLC_CONTROL),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x03000E2B, 0, 3),
    // llc protoid
    BPF_STMT(BPF_LD+BPF_H+BPF_ABS, ETH_LLC_PROTOID),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, LLC_PID_EDP, 0, 1),
    // accept
    BPF_STMT(BPF_RET+BPF_K, (u_int)-1),

    // fdp
    // ether dst 01:e0:52:cc:cc:cc
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 0),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x01E052CC, 0, 7),
    BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 4),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x0000CCCC, 0, 5),
    // llc control + org
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, ETH_LLC_CONTROL),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x0300E052, 0, 3),
    // llc protoid
    BPF_STMT(BPF_LD+BPF_H+BPF_ABS, ETH_LLC_PROTOID),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, LLC_PID_FDP, 0, 1),
    // accept
    BPF_STMT(BPF_RET+BPF_K, (u_int)-1),

    // ndp
    // ether dst 01:00:81:00:01:00
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 0),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x01008100, 0, 7),
    BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 4),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x00000100, 0, 5),
    // llc control + org
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, ETH_LLC_CONTROL),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x03000081, 0, 3),
    // llc protoid
    BPF_STMT(BPF_LD+BPF_H+BPF_ABS, ETH_LLC_PROTOID),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, LLC_PID_NDP_HELLO, 0, 1),
    // accept
    BPF_STMT(BPF_RET+BPF_K, (u_int)-1),

    // reject
    BPF_STMT(BPF_RET+BPF_K, 0)
};

#ifdef HAVE_NET_BPF_H
struct bpf_buf {
    unsigned int len;
    char *data;
};
struct bpf_buf bpf_buf = { 0, NULL };
#endif /* HAVE_NET_BPF_H */

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

    // should be last
    TAILQ_ENTRY(rawfd) entries;
};

TAILQ_HEAD(rfdhead, rawfd);
struct rfdhead rawfds;

void master_signal(int fd, short event, void *pid);
void master_cmd(int fd, short event);
void master_recv(int fd, short event, struct rawfd *rfd);

ssize_t master_send(struct master_msg *mreq);
void master_open(struct master_msg *mreq);
#if HAVE_LINUX_ETHTOOL_H
size_t master_ethtool(struct master_msg *mreq);
#endif /* HAVE_LINUX_ETHTOOL_H */
#ifdef SIOCSIFDESCR
size_t master_descr(struct master_msg *mreq);
#endif /* SIOCSIFDESCR */
void master_close(struct master_msg *mreq);

int master_check(struct master_msg *mreq);
int master_socket(struct rawfd *rfd);
void master_multi(struct rawfd *rfd, struct proto *protos, int op);
inline struct rawfd *rfd_byindex(struct rfdhead *, uint32_t index);

#endif /* _master_h */
