/*
 $Id$
*/

#include "common.h"
#include "util.h"
#include "proto/protos.h"
#include "master.h"
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#ifdef USE_CAPABILITIES
#include <sys/prctl.h>
#include <sys/capability.h>
#endif

#ifdef HAVE_NETPACKET_PACKET_H
#include <netpacket/packet.h>
#endif /* HAVE_NETPACKET_PACKET_H */
#ifdef HAVE_NET_IF_DL_H
#include <net/if_dl.h>
#endif /* HAVE_NET_IF_DL_H */

#ifdef HAVE_LINUX_FILTER_H
#include <linux/filter.h>
#endif /* HAVE_LINUX_FILTER_H */
#ifdef HAVE_NET_BPF_H
#include <net/bpf.h>
#endif /* HAVE_NET_BPF_H */

#if HAVE_LINUX_SOCKIOS_H
#include <linux/sockios.h>
#endif /* HAVE_LINUX_SOCKIOS_H */

#if HAVE_LINUX_ETHTOOL_H
#include <linux/ethtool.h>
#endif /* HAVE_LINUX_ETHTOOL_H */


#ifdef HAVE_NET_BPF_H
struct bpf_insn master_filter[] = {
#elif HAVE_LINUX_FILTER_H
struct sock_filter master_filter[] = {
#endif
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
    int len;
    char *data;
} bpf_buf;
#endif /* HAVE_NET_BPF_H */

int sock;

extern struct proto protos[];
extern uint8_t loglevel;
extern uint32_t options;

void master_init(struct nhead *netifs, uint16_t netifc,
		 pid_t child, int cmdfd, int msgfd) {

    // raw socket
    int rawfd;

    // interfaces
    struct netif *netif = NULL, *subif = NULL;
    struct master_rfd *rfds = NULL;
    unsigned int i;

    // pcap
    pcap_hdr_t pcap_hdr;

#ifdef USE_CAPABILITIES
    // capabilities
    cap_t caps;
#endif /* USE_CAPABILITIES */

    // events
    struct event ev_cmd;
    struct event ev_sigchld, ev_sigint, ev_sigterm,  ev_sighup;


    // proctitle
    setproctitle("master [priv]");

    // open a regular socket
    sock = my_socket(AF_INET, SOCK_DGRAM, 0);

    // open a raw socket or return stdout on debug
    if (!(options & OPT_DEBUG))
	rawfd = master_rsocket(NULL, O_WRONLY);
    else
	rawfd = fileno(stdout);

    if (rawfd < 0)
	my_fatal("opening raw socket failed");

    // open listen sockets
    if ((options & OPT_RECV) && (!(options & OPT_DEBUG))) {

#ifdef HAVE_NET_BPF_H
	bpf_buf.len = roundup(ETHER_MAX_LEN, getpagesize());
	bpf_buf.data = my_malloc(bpf_buf.len);
#endif /* HAVE_NET_BPF_H */

	// init
	rfds = my_calloc(netifc, sizeof(struct master_rfd));
	i = 0;

	netif = NULL;
	while ((netif = netif_iter(netif, netifs)) != NULL) {
	    my_log(INFO, "starting receive loop with interface %s",
			 netif->name);

	    subif = NULL;
	    while ((subif = subif_iter(subif, netif)) != NULL) {
		my_log(INFO, "listening on %s", subif->name);

		rfds[i].index = subif->index;
		strlcpy(rfds[i].name, subif->name, IFNAMSIZ);
		memcpy(rfds[i].hwaddr, subif->hwaddr, ETHER_ADDR_LEN);
		rfds[i].fd = master_rsocket(&rfds[i], O_RDONLY);
		rfds[i].cfd = msgfd;

		if (rfds[i].fd < 0)
		    my_fatal("opening raw socket failed");

		master_rconf(&rfds[i], protos);

		i++;
	    }
	}

	netifc = i;
    }

    // debug
    if (options & OPT_DEBUG) {

	// listen for packets on stdin
	if (options & OPT_RECV) {
	    i = 0;
	    rfds = my_calloc(1, sizeof(struct master_rfd));
	    rfds[i].fd = 0;
	    rfds[i].cfd = msgfd;
	    netifc = 1;
	}

	// zero
	memset(&pcap_hdr, 0, sizeof(pcap_hdr));

	// create pcap global header
	pcap_hdr.magic_number = PCAP_MAGIC;
	pcap_hdr.version_major = 2;
	pcap_hdr.version_minor = 4;
	pcap_hdr.snaplen = ETHER_MAX_LEN;
	pcap_hdr.network = 1;

	// send pcap global header
	if (write(rawfd, &pcap_hdr, sizeof(pcap_hdr)) != sizeof(pcap_hdr))
	    my_fatal("failed to write pcap global header");
    } else {

	my_chroot(PACKAGE_CHROOT_DIR);

#ifdef USE_CAPABILITIES
	// keep CAP_NET_ADMIN
	caps = cap_from_text("cap_net_admin=ep "
		"cap_net_broadcast=ep cap_kill=ep");

	if (caps == NULL)
	    my_fatal("unable to create capabilities: %s", strerror(errno));

	if (cap_set_proc(caps) == -1)
	    my_fatal("unable to set capabilities: %s", strerror(errno));

	(void) cap_free(caps);
#endif /* USE_CAPABILITIES */
    }


    // initalize the event library
    event_init();

    // listen for requests from the child
    event_set(&ev_cmd, cmdfd, EV_READ|EV_PERSIST, (void *)master_cmd, &rawfd);
    event_add(&ev_cmd, NULL);

    // handle signals
    signal_set(&ev_sigchld, SIGCHLD, master_signal, NULL);
    signal_set(&ev_sigint, SIGINT, master_signal, &child);
    signal_set(&ev_sigterm, SIGTERM, master_signal, &child);
    signal_set(&ev_sighup, SIGHUP, master_signal, NULL);
    signal_add(&ev_sigchld, NULL);
    signal_add(&ev_sigint, NULL);
    signal_add(&ev_sigterm, NULL);
    signal_add(&ev_sighup, NULL);


    // listen for received packets
    if (options & OPT_RECV) {
	for (i = 0; i < netifc; i++) {
	    event_set(&rfds[i].event, rfds[i].fd, EV_READ|EV_PERSIST,
		(void *)master_recv, &rfds[i]);
	    event_add(&rfds[i].event, NULL);
	}
    }

    // wait for events
    event_dispatch();

    // not reached
    exit(EXIT_FAILURE);
}


void master_signal(int sig, short event, void *pid) {
    switch (sig) {
	case SIGCHLD:
	    my_fatal("child has exited");
	    break;
	case SIGINT:
	case SIGTERM:
	    kill(*(pid_t *)pid, sig);
	    my_fatal("quitting");
	    break;
	case SIGHUP:
	    break;
	default:
	    my_fatal("unexpected signal");
    }
}


void master_cmd(int cmdfd, short event, int *rawfd) {
    struct master_msg mreq;
    ssize_t len;


    // receive request
    len = read(cmdfd, &mreq, MASTER_MSG_SIZE);

    if (len <= 0)
	return;

    // check request size
    if (len != MASTER_MSG_SIZE)
	my_fatal("invalid request received");

    // validate request
    if (master_rcheck(&mreq) != EXIT_SUCCESS)
	my_fatal("invalid request supplied");

    switch (mreq.cmd) {
	// transmit packet
	case MASTER_SEND:
	    mreq.len = master_rsend(*rawfd, &mreq);
	    break;
#if HAVE_LINUX_ETHTOOL_H
	// fetch ethtool details
	case MASTER_ETHTOOL:
	    mreq.len = master_ethtool(&mreq);
	    break;
#endif /* HAVE_LINUX_ETHTOOL_H */
#ifdef SIOCSIFDESCR
	// update interface description
	case MASTER_DESCR:
	    mreq.len = master_descr(&mreq);
	    break;
#endif /* SIOCGIFDESCR */
	// invalid request
	default:
	    my_fatal("invalid request received");
    }

    mreq.completed = 1;
    if (write(cmdfd, &mreq, MASTER_MSG_SIZE) != MASTER_MSG_SIZE)
	    my_fatal("failed to return message to child");
}


int master_rcheck(struct master_msg *mreq) {

    assert(mreq);
    assert(mreq->len <= ETHER_MAX_LEN);
    assert(mreq->cmd < MASTER_MAX);

    // validate ifindex
    if (if_indextoname(mreq->index, mreq->name) == NULL) {
	my_log(CRIT, "invalid ifindex supplied");
	return(EXIT_FAILURE);
    }

    switch (mreq->cmd) {
	case MASTER_SEND:
	    assert(mreq->len >= ETHER_MIN_LEN);
	    assert(mreq->proto < PROTO_MAX);
	    assert(protos[mreq->proto].check(mreq->msg, mreq->len) != NULL);
	    return(EXIT_SUCCESS);
#if HAVE_LINUX_ETHTOOL_H
	case MASTER_ETHTOOL:
	    assert(mreq->len == sizeof(struct ethtool_cmd));
	    return(EXIT_SUCCESS);
#endif /* HAVE_LINUX_ETHTOOL_H */
#ifdef SIOCSIFDESCR
	case MASTER_DESCR:
	    assert(mreq->len <= IFDESCRSIZE);
	    return(EXIT_SUCCESS);
#endif /* SIOCSIFDESCR */
	default:
	    return(EXIT_FAILURE);
    }

    return(EXIT_FAILURE);
}


int master_rsocket(struct master_rfd *rfd, int mode) {

    int rsocket = -1;

#ifdef HAVE_NETPACKET_PACKET_H
    struct sockaddr_ll sa;

    rsocket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    // socket open failed
    if (rsocket < 0)
	return(rsocket);

    // return unbound socket if requested
    if (rfd == NULL)
	return(rsocket);

    // bind the socket to rfd
    memset(&sa, 0, sizeof (sa));

    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = rfd->index;
    sa.sll_protocol = htons(ETH_P_ALL);

    if (bind(rsocket, (struct sockaddr *)&sa, sizeof (sa)) != 0)
	my_fatal("failed to bind socket to %s", rfd->name);

#elif HAVE_NET_BPF_H
    int n = 0;
    char dev[50];

    struct ifreq ifr;

    do {
	snprintf(dev, sizeof(dev), "/dev/bpf%d", n++);
	rsocket = open(dev, mode);
    } while (rsocket < 0 && errno == EBUSY);

    // no free bpf available
    if (rsocket < 0)
	return(rsocket);

    // return unbound socket if requested
    if (rfd == NULL)
	return(rsocket);

    // prepare ifr struct
    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, rfd->name, IFNAMSIZ);

    // bind the socket to rfd
    if (ioctl(rsocket, BIOCSETIF, (caddr_t)&ifr) < 0)
	my_fatal("failed to bind socket to %s", rfd->name);
#endif

    return(rsocket);
}


void master_rconf(struct master_rfd *rfd, struct proto *protos) {

    struct ifreq ifr;
    int p;
#ifdef AF_PACKET
    struct packet_mreq mreq;
#elif TARGET_IS_FREEBSD
    struct sockaddr_dl *saddrdl;
#endif

#ifdef HAVE_LINUX_FILTER_H
    // install socket filter
    struct sock_fprog fprog;

    memset(&fprog, 0, sizeof(fprog));
    fprog.filter = master_filter; 
    fprog.len = sizeof(master_filter) / sizeof(struct sock_filter);

    if (setsockopt(rfd->fd, SOL_SOCKET, SO_ATTACH_FILTER,
		   &fprog, sizeof(fprog)) < 0)
	my_fatal("unable to configure socket filter for %s", rfd->name);
#elif HAVE_NET_BPF_H

    // setup bpf receive
    struct bpf_program fprog;
    int immediate = 1;

    memset(&fprog, 0, sizeof(fprog));
    fprog.bf_insns = master_filter; 
    fprog.bf_len = sizeof(master_filter) / sizeof(struct bpf_insn);

    // read buffer length
    if (ioctl(rfd->fd, BIOCGBLEN, (caddr_t)&bpf_buf.len) < 0)
	my_fatal("unable to configure bufer length for %s", rfd->name);
    // disable buffering
    if (ioctl(rfd->fd, BIOCIMMEDIATE, (caddr_t)&immediate) < 0)
	my_fatal("unable to configure immediate mode for %s", rfd->name);
    // install bpf filter
    if (ioctl(rfd->fd, BIOCSETF, (caddr_t)&fprog) < 0)
	my_fatal("unable to configure bpf filter for %s", rfd->name);
#endif

    // configure multicast recv
    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, rfd->name, IFNAMSIZ);

    for (p = 0; protos[p].name != NULL; p++) {

	// only enabled protos
	if ((protos[p].enabled == 0) && !(options & OPT_AUTO))
	    continue;

#ifdef AF_PACKET
	// prepare a packet_mreq struct
	mreq.mr_ifindex = rfd->index;
	mreq.mr_type = PACKET_MR_MULTICAST;
	mreq.mr_alen = ETHER_ADDR_LEN;
	memcpy(mreq.mr_address, protos[p].dst_addr, ETHER_ADDR_LEN);

	if (setsockopt(rfd->fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
		   &mreq, sizeof(mreq)) < 0)
	    my_fatal("unable to add %s multicast to %s: %s",
		     protos[p].name, rfd->name, strerror(errno));
#elif AF_LINK
	// too bad for EDP
	if (!ETHER_IS_MULTICAST(protos[p].dst_addr))
	    continue;

#ifdef TARGET_IS_FREEBSD
	saddrdl = (struct sockaddr_dl *)&ifr.ifr_addr;
	saddrdl->sdl_family = AF_LINK;
	saddrdl->sdl_index = 0;
	saddrdl->sdl_len = sizeof(struct sockaddr_dl);
	saddrdl->sdl_alen = ETHER_ADDR_LEN;
	saddrdl->sdl_nlen = 0;
	saddrdl->sdl_slen = 0;
	memcpy(LLADDR(saddrdl), protos[p].dst_addr, ETHER_ADDR_LEN);
#else
	ifr.ifr_addr.sa_family = AF_UNSPEC;
	memcpy(ifr.ifr_addr.sa_data, protos[p].dst_addr, ETHER_ADDR_LEN);
#endif
	if ((ioctl(sock, SIOCADDMULTI, &ifr) < 0) && (errno != EADDRINUSE))
	    my_fatal("unable to add %s multicast to %s: %s",
		     protos[p].name, rfd->name, strerror(errno));
#endif
    }
}


void master_recv(int fd, short event, struct master_rfd *rfd) {
    // packet
    struct master_msg mrecv;
    struct ether_hdr *ether;
    static unsigned int rcount = 0;
    unsigned int p;
    ssize_t len = 0;
#ifdef HAVE_NET_BPF_H
    struct bpf_hdr *bhp;
    void *endp;
#endif /* HAVE_NET_BPF_H */

    assert(rfd);
    memset(&mrecv, 0, sizeof (mrecv));

#ifdef HAVE_NET_BPF_H
    if ((len = read(rfd->fd, bpf_buf.data, bpf_buf.len)) == -1) {
	my_log(CRIT,"receiving message failed: %s", strerror(errno));
	return;
    }

    bhp = (struct bpf_hdr *)bpf_buf.data;
    endp = bpf_buf.data + len;

    while ((void *)bhp < endp) {

	// with valid sizes
	if (bhp->bh_caplen < ETHER_MAX_LEN)
	    mrecv.len = bhp->bh_caplen;
	else
	    mrecv.len = ETHER_MAX_LEN;

	memcpy(mrecv.msg, bpf_buf.data + bhp->bh_hdrlen, mrecv.len);

#elif HAVE_NETPACKET_PACKET_H
    if ((len = read(rfd->fd, mrecv.msg, ETHER_MAX_LEN)) == -1) {
	my_log(CRIT,"receiving message failed: %s", strerror(errno));
	return;
    }
    mrecv.len = len;
#endif /* HAVE_NETPACKET_PACKET_H */

    // skip small packets
    if (mrecv.len < ETHER_MIN_LEN)
	return;

    // skip locally generated packets
    ether = (struct ether_hdr *)mrecv.msg;
    if (memcmp(rfd->hwaddr, ether->src, ETHER_ADDR_LEN) == 0)
	return;

    // note the command and ifindex
    mrecv.cmd = MASTER_RECV;
    mrecv.index = rfd->index;

    // detect the protocol
    for (p = 0; protos[p].name != NULL; p++) {
	if (memcmp(protos[p].dst_addr, ether->dst, ETHER_ADDR_LEN) != 0)
	    continue;

	mrecv.proto = p;
	break;
    }

    if (protos[p].name == NULL) {
	my_log(INFO, "unknown message type received");
	return;
    }
    my_log(INFO, "received %s message (%d bytes)", protos[p].name, mrecv.len);

    if (write(rfd->cfd, &mrecv, MASTER_MSG_SIZE) != MASTER_MSG_SIZE)
	    my_fatal("failed to send message to child");
    rcount++;

#ifdef HAVE_NET_BPF_H
	bhp += BPF_WORDALIGN(bhp->bh_hdrlen + bhp->bh_caplen);
    }
#endif /* HAVE_NET_BPF_H */
}


size_t master_rsend(int fd, struct master_msg *mreq) {

    size_t count = 0;

    pcaprec_hdr_t pcap_rec_hdr;
    struct timeval tv;

    // debug
    if (options & OPT_DEBUG) {

	// write a pcap record header
	if (gettimeofday(&tv, NULL) == 0) {
	    pcap_rec_hdr.ts_sec = tv.tv_sec;
	    pcap_rec_hdr.ts_usec = tv.tv_usec;
	    pcap_rec_hdr.incl_len = mreq->len;
	    pcap_rec_hdr.orig_len = mreq->len;

	    if (write(fd, &pcap_rec_hdr, sizeof(pcap_rec_hdr))
		    != sizeof(pcap_rec_hdr))
		my_fatal("failed to write pcap record header");
	}

	return(write(fd, mreq->msg, mreq->len));
    }

#ifdef HAVE_NETPACKET_PACKET_H
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof (sa));

    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = mreq->index;
    sa.sll_protocol = htons(ETH_P_ALL);

    count = sendto(fd, mreq->msg, mreq->len, 0,
		   (struct sockaddr *)&sa, sizeof (sa));
#elif HAVE_NET_BPF_H
    struct ifreq ifr;

    // prepare ifr struct
    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, mreq->name, IFNAMSIZ);

    if (ioctl(fd, BIOCSETIF, (caddr_t)&ifr) < 0)
	my_fatal("ioctl failed: %s", strerror(errno));
    count = write(fd, mreq->msg, mreq->len);
#endif

    if (count != mreq->len)
	my_log(WARN, "only %d bytes written: %s", count, strerror(errno));

    return(count);
}


#if HAVE_LINUX_ETHTOOL_H
size_t master_ethtool(struct master_msg *mreq) {

    struct ifreq ifr;
    struct ethtool_cmd ecmd;

    assert(mreq != NULL);

    // prepare ifr struct
    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, mreq->name, IFNAMSIZ);

    // prepare ecmd struct
    memset(&ecmd, 0, sizeof(ecmd));
    ecmd.cmd = ETHTOOL_GSET;
    ifr.ifr_data = (caddr_t)&ecmd;

    if (ioctl(sock, SIOCETHTOOL, &ifr) != -1) {
	memcpy(mreq->msg, &ecmd, sizeof(ecmd));
	return(sizeof(ecmd));
    } else {
	return(0);
    }
}
#endif /* HAVE_LINUX_ETHTOOL_H */

#ifdef SIOCSIFDESCR
size_t master_descr(struct master_msg *mreq) {

    struct ifreq ifr;
    int ret;

    assert(mreq != NULL);

    // prepare ifr struct
    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, mreq->name, IFNAMSIZ);
    ifr.ifr_data = (caddr_t)&mreq->msg;

    if ((ret = ioctl(sock, SIOCSIFDESCR, &ifr)) == -1)
	ret = 0;
    return(ret);
}
#endif /* SIOCGIFDESCR */

