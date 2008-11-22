/*
 $Id$
*/

#include "common.h"
#include "util.h"
#include "master.h"
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifdef USE_CAPABILITIES
#include <sys/prctl.h>
#include <sys/capability.h>
#endif

#ifdef HAVE_NETPACKET_PACKET_H
#include <netpacket/packet.h>
#endif /* HAVE_NETPACKET_PACKET_H */
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

#include "lldp.h"
#include "cdp.h"
#include "edp.h"
#include "fdp.h"
#include "ndp.h"

#define max(a,b) ((a)<(b)?(b):(a))

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

extern unsigned int do_debug;
extern unsigned int do_recv;

void master_init(struct netif *netifs, uint16_t netifc, int ac,
		 struct passwd *pwd, int cmdfd) {

    // raw socket
    int rawfd;

    // interfaces
    struct netif *netif = NULL, *subif = NULL;
    struct master_rfd *rfds = NULL;

    // pcap
    pcap_hdr_t pcap_hdr;

#ifdef USE_CAPABILITIES
    // capabilities
    cap_t caps;
#endif /* USE_CAPABILITIES */

    // select set
    fd_set rset;
    int nfds, i, rcount = 0;
    size_t len;

    // packet
    struct master_request mreq, *rbuf = NULL, *mrecv;
    struct ether_hdr *ether;

    // proctitle
    setproctitle("master [priv]");

    // open a raw socket
    rawfd = master_rsocket(NULL);

    if (rawfd < 0)
	my_fatal("opening raw socket failed");

    // open listen sockets
    if (do_recv != 0) {

	// init
	netif = netifs;
	rfds = my_calloc(netifc, sizeof(struct master_rfd));
	i = 0;

	while ((netif = netif_iter(netif, ac)) != NULL) {
	    my_log(INFO, "starting receive loop with interface %s",
			 netif->name);

	    while ((subif = subif_iter(subif, netif)) != NULL) {
		my_log(INFO, "listening on %s", subif->name);

		rfds[i].index = subif->index;
		strlcpy(rfds[i].name, subif->name, IFNAMSIZ);
		memcpy(rfds[i].hwaddr, subif->hwaddr, ETHER_ADDR_LEN);
		rfds[i].fd = master_rsocket(&rfds[i]);

		i++;
	    }

	    netif = netif->next;
	}

	netifc = i;
	rbuf = my_calloc(netifc, sizeof(*rbuf));
    }

    // debug
    if (do_debug != 0) {

	// zero
	memset(&pcap_hdr, 0, sizeof(pcap_hdr));

	// create pcap global header
	pcap_hdr.magic_number = PCAP_MAGIC;
	pcap_hdr.version_major = 2;
	pcap_hdr.version_minor = 4;
	pcap_hdr.snaplen = ETHER_MAX_LEN;
	pcap_hdr.network = 1;

	// send pcap global header
	write(rawfd, &pcap_hdr, sizeof(pcap_hdr));
    } else {

#ifdef USE_CAPABILITIES
	// keep capabilities
	if (prctl(PR_SET_KEEPCAPS,1) == -1)
	    my_fatal("unable to keep capabilities: %s", strerror(errno));
#endif /* USE_CAPABILITIES */

	my_chroot(PACKAGE_CHROOT_DIR);
	my_drop_privs(pwd);

#ifdef USE_CAPABILITIES
	// keep CAP_NET_ADMIN
	caps = cap_from_text("cap_net_admin=ep");

	if (caps == NULL)
	    my_fatal("unable to create capabilities: %s", strerror(errno));

	if (cap_set_proc(caps) == -1)
	    my_fatal("unable to set capabilities: %s", strerror(errno));

	(void) cap_free(caps);
#endif /* USE_CAPABILITIES */
    }


    FD_ZERO(&rset);
    FD_SET(cmdfd, &rset);
    nfds = cmdfd;

    if (do_recv != 0) {
	for (i = 0; i < netifc; i++) {
	    FD_SET(rfds[i].fd, &rset);
	    nfds = max(nfds, rfds[i].fd);
	}
    }

    nfds++;

    while (select(nfds, &rset, NULL, NULL, NULL) > 0) {

	if (FD_ISSET(cmdfd, &rset)) {

	    // receive request
	    len = recv(cmdfd, &mreq, MASTER_REQ_SIZE, MSG_DONTWAIT);

	    if (len == 0)
		continue;

	    // check request size
	    if (len != MASTER_REQ_SIZE)
		my_fatal("invalid request received");

	    // validate request
	    if (master_rcheck(&mreq) != EXIT_SUCCESS)
		my_fatal("invalid request supplied");

	    // transmit packet
	    if (mreq.cmd == MASTER_SEND) {
		mreq.len = master_rsend(rawfd, &mreq);
		mreq.completed = 1;
		write(cmdfd, &mreq, MASTER_REQ_SIZE);
#if HAVE_LINUX_ETHTOOL_H
	    // fetch ethtool details
	    } else if (mreq.cmd == MASTER_ETHTOOL) {
		mreq.len = master_ethtool(rawfd, &mreq);
		mreq.completed = 1;
		write(cmdfd, &mreq, MASTER_REQ_SIZE);
#endif /* HAVE_LINUX_ETHTOOL_H */
	    // invalid request
	    } else {
		my_fatal("invalid request received");
	    }
	} else {
	    FD_SET(cmdfd, &rset);
	}

	if (do_recv == 0)
	    continue;

	for (i = 0; i < netifc; i++) {

	    // skip
	    if (!FD_ISSET(rfds[i].fd, &rset)) {
		FD_SET(rfds[i].fd, &rset);
		continue;
	    }

	    // skip if the buffer is full
	    if (rcount >= netifc)
		continue;

	    mrecv = &rbuf[rcount];
	    mrecv->index = rfds[i].index;
	    mrecv->len = recv(rfds[i].fd, mrecv->msg, 
			      ETHER_MAX_LEN, MSG_DONTWAIT);

	    // skip small packets
	    if (mrecv->len < ETHER_MIN_LEN)
		continue;

	    // skip locally generated packets
	    ether = (struct ether_hdr *)mrecv->msg;
	    if (memcmp(rfds[i].hwaddr, ether->src, ETHER_ADDR_LEN) == 0)
		continue;

	    rcount++;
	}
    }
}


int master_rcheck(struct master_request *mreq) {
    struct ether_hdr ether;
    struct ether_llc llc;

    // validate ifindex
    if (if_indextoname(mreq->index, mreq->name) == NULL) {
	my_log(CRIT, "invalid ifindex supplied");
	return(EXIT_FAILURE);
    }

    if (mreq->len > ETHER_MAX_LEN) {
	my_log(CRIT, "invalid message length supplied");
	return(EXIT_FAILURE);
    }

    if (mreq->cmd == MASTER_SEND) {
	memcpy(&ether, mreq->msg, sizeof(ether));
	memcpy(&llc, mreq->msg + sizeof(ether), sizeof(llc));

	// lldp
	static uint8_t lldp_dst[] = LLDP_MULTICAST_ADDR;

	if ((memcmp(ether.dst, lldp_dst, ETHER_ADDR_LEN) == 0) &&
	    (ether.type == htons(ETHERTYPE_LLDP))) {
	    return(EXIT_SUCCESS);
	}

	// cdp
	const uint8_t cdp_dst[] = CDP_MULTICAST_ADDR;
	const uint8_t cdp_org[] = LLC_ORG_CISCO;

	if ((memcmp(ether.dst, cdp_dst, ETHER_ADDR_LEN) == 0) &&
	    (memcmp(llc.org, cdp_org, sizeof(llc.org)) == 0) &&
	    (llc.protoid == htons(LLC_PID_CDP))) {
	    return(EXIT_SUCCESS);
	}

	// edp
	const uint8_t edp_dst[] = EDP_MULTICAST_ADDR;
	const uint8_t edp_org[] = LLC_ORG_EXTREME;

	if ((memcmp(ether.dst, edp_dst, ETHER_ADDR_LEN) == 0) &&
	    (memcmp(llc.org, edp_org, sizeof(llc.org)) == 0) &&
	    (llc.protoid == htons(LLC_PID_EDP))) {
	    return(EXIT_SUCCESS);
	}

	// fdp
	const uint8_t fdp_dst[] = FDP_MULTICAST_ADDR;
	const uint8_t fdp_org[] = LLC_ORG_FOUNDRY;

	if ((memcmp(ether.dst, fdp_dst, ETHER_ADDR_LEN) == 0) &&
	    (memcmp(llc.org, fdp_org, sizeof(llc.org)) == 0) &&
	    (llc.protoid == htons(LLC_PID_FDP))) {
	    return(EXIT_SUCCESS);
	}

	// ndp
	const uint8_t ndp_dst[] = NDP_MULTICAST_ADDR;
	const uint8_t ndp_org[] = LLC_ORG_NORTEL;

	if ((memcmp(ether.dst, ndp_dst, ETHER_ADDR_LEN) == 0) &&
	    (memcmp(llc.org, ndp_org, sizeof(llc.org)) == 0) &&
	    (llc.protoid == htons(LLC_PID_NDP_HELLO))) {
	    return(EXIT_SUCCESS);
	}
    }

#if HAVE_LINUX_ETHTOOL_H
    if (mreq->cmd == MASTER_ETHTOOL) {
	if (mreq->len == sizeof(struct ethtool_cmd)) 
	    return(EXIT_SUCCESS);
    }
#endif /* HAVE_LINUX_ETHTOOL_H */

    return(EXIT_FAILURE);
}

int master_rsocket(struct master_rfd *rfd) {

    int socket = -1;

    // return stdout on debug
    if ((do_debug != 0) && (rfd == NULL))
	return(1);

#ifdef HAVE_NETPACKET_PACKET_H
    socket = my_socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    // return unbound socket if requested
    if (rfd == NULL)
	return(socket);

    // bind the socket to rfd
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof (sa));

    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = rfd->index;
    sa.sll_protocol = htons(ETH_P_ALL);

    if (bind(socket, (struct sockaddr *)&sa, sizeof (sa)) != 0)
	my_fatal("failed to bind socket to %s", rfd->name);

#ifdef HAVE_LINUX_FILTER_H
    // install socket filter
    struct sock_fprog fprog;

    memset(&fprog, 0, sizeof(fprog));
    fprog.filter = master_filter; 
    fprog.len = sizeof(master_filter) / sizeof(struct sock_filter);

    if (setsockopt(socket, SOL_SOCKET, SO_ATTACH_FILTER,
		   &fprog, sizeof(fprog)) < 0)
	my_fatal("unable to configure socket filter for %s", rfd->name);
#endif /* HAVE_LINUX_FILTER_H */

#elif HAVE_NET_BPF_H
    int n = 0;
    char *dev;

    do {
	if (asprintf(&dev, "/dev/bpf%d", n++) == -1)
	    my_fatal("failed to allocate buffer for /dev/bpf");
	socket = open(dev, O_WRONLY);
    } while (socket < 0 && errno == EBUSY);

    // return unbound socket if requested
    if (rfd == NULL)
	return(socket);

    // bind the socket to rfd
    struct ifreq ifr;

    // prepare ifr struct
    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, rfd->name, IFNAMSIZ);

    if (ioctl(socket, BIOCSETIF, (caddr_t)&ifr) < 0) {
	my_fatal("failed to bind socket to %s", rfd->name);

    // install bpf filter
    struct bpf_program fprog;

    memset(&fprog, 0, sizeof(fprog));
    fprog.bf_insns = &master_filter; 
    fprog.bf_len = sizeof(master_filter) / sizeof(struct sock_filter);

    if (ioctl(socket, BIOCSETF, (caddr_t)&prog) < 0) {
	my_fatal("unable to configure bpf filter for %s", rfd->name);
#endif

    return(socket);
}


size_t master_rsend(int s, struct master_request *mreq) {

    size_t count = 0;

    pcaprec_hdr_t pcap_rec_hdr;
    struct timeval tv;

    // debug
    if (do_debug != 0) {

	// write a pcap record header
	if (gettimeofday(&tv, NULL) == 0) {
	    pcap_rec_hdr.ts_sec = tv.tv_sec;
	    pcap_rec_hdr.ts_usec = tv.tv_usec;
	    pcap_rec_hdr.incl_len = mreq->len;
	    pcap_rec_hdr.orig_len = mreq->len;

	    (void) write(s, &pcap_rec_hdr, sizeof(pcap_rec_hdr));
	}

	return(write(s, mreq->msg, mreq->len));
    }

#ifdef HAVE_NETPACKET_PACKET_H
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof (sa));

    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = mreq->index;
    sa.sll_protocol = htons(ETH_P_ALL);

    count = sendto(s, mreq->msg, mreq->len, 0, (struct sockaddr *)&sa, sizeof (sa));
#elif HAVE_NET_BPF_H
    struct ifreq ifr;

    // prepare ifr struct
    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, mreq->name, IFNAMSIZ);

    if (ioctl(s, BIOCSETIF, (caddr_t)&ifr) < 0) {
	my_fatal("ioctl failed: %s", strerror(errno));
    count = write(s, mreq->msg, mreq->len);
#endif

    if (count != mreq->len)
	my_log(WARN, "only %d bytes written: %s", count, strerror(errno));
    
    return(count);
}

#if HAVE_LINUX_ETHTOOL_H
size_t master_ethtool(int s, struct master_request *mreq) {

    struct ifreq ifr;
    struct ethtool_cmd ecmd;

    // prepare ifr struct
    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, mreq->name, IFNAMSIZ);

    // prepare ecmd struct
    memset(&ecmd, 0, sizeof(ecmd));
    ecmd.cmd = ETHTOOL_GSET;
    ifr.ifr_data = (caddr_t)&ecmd;

    if (ioctl(s, SIOCETHTOOL, &ifr) >= 0) {
	memcpy(mreq->msg, &ecmd, sizeof(ecmd));
	return(sizeof(ecmd));
    } else {
	return(0);
    }
}
#endif /* HAVE_LINUX_ETHTOOL_H */

