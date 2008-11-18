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

extern unsigned int do_debug;
extern unsigned int do_recv;

void master_init(struct netif *netifs, int ac, struct passwd *pwd, int cmdfd) {

    // raw socket
    int rawfd;

    // interfaces
    struct netif *netif = NULL, *subif = NULL;

    // pcap
    pcap_hdr_t pcap_hdr;

#ifdef USE_CAPABILITIES
    // capabilities
    cap_t caps;
#endif /* USE_CAPABILITIES */

    // select set
    fd_set rset;
    int nfds;
    size_t len;

    // packet
    struct master_request mreq;

    // proctitle
    setproctitle("master [priv]");

    // open a raw socket
    rawfd = master_rsocket();

    if (rawfd < 0)
	my_fatal("opening raw socket failed");

    // open listen sockets
    if (do_recv != 0) {

	netif = netifs;
	while ((netif = netif_iter(netif, ac)) != NULL) {
	    my_log(INFO, "starting receive loop with interface %s",
			 netif->name);

	    while ((subif = subif_iter(subif, netif)) != NULL) {
		my_log(INFO, "listening on %s", subif->name);
		//rawfd = master_rsocket();
	    }

	    netif = netif->next;
	}
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

	my_chroot(PACKAGE_CHROOT_DIR);
	my_drop_privs(pwd);

	// keep CAP_NET_ADMIN
	caps = cap_from_text("cap_net_admin=ep");

	if (caps == NULL)
	    my_fatal("unable to create capabilities: %s", strerror(errno));

	if (cap_set_proc(caps) == -1)
	    my_fatal("unable to set capabilities: %s", strerror(errno));

	(void) cap_free(caps);
#else
	if (do_recv == 0) {
	    my_chroot(PACKAGE_CHROOT_DIR);
	    my_drop_privs(pwd);
	}
#endif /* USE_CAPABILITIES */
    }


    FD_ZERO(&rset);
    FD_SET(cmdfd, &rset);
    nfds = cmdfd + 1;

    while (select(nfds, &rset, NULL, NULL, NULL) > 0) {

	if (FD_ISSET(cmdfd, &rset)) {

	    len = recv(cmdfd, &mreq, MASTER_REQ_SIZE, MSG_DONTWAIT);

	    if (len == 0)
		continue;

	    if (len != MASTER_REQ_SIZE)
		my_fatal("invalid request received");

	    // validate request
	    if (master_rcheck(&mreq) != EXIT_SUCCESS)
		my_fatal("invalid request supplied");

	    if (mreq.cmd == MASTER_SEND) {
		mreq.len = master_rsend(rawfd, &mreq);
		mreq.completed = 1;
		write(cmdfd, &mreq, MASTER_REQ_SIZE);
	    /*
	    } else if (mreq.cmd == MASTER_RECV) {
		validate(ifindex);
		open(ifindex);
		fd=foo;
	    */
#if HAVE_LINUX_ETHTOOL_H
	    } else if (mreq.cmd == MASTER_ETHTOOL) {
		mreq.len = master_ethtool(rawfd, &mreq);
		mreq.completed = 1;
		write(cmdfd, &mreq, MASTER_REQ_SIZE);
#endif /* HAVE_LINUX_ETHTOOL_H */
	    } else {
		my_fatal("invalid request received");
	    }
	}

	/*
	for (i = 0; netfd[i].fd != 0; i++) {
	    if (!FD_ISSET(netfd[i].fd, &rset))
		continue;
	
	    buffer.ifindex = netfd[i].index;
	    recvfrom(netfd[i].fd, buffer.msg);

	    write(child, buffer);
	}
	*/
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

int master_rsocket() {

    int socket = -1;

    // return stdout on debug
    if (do_debug != 0)
	return(1);

#ifdef HAVE_NETPACKET_PACKET_H
    socket = my_socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
#elif HAVE_NET_BPF_H
    int n = 0;
    char *dev;

    do {
	if (asprintf(&dev, "/dev/bpf%d", n++) == -1) {
	    my_log(CRIT, "failed to allocate buffer");
	    return(-1);
	}
	socket = open(dev, O_WRONLY);
    } while (socket < 0 && errno == EBUSY);
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
	my_log(CRIT, "ioctl failed: %s", strerror(errno));
	return(-1);
    }
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

