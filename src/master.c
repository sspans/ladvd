/*
 $Id$
*/

#include "common.h"
#include "util.h"
#include "master.h"
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

extern unsigned int do_debug;

void master_init(struct passwd *pwd, int cmdfd) {

    // raw socket
    int rawfd;

    // pcap
    pcap_hdr_t pcap_hdr;

    // select set
    fd_set rset;
    int nfds;
    size_t len;

    // packet
    struct master_request mreq;

    // nameindex
    struct if_nameindex *ifs;

#ifdef USE_CAPABILITIES
    // capabilities
    cap_t caps;

    // keep capabilities
    if (prctl(PR_SET_KEEPCAPS,1) == -1) {
	my_log(CRIT, "unable to keep capabilities: %s", strerror(errno));
	exit(EXIT_FAILURE);
    }

    my_drop_privs(pwd);

    // keep CAP_NET_ADMIN
    caps = cap_from_text("cap_net_admin=ep");

    if (caps == NULL) {
	my_log(CRIT, "unable to create capabilities: %s", strerror(errno));
	exit(EXIT_FAILURE);
    }

    if (cap_set_proc(caps) == -1) {
	my_log(CRIT, "unable to set capabilities: %s", strerror(errno));
	exit(EXIT_FAILURE);
    }

    (void) cap_free(caps);
#endif /* USE_CAPABILITIES */

    // open a raw socket
    rawfd = master_rsocket();

    if (rawfd < 0) {
	my_log(CRIT, "opening raw socket failed");
	exit(EXIT_FAILURE);
    }

    // proctitle
    setproctitle("master [priv]");

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
    }


    FD_ZERO(&rset);
    FD_SET(cmdfd, &rset);
    nfds = cmdfd + 1;

    while (select(nfds, &rset, NULL, NULL, NULL) > 0) {

	if (FD_ISSET(cmdfd, &rset)) {

	    len = recv(cmdfd, &mreq, MASTER_REQ_SIZE, MSG_DONTWAIT);

	    if (len == 0)
		continue;

	    if (len != MASTER_REQ_SIZE) {
		my_log(CRIT, "invalid request received");
		exit(EXIT_FAILURE);
	    }

	    // fetch nameindex
	    ifs = if_nameindex();

	    if (ifs == NULL) {
		my_log(CRIT, "couldn't list interfaces");
		exit(EXIT_FAILURE);
	    }

	    if (if_indextoname(mreq.index, mreq.name) == NULL) {
		my_log(CRIT, "invalid ifindex supplied");
		exit(EXIT_FAILURE);
	    }

	    if (mreq.len > ETHER_MAX_LEN) {
		my_log(CRIT, "invalid message lenght supplied");
		exit(EXIT_FAILURE);
	    }

	    if (mreq.cmd == MASTER_SEND) {
		mreq.len = master_rsend(rawfd, &mreq);
		mreq.completed = 1;
		write(cmdfd, &mreq, MASTER_REQ_SIZE);
	    /*
	    } else if (mreq.cmd == MASTER_RECV) {
		validate(ifindex);
		open(ifindex);
		fd=foo;
	    } else if (mreq.cmd == MASTER_ETHTOOL) {
		validate(ifindex);
		ethtool = ethtool(ifindex);
		write(child, ethtool);
	    } else {
		my_log(CRIT, "invalid request received");
		exit(EXIT_FAILURE);
	    */
	    }

	    // cleanup
	    if_freenameindex(ifs);
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

