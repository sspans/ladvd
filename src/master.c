/*
 * $Id$
 *
 * Copyright (c) 2008, 2009, 2010
 *      Sten Spans <sten@blinkenlights.nl>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "common.h"
#include "util.h"
#include "proto/protos.h"
#include "master.h"
#include "filter.h"
#include <sys/select.h>
#include <sys/wait.h>
#include <ctype.h>

#ifdef HAVE_LIBCAP_NG
#include <cap-ng.h>
#elif defined(HAVE_LIBCAP)
#include <sys/prctl.h>
#include <sys/capability.h>
#endif

#ifdef HAVE_NETPACKET_PACKET_H
#include <netpacket/packet.h>
#endif /* HAVE_NETPACKET_PACKET_H */
#ifdef HAVE_NET_IF_DL_H
#include <net/if_dl.h>
#endif /* HAVE_NET_IF_DL_H */

#if HAVE_LINUX_SOCKIOS_H
#include <linux/sockios.h>
#endif /* HAVE_LINUX_SOCKIOS_H */

#if HAVE_LINUX_ETHTOOL_H
#include <linux/ethtool.h>
#endif /* HAVE_LINUX_ETHTOOL_H */

#ifdef HAVE_PCI_PCI_H
#include <pci/pci.h>
#endif /* HAVE_PCI_PCI_H */

#ifdef HAVE_SYSFS
#define SYSFS_CLASS_NET		"/sys/class/net"
#define SYSFS_PCI_DEVICE	"device/device"
#define SYSFS_PCI_VENDOR	"device/vendor"
#define SYSFS_USB_DEVICE	"device/../product"
#define SYSFS_USB_VENDOR	"device/../manufacturer"
#define SYSFS_PATH_MAX		256
#endif /* HAVE_SYSFS */

struct rfdhead rawfds;

int sock = -1;
int mfd = -1;
int dfd = -1;

extern struct proto protos[];

void master_init(int reqfd, int msgfd, pid_t child) {

    // events
    struct event ev_cmd, ev_msg;
    struct event ev_sigchld, ev_sigint, ev_sigterm,  ev_sighup;

#ifdef HAVE_LIBCAP
    // capabilities
    cap_t caps;
#endif /* HAVE_LIBCAP */

    // init the queues
    TAILQ_INIT(&rawfds);

    // proctitle
    setproctitle("master [priv]");

    // setup global sockets
    sock = my_socket(AF_INET, SOCK_DGRAM, 0);
    mfd = msgfd;

    // debug
    if (options & OPT_DEBUG) {
	if (isatty(STDOUT_FILENO))
	    my_fatal("please redirect stdout to tcpdump or a file");
	dfd = STDOUT_FILENO;
	write_pcap_hdr(dfd);
#if HAVE_LIBCAP_NG
    } else {
	capng_clear(CAPNG_SELECT_BOTH);
	capng_updatev(CAPNG_ADD, CAPNG_EFFECTIVE|CAPNG_PERMITTED, CAP_KILL,
		    CAP_NET_ADMIN, CAP_NET_RAW, CAP_NET_BROADCAST, -1);
	if (capng_apply(CAPNG_SELECT_BOTH) == -1)
	    my_fatal("unable to set capabilities");
#elif HAVE_LIBCAP
    } else {
	// keep CAP_NET_ADMIN
	caps = cap_from_text("cap_net_admin=ep cap_net_raw=ep "
		"cap_net_broadcast=ep cap_kill=ep");

	if (caps == NULL)
	    my_fatale("unable to create capabilities");

	if (cap_set_proc(caps) == -1)
	    my_fatale("unable to set capabilities");

	(void) cap_free(caps);
#endif /* HAVE_LIBCAP */
    }

    // initalize the event library
    event_init();

    // listen for request and messages from the child
    event_set(&ev_cmd, reqfd, EV_READ|EV_PERSIST, (void *)master_req, NULL);
    event_set(&ev_msg, msgfd, EV_READ|EV_PERSIST, (void *)master_send, NULL);
    event_add(&ev_cmd, NULL);
    event_add(&ev_msg, NULL);

    // handle signals
    signal_set(&ev_sigchld, SIGCHLD, master_signal, &child);
    signal_set(&ev_sigint, SIGINT, master_signal, &child);
    signal_set(&ev_sigterm, SIGTERM, master_signal, &child);
    signal_set(&ev_sighup, SIGHUP, master_signal, NULL);
    signal_add(&ev_sigchld, NULL);
    signal_add(&ev_sigint, NULL);
    signal_add(&ev_sigterm, NULL);
    signal_add(&ev_sighup, NULL);

    // make sure the child is still running
    if (waitpid(child, NULL, WNOHANG) != 0)
	    exit(EXIT_FAILURE);

    // wait for events
    event_dispatch();

    // not reached
    my_fatal("master event-loop failed");
}


void master_signal(int sig, short event, void *pid) {
    int status;

    switch (sig) {
	case SIGINT:
	case SIGTERM:
	case SIGCHLD:
	    if (waitpid(*(pid_t *)pid, &status, WNOHANG) > 0) {
		if (WIFEXITED(status))
		    my_log(CRIT, "child exited with return code %d", 
			    WEXITSTATUS(status));
		if (WIFSIGNALED(status))
		    my_log(CRIT, "child exited on signal %d%s",
			    WTERMSIG(status),
			    WCOREDUMP(status) ? " (core dumped)" : "");
	    } else {
		kill(*(pid_t *)pid, sig);
	    }
	    rfd_closeall(&rawfds);
	    unlink(PACKAGE_SOCKET);
	    my_log(CRIT, "quitting");
	    exit(EXIT_SUCCESS);
	    break;
	case SIGHUP:
	    break;
	default:
	    my_fatal("unexpected signal");
    }
}


void master_req(int reqfd, short event) {
    struct master_req mreq = {};
    struct rawfd *rfd;
    ssize_t len;

    // receive request
    len = read(reqfd, &mreq, MASTER_REQ_MAX);

    // check request size
    if (len < MASTER_REQ_MIN || len != MASTER_REQ_LEN(mreq.len))
	my_fatal("invalid request received");

    // validate ifindex
    if (if_indextoname(mreq.index, mreq.name) == NULL) {
	mreq.len = 0;
	goto out;
    }

    // validate request
    if (master_check(&mreq) != EXIT_SUCCESS)
	my_fatal("invalid request supplied");

    switch (mreq.op) {
	// open socket
	case MASTER_OPEN:
	    if ((rfd = rfd_byindex(&rawfds, mreq.index)) == NULL)
		master_open(mreq.index, mreq.name);
	    break;
	// close socket
	case MASTER_CLOSE:
	    if ((rfd = rfd_byindex(&rawfds, mreq.index)) != NULL)
		master_close(rfd);
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
#ifdef HAVE_SYSFS
	case MASTER_DEVICE:
	    mreq.len = master_device(&mreq);
	    break;
#endif /* HAVE_SYSFS */
#if defined(HAVE_SYSFS) && defined(HAVE_PCI_PCI_H)
	case MASTER_DEVICE_ID:
	    mreq.len = master_device_id(&mreq);
	    break;
#endif /* HAVE_SYSFS && HAVE_PCI_PCI_H */
	// invalid request
	default:
	    my_fatal("invalid request received");
    }

out:
    len = write(reqfd, &mreq, MASTER_REQ_LEN(mreq.len));
    if (len != MASTER_REQ_LEN(mreq.len))
	    my_fatal("failed to return request to child");
}


int master_check(struct master_req *mreq) {

    assert(mreq);
    assert(mreq->len <= ETHER_MAX_LEN);
    assert(mreq->op < MASTER_MAX);

    switch (mreq->op) {
	case MASTER_CLOSE:
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
#ifdef HAVE_SYSFS
	case MASTER_DEVICE:
	    return(EXIT_SUCCESS);
#endif /* HAVE_SYSFS */
#if defined(HAVE_SYSFS) && defined(HAVE_PCI_PCI_H)
	case MASTER_DEVICE_ID:
	    return(EXIT_SUCCESS);
#endif /* HAVE_SYSFS && HAVE_PCI_PCI_H */
	default:
	    return(EXIT_FAILURE);
    }

    return(EXIT_FAILURE);
}


void master_send(int msgfd, short event) {

    struct master_msg msend = {};
    struct rawfd *rfd = NULL;
    ssize_t len;

    // receive request
    len = read(msgfd, &msend, MASTER_MSG_MAX);

    // check request size
    if (len < MASTER_MSG_MIN || len != MASTER_MSG_LEN(msend.len))
	return;

    if (if_indextoname(msend.index, msend.name) == NULL) {
	my_log(CRIT, "invalid ifindex supplied");
	return;
    }

    assert(msend.len >= (ETHER_MIN_LEN - ETHER_VLAN_ENCAP_LEN));
    assert(msend.proto < PROTO_MAX);
    assert(protos[msend.proto].check(msend.msg, msend.len) != NULL);

    // debug
    if (options & OPT_DEBUG) {
	write_pcap_rec(dfd, &msend);
	return;
    }

    // create rfd if needed
    if (rfd_byindex(&rawfds, msend.index) == NULL)
	master_open(msend.index, msend.name);

    assert((rfd = rfd_byindex(&rawfds, msend.index)) != NULL);
    len = write(rfd->fd, msend.msg, msend.len);

    // close the socket if the device vanished
    // if needed a new socket will be created on the next run
#ifdef HAVE_NETPACKET_PACKET_H
    if ((len == -1) && (errno == ENODEV))
#elif defined HAVE_NET_BPF_H
    if ((len == -1) && (errno == EIO))
#endif /* HAVE_NET_BPF_H */
	    master_close(rfd);

    if (len != msend.len)
	my_loge(WARN, "only %zi bytes written", len);

    return;
}


void master_open(const uint32_t index, const char *name) {
    struct rawfd *rfd = NULL;

    assert(name != NULL);

    rfd = my_malloc(sizeof(struct rawfd));
    TAILQ_INSERT_TAIL(&rawfds, rfd, entries);

    rfd->index = index;
    strlcpy(rfd->name, name, IFNAMSIZ);

    rfd->fd = master_socket(rfd);
    if (rfd->fd < 0)
	my_fatal("opening raw socket failed");

    if (!(options & OPT_RECV) || (options & OPT_DEBUG))
	return;

    // register multicast membership
    master_multi(rfd, protos, 1);

    // listen for received packets
    event_set(&rfd->event, rfd->fd, EV_READ|EV_PERSIST,
	(void *)master_recv, rfd);
    event_add(&rfd->event, NULL);

    return;
}

void master_close(struct rawfd *rfd) {

    assert(rfd != NULL);

    if ((options & OPT_RECV) && !(options & OPT_DEBUG)) {
	// unregister multicast membership
	master_multi(rfd, protos, 0);
	// delete event
	event_del(&rfd->event);
    }

    // cleanup
    TAILQ_REMOVE(&rawfds, rfd, entries);
    close(rfd->fd);
#ifdef HAVE_NET_BPF_H
    if (rfd->bpf_buf.data)
	free(rfd->bpf_buf.data);
#endif /* HAVE_NET_BPF_H */
    free(rfd);

    return;
}

#if HAVE_LINUX_ETHTOOL_H
ssize_t master_ethtool(struct master_req *mreq) {

    struct ifreq ifr = {};
    struct ethtool_cmd ecmd = {};

    assert(mreq != NULL);

    // prepare ifr struct
    strlcpy(ifr.ifr_name, mreq->name, IFNAMSIZ);

    // prepare ecmd struct
    ecmd.cmd = ETHTOOL_GSET;
    ifr.ifr_data = (caddr_t)&ecmd;

    if (ioctl(sock, SIOCETHTOOL, &ifr) != -1) {
	memcpy(mreq->buf, &ecmd, sizeof(ecmd));
	return(sizeof(ecmd));
    } else {
	return(0);
    }
}
#endif /* HAVE_LINUX_ETHTOOL_H */

#ifdef SIOCSIFDESCR
ssize_t master_descr(struct master_req *mreq) {

    struct ifreq ifr = {};
    ssize_t ret = 0;

    assert(mreq != NULL);
    mreq->buf[IFDESCRSIZE] = 0;

    // prepare ifr struct
    strlcpy(ifr.ifr_name, mreq->name, IFNAMSIZ);
#ifndef __FreeBSD__
    ifr.ifr_data = (caddr_t)&mreq->buf;
#else
    ifr.ifr_buffer.buffer = &mreq->buf;
    ifr.ifr_buffer.length = mreq->len;
#endif

    if (ioctl(sock, SIOCSIFDESCR, &ifr) >= 0)
	ret = mreq->len;
    return(ret);
}
#endif /* SIOCGIFDESCR */

#ifdef HAVE_SYSFS
ssize_t master_device(struct master_req *mreq) {
    char path[SYSFS_PATH_MAX];
    struct stat sb;
    ssize_t ret = 0;

    ret = snprintf(path, SYSFS_PATH_MAX,
	    SYSFS_CLASS_NET "/%s/device", mreq->name);

    if ((ret > 0) && (stat(path, &sb) == 0))
	return(1);
    else
	return(0);
}
#endif /* HAVE_SYSFS */

#if defined(HAVE_SYSFS) && defined(HAVE_PCI_PCI_H)
ssize_t master_device_id(struct master_req *mreq) {
    uint16_t device_id = 0, vendor_id = 0;
    static struct pci_access *pacc = NULL;
    char path[SYSFS_PATH_MAX], id_str[16];
    char sub_path[SYSFS_PATH_MAX] = {}, *sub_base = NULL;
    char vendor_str[32], device_str[32], *s = NULL;
    ssize_t ret = 0;

    if (!pacc) {
	pacc = pci_alloc();
	pci_init(pacc);
    }

    ret = snprintf(path, SYSFS_PATH_MAX,
	    SYSFS_CLASS_NET "/%s/device/subsystem", mreq->name);

    if (ret == -1 || readlink(path, sub_path, sizeof(sub_path) - 1) == -1)
	return(0);
    if ((sub_base = strrchr(sub_path, '/')) == NULL)
	return(0);

    // For USB devices we use the manufacturer and product strings
    if (strcmp(sub_base, "/usb") == 0) {
	ret = snprintf(path, SYSFS_PATH_MAX,
	    SYSFS_CLASS_NET "/%s/" SYSFS_USB_VENDOR, mreq->name);
	if (ret == -1 || !read_line(path, vendor_str, sizeof(vendor_str)))
	    return(0);

	ret = snprintf(path, SYSFS_PATH_MAX,
	    SYSFS_CLASS_NET "/%s/" SYSFS_USB_DEVICE, mreq->name);
	if (ret == -1 || !read_line(path, device_str, sizeof(device_str)))
	    return(0);

	// these strings seem to have trailing spaces
	s = vendor_str + strlen(vendor_str);
	while (s != vendor_str && s-- && isspace(*s))
	    *s = '\0';
	s = device_str + strlen(device_str);
	while (s != device_str && s-- && isspace(*s))
	    *s = '\0';

	if (snprintf(mreq->buf, sizeof(mreq->buf), "%s (%s)",
		    device_str, vendor_str) < 0)
	    return(0);
	return(strlen(mreq->buf));
    }

    ret = snprintf(path, SYSFS_PATH_MAX,
	    SYSFS_CLASS_NET "/%s/" SYSFS_PCI_VENDOR, mreq->name);
    if (ret == -1 || !read_line(path, id_str, sizeof(id_str)))
	return(0);

    vendor_id = strtoul(id_str, NULL, 16);

    ret = snprintf(path, SYSFS_PATH_MAX,
	    SYSFS_CLASS_NET "/%s/" SYSFS_PCI_DEVICE, mreq->name);
    if (ret == -1 || !read_line(path, id_str, sizeof(id_str)))
	return(0);

    device_id = strtoul(id_str, NULL, 16);

    memset(mreq->buf, 0, sizeof(mreq->buf));
    pci_lookup_name(pacc, mreq->buf, sizeof(mreq->buf),
	    PCI_LOOKUP_VENDOR | PCI_LOOKUP_DEVICE, vendor_id, device_id);

    return(strlen(mreq->buf));
}
#endif /* HAVE_SYSFS && HAVE_PCI_PCI_H */

int master_socket(struct rawfd *rfd) {

    int fd = -1;

    if (options & OPT_DEBUG)
	return(dup(dfd));

#ifdef HAVE_NETPACKET_PACKET_H
    struct sockaddr_ll sa = {};

    assert(rfd);
    fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    // socket open failed
    if (fd < 0)
	return(fd);

    // bind the socket to rfd
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = rfd->index;
    sa.sll_protocol = htons(ETH_P_ALL);

    if (bind(fd, (struct sockaddr *)&sa, sizeof (sa)) != 0)
	my_fatal("failed to bind socket to %s", rfd->name);

#ifdef HAVE_LINUX_FILTER_H
    // install socket filter
    struct sock_fprog fprog = {};

    if (options & OPT_RECV) {
	fprog.filter = proto_filter; 
	fprog.len = sizeof(proto_filter) / sizeof(struct sock_filter);
    } else {
	fprog.filter = reject_filter; 
	fprog.len = sizeof(reject_filter) / sizeof(struct sock_filter);
    }

    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER,
		   &fprog, sizeof(fprog)) < 0)
	my_fatal("unable to configure socket filter for %s", rfd->name);
#endif

#elif defined HAVE_NET_BPF_H
    int n = 0;
    char dev[50];

    struct ifreq ifr = {};
    struct bpf_program fprog = {};
    int enable = 1;

    assert(rfd);

    do {
	snprintf(dev, sizeof(dev), "/dev/bpf%d", n++);
	fd = open(dev, O_RDWR);
    } while (fd < 0 && errno == EBUSY);

    // no free bpf available
    if (fd < 0)
	return(fd);

    // prepare ifr struct
    strlcpy(ifr.ifr_name, rfd->name, IFNAMSIZ);

    // bind the socket to rfd
    if (ioctl(fd, BIOCSETIF, (caddr_t)&ifr) < 0)
	my_fatal("failed to bind socket to %s", rfd->name);

    // setup bpf receive
    if (options & OPT_RECV) {
	fprog.bf_insns = proto_filter; 
	fprog.bf_len = sizeof(proto_filter) / sizeof(struct bpf_insn);
    } else {
	fprog.bf_insns = reject_filter; 
	fprog.bf_len = sizeof(reject_filter) / sizeof(struct bpf_insn);
    }

    // configure a reasonable receive buffer
    rfd->bpf_buf.len = roundup(ETHER_MAX_LEN, getpagesize());
    ioctl(fd, BIOCGBLEN, &rfd->bpf_buf.len);
    if (!rfd->bpf_buf.len)
	my_fatal("unable to fetch bpf bufer length for %s", rfd->name);
    rfd->bpf_buf.data = my_malloc(rfd->bpf_buf.len);

    // disable buffering
    if (ioctl(fd, BIOCIMMEDIATE, (caddr_t)&enable) < 0)
	my_fatal("unable to configure BPF immediate mode for %s", rfd->name);
    // set header complete
    if (ioctl(fd, BIOCSHDRCMPLT, (caddr_t)&enable) < 0)
	my_fatal("unable to configure BPF header completion for %s", rfd->name);

    // set direction
#ifdef BIOCSDIRECTION
    enable = BPF_D_IN;
    if (ioctl(fd, BIOCSDIRECTION, (caddr_t)&enable) < 0)
	my_fatal("unable to configure BPF direction for %s", rfd->name);
#elif defined BIOCSDIRFILT
    enable = BPF_DIRECTION_OUT;
    if (ioctl(fd, BIOCSDIRFILT, (caddr_t)&enable) < 0)
	my_fatal("unable to configure BPF direction for %s", rfd->name);
#endif

    // install bpf filter
    if (ioctl(fd, BIOCSETF, (caddr_t)&fprog) < 0)
	my_fatal("unable to configure BPF filter for %s", rfd->name);
#endif

    return(fd);
}


void master_multi(struct rawfd *rfd, struct proto *protos, int op) {

#ifdef AF_PACKET
    struct packet_mreq mreq = {};
#endif
#ifdef __FreeBSD__
    struct sockaddr_dl *saddrdl;
#endif
    struct ifreq ifr = {};

    if (options & OPT_DEBUG)
	return;

    strlcpy(ifr.ifr_name, rfd->name, IFNAMSIZ);

    for (int p = 0; protos[p].name != NULL; p++) {

	// only enabled protos
	if ((protos[p].enabled == 0) && !(options & OPT_AUTO))
	    continue;

	// too bad for EDP
	if (!ETHER_IS_MULTICAST(protos[p].dst_addr))
	    continue;

#ifdef AF_PACKET
	// prepare a packet_mreq struct
	mreq.mr_ifindex = rfd->index;
	mreq.mr_type = PACKET_MR_MULTICAST;
	mreq.mr_alen = ETHER_ADDR_LEN;
	memcpy(mreq.mr_address, protos[p].dst_addr, ETHER_ADDR_LEN);

	op = (op) ? PACKET_ADD_MEMBERSHIP:PACKET_DROP_MEMBERSHIP;

	if (setsockopt(rfd->fd, SOL_PACKET, op, &mreq, sizeof(mreq)) < 0)
	    my_loge(CRIT, "unable to change %s multicast on %s",
		     protos[p].name, rfd->name);

#elif defined AF_LINK
#ifdef __FreeBSD__
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
	if ((ioctl(sock, (op) ? SIOCADDMULTI: SIOCDELMULTI, &ifr) < 0) &&
	    (errno != EADDRINUSE))
	    my_loge(CRIT, "unable to change %s multicast on %s",
		     protos[p].name, rfd->name);
#endif
    }
}


/* You are not expected to understand this routine */
void master_recv(int fd, short event, struct rawfd *rfd) {
    // packet
    struct master_msg mrecv = {};
    struct ether_hdr *ether;
    static unsigned int rcount = 0;
    int p;
    ssize_t len = 0;
#ifdef HAVE_NETPACKET_PACKET_H
    struct sockaddr_ll sa = {};
    socklen_t sa_len = sizeof(sa);
#endif /* HAVE_NETPACKET_PACKET_H */
#ifdef HAVE_NET_BPF_H
    void *bp, *endp;
#define bhp ((struct bpf_hdr *)bp)
#endif /* HAVE_NET_BPF_H */

    assert(rfd);

#ifdef HAVE_NET_BPF_H
    assert(rfd->bpf_buf.len);

    if ((len = read(rfd->fd, rfd->bpf_buf.data, rfd->bpf_buf.len)) == -1) {
	my_loge(CRIT,"receiving message failed");
	return;
    }

    bp = rfd->bpf_buf.data;
    endp = rfd->bpf_buf.data + len;

    while (bp < endp) {

	// with valid sizes
	if (bhp->bh_caplen < ETHER_MAX_LEN)
	    mrecv.len = bhp->bh_caplen;
	else
	    mrecv.len = ETHER_MAX_LEN;

	memcpy(mrecv.msg, bp + bhp->bh_hdrlen, mrecv.len);

#elif defined HAVE_NETPACKET_PACKET_H
    if ((len = recvfrom(rfd->fd, mrecv.msg, ETHER_MAX_LEN, 0,
			(struct sockaddr *)&sa, &sa_len)) == -1) {
	my_loge(CRIT,"receiving message failed");
	return;
    }
    mrecv.len = len;

    // skip locally generated packets
    if (sa.sll_pkttype == PACKET_OUTGOING)
	return;
#endif /* HAVE_NETPACKET_PACKET_H */

    // skip small packets
    if (mrecv.len < (ETHER_MIN_LEN - ETHER_VLAN_ENCAP_LEN))
	return;

    // note the ifindex
    mrecv.index = rfd->index;

    ether = (struct ether_hdr *)mrecv.msg;
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
    my_log(INFO, "received %s message (%zu bytes)", protos[p].name, mrecv.len);

    len = write(mfd, &mrecv, MASTER_MSG_LEN(mrecv.len));
    if (len != MASTER_MSG_LEN(mrecv.len))
	    my_fatal("failed to send message to child");
    rcount++;

#ifdef HAVE_NET_BPF_H
	bp += BPF_WORDALIGN(bhp->bh_hdrlen + bhp->bh_caplen);
    }
#endif /* HAVE_NET_BPF_H */
}


