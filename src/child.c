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
#include "child.h"
#include <sys/un.h>
#include <time.h>

#ifdef HAVE_LIBMNL
#include <libmnl/libmnl.h>
#include <linux/rtnetlink.h>
#elif defined(HAVE_NET_ROUTE_H)
#include <net/route.h>
#ifndef LINK_STATE_IS_UP
#define LINK_STATE_IS_UP(_s)    \
	((_s) >= LINK_STATE_UP || (_s) == LINK_STATE_UNKNOWN)
#endif
#endif
#ifdef HAVE_NET_IF_TYPES_H
#include <net/if_types.h>
#endif /* HAVE_NET_IF_TYPES_H */

int sargc = 0;
char **sargv = NULL;

struct nhead netifs;
struct ehead exclifs;
struct mhead mqueue;
struct my_sysinfo sysinfo;
extern struct proto protos[];

void child_init(int reqfd, int msgfd, int ifc, char *ifl[],
		struct passwd *pwd) {

    // events
    struct child_send_args args = { .index = NETIF_INDEX_MAX };
    struct event evq, eva, evl;
    struct event ev_sigterm, ev_sigint;

    // parent socket
    extern int msock;
    int lsock, csock = -1;
    struct sockaddr_un usock;
    mode_t old_umask;

    sargc = ifc;
    sargv = ifl;

    // init the queues
    TAILQ_INIT(&netifs);
    TAILQ_INIT(&mqueue);

    // configure command socket
    msock = reqfd;

    // configure unix socket
    if (!(options & (OPT_DEBUG|OPT_ONCE))) {

	csock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	// XXX: make do with a stream and hope for the best
	if ((csock == -1) && (errno == EPROTONOSUPPORT))
	    csock = my_socket(AF_UNIX, SOCK_STREAM, 0);
	if (csock == -1)
	    my_fatale("failed to create socket");

	memset(&usock, 0, sizeof(usock));
	usock.sun_family = AF_UNIX;
	strlcpy(usock.sun_path, PACKAGE_SOCKET, sizeof(usock.sun_path));

	old_umask = umask(S_IXUSR|S_IRWXG|S_IRWXO);

	if ((unlink(PACKAGE_SOCKET) == -1) && (errno != ENOENT))
	    my_fatale("failed to remove " PACKAGE_SOCKET);
	if (bind(csock, (struct sockaddr *)&usock, SUN_LEN(&usock)) == -1)
	    my_fatale("failed to bind " PACKAGE_SOCKET);
	if (options & OPT_RECV) {
	    if (listen(csock, 10) == -1)
		my_fatale("failed to listen on " PACKAGE_SOCKET);
	}

	if (chmod(PACKAGE_SOCKET, S_IRWXU|S_IRWXG) == -1)
	    my_fatale("failed to chmod " PACKAGE_SOCKET);
	if (chown(PACKAGE_SOCKET, -1, pwd->pw_gid) == -1)
	    my_fatal("failed to chown " PACKAGE_SOCKET);

	umask(old_umask);
    }

    // initalize the events and netifs
    event_init();
    netif_init();

    // drop privileges
    if (!(options & OPT_DEBUG)) {
	my_chroot(PACKAGE_CHROOT_DIR);
	my_drop_privs(pwd);
	my_rlimit_child();
    }

    // proctitle
    setproctitle("child");

    // startup message
    my_log(CRIT, PACKAGE_STRING " running");

    // create and run the transmit event
    event_set(&args.event, msgfd, 0, (void *)child_send, &args);
    child_send(msgfd, EV_TIMEOUT, &args);

    if (options & OPT_ONCE)
	exit(EXIT_SUCCESS);

    if (options & OPT_RECV) {
	// listen for messages from the parent
	event_set(&evq, msgfd, EV_READ|EV_PERSIST, (void *)child_queue, NULL);
	event_add(&evq, NULL);

	signal_set(&ev_sigint, SIGINT, child_free, NULL);
	signal_set(&ev_sigterm, SIGTERM, child_free, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);

	// accept cli connections
	if (csock != -1) {
	    event_set(&eva, csock, EV_READ|EV_PERSIST,
			(void *)child_cli_accept, NULL);
	    event_add(&eva, NULL);
	}
    }

    // create link fd
    if ((lsock = child_link_fd()) != -1) {
	event_set(&evl, lsock, EV_READ|EV_PERSIST,
		child_link, (void *)&msgfd);
	event_add(&evl, NULL);
    }

    // wait for events
    event_dispatch();

    // not reached
    my_fatal("child event-loop failed");
}

void child_send(int fd, short event, struct child_send_args *args) {
    struct parent_msg msg;
    struct netif *netif = NULL, *subif = NULL, *linkif = NULL;
    ssize_t len;

    // bail early on known flapping interfaces
    if (args->index != NETIF_INDEX_MAX) {
	linkif = netif_byindex(&netifs, args->index);
	if (linkif && (linkif->link_event > 3))
	    goto out;
    }

    // update netifs
    my_log(INFO, "fetching all interfaces"); 

    // no configured ethernet interfaces found
    if (netif_fetch(sargc, sargv, &sysinfo, &netifs) == 0)
	goto out;

    // no interface matching the given ifindex found
    if (args->index != NETIF_INDEX_MAX) {
	if ((linkif = netif_byindex(&netifs, args->index)) == NULL)
	    goto out;
    }

    while ((netif = netif_iter(netif, &netifs)) != NULL) {

	// skip special interfaces
	if (netif->type < NETIF_REGULAR)
	    continue;
	if ((netif->type == NETIF_WIRELESS) && !(options & OPT_WIRELESS))
	    continue;
	if ((netif->type == NETIF_TAP) && !(options & OPT_TAP))
	    continue;

	// skip excluded interfaces
	if (netif_excluded(netif, &exclifs))
	    continue;

	my_log(INFO, "starting loop with interface %s", netif->name); 

	while ((subif = subif_iter(subif, netif)) != NULL) {

	    // handle a given ifindex
	    if (args->index != NETIF_INDEX_MAX) {
		if (args->index != subif->index)
		    continue;
		subif->link_event++;
	    } else {
		subif->link_event = 0;
	    }

	    // skip special interfaces
	    if (subif->type < NETIF_REGULAR)
		continue;
	    if ((subif->type == NETIF_WIRELESS) && !(options & OPT_WIRELESS))
		continue;
	    if ((subif->type == NETIF_TAP) && !(options & OPT_TAP))
		continue;

	    // skip excluded interfaces
	    if (netif_excluded(subif, &exclifs))
		continue;

	    // populate msg
	    memset(&msg, 0, sizeof(msg));
	    msg.index = subif->index;

	    // explicitly listen when recv is enabled
	    if ((options & OPT_RECV) && (subif->protos == 0)) {
		struct parent_req mreq = {};
		mreq.op = PARENT_OPEN;
		mreq.index = subif->index;
		my_mreq(&mreq);
	    }

	    // fetch interface media status
	    my_log(INFO, "fetching %s media details", subif->name);
	    if (netif_media(subif) == EXIT_FAILURE)
		my_log(CRIT, "error fetching interface media details");

	    // bail if sending packets is disabled
	    if (!(options & OPT_SEND))
		continue;

	    // generate and send packets
	    for (int p = 0; protos[p].name != NULL; p++) {

		// only enabled protos
		if (!(protos[p].enabled) && !(netif->protos & (1 << p)))
		    continue;

		// clear packet
		memset(msg.msg, 0, ETHER_MAX_LEN);

		my_log(INFO, "building %s packet for %s", 
			    protos[p].name, subif->name);
		msg.proto = p;
		msg.len = protos[p].build(p, msg.msg, subif,
						&netifs, &sysinfo);

		if (msg.len == 0) {
		    my_log(CRIT, "can't generate %s packet for %s",
				  protos[p].name, subif->name);
		    continue;
		}

		// zero the src when sending on a failover subif
		if (subif->child &&
		    (netif->bonding_mode == NETIF_BONDING_FAILOVER))
		    memset(msg.msg + ETHER_ADDR_LEN, 0, ETHER_ADDR_LEN);

		// write it to the wire.
		my_log(INFO, "sending %s packet (%zu bytes) on %s",
			    protos[p].name, msg.len, subif->name);
		len = write(fd, &msg, PARENT_MSG_LEN(msg.len));
		if (len < PARENT_MSG_MIN || len != PARENT_MSG_LEN(msg.len))
		    my_fatale("only %zi bytes written", len);
	    }
	}
    }

out:
    if (event != EV_TIMEOUT)
	return;

    // delete old messages
    if (options & OPT_RECV)
	child_expire();

    // schedule the next run
    struct timeval tv = { .tv_sec = SLEEPTIME };
    event_add(&args->event, &tv);
}

void child_queue(int fd, short __unused(event)) {
    struct parent_msg rmsg = {};
    struct parent_msg  *msg = NULL, *qmsg = NULL, *pmsg = NULL;
    struct netif *subif, *netif;
    struct ether_hdr *ether;
    time_t now;
    ssize_t len;

    my_log(INFO, "receiving message from parent");
    if ((len = read(fd, &rmsg, PARENT_MSG_MAX)) == -1)
	return;
    if (len < PARENT_MSG_MIN || len != PARENT_MSG_LEN(rmsg.len))
	return;
    if ((now = time(NULL)) == (time_t)-1)
	return;

    assert(rmsg.proto < PROTO_MAX);
    assert(rmsg.len <= ETHER_MAX_LEN);

    // skip unknown interfaces
    if ((subif = netif_byindex(&netifs, rmsg.index)) == NULL)
	return;
    strlcpy(rmsg.name, subif->name, sizeof(rmsg.name));

    // skip locally generated packets
    ether = (struct ether_hdr *)rmsg.msg;
    if (netif_byaddr(&netifs, ether->src) != NULL)
	return;

    // decode message
    my_log(INFO, "decoding advertisement");
    rmsg.decode = DECODE_STR;
    if (protos[rmsg.proto].decode(&rmsg) == 0) {
	peer_free(rmsg.peer);
    	return;
    }

    // add current timestamp unless it's a shutdown msg
    if (rmsg.ttl)
	rmsg.received = now;

    // fetch the parent netif
    if (subif->parent)
	netif = subif->parent;
    else
	netif = subif;

    TAILQ_FOREACH(qmsg, &mqueue, entries) {
	// match ifindex
	if (rmsg.index != qmsg->index)
	    continue;
	// save a pointer if the message peer matches
	if (memcmp(rmsg.msg + ETHER_ADDR_LEN, qmsg->msg + ETHER_ADDR_LEN,
		    ETHER_ADDR_LEN) == 0)
	    pmsg = qmsg;
	// match protocol
	if (rmsg.proto != qmsg->proto)
	    continue;
	// identical source & destination
	if (memcmp(rmsg.msg, qmsg->msg, ETHER_ADDR_LEN * 2) != 0)
	    continue;

       msg = qmsg;
       break;
    }

    if (msg != NULL) {
	// free the old peer decode
	peer_free(msg->peer);
	// copy everything upto the tailq_entry
	memcpy(msg, &rmsg, offsetof(struct parent_msg, entries));
    } else {
	char *hostname = NULL;

	msg = my_malloc(PARENT_MSG_SIZ);
	memcpy(msg, &rmsg, offsetof(struct parent_msg, entries));
	// group messages per peer
	if (pmsg)
	    TAILQ_INSERT_AFTER(&mqueue, pmsg, msg, entries);
	else
	    TAILQ_INSERT_TAIL(&mqueue, msg, entries);

	hostname = msg->peer[PEER_HOSTNAME];
	if (hostname)
	    my_log(CRIT, "new peer %s (%s) on interface %s",
		    hostname, protos[msg->proto].name, netif->name);
    }

    // handle shutdowns via child_expire
    if (!msg->ttl) {
	child_expire();
	return;
    }

    // update ifdescr
    if (options & OPT_IFDESCR)
	netif_descr(subif, &mqueue);

    // return unless we need to enable the received protocol
    if (!(options & OPT_AUTO) || (netif->protos & (1 << msg->proto)))
	return;

    // only enable if subif or netif are listed
    if (options & OPT_ARGV) {
	if (!(subif->argv) && !(netif->argv))
	    return;
    }

    my_log(CRIT, "enabling %s on interface %s",
	    protos[msg->proto].name, netif->name);
    netif->protos |= (1 << msg->proto);
}

void child_expire() {
    time_t now;
    struct parent_msg *msg = NULL, *nmsg = NULL;
    struct netif *netif = NULL, *subif = NULL;
    char *hostname = NULL;

    if ((now = time(NULL)) == (time_t)-1)
	return;

    // remove expired messages
    TAILQ_FOREACH_SAFE(msg, &mqueue, entries, nmsg) {
	if (likely((msg->received + msg->ttl) >= now))
	    continue;
	if (unlikely(msg->lock))
	    continue;

	hostname = msg->peer[PEER_HOSTNAME];
	if (hostname)
	    my_log(CRIT, "removing peer %s (%s)",
		    hostname, protos[msg->proto].name);

	// mark the interface
	if ((subif = netif_byindex(&netifs, msg->index)) != NULL)
	    subif->update = 1;

	TAILQ_REMOVE(&mqueue, msg, entries);
	peer_free(msg->peer);
	free(msg);
    }

    // update interfaces
    TAILQ_FOREACH(subif, &netifs, entries) { 
	if (likely(!subif->update))
	    continue;

	// fetch the parent netif
	if (subif->parent)
	    netif = subif->parent;
	else
	    netif = subif;

	// update protos
	if (options & OPT_AUTO)
	    netif_protos(netif, &mqueue);

	// update ifdescr
	if (options & OPT_IFDESCR)
	    netif_descr(subif, &mqueue);

	subif->update = 0;
    }
}

void child_free(int __unused(sig), short __unused(event), void __unused(*arg)) {
    struct parent_msg *msg = NULL, *nmsg = NULL;

    TAILQ_FOREACH_SAFE(msg, &mqueue, entries, nmsg) {
	TAILQ_REMOVE(&mqueue, msg, entries);
	peer_free(msg->peer);
	free(msg);
    }
    exit(EXIT_SUCCESS);
}

void child_cli_accept(int socket, short __unused(event)) {
    int	fd, sndbuf = PARENT_MSG_MAX * 10;
    struct sockaddr sa;
    socklen_t addrlen = sizeof(sa);
    struct child_session *session = NULL;
    struct timeval tv = { .tv_sec = 1 };

    if ((fd = accept(socket, &sa, &addrlen)) == -1) {
	my_log(WARN, "cli connection failed");
	return;
    }

    my_nonblock(fd);
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) == -1)
	my_loge(WARN, "failed to set sndbuf");

    session = my_malloc(sizeof(struct child_session));
    event_set(&session->event, fd, EV_WRITE, (void *)child_cli_write, session);
    event_add(&session->event, &tv);
}

void child_cli_write(int fd, short event, struct child_session *sess) {
    struct parent_msg *msg = sess->msg;
    struct timeval tv = { .tv_sec = 1 };

    if (event == EV_TIMEOUT)
	goto cleanup;

    // grab the first message
    if (!msg)
	msg = TAILQ_FIRST(&mqueue);
    // or release
    else
	msg->lock--;

    for (; msg != NULL; msg = TAILQ_NEXT(msg, entries)) {
	if (write(fd, msg, PARENT_MSG_MAX) != -1)
	    continue;

	// bail unless non-block
	if (errno != EAGAIN)
	    break;

	// schedule a new event
	msg->lock++;
	sess->msg = msg;
	event_set(&sess->event, fd, EV_WRITE, (void *)child_cli_write, sess);
	event_add(&sess->event, &tv);
	return;
    }

cleanup:
    event_del(&sess->event);
    free(sess);
    close(fd);
}

#ifdef HAVE_LIBMNL
struct mnl_socket *nl;
#endif

int child_link_fd() {

#ifdef HAVE_LIBMNL
    nl = mnl_socket_open(NETLINK_ROUTE);
    if (nl == NULL)
	return -1;

    if (mnl_socket_bind(nl, RTMGRP_LINK, MNL_SOCKET_AUTOPID) < 0) {
	mnl_socket_close(nl);
	return -1;
    }
    my_nonblock(mnl_socket_get_fd(nl));

    return mnl_socket_get_fd(nl);
#endif

#if defined(HAVE_NET_ROUTE_H) && defined(RTM_IFINFO)
    int fd;

    if ((fd = socket(PF_ROUTE, SOCK_RAW, 0)) == -1)
	return fd;

#if defined(ROUTE_MSGFILTER)
    unsigned int rtfilter = ROUTE_FILTER(RTM_IFINFO);
    if (setsockopt(fd, PF_ROUTE, ROUTE_MSGFILTER,
		   &rtfilter, sizeof(rtfilter)) == -1) {
	close(fd);
	fd = -1;
    }
#endif

    return fd;
#endif

    return -1;
}

#ifdef HAVE_LIBMNL
static int child_link_cb(const struct nlmsghdr *nlh, void *msgfd) {
    struct ifinfomsg *ifm = mnl_nlmsg_get_payload(nlh);
    int ifi_flags = IFF_RUNNING|IFF_LOWER_UP;
    struct child_send_args args = {};

    if (ifm->ifi_type != ARPHRD_ETHER)
        goto out;
    if ((ifm->ifi_flags & ifi_flags) != ifi_flags)
        goto out;

    my_log(INFO, "invoking child_send");
    args.index = ifm->ifi_index;
    child_send(*(int*)msgfd, 0, &args);

out:
    return MNL_CB_OK;
}
#endif
void child_link(int __unused(fd), short __unused(event), void *msgfd) {

#ifdef HAVE_LIBMNL
    char buf[MNL_SOCKET_BUFFER_SIZE];
    int ret;

    my_log(INFO, "reading link event");
    while ((ret = mnl_socket_recvfrom(nl, buf, sizeof(buf))) > 0) {
        ret = mnl_cb_run(buf, ret, 0, 0, child_link_cb, msgfd);
        if (ret <= 0)
            break;
    }

    return;
#endif

#if defined(HAVE_NET_ROUTE_H) && defined(RTM_IFINFO)

    char msg[2048] = {};
    struct if_msghdr ifm;
    struct rt_msghdr *rtm = (struct rt_msghdr *)&msg;
    int len, ifm_flags = IFF_RUNNING|IFF_UP;

    my_log(INFO, "reading link event");
    len = read(fd, msg, sizeof(msg));

    if (len < sizeof(struct rt_msghdr) ||
	(rtm->rtm_version != RTM_VERSION) ||
	(rtm->rtm_type != RTM_IFINFO))
	return;

    memcpy(&ifm, rtm, sizeof(ifm));
    if (ifm.ifm_data.ifi_type != IFT_ETHER)
	return;
    if ((ifm.ifm_flags & ifm_flags) != ifm_flags)
	return;
#if defined(LINK_STATE_UP)
    if (!LINK_STATE_IS_UP(ifm.ifm_data.ifi_link_state))
	return;
#endif

    my_log(INFO, "invoking child_send");
    struct child_send_args args = { .index = ifm.ifm_index };
    child_send(*(int*)msgfd, 0, &args);
#endif
}

