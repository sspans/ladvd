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

int sargc = 0;
char **sargv = NULL;

struct nhead netifs;
struct mhead mqueue;
struct sysinfo sysinfo;
extern struct proto protos[];

void child_init(int reqfd, int msgfd, int ifc, char *ifl[],
		struct passwd *pwd) {

    // events
    struct event evs, evq, eva;
    struct event ev_sigterm, ev_sigint;

    // master socket
    extern int msock;
    int csock = -1;
    struct sockaddr_un sun;
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

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, PACKAGE_SOCKET, sizeof(sun.sun_path));

	old_umask = umask(S_IXUSR|S_IRWXG|S_IRWXO);

	if ((unlink(PACKAGE_SOCKET) == -1) && (errno != ENOENT))
	    my_fatale("failed to remove " PACKAGE_SOCKET);
	if (bind(csock, (struct sockaddr *)&sun, SUN_LEN(&sun)) == -1)
	    my_fatale("failed to bind " PACKAGE_SOCKET);
	if (listen(csock, 10) == -1)
	    my_fatale("failed to listen on " PACKAGE_SOCKET);

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
    event_set(&evs, msgfd, 0, (void *)child_send, &evs);
    child_send(msgfd, EV_TIMEOUT, &evs);

    if (options & OPT_ONCE)
	exit(EXIT_SUCCESS);

    // listen for messages from the master
    if (options & OPT_RECV) {
	event_set(&evq, msgfd, EV_READ|EV_PERSIST, (void *)child_queue, NULL);
	event_add(&evq, NULL);

	signal_set(&ev_sigint, SIGINT, child_free, NULL);
	signal_set(&ev_sigterm, SIGTERM, child_free, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
    }

    // accept cli connections
    if (csock != -1) {
	event_set(&eva, csock, EV_READ|EV_PERSIST,
			(void *)child_cli_accept, NULL);
	event_add(&eva, NULL);
    }

    // wait for events
    event_dispatch();

    // not reached
    my_fatal("child event-loop failed");
}

void child_send(int fd, short event, void *evs) {
    struct master_msg msg;
    struct netif *netif = NULL, *subif = NULL;
    struct timeval tv = { .tv_sec = SLEEPTIME };
    ssize_t len;

    // update netifs
    my_log(INFO, "fetching all interfaces"); 
    if (netif_fetch(sargc, sargv, &sysinfo, &netifs) == 0) {
	my_log(CRIT, "no configured ethernet interfaces found");
	return;
    }

    while ((netif = netif_iter(netif, &netifs)) != NULL) {

	// skip special interfaces
	if (netif->type < NETIF_REGULAR)
	    continue;
	if ((netif->type == NETIF_WIRELESS) && !(options & OPT_WIRELESS))
	    continue;
	if ((netif->type == NETIF_TAP) && !(options & OPT_TAP))
	    continue;

	my_log(INFO, "starting loop with interface %s", netif->name); 

	while ((subif = subif_iter(subif, netif)) != NULL) {

	    // populate msg
	    memset(&msg, 0, sizeof(msg));
	    msg.index = subif->index;

	    // explicitly listen when recv is enabled
	    if ((options & OPT_RECV) && (subif->protos == 0)) {
		struct master_req mreq = {};
		mreq.op = MASTER_OPEN;
		mreq.index = subif->index;
		my_mreq(&mreq);
	    }

	    // fetch interface media status
	    my_log(INFO, "fetching %s media details", subif->name);
	    if (netif_media(subif) == EXIT_FAILURE)
		my_log(CRIT, "error fetching interface media details");

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
		msg.len = protos[p].build(msg.msg, subif, 
						&netifs, &sysinfo);

		if (msg.len == 0) {
		    my_log(CRIT, "can't generate %s packet for %s",
				  protos[p].name, subif->name);
		    continue;
		}

		// zero the src when sending on a failover slave
		if (subif->slave && 
		    (netif->bonding_mode == NETIF_BONDING_FAILOVER))
		    memset(msg.msg + ETHER_ADDR_LEN, 0, ETHER_ADDR_LEN);

		// write it to the wire.
		my_log(INFO, "sending %s packet (%zu bytes) on %s",
			    protos[p].name, msg.len, subif->name);
		len = write(fd, &msg, MASTER_MSG_LEN(msg.len));
		if (len < MASTER_MSG_MIN || len != MASTER_MSG_LEN(msg.len))
		    my_fatale("only %zi bytes written", len);
	    }
	}
    }

    // delete old messages
    if (options & OPT_RECV)
	child_expire();

    // schedule the next run
    event_add(evs, &tv);
}

void child_queue(int fd, short event) {
    struct master_msg rmsg = {};
    struct master_msg  *msg = NULL, *qmsg = NULL, *pmsg = NULL;
    struct netif *subif, *netif;
    struct ether_hdr *ether;
    time_t now;
    ssize_t len;

    my_log(INFO, "receiving message from master");
    if ((len = read(fd, &rmsg, MASTER_MSG_MAX)) == -1)
	return;
    if (len < MASTER_MSG_MIN || len != MASTER_MSG_LEN(rmsg.len))
	return;
    if ((now = time(NULL)) == (time_t)-1)
	return;

    assert(rmsg.proto < PROTO_MAX);
    assert(rmsg.len >= (ETHER_MIN_LEN - ETHER_VLAN_ENCAP_LEN));
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

    // add current timestamp
    rmsg.received = now;

    // fetch the parent netif
    if (subif->master)
	netif = subif->master;
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
	memcpy(msg, &rmsg, offsetof(struct master_msg, entries));
    } else {
	char *hostname = NULL;

	msg = my_malloc(MASTER_MSG_SIZ);
	memcpy(msg, &rmsg, offsetof(struct master_msg, entries));
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

    // update ifdescr
    if (options & OPT_DESCR)
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
    struct master_msg *msg = NULL, *nmsg = NULL;
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
	if (subif->master)
	    netif = subif->master;
	else
	    netif = subif;

	// update protos
	if (options & OPT_AUTO)
	    netif_protos(netif, &mqueue);

	// update ifdescr
	if (options & OPT_DESCR)
	    netif_descr(subif, &mqueue);

	subif->update = 0;
    }
}

void child_free(int sig, short event, void *arg) {
    struct master_msg *msg = NULL, *nmsg = NULL;

    TAILQ_FOREACH_SAFE(msg, &mqueue, entries, nmsg) {
	TAILQ_REMOVE(&mqueue, msg, entries);
	peer_free(msg->peer);
	free(msg);
    }
    exit(EXIT_SUCCESS);
}

void child_cli_accept(int socket, short event) {
    int	fd, sndbuf = MASTER_MSG_MAX * 10;
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
    struct master_msg *msg = sess->msg;
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
	if (write(fd, msg, MASTER_MSG_MAX) != -1)
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

