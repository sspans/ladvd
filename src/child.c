/*
 $Id$
*/

#include "common.h"
#include "util.h"
#include "proto/protos.h"
#include "child.h"
#include <ctype.h>
#include <unistd.h>
#include <time.h>

int sargc = 0;
char **sargv = NULL;

struct nhead netifs;
struct mhead mqueue;
struct sysinfo sysinfo;
extern struct proto protos[];

void child_init(int cmdfd, int msgfd, int ifc, char *ifl[]) {

    // events
    struct event evs, evq;

    // master socket
    extern int msock;

    // init the queues
    TAILQ_INIT(&netifs);
    TAILQ_INIT(&mqueue);

    // configure master socket
    msock = cmdfd;

    sargc = ifc;
    sargv = ifl;

    // proctitle
    setproctitle("child");

    // startup message
    my_log(CRIT, PACKAGE_STRING " running");

    // initalize the event library
    event_init();

    // create and run the transmit event
    evtimer_set(&evs, (void *)child_send, &evs);
    child_send(cmdfd, EV_TIMEOUT, &evs);

    if (options & OPT_ONCE)
	exit(EXIT_SUCCESS);

    // listen for messages from the master
    if (options & OPT_RECV) {
	event_set(&evq, msgfd, EV_READ|EV_PERSIST, (void *)child_queue, NULL);
	event_add(&evq, NULL);
    }

    // wait for events
    event_dispatch();

    // not reached
    my_fatal("child event-loop failed");
}

void child_send(int fd, short event, void *evs) {
    struct master_msg mreq;
    struct netif *netif = NULL, *subif = NULL;
    struct timeval tv;
    int p;

    // update netifs
    my_log(INFO, "fetching all interfaces"); 
    if (netif_fetch(sargc, sargv, &sysinfo, &netifs) == 0) {
	my_log(CRIT, "unable to fetch interfaces");
	return;
    }

    while ((netif = netif_iter(netif, &netifs)) != NULL) {

	my_log(INFO, "starting loop with interface %s", netif->name); 

	while ((subif = subif_iter(subif, netif)) != NULL) {

	    // populate mreq
	    memset(&mreq, 0, sizeof(mreq));
	    mreq.index = subif->index;
	    mreq.cmd = MASTER_SEND;

	    // fetch interface media status
	    my_log(INFO, "fetching %s media details", subif->name);
	    if (netif_media(subif) == EXIT_FAILURE)
		my_log(CRIT, "error fetching interface media details");

	    // generate and send packets
	    for (p = 0; protos[p].name != NULL; p++) {

		// only enabled protos
		if (!(protos[p].enabled) && !(netif->protos & (1 << p)))
		    continue;

		// clear packet
		memset(mreq.msg, 0, ETHER_MAX_LEN);

		my_log(INFO, "building %s packet for %s", 
			    protos[p].name, subif->name);
		mreq.proto = p;
		mreq.len = protos[p].build_msg(mreq.msg, subif, &sysinfo);

		if (mreq.len == 0) {
		    my_log(CRIT, "can't generate %s packet for %s",
				  protos[p].name, subif->name);
		    continue;
		}

		// write it to the wire.
		my_log(INFO, "sending %s packet (%d bytes) on %s",
			    protos[p].name, mreq.len, subif->name);
		if (my_msend(&mreq) != mreq.len)
		    my_log(CRIT, "network transmit error on %s", subif->name);
	    }
	}
    }

    // delete old messages
    if (options & OPT_RECV)
	child_expire();

    // prepare timeval
    timerclear(&tv);
    tv.tv_sec = SLEEPTIME;

    // schedule the next run
    event_add(evs, &tv);
}

void child_queue(int fd, short event) {
    struct master_msg rmsg, *msg = NULL, *qmsg = NULL, *pmsg = NULL;
    struct netif *subif, *netif;
    struct ether_hdr *ether;
    char buf[IFDESCRSIZE];
    time_t now;
    ssize_t len;

    my_log(INFO, "receiving message from master");
    len = read(fd, &rmsg, MASTER_MSG_SIZE);

    assert(len == MASTER_MSG_SIZE);
    assert(rmsg.cmd == MASTER_RECV);
    assert(rmsg.proto < PROTO_MAX);
    assert(rmsg.len >= ETHER_MIN_LEN);
    assert(rmsg.len <= ETHER_MAX_LEN);

    // skip unknown interfaces
    if ((subif = netif_byindex(&netifs, rmsg.index)) == NULL)
	return;

    // skip locally generated packets
    ether = (struct ether_hdr *)rmsg.msg;
    if (memcmp(subif->hwaddr, ether->src, ETHER_ADDR_LEN) == 0)
	return;

    // decode message
    my_log(INFO, "decoding peer name and ttl");
    if (rmsg.len != protos[rmsg.proto].peer(&rmsg))
    	return;

    memcpy(buf, rmsg.peer.name, sizeof(rmsg.peer.name));
    strnvis(rmsg.peer.name, buf, sizeof(rmsg.peer.name),
	VIS_CSTYLE|VIS_NL|VIS_TAB|VIS_OCTAL);
    memcpy(buf, rmsg.peer.port, sizeof(rmsg.peer.name));
    strnvis(rmsg.peer.port, buf, sizeof(rmsg.peer.port),
	VIS_CSTYLE|VIS_NL|VIS_TAB|VIS_OCTAL);

    // add current time to the ttl
    if ((now = time(NULL)) == (time_t)-1)
	return;
    rmsg.ttl += now;

    // fetch the parent netif
    if (subif->master)
	netif = subif->master;
    else
	netif = subif;

    TAILQ_FOREACH(qmsg, &mqueue, entries) {
	// save a pointer if the message peer matches
	if ((pmsg == NULL) &&
	    (memcmp(rmsg.msg + ETHER_ADDR_LEN, qmsg->msg + ETHER_ADDR_LEN,
		    ETHER_ADDR_LEN) == 0))
	    pmsg = qmsg;
	// match ifindex
	if (rmsg.index != qmsg->index)
	    continue;
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
	// copy everything upto the tailq_entry
	memcpy(msg, &rmsg, offsetof(struct master_msg, entries));
    } else {
	msg = my_malloc(MASTER_MSG_SIZE);
	memcpy(msg, &rmsg, MASTER_MSG_SIZE);
	// group messages per peer
	if (pmsg)
	    TAILQ_INSERT_AFTER(&mqueue, pmsg, msg, entries);
	else
	    TAILQ_INSERT_TAIL(&mqueue, msg, entries);

	my_log(CRIT, "new peer %s (%s) on interface %s",
		msg->peer.name, protos[msg->proto].name, netif->name);
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

    if ((now = time(NULL)) == (time_t)-1)
	return;

    // remove expired messages
    TAILQ_FOREACH_SAFE(msg, &mqueue, entries, nmsg) {
	if (msg->ttl >= now)
	    continue;

	my_log(CRIT, "removing peer %s (%s)",
		    msg->peer.name, protos[msg->proto].name);

	// mark the interface
	if ((subif = netif_byindex(&netifs, msg->index)) != NULL)
	    subif->update = 1;

	TAILQ_REMOVE(&mqueue, msg, entries);
	free(msg);
    }

    // update interfaces
    TAILQ_FOREACH(subif, &netifs, entries) { 
	if (!subif->update)
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

