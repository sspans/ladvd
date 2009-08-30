/*
 $Id$
*/

#include "common.h"
#include "util.h"
#include "proto/protos.h"
#include "main.h"
#include <ctype.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <time.h>

uint32_t options = OPT_DAEMON;

void usage();
void queue_msg(int fd, short event);

int main(int argc, char *argv[]) {

    int ch, i, p;
    char *username = PACKAGE_USER;
#ifndef __APPLE__
    char *pidfile = PACKAGE_PID_FILE;
    char pidstr[16];
    int fd = -1;
#endif /* __APPLE__ */
    struct passwd *pwd = NULL;

    // save argc/argv
    int sargc;
    char **sargv;

    // sysinfo
    struct sysinfo sysinfo;

    // sockets
    int cpair[2], mpair[2], rsock = -1;
    extern int msock;

    // pids
    pid_t pid;

    // packets
    struct master_msg mreq, *msg = NULL, *nmsg = NULL;

    // interfaces
    struct netif *netif = NULL, *subif = NULL;

    // receiving
    struct event evmsg;
    struct timeval tv;
    time_t now;

    // init the queues
    TAILQ_INIT(&netifs);
    TAILQ_INIT(&mqueue);

    // clear sysinfo
    memset(&sysinfo, 0, sizeof(struct sysinfo));

    // Save argv. Duplicate so setproctitle emulation doesn't clobber it
    sargc = argc;
    sargv = my_calloc(argc + 1, sizeof(*sargv));
    for (i = 0; i < argc; i++)
	sargv[i] = my_strdup(argv[i]);
    sargv[i] = NULL;

#ifndef HAVE_SETPROCTITLE
    /* Prepare for later setproctitle emulation */
    compat_init_setproctitle(argc, argv);
    argv = sargv;
#endif

    while ((ch = getopt(argc, argv, "adfhm:noru:vwzc:l:CEFN")) != -1) {
	switch(ch) {
	    case 'a':
		options |= OPT_AUTO | OPT_RECV;
		break;
	    case 'd':
		options |= OPT_DEBUG;
		options &= ~OPT_DAEMON;
		break;
	    case 'f':
		options &= ~OPT_DAEMON;
		break;
	    case 'm':
		if ( (inet_pton(AF_INET, optarg, &sysinfo.maddr4) != 1) &&
		     (inet_pton(AF_INET6, optarg, &sysinfo.maddr6) != 1) ) {
		    my_log(CRIT, "invalid management address %s", optarg);
		    usage();
		}
		break;
	    case 'n':
		options |= OPT_MADDR;
		break;
	    case 'o':
		options |= OPT_ONCE;
		break;
	    case 'r':
		options |= OPT_RECV;
		break;
	    case 'u':
		username = optarg;
		break;
	    case 'v':
		loglevel++;
		break;
	    case 'w':
		options |= OPT_WIRELESS;
		break;
	    case 'z':
#ifdef SIOCSIFDESCR
		options |= OPT_RECV | OPT_DESCR;
		break;
#else
		my_log(CRIT, "ifdescr support not available");
		usage();
#endif /* SIOCSIFDESCR */
	    case 'c':
		// two-letter ISO 3166 country code
		if (strlen(optarg) != 2)
		    usage();
		// in capital ASCII letters
		sysinfo.country[0] = toupper(optarg[0]);
		sysinfo.country[1] = toupper(optarg[1]);
		break;
	    case 'l':
		if (strlcpy(sysinfo.location, optarg, 
			sizeof(sysinfo.location)) == 0)
		    usage();
		break;
	    case 'C':
		protos[PROTO_CDP].enabled = 1;
		break;
	    case 'E':
		protos[PROTO_EDP].enabled = 1;
		break;
	    case 'F':
		protos[PROTO_FDP].enabled = 1;
		break;
	    case 'N':
		protos[PROTO_NDP].enabled = 1;
		break;
	    default:
		usage();
	}
    }

    sargc -= optind;
    sargv += optind;

    // set argv option
    if (sargc)
	options |= OPT_ARGV;

    // validate username
    if (!(options & OPT_DEBUG) && (pwd = getpwnam(username)) == NULL)
	my_fatal("user %s does not exist", username);

    // fetch system details
    sysinfo_fetch(&sysinfo);

    if (options & OPT_DAEMON) {
	// run in the background
	if (daemon(0,0) == -1)
	    my_fatal("backgrounding failed: %s", strerror(errno));

	// create pidfile
	fd = open(pidfile, O_WRONLY|O_CREAT, 0666);
	if (fd == -1)
	    my_fatal("failed to open pidfile %s: %s", pidfile, strerror(errno));
	if (flock(fd, LOCK_EX|LOCK_NB) == -1)
	    my_fatal(PACKAGE_NAME " already running (%s locked)", pidfile);

	if ((snprintf(pidstr, sizeof(pidstr), "%d\n", (int)getpid()) <= 0) ||
	    (write(fd, pidstr, strlen(pidstr)) <= 0))
	    my_fatal("failed to write pidfile: %s", strerror(errno));
    
	// call openlog before chrooting
	openlog(PACKAGE_NAME, LOG_NDELAY, LOG_DAEMON);
    }

    // init cmd/msg socketpair
    my_socketpair(cpair);
    my_socketpair(mpair);

    // create privsep parent / child
    pid = fork();

    // quit on failure
    if (pid == -1)
	my_fatal("privsep fork failed: %s", strerror(errno));

    // this is the parent
    if (pid != 0) {

	// cleanup
	close(cpair[0]);
	close(mpair[0]);

	// enter the master loop
	master_init(pid, cpair[1], mpair[1]);

	// not reached
	my_fatal("master process failed");

    } else {
	// cleanup
	close(cpair[1]);
	close(mpair[1]);

	msock = cpair[0];
	rsock = mpair[0];

	if (!(options & OPT_DEBUG)) {
	    my_chroot(PACKAGE_CHROOT_DIR);
	    my_drop_privs(pwd);
	}
	setproctitle("child");
    }


    // startup message
    my_log(CRIT, PACKAGE_STRING " running");

    // initalize the event library
    if (options & OPT_RECV) {
	event_init();
	event_set(&evmsg, rsock, EV_READ|EV_PERSIST, (void *)queue_msg, NULL);
	event_add(&evmsg, NULL);
    }

    while (msock) {

	// update netifs
	my_log(INFO, "fetching all interfaces"); 
	if (netif_fetch(sargc, sargv, &sysinfo, &netifs) == 0) {
	    my_log(CRIT, "unable to fetch interfaces");
	    goto sleep;
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
		if (netif_media(subif) == EXIT_FAILURE) {
		    my_log(CRIT, "error fetching interface media details");
		}

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
		    if (my_msend(&mreq) != mreq.len) {
			my_log(CRIT, "network transmit error on %s",
				  subif->name);
		    }
		}
	    }
	}

sleep:
	if (options & OPT_ONCE)
	    return (EXIT_SUCCESS);

	if (!(options & OPT_RECV)) {
	    my_log(INFO, "sleeping for %d seconds", SLEEPTIME);
	    sleep(SLEEPTIME);
	    continue;
	}

	// prepare timeval
	memset(&tv, 0, sizeof(tv));
	tv.tv_sec = SLEEPTIME;

	// listen for messages from the master
	event_loopexit(&tv);
	event_dispatch();

	if ((now = time(NULL)) == (time_t)-1)
	    continue;

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
	    if (subif->update == 0)
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

    return (EXIT_FAILURE);
}


void queue_msg(int fd, short event) {

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


void usage() {
    extern char *__progname;

    fprintf(stderr, "%s version %s\n" 
	"Usage: %s [-c] [-l] [-f] INTERFACE INTERFACE\n"
	    "\t-a = Auto-enable protocols based on received packets\n"
	    "\t-d = Dump pcap-compatible packets to stdout\n"
	    "\t-f = Run in the foreground\n"
	    "\t-h = Print this message\n"
	    "\t-m <address> = Management address (IPv4 and IPv6 supported)\n"
	    "\t-n = Use addresses specified via -m for all interfaces\n"
	    "\t-o = Run Once\n"
	    "\t-r = Receive Packets\n"
	    "\t-u <user> = Setuid User (defaults to %s)\n"
	    "\t-v = Increase logging verbosity\n"
	    "\t-w = Use wireless interfaces\n"
#ifdef SIOCSIFDESCR
	    "\t-z = Save received info in interface description\n"
#endif /* SIOCSIFDESCR */
	    "\t-c <CC> = System Country Code\n"
	    "\t-l <location> = System Location\n"
	    "\t-C = Enable CDP\n"
	    "\t-E = Enable EDP\n"
	    "\t-F = Enable FDP\n"
	    "\t-N = Enable NDP\n",
	    PACKAGE_NAME, PACKAGE_VERSION, __progname, PACKAGE_USER);

    exit(EXIT_FAILURE);
}

