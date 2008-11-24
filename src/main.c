/*
 $Id$
*/

#include "common.h"
#include "main.h"
#include "util.h"
#include <ctype.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>

char *progname;

extern unsigned int loglevel;
unsigned int do_detach = 1;
unsigned int do_debug = 0;
unsigned int do_recv = 0;

void usage(const char *fn);

int main(int argc, char *argv[]) {

    int ch, i, p, run_once = 0;
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
    int spair[2], cfd, mfd;

    // pids
    pid_t pid;

    // packet
    struct master_request mreq;

    // interfaces
    struct netif *netifs = NULL, *netif = NULL, *subif = NULL;
    uint16_t netifc = 0;

    // clear sysinfo
    memset(&sysinfo, 0, sizeof(struct sysinfo));

    // set progname
    progname = argv[0];

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

    while ((ch = getopt(argc, argv, "dfhm:noru:vc:l:CEFN")) != -1) {
	switch(ch) {
	    case 'd':
		do_debug = 1;
		do_detach = 0;
		break;
	    case 'f':
		do_detach = 0;
		break;
	    case 'm':
		if ( (inet_pton(AF_INET, optarg, &sysinfo.maddr4) != 1) &&
		     (inet_pton(AF_INET6, optarg, &sysinfo.maddr6) != 1) ) {
		    my_log(CRIT, "invalid management address %s", optarg);
		    usage(progname);
		}
		break;
	    case 'n':
		sysinfo.maddr_force = 1;
		break;
	    case 'o':
		run_once = 1;
		break;
	    case 'r':
		do_recv = 1;
		break;
	    case 'u':
		username = optarg;
		break;
	    case 'v':
		loglevel++;
		break;
	    case 'c':
		// two-letter ISO 3166 country code
		if (strlen(optarg) != 2)
		    usage(progname);
		// in capital ASCII letters
		sysinfo.country[0] = toupper(optarg[0]);
		sysinfo.country[1] = toupper(optarg[1]);
		break;
	    case 'l':
		if (strlcpy(sysinfo.location, optarg, 
			sizeof(sysinfo.location)) == 0)
		    usage(progname);
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
		usage(progname);
	}
    }

    sargc -= optind;
    sargv += optind;

    // validate interfaces
    netifc = netif_fetch(sargc, sargv, &sysinfo, &netifs);
    if (netifc == 0)
	my_fatal("unable fetch interfaces");

    // validate username
    if ((do_debug == 0) && (pwd = getpwnam(username)) == NULL)
	my_fatal("user %s does not exist", username);

    // fetch system details
    sysinfo_fetch(&sysinfo);

#ifndef __APPLE__
    // open pidfile
    if (do_detach == 1) {
	fd = open(pidfile, O_WRONLY|O_CREAT, 0666);
	if (fd == -1)
	    my_fatal("failed to open pidfile %s: %s", pidfile, strerror(errno));
	if (flock(fd, LOCK_EX|LOCK_NB) == -1)
	    my_fatal(PACKAGE_NAME " already running (%s locked)", pidfile);
    }
#endif /* __APPLE__ */

#ifndef __APPLE__
    // daemonize
    if (do_detach == 1) {
	if (daemon(0,0) == -1)
	    my_fatal("backgrounding failed: %s", strerror(errno));

	if ((snprintf(pidstr, sizeof(pidstr), "%d\n", (int)getpid()) <= 0) ||
	    (write(fd, pidstr, strlen(pidstr)) <= 0))
	    my_fatal("failed to write pidfile: %s", strerror(errno));
    }
#endif /* __APPLE__ */

    // create privsep socketpair
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, spair) == -1)
	my_fatal("privsep socketpair creation failed: %s", strerror(errno));

    cfd = spair[0];
    mfd = spair[1];

    // create privsep parent / child
    pid = fork();

    // quit on failure
    if (pid == -1)
	my_fatal("privsep fork failed: %s", strerror(errno));

    // this is the parent
    if (pid != 0) {

	// cleanup
	close(cfd);

	// enter the master loop
	master_init(protos, netifs, netifc, sargc, pwd, mfd);

	// not reached
	my_fatal("master process failed");

    } else {
	// cleanup
	close(mfd);

	if (do_debug == 0)
	    my_drop_privs(pwd);
	setproctitle("child");
    }


    // startup message
    my_log(CRIT, PACKAGE_STRING " running");

    while (cfd) {

	// create netifs
	my_log(INFO, "fetching all interfaces"); 
	if (netif_fetch(sargc, sargv, &sysinfo, &netifs) == 0) {
	    my_log(CRIT, "unable fetch interfaces");
	    goto sleep;
	}

	netif = netifs;
	while ((netif = netif_iter(netif, sargc)) != NULL) {

	    my_log(INFO, "starting loop with interface %s", netif->name); 

	    while ((subif = subif_iter(subif, netif)) != NULL) {

		// populate mreq
		mreq.index = subif->index;
		strlcpy(mreq.name, subif->name, IFNAMSIZ);
		mreq.cmd = MASTER_SEND;

		// fetch interface media status
		my_log(INFO, "fetching %s media details", subif->name);
		if (netif_media(cfd, subif) == EXIT_FAILURE) {
		    my_log(CRIT, "error fetching interface media details");
		}

		// generate and send packets
		for (p = 0; protos[p].name != NULL; p++) {

		    // only enabled protos
		    if (protos[p].enabled == 0)
			continue;

		    // clear packet
		    memset(mreq.msg, 0, ETHER_MAX_LEN);

		    my_log(INFO, "building %s packet for %s", 
				  protos[p].name, subif->name);
		    mreq.len = protos[p].build_msg(mreq.msg, subif, &sysinfo);

		    if (mreq.len == 0) {
			my_log(CRIT, "can't generate %s packet for %s",
				  protos[p].name, subif->name);
			continue;
		    }

		    // write it to the wire.
		    my_log(INFO, "sending %s packet (%d bytes) on %s",
				  protos[p].name, mreq.len, subif->name);
		    if (my_msend(cfd, &mreq) != mreq.len) {
			my_log(CRIT, "network transmit error on %s",
				  subif->name);
		    }
		}
	    }
	    netif = netif->next;
	}

sleep:
	if (run_once == 1)
	    return (EXIT_SUCCESS);

	my_log(INFO, "sleeping for %d seconds", SLEEPTIME);
	(void) sleep(SLEEPTIME);
    }

    return (EXIT_SUCCESS);
}

void usage(const char *fn) {

    fprintf(stderr, "%s version %s\n" 
	"Usage: %s [-c] [-l] [-f] INTERFACE INTERFACE\n"
	    "\t-d = Dump pcap-compatible packets to stdout\n"
	    "\t-f = Run in the foreground\n"
	    "\t-h = Print this message\n"
	    "\t-m <address> = Management address (IPv4 and IPv6 supported)\n"
	    "\t-n = Use addresses specified via -m for all interfaces\n"
	    "\t-o = Run Once\n"
	    "\t-r = Receive Packets\n"
	    "\t-u <user> = Setuid User (defaults to %s)\n"
	    "\t-v = Increase logging verbosity\n"
	    "\t-c <CC> = System Country Code\n"
	    "\t-l <location> = System Location\n"
	    "\t-C = Enable CDP\n"
	    "\t-E = Enable EDP\n"
	    "\t-F = Enable FDP\n"
	    "\t-N = Enable NDP\n",
	    PACKAGE_NAME, PACKAGE_VERSION, fn, PACKAGE_USER);

    exit(EXIT_FAILURE);
}

