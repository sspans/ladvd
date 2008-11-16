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
char **saved_argv;
int saved_argc;

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

    // sysinfo
    struct sysinfo sysinfo;

    // sockets
    int spair[2], cfd, mfd;

    // pids
    pid_t pid;

    // packet
    struct master_request mreq;

    // interfaces
    struct netif *netifs = NULL, *netif, *master;

    // clear sysinfo
    memset(&sysinfo, 0, sizeof(struct sysinfo));

    // set progname
    progname = argv[0];

    // Save argv. Duplicate so setproctitle emulation doesn't clobber it
    saved_argc = argc;
    saved_argv = my_calloc(argc + 1, sizeof(*saved_argv));
    for (i = 0; i < argc; i++)
	saved_argv[i] = my_strdup(argv[i]);
    saved_argv[i] = NULL;

#ifndef HAVE_SETPROCTITLE
    /* Prepare for later setproctitle emulation */
    compat_init_setproctitle(argc, argv);
    argv = saved_argv;
#endif

    while ((ch = getopt(argc, argv, "dfhm:nou:vc:l:CEFN")) != -1) {
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

    saved_argc -= optind;
    saved_argv += optind;

    // validate interfaces
    if (netif_fetch(saved_argc, saved_argv, &sysinfo, &netifs) == 0) {
	my_log(CRIT, "unable fetch interfaces");
	exit(EXIT_FAILURE);
    }

    // validate username
    if ((do_debug == 0) && (pwd = getpwnam(username)) == NULL) {
	my_log(CRIT, "User %s does not exist", username);
	exit(EXIT_FAILURE);
    }

    // fetch system details
    sysinfo_fetch(&sysinfo);

#ifndef __APPLE__
    // open pidfile
    if (do_detach == 1) {
	fd = open(pidfile, O_WRONLY|O_CREAT, 0666);
	if (fd == -1) {
	    my_log(CRIT, "failed to open pidfile %s: %s",
			pidfile, strerror(errno));
	    exit(EXIT_FAILURE);	
	}
	if (flock(fd, LOCK_EX|LOCK_NB) == -1) {
	    my_log(CRIT, PACKAGE_NAME " already running (%s locked)", pidfile);
	    exit(EXIT_FAILURE);	
	}
    }
#endif /* __APPLE__ */

#ifndef __APPLE__
    // daemonize
    if (do_detach == 1) {
	if (daemon(0,0) == -1) {
	    my_log(CRIT, "backgrounding failed: %s", strerror(errno));
	    exit(EXIT_FAILURE);
	}

	if ((snprintf(pidstr, sizeof(pidstr), "%d\n", (int)getpid()) <= 0) ||
	    (write(fd, pidstr, strlen(pidstr)) <= 0)) {
	    my_log(CRIT, "failed to write pidfile: %s", strerror(errno));
	    exit(EXIT_FAILURE);
	}
    }
#endif /* __APPLE__ */

    // create privsep socketpair
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, spair) == -1) {
	my_log(CRIT, "privsep socketpair creation failed: %s", strerror(errno));
	exit(EXIT_FAILURE);
    }

    cfd = spair[0];
    mfd = spair[1];

    // create privsep parent / child
    pid = fork();

    // quit on failure
    if (pid == -1) {
	my_log(CRIT, "privsep fork failed: %s", strerror(errno));
	exit(EXIT_FAILURE);
    }

    // this is the parent
    if (pid != 0) {

	// enter the master loop
	master_init(pwd, mfd);

	// not reached
	my_log(CRIT, "master process failed");
	exit(EXIT_FAILURE);

    } else {
	if (do_debug == 0)
	    my_drop_privs(pwd);
	setproctitle("child");
    }


    // startup message
    my_log(CRIT, PACKAGE_STRING " running");

    while (cfd) {

	// create netifs
	my_log(INFO, "fetching all interfaces"); 
	if (netif_fetch(saved_argc, saved_argv, &sysinfo, &netifs) == 0) {
	    my_log(CRIT, "unable fetch interfaces");
	    goto sleep;
	}

	for (netif = netifs; netif != NULL; netif = netif->next) {
	    // skip autodetected slaves
	    if ((saved_argc == 0) && (netif->slave == 1))
		continue;

	    // skip unlisted interfaces
	    if ((saved_argc > 0) && (netif->argv == 0))
		continue;

	    // skip masters without slaves
	    if ((netif->type > 0) && (netif->subif == NULL)) {
		my_log(INFO, "skipping interface %s", netif->name); 
		continue;
	    }

	    my_log(INFO, "starting loop with interface %s", netif->name); 

	    // point netif to subif when netif is master
	    master = netif;

	    if (master->type > 0)
		netif = master->subif;

	    while (master != NULL) {

		// populate mreq
		mreq.index = netif->index;
		strlcpy(mreq.name, netif->name, IFNAMSIZ);
		mreq.cmd = MASTER_SEND;

		// fetch interface media status
		my_log(INFO, "fetching %s media details", netif->name);
		if (netif_media(cfd, netif) == EXIT_FAILURE) {
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
				  protos[p].name, netif->name);
		    mreq.len = protos[p].build_msg(mreq.msg, netif, &sysinfo);

		    if (mreq.len == 0) {
			my_log(CRIT, "can't generate %s packet for %s",
				  protos[p].name, netif->name);
			continue;
		    }

		    // write it to the wire.
		    my_log(INFO, "sending %s packet (%d bytes) on %s",
				  protos[p].name, mreq.len, netif->name);
		    if (my_msend(cfd, &mreq) != mreq.len) {
			my_log(CRIT, "network transmit error on %s",
				  netif->name);
		    }
		}

		// point netif to the next subif
		if (master->type == 0) {
		    master = NULL;
		} else if (netif->subif != NULL) {
		    netif = netif->subif;
		} else {
		    netif = master;
		    master = NULL;
		}
	    }
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

