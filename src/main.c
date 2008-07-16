/*
 $Id$
*/

#include "main.h"
#include "util.h"
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <netdb.h>
#include <signal.h>

#ifdef USE_CAPABILITIES
#include <sys/prctl.h>
#include <sys/capability.h>
#endif

extern unsigned int loglevel;
unsigned int do_fork = 1;

int cap_parse(const char *optarg);
void usage(const char *fn);
void cleanup();

int main(int argc, char *argv[]) {

    int ch, do_cdp, do_lldp, do_once;
    int fd = -1;
    char *progname = argv[0];
    char *username = PACKAGE;
    char *pidfile = PIDFILE;
    char pidstr[16];
    struct passwd *pwd;
    struct sigaction cleanup_action;

    // sysinfo
    struct sysinfo sysinfo;
    struct hostent *hp;

    // interfaces
    struct session *sessions = NULL, *session, *csession;

#ifdef USE_CAPABILITIES
    // capabilities
    cap_t caps;
#endif

    /* set arguments */
    do_cdp  = 0;
    do_lldp = 0;
    do_once = 0;
    bzero(&sysinfo, sizeof(struct sysinfo));

    while ((ch = getopt(argc, argv, "clfou:hvC:L:")) != -1) {
	switch(ch) {
	    case 'c':
		do_cdp = 1;
		break;
	    case 'l':
		do_lldp = 1;
		break;
	    case 'f':
		do_fork = 0;
		break;
	    case 'o':
		do_once = 1;
		break;
	    case 'u':
		username = optarg;
		break;
	    case 'v':
		loglevel++;
		break;
	    case 'C':
		sysinfo.cap = cap_parse(optarg);
		if (sysinfo.cap == -1)
		    usage(progname);
		break;
	    case 'L':
		sysinfo.location = optarg;
		break;
	    default:
		usage(progname);
	}
    }

    argc -= optind;
    argv += optind;

    if (do_cdp == 0 && do_lldp == 0)
	usage(progname);

    // default to CAP_HOST
    if (sysinfo.cap == 0)
	sysinfo.cap |= CAP_HOST;

    // fetch all interfaces
    sessions = netif_fetch(argc, argv, &sysinfo);

    // validate username
    if ((pwd = getpwnam(username)) == NULL) {
	my_log(0, "User %s does not exist", username);
	exit(EXIT_FAILURE);
    }

    // sysinfo.uts
    if (uname(&sysinfo.uts) == -1) {
	my_log(0, "can't fetch uname: %s", strerror(errno));
	exit(EXIT_FAILURE);
    }

    asprintf(&sysinfo.uts_str, "%s %s %s %s",
	sysinfo.uts.sysname, sysinfo.uts.release,
	sysinfo.uts.version, sysinfo.uts.machine);
    if (sysinfo.uts_str == NULL) {
	my_log(0, "can't createsysinfo.uts_str: %s", strerror(errno));
	exit(EXIT_FAILURE);
    }

    if ((hp = gethostbyname(sysinfo.uts.nodename)) == NULL) {
	my_log(0, "cant resolve hostname: %s", hstrerror(h_errno));
	exit(EXIT_FAILURE);
    }
    sysinfo.hostname = hp->h_name;

    // open pidfile
    if (do_fork == 1) {
	fd = open(pidfile, O_WRONLY|O_CREAT, 0666);
	if (fd == -1) {
	    my_log(0, "failed to open pidfile %s: %s",
			pidfile, strerror(errno));
	    exit(EXIT_FAILURE);	
	}
	if (flock(fd, LOCK_EX|LOCK_NB) == -1) {
	    my_log(0, "failed to lock pidfile %s: %s",
			pidfile, strerror(errno));
	    exit(EXIT_FAILURE);	
	}
	if (fchown(fd, pwd->pw_uid, -1) == -1) {
	    my_log(0, "failed to chown pidfile %s: %s",
			pidfile, strerror(errno));
	    exit(EXIT_FAILURE);	
	}

	/* cleanup pidfile when shutting down */
	cleanup_action.sa_handler = cleanup;
	cleanup_action.sa_flags = 0;
	sigemptyset(&cleanup_action.sa_mask);

	sigaction (SIGTERM, &cleanup_action, NULL);
    }

    // open raw sockets on all physical devices
    for (session = sessions; session != NULL; session = session->next) {

	// skip masters
	if (session->if_master > 0)
	    continue;

	session->sockfd = my_rsocket(session->if_name);

	if (session->sockfd < 0) {
	    my_log(0, "opening socket on %s failed", session->if_name);
	    exit(EXIT_FAILURE);
	}
    }


    // fork
    if (do_fork == 1) {
	if (daemon(0,0) == -1) {
	    my_log(0, "backgrounding failed: %s", strerror(errno));
	    exit(EXIT_FAILURE);
	}
	snprintf(pidstr, sizeof(pidstr), "%u\n", getpid());
	write(fd, pidstr, strlen(pidstr));
    }

#ifdef USE_CAPABILITIES
    // keep capabilities
    if (prctl(PR_SET_KEEPCAPS,1) == -1) {
	my_log(0, "unable to keep capabilities: %s", strerror(errno));
       	exit(EXIT_FAILURE);
    }
#endif

    // setuid & setgid
    if (setgid(pwd->pw_gid) == -1){
	my_log(0, "unable to setgid: %s", strerror(errno));
       	exit(EXIT_FAILURE);
    }

    if (setgroups(0, NULL) == -1){
	my_log(0, "unable to setgroups: %s", strerror(errno));
       	exit(EXIT_FAILURE);
    }

    if (setuid(pwd->pw_uid) == -1){
   	my_log(0, "unable to setuid: %s", strerror(errno));
       	exit(EXIT_FAILURE);
    }


#ifdef USE_CAPABILITIES
    // keep CAP_NET_ADMIN
    caps = cap_from_text("cap_net_admin=ep");

    if (caps == NULL) {
	my_log(0, "unable to create capabilities: %s", strerror(errno));
	exit(EXIT_FAILURE);
    }

    if (cap_set_proc(caps) == -1) {
	my_log(0, "unable to set capabilities: %s", strerror(errno));
	exit(EXIT_FAILURE);
    }

    cap_free(caps);
#endif

    while (sessions) {

	// fetch IPv4 / IPv6 / MAC addrs
	my_log(3, "fetching addresses for all interfaces"); 
	if (netif_addrs(sessions) == EXIT_FAILURE) {
	    my_log(0, "unable fetch interface addresses");
	    exit(EXIT_FAILURE);
	};

	for (session = sessions; session != NULL; session = session->next) {
	    // skip slaves
	    if (session->if_slave == 1)
		continue;

	    // skip masters without slaves
	    if ((session->if_master > 0) && (session->subif == NULL)) {
		my_log(3, "skipping interface %s", session->if_name); 
		continue;
	    }

	    my_log(3, "starting loop with interface %s", session->if_name); 

	    // point csession to subif when session is master
	    if (session->if_master > 0)
		csession = session->subif;
	    else
		csession = session;

	    while (csession != NULL) {
		// fetch interface media status
		my_log(3, "fetching %s media details", csession->if_name);
		if (netif_media(csession) == EXIT_FAILURE) {
		    my_log(0, "error fetching interface media details");
		}

		// cdp packet
		if (do_cdp == 1) {
		    my_log(3, "building a cdp packet for %s",
				csession->if_name);

		    if (cdp_packet(csession, session, &sysinfo) == 0) {
			my_log(0, "can't generate CDP packet");
			exit(EXIT_FAILURE);
		    }

		    my_log(3, "sending cdp packet (%d bytes)",
				csession->cdp_len);
		    cdp_send(csession); 
		}

		// lldp packet
		if (do_lldp == 1) {
		    my_log(3, "building a lldp packet for %s",
				csession->if_name);

		    if (lldp_packet(csession, session, &sysinfo) == 0) {
			my_log(0, "can't generate LLDP packet");
			exit(EXIT_FAILURE);
		    }

		    my_log(3, "sending lldp packet (%d bytes)",
				csession->lldp_len);
		    lldp_send(csession); 
		}

		if (session->if_master > 0)
		    csession = csession->subif;
		else
		    csession = NULL;
	    }
	}

	if (do_once == 1)
	    return (EXIT_SUCCESS);

	my_log(3, "sleeping for %d seconds", SLEEPTIME);
	sleep(SLEEPTIME);
    }

    return (EXIT_SUCCESS);
}

int cap_parse(const char *optarg) {
    int cap = 0, i;

    for (i = 0; i < strlen(optarg); i++) {
	switch(optarg[i]) {
	    case 'b':
	    case 'B':
		cap |= CAP_BRIDGE;
		break;
	    case 'h':
	    case 'H':
		cap |= CAP_HOST;
		break;
	    case 'r':
	    case 'R':
		cap |= CAP_ROUTER;
		break;
	    case 's':
	    case 'S':
		cap |= CAP_SWITCH;
		break;
	    case 'w':
	    case 'W':
		cap |= CAP_WLAN;
		break;
	    default:
		return(-1);
	}
    }
    return(cap);
}

void usage(const char *fn) {

    fprintf(stderr, "%s version %s\n" 
	"Usage: %s [-c] [-l] [-f] INTERFACE INTERFACE\n"
	    "\t-c = Send CDP Messages\n"
	    "\t-l = Send LLDP Messages\n"
	    "\t-f = Run in the foreground\n"
	    "\t-o = Run Once\n"
	    "\t-u <user> = Setuid User (defaults to %s)\n"
	    "\t-v = Increase logging verbosity\n"
	    "\t-C <capability> = System Capabilities\n"
	    "\t\tB - Bridge, H - Host, R - Router\n"
	    "\t\tS - Switch, W - WLAN Access Point\n"
	    "\t-L <location> = System Location\n"
	    "\t-h = Print this message\n",
	    PACKAGE_NAME, PACKAGE_VERSION, fn, PACKAGE);

    exit(EXIT_FAILURE);
}

void cleanup() {
    if (unlink(PIDFILE) < 0) {
	exit(EXIT_SUCCESS);
    } else {
	my_log("pidfile cleanup failed: %s", strerror(errno));
	exit(EXIT_FAILURE);
    }
}
