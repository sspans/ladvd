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
unsigned int do_debug = 0;

void usage(const char *fn);
void cleanup();

int main(int argc, char *argv[]) {

    int ch, do_cdp, do_lldp, do_once;
    int fd = -1;
    char *progname = argv[0];
    char *username = PACKAGE_USER;
    char *pidfile = PACKAGE_PID_FILE;
    char pidstr[16];
    struct passwd *pwd = NULL;
    struct sigaction cleanup_action;

    // sysinfo
    struct sysinfo sysinfo;
    struct hostent *hp;

    // socket
    int sockfd;

    // packet
    struct packet packet;
    size_t len;

    // interfaces
    struct netif *netifs = NULL, *netif, *master;

#ifdef USE_CAPABILITIES
    // capabilities
    cap_t caps;
#endif

    /* set arguments */
    do_cdp  = 0;
    do_lldp = 0;
    do_once = 0;
    memset(&sysinfo, 0, sizeof(struct sysinfo));

    while ((ch = getopt(argc, argv, "cdfhlou:vL:")) != -1) {
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
	    case 'd':
		do_debug = 1;
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

    // validate interfaces
    if (netif_list(argc, argv, &sysinfo, &netifs) == 0) {
	my_log(0, "unable fetch interfaces");
	exit(EXIT_FAILURE);
    }

    // default to CAP_HOST
    sysinfo.cap |= CAP_HOST;

    // validate username
    if ((do_debug == 0) && (pwd = getpwnam(username)) == NULL) {
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

    // open a raw socket
    sockfd = my_rsocket();

    if (sockfd < 0) {
	my_log(0, "opening raw socket failed");
	exit(EXIT_FAILURE);
    }

    // debug
    if (do_debug == 1)
	goto loop;

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


loop: 
    // startup message
    my_log(0, PACKAGE_STRING " running");

    while (sockfd) {

	// create netifs
	my_log(3, "fetching all interfaces"); 
	if (netif_list(argc, argv, &sysinfo, &netifs) == 0) {
	    my_log(0, "unable fetch interfaces");
	    goto sleep;
	}

	for (netif = netifs; netif != NULL; netif = netif->next) {
	    // skip autodetected slaves
	    if ((argc == 0) && (netif->slave == 1))
		continue;

	    // skip unlisted interfaces
	    if ((argc > 0) && (netif->argv == 0))
		continue;

	    // skip masters without slaves
	    if ((netif->type > 0) && (netif->subif == NULL)) {
		my_log(3, "skipping interface %s", netif->name); 
		continue;
	    }

	    my_log(3, "starting loop with interface %s", netif->name); 

	    // point netif to subif when netif is master
	    if (netif->type > 0) {
		master = netif;
		netif = master->subif;
	    } else {
		master = NULL;
	    }

	    while (netif != NULL) {
		// fetch interface media status
		my_log(3, "fetching %s media details", netif->name);
		if (netif_media(netif) == EXIT_FAILURE) {
		    my_log(0, "error fetching interface media details");
		}

		// cdp packet
		if (do_cdp == 1) {
		    my_log(3, "building cdp packet for %s", netif->name);
		    len = cdp_packet(&packet, netif, &sysinfo);
		    if (len == 0) {
			my_log(0, "can't generate CDP packet for %s",
				  netif->name);
			goto sleep;
		    }

		    // write it to the wire.
		    my_log(3, "sending cdp packet (%d bytes) on %s",
				len, netif->name);
		    if (my_rsend(sockfd, netif, &packet, len) != len) {
			my_log(0, "network transmit error on %s",
				  netif->name);
		    }
		}

		// lldp packet
		if (do_lldp == 1) {
		    my_log(3, "building lldp packet for %s", netif->name);

		    len = lldp_packet(&packet, netif, &sysinfo);
		    if (len == 0) {
			my_log(0, "can't generate LLDP packet for %s",
				  netif->name);
			goto sleep;
		    }

		    // write it to the wire.
		    my_log(3, "sending lldp packet (%d bytes) on %s",
				len, netif->name);
		    if (my_rsend(sockfd, netif, &packet, len) != len) {
			my_log(0, "network transmit error on %s",
				  netif->name);
		    }
		}

		if (master != NULL)
		    netif = netif->subif;
		else
		    netif = NULL;
	    }
	}

sleep:
	if (do_once == 1)
	    return (EXIT_SUCCESS);

	my_log(3, "sleeping for %d seconds", SLEEPTIME);
	sleep(SLEEPTIME);
    }

    return (EXIT_SUCCESS);
}

void usage(const char *fn) {

    fprintf(stderr, "%s version %s\n" 
	"Usage: %s [-c] [-l] [-f] INTERFACE INTERFACE\n"
	    "\t-c = Send CDP Messages\n"
	    "\t-l = Send LLDP Messages\n"
	    "\t-f = Run in the foreground\n"
	    "\t-o = Run Once\n"
	    "\t-u <user> = Setuid User (defaults to %s)\n"
	    "\t-L <location> = System Location\n"
	    "\t-v = Increase logging verbosity\n"
	    "\t-d = Dump packets to stdout\n"
	    "\t-h = Print this message\n",
	    PACKAGE_NAME, PACKAGE_VERSION, fn, PACKAGE_USER);

    exit(EXIT_FAILURE);
}

void cleanup() {
    if (unlink(PACKAGE_PID_FILE) < 0) {
	exit(EXIT_SUCCESS);
    } else {
	my_log(0, "pidfile cleanup failed: %s", strerror(errno));
	exit(EXIT_FAILURE);
    }
}
