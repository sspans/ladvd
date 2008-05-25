/*
 $Id$
*/

#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>
#include <sys/file.h>
#include <grp.h>
#include "main.h"

unsigned int loglevel = 0;
unsigned int do_fork = 1;

int cap_parse(const char *optarg);
void usage(const char *fn);

int main(int argc, char *argv[]) {

    int ch, dev, cap, do_cdp, do_lldp;
    int fd = -1, do_once = 0;
    char *progname = argv[0];
    char *username = USER;
    char *pidfile = PIDFILE;
    char pidstr[16];
    struct passwd *pwd;
    struct utsname uts;
    char *uts_str;
    struct session *sessions = NULL, *session_prev = NULL, *session;
    struct libnet_ether_addr *hwaddr;
    char errbuf[LIBNET_ERRBUF_SIZE];

    /* set arguments */
    do_cdp  = 0;
    do_lldp = 0;

    while ((ch = getopt(argc, argv, "clfoC:u:hv")) != -1) {
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
	    case 'C':
		cap = cap_parse(optarg);
		if (cap == -1)
		    usage(progname);
		break;
	    case 'u':
		username = optarg;
		break;
	    case 'v':
		loglevel++;
		break;
	    default:
		usage(progname);
	}
    }
    argc -= optind;
    argv += optind;

    if (argc < 1 || (do_cdp == 0 && do_lldp == 0))
	usage(progname);

    if ((pwd = getpwnam(username)) == NULL) {
	log_str(0, "User %s does not exist", username);
	exit(EXIT_FAILURE);
    }


    // uts
    if (uname(&uts) == -1) {
	log_str(0, "can't fetch uname: %s", strerror(errno));
	exit(EXIT_FAILURE);
    }

    uts_str = malloc(sizeof(struct utsname) + 10);
    if (uts_str == NULL) {
	log_str(0, "can't create uts_str: %s", strerror(errno));
	exit(EXIT_FAILURE);
    }

    snprintf(uts_str, sizeof(struct utsname) + 10, "%s %s %s %s",
	uts.sysname, uts.release, uts.version, uts.machine);

    // open pidfile
    if (do_fork == 1) {
	fd = open(pidfile, O_WRONLY|O_CREAT, 0666);
	if (fd == -1) {
	    log_str(0, "failed to open pidfile %s: %s",
			pidfile, strerror(errno));
	    exit(EXIT_FAILURE);	
	}
	if (flock(fd, LOCK_EX|LOCK_NB) == -1) {
	    log_str(0, "failed to lock pidfile %s: %s",
			pidfile, strerror(errno));
	    exit(EXIT_FAILURE);	
	}
    }

    
    // create sessions for all devices
    for (dev = 0; dev < argc; dev++) {

	if ( (session = (struct session *)malloc(sizeof(struct session)) ) == NULL) {
	    log_str(0, "memory allocation for %s failed", argv[dev]);
	    exit(EXIT_FAILURE);
	}
	bzero(session, sizeof(struct session));

	// copy device name
	if ((session->dev = strdup(argv[dev])) == NULL) {
	    log_str(0, "memory allocation failed");
	    exit(EXIT_FAILURE);
	}

	// initialize libnet
	session->libnet = libnet_init(LIBNET_LINK, session->dev, errbuf);
	if (session->libnet == NULL) {
	    log_str(0, "%s %s", session->dev, errbuf);
	    exit(EXIT_FAILURE);
	}

	// fetch ethernet hwaddr
	hwaddr = libnet_get_hwaddr(session->libnet);
	if (hwaddr == NULL) {
	    log_str(0, "can't fetch hardware address: %s", libnet_geterror(session->libnet));
	    exit(EXIT_FAILURE);
	}
	memcpy(session->hwaddr, hwaddr->ether_addr_octet, 6 * sizeof(uint8_t));

	// fetch ipv4 addr (unnumbered is acceptable)
	session->ipaddr4 = ntohl(libnet_get_ipaddr4(session->libnet));

	// TODO: ipv6
	// fetch interface details
	if (ifinfo_get(session) == EXIT_FAILURE) {
	    log_str(0, "error fetching interface details");
	    exit(EXIT_FAILURE);
	}
	

	// copy uts information
	session->uts = &uts;
	session->uts_str = uts_str;

	// copy capabilities
	session->cap = cap;
	
	// cdp packet
	if (do_cdp == 1) {

	    log_str(3, "building a cdp packet for %s", session->dev);
	    cdp_packet(session);
	    if (session->cdp_data == NULL) {
		log_str(0, "can't generate CDP packet");
		exit(EXIT_FAILURE);
	    }
	    log_str(3, "generated a cdp packet (%d bytes)",
		    session->cdp_length);
	}

	// lldp packet
	if (do_lldp == 1) {

	    log_str(3, "building an lldp packet for %s", session->dev);
	    lldp_packet(session);
	    if (session->lldp_data == NULL) {
		log_str(0, "can't generate LLDP packet");
		exit(EXIT_FAILURE);
	    }
	    log_str(3, "generated an lldp packet (%d bytes)",
		    session->lldp_length);
	}

	if (sessions == NULL)
	    sessions = session;
	else
	    session_prev->next = session;

	session_prev = session;
    }


    // fork
    if (do_fork == 1) {
	if (daemon(0,0) == -1) {
	    log_str(0, "backgrounding failed: %s", strerror(errno));
	    exit(EXIT_FAILURE);
	}
	snprintf(pidstr, sizeof(pidstr), "%u\n", getpid());
	write(fd, pidstr, strlen(pidstr));
    }


    // TODO: chroot


    // setuid & setgid
    if(setgid(pwd->pw_gid) == -1){
	log_str(0, "unable to setgid: %s", strerror(errno));
       	exit(EXIT_FAILURE);
    }

    if(setgroups(0, NULL) == -1){
	log_str(0, "unable to setgroups: %s", strerror(errno));
       	exit(EXIT_FAILURE);
    }

    if(setuid(pwd->pw_uid) == -1){
   	log_str(0, "unable to setuid: %s", strerror(errno));
       	exit(EXIT_FAILURE);
    }


    while (1) {

	for (session = sessions; session != NULL; session = session->next) {
	    log_str(3, "starting loop with interface %s", session->dev); 

	    if (do_cdp == 1)
		log_str(3, "sending cdp packet (%d bytes)",
			session->cdp_length); 
		cdp_send(session); 

	    if (do_lldp == 1)
		log_str(3, "sending lldp packet (%d bytes)",
			session->lldp_length); 
		lldp_send(session); 
	}

	if (do_once == 1)
	    return (EXIT_SUCCESS);

	log_str(3, "sleeping for %d seconds", SLEEPTIME);
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
	"Usage: %s [-c] [-l] [-r] [-f] [-u %s ] INTERFACE INTERFACE\n"
	    "\t-c = Send CDP Messages\n"
	    "\t-l = Send LLDP Messages\n"
	    "\t-f = Run in the foreground\n"
	    "\t-o = Run Once\n"
	    "\t-u <user> = Setuid User (defaults to %s)\n"
	    "\t-C <capability> = System Capabilities\n"
	    "\tB - Bridge, H - Host, R - Router\n"
	    "\tS - Switch, W - WLAN Access Point\n"
	    "\t-v = Increase logging verbosity\n"
	    "\t-h = Print this message\n",
	    PACKAGE_NAME, PACKAGE_VERSION, fn, USER, USER);

    exit(EXIT_FAILURE);
}

void log_str(int prio, const char *fmt, ...) {

    va_list ap;
    va_start(ap, fmt);

    if (prio > loglevel)
	return;

    if (do_fork == 1) {
	vsyslog(LOG_INFO, fmt, ap);
    } else {
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
    }
}

