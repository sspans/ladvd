/*
 * $Id$
 *
 * Copyright (c) 2008, 2009
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
#include "main.h"
#include <sys/file.h>
#include <ctype.h>
#include <syslog.h>

uint32_t options = OPT_DAEMON;
extern struct sysinfo sysinfo;
extern char *__progname;

int main(int argc, char *argv[]) {

    int ch, i;
    char *username = PACKAGE_USER;
    char *pidfile = PACKAGE_PID_FILE;
    char pidstr[16];
    int fd = -1;
    struct passwd *pwd = NULL;

    // save argc/argv
    int sargc;
    char **sargv;

    // sockets
    int cpair[2], mpair[2];

    // pids
    extern pid_t pid;

    // clear sysinfo
    memset(&sysinfo, 0, sizeof(struct sysinfo));

    // cli
    if (strcmp(__progname, PACKAGE_CLI) == 0)
	return 0; // cli_init(argc, argv);

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
    
	// init syslog before chrooting (including tz)
	tzset();
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
	master_init(cpair[1], mpair[1], pid);

	// not reached
	my_fatal("master process failed");

    } else {

	// cleanup
	close(cpair[1]);
	close(mpair[1]);

	// enter the child loop
	child_init(cpair[0], mpair[0], sargc, sargv, pwd);

	// not reached
	my_fatal("child process failed");
    }

    // not reached
    return (EXIT_FAILURE);
}


void usage() {

    fprintf(stderr, PACKAGE_NAME " version " PACKAGE_VERSION "\n" 
	"Usage: %s [-a] INTERFACE INTERFACE\n"
	    "\t-a = Auto-enable protocols based on received packets\n"
	    "\t-d = Dump pcap-compatible packets to stdout\n"
	    "\t-f = Run in the foreground\n"
	    "\t-h = Print this message\n"
	    "\t-m <address> = Management address (IPv4 and IPv6 supported)\n"
	    "\t-n = Use addresses specified via -m for all interfaces\n"
	    "\t-o = Run Once\n"
	    "\t-r = Receive Packets\n"
	    "\t-u <user> = Setuid User (defaults to " PACKAGE_USER ")\n"
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
	    __progname);

    exit(EXIT_FAILURE);
}

