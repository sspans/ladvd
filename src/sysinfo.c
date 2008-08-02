/*
 $Id$
*/

#include "main.h"
#include "util.h"
#include <unistd.h>
#include <netdb.h>

int sysinfo_fetch(struct sysinfo *sysinfo) {

    struct hostent *hp;

    // sysinfo.uts
    if (uname(&sysinfo->uts) == -1) {
	my_log(0, "can't fetch uname: %s", strerror(errno));
	exit(EXIT_FAILURE);
    }

    asprintf(&sysinfo->uts_str, "%s %s %s %s",
	sysinfo->uts.sysname, sysinfo->uts.release,
	sysinfo->uts.version, sysinfo->uts.machine);
    if (sysinfo->uts_str == NULL) {
	my_log(0, "can't create uts string: %s", strerror(errno));
	exit(EXIT_FAILURE);
    }

    if ((hp = gethostbyname(sysinfo->uts.nodename)) == NULL) {
	my_log(0, "cant resolve hostname: %s", hstrerror(h_errno));
	exit(EXIT_FAILURE);
    }
    sysinfo->hostname = hp->h_name;

    return(0);
}

