/*
 $Id$
*/

#include "common.h"
#include "util.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <grp.h>
#include <unistd.h>

unsigned int loglevel = CRIT;
extern unsigned int do_detach;
extern unsigned int do_debug;

void my_log(unsigned int prio, const char *fmt, ...) {

    va_list ap;
    va_start(ap, fmt);

    if (prio > loglevel)
	return;

    if (do_detach == 1) {
	(void) vsyslog(LOG_INFO, fmt, ap);
    } else {
	(void) vfprintf(stderr, fmt, ap);
	(void) fprintf(stderr, "\n");
    }
}

void my_fatal(const char *fmt, ...) {
    va_list args;

    va_start(args, fmt);
    my_log(CRIT, fmt, args);
    va_end(args);
    exit(EXIT_FAILURE);
}

void * my_malloc(size_t size) {
    void *ptr;

    if ((ptr = malloc(size)) == NULL)
	my_fatal("malloc failed: %s", strerror(errno));
    memset(ptr, 0, size);
    return(ptr);
}

void * my_calloc(size_t nmemb, size_t size) {
    void *ptr;

    if ((ptr = calloc(nmemb, size)) == NULL)
	my_fatal("calloc failed: %s", strerror(errno));

    return(ptr);
}

char * my_strdup(const char *str) {
    char *cstr;

    if ((cstr = strdup(str)) == NULL)
	my_fatal("strdup failed: %s", strerror(errno));

    return(cstr);
}

int my_socket(int af, int type, int proto) {
    int s;

    if ((s = socket(af, type, proto)) < 0)
	my_fatal("opening socket failed: %s", strerror(errno));

    return(s);
}

size_t my_msend(int s, struct master_request *mreq) {
    size_t count = 0;

    count = write(s, mreq, MASTER_REQ_SIZE);
    if (count != MASTER_REQ_SIZE)
	my_fatal("only %d bytes written: %s", count, strerror(errno));

    count = recv(s, mreq, MASTER_REQ_SIZE, 0);
    if (count != MASTER_REQ_SIZE)
	my_fatal("invalid reply received from master");

    if (mreq->completed != 1) {
	my_log(WARN, "request failed");
	return(0);
    } else {
	return(mreq->len);
    }
};

struct netif *netif_byindex(struct netif *netifs, uint32_t index) {
    struct netif *netif;

    for (netif = netifs; netif != NULL; netif = netif->next) {
	if (netif->index == index)
	    break;
    }
    return(netif);
}

struct netif *netif_byname(struct netif *netifs, char *name) {
    struct netif *netif;

    for (netif = netifs; netif != NULL; netif = netif->next) {
	if (strcmp(netif->name, name) == 0)
	    break;
    }
    return(netif);
}

int read_line(char *path, char *line, uint16_t len) {
    FILE *file;
    char *newline;

    if ((file = fopen(path, "r")) == NULL)
	return(-1);

    if (fgets(line, len, file) == NULL) {
	(void) fclose(file);
	return(-1);
    }
    (void) fclose(file);

    // remove newline
    newline = strchr(line, '\n');
    if (newline != NULL)
	*newline = '\0';

    return(strlen(line));
}

// adapted from openssh's safely_chroot
void my_chroot(const char *path) {
    const char *cp;
    char component[MAXPATHLEN];
    struct stat st;

    if (*path != '/')
	my_fatal("chroot path does not begin at root");
    if (strlen(path) >= sizeof(component))
	my_fatal("chroot path too long");

    for (cp = path; cp != NULL;) {
	if ((cp = strchr(cp, '/')) == NULL)
	    strlcpy(component, path, sizeof(component));
	else {
	    cp++;
	    memcpy(component, path, cp - path);
	    component[cp - path] = '\0';
	}

	if (stat(component, &st) != 0)
	    my_fatal("stat(\"%s\"): %s", component, strerror(errno));
	if (st.st_uid != 0 || (st.st_mode & 022) != 0)
	    my_fatal("bad ownership or modes for chroot "
		    "directory %s\"%s\"",
		    cp == NULL ? "" : "component ", component);
	if (!S_ISDIR(st.st_mode))
	    my_fatal("chroot path %s\"%s\" is not a directory",
		cp == NULL ? "" : "component ", component);
    }

    if (chdir(path) == -1)
	my_fatal("unable to chdir to chroot path \"%s\": %s",
		 path, strerror(errno));
    if (chroot(path) == -1)
	my_fatal("chroot(\"%s\"): %s", path, strerror(errno));
    if (chdir("/") == -1)
	my_fatal("chdir(/) after chroot: %s", strerror(errno));
}

void my_drop_privs(struct passwd *pwd) {
    // setuid & setgid
    if (setgid(pwd->pw_gid) == -1)
	my_fatal("unable to setgid: %s", strerror(errno));

    if (setgroups(0, NULL) == -1)
	my_fatal("unable to setgroups: %s", strerror(errno));

    if (setuid(pwd->pw_uid) == -1)
   	my_fatal("unable to setuid: %s", strerror(errno));
}

/*
 * Actually, this is the standard IP checksum algorithm.
 */
uint16_t my_chksum(void *data, size_t length, int cisco) {
    uint32_t sum = 0;
    const uint16_t *d = (const uint16_t *)data;

    while (length > 1) {
	sum += *d++;
	length -= 2;
    }
    if (length) {
	if (cisco) {
	    sum += htons(*(const uint8_t *)d);
	} else {
	    sum += htons(*(const uint8_t *)d << 8);
	}
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}

