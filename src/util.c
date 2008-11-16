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
#include <sys/types.h>
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

void * my_malloc(size_t size) {
    void *ptr;

    if ((ptr = malloc(size)) == NULL) {
	my_log(CRIT, "malloc failed: %s", strerror(errno));
	exit(EXIT_FAILURE);
    }
    memset(ptr, 0, size);
    return(ptr);
}

void * my_calloc(size_t nmemb, size_t size) {
    void *ptr;

    if ((ptr = calloc(nmemb, size)) == NULL) {
	my_log(CRIT, "calloc failed: %s", strerror(errno));
	exit(EXIT_FAILURE);
    }
    return(ptr);
}

char * my_strdup(const char *str) {
    char *cstr;

    if ((cstr = strdup(str)) == NULL) {
	my_log(CRIT, "strdup failed: %s", strerror(errno));
	exit(EXIT_FAILURE);
    }
    return(cstr);
}

int my_socket(int af, int type, int proto) {
    int s;

    if ((s = socket(af, type, proto)) < 0) {
	my_log(CRIT, "opening socket failed: %s", strerror(errno));
	exit(EXIT_FAILURE);
    }
    return(s);
}

size_t my_msend(int s, struct master_request *mreq) {
    size_t count = 0;

    count = write(s, mreq, sizeof(struct master_request));

    if (sizeof(struct master_request) != count)
	my_log(WARN, "only %d bytes written: %s", count, strerror(errno));

    // timeout ?
    count = recv(s, mreq, MASTER_REQ_SIZE, 0);

    if (sizeof(struct master_request) != count) {
	my_log(WARN, "invalid reply received from master");
       	exit(EXIT_FAILURE);
    } else if (mreq->completed != 1) {
	my_log(WARN, "command failed");
	return(0);
    }

    return(mreq->len);
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

void my_drop_privs(struct passwd *pwd) {
    // setuid & setgid
    if (setgid(pwd->pw_gid) == -1){
	my_log(CRIT, "unable to setgid: %s", strerror(errno));
       	exit(EXIT_FAILURE);
    }

    if (setgroups(0, NULL) == -1){
	my_log(CRIT, "unable to setgroups: %s", strerror(errno));
       	exit(EXIT_FAILURE);
    }

    if (setuid(pwd->pw_uid) == -1){
   	my_log(CRIT, "unable to setuid: %s", strerror(errno));
       	exit(EXIT_FAILURE);
    }
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

