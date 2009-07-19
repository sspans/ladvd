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

int8_t loglevel = CRIT;

void __my_log(const char *func, int8_t prio, const char *fmt, ...) {

    va_list ap;
    va_start(ap, fmt);

    if (prio > loglevel)
	return;

    if (options & OPT_DAEMON) {
	vsyslog(LOG_INFO, fmt, ap);
    } else {
	if (loglevel == DEBUG)
	    fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
    }
    va_end(ap);

    if (prio == FATAL)
	exit(EXIT_FAILURE);
}

void * my_malloc(size_t size) {
    void *ptr;

    if ((ptr = malloc(size)) == NULL)
	my_fatal("malloc failed");
    memset(ptr, 0, size);
    return(ptr);
}

void * my_calloc(size_t nmemb, size_t size) {
    void *ptr;

    if ((ptr = calloc(nmemb, size)) == NULL)
	my_fatal("calloc failed");

    return(ptr);
}

char * my_strdup(const char *str) {
    char *cstr;

    if ((cstr = strdup(str)) == NULL)
	my_fatal("strdup failed");

    return(cstr);
}

int my_socket(int af, int type, int proto) {
    int s;

    if ((s = socket(af, type, proto)) < 0)
	my_fatal("opening socket failed: %s", strerror(errno));

    return(s);
}

void my_socketpair(int spair[2]) {
    int i, rbuf = MASTER_MSG_SIZE * 10;

    assert(spair != NULL);

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, spair) == -1)
	my_fatal("msg socketpair creation failed: %s", strerror(errno));

    for (i = 0; i<2; i++) {
	if (setsockopt(spair[i], SOL_SOCKET, SO_RCVBUF,
		       &rbuf, sizeof(rbuf)) == -1)
	    my_fatal("failed to set rcvbuf: %s", strerror(errno));

	if (setsockopt(spair[i], SOL_SOCKET, SO_SNDBUF,
		       &rbuf, sizeof(rbuf)) == -1)
	    my_fatal("failed to set sndbuf: %s", strerror(errno));
    }
}

size_t my_msend(int s, struct master_msg *mreq) {
    ssize_t count = 0;

    assert(mreq != NULL);

    count = write(s, mreq, MASTER_MSG_SIZE);
    if (count != MASTER_MSG_SIZE)
	my_fatal("only %d bytes written: %s", count, strerror(errno));

    count = read(s, mreq, MASTER_MSG_SIZE);
    if (count != MASTER_MSG_SIZE)
	my_fatal("invalid reply received from master");

    if (mreq->completed != 1) {
	my_log(WARN, "request failed");
	return(0);
    } else {
	return(mreq->len);
    }
};

struct netif *netif_iter(struct netif *netif, struct nhead *netifs) {

    if (netifs == NULL)
	return NULL;

    if (netif == NULL)
	netif = TAILQ_FIRST(netifs);
    else
	netif = TAILQ_NEXT(netif, entries);

    for (; netif != NULL; netif = TAILQ_NEXT(netif, entries)) {
	// skip autodetected slaves
	if (!(options & OPT_ARGV) && (netif->slave == 1))
	    continue;

	// skip unlisted interfaces
	if ((options & OPT_ARGV) && (netif->argv == 0))
	    continue;

	// skip masters without slaves
	if ((netif->type > 0) && (netif->subif == NULL)) {
	    my_log(INFO, "skipping interface %s", netif->name);
	    continue;
	}

	break;
    }

    return(netif);
}

struct netif *subif_iter(struct netif *subif, struct netif *netif) {

    if (netif == NULL)
	return NULL;

    if (subif == NULL) {
	if (netif->type > 0)
	    return(netif->subif);
	else
	    return(netif);
    } else if (subif == netif) {
	return(NULL);
    } else {
	return(subif->subif);
    }
}

struct netif *netif_byindex(struct nhead *netifs, uint32_t index) {
    struct netif *netif = NULL;

    if (netifs == NULL)
	return NULL;

    TAILQ_FOREACH(netif, netifs, entries) {
	if (netif->index == index)
	    break;
    }
    return(netif);
}

struct netif *netif_byname(struct nhead *netifs, char *name) {
    struct netif *netif;

    if (netifs == NULL || name == NULL)
	return NULL;

    TAILQ_FOREACH(netif, netifs, entries) {
	if (strcmp(netif->name, name) == 0)
	    break;
    }
    return(netif);
}

void netif_protos(struct netif *netif, struct mhead *mqueue) {
    struct netif *subif = NULL;
    struct master_msg *qmsg = NULL;
    uint16_t protos = 0;
    
    while ((subif = subif_iter(subif, netif)) != NULL) {
	TAILQ_FOREACH(qmsg, mqueue, entries) {
	    if (subif->index == qmsg->index)
		protos |= (1 << qmsg->proto);
	}
    }
    netif->protos = protos;
}

void netif_descr(int s, struct netif *netif, struct mhead *mqueue) {
    struct master_msg *qmsg = NULL, *dmsg = NULL;
    char *peer = NULL, *port = NULL;
    char descr[IFDESCRSIZE], paddr[ETHER_ADDR_LEN];
    uint16_t peers = 0;

    TAILQ_FOREACH(qmsg, mqueue, entries) {
	if (netif->index != qmsg->index)
	    continue;

	if (!peer && strlen(qmsg->peer.name))
	    peer = qmsg->peer.name;
	if (!port && strlen(qmsg->peer.port))
	    port = qmsg->peer.port;

	// this assumes a sorted queue
	if (memcmp(paddr, qmsg->msg + ETHER_ADDR_LEN, ETHER_ADDR_LEN) == 0)
	    continue;

	memcpy(paddr, qmsg->msg + ETHER_ADDR_LEN, ETHER_ADDR_LEN);
	peers++;
    }

    if (peers == 0)
	memset(descr, 0, IFDESCRSIZE);
    else if (peers == 1) {
	if (peer && port)
	    snprintf(descr, IFDESCRSIZE, "connected to %s (%s)", peer, port);
	else if (peer)
	    snprintf(descr, IFDESCRSIZE, "connected to %s", peer);
	else
	    memset(descr, 0, IFDESCRSIZE);
    } else
	snprintf(descr, IFDESCRSIZE, "connected to %d peers", peers);

    // only update if changed
    if (strncmp(descr, netif->description, IFDESCRSIZE) == 0)
	return;

    dmsg = my_malloc(sizeof(struct master_msg));
    dmsg->index = netif->index;
    strlcpy(dmsg->name, netif->name, IFNAMSIZ);
    dmsg->cmd = MASTER_DESCR;
    dmsg->len = strlen(descr);
    strlcpy(dmsg->msg, descr, dmsg->len);

    if (my_msend(s, dmsg) != dmsg->len)
	my_log(CRIT, "ifdescr ioctl failed on %s", netif->name);

    free(dmsg);
}

int read_line(const char *path, char *line, uint16_t len) {
    FILE *file;
    char *newline;

    if (path == NULL || line == NULL)
	return(-1);

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

int strisascii(const char *str) {
    int i;
    if (!str)
	return 0;

    for (i=0; i < strlen(str); i++) {
	if (str[i] & ~0x7f)
	    return 0;
    }
    return 1;
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
uint16_t my_chksum(const void *data, size_t length, int cisco) {
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

