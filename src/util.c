/*
 * $Id$
 *
 * Copyright (c) 2008, 2009, 2010
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
#include <syslog.h>
#include <grp.h>

int8_t loglevel = CRIT;
int msock = -1;
pid_t pid = 0;

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

    if (prio == FATAL) {
	if (!pid)
	    exit(EXIT_FAILURE);
	// exit via a sigterm signal
	master_signal(SIGTERM, 0, &pid);
    }
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

    if ((s = socket(af, type, proto)) == -1)
	my_fatal("opening socket failed: %s", strerror(errno));

    return(s);
}

void my_socketpair(int spair[]) {
    int i, rbuf = MASTER_MSG_MAX * 10;

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

int my_nonblock(int s) {
    int flags;

    flags = fcntl(s, F_GETFL);
    if (flags < 0)
	return 0;
    flags |= O_NONBLOCK;
    if (fcntl(s, F_SETFL, flags) < 0)
	return 0;

    return flags;
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
    if (setgroups(0, NULL) == -1)
	my_fatal("unable to setgroups: %s", strerror(errno));

    if (setresgid(pwd->pw_gid, pwd->pw_gid, pwd->pw_gid) == -1)
	my_fatal("unable to setresgid: %s", strerror(errno));

    if (setresuid(pwd->pw_uid, pwd->pw_uid, pwd->pw_uid) == -1)
   	my_fatal("unable to setresuid: %s", strerror(errno));
}

int read_line(const char *path, char *line, uint16_t len) {
    FILE *file;
    int ret = 0;

    if (path == NULL || line == NULL)
	return(0);

    if ((file = fopen(path, "r")) == NULL)
	return(0);

    if (fgets(line, len, file) != NULL) {
	line[strcspn(line, "\n")] = '\0';
	ret = strlen(line);
    }

    fclose(file);
    return(ret);
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

ssize_t my_mreq(struct master_req *mreq) {
    ssize_t len = 0;

    assert(mreq != NULL);

    len = write(msock, mreq, MASTER_REQ_LEN(mreq->len));
    if (len < MASTER_REQ_MIN || len != MASTER_REQ_LEN(mreq->len))
	my_fatal("only %zi bytes written: %s", len, strerror(errno));

    memset(mreq, 0, MASTER_REQ_MAX);
    len = read(msock, mreq, MASTER_REQ_MAX);
    if (len < MASTER_REQ_MIN || len != MASTER_REQ_LEN(mreq->len))
	my_fatal("invalid reply received from master");

    return(mreq->len);
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

void netif_descr(struct netif *netif, struct mhead *mqueue) {
    struct master_msg *qmsg = NULL;
    struct master_req *mreq = NULL;
    char *peer = NULL, *port = NULL;
    char descr[IFDESCRSIZE], paddr[ETHER_ADDR_LEN];
    uint16_t peers = 0;

    TAILQ_FOREACH(qmsg, mqueue, entries) {
	if (netif->index != qmsg->index)
	    continue;

	if (!peer && qmsg->peer[PEER_HOSTNAME])
	    peer = qmsg->peer[PEER_HOSTNAME];
	if (!port && qmsg->peer[PEER_PORTNAME])
	    port = qmsg->peer[PEER_PORTNAME];

	// this assumes a sorted queue
	if (memcmp(paddr, qmsg->msg + ETHER_ADDR_LEN, ETHER_ADDR_LEN) == 0)
	    continue;

	memcpy(paddr, qmsg->msg + ETHER_ADDR_LEN, ETHER_ADDR_LEN);
	peers++;
    }

    if (peers == 0) {
	memset(descr, 0, IFDESCRSIZE);
    } else if (peers == 1) {
	if (peer && port)
	    snprintf(descr, IFDESCRSIZE, "connected to %s (%s)", peer, port);
	else if (peer)
	    snprintf(descr, IFDESCRSIZE, "connected to %s", peer);
	else
	    memset(descr, 0, IFDESCRSIZE);
    } else {
	snprintf(descr, IFDESCRSIZE, "connected to %" PRIu16 " peers", peers);
    }

    // only update if changed
    if (strncmp(descr, netif->description, IFDESCRSIZE) == 0)
	return;

    mreq = my_malloc(MASTER_REQ_MAX);
    mreq->op = MASTER_DESCR;
    mreq->index = netif->index;
    mreq->len = IFDESCRSIZE;
    mreq->len = strlen(descr) + 1;
    memcpy(mreq->buf, descr, mreq->len);

    if (!my_mreq(mreq))
	my_log(CRIT, "ifdescr ioctl failed on %s", netif->name);

    free(mreq);
}

void write_pcap_hdr(int fd) {
    pcap_hdr_t pcap_hdr = {};

    // create pcap global header
    pcap_hdr.magic_number = PCAP_MAGIC;
    pcap_hdr.version_major = 2;
    pcap_hdr.version_minor = 4;
    pcap_hdr.snaplen = ETHER_MAX_LEN;
    pcap_hdr.network = 1;

    // send pcap global header
    if (write(fd, &pcap_hdr, sizeof(pcap_hdr)) != sizeof(pcap_hdr))
	my_fatal("failed to write pcap global header");
}

void write_pcap_rec(int fd, struct master_msg *msg) {
    pcaprec_hdr_t pcap_rec_hdr = {};
    struct timeval tv;
    ssize_t len = 0;

    // write a pcap record header
    if (gettimeofday(&tv, NULL) == 0) {
	pcap_rec_hdr.ts_sec = tv.tv_sec;
	pcap_rec_hdr.ts_usec = tv.tv_usec;
	pcap_rec_hdr.incl_len = msg->len;
	pcap_rec_hdr.orig_len = msg->len;

	if (write(fd, &pcap_rec_hdr, sizeof(pcap_rec_hdr))
		    != sizeof(pcap_rec_hdr))
	    my_fatal("failed to write pcap record header");
    }

    len = write(fd, msg->msg, msg->len);
    if (len != msg->len)
	my_log(WARN, "only %zi bytes written: %s", len, strerror(errno));

    return;
}
