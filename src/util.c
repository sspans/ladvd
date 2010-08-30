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

static void my_vlog(const char *func, int err, const char *fmt, va_list ap) {
    char *efmt;

    if (options & OPT_DAEMON) {
	if (err && asprintf(&efmt, "%s: %s", fmt, strerror(err)) != -1) {
	    vsyslog(LOG_ERR, efmt, ap);
	    free(efmt);
	} else {
	    vsyslog(LOG_INFO, fmt, ap);
	}
    } else {
	if (loglevel == DEBUG)
	    fprintf(stderr, "%s: ", func);

	if (err && asprintf(&efmt, "%s: %s\n", fmt, strerror(err)) != -1) {
	    vfprintf(stderr, efmt, ap);
	    free(efmt);
	} else {
	    vfprintf(stderr, fmt, ap);
	    fprintf(stderr, "\n");
	}
    }
}

void __my_log(const char *func, int8_t prio, int err, const char *fmt, ...) {
    va_list ap;

    if (prio > loglevel)
	return;

    va_start(ap, fmt);
    my_vlog(func, err, fmt, ap);
    va_end(ap);
}

__noreturn
void __my_fatal(const char *func, int err, const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    my_vlog(func, err, fmt, ap);
    va_end(ap);

    // exit via a sigterm signal
    if (pid)
	master_signal(SIGTERM, 0, &pid);

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

    if ((s = socket(af, type, proto)) == -1)
	my_fatale("opening socket failed");

    return(s);
}

void my_socketpair(int spair[]) {
    int rbuf = MASTER_MSG_MAX * 10;

    assert(spair != NULL);

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, spair) == -1)
	my_fatale("socketpair creation failed");

    for (int i = 0; i<2; i++) {
	if (setsockopt(spair[i], SOL_SOCKET, SO_RCVBUF,
		       &rbuf, sizeof(rbuf)) == -1)
	    my_fatale("failed to set rcvbuf");

	if (setsockopt(spair[i], SOL_SOCKET, SO_SNDBUF,
		       &rbuf, sizeof(rbuf)) == -1)
	    my_fatale("failed to set sndbuf");
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
__nonnull()
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
	    my_fatale("stat(\"%s\")", component);
	if (st.st_uid != 0 || (st.st_mode & 022) != 0)
	    my_fatal("bad ownership or modes for chroot "
		    "directory %s\"%s\"",
		    cp == NULL ? "" : "component ", component);
	if (!S_ISDIR(st.st_mode))
	    my_fatal("chroot path %s\"%s\" is not a directory",
		cp == NULL ? "" : "component ", component);
    }

    if (chdir(path) == -1)
	my_fatale("unable to chdir to chroot path \"%s\"", path);
    if (chroot(path) == -1)
	my_fatale("chroot(\"%s\")", path);
    if (chdir("/") == -1)
	my_fatale("chdir(/) after chroot");
}

__nonnull()
void my_drop_privs(struct passwd *pwd) {
    if (setgroups(0, NULL) == -1)
	my_fatale("unable to setgroups");

    if (setresgid(pwd->pw_gid, pwd->pw_gid, pwd->pw_gid) == -1)
	my_fatale("unable to setresgid");

    if (setresuid(pwd->pw_uid, pwd->pw_uid, pwd->pw_uid) == -1)
   	my_fatale("unable to setresuid");
}

__nonnull()
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
__nonnull()
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
	my_fatale("only %zi bytes written", len);

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
	return(NULL);

    if (subif == NULL) {
	if (netif->type > NETIF_REGULAR)
	    return(netif->subif);
	else if (netif->type < NETIF_REGULAR)
	    return(NULL);
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
    char descr[IFDESCRSIZE] = {};
    char paddr[ETHER_ADDR_LEN] = {};
    uint16_t peers = 0;

    TAILQ_FOREACH(qmsg, mqueue, entries) {
	if (netif->index != qmsg->index)
	    continue;

	if (!peer && qmsg->peer[PEER_HOSTNAME])
	    peer = qmsg->peer[PEER_HOSTNAME];
	if (!port && qmsg->peer[PEER_PORTNAME])
	    port = my_strdup(qmsg->peer[PEER_PORTNAME]);

	// this assumes a sorted queue
	if (memcmp(paddr, qmsg->msg + ETHER_ADDR_LEN, ETHER_ADDR_LEN) == 0)
	    continue;

	memcpy(paddr, qmsg->msg + ETHER_ADDR_LEN, ETHER_ADDR_LEN);
	peers++;
    }

    if (peers == 0) {
	memset(descr, 0, IFDESCRSIZE);
    } else if (peers == 1) {
	if (port)
	    portname_abbr(port);
	if (peer && port)
	    snprintf(descr, IFDESCRSIZE, "connected to %s (%s)", peer, port);
	else if (peer)
	    snprintf(descr, IFDESCRSIZE, "connected to %s", peer);
	else
	    memset(descr, 0, IFDESCRSIZE);
    } else {
	snprintf(descr, IFDESCRSIZE, "connected to %" PRIu16 " peers", peers);
    }

    if (port)
	free(port);

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

void portname_abbr(char *portname) {
    size_t len;
    char *media_types[] = { "FastEthernet", "GigabitEthernet",
			    "TenGigabitEthernet", NULL};

    assert(portname);

    for (int m = 0; media_types[m] != NULL; m++) {
	if (strstr(portname, media_types[m]) != portname)
	    continue;
	len = strlen(media_types[m]);
	memmove(portname + 2, portname + len, strlen(portname + len) + 1);
	return;
    }
    
    if (strcasestr(portname, "ethernet") == portname) {
	len = strlen("ethernet");
	memmove(portname + 3, portname + len, strlen(portname + len) + 1);
    }
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
    struct iovec iov[2];
    pcaprec_hdr_t pcap_rec_hdr = {};
    struct timeval tv;
    ssize_t len = 0;

    // create a pcap record header
    if (gettimeofday(&tv, NULL) == 0) {
	pcap_rec_hdr.ts_sec = tv.tv_sec;
	pcap_rec_hdr.ts_usec = tv.tv_usec;
    }
    pcap_rec_hdr.incl_len = msg->len;
    pcap_rec_hdr.orig_len = msg->len;

    iov[0].iov_base = &pcap_rec_hdr;
    iov[0].iov_len = sizeof(pcap_rec_hdr);

    iov[1].iov_base = msg->msg;
    iov[1].iov_len = msg->len;

    len = writev(fd, iov, 2);
    if (len != (sizeof(pcap_rec_hdr) + msg->len))
	my_loge(WARN, "only %zi bytes written", len);

    return;
}
