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

#ifndef _master_h
#define _master_h

#include <sys/ioctl.h>

struct rawfd {
    uint32_t index;
    char name[IFNAMSIZ];
    int fd;
    struct event event;

#ifdef HAVE_NET_BPF_H
    struct {
	unsigned int len;
	char *data;
    } bpf_buf;
#endif /* HAVE_NET_BPF_H */

    // should be last
    TAILQ_ENTRY(rawfd) entries;
};

TAILQ_HEAD(rfdhead, rawfd);

void master_req(int fd, short event);
void master_send(int fd, short event);
void master_recv(int fd, short event, struct rawfd *rfd);

void master_open(struct master_msg *mreq);
#if HAVE_LINUX_ETHTOOL_H
ssize_t master_ethtool(struct master_req *mreq);
#endif /* HAVE_LINUX_ETHTOOL_H */
#ifdef SIOCSIFDESCR
ssize_t master_descr(struct master_req *mreq);
#endif /* SIOCSIFDESCR */
#ifdef HAVE_SYSFS
ssize_t master_device(struct master_req *mreq);
#endif /* HAVE_SYSFS */
#if defined(HAVE_SYSFS) && defined(HAVE_PCI_PCI_H)
ssize_t master_device_id(struct master_req *mreq);
#endif /* HAVE_SYSFS && HAVE_PCI_PCI_H */
void master_close(struct rawfd *rfd);

int master_check(struct master_req *mreq);
int master_socket(struct rawfd *rfd);
void master_multi(struct rawfd *rfd, struct proto *protos, int op);

static inline
struct rawfd *rfd_byindex(struct rfdhead *rawfds, uint32_t index) {
    struct rawfd *rfd = NULL;

    TAILQ_FOREACH(rfd, rawfds, entries) {
	if (rfd->index == index)
	    break;
    }
    return(rfd);
}

static inline
void rfd_closeall(struct rfdhead *rawfds) {
    struct rawfd *rfd, *nrfd;

    TAILQ_FOREACH_SAFE(rfd, rawfds, entries, nrfd) {
	master_close(rfd);
    }
}

#endif /* _master_h */
