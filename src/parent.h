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

#ifndef _parent_h
#define _parent_h

#ifdef HAVE_NETPACKET_PACKET_H
#include <netpacket/packet.h>
#endif /* HAVE_NETPACKET_PACKET_H */
#include <pcap.h>
#include <sys/ioctl.h>

struct rawfd {
    uint32_t index;
    char name[IFNAMSIZ];
    int fd;
    struct event event;

    pcap_t *p_handle;

    // should be last
    TAILQ_ENTRY(rawfd) entries;
};

TAILQ_HEAD(rfdhead, rawfd);

void parent_req(int fd, short event);
void parent_send(int fd, short event);
void parent_recv(int fd, short event, struct rawfd *rfd);

void parent_open(const uint32_t index, const char *name);
#if HAVE_LINUX_ETHTOOL_H
ssize_t parent_ethtool(struct parent_req *mreq);
#endif /* HAVE_LINUX_ETHTOOL_H */
#if HAVE_LIBTEAM
ssize_t parent_libteam(struct parent_req *mreq);
#endif /* HAVE_LIBTEAM */
ssize_t parent_descr(struct parent_req *mreq);
#ifdef HAVE_SYSFS
ssize_t parent_device(struct parent_req *mreq);
#endif /* HAVE_SYSFS */
#if defined(HAVE_SYSFS) && defined(HAVE_PCI_PCI_H)
ssize_t parent_device_id(struct parent_req *mreq);
#endif /* HAVE_SYSFS && HAVE_PCI_PCI_H */
void parent_close(struct rawfd *rfd);

int parent_check(struct parent_req *mreq);
int parent_socket(struct rawfd *rfd);
void parent_multi(struct rawfd *rfd, struct proto *protos, int op);

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
	parent_close(rfd);
    }
}

#endif /* _parent_h */
