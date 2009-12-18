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

#define PCAP_MAGIC	0xA1B2C3D4

typedef struct pcap_hdr_s {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
} __attribute__ ((__packed__)) pcap_hdr_t;

typedef struct pcaprec_hdr_s {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
} __attribute__ ((__packed__)) pcaprec_hdr_t;

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

static void master_cmd(int fd, short event);
static void master_recv(int fd, short event, struct rawfd *rfd);

static ssize_t master_send(struct master_msg *mreq);
static void master_open(struct master_msg *mreq);
#if HAVE_LINUX_ETHTOOL_H
static ssize_t master_ethtool(struct master_msg *mreq);
#endif /* HAVE_LINUX_ETHTOOL_H */
#ifdef SIOCSIFDESCR
static ssize_t master_descr(struct master_msg *mreq);
#endif /* SIOCSIFDESCR */
#ifdef HAVE_SYSFS
static ssize_t master_device(struct master_msg *mreq);
#endif /* HAVE_SYSFS */
static void master_close(struct rawfd *rfd);

static int master_check(struct master_msg *mreq);
static int master_socket(struct rawfd *rfd);
static void master_multi(struct rawfd *rfd, struct proto *protos, int op);
static inline struct rawfd *rfd_byindex(uint32_t index);
static inline void rfd_closeall();

#endif /* _master_h */
