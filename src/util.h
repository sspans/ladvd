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

#ifndef _util_h
#define _util_h

#include <pwd.h>

#define FATAL	-1
#define CRIT	0
#define WARN	1
#define INFO	2
#define DEBUG	3

extern int8_t loglevel;

#define my_log(p, ...)	    __my_log(__func__, p, __VA_ARGS__)
#define my_fatal(...)	    __my_log(__func__, FATAL, __VA_ARGS__)
void __my_log(const char *func, int8_t prio, const char *fmt, ...);

void *my_malloc(size_t size);
void *my_calloc(size_t, size_t);
char *my_strdup(const char *str);
int my_socket(int af, int type, int proto);
void my_socketpair(int spair[]);
int my_nonblock(int s);

ssize_t my_mreq(struct master_req *mreq);

struct netif *netif_iter(struct netif *netif, struct nhead *);
struct netif *subif_iter(struct netif *subif, struct netif *netif);
struct netif *netif_byindex(struct nhead *, uint32_t index);
struct netif *netif_byname(struct nhead *, char *name);
void netif_protos(struct netif *netif, struct mhead *mqueue);
void netif_descr(struct netif *netif, struct mhead *mqueue);

void my_chroot(const char *path);
void my_drop_privs(struct passwd *pwd);

int read_line(const char *path, char *line, uint16_t len);
uint16_t my_chksum(const void *data, size_t length, int cisco);

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

void write_pcap_hdr(int);
void write_pcap_rec(int, struct master_msg *);

#endif /* _util_h */
