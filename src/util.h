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

#define CRIT	0
#define WARN	1
#define INFO	2
#define DEBUG	3

extern int8_t loglevel;

#define my_log(p, ...)	    __my_log(__func__, p, 0, __VA_ARGS__)
#define my_loge(p, ...)	    __my_log(__func__, p, errno, __VA_ARGS__)
#define my_fatal(...)	    __my_fatal(__func__, 0, __VA_ARGS__)
#define my_fatale(...)	    __my_fatal(__func__, errno, __VA_ARGS__)
void __my_log(const char *func, int8_t prio, int err, const char *fmt, ...);
void __my_fatal(const char *func, int err, const char *fmt, ...) __noreturn;

void *my_malloc(size_t size);
void *my_calloc(size_t, size_t);
char *my_strdup(const char *str);
int my_socket(int af, int type, int proto);
void my_socketpair(int spair[]);
int my_nonblock(int s);

void my_chroot(const char *path) __nonnull();
void my_drop_privs(struct passwd *pwd) __nonnull();
void my_rlimit_child();

int read_line(const char *path, char *line, uint16_t len) __nonnull();
int write_line(const char *path, char *line, uint16_t len) __nonnull();
uint16_t my_chksum(const void *data, size_t length, int cisco) __nonnull();

ssize_t my_mreq(struct master_req *mreq);

struct netif *netif_iter(struct netif *netif, struct nhead *);
struct netif *subif_iter(struct netif *subif, struct netif *netif);
void netif_protos(struct netif *netif, struct mhead *mqueue);
void netif_descr(struct netif *netif, struct mhead *mqueue);
void portname_abbr(char *);

static inline
struct netif *netif_byindex(struct nhead *netifs, uint32_t index) {
    struct netif *netif = NULL;

    assert(netifs);

    TAILQ_FOREACH(netif, netifs, entries) {
	if (netif->index == index)
	    break;
    }
    return(netif);
}

static inline
struct netif *netif_byname(struct nhead *netifs, char *name) {
    struct netif *netif;

    assert((netifs != NULL) && (name != NULL));

    TAILQ_FOREACH(netif, netifs, entries) {
	if (strcmp(netif->name, name) == 0)
	    break;
    }
    return(netif);
}

static inline
struct netif *netif_byaddr(struct nhead *netifs, uint8_t *hwaddr) {
    struct netif *netif;

    assert((netifs != NULL) && (hwaddr != NULL));

    TAILQ_FOREACH(netif, netifs, entries) {
	if (memcmp(netif->hwaddr, hwaddr, ETHER_ADDR_LEN) == 0)
	    break;
    }
    return(netif);
}

#define PCAP_MAGIC       0xa1b2c3d4
#define PCAP_PKTHDR_SIZ  16

void my_pcap_init(int fd);
void my_pcap_write(struct master_msg *);
void my_pcap_close();

#endif /* _util_h */
