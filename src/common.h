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

#ifndef _common_h
#define _common_h

#include "config.h"
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#ifndef S_SPLINT_S
#include <unistd.h>
#endif
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#ifdef HAVE_STRNVIS
#include <vis.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <pwd.h>

#include <event.h>
#if HAVE_EVHTTP_H
#include <evhttp.h>
#endif /* HAVE_EVHTTP_H */

#if HAVE_NET_IF_H
#include <net/if.h>
#define _LINUX_IF_H
#define IFF_LOWER_UP 0x10000
#endif
#if HAVE_NETINET_IF_ETHER_H
#include <netinet/if_ether.h>
#endif

#ifndef __noreturn
# define __noreturn	__attribute__ ((noreturn))
#endif
#ifndef __packed
# define __packed	__attribute__ ((packed))
#endif
#ifndef __nonnull
# define __nonnull(x)	__attribute__ ((__nonnull__ x))
#endif
#if __GNUC__ >= 3
# define likely(x)	__builtin_expect (!!(x), 1)
# define unlikely(x)	__builtin_expect (!!(x), 0)
#else
# define likely(x)	(x)
# define unlikely(x)	(x)
#endif

#include "ether.h"
#include "compat/compat.h"

#define SLEEPTIME   30
#define LADVD_TTL   180

#ifndef IFDESCRSIZE
#define IFDESCRSIZE 64
#endif

#define LLDP_INVENTORY_SIZE 32

#define NETIF_BONDING_LACP  	1
#define NETIF_BONDING_FAILOVER	2
#define NETIF_SLAVE_ACTIVE	1
#define NETIF_SLAVE_BACKUP	2

struct netif {
    uint32_t index;
    char name[IFNAMSIZ];
    char description[IFDESCRSIZE];
    uint8_t hwaddr[ETHER_ADDR_LEN];
    uint16_t mtu;
    int8_t duplex;
    int8_t autoneg_supported; 
    int8_t autoneg_enabled; 
    uint16_t autoneg_pmd;
    uint16_t mau;

    uint32_t ipaddr4;
    uint32_t ipaddr6[4];

    uint8_t argv;
    int8_t type;
    uint8_t slave;
    uint8_t bonding_mode;
    uint8_t lacp_index;

    uint16_t vlan_id; 
    uint32_t vlan_parent;

    uint8_t protos;
    uint8_t update;

    struct netif *master;
    struct netif *subif;

    // should be last
    TAILQ_ENTRY(netif) entries;

    uint8_t link_event;
    uint8_t device_identified;
    char device_name[IFDESCRSIZE];
};

TAILQ_HEAD(nhead, netif);

struct hinv {
    char hw_revision[LLDP_INVENTORY_SIZE + 1];
    char fw_revision[LLDP_INVENTORY_SIZE + 1];
    char sw_revision[LLDP_INVENTORY_SIZE + 1];
    char serial_number[LLDP_INVENTORY_SIZE + 1];
    char manufacturer[LLDP_INVENTORY_SIZE + 1];
    char model_name[LLDP_INVENTORY_SIZE + 1];
    char asset_id[LLDP_INVENTORY_SIZE + 1];
};

struct sysinfo {
    struct utsname uts;
    char uts_str[256];
    uint8_t uts_rel[3];
    char platform[256];
    char hostname[256];
    char country[3];
    char location[256];
    uint16_t cap;
    uint16_t cap_active;
    uint16_t cap_lldpmed;
    int8_t lldpmed_devtype;
    uint8_t hwaddr[ETHER_ADDR_LEN];
    uint16_t physif_count;

    uint32_t maddr4;
    uint32_t maddr6[4];
    const char *mifname;
    struct netif *mnetif;

    struct hinv hinv;
};

#define CAP_REPEATER	(1 << 0)
#define CAP_BRIDGE	(1 << 1)
#define CAP_HOST	(1 << 2)
#define CAP_ROUTER	(1 << 3)
#define CAP_SWITCH	(1 << 4)
#define CAP_WLAN	(1 << 5)
#define CAP_DOCSIS	(1 << 6)
#define CAP_PHONE	(1 << 7)
#define CAP_OTHER	(1 << 8)
#define CAP_MAX		9
#define CAP_STRING	"rBHRSWCTO"

#define NETIF_INVALID	INT8_MIN
#define NETIF_VLAN	-1
#define NETIF_REGULAR	0
#define NETIF_WIRELESS	1
#define NETIF_TAP	2
#define NETIF_PARENT	10
#define NETIF_BONDING	11
#define NETIF_BRIDGE	12
#define NETIF_OLD	INT8_MAX

#define OPT_DAEMON	(1 << 0)
#define OPT_SEND	(1 << 1)
#define OPT_RECV	(1 << 2)
#define OPT_AUTO	(1 << 3)
#define OPT_ONCE	(1 << 4)
#define OPT_ARGV	(1 << 5)
#define OPT_DEBUG	(1 << 6)
#define OPT_MNETIF	(1 << 7)
#define OPT_MADDR	(1 << 8)
#define OPT_WIRELESS	(1 << 9)
#define OPT_TAP		(1 << 10)
#define OPT_IFDESCR	(1 << 11)
#define OPT_USEDESCR	(1 << 12)
#define OPT_CHASSIS_IF	(1 << 13)
#define OPT_CHECK	(1 << 31)

extern uint32_t options;

struct master_req {
    uint8_t op;
    uint32_t index;
    char name[IFNAMSIZ];
    ssize_t len;
    char buf[512];
};

#define MASTER_REQ_MIN	    offsetof(struct master_req, buf)
#define MASTER_REQ_MAX	    sizeof(struct master_req)
#define MASTER_REQ_LEN(l)   MASTER_REQ_MIN + l

#define DECODE_STR	1
#define DECODE_PRINT	2

#define PEER_HOSTNAME	0
#define PEER_PORTNAME	1
#define PEER_PORTDESCR	2
#define PEER_CAP	3
#define PEER_ADDR_INET4	4
#define PEER_ADDR_INET6	5
#define PEER_ADDR_802	6
#define PEER_VLAN_ID	7
#define PEER_MAX	8
#define PEER_STR(x,y)  ((x)?(free(y)):(x = y))

static inline
void peer_free(char *p[]) {
    int s;
    for (s = 0; s < PEER_MAX; s++) {
	if (!p[s])
	    continue;
	free(p[s]);
	p[s] = NULL;
    }
}

struct master_msg {
    uint32_t index;
    char name[IFNAMSIZ];
    uint8_t proto;
    time_t received;
    ssize_t len;
    unsigned char msg[ETHER_MAX_LEN];

    uint8_t decode;
    uint16_t ttl;
    char *peer[PEER_MAX];

    uint8_t lock;

    // should be last
    TAILQ_ENTRY(master_msg) entries;
};

TAILQ_HEAD(mhead, master_msg);

#define MASTER_MSG_MIN	    offsetof(struct master_msg, msg)
#define MASTER_MSG_MAX	    offsetof(struct master_msg, decode)
#define MASTER_MSG_SIZ	    sizeof(struct master_msg)
#define MASTER_MSG_LEN(l)   MASTER_MSG_MIN + l
#define MASTER_OPEN	    0
#define MASTER_CLOSE	    1
#define MASTER_DESCR	    2
#define MASTER_ALIAS	    3
#define MASTER_DEVICE	    4
#define MASTER_DEVICE_ID    5
#define MASTER_ETHTOOL_GSET 6
#define MASTER_ETHTOOL_GDRV 7
#define MASTER_MAX	    8

struct proto {
    uint8_t enabled;
    const char *name;
    uint8_t dst_addr[ETHER_ADDR_LEN];
    uint8_t llc_org[3];
    uint16_t llc_pid;
    size_t (* const build) (void *, struct netif *, struct nhead *,
			    struct sysinfo *);
    unsigned char * (* const check) (void *, size_t);
    size_t (* const decode) (struct master_msg *);
};

void cli_main(int argc, char *argv[]) __noreturn;
void child_init(int reqfd, int msgfd, int ifc, char *ifl[], struct passwd *pwd);
void master_init(int reqfd, int msgfd, pid_t pid);
void master_signal(int fd, short event, void *pid);

void sysinfo_fetch(struct sysinfo *);
void netif_init();
uint16_t netif_fetch(int ifc, char *ifl[], struct sysinfo *, struct nhead *);
int netif_media(struct netif *);

#endif /* _common_h */
