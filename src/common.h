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

#define __USE_GNU

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
#include <pwd.h>

#include <event.h>

#if HAVE_NET_IF_H
#include <net/if.h>
#define _LINUX_IF_H
#endif
#if HAVE_NETINET_IF_ETHER_H
#include <netinet/if_ether.h>
#endif

#include "ether.h"
#include "compat/compat.h"

#define SLEEPTIME   30
#define LADVD_TTL   180

#ifndef IFDESCRSIZE
#define IFDESCRSIZE 64
#endif

#define LLDP_INVENTORY_SIZE 32

struct netif {
    uint32_t index;
    char name[IFNAMSIZ];
    char description[IFDESCRSIZE];
    uint8_t hwaddr[ETHER_ADDR_LEN];
    uint16_t mtu;
    int8_t duplex;
    int8_t autoneg_supported; 
    int8_t autoneg_enabled; 
    uint16_t mau;

    uint32_t ipaddr4;
    uint32_t ipaddr6[4];

    uint8_t argv;
    uint8_t type;
    uint8_t slave;
    uint8_t lacp;
    uint8_t lacp_index;

    uint16_t protos;
    uint8_t update;

    struct netif *master;
    struct netif *subif;

    // should be last
    TAILQ_ENTRY(netif) entries;
};

TAILQ_HEAD(nhead, netif);

struct sysinfo {
    struct utsname uts;
    char uts_str[256];
    uint8_t uts_rel[3];
    char hostname[256];
    char country[3];
    char location[256];
    int8_t cap;
    int8_t cap_active;
    uint8_t hwaddr[ETHER_ADDR_LEN];
    uint16_t physif_count;

    uint32_t maddr4;
    uint32_t maddr6[4];

    char hw_revision[LLDP_INVENTORY_SIZE + 1];
    char fw_revision[LLDP_INVENTORY_SIZE + 1];
    char sw_revision[LLDP_INVENTORY_SIZE + 1];
    char serial_number[LLDP_INVENTORY_SIZE + 1];
    char manufacturer[LLDP_INVENTORY_SIZE + 1];
    char model_name[LLDP_INVENTORY_SIZE + 1];
    char asset_id[LLDP_INVENTORY_SIZE + 1];
};

#define CAP_BRIDGE	(1 << 0)
#define CAP_HOST	(1 << 1)
#define CAP_ROUTER	(1 << 2)
#define CAP_SWITCH	(1 << 3)
#define CAP_WLAN	(1 << 4)

#define NETIF_INVALID	-1
#define NETIF_REGULAR	0
#define NETIF_BONDING	1
#define NETIF_BRIDGE	2
#define NETIF_OLD	255


#define OPT_DAEMON	(1 << 0)
#define OPT_RECV	(1 << 1)
#define OPT_AUTO	(1 << 2)
#define OPT_ONCE	(1 << 3)
#define OPT_ARGV	(1 << 4)
#define OPT_DEBUG	(1 << 5)
#define OPT_MADDR	(1 << 6)
#define OPT_WIRELESS	(1 << 7)
#define OPT_DESCR	(1 << 8)
#define OPT_CHECK	(1 << 31)

extern uint32_t options;

struct master_msg {
    uint32_t index;
    char name[IFNAMSIZ];
    uint8_t cmd;
    uint8_t completed;
    char msg[ETHER_MAX_LEN];
    ssize_t len;
    uint8_t proto;
    time_t ttl;

    struct {
	char name[IFDESCRSIZE];
	char port[IFDESCRSIZE];
    } peer;

    // should be last
    TAILQ_ENTRY(master_msg) entries;
};

TAILQ_HEAD(mhead, master_msg);

#define MASTER_MSG_SIZE   sizeof(struct master_msg)
#define MASTER_CLOSE	0
#define MASTER_RECV	1
#define MASTER_ETHTOOL	2
#define MASTER_DESCR	3
#define MASTER_DEVICE	4
#define MASTER_MAX	5

struct proto {
    uint8_t enabled;
    const char *name;
    uint8_t dst_addr[ETHER_ADDR_LEN];
    uint8_t llc_org[3];
    uint16_t llc_pid;
    size_t (*build_msg) (void *, struct netif *, struct sysinfo *);
    char * (*check) (void *, size_t);
    size_t (*peer) (struct master_msg *);
    char * (*decode) (void *, size_t);
};

void cli_main(int argc, char *argv[]) __attribute__ ((__noreturn__));
void child_init(int cmdfd, int msgfd, int ifc, char *ifl[], struct passwd *pwd);
void master_init(int cmdfd, int msgfd, pid_t pid);
void master_signal(int fd, short event, void *pid);

void sysinfo_fetch(struct sysinfo *);
uint16_t netif_fetch(int ifc, char *ifl[], struct sysinfo *, struct nhead *);
int netif_media(struct netif *session);

#endif /* _common_h */
