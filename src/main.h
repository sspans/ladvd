
#ifndef _main_h
#define _main_h

#include "config.h"
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/utsname.h>

#if HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif
#if HAVE_NET_IF_H
#include <net/if.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_NETINET_IF_ETHER_H
#include <netinet/if_ether.h>
#endif

#define PIDFILE	    "/var/run/ladvd.pid"
#define SLEEPTIME   30
#define LADVD_TTL   180

struct packet {
    uint8_t dst[ETHER_ADDR_LEN];
    uint8_t src[ETHER_ADDR_LEN];
    union {
	uint8_t type[ETHER_TYPE_LEN];
	uint8_t length[ETHER_TYPE_LEN];
    };
    uint8_t data[1024];
};

struct session {
    uint8_t if_index;
    char if_name[IFNAMSIZ];
    uint8_t if_hwaddr[ETHER_ADDR_LEN];
    uint16_t mtu;
    int8_t duplex;
    int8_t autoneg_supported; 
    int8_t autoneg_enabled; 
    uint16_t mau;

    uint32_t ipaddr4;
    uint32_t ipaddr6[4];

    uint8_t if_master;
    uint8_t if_slave;
    uint8_t if_lacp;
    uint8_t if_lacp_ifindex;

    struct session *subif;
    struct session *next;
};

struct sysinfo {
    struct utsname uts;
    char *uts_str;
    char *hostname;
    char *location;
    int8_t cap;
};

#define CAP_BRIDGE	(1 << 0)
#define CAP_HOST	(1 << 1)
#define CAP_ROUTER	(1 << 2)
#define CAP_SWITCH	(1 << 3)
#define CAP_WLAN	(1 << 4)

#define MASTER_BONDING	1
#define MASTER_BRIDGE	2

struct session * netif_fetch(int ifc, char *ifl[], struct sysinfo *sysinfo);
int netif_names(struct session *sessions);
int netif_addrs(struct session *sessions);
int netif_media(struct session *session);

int cdp_packet(struct packet *,
	       struct session *, struct session *,
	       struct sysinfo *);
int lldp_packet(struct packet *,
		struct session *, struct session *,
		struct sysinfo *);

#endif /* _main_h */
