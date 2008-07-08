
#ifndef _main_h
#define _main_h

#include "config.h"
#include <sys/utsname.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include "util.h"

#define PIDFILE	    "/var/run/ladvd.pid"
#define SLEEPTIME   30
#define LADVD_TTL   180

struct session {
    uint8_t if_index;
    char *if_name;
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

    uint8_t cdp_msg[BUFSIZ];
    size_t cdp_len;
    uint8_t lldp_msg[BUFSIZ];
    size_t lldp_len;

    int sockfd;

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
int netif_addr(struct session *session);
int netif_media(struct session *session);

int cdp_packet(struct session *, struct session *, struct sysinfo *);
int cdp_send(struct session *session);

int lldp_packet(struct session *, struct session *, struct sysinfo *);
int lldp_send(struct session *session);

#endif /* _main_h */
