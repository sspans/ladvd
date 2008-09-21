
#ifndef _main_h
#define _main_h

#include "config.h"
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/utsname.h>

#if HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif

#if HAVE_LINUX_IF_H
#include <linux/if.h>
#elif defined(HAVE_NET_IF_H)
#include <net/if.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_NETINET_IF_ETHER_H
#include <netinet/if_ether.h>
#endif

#define SLEEPTIME   30
#define LADVD_TTL   180

#ifndef IFDESCRSIZE
#define IFDESCRSIZE 256
#endif

#define LLDP_INVENTORY_SIZE 32

struct packet {
    uint8_t dst[ETHER_ADDR_LEN];
    uint8_t src[ETHER_ADDR_LEN];
    union {
	uint8_t type[ETHER_TYPE_LEN];
	uint8_t length[ETHER_TYPE_LEN];
    };
    uint8_t data[1024];
};

struct netif {
    uint8_t index;
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

    struct netif *master;
    struct netif *subif;
    struct netif *next;
};

struct sysinfo {
    struct utsname uts;
    char uts_str[256];
    char hostname[256];
    char location[256];
    int8_t cap;
    int8_t cap_active;
    uint8_t hwaddr[ETHER_ADDR_LEN];

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

void sysinfo_fetch(struct sysinfo *);
uint16_t netif_fetch(int ifc, char *ifl[], struct sysinfo *, struct netif **);
int netif_media(struct netif *session);

size_t cdp_packet(struct packet *, struct netif *, struct sysinfo *);
size_t lldp_packet(struct packet *, struct netif *, struct sysinfo *);

#endif /* _main_h */
