
#ifndef _common_h
#define _common_h

#include "config.h"
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/utsname.h>

#if HAVE_NET_IF_H
#include <net/if.h>
#define _LINUX_IF_H
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_NETINET_IF_ETHER_H
#include <netinet/if_ether.h>
#endif

#include "ether.h"
#include "compat/compat.h"

#define SLEEPTIME   30
#define LADVD_TTL   180

#ifndef IFDESCRSIZE
#define IFDESCRSIZE 256
#endif

#define LLDP_INVENTORY_SIZE 32

#define HOSTNAME_CHARS	"ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
			"abcdefghijklmnopqrstuvwxyz" \
			"0123456789" ".-"
#define IS_HOSTNAME(s)	(strspn(s, HOSTNAME_CHARS) == strlen(s))

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

    struct netif *master;
    struct netif *subif;

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
#define OPT_DEBUG	(1 << 4)
#define OPT_MADDR	(1 << 5)
#define OPT_DESCR	(1 << 6)


struct proto {
    uint8_t enabled;
    const char *name;
    uint8_t dst_addr[ETHER_ADDR_LEN];
    size_t (*build_msg) (void *, struct netif *, struct sysinfo *);
    char * (*check) (void *, size_t);
    char * (*decode) (void *, size_t);
    uint8_t llc_org[3];
    uint16_t llc_pid;
};


void sysinfo_fetch(struct sysinfo *);
uint16_t netif_fetch(int ifc, char *ifl[], struct sysinfo *, struct nhead *);
int netif_media(int cfd, struct netif *session);


size_t lldp_packet(void *, struct netif *, struct sysinfo *);
size_t cdp_packet(void *, struct netif *, struct sysinfo *);
size_t edp_packet(void *, struct netif *, struct sysinfo *);
size_t fdp_packet(void *, struct netif *, struct sysinfo *);
size_t ndp_packet(void *, struct netif *, struct sysinfo *);

char * lldp_check(void *, size_t);
char * cdp_check(void *, size_t);
char * edp_check(void *, size_t);
char * fdp_check(void *, size_t);
char * ndp_check(void *, size_t);

char * lldp_decode(void *, size_t);
char * cdp_decode(void *, size_t);
char * edp_decode(void *, size_t);
char * fdp_decode(void *, size_t);
char * ndp_decode(void *, size_t);

#endif /* _common_h */
