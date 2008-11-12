
#ifndef _common_h
#define _common_h

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

#include "ether.h"

#define SLEEPTIME   30
#define LADVD_TTL   180

#ifndef IFDESCRSIZE
#define IFDESCRSIZE 256
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

    struct netif *master;
    struct netif *subif;
    struct netif *next;
};

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

    uint8_t maddr_force;
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


size_t lldp_packet(void *, struct netif *, struct sysinfo *);
size_t cdp_packet(void *, struct netif *, struct sysinfo *);
size_t edp_packet(void *, struct netif *, struct sysinfo *);
size_t fdp_packet(void *, struct netif *, struct sysinfo *);
size_t ndp_packet(void *, struct netif *, struct sysinfo *);

#endif /* _common_h */
