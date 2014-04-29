/*
 * $Id$
 *
 * Copyright (c) 2008, 2009, 2010
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

#include "common.h"
#include "util.h"
#include "proto/lldp.h"

#include <ifaddrs.h>
#include <dirent.h>
#include <ctype.h>

#if HAVE_ASM_TYPES_H
#include <asm/types.h>
#endif /* HAVE_ASM_TYPES_H */

#if HAVE_LINUX_SOCKIOS_H
#include <linux/sockios.h>
#endif /* HAVE_LINUX_SOCKIOS_H */

#if HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif /* HAVE_SYS_SOCKIO_H */

#ifdef HAVE_NETPACKET_PACKET_H
#include <netpacket/packet.h>
#endif /* HAVE_NETPACKET_PACKET_H */

#ifdef HAVE_NET_IF_DL_H
#include <net/if_dl.h>
#endif /* HAVE_NET_IF_DL_H */

#ifdef HAVE_NET_IF_TYPES_H
#include <net/if_types.h>
#endif /* HAVE_NET_IF_TYPES_H */


#ifdef AF_PACKET
#define NETIF_AF    AF_PACKET
#elif defined(AF_LINK)
#define NETIF_AF    AF_LINK
#endif

static int sockfd = -1;

static void netif_addrs(struct ifaddrs *, struct nhead *, struct sysinfo *);

#if defined(NETIF_LINUX)
#include "netif_linux.c"
#elif defined(NETIF_BSD)
#include "netif_bsd.c"
#endif

void netif_init() {
    if (sockfd == -1)
	sockfd = my_socket(AF_INET, SOCK_DGRAM, 0);
}

// create netifs for a list of interfaces
uint16_t netif_fetch(int ifc, char *ifl[], struct sysinfo *sysinfo,
		    struct nhead *netifs) {

    struct ifaddrs *ifaddrs, *ifaddr = NULL;
    struct ifreq ifr;
    int count = 0;
    int type, enabled;
    uint32_t index;
    struct master_req mreq = {};

#ifdef AF_PACKET
    struct sockaddr_ll saddrll;
#endif
#ifdef AF_LINK
    struct sockaddr_dl saddrdl;
#endif

    // netifs
    struct netif *n_netif, *netif = NULL;

    if (sockfd == -1)
	my_fatal("please call netif_init first");

    if (getifaddrs(&ifaddrs) < 0) {
	my_loge(CRIT, "address detection failed");
	return(0);
    }

    // zero
    count = 0;

    // unset all but CAP_HOST and CAP_ROUTER
    sysinfo->cap &= (CAP_HOST|CAP_ROUTER);
    sysinfo->cap_active &= (CAP_HOST|CAP_ROUTER);
    // reset counter
    sysinfo->physif_count = 0;

    // mark all interfaces
    TAILQ_FOREACH(netif, netifs, entries) {
	netif->type = NETIF_OLD;
    }

    for (ifaddr = ifaddrs; ifaddr != NULL; ifaddr = ifaddr->ifa_next) {

	// skip interfaces without addresses
	if (ifaddr->ifa_addr == NULL) {
	    my_log(INFO, "skipping interface %s", ifaddr->ifa_name);
	    continue;
	}

	// only handle datalink addresses
	if (ifaddr->ifa_addr->sa_family != NETIF_AF)
	    continue;

	// prepare ifr struct
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifaddr->ifa_name, sizeof(ifr.ifr_name));


	// skip non-ethernet interfaces
#ifdef AF_PACKET
	memcpy(&saddrll, ifaddr->ifa_addr, sizeof(saddrll));
	if (saddrll.sll_hatype != ARPHRD_ETHER) {
	    my_log(INFO, "skipping interface %s", ifaddr->ifa_name);
	    continue;
	}
	index = saddrll.sll_ifindex;
#elif AF_LINK
	memcpy(&saddrdl, ifaddr->ifa_addr, sizeof(saddrdl));
#ifdef IFT_BRIDGE
	if ((saddrdl.sdl_type != IFT_BRIDGE) &&
	    (saddrdl.sdl_type != IFT_ETHER)) {
#else
	if (saddrdl.sdl_type != IFT_ETHER) {
#endif
	    my_log(INFO, "skipping interface %s", ifaddr->ifa_name);
	    continue;
	}
	index = saddrdl.sdl_index;
#endif

	// check for interfaces that are down
	enabled = 0;
	if (ioctl(sockfd, SIOCGIFFLAGS, (caddr_t)&ifr) >= 0)
	    enabled = (ifr.ifr_flags & IFF_UP);

	// detect interface type
	type = netif_type(sockfd, index, ifaddr, &ifr);

	if (type == NETIF_REGULAR) { 
	    my_log(INFO, "found ethernet interface %s", ifaddr->ifa_name);
	    sysinfo->physif_count++;
	} else if (type == NETIF_WIRELESS) {
	    my_log(INFO, "found wireless interface %s", ifaddr->ifa_name);
	    sysinfo->cap |= CAP_WLAN;
	    sysinfo->cap_active |= (enabled == 1) ? CAP_WLAN : 0;
	} else if (type == NETIF_TAP) {
	    my_log(INFO, "found tun/tap interface %s", ifaddr->ifa_name);
	} else if (type == NETIF_BONDING) {
	    my_log(INFO, "found bond interface %s", ifaddr->ifa_name);
	} else if (type == NETIF_BRIDGE) {
	    my_log(INFO, "found bridge interface %s", ifaddr->ifa_name);
	    sysinfo->cap |= CAP_BRIDGE; 
	    sysinfo->cap_active |= (enabled == 1) ? CAP_BRIDGE : 0;
	} else if (type == NETIF_VLAN) {
	    my_log(INFO, "found vlan interface %s", ifaddr->ifa_name);
	} else if (type == NETIF_INVALID) {
	    my_log(INFO, "skipping interface %s", ifaddr->ifa_name);
	    continue;
	}


	// skip interfaces that are down
	if (enabled == 0) {
	    my_log(INFO, "skipping interface %s (down)", ifaddr->ifa_name);
	    continue;
	}


	my_log(INFO, "adding interface %s", ifaddr->ifa_name);

	// fetch / create netif
	if ((netif = netif_byindex(netifs, index)) == NULL) {
	    netif = my_malloc(sizeof(struct netif));
	    TAILQ_INSERT_TAIL(netifs, netif, entries);
	} else {
	    // reset everything up to the tailq_entry but keep protos
	    uint16_t protos = netif->protos;
	    memset(netif, 0, offsetof(struct netif, entries));
	    netif->protos = protos;
	}

        // copy name, index and type
	netif->index = index;
	strlcpy(netif->name, ifaddr->ifa_name, sizeof(netif->name));
	netif->type = type;

#ifdef HAVE_SYSFS
	mreq.op = MASTER_ALIAS;
	mreq.index = netif->index;

	if (my_mreq(&mreq))
	    strlcpy(netif->description, mreq.buf, IFDESCRSIZE);
#elif defined(SIOCGIFDESCR)
#ifndef __FreeBSD__
	ifr.ifr_data = (caddr_t)&netif->description;
#else
	ifr.ifr_buffer.buffer = &netif->description;
	ifr.ifr_buffer.length = IFDESCRSIZE;
#endif
	ioctl(sockfd, SIOCGIFDESCR, &ifr);
#endif

	if (sysinfo->mifname && (strcmp(netif->name, sysinfo->mifname) == 0))
	    sysinfo->mnetif = netif;

	// update counters
	count++;
    }

    // remove old interfaces
    TAILQ_FOREACH_SAFE(netif, netifs, entries, n_netif) {
	if (netif->type != NETIF_OLD)
	    continue;

	my_log(INFO, "removing old interface %s", netif->name);

	mreq.op = MASTER_CLOSE;
	mreq.index = netif->index;
	my_mreq(&mreq);

	TAILQ_REMOVE(netifs, netif, entries);
	if (sysinfo->mnetif == netif)
	    sysinfo->mnetif = NULL;
	free(netif);
    }

    // add slave subif lists to each bond/bridge
    // detect vlan interface settings
    TAILQ_FOREACH(netif, netifs, entries) {
	my_log(INFO, "detecting %s settings", netif->name);
	switch(netif->type) {
	    case NETIF_BONDING:
		netif_bond(sockfd, netifs, netif, &ifr);
		break;
	    case NETIF_BRIDGE:
		netif_bridge(sockfd, netifs, netif, &ifr);
		break;
	    case NETIF_VLAN:
		netif_vlan(sockfd, netifs, netif, &ifr);
		break;
	    case NETIF_REGULAR:
		netif_device_id(sockfd, netif, &ifr);
		break;
	    default:
		break;
	}
    }

    // add addresses to netifs
    my_log(INFO, "fetching addresses for all interfaces");
    netif_addrs(ifaddrs, netifs, sysinfo);

    // use the first mac as chassis id
    if ((netif = TAILQ_FIRST(netifs)) != NULL)
	memcpy(&sysinfo->hwaddr, &netif->hwaddr, ETHER_ADDR_LEN);

    // validate detected interfaces
    if (ifc > 0) {
	count = 0;

	for (int j = 0; j < ifc; j++) {
	    netif = netif_byname(netifs, ifl[j]);
	    if (netif == NULL) {
		my_log(CRIT, "interface %s is invalid", ifl[j]);
	    } else if (netif->type == NETIF_VLAN) {
		my_log(CRIT, "vlan interface %s is not supported", ifl[j]);
	    } else {
		netif->argv = 1;
		count++;
	    }
	}
	if (count != ifc)
	    count = 0;

    } else if (count == 0) {
	my_log(CRIT, "no valid interface found");
    }

    if ((options & OPT_MNETIF) && !sysinfo->mnetif)
	my_log(CRIT, "could not detect the specified management interface");

    // cleanup
    freeifaddrs(ifaddrs);

    return(count);
};


// perform address detection for all netifs
static void netif_addrs(struct ifaddrs *ifaddrs, struct nhead *netifs,
		struct sysinfo *sysinfo) {
    struct ifaddrs *ifaddr;
    struct netif *netif, *mnetif;

    struct sockaddr_in saddr4;
    struct sockaddr_in6 saddr6;
#ifdef AF_PACKET
    struct sockaddr_ll saddrll;
#endif
#ifdef AF_LINK
    struct sockaddr_dl saddrdl;
#endif

    for (ifaddr = ifaddrs; ifaddr != NULL; ifaddr = ifaddr->ifa_next) {

	// skip interfaces without addresses
	if (ifaddr->ifa_addr == NULL)
	    continue;

	// fetch the netif for this ifaddr
	netif = netif_byname(netifs, ifaddr->ifa_name);
	if (netif == NULL)
	    continue;

	if (ifaddr->ifa_addr->sa_family == AF_INET) {
	    if (netif->ipaddr4 != 0)
		continue;

	    // alignment
	    memcpy(&saddr4, ifaddr->ifa_addr, sizeof(saddr4));

	    memcpy(&netif->ipaddr4, &saddr4.sin_addr,
		  sizeof(saddr4.sin_addr));

	    // detect mnetif
	    if (sysinfo->mnetif || (sysinfo->maddr4 == 0))
		continue;

	    if (sysinfo->maddr4 == netif->ipaddr4)
		sysinfo->mnetif = netif;

	} else if (ifaddr->ifa_addr->sa_family == AF_INET6) {
	    if (!IN6_IS_ADDR_UNSPECIFIED((struct in6_addr *)netif->ipaddr6))
		continue;

	    // alignment
	    memcpy(&saddr6, ifaddr->ifa_addr, sizeof(saddr6));

	    // skip link-local
	    if (IN6_IS_ADDR_LINKLOCAL(&saddr6.sin6_addr))
		continue;

	    memcpy(&netif->ipaddr6, &saddr6.sin6_addr,
		  sizeof(saddr6.sin6_addr));

	    // detect mnetif
	    if (sysinfo->mnetif ||
		(IN6_IS_ADDR_UNSPECIFIED((struct in6_addr *)sysinfo->maddr6)))
		continue;

	    if (memcmp(&sysinfo->maddr6, &netif->ipaddr6,
			sizeof(sysinfo->maddr6)) == 0)
		sysinfo->mnetif = netif;
#ifdef AF_PACKET
	} else if (ifaddr->ifa_addr->sa_family == AF_PACKET) {

	    // alignment
	    memcpy(&saddrll, ifaddr->ifa_addr, sizeof(saddrll));

	    memcpy(&netif->hwaddr, &saddrll.sll_addr, ETHER_ADDR_LEN);
#endif
#ifdef AF_LINK
	} else if (ifaddr->ifa_addr->sa_family == AF_LINK) {

	    // alignment
	    memcpy(&saddrdl, ifaddr->ifa_addr, sizeof(saddrdl));

	    memcpy(&netif->hwaddr, LLADDR(&saddrdl), ETHER_ADDR_LEN);
#endif
	}
    }

    // return when no management netif is available
    if (!(options & OPT_MADDR) || !sysinfo->mnetif)
	return;
    mnetif = sysinfo->mnetif;

    // use management address when requested
    TAILQ_FOREACH(netif, netifs, entries) {
	netif->ipaddr4 = mnetif->ipaddr4;
	memcpy(&netif->ipaddr6, &mnetif->ipaddr6, sizeof(mnetif->ipaddr6));
    }
}


// perform media detection on physical interfaces
int netif_media(struct netif *netif) {

    struct ifreq ifr = {};

    if (sockfd == -1)
	my_fatal("please call netif_init first");

    netif->duplex = -1;
    netif->autoneg_supported = -1;
    netif->autoneg_enabled = -1;
    netif->autoneg_pmd = 0;
    netif->mau = 0;

    strlcpy(ifr.ifr_name, netif->name, sizeof(ifr.ifr_name));

    // interface mtu
    if (ioctl(sockfd, SIOCGIFMTU, (caddr_t)&ifr) >= 0)
	netif->mtu = ifr.ifr_mtu;
    else
	my_log(INFO, "mtu detection failed on interface %s", netif->name);

    // the rest only makes sense for real interfaces
    if (netif->type != NETIF_REGULAR)
	return(EXIT_SUCCESS);

    netif_physical(sockfd, netif);

    return(EXIT_SUCCESS);
}

