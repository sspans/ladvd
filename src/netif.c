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

#if HAVE_ASM_TYPES_H
#include <asm/types.h>
#endif /* HAVE_ASM_TYPES_H */

#if HAVE_LINUX_SOCKIOS_H
#include <linux/sockios.h>
#endif /* HAVE_LINUX_SOCKIOS_H */

#if HAVE_LINUX_ETHTOOL_H
#include <linux/ethtool.h>
#endif /* HAVE_LINUX_ETHTOOL_H */

#if HAVE_NET_IF_MEDIA_H
#include <net/if_media.h>
#endif /* HAVE_NET_IF_MEDIA_H */

#ifdef HAVE_NETPACKET_PACKET_H
#include <netpacket/packet.h>
#endif /* HAVE_NETPACKET_PACKET_H */

#ifdef HAVE_NET_IF_DL_H
#include <net/if_dl.h>
#endif /* HAVE_NET_IF_DL_H */

#ifdef HAVE_NET_IF_TYPES_H
#include <net/if_types.h>
#endif /* HAVE_NET_IF_TYPES_H */


#ifdef HAVE_LINUX_IF_VLAN_H
#include <linux/if_vlan.h>
#endif /* HAVE_LINUX_IF_VLAN_H */

#ifdef HAVE_NET_IF_VLAN_VAR_H
#include <net/if_vlan_var.h>
#endif /* HAVE_NET_IF_VLAN_VAR_H */


#ifdef HAVE_NET_IF_LAGG_H
#include <net/if_lagg.h>
#endif /* HAVE_NET_IF_LAGG_H */

#ifdef HAVE_NET_IF_TRUNK_H
#include <net/if_trunk.h>
#endif /* HAVE_NET_IF_TRUNK_H */

#ifdef HAVE_NET_IF_BOND_VAR_H
#include <net/if_bond_var.h>
#endif /* HAVE_NET_IF_BOND_VAR_H */


#ifdef HAVE_LINUX_IF_BONDING_H
#include <linux/if_bonding.h>
#endif /* HAVE_LINUX_IF_BONDING_H */

#ifdef HAVE_LINUX_IF_BRIDGE_H
#include <linux/if_bridge.h>
#define BRIDGE_MAX_PORTS 1024
#endif /* HAVE_LINUX_IF_BRIDGE_H */

#if HAVE_NET_IF_BRIDGEVAR_H
#include <net/if_bridgevar.h>
#endif /* HAVE_NET_IF_BRIDGEVAR_H */

#if HAVE_NET_IF_BRIDGE_H
#include <net/if_bridge.h>
#endif /* HAVE_NET_IF_BRIDGE_H */


#ifdef HAVE_LINUX_WIRELESS_H
#include <linux/wireless.h>
#endif /* HAVE_LINUX_WIRELESS_H */

#ifdef HAVE_NET80211_IEEE80211_H
#include <net80211/ieee80211.h>
#endif /* HAVE_NET80211_IEEE80211_H */
#ifdef HAVE_NET80211_IEEE80211_IOCTL_H
#include <net80211/ieee80211_ioctl.h>
#endif /* HAVE_NET80211_IEEE80211_IOCTL_H */

#ifdef HAVE_NET_IF_MIB_H
#include <net/if_mib.h>
#endif /* HAVE_NET_IF_MIB_H */

#ifdef AF_PACKET
#define NETIF_AF    AF_PACKET
#elif defined(AF_LINK)
#define NETIF_AF    AF_LINK
#endif

int netif_wireless(int, struct ifaddrs *ifaddr, struct ifreq *);
int netif_type(int, uint32_t index, struct ifaddrs *ifaddr, struct ifreq *);
void netif_bond(int, struct nhead *, struct netif *, struct ifreq *);
void netif_bridge(int, struct nhead *, struct netif *, struct ifreq *);
void netif_vlan(int, struct nhead *, struct netif *, struct ifreq *);
void netif_device_id(struct netif *);
void netif_addrs(struct ifaddrs *, struct nhead *, struct sysinfo *);


// create netifs for a list of interfaces
uint16_t netif_fetch(int ifc, char *ifl[], struct sysinfo *sysinfo,
		    struct nhead *netifs) {

    int sockfd, af = AF_INET;
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

    sockfd = my_socket(af, SOCK_DGRAM, 0);

    if (getifaddrs(&ifaddrs) < 0) {
	my_loge(CRIT, "address detection failed");
	(void) close(sockfd);
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

	// detect wireless interfaces
	if (netif_wireless(sockfd, ifaddr, &ifr) == 0) {
	    sysinfo->cap |= CAP_WLAN; 
	    sysinfo->cap_active |= (enabled == 1) ? CAP_WLAN : 0;

	    if (!(options & OPT_WIRELESS)) {
		my_log(INFO, "skipping wireless interface %s",
			ifaddr->ifa_name);
		continue;
	    }
	}

	// detect interface type
	type = netif_type(sockfd, index, ifaddr, &ifr);

	if (type == NETIF_REGULAR) { 
	    my_log(INFO, "found ethernet interface %s", ifaddr->ifa_name);
	    sysinfo->physif_count++;
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

#ifdef SIOCGIFDESCR
#ifndef __FreeBSD__
	ifr.ifr_data = (caddr_t)&netif->description;
#else
	ifr.ifr_buffer.buffer = &netif->description;
	ifr.ifr_buffer.length = IFDESCRSIZE;
#endif
	ioctl(sockfd, SIOCGIFDESCR, &ifr);
#endif

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
		netif_device_id(netif);
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

    // cleanup
    freeifaddrs(ifaddrs);
    (void) close(sockfd);

    return(count);
};


// detect wireless interfaces
int netif_wireless(int sockfd, struct ifaddrs *ifaddr, struct ifreq *ifr) {

#if HAVE_NET_IF_MEDIA_H
    struct ifmediareq ifmr = {};
#endif /* HAVE_HAVE_NET_IF_MEDIA_H */

#ifdef HAVE_LINUX_WIRELESS_H
    struct iwreq iwreq = {};

    strlcpy(iwreq.ifr_name, ifaddr->ifa_name, sizeof(iwreq.ifr_name));

    return(ioctl(sockfd, SIOCGIWNAME, &iwreq));
#endif

#ifdef HAVE_NET80211_IEEE80211_IOCTL_H
#ifdef SIOCG80211
    struct ieee80211req ireq = {};
    u_int8_t i_data[32];

    strlcpy(ireq.i_name, ifaddr->ifa_name, sizeof(ireq.i_name));
    ireq.i_data = &i_data;

    ireq.i_type = IEEE80211_IOC_SSID;
    ireq.i_val = -1;

    return(ioctl(sockfd, SIOCG80211, &ireq));
#elif defined(SIOCG80211NWID)
    struct ieee80211_nwid nwid;

    ifr->ifr_data = (caddr_t)&nwid;

    return(ioctl(sockfd, SIOCG80211NWID, (caddr_t)ifr));
#endif
#endif /* HAVE_NET80211_IEEE80211_IOCTL_H */

#if defined(HAVE_NET_IF_MEDIA_H) && defined(IFM_IEEE80211)
    strlcpy(ifmr.ifm_name, ifaddr->ifa_name, sizeof(ifmr.ifm_name));

    if (ioctl(sockfd, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0)
	return(-1);

    if (IFM_TYPE(ifmr.ifm_current) == IFM_IEEE80211)
	return(0);
#endif /* HAVE_HAVE_NET_IF_MEDIA_H */

    // default
    return(-1);
}


// detect interface type
int netif_type(int sockfd, uint32_t index,
	struct ifaddrs *ifaddr, struct ifreq *ifr) {

#if HAVE_LINUX_ETHTOOL_H
    struct ethtool_drvinfo drvinfo = {};
#endif

#if defined(HAVE_LINUX_IF_VLAN_H) && \
    defined(HAVE_DECL_GET_VLAN_REALDEV_NAME_CMD)
    struct vlan_ioctl_args if_request = {};
#endif /* HAVE_LINUX_IF_VLAN_H */
#ifdef HAVE_NET_IF_VLAN_VAR_H
    struct vlanreq vreq = {};
#endif /* HAVE_NET_IF_VLAN_VAR_H */
#ifdef HAVE_NET_IF_LAGG_H
    struct lagg_reqall ra = {};
#elif HAVE_NET_IF_TRUNK_H
    struct trunk_reqall ra = {};
#endif

#ifdef HAVE_SYSFS
    struct master_req mreq = {};

    mreq.op = MASTER_DEVICE;
    mreq.index = index;

    if (my_mreq(&mreq))
	return(NETIF_REGULAR);
#endif /* HAVE_SYSFS */

#if defined(HAVE_LINUX_IF_VLAN_H) && \
    defined(HAVE_DECL_GET_VLAN_REALDEV_NAME_CMD)
    // vlan
    if_request.cmd = GET_VLAN_REALDEV_NAME_CMD;
    strlcpy(if_request.device1, ifaddr->ifa_name, sizeof(if_request.device1));

    if (ioctl(sockfd, SIOCSIFVLAN, &if_request) >= 0)
	return(NETIF_VLAN);
#endif /* HAVE_LINUX_IF_VLAN_H */

#if HAVE_LINUX_ETHTOOL_H
    // use ethtool to detect various drivers
    drvinfo.cmd = ETHTOOL_GDRVINFO;
    ifr->ifr_data = (caddr_t)&drvinfo;

    if (ioctl(sockfd, SIOCETHTOOL, ifr) >= 0) {
	// handle bonding
	if (strcmp(drvinfo.driver, "bonding") == 0) {
	    return(NETIF_BONDING);
	// handle bridge
	} else if (strcmp(drvinfo.driver, "bridge") == 0) {
	    return(NETIF_BRIDGE);
	// handle vlan
	} else if (strcmp(drvinfo.driver, "802.1Q VLAN Support") == 0) {
	    return(NETIF_VLAN);
	// handle tun/tap
	} else if (strcmp(drvinfo.driver, "tun") == 0) {
	    return(NETIF_REGULAR);
	}

	// we'll accept interfaces which support ethtool (aka wing it)
	return(NETIF_REGULAR);
    }

    // we don't want the rest
    return(NETIF_INVALID);
#endif /* HAVE_LINUX_ETHTOOL_H */

#ifdef AF_LINK
    struct if_data *if_data = ifaddr->ifa_data;

    if (if_data->ifi_type == IFT_ETHER) {

	// vlan
#ifdef HAVE_NET_IF_VLAN_VAR_H
	ifr->ifr_data = (caddr_t)&vreq;
	if (ioctl(sockfd, SIOCGETVLAN, ifr) >= 0)
	    return(NETIF_VLAN);
#endif /* HAVE_NET_IF_VLAN_VAR_H */

	// bonding
#if defined(HAVE_NET_IF_LAGG_H) || defined(HAVE_NET_IF_TRUNK_H)
	strlcpy(ra.ra_ifname, ifaddr->ifa_name, sizeof(ra.ra_ifname));
#ifdef HAVE_NET_IF_LAGG_H
	if (ioctl(sockfd, SIOCGLAGG, &ra) >= 0)
	    return(NETIF_BONDING);
#elif HAVE_NET_IF_TRUNK_H
	if (ioctl(sockfd, SIOCGTRUNK, &ra) == 0)
	    return(NETIF_BONDING);
#endif
#endif

	// accept regular devices
	return(NETIF_REGULAR);

    // bridge
#ifdef IFT_BRIDGE
    } else if (if_data->ifi_type == IFT_BRIDGE) {
	return(NETIF_BRIDGE);
#endif
#ifdef IFT_IEEE8023ADLAG
    // trunk ports have a special type
    } else if (if_data->ifi_type == IFT_IEEE8023ADLAG) {
	return(NETIF_REGULAR);
#endif
    }

    // we don't want the rest
    return(NETIF_INVALID);
#endif /* AF_LINK */

    // default
    return(NETIF_REGULAR);
}


void netif_device_id(struct netif *netif) {

    if (netif->device_identified)
	return;
    netif->device_identified = 1;

#ifdef HAVE_SYSFS
    struct master_req mreq = {};

    mreq.op = MASTER_DEVICE_ID;
    mreq.index = netif->index;

    if (!my_mreq(&mreq))
	return;

    strlcpy(netif->device_name, mreq.buf, sizeof(netif->device_name));

#elif defined(__FreeBSD__)
    int name[6], ret;
    char *dname, *dunit, desc_sysctl[64] = {};
    size_t len = 0;

    // First figure out the name of the driver
    name[0] = CTL_NET;
    name[1] = PF_LINK;
    name[2] = NETLINK_GENERIC;
    name[3] = IFMIB_IFDATA;
    name[4] = netif->index;
    name[5] = IFDATA_DRIVERNAME;

    if (sysctl(name, 6, NULL, &len, 0, 0) < 0) 
	return;

    // + 1 for the sysctl dunit dot
    dname = my_malloc(len + 1);

    if (sysctl(name, 6, dname, &len, 0, 0) < 0) {
	free(dname);
	return;
    }

    // find the unit number at the end of dname
    dunit = dname + strlen(dname);
    while (strspn(dunit - 1, "0123456789"))
	dunit--;

    // no unit found, all too hard
    if (!strlen(dunit)) {
	free(dname);
	return;
    }

    // insert dot
    memmove(dunit + 1, dunit, strlen(dunit));
    *dunit = '.';

    ret = snprintf(desc_sysctl, sizeof(desc_sysctl), "dev.%s.%%desc", dname);
    free(dname);

    if (ret == -1)
	return;

    len = sizeof(netif->device_name);
    sysctlbyname(desc_sysctl, netif->device_name, &len, NULL, 0);
#endif
}

// handle aggregated interfaces
void netif_bond(int sockfd, struct nhead *netifs, struct netif *master,
		struct ifreq *ifr) {

    struct netif *subif = NULL, *csubif = master;

#ifdef HAVE_LINUX_IF_BONDING_H
    struct ifbond ifbond = {};
    struct ifslave ifslave = {};
#elif HAVE_NET_IF_LAGG_H
    struct lagg_reqport rpbuf[LAGG_MAX_PORTS];
    struct lagg_reqall ra = {};
#elif HAVE_NET_IF_TRUNK_H
    struct trunk_reqport rpbuf[TRUNK_MAX_PORTS];
    struct trunk_reqall ra = {};
#endif

    // check for lacp
#if defined(HAVE_LINUX_IF_BONDING_H) && defined(BOND_MODE_8023AD)
    strlcpy(ifr->ifr_name, master->name, IFNAMSIZ);
    ifr->ifr_data = (char *)&ifbond;

    if (ioctl(sockfd, SIOCBONDINFOQUERY, ifr) >= 0) {
	if (ifbond.bond_mode == BOND_MODE_8023AD)
	    master->lacp = 1;
    }
#endif /* HAVE_LINUX_IF_BONDING_H && BOND_MODE_8023AD */

    if (master->lacp == 1)
	my_log(INFO, "lacp enabled on %s", master->name);


    // handle slaves
#ifdef HAVE_LINUX_IF_BONDING_H

    // check for a sensible num_slaves entry
    if (ifbond.num_slaves <= 0)
	return;

    for (int i = 0; i < ifbond.num_slaves; i++) {
	ifslave.slave_id = i;
	ifr->ifr_data = (char *)&ifslave;

	if (ioctl(sockfd, SIOCBONDSLAVEINFOQUERY, ifr) >= 0) {
	    subif = netif_byname(netifs, ifslave.slave_name);

	    // XXX: multi-level bonds not supported
	    if ((subif != NULL) && (subif->type == NETIF_REGULAR)) {
		my_log(INFO, "found slave %s", subif->name);
		subif->slave = 1;
		subif->master = master;
		subif->lacp_index = i;
		csubif->subif = subif;
		csubif = subif;
	    }
	}
    }

    return;
#endif /* HAVE_LINUX_IF_BONDING_H */

#if defined(HAVE_NET_IF_LAGG_H) || defined(HAVE_NET_IF_TRUNK_H)
    strlcpy(ra.ra_ifname, master->name, sizeof(ra.ra_ifname));
    ra.ra_size = sizeof(rpbuf);
    ra.ra_port = rpbuf;

#ifdef HAVE_NET_IF_LAGG_H
    if (ioctl(sockfd, SIOCGLAGG, &ra) >= 0)
	if (ra.ra_proto == LAGG_PROTO_LACP)
	    master->lacp = 1;
#elif HAVE_NET_IF_TRUNK_H
    if (ioctl(sockfd, SIOCGTRUNK, &ra) >= 0)
	if ((ra.ra_proto == TRUNK_PROTO_ROUNDROBIN) ||
	    (ra.ra_proto == TRUNK_PROTO_LOADBALANCE))
	    master->lacp = 1;
#endif
    
    for (int i = 0; i < ra.ra_ports; i++) {
	subif = netif_byname(netifs, rpbuf[i].rp_portname);

	// XXX: multi-level bonds not supported
	if ((subif != NULL) && (subif->type == NETIF_REGULAR)) {
	    my_log(INFO, "found slave %s", subif->name);
	    subif->slave = 1;
	    subif->master = master;
	    subif->lacp_index = i;
	    csubif->subif = subif;
	    csubif = subif;
	}
    }

    return;
#endif /* HAVE_NET_IF_LAGG_H || HAVE_NET_IF_TRUNK_H */

#ifdef HAVE_NET_IF_BOND_VAR_H
    struct if_bond_req ibr = {};
    struct if_bond_status *ibs;
    struct if_bond_status_req *ibsr;

    ibr.ibr_op = IF_BOND_OP_GET_STATUS;
    ibsr = &ibr.ibr_ibru.ibru_status;
    ibsr->ibsr_version = IF_BOND_STATUS_REQ_VERSION;

    strlcpy(ifr->ifr_name, master->name, IFNAMSIZ);
    ifr->ifr_data = (caddr_t)&ibr;

    if (ioctl(sockfd, SIOCGIFBOND, ifr) >= 0)
	if (ibsr->ibsr_mode == IF_BOND_MODE_LACP)
	    master->lacp = 1;

    if (ibsr->ibsr_total <= 0) 
	return;

    ibsr->ibsr_buffer = my_malloc(sizeof(struct if_bond_status) * 
				    ibsr->ibsr_total);
    ibsr->ibsr_count = ibsr->ibsr_total;

    if ((ioctl(sockfd, SIOCGIFBOND, ifr) >= 0) && (ibsr->ibsr_total > 0)) {
	ibs = (struct if_bond_status *)ibsr->ibsr_buffer;

	for (int i = 0; i < ibsr->ibsr_total; i++) {
	    subif = netif_byname(netifs, ibs->ibs_if_name);

	    // XXX: multi-level bonds not supported
	    if ((subif != NULL) && (subif->type == NETIF_REGULAR)) {
		my_log(INFO, "found slave %s", subif->name);
		subif->slave = 1;
		subif->master = master;
		subif->lacp_index = i++;
		csubif->subif = subif;
		csubif = subif;
	    }
	}
    }	

    free(ibsr->ibsr_buffer);
    return;
#endif /* HAVE_NET_IF_BOND_VAR_H */
}


// handle bridge interfaces
void netif_bridge(int sockfd, struct nhead *netifs, struct netif *master,
		  struct ifreq *ifr) {

#if defined(HAVE_LINUX_IF_BRIDGE_H) || \
    defined(HAVE_NET_IF_BRIDGEVAR_H) || defined(HAVE_NET_IF_BRIDGE_H)
    struct netif *subif = NULL, *csubif = master;
#endif

#ifdef HAVE_LINUX_IF_BRIDGE_H
    int ifindex[BRIDGE_MAX_PORTS] = {};
    unsigned long args[4] = { BRCTL_GET_PORT_LIST,
		    (unsigned long)ifindex, BRIDGE_MAX_PORTS, 0 };
#endif /* HAVE_LINUX_IF_BRIDGE_H */


    // handle slaves
#ifdef HAVE_LINUX_IF_BRIDGE_H
    strlcpy(ifr->ifr_name, master->name, IFNAMSIZ);
    ifr->ifr_data = (char *)&args;

    if (ioctl(sockfd, SIOCDEVPRIVATE, ifr) < 0) {
	my_loge(CRIT, "bridge ioctl failed on interface %s", master->name);
	return;
    }

    for (int i = 0; i < BRIDGE_MAX_PORTS; i++) {
	subif = netif_byindex(netifs, ifindex[i]);

	// XXX: multi-level bridges not supported
	if ((subif != NULL) && (subif->type == NETIF_REGULAR)) {
	    my_log(INFO, "found slave %s", subif->name);
	    subif->slave = 1;
	    subif->master = master;
	    csubif->subif = subif;
	    csubif = subif;
	}
    }

    return;
#endif /* HAVE_LINUX_IF_BRIDGE_H */

#if defined(HAVE_NET_IF_BRIDGEVAR_H) || defined(HAVE_NET_IF_BRIDGE_H)
    struct ifbifconf bifc;
    struct ifbreq *req;
    char *inbuf = NULL, *ninbuf;
    int len = 8192;

#ifdef HAVE_NET_IF_BRIDGEVAR_H
    struct ifdrv ifd = {};

    strlcpy(ifd.ifd_name, master->name, sizeof(ifd.ifd_name));
    ifd.ifd_cmd = BRDGGIFS;
    ifd.ifd_len = sizeof(bifc);
    ifd.ifd_data = &bifc;
#elif HAVE_NET_IF_BRIDGE_H
    strlcpy(bifc.ifbic_name, master->name, sizeof(bifc.ifbic_name));
#endif /* HAVE_NET_IF_BRIDGEVAR_H */

    for (;;) {
	ninbuf = realloc(inbuf, len);

	if (ninbuf == NULL) {
	    if (inbuf != NULL)
		free(inbuf);
	    my_log(WARN, "unable to allocate interface buffer");
	    return;
	}

	bifc.ifbic_len = len;
	bifc.ifbic_buf = inbuf = ninbuf;

#ifdef HAVE_NET_IF_BRIDGEVAR_H
	if (ioctl(sockfd, SIOCGDRVSPEC, &ifd) < 0) {
#elif HAVE_NET_IF_BRIDGE_H
	if (ioctl(sockfd, SIOCBRDGIFS, &bifc) < 0) {
#endif
	    free(inbuf);
	    return;
	}

	if ((bifc.ifbic_len + sizeof(*req)) < len)
	    break;
	len *= 2;
    }

    for (int i = 0; i < bifc.ifbic_len / sizeof(*req); i++) {
	req = bifc.ifbic_req + i;

	subif = netif_byname(netifs, req->ifbr_ifsname);

	// XXX: multi-level bridges not supported
	if ((subif != NULL) && (subif->type == NETIF_REGULAR)) {
	    my_log(INFO, "found slave %s", subif->name);
	    subif->slave = 1;
	    subif->master = master;
	    csubif->subif = subif;
	    csubif = subif;
	}
    }

    // cleanup
    free(inbuf);

    return;
#endif

}


// handle vlan interfaces
void netif_vlan(int sockfd, struct nhead *netifs, struct netif *vlan,
		  struct ifreq *ifr) {

    struct netif *netif = NULL;

#ifdef HAVE_LINUX_IF_VLAN_H
#if defined(HAVE_DECL_GET_VLAN_REALDEV_NAME_CMD) && \
    defined(HAVE_DECL_GET_VLAN_VID_CMD)
    struct vlan_ioctl_args if_request = {};

    if_request.cmd = GET_VLAN_REALDEV_NAME_CMD;
    strlcpy(if_request.device1, vlan->name, sizeof(if_request.device1));

    if (ioctl(sockfd, SIOCSIFVLAN, &if_request) < 0)
	return;

    netif = netif_byname(netifs, if_request.u.device2);
    if (netif == NULL)
	return;
    vlan->vlan_parent = netif->index;

    if_request.cmd = GET_VLAN_VID_CMD;
    if (ioctl(sockfd, SIOCSIFVLAN, &if_request) >= 0)
	vlan->vlan_id = if_request.u.VID;

    return;
#endif
#endif /* HAVE_LINUX_IF_VLAN_H */

#ifdef HAVE_NET_IF_VLAN_VAR_H
    struct vlanreq vreq = {};

    ifr->ifr_data = (caddr_t)&vreq;
    if (ioctl(sockfd, SIOCGETVLAN, ifr) < 0)
	return;

    netif = netif_byname(netifs, vreq.vlr_parent);
    if (netif == NULL)
	return;

    vlan->vlan_parent = netif->index;
    vlan->vlan_id = vreq.vlr_tag;
#endif /* HAVE_NET_IF_VLAN_VAR_H */
}


// perform address detection for all netifs
void netif_addrs(struct ifaddrs *ifaddrs, struct nhead *netifs,
		struct sysinfo *sysinfo) {
    struct ifaddrs *ifaddr;
    struct netif *netif;

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

    // return when no management addresses are defined
    if ((sysinfo->maddr4 == 0) &&
	(IN6_IS_ADDR_UNSPECIFIED((struct in6_addr *)sysinfo->maddr6)) )
	return;

    // use management address when unnumbered
    TAILQ_FOREACH(netif, netifs, entries) {

	if ((netif->ipaddr4 == 0) || (options & OPT_MADDR))
	    netif->ipaddr4 = sysinfo->maddr4;

	if (IN6_IS_ADDR_UNSPECIFIED((struct in6_addr *)netif->ipaddr6) ||
	    (options & OPT_MADDR))
	    memcpy(&netif->ipaddr6, &sysinfo->maddr6, sizeof(sysinfo->maddr6));
    }

    return;
}


// perform media detection on physical interfaces
int netif_media(struct netif *netif) {
    int sockfd, af = AF_INET;
    struct ifreq ifr = {};

#if HAVE_LINUX_ETHTOOL_H
    struct ethtool_cmd ecmd;
    struct master_req mreq = {};
#endif /* HAVE_LINUX_ETHTOOL_H */

#if HAVE_NET_IF_MEDIA_H
    struct ifmediareq ifmr = {};
    int *media_list;
#endif /* HAVE_HAVE_NET_IF_MEDIA_H */

    sockfd = my_socket(af, SOCK_DGRAM, 0);

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

#if HAVE_LINUX_ETHTOOL_H
    int ecmd_to_lldp_pmd[][2] = {
	{ADVERTISED_10baseT_Half,   LLDP_MAU_PMD_10BASE_T},
	{ADVERTISED_10baseT_Full,   LLDP_MAU_PMD_10BASE_T_FD},
	{ADVERTISED_100baseT_Half,  LLDP_MAU_PMD_100BASE_TX},
	{ADVERTISED_100baseT_Full,  LLDP_MAU_PMD_100BASE_TX_FD},
	{ADVERTISED_1000baseT_Half, LLDP_MAU_PMD_1000BASE_T},
	{ADVERTISED_1000baseT_Full, LLDP_MAU_PMD_1000BASE_T_FD},
	{ADVERTISED_10000baseT_Full, LLDP_MAU_PMD_OTHER},
	{ADVERTISED_Pause,	    LLDP_MAU_PMD_FDXPAUSE},
	{ADVERTISED_Asym_Pause,	    LLDP_MAU_PMD_FDXAPAUSE},
	{ADVERTISED_2500baseX_Full, LLDP_MAU_PMD_OTHER},
	{0, 0}
    };

    mreq.op = MASTER_ETHTOOL;
    mreq.index = netif->index;
    mreq.len = sizeof(ecmd);

    if (my_mreq(&mreq) != sizeof(ecmd)) {
	// cleanup
	close(sockfd);

	return(EXIT_SUCCESS);
    }

    // copy ecmd struct
    memcpy(&ecmd, mreq.buf, sizeof(ecmd));

    // duplex
    netif->duplex = (ecmd.duplex == DUPLEX_FULL);

    // autoneg
    if (ecmd.supported & SUPPORTED_Autoneg) {
	my_log(INFO, "autoneg supported on %s", netif->name);
	netif->autoneg_supported = 1;
	netif->autoneg_enabled = (ecmd.autoneg == AUTONEG_ENABLE);
	for (int i=0; ecmd_to_lldp_pmd[i][0]; i++) {
	    if (ecmd.advertising & ecmd_to_lldp_pmd[i][0])
		netif->autoneg_pmd |= ecmd_to_lldp_pmd[i][1];
	}
    } else {
	my_log(INFO, "autoneg not supported on %s", netif->name);
	netif->autoneg_supported = 0;
    }	

    // report a mau guesstimate
    netif->mau = LLDP_MAU_TYPE_UNKNOWN;

    switch (ecmd.port) {
	case PORT_TP:
	    if (ecmd.speed == SPEED_10)
		netif->mau = (netif->duplex) ?
		     LLDP_MAU_TYPE_10BASE_T_FD : LLDP_MAU_TYPE_10BASE_T_HD;
	    else if (ecmd.speed == SPEED_100)
		netif->mau = (netif->duplex) ?
		     LLDP_MAU_TYPE_100BASE_TX_FD: LLDP_MAU_TYPE_100BASE_TX_HD;
	    else if (ecmd.speed == SPEED_1000)
		netif->mau = (netif->duplex) ?
		     LLDP_MAU_TYPE_1000BASE_T_FD: LLDP_MAU_TYPE_1000BASE_T_HD;
	    else if (ecmd.speed == SPEED_10000)
		netif->mau = LLDP_MAU_TYPE_10GBASE_T;
	    break;
	case PORT_FIBRE:
	    if (ecmd.speed == SPEED_10)
		netif->mau = (netif->duplex) ?
		     LLDP_MAU_TYPE_10BASE_FL_FD: LLDP_MAU_TYPE_10BASE_FL_HD;
	    else if (ecmd.speed == SPEED_100)
		netif->mau = (netif->duplex) ?
		     LLDP_MAU_TYPE_100BASE_FX_FD: LLDP_MAU_TYPE_100BASE_FX_HD;
	    else if (ecmd.speed == SPEED_1000)
		netif->mau = (netif->duplex) ?
		     LLDP_MAU_TYPE_1000BASE_X_FD: LLDP_MAU_TYPE_1000BASE_X_HD;
	    else if (ecmd.speed == SPEED_10000)
		netif->mau = LLDP_MAU_TYPE_10GBASE_X;
	    break;
	case PORT_BNC:
	    if (ecmd.speed == SPEED_10)
		netif->mau = LLDP_MAU_TYPE_10BASE_2; 
	    break;
	case PORT_AUI:
	    netif->mau = LLDP_MAU_TYPE_AUI;
	    break;
	case PORT_MII:
	    break;
#ifdef PORT_DA
	case PORT_DA:
	    if (ecmd.speed == SPEED_10000)
		netif->mau = LLDP_MAU_TYPE_10GBASE_CX4;
	    break
#endif
    }
#endif /* HAVE_LINUX_ETHTOOL_H */

#if HAVE_NET_IF_MEDIA_H
    strlcpy(ifmr.ifm_name, netif->name, sizeof(ifmr.ifm_name));

    if (ioctl(sockfd, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0) {
	my_log(INFO, "media detection not supported on %s", netif->name);
	close(sockfd);
	return(EXIT_SUCCESS);
    }

    if (IFM_TYPE(ifmr.ifm_current) != IFM_ETHER) {
	my_log(INFO, "non-ethernet interface %s found", netif->name);
	close(sockfd);
	return(EXIT_FAILURE);
    }

    if ((ifmr.ifm_status & IFM_ACTIVE) == 0) { 
	my_log(INFO, "no link detected on interface %s", netif->name);
	close(sockfd);
	return(EXIT_SUCCESS);
    }

    if (ifmr.ifm_count == 0) {
	my_log(CRIT, "missing media types for interface %s", netif->name);
	close(sockfd);
	return(EXIT_FAILURE);
    }

    media_list = my_malloc(ifmr.ifm_count * sizeof(int));
    ifmr.ifm_ulist = media_list;

    if (ioctl(sockfd, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0) {
	my_log(CRIT, "media detection failed for interface %s", netif->name);
	free(media_list);
	close(sockfd);
	return(EXIT_FAILURE);
    }

    // autoneg and advertised media
    for (int m = 0; m < ifmr.ifm_count; m++) {
	unsigned int media = IFM_SUBTYPE(ifmr.ifm_ulist[m]);
	unsigned int duplex = IFM_OPTIONS(ifmr.ifm_ulist[m]) & IFM_FDX;

	if (media == IFM_AUTO) {
	    my_log(INFO, "autoneg supported on %s", netif->name);
	    netif->autoneg_supported = 1;
	    continue;
	}

	switch (media) {
	    case IFM_10_T:
		netif->autoneg_pmd |= (duplex) ?
		    LLDP_MAU_PMD_10BASE_T_FD : LLDP_MAU_PMD_10BASE_T;
		break;
	    case IFM_100_TX:
		netif->autoneg_pmd |= (duplex) ?
		    LLDP_MAU_PMD_100BASE_TX_FD : LLDP_MAU_PMD_100BASE_TX;
		break;
	    case IFM_100_T2:
		netif->autoneg_pmd |= (duplex) ?
		    LLDP_MAU_PMD_100BASE_T2_FD : LLDP_MAU_PMD_100BASE_T2;
		break;
	    case IFM_100_T4:
		netif->autoneg_pmd |= LLDP_MAU_PMD_100BASE_T4;
		break;
	    case IFM_1000_T:
		netif->autoneg_pmd |= (duplex) ?
		    LLDP_MAU_PMD_1000BASE_T_FD : LLDP_MAU_PMD_1000BASE_T;
		break;
	    case IFM_1000_SX:
	    case IFM_1000_LX:
	    case IFM_1000_CX:
		netif->autoneg_pmd |= (duplex) ?
		    LLDP_MAU_PMD_1000BASE_X_FD : LLDP_MAU_PMD_1000BASE_X;
		break;
	    default:
		netif->autoneg_pmd |= LLDP_MAU_PMD_OTHER;
	}
    }

    // autoneg enabled
    if (netif->autoneg_supported == 1) {
	if (IFM_SUBTYPE(ifmr.ifm_current) == IFM_AUTO) {
	    my_log(INFO, "autoneg enabled on %s", netif->name);
	    netif->autoneg_enabled = 1;
	} else {
	    my_log(INFO, "autoneg disabled on interface %s", netif->name);
	    netif->autoneg_enabled = 0;
	}
    } else {
	my_log(INFO, "autoneg not supported on interface %s", netif->name);
	netif->autoneg_supported = 0;
    }

    // duplex
    if ((IFM_OPTIONS(ifmr.ifm_active) & IFM_FDX) != 0) {
	my_log(INFO, "full-duplex enabled on interface %s", netif->name);
	netif->duplex = 1;
    } else {
	my_log(INFO, "half-duplex enabled on interface %s", netif->name);
	netif->duplex = 0;
    }

    // mau
    netif->mau = LLDP_MAU_TYPE_UNKNOWN;

    switch (IFM_SUBTYPE(ifmr.ifm_active)) {
	case IFM_10_T:
	    netif->mau = (netif->duplex) ?
		LLDP_MAU_TYPE_10BASE_T_FD : LLDP_MAU_TYPE_10BASE_T_HD;
	    break;
	case IFM_10_2:
	    netif->mau = LLDP_MAU_TYPE_10BASE_2;
	    break;
	case IFM_10_5:
	    netif->mau = LLDP_MAU_TYPE_10BASE_5;
	    break;
	case IFM_100_TX:
	    netif->mau = (netif->duplex) ?
		LLDP_MAU_TYPE_100BASE_TX_FD : LLDP_MAU_TYPE_100BASE_TX_HD;
	    break;
	case IFM_100_FX:
	    netif->mau = (netif->duplex) ?
		LLDP_MAU_TYPE_100BASE_FX_FD : LLDP_MAU_TYPE_100BASE_FX_HD;
	    break;
	case IFM_100_T4:
	    netif->mau = LLDP_MAU_TYPE_100BASE_T4;
	    break;
	case IFM_100_T2:
	    netif->mau = (netif->duplex) ?
		LLDP_MAU_TYPE_100BASE_T2_FD : LLDP_MAU_TYPE_100BASE_T2_HD;
	    break;
	case IFM_1000_SX:
	    netif->mau = (netif->duplex) ?
		LLDP_MAU_TYPE_1000BASE_SX_FD : LLDP_MAU_TYPE_1000BASE_SX_HD;
	    break;
	case IFM_10_FL: 
	    netif->mau = (netif->duplex) ?
		LLDP_MAU_TYPE_10BASE_FL_FD : LLDP_MAU_TYPE_10BASE_FL_HD;
	    break;
	case IFM_1000_LX:
	    netif->mau = (netif->duplex) ?
		LLDP_MAU_TYPE_1000BASE_LX_FD : LLDP_MAU_TYPE_1000BASE_LX_HD;
	    break;
	case IFM_1000_CX:
	    netif->mau = (netif->duplex) ?
		LLDP_MAU_TYPE_1000BASE_CX_FD : LLDP_MAU_TYPE_1000BASE_CX_HD;
	    break;
	case IFM_1000_T:
	    netif->mau = (netif->duplex) ?
		LLDP_MAU_TYPE_1000BASE_T_FD : LLDP_MAU_TYPE_1000BASE_T_HD;
	    break;
	case IFM_10G_LR:
	    netif->mau = LLDP_MAU_TYPE_10GBASE_LR;
	    break;
	case IFM_10G_SR:
	    netif->mau = LLDP_MAU_TYPE_10GBASE_SR;
	    break;
	case IFM_10G_CX4:
	    netif->mau = LLDP_MAU_TYPE_10GBASE_CX4;
	    break;
	case IFM_10G_T:
	    netif->mau = LLDP_MAU_TYPE_10GBASE_T;
	    break;
    }

    free(media_list);
#endif /* HAVE_NET_IF_MEDIA_H */

    // cleanup
    close(sockfd);

    return(EXIT_SUCCESS);
}

