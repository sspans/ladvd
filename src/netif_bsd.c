/*
 * Copyright (c) 2012
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

#if HAVE_NET_IF_MEDIA_H
#include <net/if_media.h>
#endif /* HAVE_NET_IF_MEDIA_H */

#ifdef HAVE_NET_IF_DL_H
#include <net/if_dl.h>
#endif /* HAVE_NET_IF_DL_H */

#ifdef HAVE_NET_IF_TYPES_H
#include <net/if_types.h>
#endif /* HAVE_NET_IF_TYPES_H */


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


#if HAVE_NET_IF_BRIDGEVAR_H
#include <net/if_bridgevar.h>
#endif /* HAVE_NET_IF_BRIDGEVAR_H */

#if HAVE_NET_IF_BRIDGE_H
#include <net/if_bridge.h>
#endif /* HAVE_NET_IF_BRIDGE_H */


#ifdef HAVE_NET80211_IEEE80211_H
#include <net80211/ieee80211.h>
#endif /* HAVE_NET80211_IEEE80211_H */
#ifdef HAVE_NET80211_IEEE80211_IOCTL_H
#include <net80211/ieee80211_ioctl.h>
#endif /* HAVE_NET80211_IEEE80211_IOCTL_H */

#ifdef HAVE_NET_IF_MIB_H
#include <net/if_mib.h>
#endif /* HAVE_NET_IF_MIB_H */

static int netif_wireless(int, struct ifaddrs *ifaddr, struct ifreq *);
static void netif_driver(int, uint32_t index, struct ifreq *, char *, size_t);

// detect interface type
static int netif_type(int sockfd, uint32_t index,
	struct ifaddrs *ifaddr, struct ifreq *ifr) {

    char dname[IFNAMSIZ+1] = {};
#ifdef HAVE_NET_IF_VLAN_VAR_H
    struct vlanreq vreq = {};
#endif /* HAVE_NET_IF_VLAN_VAR_H */
#ifdef HAVE_NET_IF_LAGG_H
    struct lagg_reqall ra = {};
#elif HAVE_NET_IF_TRUNK_H
    struct trunk_reqall ra = {};
#endif

    // detect driver name
    netif_driver(sockfd, index, ifr, dname, IFNAMSIZ);

    // detect wireless interfaces
    if (netif_wireless(sockfd, ifaddr, ifr) >= 0)
	return(NETIF_WIRELESS);

#ifdef AF_LINK
    struct if_data *if_data = ifaddr->ifa_data;
    char *dunit;

    if (if_data->ifi_type == IFT_ETHER) {

	// vlan
#ifdef HAVE_NET_IF_VLAN_VAR_H
	ifr->ifr_data = (caddr_t)&vreq;
	if (ioctl(sockfd, SIOCGETVLAN, ifr) >= 0)
	    return(NETIF_VLAN);
#endif /* HAVE_NET_IF_VLAN_VAR_H */

	// zap dunit
	dunit = dname + strlen(dname);
	while (dunit != dname && dunit-- && isdigit(*dunit))
	    *dunit = '\0';

	// detect tun/tap based on the driver name
	if ((strcmp(dname, "tun") == 0) || (strcmp(dname, "tap") == 0))
	    return(NETIF_TAP);

#ifdef __FreeBSD__
	// ipfw log interface has no ioctl and is IFT_ETHER
	if (strcmp(dname, "ipfw") == 0)
	    return(NETIF_INVALID);
#endif

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
#ifdef IFT_L2VLAN
    } else if (if_data->ifi_type == IFT_L2VLAN) {
	return(NETIF_VLAN);
#endif
    }

    // we don't want the rest
    return(NETIF_INVALID);
#endif /* AF_LINK */

    // default
    return(NETIF_REGULAR);
}


// detect driver names via ethtool, sysctl, etc
static void netif_driver(int sockfd, uint32_t index, struct ifreq *ifr,
		    char *dname, size_t len) {
#if defined IFDATA_DRIVERNAME
    int name[6];

    memset(dname, 0, len);

    name[0] = CTL_NET;
    name[1] = PF_LINK;
    name[2] = NETLINK_GENERIC;
    name[3] = IFMIB_IFDATA;
    name[4] = index;
    name[5] = IFDATA_DRIVERNAME;

    sysctl(name, 6, dname, &len, 0, 0);
#elif defined(__OpenBSD__)
    strlcpy(dname, ifr->ifr_name, len);
#endif
}


// detect wireless interfaces
static int netif_wireless(int sockfd, struct ifaddrs *ifaddr, struct ifreq *ifr) {

#if HAVE_NET_IF_MEDIA_H
    struct ifmediareq ifmr = {};
#endif /* HAVE_HAVE_NET_IF_MEDIA_H */

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


static void netif_device_id(int sockfd, struct netif *netif, struct ifreq *ifr) {

    if (netif->device_identified)
	return;
    netif->device_identified = 1;

#if defined(__FreeBSD__)
    char dname[IFNAMSIZ+1] = {}, desc_sysctl[64] = {}, *dunit;
    int ret;
    size_t len = 0;

    // leave room for the sysctl dunit dot
    netif_driver(sockfd, netif->index, ifr, dname, IFNAMSIZ);
    if (!strlen(dname))
	return;

    // find the unit number at the end of dname
    dunit = dname + strlen(dname);
    while (isdigit(*(dunit-1)) && dunit-- && dunit != dname);

    // no unit found, all too hard
    if (!strlen(dunit))
	return;

    // insert dot
    memmove(dunit + 1, dunit, strlen(dunit));
    *dunit = '.';

    ret = snprintf(desc_sysctl, sizeof(desc_sysctl), "dev.%s.%%desc", dname);
    if (ret == -1)
	return;

    len = sizeof(netif->device_name);
    sysctlbyname(desc_sysctl, netif->device_name, &len, NULL, 0);
#endif
}

// handle aggregated interfaces
static void netif_bond(int sockfd, struct nhead *netifs, struct netif *parent,
		struct ifreq *ifr) {
#if HAVE_NET_IF_LAGG_H || HAVE_NET_IF_TRUNK_H || HAVE_NET_IF_BOND_VAR_H
    struct netif *subif = NULL, *csubif = parent;
#endif

#if HAVE_NET_IF_LAGG_H
    struct lagg_reqport rpbuf[LAGG_MAX_PORTS];
    struct lagg_reqall ra = {};
#elif HAVE_NET_IF_TRUNK_H
    struct trunk_reqport rpbuf[TRUNK_MAX_PORTS];
    struct trunk_reqall ra = {};
#elif HAVE_NET_IF_BOND_VAR_H
    struct if_bond_req ibr = {};
    struct if_bond_status *ibs;
    struct if_bond_status_req *ibsr;
#endif

#if defined(HAVE_NET_IF_LAGG_H) || defined(HAVE_NET_IF_TRUNK_H)
    strlcpy(ra.ra_ifname, parent->name, sizeof(ra.ra_ifname));
    ra.ra_size = sizeof(rpbuf);
    ra.ra_port = rpbuf;

#ifdef HAVE_NET_IF_LAGG_H
    if (ioctl(sockfd, SIOCGLAGG, &ra) >= 0) {
	if (ra.ra_proto == LAGG_PROTO_LACP)
	    parent->bonding_mode = NETIF_BONDING_LACP;
	else if (ra.ra_proto == LAGG_PROTO_FAILOVER)
	    parent->bonding_mode = NETIF_BONDING_FAILOVER;
    }
#elif HAVE_NET_IF_TRUNK_H
    if (ioctl(sockfd, SIOCGTRUNK, &ra) >= 0) {
	if (ra.ra_proto == TRUNK_PROTO_LACP)
	    parent->bonding_mode = NETIF_BONDING_LACP;
	else if (ra.ra_proto == TRUNK_PROTO_FAILOVER)
	    parent->bonding_mode = NETIF_BONDING_FAILOVER;
    }
#endif
    
    for (int i = 0; i < ra.ra_ports; i++) {
	subif = netif_byname(netifs, rpbuf[i].rp_portname);

	// XXX: multi-level bonds not supported
	if ((subif != NULL) && (subif->type < NETIF_PARENT)) {
	    my_log(INFO, "found child %s", subif->name);
	    subif->child = NETIF_CHILD_ACTIVE;
#ifdef HAVE_NET_IF_LAGG_H
	    if (!(rpbuf[i].rp_flags & LAGG_PORT_ACTIVE))
#elif HAVE_NET_IF_TRUNK_H
	    if (!(rpbuf[i].rp_flags & TRUNK_PORT_ACTIVE))
#endif
		subif->child = NETIF_CHILD_BACKUP;
		
	    subif->lacp_index = i;
	    subif->parent = parent;
	    csubif->subif = subif;
	    csubif = subif;
	}
    }

    return;
#endif /* HAVE_NET_IF_LAGG_H || HAVE_NET_IF_TRUNK_H */

#ifdef HAVE_NET_IF_BOND_VAR_H
    ibr.ibr_op = IF_BOND_OP_GET_STATUS;
    ibsr = &ibr.ibr_ibru.ibru_status;
    ibsr->ibsr_version = IF_BOND_STATUS_REQ_VERSION;

    strlcpy(ifr->ifr_name, parent->name, IFNAMSIZ);
    ifr->ifr_data = (caddr_t)&ibr;

    if (ioctl(sockfd, SIOCGIFBOND, ifr) >= 0)
	if (ibsr->ibsr_mode == IF_BOND_MODE_LACP)
	    parent->bonding_mode = NETIF_BONDING_LACP;

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
	    if ((subif != NULL) && (subif->type < NETIF_PARENT)) {
		my_log(INFO, "found child %s", subif->name);
		subif->child = NETIF_CHILD_ACTIVE;
		subif->parent = parent;
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
static void netif_bridge(int sockfd, struct nhead *netifs, struct netif *parent,
		  struct ifreq *ifr) {

#if defined(HAVE_NET_IF_BRIDGEVAR_H) || defined(HAVE_NET_IF_BRIDGE_H)
    struct netif *subif = NULL, *csubif = parent;

    struct ifbifconf bifc;
    struct ifbreq *req;
    char *inbuf = NULL, *ninbuf;
    int len = 8192;

#ifdef HAVE_NET_IF_BRIDGEVAR_H
    struct ifdrv ifd = {};

    strlcpy(ifd.ifd_name, parent->name, sizeof(ifd.ifd_name));
    ifd.ifd_cmd = BRDGGIFS;
    ifd.ifd_len = sizeof(bifc);
    ifd.ifd_data = &bifc;
#elif HAVE_NET_IF_BRIDGE_H
    strlcpy(bifc.ifbic_name, parent->name, sizeof(bifc.ifbic_name));
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
	if ((subif != NULL) && (subif->type < NETIF_PARENT)) {
	    my_log(INFO, "found child %s", subif->name);
	    subif->child = NETIF_CHILD_ACTIVE;
	    subif->parent = parent;
	    csubif->subif = subif;
	    csubif = subif;
	}
    }

    // cleanup
    free(inbuf);

#endif
}


// handle vlan interfaces
static void netif_vlan(int sockfd, struct nhead *netifs, struct netif *vlan,
		  struct ifreq *ifr) {

#ifdef HAVE_NET_IF_VLAN_VAR_H
    struct vlanreq vreq = {};

    ifr->ifr_data = (caddr_t)&vreq;
    if (ioctl(sockfd, SIOCGETVLAN, ifr) < 0)
	return;

    struct netif *netif = netif_byname(netifs, vreq.vlr_parent);
    if (netif == NULL)
	return;

    vlan->vlan_parent = netif->index;
    vlan->vlan_id = vreq.vlr_tag;
#endif /* HAVE_NET_IF_VLAN_VAR_H */
}



// perform media detection on physical interfaces
static int netif_physical(int sockfd, struct netif *netif) {

#if HAVE_NET_IF_MEDIA_H
    struct ifmediareq ifmr = {};
    int *media_list;

    strlcpy(ifmr.ifm_name, netif->name, sizeof(ifmr.ifm_name));

    if (ioctl(sockfd, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0) {
	my_log(INFO, "media detection not supported on %s", netif->name);
	return(EXIT_SUCCESS);
    }

    if (IFM_TYPE(ifmr.ifm_current) != IFM_ETHER) {
	my_log(INFO, "non-ethernet interface %s found", netif->name);
	return(EXIT_FAILURE);
    }

    if ((ifmr.ifm_status & IFM_ACTIVE) == 0) { 
	my_log(INFO, "no link detected on interface %s", netif->name);
	return(EXIT_SUCCESS);
    }

    if (ifmr.ifm_count == 0) {
	my_log(CRIT, "missing media types for interface %s", netif->name);
	return(EXIT_FAILURE);
    }

    media_list = my_malloc(ifmr.ifm_count * sizeof(int));
    ifmr.ifm_ulist = media_list;

    if (ioctl(sockfd, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0) {
	my_log(CRIT, "media detection failed for interface %s", netif->name);
	free(media_list);
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
#ifdef IFM_10G_T
	case IFM_10G_T:
	    netif->mau = LLDP_MAU_TYPE_10GBASE_T;
	    break;
#endif
    }

    free(media_list);
#endif /* HAVE_NET_IF_MEDIA_H */

    return(EXIT_SUCCESS);
}

void netif_init_custom() {};

