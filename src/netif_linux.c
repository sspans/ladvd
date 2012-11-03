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

#if HAVE_ASM_TYPES_H
#include <asm/types.h>
#endif /* HAVE_ASM_TYPES_H */

#if HAVE_LINUX_SOCKIOS_H
#include <linux/sockios.h>
#endif /* HAVE_LINUX_SOCKIOS_H */

#if HAVE_LINUX_ETHTOOL_H
#include <linux/ethtool.h>
#endif /* HAVE_LINUX_ETHTOOL_H */

#ifdef HAVE_NETPACKET_PACKET_H
#include <netpacket/packet.h>
#endif /* HAVE_NETPACKET_PACKET_H */

#ifdef HAVE_NET_IF_TYPES_H
#include <net/if_types.h>
#endif /* HAVE_NET_IF_TYPES_H */


#ifdef HAVE_LINUX_IF_VLAN_H
#include <linux/if_vlan.h>
#endif /* HAVE_LINUX_IF_VLAN_H */

#ifdef HAVE_NET_IF_VLAN_VAR_H
#include <net/if_vlan_var.h>
#endif /* HAVE_NET_IF_VLAN_VAR_H */


#ifdef HAVE_LINUX_IF_BONDING_H
#include <linux/if_bonding.h>
#endif /* HAVE_LINUX_IF_BONDING_H */

#ifdef HAVE_LINUX_IF_BRIDGE_H
#include <linux/if_bridge.h>
#define BRIDGE_MAX_PORTS 1024
#endif /* HAVE_LINUX_IF_BRIDGE_H */

#ifdef HAVE_LINUX_WIRELESS_H
#include <linux/wireless.h>
#endif /* HAVE_LINUX_WIRELESS_H */


static int netif_wireless(int, struct ifaddrs *ifaddr, struct ifreq *);
static void netif_driver(int, uint32_t index, struct ifreq *, char *, size_t);

// detect interface type
static int netif_type(int sockfd, uint32_t index,
	struct ifaddrs *ifaddr, struct ifreq *ifr) {

    char dname[IFNAMSIZ+1] = {};
#if defined(HAVE_LINUX_IF_VLAN_H) && \
    HAVE_DECL_GET_VLAN_REALDEV_NAME_CMD
    struct vlan_ioctl_args if_request = {};
#endif /* HAVE_LINUX_IF_VLAN_H */
#ifdef HAVE_NET_IF_VLAN_VAR_H
    struct vlanreq vreq = {};
#endif /* HAVE_NET_IF_VLAN_VAR_H */

    // detect driver name
    netif_driver(sockfd, index, ifr, dname, IFNAMSIZ);

    // detect wireless interfaces
    if (netif_wireless(sockfd, ifaddr, ifr) >= 0)
	return(NETIF_WIRELESS);

#ifdef HAVE_SYSFS
    struct master_req mreq = {};

    mreq.op = MASTER_DEVICE;
    mreq.index = index;

    if (my_mreq(&mreq))
	return(NETIF_REGULAR);
#endif /* HAVE_SYSFS */

#if defined(HAVE_LINUX_IF_VLAN_H) && \
    HAVE_DECL_GET_VLAN_REALDEV_NAME_CMD
    // vlan
    if_request.cmd = GET_VLAN_REALDEV_NAME_CMD;
    strlcpy(if_request.device1, ifaddr->ifa_name, sizeof(if_request.device1));

    if (ioctl(sockfd, SIOCSIFVLAN, &if_request) >= 0)
	return(NETIF_VLAN);
#endif /* HAVE_LINUX_IF_VLAN_H */

#if HAVE_LINUX_ETHTOOL_H
    if (strlen(dname)) {
	// handle bonding
	if (strcmp(dname, "bonding") == 0) {
	    return(NETIF_BONDING);
	// handle bridge
	} else if (strcmp(dname, "bridge") == 0) {
	    return(NETIF_BRIDGE);
	// handle vlan
	} else if (strcmp(dname, "802.1Q VLAN Support") == 0) {
	    return(NETIF_VLAN);
	// handle tun/tap
	} else if (strcmp(dname, "tun") == 0) {
	    return(NETIF_TAP);
	}

	// we'll accept interfaces which support ethtool (aka wing it)
	return(NETIF_REGULAR);
    }

    // we don't want the rest
    return(NETIF_INVALID);
#endif /* HAVE_LINUX_ETHTOOL_H */

    // default
    return(NETIF_REGULAR);
}


// detect driver names via ethtool, sysctl, etc
static void netif_driver(int sockfd, uint32_t index, struct ifreq *ifr,
		    char *dname, size_t len) {
#if HAVE_LINUX_ETHTOOL_H
    struct master_req mreq = {};
    struct ethtool_drvinfo drvinfo = {};

    memset(dname, 0, len);

    mreq.op = MASTER_ETHTOOL_GDRV;
    mreq.index = index;
    mreq.len = sizeof(drvinfo);

    if (my_mreq(&mreq) != sizeof(drvinfo))
	return;

    // copy drvinfo struct
    memcpy(&drvinfo, mreq.buf, sizeof(drvinfo));

    strlcpy(dname, drvinfo.driver, len);
#endif /* HAVE_LINUX_ETHTOOL_H */
}


// detect wireless interfaces
static int netif_wireless(int sockfd, struct ifaddrs *ifaddr, struct ifreq *ifr) {

#ifdef HAVE_LINUX_WIRELESS_H
    struct iwreq iwreq = {};

    strlcpy(iwreq.ifr_name, ifaddr->ifa_name, sizeof(iwreq.ifr_name));

    return (ioctl(sockfd, SIOCGIWNAME, &iwreq));
#endif

    return(-1);
}


static void netif_device_id(int sockfd, struct netif *netif, struct ifreq *ifr) {

    if (netif->device_identified)
	return;
    netif->device_identified = 1;

#if defined(HAVE_PCI_PCI_H)
    struct master_req mreq = {};

    mreq.op = MASTER_DEVICE_ID;
    mreq.index = netif->index;

    if (!my_mreq(&mreq))
	return;

    strlcpy(netif->device_name, mreq.buf, sizeof(netif->device_name));
#endif /* HAVE_PCI_PCI_H */
}

// handle aggregated interfaces
static void netif_bond(int sockfd, struct nhead *netifs, struct netif *master,
		struct ifreq *ifr) {

#if HAVE_LINUX_IF_BONDING_H
    struct netif *subif = NULL, *csubif = master;

    struct ifbond ifbond = {};
    struct ifslave ifslave = {};

    // check for lacp
    strlcpy(ifr->ifr_name, master->name, IFNAMSIZ);
    ifr->ifr_data = (char *)&ifbond;

    if (ioctl(sockfd, SIOCBONDINFOQUERY, ifr) >= 0) {
#if defined(BOND_MODE_8023AD)
	if (ifbond.bond_mode == BOND_MODE_8023AD)
	    master->bonding_mode = NETIF_BONDING_LACP;
#endif
	if (ifbond.bond_mode == BOND_MODE_ACTIVEBACKUP)
	    master->bonding_mode = NETIF_BONDING_FAILOVER;
    }

    if (master->bonding_mode == NETIF_BONDING_LACP)
	my_log(INFO, "lacp enabled on %s", master->name);


    // handle slaves

    // check for a sensible num_slaves entry
    if (ifbond.num_slaves <= 0)
	return;

    for (int i = 0; i < ifbond.num_slaves; i++) {
	ifslave.slave_id = i;
	ifr->ifr_data = (char *)&ifslave;

	if (ioctl(sockfd, SIOCBONDSLAVEINFOQUERY, ifr) >= 0) {
	    subif = netif_byname(netifs, ifslave.slave_name);

	    // XXX: multi-level bonds not supported
	    if ((subif != NULL) && (subif->type < NETIF_PARENT)) {
		my_log(INFO, "found slave %s", subif->name);
		subif->slave = NETIF_SLAVE_ACTIVE;
		if (ifslave.state == BOND_STATE_BACKUP)
		    subif->slave = NETIF_SLAVE_BACKUP;
		subif->lacp_index = i;
		subif->master = master;
		csubif->subif = subif;
		csubif = subif;
	    }
	}
    }
#endif /* HAVE_LINUX_IF_BONDING_H */
}


// handle bridge interfaces
static void netif_bridge(int sockfd, struct nhead *netifs, struct netif *master,
		  struct ifreq *ifr) {

#if defined(HAVE_LINUX_IF_BRIDGE_H)
    struct netif *subif = NULL, *csubif = master;

    int ifindex[BRIDGE_MAX_PORTS] = {};
    unsigned long args[4] = { BRCTL_GET_PORT_LIST,
		    (unsigned long)ifindex, BRIDGE_MAX_PORTS, 0 };

    // handle slaves
    strlcpy(ifr->ifr_name, master->name, IFNAMSIZ);
    ifr->ifr_data = (char *)&args;

    if (ioctl(sockfd, SIOCDEVPRIVATE, ifr) < 0) {
	my_loge(CRIT, "bridge ioctl failed on interface %s", master->name);
	return;
    }

    for (int i = 0; i < BRIDGE_MAX_PORTS; i++) {
	subif = netif_byindex(netifs, ifindex[i]);

	// XXX: multi-level bridges not supported
	if ((subif != NULL) && (subif->type < NETIF_PARENT)) {
	    my_log(INFO, "found slave %s", subif->name);
	    subif->slave = NETIF_SLAVE_ACTIVE;
	    subif->master = master;
	    csubif->subif = subif;
	    csubif = subif;
	}
    }
#endif /* HAVE_LINUX_IF_BRIDGE_H */
}


// handle vlan interfaces
static void netif_vlan(int sockfd, struct nhead *netifs, struct netif *vlan,
		  struct ifreq *ifr) {

#ifdef HAVE_LINUX_IF_VLAN_H
#if HAVE_DECL_GET_VLAN_REALDEV_NAME_CMD && \
    HAVE_DECL_GET_VLAN_VID_CMD
    struct vlan_ioctl_args if_request = {};

    if_request.cmd = GET_VLAN_REALDEV_NAME_CMD;
    strlcpy(if_request.device1, vlan->name, sizeof(if_request.device1));

    if (ioctl(sockfd, SIOCSIFVLAN, &if_request) < 0)
	return;

    struct netif *netif = netif_byname(netifs, if_request.u.device2);
    if (netif == NULL)
	return;
    vlan->vlan_parent = netif->index;

    if_request.cmd = GET_VLAN_VID_CMD;
    if (ioctl(sockfd, SIOCSIFVLAN, &if_request) >= 0)
	vlan->vlan_id = if_request.u.VID;

    return;
#endif
#endif /* HAVE_LINUX_IF_VLAN_H */
}



// perform media detection on physical interfaces
static void netif_physical(int sockfd, struct netif *netif) {

#if HAVE_LINUX_ETHTOOL_H
    struct ethtool_cmd ecmd;
    struct master_req mreq = {};

    int ecmd_to_lldp_pmd[][2] = {
	{ADVERTISED_10baseT_Half,   LLDP_MAU_PMD_10BASE_T},
	{ADVERTISED_10baseT_Full,   LLDP_MAU_PMD_10BASE_T_FD},
	{ADVERTISED_100baseT_Half,  LLDP_MAU_PMD_100BASE_TX},
	{ADVERTISED_100baseT_Full,  LLDP_MAU_PMD_100BASE_TX_FD},
	{ADVERTISED_1000baseT_Half, LLDP_MAU_PMD_1000BASE_T},
	{ADVERTISED_1000baseT_Full, LLDP_MAU_PMD_1000BASE_T_FD},
#ifdef ADVERTISED_10000baseT_Full
	{ADVERTISED_10000baseT_Full, LLDP_MAU_PMD_OTHER},
#endif
#ifdef ADVERTISED_Pause
	{ADVERTISED_Pause,	    LLDP_MAU_PMD_FDXPAUSE},
#endif
#ifdef ADVERTISED_Asym_Pause
	{ADVERTISED_Asym_Pause,	    LLDP_MAU_PMD_FDXAPAUSE},
#endif
#ifdef ADVERTISED_2500baseX_Full
	{ADVERTISED_2500baseX_Full, LLDP_MAU_PMD_OTHER},
#endif
	{0, 0}
    };

    mreq.op = MASTER_ETHTOOL_GSET;
    mreq.index = netif->index;
    mreq.len = sizeof(ecmd);

    if (my_mreq(&mreq) != sizeof(ecmd))
	return;

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
	case PORT_MII:
	    // fallthrough if we're advertising twisted-pair
	    if (!(ecmd.advertising & ADVERTISED_TP))
		break;
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
#ifdef SPEED_10000
	    else if (ecmd.speed == SPEED_10000)
		netif->mau = LLDP_MAU_TYPE_10GBASE_T;
#endif
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
#ifdef SPEED_10000
	    else if (ecmd.speed == SPEED_10000)
		netif->mau = LLDP_MAU_TYPE_10GBASE_X;
#endif
	    break;
	case PORT_BNC:
	    if (ecmd.speed == SPEED_10)
		netif->mau = LLDP_MAU_TYPE_10BASE_2; 
	    break;
	case PORT_AUI:
	    netif->mau = LLDP_MAU_TYPE_AUI;
	    break;
#ifdef PORT_DA
	case PORT_DA:
	    if (ecmd.speed == SPEED_10000)
		netif->mau = LLDP_MAU_TYPE_10GBASE_CX4;
	    break;
#endif
    }
#endif /* HAVE_LINUX_ETHTOOL_H */
}

