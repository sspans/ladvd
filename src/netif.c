/*
 *  $Id$
 */

#include "common.h"
#include "util.h"
#include "proto/lldp.h"

#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ifaddrs.h>
#include <dirent.h>
#include <unistd.h>

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
#ifndef SYSFS_BRIDGE_PORT_SUBDIR
#define SYSFS_BRIDGE_PORT_SUBDIR "brif"
#endif
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

#ifdef HAVE_SYSFS
#define SYSFS_CLASS_NET		"/sys/class/net"
#define SYSFS_PATH_MAX		256
#endif

#ifdef HAVE_PROC_SYS_NET
#define PROCFS_FORWARD_IPV4	"/proc/sys/net/ipv4/conf/all/forwarding"
#define PROCFS_FORWARD_IPV6	"/proc/sys/net/ipv6/conf/all/forwarding"
#endif

#ifdef AF_PACKET
#define NETIF_AF    AF_PACKET
#elif defined(AF_LINK)
#define NETIF_AF    AF_LINK
#endif

int netif_wireless(int, struct ifaddrs *ifaddr, struct ifreq *);
int netif_type(int, struct ifaddrs *ifaddr, struct ifreq *);
void netif_bond(int, struct nhead *, struct netif *, struct ifreq *);
void netif_bridge(int, struct nhead *, struct netif *, struct ifreq *);
void netif_addrs(struct ifaddrs *, struct nhead *, struct sysinfo *);
void netif_forwarding(struct sysinfo *);


// create netifs for a list of interfaces
uint16_t netif_fetch(int ifc, char *ifl[], struct sysinfo *sysinfo,
		    struct nhead *netifs) {

    int sockfd, af = AF_INET;
    struct ifaddrs *ifaddrs, *ifaddr = NULL;
    struct ifreq ifr;
    int j, count = 0;
    int type, enabled;
    uint32_t index;

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
	my_log(CRIT, "address detection failed: %s", strerror(errno));
	(void) close(sockfd);
	return(0);
    }

    // zero
    count = 0;

    // default to CAP_HOST
    sysinfo->cap = CAP_HOST;
    sysinfo->cap_active = CAP_HOST;
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

	// reset type
	type = 0;
	enabled = 0;

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
#endif

	// check for interfaces that are down
	if (ioctl(sockfd, SIOCGIFFLAGS, (caddr_t)&ifr) >= 0)
	    enabled = (ifr.ifr_flags & IFF_UP) ? 1 : 0;

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
	type = netif_type(sockfd, ifaddr, &ifr);

	if (type == NETIF_REGULAR) { 
	    my_log(INFO, "found ethernet interface %s", ifaddr->ifa_name);
	    sysinfo->physif_count++;
	} else if (type == NETIF_BONDING) {
	    my_log(INFO, "found bond interface %s", ifaddr->ifa_name);
	} else if (type == NETIF_BRIDGE) {
	    my_log(INFO, "found bridge interface %s", ifaddr->ifa_name);
	    sysinfo->cap |= CAP_BRIDGE; 
	    sysinfo->cap_active |= (enabled == 1) ? CAP_BRIDGE : 0;
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
#ifdef AF_PACKET
	index = saddrll.sll_ifindex;
#elif AF_LINK
	index = saddrdl.sdl_index;
#endif
	if ((netif = netif_byindex(netifs, index)) == NULL) {
	    netif = my_malloc(sizeof(struct netif));
	    memset(netif, 0, sizeof(struct netif));
	    TAILQ_INSERT_TAIL(netifs, netif, entries);
	} else {
	    // reset everything but protos and tailq_entry
	    uint16_t protos = netif->protos;
	    memset(netif, 0, offsetof(struct netif, entries));
	    netif->protos = protos;
	}

        // copy name, index and type
	netif->index = index;
	strlcpy(netif->name, ifaddr->ifa_name, sizeof(netif->name));
	netif->type = type;

#ifdef SIOCGIFDESCR
	ifr.ifr_data = (caddr_t)&netif->description;
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
	TAILQ_REMOVE(netifs, netif, entries);
	free(netif);
    }

    // add slave subif lists to each master
    TAILQ_FOREACH(netif, netifs, entries) {
	switch(netif->type) {
	    case NETIF_BONDING:
		my_log(INFO, "detecting %s settings", netif->name);
		netif_bond(sockfd, netifs, netif, &ifr);
		break;
	    case NETIF_BRIDGE:
		my_log(INFO, "detecting %s settings", netif->name);
		netif_bridge(sockfd, netifs, netif, &ifr);
		break;
	    default:
		break;
	}
    }

    // add addresses to netifs
    my_log(INFO, "fetching addresses for all interfaces");
    netif_addrs(ifaddrs, netifs, sysinfo);

    // check for forwarding
    my_log(INFO, "checking forwarding status");
    netif_forwarding(sysinfo);

    // use the first mac as chassis id
    if ((netif = TAILQ_FIRST(netifs)) != NULL)
	memcpy(&sysinfo->hwaddr, &netif->hwaddr, ETHER_ADDR_LEN);

    // validate detected interfaces
    if (ifc > 0) {
	count = 0;

	for (j=0; j < ifc; j++) {
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
    struct ifmediareq ifmr;
#endif /* HAVE_HAVE_NET_IF_MEDIA_H */

#ifdef HAVE_LINUX_WIRELESS_H
    struct iwreq iwreq;

    memset(&iwreq, 0, sizeof(iwreq));
    strlcpy(iwreq.ifr_name, ifaddr->ifa_name, sizeof(iwreq.ifr_name));

    return(ioctl(sockfd, SIOCGIWNAME, &iwreq));
#endif

#ifdef HAVE_NET80211_IEEE80211_IOCTL_H
#ifdef SIOCG80211
    struct ieee80211req ireq;
    u_int8_t i_data[32];

    memset(&ireq, 0, sizeof(ireq));
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
    memset(&ifmr, 0, sizeof(ifmr));
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
int netif_type(int sockfd, struct ifaddrs *ifaddr, struct ifreq *ifr) {

#ifdef HAVE_SYSFS
    char path[SYSFS_PATH_MAX];
    struct stat sb;
#endif

#if HAVE_LINUX_ETHTOOL_H
    struct ethtool_drvinfo drvinfo;
    memset(&drvinfo, 0, sizeof(drvinfo));
#endif

#ifdef HAVE_SYSFS
    if (snprintf(path, SYSFS_PATH_MAX,
	    SYSFS_CLASS_NET "/%s/device", ifaddr->ifa_name) > 0) {

	// accept physical devices via sysfs
	if (stat(path, &sb) == 0)
	    return(NETIF_REGULAR);
    }
#endif

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
	// handle tun/tap
	} else if (strcmp(drvinfo.driver, "tun") == 0) {
	    return(NETIF_REGULAR);
	}

	// if we don't have sysfs, we'll accept interfaces
	// which support ethtool (aka wing it)
	if (stat(SYSFS_CLASS_NET, &sb) == -1)
	    return(NETIF_REGULAR);
    }

    // we don't want the rest
    return(NETIF_INVALID);
#endif /* HAVE_LINUX_ETHTOOL_H */

#ifdef AF_LINK
    struct if_data *if_data = ifaddr->ifa_data;

    if (if_data->ifi_type == IFT_ETHER) {

	// bonding
#ifdef HAVE_NET_IF_LAGG_H
	if (ioctl(sockfd, SIOCGLAGG, (caddr_t)ifr) >= 0)
	    return(NETIF_BONDING);
#elif HAVE_NET_IF_TRUNK_H
	if (ioctl(sockfd, SIOCGTRUNK, (caddr_t)ifr) == 0)
	    return(NETIF_BONDING);
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


// handle aggregated interfaces
void netif_bond(int sockfd, struct nhead *netifs, struct netif *master,
		struct ifreq *ifr) {

    struct netif *subif = NULL, *csubif = master;
    int i;

#ifdef HAVE_SYSFS
    // handle linux bonding interfaces
    char path[SYSFS_PATH_MAX];
    FILE *file;
    char line[1024];
    char *slave, *nslave;
#endif /* HAVE_SYSFS */

#ifdef HAVE_LINUX_IF_BONDING_H
    struct ifbond ifbond;
    struct ifslave ifslave;
#elif HAVE_NET_IF_LAGG_H
    struct lagg_reqport rpbuf[LAGG_MAX_PORTS];
    struct lagg_reqall ra;
#elif HAVE_NET_IF_TRUNK_H
    struct trunk_reqport rpbuf[TRUNK_MAX_PORTS];
    struct trunk_reqall ra;
#endif

    // check for lacp

#ifdef HAVE_SYSFS
    // via sysfs
    if (snprintf(path, SYSFS_PATH_MAX, "%s/%s/bonding/mode", 
		SYSFS_CLASS_NET, master->name) > 0) {
	if ((file = fopen(path, "r")) != NULL) {
	    if (fscanf(file, "802.3ad") != EOF)
		master->lacp = 1;
	    (void) fclose(file);
	}
    }
#endif /* HAVE_SYSFS */

#if defined(HAVE_LINUX_IF_BONDING_H) && defined(BOND_MODE_8023AD)
    strlcpy(ifr->ifr_name, master->name, IFNAMSIZ);
    memset(&ifbond, 0, sizeof(ifbond));
    ifr->ifr_data = (char *)&ifbond;

    if (ioctl(sockfd, SIOCBONDINFOQUERY, ifr) >= 0) {
	if (ifbond.bond_mode == BOND_MODE_8023AD)
	    master->lacp = 1;
    }
#endif /* HAVE_LINUX_IF_BONDING_H && BOND_MODE_8023AD */

    if (master->lacp == 1)
	my_log(INFO, "lacp enabled on %s", master->name);


    // handle slaves

#ifdef HAVE_SYSFS
    // via sysfs
    if ((snprintf(path, SYSFS_PATH_MAX,
	    SYSFS_CLASS_NET "/%s/bonding/slaves", master->name) > 0) &&
	(read_line(path, line, sizeof(line)) != -1)) {

	slave = line;
	i = 0;
	while (strlen(slave) > 0) {
	    nslave = strstr(slave, " ");
	    if (nslave != NULL)
		*nslave = '\0';

	    subif = netif_byname(netifs, slave);
	    if (subif != NULL) {
		my_log(INFO, "found slave %s", subif->name);
		subif->slave = 1;
		subif->master = master;
		subif->lacp_index = i++;
		csubif->subif = subif;
		csubif = subif;
	    }

	    if (nslave != NULL) {
		nslave++;
		slave = nslave;
	    } else {
		break;
	    }
	}

	return;
    }
#endif /* HAVE_SYSFS */

#ifdef HAVE_LINUX_IF_BONDING_H
    // or ioctl

    // check for a sensible num_slaves entry
    if (ifbond.num_slaves <= 0)
	return;

    for (i = 0; i < ifbond.num_slaves; i++) {
	ifslave.slave_id = i;
	ifr->ifr_data = (char *)&ifslave;

	if (ioctl(sockfd, SIOCBONDSLAVEINFOQUERY, ifr) >= 0) {
	    subif = netif_byname(netifs, ifslave.slave_name);

	    if (subif != NULL) {
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
    memset(&ra, 0, sizeof(ra));

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
    
    for (i = 0; i < ra.ra_ports; i++) {
	subif = netif_byname(netifs, rpbuf[i].rp_portname);

	if (subif != NULL) {
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
    struct if_bond_req ibr;
    struct if_bond_status *ibs;
    struct if_bond_status_req *ibsr;

    memset(&ibr, 0, sizeof(ibr));
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

	for (i = 0; i < ibsr->ibsr_total; i++) {
	    subif = netif_byname(netifs, ibs->ibs_if_name);

	    if (subif != NULL) {
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

#if defined(HAVE_SYSFS) || defined(HAVE_LINUX_IF_BRIDGE_H) || \
    defined(HAVE_NET_IF_BRIDGEVAR_H) || defined(HAVE_NET_IF_BRIDGE_H)
    struct netif *subif = NULL, *csubif = master;
    int i;
#endif

#ifdef HAVE_SYSFS
    // handle linux bridge interfaces
    char path[SYSFS_PATH_MAX];
    DIR  *dir;
    struct dirent *dirent;
#endif /* HAVE_SYSFS */

#ifdef HAVE_LINUX_IF_BRIDGE_H
    int ifindex[BRIDGE_MAX_PORTS];
    unsigned long args[4] = { BRCTL_GET_PORT_LIST,
		    (unsigned long)ifindex, BRIDGE_MAX_PORTS, 0 };
#endif /* HAVE_LINUX_IF_BRIDGE_H */


    // handle slaves
 
#if HAVE_SYSFS
    // via sysfs
    sprintf(path, SYSFS_CLASS_NET "/%s/" SYSFS_BRIDGE_PORT_SUBDIR, master->name); 
    if ((dir = opendir(path)) != NULL) {

	while ((dirent = readdir(dir)) != NULL) {
	    subif = netif_byname(netifs, dirent->d_name);

	    if (subif != NULL) {
		my_log(INFO, "found slave %s", subif->name);
		subif->slave = 1;
		subif->master = master;
		csubif->subif = subif;
		csubif = subif;
	    }
	}

	closedir(dir);
	return;
    }
#endif /* HAVE_SYSFS */

#ifdef HAVE_LINUX_IF_BRIDGE_H
    // or ioctl
    memset(ifindex, 0, sizeof(ifindex));
    strlcpy(ifr->ifr_name, master->name, IFNAMSIZ);
    ifr->ifr_data = (char *)&args;

    if (ioctl(sockfd, SIOCDEVPRIVATE, ifr) < 0) {
	my_log(CRIT, "bridge ioctl failed on interface %s: %s",
	       master->name, strerror(errno));
	return;
    }

    for (i = 0; i < BRIDGE_MAX_PORTS; i++) {
	subif = netif_byindex(netifs, ifindex[i]);

	if (subif != NULL) {
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
    struct ifdrv ifd;

    memset(&ifd, 0, sizeof(ifd));

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

    for (i = 0; i < bifc.ifbic_len / sizeof(*req); i++) {
	req = bifc.ifbic_req + i;

	subif = netif_byname(netifs, req->ifbr_ifsname);
	if (subif != NULL) {
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


// detect forwarding capability
void netif_forwarding(struct sysinfo *sysinfo) {

#ifdef HAVE_PROC_SYS_NET
    char line[256];
#endif

#ifdef CTL_NET
    int mib[4], n;
    size_t len;

    len = sizeof(n);

    mib[0] = CTL_NET;
#endif

#ifdef HAVE_PROC_SYS_NET
    if (read_line(PROCFS_FORWARD_IPV4, line, sizeof(line)) != -1) {
	sysinfo->cap |= CAP_ROUTER; 

        if (atoi(line) == 1) {
	    sysinfo->cap_active |= CAP_ROUTER; 
	    return;
	}
    }

    if (read_line(PROCFS_FORWARD_IPV6, line, sizeof(line)) != -1) {
	sysinfo->cap |= CAP_ROUTER; 

        if (atoi(line) == 1) {
	    sysinfo->cap_active |= CAP_ROUTER; 
	    return;
	}
    }
#endif

#ifdef CTL_NET
    mib[1] = PF_INET;
    mib[2] = IPPROTO_IP;
    mib[3] = IPCTL_FORWARDING;

    if (sysctl(mib, 4, &n, &len, NULL, 0) != -1) {
	sysinfo->cap |= CAP_ROUTER; 
	if (n == 1) {
	    sysinfo->cap_active |= CAP_ROUTER; 
	    return;
	}
    }

    mib[1] = PF_INET6;
    mib[2] = IPPROTO_IPV6;
    mib[3] = IPV6CTL_FORWARDING;

    if (sysctl(mib, 4, &n, &len, NULL, 0) != -1) {
	sysinfo->cap |= CAP_ROUTER; 
	if (n == 1) {
	    sysinfo->cap_active |= CAP_ROUTER; 
	    return;
	}
    }
#endif
}


// perform media detection on physical interfaces
int netif_media(int cfd, struct netif *netif) {
    int sockfd, af = AF_INET;
    struct ifreq ifr;

#if HAVE_LINUX_ETHTOOL_H
    struct ethtool_cmd ecmd;
    struct master_msg mreq;
#endif /* HAVE_LINUX_ETHTOOL_H */

#if HAVE_NET_IF_MEDIA_H
    struct ifmediareq ifmr;
    int *media_list, i;
#endif /* HAVE_HAVE_NET_IF_MEDIA_H */

    sockfd = my_socket(af, SOCK_DGRAM, 0);

    netif->duplex = -1;
    netif->autoneg_supported = -1;
    netif->autoneg_enabled = -1;
    netif->mau = 0;

    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, netif->name, sizeof(ifr.ifr_name));

    // interface mtu
    if (ioctl(sockfd, SIOCGIFMTU, (caddr_t)&ifr) >= 0)
	netif->mtu = ifr.ifr_mtu;
    else
	my_log(INFO, "mtu detection failed on interface %s", netif->name);

#if HAVE_LINUX_ETHTOOL_H
    memset(&mreq, 0, sizeof(mreq));
    mreq.index = netif->index;
    strlcpy(mreq.name, netif->name, IFNAMSIZ);
    mreq.cmd = MASTER_ETHTOOL;
    mreq.len = sizeof(ecmd);

    if (my_msend(cfd, &mreq) == sizeof(ecmd)) {

	// copy ecmd struct
	memcpy(&ecmd, mreq.msg, sizeof(ecmd));

	// duplex
	netif->duplex = (ecmd.duplex == DUPLEX_FULL) ? 1 : 0;

	// autoneg
	if (ecmd.supported & SUPPORTED_Autoneg) {
	    my_log(INFO, "autoneg supported on %s", netif->name);
	    netif->autoneg_supported = 1;
	    netif->autoneg_enabled = (ecmd.autoneg == AUTONEG_ENABLE) ? 1 : 0;
	} else {
	    my_log(INFO, "autoneg not supported on %s", netif->name);
	    netif->autoneg_supported = 0;
	}	
    } else {
	my_log(INFO, "ethtool ioctl failed on interface %s", netif->name);
    }
#endif /* HAVE_LINUX_ETHTOOL_H */

#if HAVE_NET_IF_MEDIA_H
    memset(&ifmr, 0, sizeof(ifmr));
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

    // autoneg support
    for (i = 0; i < ifmr.ifm_count; i++) {
	if (IFM_SUBTYPE(ifmr.ifm_ulist[i]) == IFM_AUTO) {
	    my_log(INFO, "autoneg supported on %s", netif->name);
	    netif->autoneg_supported = 1;
	    break;
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
    switch (IFM_SUBTYPE(ifmr.ifm_active)) {
	case IFM_10_T:
	    if (netif->duplex == 1)
		netif->mau = LLDP_MAU_TYPE_10BASE_T_FD;
	    else
		netif->mau = LLDP_MAU_TYPE_10BASE_T_HD;
	    break;
	case IFM_10_2:
	    netif->mau = LLDP_MAU_TYPE_10BASE_2;
	    break;
	case IFM_10_5:
	    netif->mau = LLDP_MAU_TYPE_10BASE_5;
	    break;
	case IFM_100_TX:
	    if (netif->duplex == 1)
		netif->mau = LLDP_MAU_TYPE_100BASE_TX_FD;
	    else
		netif->mau = LLDP_MAU_TYPE_100BASE_TX_HD;
	    break;
	case IFM_100_FX:
	    if (netif->duplex == 1)
		netif->mau = LLDP_MAU_TYPE_100BASE_FX_FD;
	    else
		netif->mau = LLDP_MAU_TYPE_100BASE_FX_HD;
	    break;
	case IFM_100_T4:
	    netif->mau = LLDP_MAU_TYPE_100BASE_T4;
	    break;
	case IFM_100_T2:
	    if (netif->duplex == 1)
		netif->mau = LLDP_MAU_TYPE_100BASE_T2_FD;
	    else
		netif->mau = LLDP_MAU_TYPE_100BASE_T2_HD;
	    break;
	case IFM_1000_SX:
	    if (netif->duplex == 1)
		netif->mau = LLDP_MAU_TYPE_1000BASE_SX_FD;
	    else
		netif->mau = LLDP_MAU_TYPE_1000BASE_SX_HD;
	    break;
	case IFM_10_FL: 
	    if (netif->duplex == 1)
		netif->mau = LLDP_MAU_TYPE_10BASE_FL_FD;
	    else
		netif->mau = LLDP_MAU_TYPE_10BASE_FL_HD;
	    break;
	case IFM_1000_LX:
	    if (netif->duplex == 1)
		netif->mau = LLDP_MAU_TYPE_1000BASE_LX_FD;
	    else
		netif->mau = LLDP_MAU_TYPE_1000BASE_LX_HD;
	    break;
	case IFM_1000_CX:
	    if (netif->duplex == 1)
		netif->mau = LLDP_MAU_TYPE_1000BASE_CX_FD;
	    else
		netif->mau = LLDP_MAU_TYPE_1000BASE_CX_HD;
	    break;
	case IFM_1000_T:
	    if (netif->duplex == 1)
		netif->mau = LLDP_MAU_TYPE_1000BASE_T_FD;
	    else
		netif->mau = LLDP_MAU_TYPE_1000BASE_T_HD;
	    break;
	case IFM_10G_LR:
	    netif->mau = LLDP_MAU_TYPE_10GBASE_LR;
	    break;
	case IFM_10G_SR:
	    netif->mau = LLDP_MAU_TYPE_10GBASE_SR;
	    break;
    }

    free(media_list);
#endif /* HAVE_NET_IF_MEDIA_H */

    // cleanup
    close(sockfd);

    return(EXIT_SUCCESS);
}

