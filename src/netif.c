/*
 *  $Id$
 */

#include "main.h"
#include "util.h"
#include "lldp.h"

#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
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


#if HAVE_LINUX_IF_BRIDGE_H
#include <linux/if_bridge.h>
#endif /* HAVE_LINUX_IF_BRIDGE_H */

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

#define SYSFS_VIRTUAL "/sys/devices/virtual/net"
#define SYSFS_PATH_MAX  256


// handle aggregated interfaces
void netif_bond(struct session *sessions, struct session *session) {

    struct session *subif = NULL, *csubif = session;
    int i;

#ifdef HAVE_LINUX_IF_BONDING_H
    // handle linux bonding interfaces
    char path[SYSFS_PATH_MAX];
    FILE *fp;
    char line[1024];
    char *slave, *nslave;

    // check for lacp
    sprintf(path, "%s/%s/bonding/mode", SYSFS_VIRTUAL, session->if_name); 
    if ((fp = fopen(path, "r")) != NULL) {
	if (fscanf(fp, "802.3ad") != EOF)
	    session->if_lacp = 1;
	fclose(fp);
    }

    // handle slaves
    sprintf(path, "%s/%s/bonding/slaves", SYSFS_VIRTUAL, session->if_name); 
    if ((fp = fopen(path, "r")) != NULL) {
	if (fgets(line, sizeof(line), fp) != NULL) {
	    // remove newline
	    *strchr(line, '\n') = '\0';

	    slave = line;
	    i = 0;
	    while (strlen(slave) > 0) {
		nslave = strstr(line, " ");
		if (nslave != NULL)
		    *nslave = '\0';

		subif = session_byname(sessions, slave);
		if (subif != NULL) {
		    my_log(3, "found slave %s", subif->if_name);
		    subif->if_slave = 1;
		    subif->if_lacp_ifindex = i++;
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
	};

	fclose(fp);
    }

    return;
#endif /* HAVE_LINUX_IF_BONDING_H */

#if defined(HAVE_NET_IF_LAGG_H) || defined(HAVE_NET_IF_TRUNK_H)
    int sockfd, af = AF_INET;

#ifdef HAVE_NET_IF_LAGG_H
    struct lagg_reqport rpbuf[LAGG_MAX_PORTS];
    struct lagg_reqall ra;
#elif HAVE_NET_IF_TRUNK_H
    struct trunk_reqport rpbuf[TRUNK_MAX_PORTS];
    struct trunk_reqall ra;
#endif

    sockfd = my_socket(af, SOCK_DGRAM, 0);

    bzero(&ra, sizeof(ra));

    strncpy(ra.ra_ifname, session->if_name, sizeof(ra.ra_ifname));
    ra.ra_size = sizeof(rpbuf);
    ra.ra_port = rpbuf;

#ifdef HAVE_NET_IF_LAGG_H
    my_ioctl(sockfd, SIOCGLAGG, &ra);

    if (ra.ra_proto == LAGG_PROTO_LACP)
	session->if_lacp = 1;
#elif HAVE_NET_IF_TRUNK_H
    my_ioctl(sockfd, SIOCGTRUNK, &ra);

    
    if ((ra.ra_proto == TRUNK_PROTO_ROUNDROBIN) ||
	(ra.ra_proto == TRUNK_PROTO_LOADBALANCE))
	session->if_lacp = 1;
#endif
    
    for (i = 0; i < ra.ra_ports; i++) {
	subif = session_byname(sessions, rpbuf[i].rp_portname);

	if (subif != NULL) {
	    my_log(3, "found slave %s", subif->if_name);
	    subif->if_slave = 1;
	    subif->if_lacp_ifindex = i++;
	    csubif->subif = subif;
	    csubif = subif;
	}
    }

    return;
#endif /* HAVE_NET_IF_LAGG_H */

}


// handle bridge interfaces
void netif_bridge(struct session *sessions, struct session *session) {

    struct session *subif = NULL, *csubif = session;

#if HAVE_LINUX_IF_BRIDGE_H 
    // handle linux bridge interfaces
    char path[SYSFS_PATH_MAX];
    DIR  *dir;
    struct dirent *dirent;

    // handle slaves
    sprintf(path, "%s/%s/%s",
		SYSFS_VIRTUAL, session->if_name, SYSFS_BRIDGE_PORT_SUBDIR); 

    if ((dir = opendir(path)) == NULL) {
	my_log(0, "reading bridge %s subdir %s failed: %s",
	    session->if_name, path, strerror(errno));
	return;
    }

    while ((dirent = readdir(dir)) != NULL) {
	subif = session_byname(sessions, dirent->d_name);
	if (subif != NULL) {
	    subif->if_slave = 1;
	    csubif->subif = subif;
	    csubif = subif;
	}
    }

    closedir(dir);
    return;
#endif /* HAVE_LINUX_IF_BRIDGE_H */

#if defined(HAVE_NET_IF_BRIDGEVAR_H) || defined(HAVE_NET_IF_BRIDGE_H)
    int sockfd, af = AF_INET;
    struct ifbifconf bifc;
    struct ifbreq *req;
    char *inbuf = NULL, *ninbuf;
    int i, len = 8192;

#ifdef HAVE_NET_IF_BRIDGEVAR_H
    struct ifdrv ifd;

    bzero(&ifd, sizeof(ifd));

    strncpy(ifd.ifd_name, session->if_name, sizeof(ifd.ifd_name));
    ifd.ifd_cmd = BRDGGIFS;
    ifd.ifd_len = sizeof(bifc);
    ifd.ifd_data = &bifc;
#endif /* HAVE_NET_IF_BRIDGEVAR_H */

    sockfd = my_socket(af, SOCK_DGRAM, 0);

    for (;;) {
	ninbuf = realloc(inbuf, len);

	if (ninbuf == NULL) {
	    my_log(1, "unable to allocate interface buffer");
	    return;
	}

	bifc.ifbic_len = len;
	bifc.ifbic_buf = inbuf = ninbuf;

#ifdef HAVE_NET_IF_BRIDGEVAR_H
	my_ioctl(sockfd, SIOCGDRVSPEC, &ifd);
#elif HAVE_NET_IF_BRIDGE_H
	my_ioctl(sockfd, SIOCBRDGIFS, &bifc);
#endif
	if ((bifc.ifbic_len + sizeof(*req)) < len)
	    break;
	len *= 2;
    }

    for (i = 0; i < bifc.ifbic_len / sizeof(*req); i++) {
	req = bifc.ifbic_req + i;

	subif = session_byname(sessions, req->ifbr_ifsname);
	if (subif != NULL) {
	    subif->if_slave = 1;
	    csubif->subif = subif;
	    csubif = subif;
	}
    }

    return;
#endif

}


// create sessions for a list of interfaces
struct session * netif_fetch(int ifc, char *ifl[], struct sysinfo *sysinfo) {
    int sockfd, af = AF_INET;
    struct ifaddrs *ifaddrs, *ifaddr;
    struct ifreq ifr;
    int j, count = 0;
    int if_master;

#ifdef AF_PACKET
    struct sockaddr_ll saddrll;
#endif
#ifdef AF_LINK
    struct sockaddr_dl saddrdl;
    struct if_data *if_data;
#endif

#ifdef HAVE_LINUX_ETHTOOL_H
    char path[SYSFS_PATH_MAX];
    struct stat sb;

    struct ethtool_drvinfo drvinfo;
#endif /* HAVE_LINUX_ETHTOOL_H */

#ifdef HAVE_NET80211_IEEE80211_IOCTL_H
#ifdef SIOCG80211
    struct ieee80211req ireq;
    u_int8_t i_data[32];
#elif defined(SIOCG80211NWID)
    struct ieee80211_nwid nwid;
#endif
#endif

    // sessions
    struct session *sessions = NULL, *session_prev = NULL, *session;

    if (getifaddrs(&ifaddrs) < 0) {
	my_log(0, "address detection failed: %s", strerror(errno));
	exit(EXIT_FAILURE);
    }

    sockfd = my_socket(af, SOCK_DGRAM, 0);

    for (ifaddr = ifaddrs; ifaddr != NULL; ifaddr = ifaddr->ifa_next) {

	// only handle datalink addresses
#ifdef AF_PACKET
	if (ifaddr->ifa_addr->sa_family != AF_PACKET)
	    continue;
#endif
#ifdef AF_LINK
	if (ifaddr->ifa_addr->sa_family != AF_LINK) 
	    continue;
#endif

	// reset if_master
	if_master = 0;

	// TODO: be clever about subifs
	// skip unlisted interfaces if needed
	if (ifc > 0) {

	    for (j=0; j < ifc; j++) {
		if (strcmp(ifaddr->ifa_name, ifl[j]) == 0) {
		    break;
		}
	    }
	    
	    // skip if no match is found
	    if (j >= ifc)
		continue;
	}

	// prepare ifr struct
	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, ifaddr->ifa_name, IFNAMSIZ);


	// skip interfaces that are down
	my_ioctl(sockfd, SIOCGIFFLAGS, (caddr_t)&ifr);
	if ((ifr.ifr_flags & IFF_UP) == 0) {
	    my_log(3, "skipping interface %s", ifaddr->ifa_name);
	    continue;
	}

	// skip non-ethernet interfaces
#ifdef AF_PACKET
	bcopy(ifaddr->ifa_addr, &saddrll, sizeof(saddrll));
	if (saddrll.sll_hatype != ARPHRD_ETHER) {
	    my_log(3, "skipping interface %s", ifaddr->ifa_name);
	    continue;
	}
#endif
#ifdef AF_LINK
	bcopy(ifaddr->ifa_addr, &saddrdl, sizeof(saddrdl));
	if (saddrdl.sdl_type != IFT_ETHER) {
	    my_log(3, "skipping interface %s", ifaddr->ifa_name);
	    continue;
	}
#endif


	// detect virtual network interfaces
#if HAVE_LINUX_ETHTOOL_H
	sprintf(path, "%s/%s", SYSFS_VIRTUAL, ifaddr->ifa_name); 

	if (stat(path, &sb) == 0) {

	    // use ethtool to detect various drivers
	    drvinfo.cmd = ETHTOOL_GDRVINFO;
	    ifr.ifr_data = (caddr_t)&drvinfo;

	    if (ioctl(sockfd, SIOCETHTOOL, &ifr) >= 0) {
		// handle bonding / bridge
		if (strcmp(drvinfo.driver, "bonding") == 0) {
		    my_log(2, "found bond interface %s", ifaddr->ifa_name);
		    if_master = MASTER_BONDING;
		    goto session;
		} else if (strcmp(drvinfo.driver, "bridge") == 0) {
		    my_log(2, "found bridge interface %s", ifaddr->ifa_name);
		    if_master = MASTER_BRIDGE;
		    goto session;
		// handle tun/tap
		} else if (strcmp(drvinfo.driver, "tun") == 0) {
		    my_log(2, "found tap interface %s", ifaddr->ifa_name);
		    goto session;
		}
	    }

	    // we don't want the rest
	    my_log(3, "skipping interface %s", ifaddr->ifa_name);
	    continue;
	}
#endif /* HAVE_LINUX_ETHTOOL_H */


	// detect virtual network interfaces
#ifdef AF_LINK
	if (ifaddr->ifa_addr->sa_family == AF_LINK) {
	    if_data = ifaddr->ifa_data;

	    if (if_data->ifi_type == IFT_ETHER) {

#ifdef HAVE_NET80211_IEEE80211_IOCTL_H
		// skip wireless interfaces
#ifdef SIOCG80211
		bzero(&ireq, sizeof(ireq));
		strncpy(ireq.i_name, ifaddr->ifa_name, sizeof(ireq.i_name));
		ireq.i_data = &i_data;

		ireq.i_type = IEEE80211_IOC_SSID;
		ireq.i_val = -1;

		if (ioctl(sockfd, SIOCG80211, &ireq) == 0) {
		    my_log(3, "skipping wireless interface %s",
			      ifaddr->ifa_name);
		    continue;
		}
#elif defined(SIOCG80211NWID)
		ifr.ifr_data = (caddr_t)&nwid;

		if (ioctl(sockfd, SIOCG80211NWID, (caddr_t)&ifr) == 0) {
		    my_log(3, "skipping wireless interface %s",
			      ifaddr->ifa_name);
		    continue;
		}
#endif
#endif /* HAVE_NET80211_IEEE80211_IOCTL_H */

		// bonding
#ifdef HAVE_NET_IF_LAGG_H
		if (ioctl(sockfd, SIOCGLAGG, (caddr_t)&ifr) == 0) {
		    my_log(2, "found bond interface %s", ifaddr->ifa_name);
		    if_master = MASTER_BONDING;
		    goto session;
		}
#elif HAVE_NET_IF_TRUNK_H
		if (ioctl(sockfd, SIOCGTRUNK, (caddr_t)&ifr) == 0) {
		    my_log(2, "found bond interface %s", ifaddr->ifa_name);
		    if_master = MASTER_BONDING;
		    goto session;
		}
#endif

		my_log(2, "found interface %s", ifaddr->ifa_name);
		goto session;

	    // bridge
	    } else if (if_data->ifi_type == IFT_BRIDGE) {
		my_log(2, "found bridge interface %s", ifaddr->ifa_name);
		if_master = MASTER_BRIDGE;
		goto session;
	    }

	    // we don't want the rest
	    my_log(3, "skipping interface %s", ifaddr->ifa_name);
	    continue;
	}
#endif /* AF_LINK */


    session:
	// create session
	session = my_malloc(sizeof(struct session));

        // copy name, index and master
#ifdef AF_PACKET
	session->if_index = saddrll.sll_ifindex;
#endif
#ifdef AF_LINK
	session->if_index = saddrdl.sdl_index;
#endif
	strncpy(session->if_name, ifaddr->ifa_name, IFNAMSIZ);
	session->if_master = if_master;

	// update linked list
	if (sessions == NULL)
	    sessions = session;
	else
	    session_prev->next = session;

	session_prev = session;

	// update counter
	count++;
    }

    // add slave subif lists to each master
    for (session = sessions; session != NULL; session = session->next) {

	switch(session->if_master) {
	    case MASTER_BONDING:
		netif_bond(sessions, session);
		break;
	    case MASTER_BRIDGE:
		netif_bridge(sessions, session);
		break;
	    default:
		break;
	}
    }

    // validate detected interfaces
    if (ifc != 0) {
	for (j=0; j < ifc; j++) {
	    session = session_byname(sessions, ifl[j]);
	    if (session == NULL)
		my_log(0, "interface %s is invalid", ifl[j]);
	}
	if (j != ifc)
	    exit(EXIT_FAILURE);
    } else if (count == 0) {
	my_log(0, "no valid interface found");
	exit(EXIT_FAILURE);
    }

    // cleanup
    freeifaddrs(ifaddrs);
    close(sockfd);

    return(sessions);
};


// update interface names for all sessions
int netif_names(struct session *sessions) {
    struct session *session;

    for (session = sessions; session != NULL; session = session->next) {
	if (if_indextoname(session->if_index, session->if_name) == NULL) {
	    my_log(0,"could not fetch interface name");
	    return(EXIT_FAILURE);
	}
    }

    return(EXIT_SUCCESS);
}


// perform address detection for all sessions
int netif_addrs(struct session *sessions) {
    struct ifaddrs *ifaddrs, *ifaddr;
    struct session *session;

    struct sockaddr_in saddr4;
    struct sockaddr_in6 saddr6;
#ifdef AF_PACKET
    struct sockaddr_ll saddrll;
#endif
#ifdef AF_LINK
    struct sockaddr_dl saddrdl;
#endif

    if (getifaddrs(&ifaddrs) < 0) {
	my_log(0, "address detection failed: %s", strerror(errno));
	return(EXIT_FAILURE);
    }

    for (ifaddr = ifaddrs; ifaddr != NULL; ifaddr = ifaddr->ifa_next) {
	// fetch the session for this ifaddr
	session = session_byname(sessions, ifaddr->ifa_name);
	if (session == NULL)
	    continue;

	if (ifaddr->ifa_addr->sa_family == AF_INET) {
	    if (session->ipaddr4 != 0)
		continue;

	    // alignment
	    bcopy(ifaddr->ifa_addr, &saddr4, sizeof(saddr4));

	    bcopy(&saddr4.sin_addr, &session->ipaddr4,
		  sizeof(saddr4.sin_addr));

	} else if (ifaddr->ifa_addr->sa_family == AF_INET6) {
	    if (!IN6_IS_ADDR_UNSPECIFIED((struct in6_addr *)session->ipaddr6))
		continue;

	    // alignment
	    bcopy(ifaddr->ifa_addr, &saddr6, sizeof(saddr6));

	    // skip link-local
	    if (IN6_IS_ADDR_LINKLOCAL(&saddr6.sin6_addr))
		continue;

	    bcopy(&saddr6.sin6_addr, &session->ipaddr6,
		  sizeof(saddr6.sin6_addr));
#ifdef AF_PACKET
	} else if (ifaddr->ifa_addr->sa_family == AF_PACKET) {

	    // alignment
	    bcopy(ifaddr->ifa_addr, &saddrll, sizeof(saddrll));

	    bcopy(&saddrll.sll_addr, &session->if_hwaddr, ETHER_ADDR_LEN);
#endif
#ifdef AF_LINK
	} else if (ifaddr->ifa_addr->sa_family == AF_LINK) {

	    // alignment
	    bcopy(ifaddr->ifa_addr, &saddrdl, sizeof(saddrdl));

	    bcopy(LLADDR(&saddrdl), &session->if_hwaddr, ETHER_ADDR_LEN);
#endif
	}
    }

    // cleanup
    freeifaddrs(ifaddrs);

    return(EXIT_SUCCESS);
}


// perform media detection on physical interfaces
int netif_media(struct session *session) {
    int sockfd, af = AF_INET;
    struct ifreq ifr;

#if HAVE_LINUX_ETHTOOL_H
    struct ethtool_cmd ecmd;
#endif /* HAVE_LINUX_ETHTOOL_H */

#if HAVE_NET_IF_MEDIA_H
    struct ifmediareq ifmr;
    int *media_list, i;
#endif /* HAVE_HAVE_NET_IF_MEDIA_H */

    sockfd = my_socket(af, SOCK_DGRAM, 0);

    session->duplex = -1;
    session->autoneg_supported = -1;
    session->autoneg_enabled = -1;
    session->mau = 0;

    bzero(&ifr, sizeof(ifr));
    strncpy(ifr.ifr_name, session->if_name, IFNAMSIZ);

    // interface mtu
    my_ioctl(sockfd, SIOCGIFMTU, (caddr_t)&ifr);
    session->mtu = ifr.ifr_mtu;

#if HAVE_LINUX_ETHTOOL_H
    ecmd.cmd = ETHTOOL_GSET;
    ifr.ifr_data = (caddr_t)&ecmd;

    if (ioctl(sockfd, SIOCETHTOOL, &ifr) >= 0) {
	// duplex
	session->duplex = (ecmd.duplex == DUPLEX_FULL) ? 1 : 0;

	// autoneg
	if (ecmd.supported & SUPPORTED_Autoneg) {
	    my_log(3, "autoneg supported on %s", session->if_name);
	    session->autoneg_supported = 1;
	    session->autoneg_enabled = (ecmd.autoneg == AUTONEG_ENABLE) ? 1 : 0;
	} else {
	    my_log(3, "autoneg not supported on %s", session->if_name);
	    session->autoneg_supported = 0;
	}	
    } else {
	my_log(3, "ethtool ioctl failed on interface %s", session->if_name);
    }
#endif /* HAVE_LINUX_ETHTOOL_H */

#if HAVE_NET_IF_MEDIA_H
    bzero(&ifmr, sizeof(ifmr));
    strncpy(ifmr.ifm_name, session->if_name, IFNAMSIZ);

    if (ioctl(sockfd, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0) {
	my_log(3, "media detection not supported on %s", session->if_name);
	return(EXIT_SUCCESS);
    }

    if (ifmr.ifm_count == 0) {
	my_log(0, "missing media types for interface %s", session->if_name);
	return(EXIT_FAILURE);
    }

    media_list = my_malloc(ifmr.ifm_count * sizeof(int));
    ifmr.ifm_ulist = media_list;

    if (ioctl(sockfd, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0) {
	my_log(0, "media detection failed for interface %s", session->if_name);
	return(EXIT_FAILURE);
    }

    if (IFM_TYPE(ifmr.ifm_current) != IFM_ETHER) {
	my_log(0, "non-ethernet interface %s found", session->if_name);
	return(EXIT_FAILURE);
    }

    if ((ifmr.ifm_status & IFM_ACTIVE) == 0) { 
	my_log(0, "no link detected on interface %s", session->if_name);
	return(EXIT_SUCCESS);
    }

    // autoneg support
    for (i = 0; i < ifmr.ifm_count; i++) {
	if (IFM_SUBTYPE(ifmr.ifm_ulist[i]) == IFM_AUTO) {
	    my_log(3, "autoneg supported on %s", session->if_name);
	    session->autoneg_supported = 1;
	    break;
	}
    }

    // autoneg enabled
    if (session->autoneg_supported == 1) {
	if (IFM_SUBTYPE(ifmr.ifm_current) == IFM_AUTO) {
	    my_log(3, "autoneg enabled on %s", session->if_name);
	    session->autoneg_enabled = 1;
	} else {
	    my_log(3, "autoneg disabled on interface %s", session->if_name);
	    session->autoneg_enabled = 0;
	}
    } else {
	my_log(3, "autoneg not supported on interface %s", session->if_name);
	session->autoneg_supported = 0;
    }

    // duplex
    if ((IFM_OPTIONS(ifmr.ifm_active) & IFM_FDX) != 0) {
	my_log(3, "full-duplex enabled on interface %s", session->if_name);
	session->duplex = 1;
    } else {
	my_log(3, "half-duplex enabled on interface %s", session->if_name);
	session->duplex = 0;
    }

    // mau
    switch (IFM_SUBTYPE(ifmr.ifm_active)) {
	case IFM_10_T:
	    if (session->duplex == 1)
		session->mau = LLDP_MAU_TYPE_10BASE_T_FD;
	    else
		session->mau = LLDP_MAU_TYPE_10BASE_T_HD;
	    break;
	case IFM_10_2:
	    session->mau = LLDP_MAU_TYPE_10BASE_2;
	    break;
	case IFM_10_5:
	    session->mau = LLDP_MAU_TYPE_10BASE_5;
	    break;
	case IFM_100_TX:
	    if (session->duplex == 1)
		session->mau = LLDP_MAU_TYPE_100BASE_TX_FD;
	    else
		session->mau = LLDP_MAU_TYPE_100BASE_TX_HD;
	    break;
	case IFM_100_FX:
	    if (session->duplex == 1)
		session->mau = LLDP_MAU_TYPE_100BASE_FX_FD;
	    else
		session->mau = LLDP_MAU_TYPE_100BASE_FX_HD;
	    break;
	case IFM_100_T4:
	    session->mau = LLDP_MAU_TYPE_100BASE_T4;
	    break;
	case IFM_100_T2:
	    if (session->duplex == 1)
		session->mau = LLDP_MAU_TYPE_100BASE_T2_FD;
	    else
		session->mau = LLDP_MAU_TYPE_100BASE_T2_HD;
	    break;
	case IFM_1000_SX:
	    if (session->duplex == 1)
		session->mau = LLDP_MAU_TYPE_1000BASE_SX_FD;
	    else
		session->mau = LLDP_MAU_TYPE_1000BASE_SX_HD;
	    break;
	case IFM_10_FL: 
	    if (session->duplex == 1)
		session->mau = LLDP_MAU_TYPE_10BASE_FL_FD;
	    else
		session->mau = LLDP_MAU_TYPE_10BASE_FL_HD;
	    break;
	case IFM_1000_LX:
	    if (session->duplex == 1)
		session->mau = LLDP_MAU_TYPE_1000BASE_LX_FD;
	    else
		session->mau = LLDP_MAU_TYPE_1000BASE_LX_HD;
	    break;
	case IFM_1000_CX:
	    if (session->duplex == 1)
		session->mau = LLDP_MAU_TYPE_1000BASE_CX_FD;
	    else
		session->mau = LLDP_MAU_TYPE_1000BASE_CX_HD;
	    break;
	case IFM_1000_T:
	    if (session->duplex == 1)
		session->mau = LLDP_MAU_TYPE_1000BASE_T_FD;
	    else
		session->mau = LLDP_MAU_TYPE_1000BASE_T_HD;
	    break;
	case IFM_10G_LR:
	    session->mau = LLDP_MAU_TYPE_10GBASE_LR;
	    break;
	case IFM_10G_SR:
	    session->mau = LLDP_MAU_TYPE_10GBASE_SR;
	    break;
    }

    free(media_list);
#endif /* HAVE_NET_IF_MEDIA_H */

    // cleanup
    close(sockfd);

    return(EXIT_SUCCESS);
}

