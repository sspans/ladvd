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

#if HAVE_LINUX_IF_BRIDGE_H
#include <linux/if_bridge.h>
#endif /* HAVE_LINUX_IF_BRIDGE_H */

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

#define SYSFS_VIRTUAL "/sys/devices/virtual/net"
#define SYSFS_PATH_MAX  256


// handle aggregated interfaces
void netif_bond(struct session *sessions, struct session *session) {

    struct session *subif = NULL, *csubif = session;

#if HAVE_LINUX_IF_BONDING_H
    // handle linux bonding interfaces
    char path[SYSFS_PATH_MAX];
    FILE *fp;
    char line[1024];
    char *slave, *nslave;
    int m;

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
	    m = 0;
	    while (strlen(slave) > 0) {
		nslave = strstr(line, " ");
		if (nslave != NULL)
		    *nslave = '\0';

		subif = session_byname(sessions, slave);
		if (subif != NULL) {
		    subif->if_slave = 1;
		    subif->if_lacp_ifindex = m++;
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

#elif HAVE_NET_LAGG_H
    // TODO: handle bsd lagg interfaces
#endif

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
#elif HAVE_NET_IF_BRIDGEVAR_H
    // TODO: handle bsd bridge interfaces
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
#endif

#if HAVE_LINUX_ETHTOOL_H
    char path[SYSFS_PATH_MAX];
    struct stat sb;

    struct ethtool_drvinfo drvinfo;
#endif /* HAVE_LINUX_ETHTOOL_H */

#if HAVE_NET_IF_MEDIA_H
    struct ifmediareq ifmr;
#endif /* HAVE_HAVE_NET_IF_MEDIA_H */

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
	if(ifaddr->ifa_addr->sa_family != AF_PACKET)
	    continue;
#endif
#ifdef AF_LINK
	if(ifaddr->ifa_addr->sa_family != AF_LINK) 
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
	strncpy(ifr.ifr_name, ifaddr->ifa_name, sizeof(ifaddr->ifa_name) -1);


	// skip interfaces that are down
	my_ioctl(sockfd, SIOCGIFFLAGS, (caddr_t)&ifr);
	if ((ifr.ifr_flags & IFF_UP) == 0)
	    continue;


	// skip non-ethernet interfaces
#ifdef AF_PACKET
	bcopy(ifaddr->ifa_addr, &saddrll, sizeof(saddrll));
	if (saddrll.sll_hatype != ARPHRD_ETHER)
	    continue;
#endif
#ifdef AF_LINK
	bcopy(ifaddr->ifa_addr, &saddrdl, sizeof(saddrdl));
	if (saddrdl.sdl_type != IFT_ETHER)
	    continue;
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
			if_master = MASTER_BONDING;
			goto session;	
		} else if (strcmp(drvinfo.driver, "bridge") == 0) {
			if_master = MASTER_BRIDGE;
			goto session;
		// handle tun/tap
		} else if (strcmp(drvinfo.driver, "tun") == 0) {
		    goto session;	
		}
	    }
	    // we don't want the rest
	    continue;
	}
#endif /* HAVE_LINUX_ETHTOOL_H */

	// TODO: BSD virtual detect


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
	session->if_name = my_strdup(ifaddr->ifa_name);
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

	if(ifaddr->ifa_addr->sa_family == AF_INET) {
	    if (session->ipaddr4 != 0)
		continue;

	    // alignment
	    bcopy(ifaddr->ifa_addr, &saddr4, sizeof(saddr4));

	    bcopy(&saddr4.sin_addr, &session->ipaddr4,
		  sizeof(saddr4.sin_addr));

	} else if(ifaddr->ifa_addr->sa_family == AF_INET6) {
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
	} else if(ifaddr->ifa_addr->sa_family == AF_PACKET) {

	    // alignment
	    bcopy(ifaddr->ifa_addr, &saddrll, sizeof(saddrll));

	    bcopy(&saddrll.sll_addr, &session->if_hwaddr, ETHER_ADDR_LEN);
#endif
#ifdef AF_LINK
	} else if(ifaddr->ifa_addr->sa_family == AF_LINK) {

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
    strncpy(ifr.ifr_name, session->if_name, sizeof(ifr.ifr_name) -1);

    // ether addr

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
	    session->autoneg_supported = 1;
	    session->autoneg_enabled = (ecmd.autoneg == AUTONEG_ENABLE) ? 1 : 0;
	} else {
	    session->autoneg_supported = 0;
	}	
    } else {
	my_log(3, "ethtool ioctl failed on interface %s", session->if_name);
    }
#endif /* HAVE_LINUX_ETHTOOL_H */

#if HAVE_NET_IF_MEDIA_H
    bzero(&ifmr, sizeof(ifmr));
    strncpy(ifmr.ifm_name, session->if_name, sizeof(ifmr.ifm_name) -1);

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
	    my_log(3, "autoneg supported on interface %s", session->if_name);
	    session->autoneg_supported = 1;
	    break;
	}
    }

    // autoneg enabled
    if (session->autoneg_supported == 1) {
	if (IFM_SUBTYPE(ifmr.ifm_current) == IFM_AUTO) {
	    my_log(3, "autoneg enabled on interface %s", session->if_name);
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

