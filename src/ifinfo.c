
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <main.h>

#if HAVE_ASM_TYPES_H
# include <asm/types.h>
#endif /* HAVE_ASM_TYPES_H */

#if HAVE_LINUX_SOCKIOS_H
# include <linux/sockios.h>
#endif /* HAVE_LINUX_SOCKIOS_H */

#if HAVE_LINUX_ETHTOOL_H
# include <linux/ethtool.h>
#endif /* HAVE_LINUX_ETHTOOL_H */

#if HAVE_NET_IF_MEDIA_H
# include <net/if_media.h>
#endif /* HAVE_NET_IF_MEDIA_H */

int ifinfo_get(struct session *session) {
    int fd;
    struct ifreq ifr;

#if HAVE_LINUX_ETHTOOL_H
    struct ethtool_cmd ecmd;
#endif /* HAVE_LINUX_ETHTOOL_H */

#if HAVE_NET_IF_MEDIA_H
    struct ifmediareq ifmr;
#endif /* HAVE_HAVE_NET_IF_MEDIA_H */

    fd = libnet_getfd(session->libnet);
    session->duplex = -1;
    session->autoneg_supported = -1;
    session->autoneg_enabled = -1;

    bzero(&ifr, sizeof(ifr));
    strncpy(ifr.ifr_name, session->dev, sizeof(ifr.ifr_name) -1);

    // interface mtu
    if (ioctl(fd, SIOCGIFMTU, (caddr_t)&ifr) < 0) {
	log_str(0, "fetching %s mtu failed: %s", session->dev, strerror(errno));
    } else {
	session->mtu = ifr.ifr_mtu;
    }

#if HAVE_LINUX_ETHTOOL_H
    ifr.ifr_data = (caddr_t)&ecmd;
    ecmd.cmd = ETHTOOL_GSET;

    if (ioctl(fd, SIOCETHTOOL, &ifr) >= 0) {
	session->duplex = (ecmd.duplex == DUPLEX_FULL) ? 1 : 0;
	session->speed = ecmd.speed;

	// autoneg
	if(ecmd.supported & SUPPORTED_Autoneg) {
	    session->autoneg_supported = 1;
	    session->autoneg_enabled = (ecmd.autoneg == AUTONEG_ENABLE) ? 1 : 0;
	} else {
	    session->autoneg_supported = 0;
	}	
    }

    return(EXIT_SUCCESS);
#endif /* HAVE_LINUX_ETHTOOL_H */

#if HAVE_NET_IF_MEDIA_H
    bzero(&ifmr, sizeof(ifmr));
    strncpy(ifmr.ifm_name, session->dev, sizeof(ifmr.ifm_name) -1);

    if (ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0) {
	// media detection not supported
	return(EXIT_SUCCESS);
    }

    if (ifmr.ifm_count == 0) {
	log_str(0, "missing media types for interface %s", session->dev);
	return(EXIT_FAILURE);
    }

    ifmr.ifm_ulist = malloc(ifmr.ifm_count * sizeof(int));
    if (ifmr.ifm_ulist == NULL) {
	log_str(0, "malloc failed for interface %s", session->dev);
	return(EXIT_FAILURE);
    }

    if (ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0) {
	log_str(0, "media detection failed for interface %s", session->dev);
	return(EXIT_FAILURE);
    }

    if (IFM_TYPE(ifmr.ifm_current) != IFM_ETHER) {
	log_str(0, "non-ethernet interface %s found", session->dev);
	return(EXIT_FAILURE);
    }

    // autoneg
    if(ifmr.ifm_current & IFM_AUTO) {
	session->autoneg_supported = 1;
	session->autoneg_enabled = 1;
    } else {
	session->autoneg_supported = 1;
	session->autoneg_enabled = 0;
    }

    if(ifmr.ifm_active & IFM_FDX) {
	session->autoneg_supported = 1;
    }

    return(EXIT_SUCCESS);
#endif /* HAVE_NET_IF_MEDIA_H */

    return(EXIT_SUCCESS);
}
