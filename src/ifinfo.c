
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

int ifinfo_get(struct session *session) {
    int fd;
    struct ifreq ifr;

#if HAVE_LINUX_ETHTOOL_H
    struct ethtool_cmd ecmd;
#endif /* HAVE_LINUX_ETHTOOL_H */

    fd = libnet_getfd(session->libnet);
    session->duplex = -1;
    session->autoneg = -1;

    // fetch interface mtu
    (void) memset(&ifr, 0, sizeof(ifr));
    (void) strncpy(ifr.ifr_name, session->dev, sizeof(ifr.ifr_name) -1);

    if (ioctl(fd, SIOCGIFMTU, (caddr_t)&ifr) < 0) {
	log_str(0, "Fetching %s mtu failed: %s", session->dev, strerror(errno));
    } else {
	session->mtu = ifr.ifr_mtu;
    }

#if HAVE_LINUX_ETHTOOL_H
    ifr.ifr_data = (caddr_t)&ecmd;
    ecmd.cmd = ETHTOOL_GSET;

    if (ioctl(fd, SIOCETHTOOL, &ifr) >= 0) {
	session->duplex = (ecmd.duplex == DUPLEX_FULL) ? 1 : 0;
	session->speed = ecmd.speed;
	session->autoneg = (ecmd.autoneg == AUTONEG_ENABLE) ? 1 : 0;
    }
#endif /* HAVE_LINUX_ETHTOOL_H */

    return (EXIT_SUCCESS);
}
