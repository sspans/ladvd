
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <main.h>

int ifinfo_get(struct session *session) {
    struct ifreq ifr;

    // fetch interface mtu
    (void) memset(&ifr, 0, sizeof(ifr));
    (void) strncpy(ifr.ifr_name, session->dev, sizeof(ifr.ifr_name));

    if (ioctl(libnet_getfd(session->libnet), SIOCGIFMTU, (caddr_t)&ifr) < 0) {
	log_str(0, "Fetching %s mtu failed: %s", session->dev, strerror(errno));
    } else {
	session->mtu = ifr.ifr_mtu;
    }

    return (EXIT_SUCCESS);
}
