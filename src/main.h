#include <libnet.h>
#include "config.h"
#include <sys/utsname.h>

#define USER	    "nobody"
#define PIDFILE	    "/var/run/ladvd.pid"
#define SLEEPTIME   30

struct session {
    libnet_t *libnet;

    char *dev;
    uint8_t ifindex;
    uint8_t hwaddr[6];
    uint16_t mtu;
    int8_t duplex;
    int8_t autoneg_supported; 
    int8_t autoneg_enabled; 
    uint16_t mau;

    uint32_t ipaddr4;
    // TODO: ipv6

    struct utsname *uts;
    char *uts_str;
    char *hostname;
    int8_t cap;
    char *location;

    uint8_t *cdp_data;
    size_t cdp_length;
    uint8_t *lldp_data;
    size_t lldp_length;
    
    struct session *next;
};

#define CAP_BRIDGE	(1 << 0)
#define CAP_HOST	(1 << 1)
#define CAP_ROUTER	(1 << 2)
#define CAP_SWITCH	(1 << 3)
#define CAP_WLAN	(1 << 4)

void log_str(int prio, const char *fmt, ...);

int ifinfo_get(struct session *session);

int cdp_packet(struct session *session);
int cdp_send(struct session *session);

int lldp_packet(struct session *session);
int lldp_send(struct session *session);

