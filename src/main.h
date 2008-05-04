#define USER	    "nobody"
#define PIDFILE	    "/var/run/ladvd.pid"
#define SLEEPTIME   30

#include <sys/utsname.h>
#include <libnet.h>
#include "config.h"

struct session {
    libnet_t *libnet;

    char *dev;
    uint8_t hwaddr[6];
    uint32_t mtu;
    // TODO: media

    uint32_t ipaddr4;
    // TODO: ipv6

    struct utsname *uts;
    char *uts_str;
    uint8_t cap_router;

    uint8_t *cdp_data;
    size_t cdp_length;
    uint8_t *lldp_data;
    size_t lldp_length;
    
    struct session *next;
};

void log_str(int prio, const char *fmt, ...);

int ifinfo_get(struct session *session);

int cdp_packet(struct session *session);
int cdp_send(struct session *session);

int lldp_packet(struct session *session);
int lldp_send(struct session *session);

