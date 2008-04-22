#define USER	    "nobody"
#define PIDFILE	    "/var/run/ladvd.pid"
#define SLEEPTIME   30

#include <sys/utsname.h>
#include <libnet.h>
#include "config.h"

struct session {
    libnet_t *libnet;

    char *dev;
    u_int8_t hwaddr[6];
    u_int32_t ipaddr4;
    struct utsname *uts;
    char *uts_str;
    u_int8_t cap_router;

    u_int8_t *cdp_data;
    size_t cdp_length;
    u_int8_t *lldp_data;
    size_t lldp_length;
    
    struct session *next;
};

void log_str(int prio, const char *fmt, ...);

int cdp_packet(struct session *session);
int cdp_send(struct session *session);

int lldp_packet(struct session *session);
int lldp_send(struct session *session);

