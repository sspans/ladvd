
#ifndef _master_h
#define _master_h

#include <pwd.h>

#define MASTER_SEND	0
#define MASTER_RECV	1
#define MASTER_ETHTOOL	2

struct master_request {
    uint32_t index;
    char name[IFNAMSIZ];
    uint8_t cmd;
    uint8_t completed;
    char msg[ETHER_MAX_LEN];
    size_t len;
};

#define MASTER_REQ_SIZE   sizeof(struct master_request)

void master_init(struct passwd *pwd, int cmdfd);
int master_rsocket();
size_t master_rsend(int s, struct master_request *mreq);

#endif /* _master_h */
