
#ifndef _util_h
#define _util_h

#include <pwd.h>

#define CRIT    1
#define WARN    2
#define INFO    3
#define DEBUG   4

void my_log(unsigned int prio, const char *fmt, ...);
void *my_malloc(size_t size);
char *my_strdup(const char *str);
int my_socket(int af, int type, int proto);

int my_rsocket();
size_t my_rsend(int s, struct netif *, const void *msg, size_t len);

struct netif *netif_byindex(struct netif *, uint32_t index);
struct netif *netif_byname(struct netif *, char *name);

int read_line(char *path, char *line, uint16_t len);

void my_drop_privs(struct passwd *pwd);

uint16_t my_chksum(void *data, size_t length, int cisco);

#endif /* _util_h */
