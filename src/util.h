
#ifndef _util_h
#define _util_h

void my_log(int prio, const char *fmt, ...);
void *my_malloc(size_t size);
char *my_strdup(const char *str);
int my_ioctl(int fd, int request, void *arg);
int my_socket(int af, int type, int proto);

int my_rsocket(const char *if_name);
int my_rsend(int socket, const void *msg, size_t len);

struct session *session_byname(struct session *sessions, char *name);

#endif /* _util_h */
