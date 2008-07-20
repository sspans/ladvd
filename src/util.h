
#ifndef _util_h
#define _util_h

void my_log(int prio, const char *fmt, ...);
void *my_malloc(size_t size);
char *my_strdup(const char *str);
int my_socket(int af, int type, int proto);

int my_rsocket();
int my_rsend(int s, struct session *session, const void *msg, size_t len);

struct session *session_byindex(struct session *sessions, uint8_t index);
struct session *session_byname(struct session *sessions, char *name);

#endif /* _util_h */
