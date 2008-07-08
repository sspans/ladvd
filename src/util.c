/*
 $Id$
*/

#include "main.h"
#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

unsigned int loglevel = 0;
extern int do_fork;

void my_log(int prio, const char *fmt, ...) {

    va_list ap;
    va_start(ap, fmt);

    if (prio > loglevel)
	return;

    if (do_fork == 1) {
	vsyslog(LOG_INFO, fmt, ap);
    } else {
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
    }
}

void * my_malloc(size_t size) {
    void *ptr;

    if ((ptr = malloc(size)) == NULL) {
	my_log(0, "malloc failed: %s", strerror(errno));
	exit(EXIT_FAILURE);
    }
    bzero(ptr, size);
    return(ptr);
}

char * my_strdup(const char *str) {
    char *cstr;

    if ((cstr = strdup(str)) == NULL) {
	my_log(0, "strdup failed: %s", strerror(errno));
	exit(EXIT_FAILURE);
    }
    return(cstr);
}

int my_ioctl(int fd, int request, void *arg) {
    int n;

    if ((n = ioctl(fd, request, arg)) == -1) {
	my_log(0, "ioctl error: %s", strerror(errno));
	exit(EXIT_FAILURE);
    }
    return(n);      /* streamio of I_LIST returns value */
}

int my_socket(int af, int type, int proto) {
    int s;

    if ((s = socket(af, type, proto)) < 0) {
	my_log(0, "opening socket failed: %s", strerror(errno));
	exit(EXIT_FAILURE);
    }
    return(s);
}

int my_rsocket(const char *if_name) {

    int socket;

#ifdef PF_PACKET
    socket = my_socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
#elif HAVE_NET_BPF_H
    socket = open("/dev/bpf", O_WRONLY);
#endif

    return(socket);
}

int my_rsend(int socket, const void *msg, size_t len) {

    size_t count = 0;

#ifdef PF_PACKET
    count = send(socket, msg, len, 0);
#elif HAVE_NET_BPF_H
    count = write(socket, msg, len);
#endif

    if (count != len)
	my_log(0, "only %d bytes written: %s", count, strerror(errno));
    
    return(count);
}

struct session *session_byname(struct session *sessions, char *name) {
    struct session *session;

    for (session = sessions; session != NULL; session = session->next) {
	if (strcmp(session->if_name, name) == 0)
	    break;
    }
    return(session);
}

