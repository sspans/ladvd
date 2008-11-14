/*
 $Id$
*/

#include "common.h"
#include "util.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#ifdef HAVE_NETPACKET_PACKET_H
#include <netpacket/packet.h>
#endif /* HAVE_NETPACKET_PACKET_H */
#ifdef HAVE_NET_BPF_H
#include <net/bpf.h>
#endif /* HAVE_NET_BPF_H */

unsigned int loglevel = CRIT;
extern unsigned int do_detach;
extern unsigned int do_debug;

void my_log(unsigned int prio, const char *fmt, ...) {

    va_list ap;
    va_start(ap, fmt);

    if (prio > loglevel)
	return;

    if (do_detach == 1) {
	(void) vsyslog(LOG_INFO, fmt, ap);
    } else {
	(void) vfprintf(stderr, fmt, ap);
	(void) fprintf(stderr, "\n");
    }
}

void * my_malloc(size_t size) {
    void *ptr;

    if ((ptr = malloc(size)) == NULL) {
	my_log(CRIT, "malloc failed: %s", strerror(errno));
	exit(EXIT_FAILURE);
    }
    memset(ptr, 0, size);
    return(ptr);
}

char * my_strdup(const char *str) {
    char *cstr;

    if ((cstr = strdup(str)) == NULL) {
	my_log(CRIT, "strdup failed: %s", strerror(errno));
	exit(EXIT_FAILURE);
    }
    return(cstr);
}

int my_socket(int af, int type, int proto) {
    int s;

    if ((s = socket(af, type, proto)) < 0) {
	my_log(CRIT, "opening socket failed: %s", strerror(errno));
	exit(EXIT_FAILURE);
    }
    return(s);
}

int my_rsocket() {

    int socket = -1;

    // return stdout on debug
    if (do_debug == 1)
	return(1);

#ifdef HAVE_NETPACKET_PACKET_H
    socket = my_socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
#elif HAVE_NET_BPF_H
    int n = 0;
    char *dev;

    do {
	if (asprintf(&dev, "/dev/bpf%d", n++) == -1) {
	    my_log(CRIT, "failed to allocate buffer");
	    return(-1);
	}
	socket = open(dev, O_WRONLY);
    } while (socket < 0 && errno == EBUSY);
#endif

    return(socket);
}

size_t my_rsend(int s, struct netif *netif, const void *msg, size_t len) {

    size_t count = 0;

    pcaprec_hdr_t pcap_rec_hdr;
    struct timeval tv;

    // debug
    if (do_debug == 1) {

	// write a pcap record header if netif is set
	if ((netif != NULL) && (gettimeofday(&tv, NULL) == 0)) {
	    pcap_rec_hdr.ts_sec = tv.tv_sec;
	    pcap_rec_hdr.ts_usec = tv.tv_usec;
	    pcap_rec_hdr.incl_len = len;
	    pcap_rec_hdr.orig_len = len;

	    (void) write(s, &pcap_rec_hdr, sizeof(pcap_rec_hdr));
	}

	return(write(s, msg, len));
    }

#ifdef HAVE_NETPACKET_PACKET_H
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof (sa));

    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = netif->index;
    sa.sll_protocol = htons(ETH_P_ALL);

    count = sendto(s, msg, len, 0, (struct sockaddr *)&sa, sizeof (sa));
#elif HAVE_NET_BPF_H
    struct ifreq ifr;

    // prepare ifr struct
    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, netif->name, IFNAMSIZ);

    if (ioctl(s, BIOCSETIF, (caddr_t)&ifr) < 0) {
	my_log(CRIT, "ioctl failed: %s", strerror(errno));
	return(-1);
    }
    count = write(s, msg, len);
#endif

    if (count != len)
	my_log(WARN, "only %d bytes written: %s", count, strerror(errno));
    
    return(count);
}

struct netif *netif_byindex(struct netif *netifs, uint32_t index) {
    struct netif *netif;

    for (netif = netifs; netif != NULL; netif = netif->next) {
	if (netif->index == index)
	    break;
    }
    return(netif);
}

struct netif *netif_byname(struct netif *netifs, char *name) {
    struct netif *netif;

    for (netif = netifs; netif != NULL; netif = netif->next) {
	if (strcmp(netif->name, name) == 0)
	    break;
    }
    return(netif);
}

int read_line(char *path, char *line, uint16_t len) {
    FILE *file;
    char *newline;

    if ((file = fopen(path, "r")) == NULL)
	return(-1);

    if (fgets(line, len, file) == NULL) {
	(void) fclose(file);
	return(-1);
    }
    (void) fclose(file);

    // remove newline
    newline = strchr(line, '\n');
    if (newline != NULL)
	*newline = '\0';

    return(strlen(line));
}


/*
 * Actually, this is the standard IP checksum algorithm.
 */
uint16_t my_chksum(void *data, size_t length, int cisco) {
    uint32_t sum = 0;
    const uint16_t *d = (const uint16_t *)data;

    while (length > 1) {
	sum += *d++;
	length -= 2;
    }
    if (length) {
	if (cisco) {
	    sum += htons(*(const uint8_t *)d);
	} else {
	    sum += htons(*(const uint8_t *)d << 8);
	}
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}

