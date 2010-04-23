/*
 * $Id$
 *
 * Copyright (c) 2008, 2009, 2010
 *      Sten Spans <sten@blinkenlights.nl>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "common.h"
#include "util.h"
#include "proto/protos.h"
#include <sys/file.h>
#include <sys/un.h>
#include <netdb.h>

static void usage() __noreturn;
extern struct proto protos[];

void init_brief();
void init_post();
void init_debug();
void print_brief(struct master_msg *msg, uint16_t holdtime);
void print_batch(struct master_msg *msg, uint16_t holdtime);
void print_post(struct master_msg *msg, uint16_t holdtime);
void print_debug(struct master_msg *msg, uint16_t holdtime);

struct mode {
    void (*init) ();
    void (*print) (struct master_msg *, uint16_t);
};

struct mode modes[] = {
  { &init_brief, &print_brief },
  { NULL, &print_batch },
  { NULL, NULL },
  { &init_post, &print_post },
  { &init_debug, &print_debug }
};

#define MODE_BRIEF  0
#define MODE_BATCH  1
#define MODE_FULL   2
#define MODE_POST   3
#define MODE_DEBUG  4

struct {
    int sock;
    char *host;
    char *path;
    struct sysinfo sysinfo;
} post;
    
__noreturn
void cli_main(int argc, char *argv[]) {
    int ch, i;
    uint8_t mode = MODE_BRIEF, proto = 0;
    uint32_t *indexes = NULL;
    struct sockaddr_un sun;
    int fd = -1;
    time_t now;
    struct master_msg msg = {};
    uint16_t holdtime;
    ssize_t len;

    options = 0;

    while ((ch = getopt(argc, argv, "LCEFNbdfp:oh")) != -1) {
	switch(ch) {
	    case 'L':
		proto |= (1 << PROTO_LLDP);
		break;
	    case 'C':
		proto |= (1 << PROTO_CDP);
		break;
	    case 'E':
		proto |= (1 << PROTO_EDP);
		break;
	    case 'F':
		proto |= (1 << PROTO_FDP);
		break;
	    case 'N':
		proto |= (1 << PROTO_NDP);
		break;
	    case 'b':
		mode = MODE_BATCH;
		break;
	    case 'd':
		mode = MODE_DEBUG;
		break;
	    case 'f':
		mode = MODE_FULL;
		break;
	    case 'p':
		mode = MODE_POST;
		if ((strlen(optarg) < 8) || strncmp(optarg, "http://", 7))
		    usage();
		char *host = my_strdup(optarg + 7);
		char *path = strchr(host, '/');
		if (path) {
		    post.path = my_strdup(path);
		    *path = '\0';
		} else {
		    post.path = my_strdup("/");
		}
		post.host = my_strdup(host);
		free(host);
		break;
	    case 'o':
		options |= OPT_ONCE;
		break;
	    default:
		usage();
	}
    }

    argc -= optind;
    argv += optind;

    // default to all protocols
    if (proto == 0)
	proto = UINT8_MAX;

    if (argc) {
	indexes = my_calloc(argc, sizeof(msg.index));
	for (i = 0; i < argc; i++) {
	    indexes[i] = if_nametoindex(argv[i]);
	    if (!indexes[i])
		usage();
	}
    }

    // open socket connection
    fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    // XXX: make do with a stream and hope for the best
    if ((fd == -1) && (errno == EPROTONOSUPPORT))
	fd = my_socket(AF_UNIX, SOCK_STREAM, 0);
    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    strlcpy(sun.sun_path, PACKAGE_SOCKET, sizeof(sun.sun_path));
    if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) == -1)
	my_fatal("failed to open " PACKAGE_SOCKET ": %s", strerror(errno));

    if ((now = time(NULL)) == (time_t)-1)
	my_fatal("failed fetch time: %s", strerror(errno));

    if (modes[mode].init)
	modes[mode].init();

    while ((len = read(fd, &msg, MASTER_MSG_MAX)) > 0) {

	if (len < MASTER_MSG_MIN || len != MASTER_MSG_LEN(msg.len))
	    continue;

	if (msg.proto > PROTO_MAX)
	    continue;
	if ((msg.len < ETHER_MIN_LEN) || (msg.len > ETHER_MAX_LEN))
	    continue;
	
	// skip unwanted interfaces
	if (indexes) {
	    for (i = 0; i < argc; i++) {
		if (indexes[i] == msg.index)
		    break;
	    }
	    if (i == argc)
		continue;
	}

	// skip unwanted protocols
	if (!(proto & (1 << msg.proto)))
	    continue;

	// decode packet
	msg.decode = UINT16_MAX;
	if (msg.len != protos[msg.proto].decode(&msg))
	    continue;
	// skip expired packets
	if (msg.ttl < (now - msg.received))
	    continue;

	holdtime = msg.ttl - (now - msg.received);
	
	if (modes[mode].print)
	    modes[mode].print(&msg, holdtime);

	peer_free(msg.peer);

	if (options & OPT_ONCE)
	    exit(EXIT_SUCCESS);
    }

    exit(EXIT_SUCCESS);
}

inline void swapchr(char *str, int c, int d) {
    while ((str = strchr(str, c)) != NULL) {
	*str = d;
	 str++;
    }
}

#define STR(x)	(x) ? x : ""

void init_brief() {
    printf("Capability Codes:\n"
	"\tr - Repeater, B - Bridge, H - Host, R - Router, S - Switch,\n"
	"\tW - WLAN Access Point, C - DOCSIS Device, T - Telephone, "
	"O - Other\n\n");
    printf("Device ID           Local Intf    Proto   "
	"Hold-time    Capability    Port ID\n");
}

void print_brief(struct master_msg *msg, uint16_t holdtime) {
    char *hostname = msg->peer[PEER_HOSTNAME];
    char *portname = msg->peer[PEER_PORTNAME];
    char *cap = msg->peer[PEER_CAP];

    // shorten
    if (hostname)
	hostname[strcspn(hostname, ".")] = '\0';
    if (portname)
	portname_abbr(portname);

    printf("%-19.19s %-13.13s %-7.7s %-12" PRIu16 " %-13.13s %-10.10s\n",
	STR(hostname), STR(msg->name), protos[msg->proto].name,
	holdtime, STR(cap),  STR(portname));
}

void print_batch(struct master_msg *msg, uint16_t holdtime) {
    char *hostname = msg->peer[PEER_HOSTNAME];
    char *portname = msg->peer[PEER_PORTNAME];
    char *cap = msg->peer[PEER_CAP];
    static unsigned int count = 0;

    swapchr(hostname, '\'', '\"');
    swapchr(portname, '\'', '\"');

    printf("INTERFACE%u='%s'\n", count, STR(msg->name));
    printf("HOSTNAME%u='%s'\n", count, STR(hostname));
    printf("PORTNAME%u='%s'\n", count, STR(portname));
    printf("PROTOCOL%u='%s'\n", count, protos[msg->proto].name);
    printf("CAPABILITIES%u='%s'\n", count, STR(cap));
    printf("TTL%u='%" PRIu16 "'\n", count, msg->ttl);
    printf("HOLDTIME%u='%" PRIu16 "'\n", count, holdtime);

    count++;
}

void init_post() {
    struct addrinfo hints = {}, *res, *res0;
    int error;
    struct timeval tv = { .tv_usec = 500000 };

    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    error = getaddrinfo(post.host, "http", &hints, &res0);
    if (error)
        my_fatal("%s lookup failed: %s", post.host, gai_strerror(error));

    post.sock = -1;

    for (res = res0; res; res = res->ai_next) {
        post.sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (post.sock == -1)
	    continue;

        if (connect(post.sock, res->ai_addr, res->ai_addrlen) < 0) {
            close(post.sock);
            post.sock = -1;
            continue;
        }

	break;  /* okay we got one */
    }

    if (post.sock == -1)
        my_fatal("%s socket connection failed", post.host);

    freeaddrinfo(res0);

    // configure receive timeout
    setsockopt(post.sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sysinfo_fetch(&post.sysinfo);
}

char * encode_post(char *src) {
    char *str = NULL;
    size_t len;

    if (!src)
	return my_strdup("");

    len = strlen(src) * 4 + 1;
    str = my_malloc(len);
    strnvis(str, src, len, VIS_NL|VIS_TAB|VIS_HTTPSTYLE);
    swapchr(str, ' ', '+'); 

    return(str);
}

void print_post(struct master_msg *msg, uint16_t holdtime) {
    int ret;
    char *peer_host, *peer_port, *str;
    char *cap = msg->peer[PEER_CAP];
    struct iovec http_post[2];
    char buf[1024];

    // url-encode the received strings
    peer_host = encode_post(msg->peer[PEER_HOSTNAME]);
    peer_port = encode_post(msg->peer[PEER_PORTNAME]);

    ret = asprintf(&str,
	"hostname=%s&interface=%s&peer_hostname=%s&peer_portname=%s&"
	"protocol=%s&capabilities=%s&ttl=%" PRIu16 "&holdtime=%" PRIu16
	"\r\n\r\n",
	post.sysinfo.hostname, STR(msg->name), peer_host, peer_port,
	protos[msg->proto].name, STR(cap), msg->ttl, holdtime);
    if (ret == -1)
	my_fatal("asprintf failed");

    http_post[1].iov_base = str;
    http_post[1].iov_len = strlen(str);

    ret = asprintf(&str,
	"POST %s HTTP/1.1\r\n" "Host: %s\r\n"
	"User-Agent: " PACKAGE_CLI "/" PACKAGE_VERSION "\r\n"
	"Content-Type: application/x-www-form-urlencoded\r\n"
	"Content-Length: %zu\r\n\r\n",
	post.path, post.host, http_post[1].iov_len);
    if (ret == -1)
	my_fatal("asprintf failed");

    http_post[0].iov_base = str;
    http_post[0].iov_len = strlen(str);

    if (writev(post.sock, http_post, 2) == -1)
	my_fatal("failed to send HTTP header");

    free(peer_host);
    free(peer_port);
    free(http_post[0].iov_base);
    free(http_post[1].iov_base);

    while (read(post.sock, &buf, sizeof(buf)) > 0) {};
}

void init_debug() {
    write_pcap_hdr(fileno(stdout));
}

void print_debug(struct master_msg *msg, uint16_t holdtime) {
    write_pcap_rec(fileno(stdout), msg);
}

__noreturn
static void usage() {
    extern char *__progname;

    fprintf(stderr, PACKAGE_NAME " version " PACKAGE_VERSION "\n" 
	"Usage: %s [-LCEFN] [INTERFACE] [INTERFACE]\n"
	    "\t-L = Print LLDP\n"
	    "\t-C = Print CDP\n"
	    "\t-E = Print EDP\n"
	    "\t-F = Print FDP\n"
	    "\t-N = Print NDP\n"
	    "\t-b = Print scriptable output\n"
	    "\t-d = Dump pcap-compatible packets to stdout\n"
	    "\t-f = Print full decode\n"
	    "\t-o = Decode only one packet\n"
	    "\t-p <url> = Post decode to url\n"
	    "\t-h = Print this message\n",
	    __progname);

    exit(EXIT_FAILURE);
}

