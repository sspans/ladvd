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
#if HAVE_EVHTTP_H
#include <evhttp.h>
#endif /* HAVE_EVHTTP_H */

static void usage() __noreturn;
extern struct proto protos[];
int status = EXIT_SUCCESS;

void batch_write(struct master_msg *msg, uint16_t holdtime);
void cli_header();
void cli_write(struct master_msg *msg, uint16_t holdtime);
void debug_header();
void debug_write(struct master_msg *msg, uint16_t holdtime);
#if HAVE_EVHTTP_H
void http_connect();
void http_request(struct master_msg *msg, uint16_t holdtime);
void http_reply(struct evhttp_request *req, void *arg);
void http_dispatch();
#endif /* HAVE_EVHTTP_H */

struct mode {
    void (*init) ();
    void (*write) (struct master_msg *, uint16_t);
    void (*dispatch) ();
};

struct mode modes[] = {
  { NULL, &batch_write, NULL },
  { &cli_header, &cli_write, NULL },
  { &debug_header, &debug_write, NULL },
  { NULL, NULL, NULL },
#if HAVE_EVHTTP_H
  { &http_connect, &http_request, &http_dispatch },
#endif /* HAVE_EVHTTP_H */
};

#define MODE_BATCH  0
#define MODE_CLI    1
#define MODE_DEBUG  2
#define MODE_FULL   3
#define MODE_HTTP   4

#if HAVE_EVHTTP_H
char *http_host = NULL;
char *http_path = NULL;
struct sysinfo sysinfo = {};

struct evhttp_connection *evcon = NULL;
struct evhttp_request *lreq = NULL;
#endif /* HAVE_EVHTTP_H */

__noreturn
void cli_main(int argc, char *argv[]) {
    int ch, i;
    uint8_t proto = 0, mode = MODE_CLI;
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
#if HAVE_EVHTTP_H
	    case 'p':
		mode = MODE_HTTP;
		if (strncmp(optarg, "http://", 7) == 0)
		    optarg += 7;
		char *host = my_strdup(optarg);
		char *path = strchr(host, '/');
		if (path) {
		    http_path = my_strdup(path);
		    *path = '\0';
		} else {
		    http_path = my_strdup("/");
		}
		http_host = my_strdup(host);
		free(host);
		break;
#endif /* HAVE_EVHTTP_H */
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
	
	if (modes[mode].write)
	    modes[mode].write(&msg, holdtime);

	peer_free(msg.peer);

	if (options & OPT_ONCE)
	    goto out;
    }

out:
    if (modes[mode].dispatch)
	modes[mode].dispatch();

    exit(status);
}

inline void swapchr(char *str, int c, int d) {
    while ((str = strchr(str, c)) != NULL) {
	*str = d;
	 str++;
    }
}

#define STR(x)	(x) ? x : ""

void batch_write(struct master_msg *msg, uint16_t holdtime) {
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

void cli_header() {
    printf("Capability Codes:\n"
	"\tr - Repeater, B - Bridge, H - Host, R - Router, S - Switch,\n"
	"\tW - WLAN Access Point, C - DOCSIS Device, T - Telephone, "
	"O - Other\n\n");
    printf("Device ID           Local Intf    Proto   "
	"Hold-time    Capability    Port ID\n");
}

void cli_write(struct master_msg *msg, uint16_t holdtime) {
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

void debug_header() {
    if (isatty(fileno(stdout)))
	my_fatal("please redirect stdout to tcpdump or a file");
    write_pcap_hdr(fileno(stdout));
}

void debug_write(struct master_msg *msg, uint16_t holdtime) {
    write_pcap_rec(fileno(stdout), msg);
}

#if HAVE_EVHTTP_H
void http_connect() {
    struct servent *sp;
    short port;

    if ((sp = getservbyname("http", "tcp")) == NULL)
	my_fatal("HTTP port not found");
    port = ntohs(sp->s_port);

    // initalize the event library
    event_init();

    evcon = evhttp_connection_new(http_host, port);
    if (evcon == NULL)
        my_fatal("HTTP connection failed");

    sysinfo_fetch(&sysinfo);
}

void http_request(struct master_msg *msg, uint16_t holdtime) {
    int ret;
    char *peer_host, *peer_port, *data;
    char *cap = msg->peer[PEER_CAP];
    struct evhttp_request *req = NULL;

    // url-encode the received strings
    peer_host = evhttp_encode_uri(msg->peer[PEER_HOSTNAME]);
    peer_port = evhttp_encode_uri(msg->peer[PEER_PORTNAME]);

    ret = asprintf(&data,
	"hostname=%s&interface=%s&peer_hostname=%s&peer_portname=%s&"
	"protocol=%s&capabilities=%s&ttl=%" PRIu16 "&holdtime=%" PRIu16
	"\r\n\r\n",
	sysinfo.hostname, STR(msg->name), peer_host, peer_port,
	protos[msg->proto].name, STR(cap), msg->ttl, holdtime);
    if (ret == -1)
	my_fatal("asprintf failed");

    req = evhttp_request_new(http_reply, NULL);
    if (ret == -1)
	my_fatal("failed to allocate HTTP request");

    evhttp_add_header(req->output_headers, "Host", http_host);
    evhttp_add_header(req->output_headers, "User-Agent", 
		PACKAGE_CLI "/" PACKAGE_VERSION);
    evhttp_add_header(req->output_headers, "Content-Type",
		"application/x-www-form-urlencoded");
    evbuffer_add(req->output_buffer, data, strlen(data));

    if (evhttp_make_request(evcon, req, EVHTTP_REQ_POST, http_path) == -1)
	my_fatal("failed to create HTTP request");
    lreq = req;

    free(peer_host);
    free(peer_port);
    free(data);
}

void http_reply(struct evhttp_request *req, void *arg) {
    if ((req == NULL) || (req->response_code == 0))
	my_fatal("HTTP request failed");

    if (req->response_code < HTTP_BADREQUEST)
	return;

    my_log(CRIT, "HTTP error %d received", req->response_code);
    status = EXIT_FAILURE;
}

void http_dispatch() {
    // auto-close the connection after the last request
    if (lreq)
	evhttp_add_header(lreq->output_headers, "Connection", "close");

    event_dispatch();
    evhttp_connection_free(evcon);
}
#endif /* HAVE_EVHTTP_H */

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
#if HAVE_EVHTTP_H
	    "\t-p <url> = Post decode to url\n"
#endif /* HAVE_EVHTTP_H */
	    "\t-h = Print this message\n",
	    __progname);

    exit(EXIT_FAILURE);
}

