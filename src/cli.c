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

static void usage() __attribute__ ((__noreturn__));
extern struct proto protos[];

__attribute__ ((__noreturn__))
void cli_main(int argc, char *argv[]) {
    int ch, i;
    uint8_t proto = 0xFF;
    uint32_t *indexes = NULL;
    struct sockaddr_un sun;
    int fd = -1;
    struct master_msg msg;
    ssize_t len;

    options = 0;

    while ((ch = getopt(argc, argv, "LCEFNh")) != -1) {
	// reset protos
	if (proto == 0xFF)
	    proto = 0;

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
	    default:
		usage();
	}
    }

    argc -= optind;
    argv += optind;

    if (argc) {
	indexes = my_calloc(argc, sizeof(msg.index));
	for (i = 0; i < argc; i++) {
	    indexes[i] = if_nametoindex(argv[i]);
	    if (!indexes[i])
		usage();
	}
    }

    // open socket connection
    fd = my_socket(AF_UNIX, SOCK_SEQPACKET, 0);
    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    strlcpy(sun.sun_path, PACKAGE_SOCKET, sizeof(sun.sun_path));
    if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) == -1)
	my_fatal("failed to open " PACKAGE_SOCKET ": %s", strerror(errno));

    while ((len = read(fd, &msg, MASTER_MSG_MAX)) != -1) {
    
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

	if (if_indextoname(msg.index, msg.name) == NULL)
	    continue;

	// skip unwanted protocols
	if (!(proto & (1 << msg.proto)))
	    continue;

	// decode packet
	msg.decode = UINT16_MAX;
	if (msg.len != protos[msg.proto].decode(&msg))
	    continue;

	printf("peer %s (%s) on interface %s\n",
		msg.peer[PEER_HOSTNAME], protos[msg.proto].name, msg.name);

	PEER_FREE(msg.peer);
    }

    exit(EXIT_SUCCESS);
}


__attribute__ ((__noreturn__))
static void usage() {
    extern char *__progname;

    fprintf(stderr, PACKAGE_NAME " version " PACKAGE_VERSION "\n" 
	"Usage: %s [-LCEFN] [INTERFACE] [INTERFACE]\n"
	    "\t-L = Print LLDP\n"
	    "\t-C = Print CDP\n"
	    "\t-E = Print EDP\n"
	    "\t-F = Print FDP\n"
	    "\t-N = Print NDP\n"
	    "\t-h = Print this message\n",
	    __progname);

    exit(EXIT_FAILURE);
}

