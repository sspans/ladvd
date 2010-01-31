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
#include "proto/tlv.h"

void tlv_value_str(struct master_msg *msg,
	    uint16_t type, uint16_t length, void *value) {
    char src[TLV_LEN], *str = NULL;
    size_t srclen, strlen;

    // skip if not wanted or already decoded
    if (!(msg->decode & (1 << type)) || msg->peer[type])
	return;

    switch (type) {
	case PEER_HOSTNAME:
	case PEER_PORTNAME:
	case PEER_HARDWARE:
	case PEER_SOFTWARE:
	    srclen = MIN(length, TLV_LEN - 1);
	    memcpy(src, value, srclen);
	    *(src + srclen) = '\0';
	    strlen = srclen * 4 + 1;
	    str = my_malloc(strlen);
	    strnvis(str, src, strlen, VIS_NL|VIS_TAB|VIS_OCTAL);
	    break;
	case PEER_ETHER:
	    if (length != sizeof(struct ether_addr))
		break;
	    str = ether_ntoa(value);
	    break;
	case PEER_IPV4:
	    if (length != sizeof(struct in_addr))
		break;
	    str = my_malloc(INET_ADDRSTRLEN);
	    if (!inet_ntop(AF_INET, value, str, INET_ADDRSTRLEN)) {
		free(str);
		str = NULL;
	    }
	    break;
	case PEER_IPV6:
	    if (length != sizeof(struct in6_addr))
		break;
	    str = my_malloc(INET6_ADDRSTRLEN);
	    if (!inet_ntop(AF_INET6, value, str, INET6_ADDRSTRLEN)) {
		free(str);
		str = NULL;
	    }
	    break;
	default:
	    my_fatal("unhandled type %d", type);
    }

    if (str)
	msg->peer[type] = str;
}

