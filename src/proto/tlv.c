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
    size_t srclen, len;
    uint16_t cap, i, j = 0;
    const char *cap_str = CAP_STRING;

    // skip if not wanted or already decoded
    if (!(msg->decode & (1 << type)) || msg->peer[type])
	return;

    switch (type) {
	case PEER_HOSTNAME:
	case PEER_PORTNAME:
	    srclen = MIN(length, TLV_LEN - 1);
	    memcpy(src, value, srclen);
	    *(src + srclen) = '\0';
	    len = srclen * 4 + 1;
	    str = my_malloc(len);
	    strnvis(str, src, len, VIS_NL|VIS_TAB|VIS_GLOB|VIS_OCTAL);
	    break;
	case PEER_CAP:
	    memcpy(&cap, value, sizeof(uint16_t));
	    str = my_malloc(CAP_MAX + 1);
	    for (i = 0; i < CAP_MAX; i++) {
		if (cap & (1 << i))
		    str[j++] = cap_str[i];
	    }
	    break;
	default:
	    my_fatal("unhandled type %d", type);
    }

    if (str)
	msg->peer[type] = str;
}

