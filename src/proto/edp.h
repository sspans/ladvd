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

#ifndef _edp_h
#define _edp_h

#define EDP_MULTICAST_ADDR { 0x00, 0xe0, 0x2b, 0x00, 0x00, 0x00 }
#define LLC_ORG_EXTREME { 0x00, 0xe0, 0x2b }
#define LLC_PID_EDP 0x00bb

struct edp_header {
    uint8_t version;
    uint8_t reserved;
    uint16_t length;
    uint16_t checksum;
    uint16_t sequence;
    uint16_t id_type; /* currently 2 0 octets */
    uint8_t hwaddr[ETHER_ADDR_LEN];
} __attribute__ ((__packed__));

// EDP TVL Types
#define EDP_TYPE_NULL	    0x00
#define EDP_TYPE_DISPLAY    0x01
#define EDP_TYPE_INFO	    0x02
#define EDP_TYPE_VLAN	    0x05
#define EDP_TYPE_ESRP	    0x08

#define EDP_VLAN_FLAG_IP    1 << 7

#endif /* _edp_h */
