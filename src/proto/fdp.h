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

#ifndef _fdp_h
#define _fdp_h

#define FDP_VERSION 1
#define FDP_MULTICAST_ADDR { 0x01, 0xe0, 0x52, 0xcc, 0xcc, 0xcc }
#define LLC_ORG_FOUNDRY { 0x00, 0xe0, 0x52 }
#define LLC_PID_FDP 0x2000

struct fdp_header {
    uint8_t version;
    uint8_t ttl;
    uint16_t checksum;
} __attribute__ ((__packed__));

// FDP TLV Types
#define FDP_TYPE_DEVICE_ID	0x0001
#define FDP_TYPE_ADDRESS	0x0002
#define FDP_TYPE_PORT_ID	0x0003
#define FDP_TYPE_CAPABILITIES	0x0004
#define FDP_TYPE_SW_VERSION	0x0005
#define FDP_TYPE_PLATFORM	0x0006
#define FDP_TYPE_UNKNOWN_101	0x0101
#define FDP_TYPE_UNKNOWN_102	0x0102

#endif /* _fdp_h */
