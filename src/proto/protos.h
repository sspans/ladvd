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

#ifndef _protos_h
#define _protos_h

#include "proto/lldp.h"
#include "proto/cdp.h"
#include "proto/edp.h"
#include "proto/fdp.h"
#include "proto/ndp.h"

#define PROTO_LLDP  0
#define PROTO_CDP   1
#define PROTO_EDP   2
#define PROTO_FDP   3
#define PROTO_NDP   4
#define PROTO_MAX   5


size_t lldp_packet(void *, struct netif *, struct nhead *, struct sysinfo *);
size_t cdp_packet(void *, struct netif *, struct nhead *, struct sysinfo *);
size_t edp_packet(void *, struct netif *, struct nhead *, struct sysinfo *);
size_t fdp_packet(void *, struct netif *, struct nhead *, struct sysinfo *);
size_t ndp_packet(void *, struct netif *, struct nhead *, struct sysinfo *);

unsigned char * lldp_check(void *, size_t);
unsigned char * cdp_check(void *, size_t);
unsigned char * edp_check(void *, size_t);
unsigned char * fdp_check(void *, size_t);
unsigned char * ndp_check(void *, size_t);

size_t lldp_decode(struct master_msg *msg);
size_t cdp_decode(struct master_msg *msg);
size_t edp_decode(struct master_msg *msg);
size_t fdp_decode(struct master_msg *msg);
size_t ndp_decode(struct master_msg *msg);

#endif /* _protos_h */
