/*
 * $Id$
 *
 * Copyright (c) 2008, 2009
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

#ifndef _ether_h
#define _ether_h

#if HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif
#if HAVE_NET_ETHERTYPES_H
#include <net/ethertypes.h>
#endif

// IEEE 802.3 Ethernet
struct ether_hdr {
    uint8_t dst[ETHER_ADDR_LEN];
    uint8_t src[ETHER_ADDR_LEN];
    uint16_t type;
} __attribute__ ((__packed__));

#ifndef ETHER_HDR_LEN
#define ETHER_HDR_LEN	sizeof(struct ether_hdr)
#endif

// IEEE 802.2 LLC
struct ether_llc {
    uint8_t dsap;
    uint8_t ssap;
    uint8_t control;
    uint8_t org[3];
    uint16_t protoid;
} __attribute__ ((__packed__));

#define ETH_LLC_CONTROL	ETHER_HDR_LEN + 2
#define ETH_LLC_PROTOID	ETHER_HDR_LEN + 6

/* Should be defined in net/ethertypes.h */
#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN  0x8100
#endif
#ifndef ETHER_VLAN_ENCAP_LEN
#define ETHER_VLAN_ENCAP_LEN	4   /* len of 802.1Q VLAN encapsulation */
#endif
#ifndef ETHERTYPE_LLDP
#define ETHERTYPE_LLDP  0x88cc
#endif

#ifndef ETHER_IS_MULTICAST
#define ETHER_IS_MULTICAST(addr) (*(addr) & 0x01) /* is address mcast/bcast? */
#endif

#endif /* _ether_h */
