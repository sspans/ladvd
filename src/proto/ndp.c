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
#include "proto/ndp.h"
#include "proto/tlv.h"


size_t ndp_packet(void *packet, struct netif *netif, struct sysinfo *sysinfo) {

    struct ether_hdr ether;
    struct ether_llc llc;
    struct ndp_header ndp;

    uint8_t *pos = packet;

    struct netif *master;

    const uint8_t ndp_dst[] = NDP_MULTICAST_ADDR;
    const uint8_t llc_org[] = LLC_ORG_NORTEL;

    // fixup master netif
    if (netif->master != NULL)
	master = netif->master;
    else
	master = netif;

    // ethernet header
    memcpy(ether.dst, ndp_dst, ETHER_ADDR_LEN);
    memcpy(ether.src, netif->hwaddr, ETHER_ADDR_LEN);
    pos += sizeof(struct ether_hdr);

    // llc snap header
    llc.dsap = llc.ssap = LLC_SNAP_LSAP;
    llc.control = LLC_UI;
    memcpy(llc.org, llc_org, sizeof(llc.org));
    llc.protoid = htons(LLC_PID_NDP_HELLO);
    memcpy(pos, &llc, sizeof(struct ether_llc));
    pos += sizeof(struct ether_llc);

    // ndp header
    memset(&ndp, 0, sizeof(struct ndp_header));
    ndp.addr = master->ipaddr4;
    ndp.seg[2] = netif->index;
    ndp.chassis = NDP_CHASSIS_OTHER;
    ndp.backplane = NDP_BACKPLANE_ETH_FE_GE;
    ndp.links = sysinfo->physif_count;
    ndp.state = NDP_TOPOLOGY_NEW;
    memcpy(pos, &ndp, sizeof(struct ndp_header));
    pos += sizeof(struct ndp_header);


    // ethernet header
    ether.type = htons(VOIDP_DIFF(pos, packet + sizeof(struct ether_hdr)));
    memcpy(packet, &ether, sizeof(struct ether_hdr));

    // packet length
    return(VOIDP_DIFF(pos, packet));
}

char * ndp_check(void *packet, size_t length) {
    struct ether_hdr ether;
    uint8_t offset = 0;
    struct ether_llc llc;
    const uint8_t ndp_dst[] = NDP_MULTICAST_ADDR;
    const uint8_t ndp_org[] = LLC_ORG_NORTEL;

    assert(packet);
    assert(length > (sizeof(ether) + sizeof(llc)));
    assert(length <= ETHER_MAX_LEN);

    memcpy(&ether, packet, sizeof(ether));
    if (memcmp(ether.dst, ndp_dst, ETHER_ADDR_LEN) != 0)
	return(NULL);
    if (ether.type == htons(ETHERTYPE_VLAN))
	offset = ETHER_VLAN_ENCAP_LEN;

    memcpy(&llc, packet + sizeof(ether) + offset, sizeof(llc));
    if ((llc.dsap != LLC_SNAP_LSAP) || (llc.ssap != LLC_SNAP_LSAP) ||
	(llc.control != LLC_UI))
	return(NULL);
    if ((memcmp(llc.org, ndp_org, sizeof(llc.org)) == 0) &&
	(llc.protoid == htons(LLC_PID_NDP_HELLO)))
	    return(packet + sizeof(ether) + offset + sizeof(llc));

    return(NULL);
}

size_t ndp_decode(struct master_msg *msg) {
    char *packet = NULL;
    size_t length;
    struct ndp_header ndp;

    char *pos, *str;

    assert(msg);

    packet = msg->msg;
    length = msg->len;

    assert(packet);
    assert((pos = ndp_check(packet, length)) != NULL);
    length -= VOIDP_DIFF(pos, packet);
    if (length < sizeof(ndp)) {
	my_log(INFO, "missing NDP header");
	return 0;
    }

    memcpy(&ndp, pos, sizeof(ndp));
    str = my_malloc(INET_ADDRSTRLEN);
    if (!inet_ntop(AF_INET, &ndp.addr, str, INET_ADDRSTRLEN)) {
	my_log(INFO, "failed to copy peer addr");
	free(str);
	return 0;
    } else {
	msg->peer[PEER_IPV4] = str;
    }

    // XXX: this should be improved
    msg->ttl = LADVD_TTL;


    // update tlv counters
    pos += sizeof(ndp);
    length -= sizeof(ndp);

    // return the packet length
    return(VOIDP_DIFF(pos, packet));
}
