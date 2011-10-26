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
#include "proto/edp.h"
#include "proto/tlv.h"


size_t edp_packet(void *packet, struct netif *netif,
	    struct nhead *netifs, struct sysinfo *sysinfo) {

    struct ether_hdr ether;
    struct ether_llc llc;
    struct edp_header edp = {};

    char *tlv;
    char *pos = packet;
    size_t length = ETHER_MAX_LEN;
    tlv_t type;

    static uint16_t edp_count = 0;

    void *edp_start;
    struct netif *master, *vlanif = NULL;
    uint8_t *hwaddr;

    const uint8_t edp_dst[] = EDP_MULTICAST_ADDR;
    const uint8_t llc_org[] = LLC_ORG_EXTREME;

    // fixup master netif
    if (netif->master != NULL)
	master = netif->master;
    else
	master = netif;

    // chassis id
    hwaddr = (options & OPT_CHASSIS_IF) ? netif->hwaddr : sysinfo->hwaddr;

    // ethernet header
    memcpy(ether.dst, edp_dst, ETHER_ADDR_LEN);
    memcpy(ether.src, netif->hwaddr, ETHER_ADDR_LEN);
    pos += sizeof(struct ether_hdr);

    // llc snap header
    llc.dsap = llc.ssap = LLC_SNAP_LSAP;
    llc.control = LLC_UI;
    memcpy(llc.org, llc_org, sizeof(llc.org));
    llc.protoid = htons(LLC_PID_EDP);
    memcpy(pos, &llc, sizeof(struct ether_llc));
    pos += sizeof(struct ether_llc);

    // edp header
    edp.version = 1;
    edp.sequence = htons(edp_count++);
    memcpy(&edp.hwaddr, hwaddr, ETHER_ADDR_LEN);
    edp_start = pos;

    // update tlv counters
    pos += sizeof(struct edp_header);
    length -= VOIDP_DIFF(pos, packet);


    // display
    if (!(
	START_EDP_TLV(EDP_TYPE_DISPLAY) &&
	PUSH_BYTES(sysinfo->hostname, strlen(sysinfo->hostname) + 1)
    ))
	return 0;
    END_EDP_TLV;


    // info
    if (!(
	START_EDP_TLV(EDP_TYPE_INFO) &&
	PUSH_UINT16(0) &&		    // slot
	PUSH_UINT16(netif->index) &&	    // port
	PUSH_UINT16(0) &&		    // chassis
	PUSH_UINT32(0) && PUSH_UINT16(0) && // reserved
	PUSH_UINT8(sysinfo->uts_rel[0]) && PUSH_UINT8(sysinfo->uts_rel[1]) &&
	PUSH_UINT8(sysinfo->uts_rel[2]) && PUSH_UINT8(0) &&
	PUSH_UINT16(0xffff) && PUSH_UINT16(0) &&
	PUSH_UINT32(0) && PUSH_UINT32(0) && PUSH_UINT32(0)
    ))
	return 0;
    END_EDP_TLV;


    // vlan
    if (master->ipaddr4 != 0) {
	if (!(
	    START_EDP_TLV(EDP_TYPE_VLAN) &&
	    PUSH_UINT8(EDP_VLAN_FLAG_IP) &&
	    PUSH_UINT8(0) &&	    // reserved
	    PUSH_UINT16(0) &&	    // vlan-id
	    PUSH_UINT32(0) &&	    // reserved
	    PUSH_BYTES(&master->ipaddr4, sizeof(master->ipaddr4)) &&
	    PUSH_BYTES(netif->name, strlen(netif->name)) &&
	    PUSH_UINT8(0)
	))
	    return 0;
	END_EDP_TLV;
    }

    while ((vlanif = netif_iter(vlanif, netifs)) != NULL) {
	if (vlanif->type != NETIF_VLAN)
	    continue;
    
	// skip unless attached to this interface or the parent
	if ((vlanif->vlan_parent != netif->index) &&
	    (vlanif->vlan_parent != master->index))
	    continue;

	if (!(
	    START_EDP_TLV(EDP_TYPE_VLAN) &&
	    PUSH_UINT8((vlanif->ipaddr4) ? EDP_VLAN_FLAG_IP : 0) &&
	    PUSH_UINT8(0) &&			    // reserved
	    PUSH_UINT16(vlanif->vlan_id) &&	    // vlan-id
	    PUSH_UINT32(0) &&			    // reserved
	    PUSH_BYTES(&vlanif->ipaddr4, sizeof(vlanif->ipaddr4)) &&
	    PUSH_BYTES(netif->name, strlen(netif->name))
	))
	    return 0;
	END_EDP_TLV;
    }

    // the end
    if (!(
	START_EDP_TLV(EDP_TYPE_NULL)
    ))
	return 0;
    END_EDP_TLV;


    // edp header
    edp.length = htons(VOIDP_DIFF(pos, edp_start));
    memcpy(edp_start, &edp, sizeof(struct edp_header));
    edp.checksum = my_chksum(edp_start, VOIDP_DIFF(pos, edp_start), 0);
    memcpy(edp_start, &edp, sizeof(struct edp_header));

    // ethernet header
    ether.type = htons(VOIDP_DIFF(pos, packet + sizeof(struct ether_hdr)));
    memcpy(packet, &ether, sizeof(struct ether_hdr));

    // packet length
    return(VOIDP_DIFF(pos, packet));
}

unsigned char * edp_check(void *packet, size_t length) {
    struct ether_hdr ether;
    uint8_t offset = 0;
    struct ether_llc llc;
    const uint8_t edp_dst[] = EDP_MULTICAST_ADDR;
    const uint8_t edp_org[] = LLC_ORG_EXTREME;

    assert(packet);
    assert(length > (sizeof(ether) + sizeof(llc)));
    assert(length <= ETHER_MAX_LEN);

    memcpy(&ether, packet, sizeof(ether));
    if (memcmp(ether.dst, edp_dst, ETHER_ADDR_LEN) != 0)
	return(NULL);
    if (ether.type == htons(ETHERTYPE_VLAN))
	offset = ETHER_VLAN_ENCAP_LEN;

    memcpy(&llc, packet + sizeof(ether) + offset, sizeof(llc));
    if ((llc.dsap != LLC_SNAP_LSAP) || (llc.ssap != LLC_SNAP_LSAP) ||
	(llc.control != LLC_UI))
	return(NULL);
    if ((memcmp(llc.org, edp_org, sizeof(llc.org)) == 0) &&
	(llc.protoid == htons(LLC_PID_EDP)))
	    return(packet + sizeof(ether) + offset + sizeof(llc));

    return(NULL);
}

size_t edp_decode(struct master_msg *msg) {

    unsigned char *packet = NULL;
    size_t length;
    struct edp_header edp;

    unsigned char *pos;
    tlv_t type;

    uint16_t tlv_type;
    uint16_t tlv_length;

    assert(msg);

    packet = msg->msg;
    length = msg->len;

    assert(packet);
    assert((pos = edp_check(packet, length)) != NULL);
    length -= VOIDP_DIFF(pos, packet);
    if (length < sizeof(edp)) {
	my_log(INFO, "missing EDP header");
	return 0;
    }

    memcpy(&edp, pos, sizeof(edp));
    if (edp.version != 1) {
	my_log(INFO, "unsupported EDP version");
	return 0;
    }
    // no ttl in edp available
    msg->ttl = LADVD_TTL;

    // update tlv counters
    pos += sizeof(edp);
    length -= sizeof(edp);

    while (length) {
	if (!GRAB_EDP_TLV(tlv_type, tlv_length)) {
	    my_log(INFO, "Corrupt EDP packet: invalid TLV");
	    return 0;
	}

	switch(tlv_type) {
	case EDP_TYPE_DISPLAY:
		if (!DECODE_STRING(msg, PEER_HOSTNAME, tlv_length)) {
		    my_log(INFO, "Corrupt EDP packet: invalid Display TLV");
		    return 0;
		}
		break;
	default:
		my_log(DEBUG, "unknown TLV: type %d, length %d, leaves %zu",
			    tlv_type, tlv_length, length);
		if (!SKIP(tlv_length)) {
		    my_log(INFO, "Corrupt EDP packet: invalid TLV length");
		    return 0;
		}
		break;
	}
    }

    // return the packet length
    return(VOIDP_DIFF(pos, packet));
}

