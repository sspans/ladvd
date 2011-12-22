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
#include "proto/cdp.h"
#include "proto/tlv.h"

const struct cdp_proto cdp_protos[] = {
    ADDR_PROTO_CLNP, ADDR_PROTO_IPV4, ADDR_PROTO_IPV6,
};

size_t cdp_packet(void *packet, struct netif *netif,
		struct nhead *netifs, struct sysinfo *sysinfo) {

    struct ether_hdr ether;
    struct ether_llc llc;
    struct cdp_header cdp;

    char *tlv;
    char *pos = packet;
    size_t length = ETHER_MAX_LEN;
    tlv_t type;

    void *cdp_start;
    uint8_t cap = 0;
    uint32_t addr_count = 0;
    struct netif *master, *mgmt;

    const uint8_t cdp_dst[] = CDP_MULTICAST_ADDR;
    const uint8_t llc_org[] = LLC_ORG_CISCO;

    // fixup master netif
    if (netif->master != NULL)
	master = netif->master;
    else
	master = netif;

    // configure managment interface
    mgmt = sysinfo->mnetif;
    if (!mgmt)
	mgmt = master;


    // ethernet header
    memcpy(ether.dst, cdp_dst, ETHER_ADDR_LEN);
    memcpy(ether.src, netif->hwaddr, ETHER_ADDR_LEN);
    pos += sizeof(struct ether_hdr);

    // llc snap header
    llc.dsap = llc.ssap = LLC_SNAP_LSAP;
    llc.control = LLC_UI;
    memcpy(llc.org, llc_org, sizeof(llc.org));
    llc.protoid = htons(LLC_PID_CDP);
    memcpy(pos, &llc, sizeof(struct ether_llc));
    pos += sizeof(struct ether_llc);

    // cdp header
    cdp.version = CDP_VERSION;
    cdp.ttl = LADVD_TTL;
    cdp.checksum = 0;
    memcpy(pos, &cdp, sizeof(struct cdp_header));
    cdp_start = pos;

    // update tlv counters
    pos += sizeof(struct cdp_header);
    length -= VOIDP_DIFF(pos, packet);


    // device id
    if (!(
	START_CDP_TLV(CDP_TYPE_DEVICE_ID) &&
	PUSH_BYTES(sysinfo->hostname, strlen(sysinfo->hostname))
    ))
	return 0;
    END_CDP_TLV;


    // version
    if (!(
	START_CDP_TLV(CDP_TYPE_IOS_VERSION) &&
	PUSH_BYTES(sysinfo->uts_str, strlen(sysinfo->uts_str))
    ))
	return 0;
    END_CDP_TLV;


    // platform
    if (!(
	START_CDP_TLV(CDP_TYPE_PLATFORM) &&
	PUSH_BYTES(sysinfo->platform, strlen(sysinfo->platform))
    ))
	return 0;
    END_CDP_TLV;


    // port id
    if (!(
	START_CDP_TLV(CDP_TYPE_PORT_ID) &&
	PUSH_BYTES(netif->name, strlen(netif->name))
    ))
	return 0;
    END_CDP_TLV;


    // capabilities
    if (sysinfo->cap_active == CAP_HOST) {
	cap = CDP_CAP_HOST;
    } else {
	cap |= (sysinfo->cap_active & CAP_BRIDGE) ? CDP_CAP_TRANSPARENT_BRIDGE : 0;
	cap |= (sysinfo->cap_active & CAP_ROUTER) ? CDP_CAP_ROUTER : 0;
	cap |= (sysinfo->cap_active & CAP_SWITCH) ? CDP_CAP_SWITCH : 0;
    }

    if (!(
	START_CDP_TLV(CDP_TYPE_CAPABILITIES) &&
	PUSH_UINT32(cap)
    ))
	return 0;
    END_CDP_TLV;


    // management addrs
    if (mgmt->ipaddr4 != 0)
	addr_count++;
    if (!IN6_IS_ADDR_UNSPECIFIED((struct in6_addr *)mgmt->ipaddr6)) 
	addr_count++;

    if (addr_count > 0) {
	if (!(
	    START_CDP_TLV(CDP_TYPE_ADDRESS) &&
	    PUSH_UINT32(addr_count)
	))
	    return 0;

	if (mgmt->ipaddr4 != 0) {
	    if (!(
		PUSH_UINT8(cdp_protos[CDP_ADDR_IPV4].protocol_type) &&
		PUSH_UINT8(cdp_protos[CDP_ADDR_IPV4].protocol_length) &&
		PUSH_BYTES(cdp_protos[CDP_ADDR_IPV4].protocol,
			   cdp_protos[CDP_ADDR_IPV4].protocol_length) &&
		PUSH_UINT16(sizeof(mgmt->ipaddr4)) &&
		PUSH_BYTES(&mgmt->ipaddr4, sizeof(mgmt->ipaddr4))
	    ))
		return 0;
	}

	if (!IN6_IS_ADDR_UNSPECIFIED((struct in6_addr *)mgmt->ipaddr6)) {
	    if (!(
		PUSH_UINT8(cdp_protos[CDP_ADDR_IPV6].protocol_type) &&
		PUSH_UINT8(cdp_protos[CDP_ADDR_IPV6].protocol_length) &&
		PUSH_BYTES(cdp_protos[CDP_ADDR_IPV6].protocol,
			   cdp_protos[CDP_ADDR_IPV6].protocol_length) &&
		PUSH_UINT16(sizeof(mgmt->ipaddr6)) &&
		PUSH_BYTES(mgmt->ipaddr6, sizeof(mgmt->ipaddr6))
	    ))
		return 0;
	}

	END_CDP_TLV;
    }


    // mtu
    if (netif->mtu) {
	if (!(
	    START_CDP_TLV(CDP_TYPE_MTU) &&
	    PUSH_UINT32(netif->mtu)
	))
	    return 0;
	END_CDP_TLV;
    }


    // duplex
    if (netif->duplex != -1) {
	if (!(
	    START_CDP_TLV(CDP_TYPE_DUPLEX) &&
	    PUSH_UINT8(netif->duplex)
	))
	    return 0;
	END_CDP_TLV;
    }


    // location
    if (strlen(sysinfo->location) != 0) {
	if (!(
	    START_CDP_TLV(CDP_TYPE_LOCATION) &&
	    PUSH_UINT8(0) &&
	    PUSH_BYTES(sysinfo->location, strlen(sysinfo->location))
	))
	    return 0;
	END_CDP_TLV;
    }


    // workaround cisco crc bug (>0x80 in last uneven byte)
    // by having system_name tlv at the end
    if (!(
	START_CDP_TLV(CDP_TYPE_SYSTEM_NAME) &&
	PUSH_BYTES(sysinfo->hostname, strlen(sysinfo->hostname))
    ))
	return 0;
    END_CDP_TLV;


    // cdp header
    cdp.checksum = my_chksum(cdp_start, VOIDP_DIFF(pos, cdp_start), 1);
    memcpy(cdp_start, &cdp, sizeof(struct cdp_header));

    // ethernet header
    ether.type = htons(VOIDP_DIFF(pos, packet + sizeof(struct ether_hdr)));
    memcpy(packet, &ether, sizeof(struct ether_hdr));

    // packet length
    return(VOIDP_DIFF(pos, packet));
}

unsigned char * cdp_check(void *packet, size_t length) {
    struct ether_hdr ether;
    uint8_t offset = 0;
    struct ether_llc llc;
    const uint8_t cdp_dst[] = CDP_MULTICAST_ADDR;
    const uint8_t cdp_org[] = LLC_ORG_CISCO;

    assert(packet);
    assert(length > (sizeof(ether) + sizeof(llc)));
    assert(length <= ETHER_MAX_LEN);

    memcpy(&ether, packet, sizeof(ether));
    if (memcmp(ether.dst, cdp_dst, ETHER_ADDR_LEN) != 0)
	return(NULL);
    if (ether.type == htons(ETHERTYPE_VLAN))
	offset = ETHER_VLAN_ENCAP_LEN;

    memcpy(&llc, packet + sizeof(ether) + offset, sizeof(llc));
    if ((llc.dsap != LLC_SNAP_LSAP) || (llc.ssap != LLC_SNAP_LSAP) ||
	(llc.control != LLC_UI))
	return(NULL);
    if ((memcmp(llc.org, cdp_org, sizeof(llc.org)) == 0) &&
	(llc.protoid == htons(LLC_PID_CDP))) 
	    return(packet + sizeof(ether) + offset + sizeof(llc));

    return(NULL);
}

size_t cdp_decode(struct master_msg *msg) {

    unsigned char *packet = NULL;
    size_t length;
    struct cdp_header cdp;

    unsigned char *pos;
    tlv_t type;

    uint16_t tlv_type;
    uint16_t tlv_length;

    uint32_t cdp_cap = 0;
    uint16_t cap = 0;

    uint32_t addr_count = 0;
    int pt, pl, al, peer_addr;

    assert(msg);

    packet = msg->msg;
    length = msg->len;

    assert(packet);
    assert((pos = cdp_check(packet, length)) != NULL);
    length -= VOIDP_DIFF(pos, packet);
    if (length < sizeof(cdp)) {
	my_log(INFO, "missing CDP header");
	return 0;
    }

    memcpy(&cdp, pos, sizeof(cdp));
    if ((cdp.version < 1) || (cdp.version > 2)) {
	my_log(INFO, "invalid CDP version");
	return 0;
    }
    msg->ttl = cdp.ttl;

    // update tlv counters
    pos += sizeof(cdp);
    length -= sizeof(cdp);

    while (length) {
	if (!GRAB_CDP_TLV(tlv_type, tlv_length)) {
	    my_log(INFO, "Corrupt CDP packet: invalid TLV");
	    return 0;
	}

	switch(tlv_type) {
	case CDP_TYPE_DEVICE_ID:
	case CDP_TYPE_SYSTEM_NAME:
	    if (!DECODE_STRING(msg, PEER_HOSTNAME, tlv_length)) {
		my_log(INFO, "Corrupt CDP packet: invalid System Name TLV");
		return 0;
	    }
	    break;
	case CDP_TYPE_PORT_ID:
	    if (!DECODE_STRING(msg, PEER_PORTNAME, tlv_length)) {
		my_log(INFO, "Corrupt CDP packet: invalid Port ID TLV");
		return 0;
	    }
	    break;
	case CDP_TYPE_CAPABILITIES:
	    if ((tlv_length != 4) || !GRAB_UINT32(cdp_cap)) {
		my_log(INFO, "Corrupt CDP packet: invalid Cap TLV");
		return 0;
	    }
	    cap |= (cdp_cap & CDP_CAP_ROUTER) ? CAP_ROUTER : 0;
	    cap |= (cdp_cap & CDP_CAP_TRANSPARENT_BRIDGE) ? CAP_BRIDGE : 0;
	    cap |= (cdp_cap & CDP_CAP_SOURCE_BRIDGE) ? CAP_BRIDGE : 0;
	    cap |= (cdp_cap & CDP_CAP_SWITCH) ? CAP_SWITCH : 0;
	    cap |= (cdp_cap & CDP_CAP_HOST) ? CAP_HOST : 0;
	    cap |= (cdp_cap & CDP_CAP_REPEATER) ? CAP_REPEATER : 0;
	    cap |= (cdp_cap & CDP_CAP_PHONE) ? CAP_PHONE : 0;
	    tlv_value_str(msg, PEER_CAP, sizeof(cap), &cap);
	    break;
	case CDP_TYPE_ADDRESS:
	    if (!GRAB_UINT32(addr_count)) {
		my_log(INFO, "Corrupt CDP packet: invalid address TLV");
		return 0;
	    }
	    tlv_length -= 4;

	    next_addr:
	    if (!GRAB_UINT8(pt) || !GRAB_UINT8(pl)) {
		my_log(INFO, "Corrupt CDP packet: invalid address TLV");
		return 0;
	    }
	    tlv_length -= 2;

	    if (tlv_length < (pl + sizeof(uint16_t))) {
		my_log(INFO, "Corrupt CDP packet: invalid address TLV");
		return 0;
	    }

	    peer_addr = 0;
	    // v4
	    if ((pt == cdp_protos[CDP_ADDR_IPV4].protocol_type) &&
		(pl == cdp_protos[CDP_ADDR_IPV4].protocol_length)) {
		if (memcmp(pos, cdp_protos[CDP_ADDR_IPV4].protocol, pl) == 0)
		    peer_addr = PEER_ADDR_INET4;
	    // v6
	    } else if ((pt == cdp_protos[CDP_ADDR_IPV6].protocol_type) &&
		(pl == cdp_protos[CDP_ADDR_IPV6].protocol_length)) {
		if (memcmp(pos, cdp_protos[CDP_ADDR_IPV6].protocol, pl) == 0)
		    peer_addr = PEER_ADDR_INET6;
	    } 

	    if (!SKIP(pl) || !GRAB_UINT16(al)) {
		my_log(INFO, "Corrupt CDP packet: invalid TLV length 1");
		return 0;
	    }
	    tlv_length -= pl + sizeof(uint16_t);

	    if (peer_addr) {
		if (!DECODE_STRING(msg, peer_addr, al)) {
		    my_log(INFO, "Corrupt CDP packet: invalid address TLV");
		    return 0;
		}
	    } else if (!SKIP(al)) {
		my_log(INFO, "Corrupt CDP packet: invalid TLV length");
		return 0;
	    }

	    tlv_length -= al;
	    addr_count--;
	    if (tlv_length && addr_count > 0)
		goto next_addr;
	    break;
	case CDP_TYPE_IOS_VERSION:
	case CDP_TYPE_PLATFORM:
	case CDP_TYPE_MTU:
	case CDP_TYPE_DUPLEX:
	    // XXX: todo
	default:
	    my_log(DEBUG, "unknown TLV: type %d, length %d, leaves %zu",
			    tlv_type, tlv_length, length);
	    if (!SKIP(tlv_length)) {
		my_log(INFO, "Corrupt CDP packet: invalid TLV length");
		return 0;
	    }
	    break;
	}
    }

    // return the packet length
    return(VOIDP_DIFF(pos, packet));
}

