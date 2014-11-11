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
#include "proto/protos.h"
#include "proto/tlv.h"

const struct cdp_proto cdp_protos[] = {
    ADDR_PROTO_CLNP, ADDR_PROTO_IPV4, ADDR_PROTO_IPV6,
};

struct type_str {
    int t;                  /* type */
    const char *s;          /* string */
};

static const struct type_str cdp_tlv_types[] = {
    { CDP_TYPE_DEVICE_ID, "Device-ID"},
    { CDP_TYPE_ADDRESS, "Address"},
    { CDP_TYPE_PORT_ID, "Port-ID"},
    { CDP_TYPE_CAPABILITIES, "Capability"},
    { CDP_TYPE_IOS_VERSION, "Version"},
    { CDP_TYPE_PLATFORM, "Platform"},
    { CDP_TYPE_IP_PREFIX, "Prefixes"},
    { CDP_TYPE_PROTOCOL_HELLO, "Protocol-Hello option"},
    { CDP_TYPE_VTP_MGMT_DOMAIN, "VTP Management Domain"},
    { CDP_TYPE_NATIVE_VLAN, "Native VLAN ID"},
    { CDP_TYPE_DUPLEX, "Duplex"},
    { CDP_TYPE_APPLIANCE_REPLY, "ATA-186 VoIP VLAN request"},
    { CDP_TYPE_APPLIANCE_QUERY, "ATA-186 VoIP VLAN assignment"},
    { CDP_TYPE_POWER_CONSUMPTION, "power consumption"},
    { CDP_TYPE_MTU, "MTU"},
    { CDP_TYPE_EXTENDED_TRUST, "AVVID trust bitmap"},
    { CDP_TYPE_UNTRUSTED_COS, "AVVID untrusted ports CoS"},
    { CDP_TYPE_SYSTEM_NAME, "System Name"},
    { CDP_TYPE_SYSTEM_OID, "System Object ID"},
    { CDP_TYPE_MGMT_ADDRESS, "Management Addresses"},
    { CDP_TYPE_LOCATION, "Physical Location"},
    { 0, NULL}
};

static tlv_t type;
static int cdp_header_check(struct master_msg *, unsigned char *, size_t);
static int cdp_system_name(struct master_msg *, unsigned char *, size_t,
			    uint16_t);
static int cdp_port_id(struct master_msg *, unsigned char *, size_t);
static int cdp_system_cap(struct master_msg *, unsigned char *, size_t);
static int cdp_addr(struct master_msg *, unsigned char *, size_t, uint16_t);
static int cdp_vlan(struct master_msg *, unsigned char *, size_t);
static int cdp_descr_print(uint16_t, unsigned char *, size_t);
static int cdp_vtp_print(struct master_msg *, unsigned char *, size_t);
static int cdp_duplex_print(struct master_msg *, unsigned char *, size_t);


size_t cdp_packet(uint8_t proto, void *packet, struct netif *netif,
		struct nhead *netifs, struct my_sysinfo *sysinfo) {

    struct ether_hdr ether;
    struct ether_llc llc;
    struct cdp_header cdp;

    char *tlv;
    char *pos = packet;
    size_t length = ETHER_MAX_LEN;

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
    if (proto == PROTO_CDP1)
	cdp.version = CDP1_VERSION;
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


    // interface addrs
    addr_count = 0;
    if (master->ipaddr4 != 0)
	addr_count++;
    if (!IN6_IS_ADDR_UNSPECIFIED((struct in6_addr *)master->ipaddr6)) 
	addr_count++;

    if (addr_count > 0) {
	if (!(
	    START_CDP_TLV(CDP_TYPE_ADDRESS) &&
	    PUSH_UINT32(addr_count)
	))
	    return 0;

	if (master->ipaddr4 != 0) {
	    if (!(
		PUSH_UINT8(cdp_protos[CDP_ADDR_IPV4].protocol_type) &&
		PUSH_UINT8(cdp_protos[CDP_ADDR_IPV4].protocol_length) &&
		PUSH_BYTES(cdp_protos[CDP_ADDR_IPV4].protocol,
			   cdp_protos[CDP_ADDR_IPV4].protocol_length) &&
		PUSH_UINT16(sizeof(master->ipaddr4)) &&
		PUSH_BYTES(&master->ipaddr4, sizeof(master->ipaddr4))
	    ))
		return 0;
	}

	if (!IN6_IS_ADDR_UNSPECIFIED((struct in6_addr *)master->ipaddr6)) {
	    if (!(
		PUSH_UINT8(cdp_protos[CDP_ADDR_IPV6].protocol_type) &&
		PUSH_UINT8(cdp_protos[CDP_ADDR_IPV6].protocol_length) &&
		PUSH_BYTES(cdp_protos[CDP_ADDR_IPV6].protocol,
			   cdp_protos[CDP_ADDR_IPV6].protocol_length) &&
		PUSH_UINT16(sizeof(master->ipaddr6)) &&
		PUSH_BYTES(master->ipaddr6, sizeof(master->ipaddr6))
	    ))
		return 0;
	}

	END_CDP_TLV;
    }


    // management addrs
    addr_count = 0;
    if (mgmt && (mgmt->ipaddr4 != 0))
	addr_count++;
    if (mgmt && !IN6_IS_ADDR_UNSPECIFIED((struct in6_addr *)mgmt->ipaddr6)) 
	addr_count++;

    if (addr_count > 0) {
	if (!(
	    START_CDP_TLV(CDP_TYPE_MGMT_ADDRESS) &&
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

    unsigned char *pos;

    uint16_t tlv_type;
    uint16_t tlv_length;

    assert(msg);

    packet = msg->msg;
    length = msg->len;

    assert(packet);
    assert((pos = cdp_check(packet, length)) != NULL);
    length -= VOIDP_DIFF(pos, packet);

    if (!cdp_header_check(msg, pos, length))
	return 0;

    // update tlv counters
    pos += sizeof(struct cdp_header);
    length -= sizeof(struct cdp_header);

    while (length) {
	if (!GRAB_CDP_TLV(tlv_type, tlv_length)) {
	    my_log(INFO, "Corrupt CDP packet: invalid TLV");
	    return 0;
	}

        if (length < tlv_length) {
	    my_log(INFO, "Corrupt CDP packet: invalid TLV length");
	    return 0;
	}

	switch(tlv_type) {
	    case CDP_TYPE_DEVICE_ID:
	    case CDP_TYPE_SYSTEM_NAME:
		if (!cdp_system_name(msg, pos, tlv_length, tlv_type))
		    return 0;
		break;
	    case CDP_TYPE_PORT_ID:
		if (!cdp_port_id(msg, pos, tlv_length))
		    return 0;
		break;
	    case CDP_TYPE_CAPABILITIES:
		if (!cdp_system_cap(msg, pos, tlv_length))
		    return 0;
		break;
	    break;
	    case CDP_TYPE_ADDRESS:
	    case CDP_TYPE_MGMT_ADDRESS:
		if (!cdp_addr(msg, pos, tlv_length, tlv_type))
		    return 0;
		break;
	    case CDP_TYPE_IOS_VERSION:
	    case CDP_TYPE_PLATFORM:
		if ((msg->decode == DECODE_PRINT) && 
		    !cdp_descr_print(tlv_type, pos, tlv_length))
		    return 0;
		break;
	    case CDP_TYPE_VTP_MGMT_DOMAIN:
		if ((msg->decode == DECODE_PRINT) && 
		    !cdp_vtp_print(msg, pos, tlv_length))
		    return 0;
		break;
	    case CDP_TYPE_NATIVE_VLAN:
		if (!cdp_vlan(msg, pos, tlv_length))
		    return 0;
		break;
	    case CDP_TYPE_DUPLEX:
		if ((msg->decode == DECODE_PRINT) && 
		    !cdp_duplex_print(msg, pos, tlv_length))
		    return 0;
		break;
	    case CDP_TYPE_MTU:
		// XXX: todo
	    default:
		my_log(DEBUG, "unknown TLV: type %d, length %d, leaves %zu",
			    tlv_type, tlv_length, length);
		break;
	}

	if (!SKIP(tlv_length)) {
	    my_log(INFO, "Corrupt CDP packet: invalid TLV length");
	    return 0;
	}
    }

    // return the packet length
    return(VOIDP_DIFF(pos, packet));
}

static int cdp_header_check(struct master_msg *msg, 
    unsigned char *pos, size_t length) {

    struct cdp_header cdp;
    time_t now;
    uint16_t holdtime;

    if (length < sizeof(cdp)) {
	my_log(INFO, "missing CDP header");
	return 0;
    }

    memcpy(&cdp, pos, sizeof(cdp));
    if ((cdp.version < 1) || (cdp.version > 2)) {
	my_log(INFO, "invalid CDP version");
	return 0;
    }

    // update proto based on CDP version
    msg->proto = PROTO_CDP;
    if (cdp.version == 1)
	msg->proto = PROTO_CDP1;

    msg->ttl = cdp.ttl;

    if ((now = time(NULL)) == (time_t)-1)
	my_fatale("failed to fetch time");

    holdtime = msg->ttl - (now - msg->received);

    if (msg->decode == DECODE_PRINT)
    	printf("CDP Version: %u\nHoldtime: %" PRIu16 "\n",
	    cdp.version, holdtime);

    return 1;
}

static int cdp_system_name(struct master_msg *msg, 
    unsigned char *pos, size_t length, uint16_t tlv_type) {

    char *str = NULL;

    str = tlv_str_copy(pos, length);

    if (msg->decode == DECODE_PRINT) {
    	printf("%s: %s\n", 
	    (tlv_type == CDP_TYPE_DEVICE_ID)? "Device ID":"System Name", str);
	free(str);
    } else {
	PEER_STR(msg->peer[PEER_HOSTNAME], str);
    }

    return 1;
}

static int cdp_port_id(struct master_msg *msg, 
    unsigned char *pos, size_t length) {

    char *str = NULL;

    str = tlv_str_copy(pos, length);

    if (msg->decode == DECODE_PRINT) {
	printf("Interface: %s, Port ID (outgoing port): %s\n",
	    msg->name, str);
	free(str);
    } else {
	PEER_STR(msg->peer[PEER_PORTNAME], str);
    }

    return 1;
}

static int cdp_descr_print(uint16_t tlv_type,
    unsigned char *pos, size_t length) {

    const struct type_str *token;
    const char *type_str = NULL;
    char *str = NULL, *token_str = NULL;

    token = cdp_tlv_types;

    while (token->s != NULL) {
        if (token->t == tlv_type) {
            type_str = token->s;
	    break;
	}
        ++token;
    }
    if (!type_str)
	type_str = "Unknown";

    str = tlv_str_copy(pos, length);
    if (strchr(str, '\n')) {
	printf("%s:\n", type_str);
	while ((token_str = strsep(&str, "\n")) != NULL)
	    printf("  %s\n", token_str);
    } else {
	printf("%s: %s\n", type_str, str);
    }
    free(str);

    return 1;
}

static int cdp_system_cap(struct master_msg *msg,
    unsigned char *pos, size_t length) {

    uint32_t cdp_cap = 0;
    uint16_t cap = 0;
    char *str = NULL;

    if ((length != 4) || !GRAB_UINT32(cdp_cap)) {
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

    str = tlv_str_cap(cap);
    if (msg->decode == DECODE_PRINT) {
        printf("Capabilities: %s\n", str);
        free(str);
    } else {
        PEER_STR(msg->peer[PEER_CAP], str);
    }

    return 1;
}

static int cdp_addr(struct master_msg *msg,
    unsigned char *pos, size_t length, uint16_t tlv_type) {

    char *str = NULL;
    uint32_t addr_count = 0;
    int pt, pl, al, af;

    if (!GRAB_UINT32(addr_count)) {
	my_log(INFO, "Corrupt CDP packet: invalid address TLV");
	return 0;
    }

    if (msg->decode == DECODE_PRINT)
	printf("%s address(es):\n", 
	    (tlv_type == CDP_TYPE_MGMT_ADDRESS) ? "Management":"Entry");

next_addr:
    if (!GRAB_UINT8(pt) || !GRAB_UINT8(pl)) {
	my_log(INFO, "Corrupt CDP packet: invalid address TLV");
	return 0;
    }

    if (length < (pl + sizeof(uint16_t))) {
	my_log(INFO, "Corrupt CDP packet: invalid address TLV");
	return 0;
    }

    af = 0;
    // v4
    if ((pt == cdp_protos[CDP_ADDR_IPV4].protocol_type) &&
	(pl == cdp_protos[CDP_ADDR_IPV4].protocol_length)) {
	if (memcmp(pos, cdp_protos[CDP_ADDR_IPV4].protocol, pl) == 0)
	    af = PEER_ADDR_INET4;
    // v6
    } else if ((pt == cdp_protos[CDP_ADDR_IPV6].protocol_type) &&
	(pl == cdp_protos[CDP_ADDR_IPV6].protocol_length)) {
	if (memcmp(pos, cdp_protos[CDP_ADDR_IPV6].protocol, pl) == 0)
	    af = PEER_ADDR_INET6;
    } 

    if (!SKIP(pl) || !GRAB_UINT16(al)) {
	my_log(INFO, "Corrupt CDP packet: invalid TLV length");
	return 0;
    }

    if (length < al) {
	my_log(INFO, "Corrupt CDP packet: invalid address TLV");
	return 0;
    }

    if (af) {
	if ((str = tlv_str_addr(af, pos, al)) == NULL) {
	    my_log(INFO, "Corrupt CDP packet: invalid address TLV");
	    return 0;
	}

	if (msg->decode == DECODE_PRINT) {
	    printf("  IP%s address: %s\n", 
		(af == PEER_ADDR_INET6)? "v6":"", str);
	    free(str);
	} else {
	    PEER_STR(msg->peer[af], str);
	}
    } 
    if (!SKIP(al)) {
	my_log(INFO, "Corrupt CDP packet: invalid TLV length");
	return 0;
    }

    addr_count--;
    if (length && addr_count > 0)
	goto next_addr;

    return 1;
}

static int cdp_vlan(struct master_msg *msg, 
    unsigned char *pos, size_t length) {

    char *str = NULL;
    uint16_t vlan = 0;

    if ((length != 2) || !GRAB_UINT16(vlan)) {
	my_log(INFO, "Corrupt CDP packet: invalid Native VLAN TLV");
	return 0;
    }

    if (msg->decode == DECODE_PRINT)
	printf("Native VLAN: %" PRIu16 "\n", vlan);
    else
	if (asprintf(&str, "%" PRIu16, vlan) > 0)
	    PEER_STR(msg->peer[PEER_VLAN_ID], str);

    return 1;
}

static int cdp_vtp_print(struct master_msg *msg, 
    unsigned char *pos, size_t length) {

    char *str = NULL;

    str = tlv_str_copy(pos, length);
    printf("VTP Management Domain: '%s'\n", str);
    free(str);

    return 1;
}

static int cdp_duplex_print(struct master_msg *msg, 
    unsigned char *pos, size_t length) {

    uint8_t duplex = 0;

    if ((length != 1) || !GRAB_UINT8(duplex)) {
	my_log(INFO, "Corrupt CDP packet: invalid Duplex TLV");
	return 0;
    }

    printf("Duplex: %s\n", (duplex)? "full":"half");

    return 1;
}

