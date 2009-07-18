/*
 $Id$
*/

#include "common.h"
#include "util.h"
#include "proto/cdp.h"
#include "proto/tlv.h"

size_t cdp_packet(void *packet, struct netif *netif, struct sysinfo *sysinfo) {

    struct ether_hdr ether;
    struct ether_llc llc;
    struct cdp_header cdp;

    char *tlv;
    char *pos = packet;
    size_t length = ETHER_MAX_LEN;
    tlv_t type;

    void *cdp_start;
    uint8_t cap = 0;
    uint8_t addr_count = 0;
    struct netif *master;

    const uint8_t cdp_dst[] = CDP_MULTICAST_ADDR;
    const uint8_t llc_org[] = LLC_ORG_CISCO;
    const struct cdp_proto cdp_protos[] = {
	ADDR_PROTO_CLNP, ADDR_PROTO_IPV4, ADDR_PROTO_IPV6,
    };

    // fixup master netif
    if (netif->master != NULL)
	master = netif->master;
    else
	master = netif;


    // ethernet header
    memcpy(ether.dst, cdp_dst, ETHER_ADDR_LEN);
    memcpy(ether.src, netif->hwaddr, ETHER_ADDR_LEN);
    pos += sizeof(struct ether_hdr);

    // llc snap header
    llc.dsap = llc.ssap = 0xaa;
    llc.control = 0x03;
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
	PUSH_BYTES(sysinfo->uts.sysname, strlen(sysinfo->uts.sysname))
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
		PUSH_UINT8(cdp_protos[CDP_ADDR_PROTO_IPV4].protocol_type) &&
		PUSH_UINT8(cdp_protos[CDP_ADDR_PROTO_IPV4].protocol_length) &&
		PUSH_BYTES(cdp_protos[CDP_ADDR_PROTO_IPV4].protocol,
			   cdp_protos[CDP_ADDR_PROTO_IPV4].protocol_length) &&
		PUSH_UINT16(sizeof(master->ipaddr4)) &&
		PUSH_BYTES(&master->ipaddr4, sizeof(master->ipaddr4))
	    ))
		return 0;
	}

	if (!IN6_IS_ADDR_UNSPECIFIED((struct in6_addr *)master->ipaddr6)) {
	    if (!(
		PUSH_UINT8(cdp_protos[CDP_ADDR_PROTO_IPV6].protocol_type) &&
		PUSH_UINT8(cdp_protos[CDP_ADDR_PROTO_IPV6].protocol_length) &&
		PUSH_BYTES(cdp_protos[CDP_ADDR_PROTO_IPV6].protocol,
			   cdp_protos[CDP_ADDR_PROTO_IPV6].protocol_length) &&
		PUSH_UINT16(sizeof(master->ipaddr6)) &&
		PUSH_BYTES(master->ipaddr6, sizeof(master->ipaddr6))
	    ))
		return 0;
	}

	END_CDP_TLV;
    }


    // mtu
    if (netif->mtu && !(
	START_CDP_TLV(CDP_TYPE_MTU) &&
	PUSH_UINT32(netif->mtu)
    ))
	return 0;
    END_CDP_TLV;


    // duplex
    if ((netif->duplex != -1) && !(
	START_CDP_TLV(CDP_TYPE_DUPLEX) &&
	PUSH_UINT8(netif->duplex)
    ))
	return 0;
    END_CDP_TLV;


    // location
    if ((strlen(sysinfo->location) != 0) && !(
	START_CDP_TLV(CDP_TYPE_LOCATION) &&
	PUSH_UINT8(0) &&
	PUSH_BYTES(sysinfo->location, strlen(sysinfo->location))
    ))
	return 0;
    END_CDP_TLV;


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

char * cdp_check(void *packet, size_t length) {
    struct ether_hdr ether;
    struct ether_llc llc;
    const uint8_t cdp_dst[] = CDP_MULTICAST_ADDR;
    const uint8_t cdp_org[] = LLC_ORG_CISCO;

    assert(packet);
    assert(length > (sizeof(ether) + sizeof(llc)));
    assert(length <= ETHER_MAX_LEN);

    memcpy(&ether, packet, sizeof(ether));
    memcpy(&llc, packet + sizeof(ether), sizeof(llc));

    if ((memcmp(ether.dst, cdp_dst, ETHER_ADDR_LEN) == 0) &&
	(memcmp(llc.org, cdp_org, sizeof(llc.org)) == 0) &&
	(llc.protoid == htons(LLC_PID_CDP))) {
	    return(packet + sizeof(ether) + sizeof(llc));
    }
    return(NULL);
}

size_t cdp_peer(struct master_msg *msg) {

    char *packet = NULL;
    size_t length;
    struct cdp_header cdp;

    char *tlv;
    char *pos;
    tlv_t type;

    uint16_t tlv_type;
    uint16_t tlv_length;

    char *hostname = NULL;

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
		if (!GRAB_STRING(hostname, tlv_length)) {
		    my_log(INFO, "Corrupt CDP packet: invalid System Name TLV");
		    return 0;
		}
		strlcpy(msg->peer.name, hostname, IFDESCRSIZE);
		free(hostname);
		break;
	default:
		my_log(DEBUG, "unknown TLV: type %d, length %d, leaves %d",
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

