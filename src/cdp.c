/*
 $Id$
*/

#include "main.h"
#include "util.h"
#include "cdp.h"
#include "tlv.h"

static uint8_t cdp_version = 2;
static uint8_t cdp_dst[] = { 0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc };
static uint8_t cdp_snap[] = { 0x00, 0x00, 0x0c, 0x20, 0x00 };

/*
 * Actually, this is the standard IP checksum algorithm.
 */
uint16_t cdp_checksum(void *data, size_t length) {
    register uint32_t sum = 0;
    register const uint16_t *d = (const uint16_t *)data;

    while (length > 1) {
	sum += *d++;
	length -= 2;
    }
    if (length)
	sum += htons(*(const uint8_t *)d);
	
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}

int cdp_packet(struct packet *packet, struct netif *netif,
	       struct sysinfo *sysinfo) {

    size_t length;
    uint8_t *pos, *tlv;
    uint8_t cap = 0;

    void *cdp_pos, *checksum_pos;
    uint8_t addr_count = 0;
    struct netif *master;

    // init
    memset(packet, 0, sizeof(packet));
    pos = packet->data;
    length = sizeof(packet->data);


    if (netif->master != NULL)
	master = netif->master;
    else
	master = netif;


    // snap header
    if (!(
	PUSH_UINT8(0xaa) && PUSH_UINT8(0xaa) && PUSH_UINT8(0x03) &&
	PUSH_BYTES(cdp_snap, sizeof(cdp_snap))
    ))
	return 0;

    // save start of the cdp data
    cdp_pos = pos;

    // version
    PUSH_UINT8(cdp_version);
    if (!PUSH_UINT8(LADVD_TTL))
	return 0;


    // save the current position, then leave enough space for the checksum.
    checksum_pos = pos;
    if (!PUSH_UINT16(0))
	return 0;


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
    if (sysinfo->cap == CAP_HOST) {
	cap = CDP_CAP_HOST;
    } else {
	cap |= (sysinfo->cap & CAP_BRIDGE) ? CDP_CAP_TRANSPARENT_BRIDGE : 0;
	cap |= (sysinfo->cap & CAP_ROUTER) ? CDP_CAP_ROUTER : 0;
	cap |= (sysinfo->cap & CAP_SWITCH) ? CDP_CAP_SWITCH : 0;
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
		PUSH_UINT8(cdp_predefs[CDP_ADDR_PROTO_IPV4].protocol_type) &&
		PUSH_UINT8(cdp_predefs[CDP_ADDR_PROTO_IPV4].protocol_length) &&
		PUSH_BYTES(cdp_predefs[CDP_ADDR_PROTO_IPV4].protocol,
			   cdp_predefs[CDP_ADDR_PROTO_IPV4].protocol_length) &&
		PUSH_UINT16(sizeof(master->ipaddr4)) &&
		PUSH_BYTES(&master->ipaddr4, sizeof(master->ipaddr4))
	    ))
		return 0;
	}

	if (!IN6_IS_ADDR_UNSPECIFIED((struct in6_addr *)master->ipaddr6)) {
	    if (!(
		PUSH_UINT8(cdp_predefs[CDP_ADDR_PROTO_IPV6].protocol_type) &&
		PUSH_UINT8(cdp_predefs[CDP_ADDR_PROTO_IPV6].protocol_length) &&
		PUSH_BYTES(cdp_predefs[CDP_ADDR_PROTO_IPV6].protocol,
			   cdp_predefs[CDP_ADDR_PROTO_IPV6].protocol_length) &&
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
    if (sysinfo->location != NULL && !(
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


    // cdp checksum
    *(uint16_t *)checksum_pos = cdp_checksum(cdp_pos,
					VOIDP_DIFF(pos, cdp_pos));

    // ethernet header
    memcpy(packet->dst, cdp_dst, ETHER_ADDR_LEN);
    memcpy(packet->src, netif->hwaddr, ETHER_ADDR_LEN);
    *(uint16_t *)packet->length = htons(VOIDP_DIFF(pos, packet->data));

    // packet length
    return(VOIDP_DIFF(pos, packet));
}

