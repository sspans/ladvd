/*
 $Id$
*/

#include "main.h"
#include "cdp.h"
#include "tlv.h"

static uint8_t cdp_version = 0;
static uint8_t cdp_dst[] = { 0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc };
static uint8_t cdp_src[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static uint8_t cdp_snap[] = { 0x00, 0x00, 0x0c, 0x20, 0x00 };

/*
 * Actually, this is the standard IP checksum algorithm.
 */
uint16_t cdp_checksum(const unsigned short *data, size_t length) {
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

int cdp_packet(struct session *csession, struct session *session,
	       struct sysinfo *sysinfo) {

    size_t length = BUFSIZ;
    void *cdp_pos, *checksum_pos;
    uint8_t *pos, *tlv;
    uint8_t capabilities = 0;

    pos = csession->cdp_msg;

    // zero
    bzero(csession->cdp_msg, length);
    csession->cdp_len = 0;

    // ethernet header
    if (!(
	PUSH_BYTES(cdp_dst, sizeof(cdp_dst)) &&
	PUSH_BYTES(cdp_src, sizeof(cdp_src)) &&
	PUSH_UINT16(0)
    ))
	return 0;

    // snap header
    if (!(
	PUSH_UINT8(0xaa) && PUSH_UINT8(0xaa) && PUSH_UINT8(0x03) &&
	PUSH_BYTES(cdp_snap, sizeof(cdp_snap))
    ))
	return 0;

    // save the cdp start position
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
	PUSH_BYTES(csession->if_name, strlen(csession->if_name))
    ))
	return 0;
    END_CDP_TLV;

    // capabilities
    if (sysinfo->cap & CAP_BRIDGE)
    	capabilities |= CDP_CAP_TRANSPARENT_BRIDGE;
    if (sysinfo->cap & CAP_HOST)
    	capabilities |= CDP_CAP_HOST;
    if (sysinfo->cap & CAP_ROUTER)
    	capabilities |= CDP_CAP_ROUTER;
    if (sysinfo->cap & CAP_SWITCH)
    	capabilities |= CDP_CAP_SWITCH;

    if (!(
	START_CDP_TLV(CDP_TYPE_CAPABILITIES) &&
	PUSH_UINT32(capabilities)
    ))
	return 0;
    END_CDP_TLV;

    // ipv4 management addr 
    if (session->ipaddr4 != 0) {
	if (!(
	    START_CDP_TLV(CDP_TYPE_ADDRESS) &&
	    PUSH_UINT32(1)
	))
	    return 0;

	if (!(
	    PUSH_UINT8(cdp_predefs[CDP_ADDR_PROTO_IPV4].protocol_type) &&
	    PUSH_UINT8(cdp_predefs[CDP_ADDR_PROTO_IPV4].protocol_length) &&
	    PUSH_BYTES(cdp_predefs[CDP_ADDR_PROTO_IPV4].protocol,
		   cdp_predefs[CDP_ADDR_PROTO_IPV4].protocol_length) &&
	    PUSH_UINT16(sizeof(session->ipaddr4)) &&
	    PUSH(session->ipaddr4, uint32_t,)
	))
	    return 0;

	END_CDP_TLV;
    }
    // TODO: IPv6

    // mtu
    if (csession->mtu && !(
	START_CDP_TLV(CDP_TYPE_MTU) &&
	PUSH_UINT32(csession->mtu)
    ))
	return 0;
    END_CDP_TLV;

    // duplex
    if ((csession->duplex != -1) && !(
	START_CDP_TLV(CDP_TYPE_DUPLEX) &&
	PUSH_UINT8(csession->duplex)
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

    *(uint16_t *)checksum_pos = cdp_checksum(cdp_pos, VOIDP_DIFF(pos, cdp_pos));
    csession->cdp_len = VOIDP_DIFF(pos, csession->cdp_msg);

    return(csession->cdp_len);
}

int cdp_send(struct session *session) {

    // write it to the wire.
    if (my_rsend(session->sockfd, session->cdp_msg, session->cdp_len) == -1) {
	my_log(0, "network transmit error on %s", session->if_name);
	return (EXIT_FAILURE);
    }

    return (EXIT_SUCCESS);
}

