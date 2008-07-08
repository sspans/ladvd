/*
 $Id$
*/

#include "main.h"
#include "cdp.h"
#include "tlv.h"

static uint8_t cdp_mac[] = { 0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc };
static uint8_t cdp_snap_oui[] = { 0x00, 0x00, 0x0c };

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

size_t cdp_encode(struct cdp_packet *packet, void *data, size_t length) {
	uint8_t *pos;
	void *checksum_pos;
	uint8_t *tlv;

	pos = data;

	PUSH_UINT8(packet->version);
	if (!PUSH_UINT8(packet->ttl))
		return 0;

	/*
	 * Save the current position, then leave enough space for the
	 * checksum.
	 */
	checksum_pos = pos;
	if (!PUSH_UINT16(0))
		return 0;

	if (!(
	    START_CDP_TLV(CDP_TYPE_DEVICE_ID) &&
	    PUSH_BYTES(packet->device_id, strlen(packet->device_id))
	))
	    return 0;
	END_CDP_TLV;

	if (packet->address4 != 0) {
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
		PUSH_UINT16(sizeof(packet->address4)) &&
		PUSH(packet->address4, uint32_t,)
	    ))
		return 0;

	    END_CDP_TLV;
	}

	if (!(
	    START_CDP_TLV(CDP_TYPE_PORT_ID) &&
	    PUSH_BYTES(packet->port_id, strlen(packet->port_id))
	))
	    return 0;
	END_CDP_TLV;

	if (!(
	    START_CDP_TLV(CDP_TYPE_CAPABILITIES) &&
	    PUSH_UINT32(packet->capabilities)
	))
	    return 0;
	END_CDP_TLV;

	if (!(
	    START_CDP_TLV(CDP_TYPE_IOS_VERSION) &&
	    PUSH_BYTES(packet->ios_version, strlen(packet->ios_version))
	))
	    return 0;
	END_CDP_TLV;

	if (!(
	    START_CDP_TLV(CDP_TYPE_PLATFORM) &&
	    PUSH_BYTES(packet->platform, strlen(packet->platform))
	))
	    return 0;
	END_CDP_TLV;

	if (packet->duplex && !(
	    START_CDP_TLV(CDP_TYPE_DUPLEX) &&
	    PUSH_UINT8(packet->duplex)
	))
	    return 0;
	END_CDP_TLV;

	if (packet->mtu && !(
	    START_CDP_TLV(CDP_TYPE_MTU) &&
	    PUSH_UINT32(packet->mtu)
	))
	    return 0;
	END_CDP_TLV;

	if (packet->location != NULL && !(
	    START_CDP_TLV(CDP_TYPE_LOCATION) &&
	    PUSH_UINT8(0) &&
	    PUSH_BYTES(packet->location, strlen(packet->location))
	))
	    return 0;
	END_CDP_TLV;

	// workaround cisco crc bug (>0x80 in last uneven byte)
	// by having system_name at the end
	if (!(
	    START_CDP_TLV(CDP_TYPE_SYSTEM_NAME) &&
	    PUSH_BYTES(packet->system_name, strlen(packet->system_name))
	))
	    return 0;
	END_CDP_TLV;

	*(uint16_t *)checksum_pos = cdp_checksum(data, VOIDP_DIFF(pos, data));

	return VOIDP_DIFF(pos, data);
}

int cdp_packet(struct session *csession, struct session *session,
	       struct sysinfo *sysinfo) {

    struct cdp_packet packet;

    packet.version = 2;
    packet.ttl = LADVD_TTL;
    packet.device_id = sysinfo->hostname;
    packet.ios_version = sysinfo->uts_str;
    packet.platform = sysinfo->uts.sysname;
    packet.port_id = csession->if_name;
    packet.mtu = csession->mtu;
    packet.system_name = sysinfo->hostname;
    packet.location = sysinfo->location;

    if (sysinfo->cap & CAP_BRIDGE)
    	packet.capabilities |= CDP_CAP_TRANSPARENT_BRIDGE;
    if (sysinfo->cap & CAP_HOST)
    	packet.capabilities |= CDP_CAP_HOST;
    if (sysinfo->cap & CAP_ROUTER)
    	packet.capabilities |= CDP_CAP_ROUTER;
    if (sysinfo->cap & CAP_SWITCH)
    	packet.capabilities |= CDP_CAP_SWITCH;

    // parent interface
    if (session->ipaddr4 != 0)
    	packet.address4 = session->ipaddr4;


    // media information
    if (csession->duplex != -1)
    	packet.duplex = csession->duplex;

    bzero(csession->cdp_msg, BUFSIZ);

   if (libnet_build_802_2snap(0xaa, 0xaa, 0x03, cdp_snap_oui, 
			      0x2000, NULL, 0, l, 0) == -1) {
	my_log(0, "can't build cdp snap header: %s", libnet_geterror(l));
	goto fail;
   }

   /* length is 802.2 SNAP header + CDP's length */
   if(libnet_build_802_3(cdp_mac, libnet_get_hwaddr(l),
			 LIBNET_802_2SNAP_H + session->cdp_len,
			 NULL, 0, l, 0) == -1) {

	my_log(0, "can't build cdp ethernet header: %s", libnet_geterror(l));
	goto fail;
    }

    csession->cdp_len = cdp_encode(&packet, csession->cdp_msg, BUFSIZ);
    if (csession->cdp_len == 0) {
	my_log(0, "generated cdp packet too large");
	return(EXIT_FAILURE);
    }

    return(EXIT_SUCCESS);
}

int cdp_send(struct session *session) {

    // write it to the wire.
    if (my_rsendto(session->socket, session->cdp_msg, session->cdp_len) == -1) {
	my_log(0, "network transmit error on %s", session->if_name);
	return (EXIT_FAILURE);
    }

    return (EXIT_SUCCESS);
}

