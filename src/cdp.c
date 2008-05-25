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
	register long sum = 0;
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
		PUSH_UINT32(packet->address4)
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
	
	*(uint16_t *)checksum_pos = cdp_checksum(data, VOIDP_DIFF(pos, data));

	return VOIDP_DIFF(pos, data);
}

int cdp_packet(struct session *session) {
    struct cdp_packet *packet;

    packet = malloc(sizeof(struct cdp_packet));
    bzero(packet, sizeof(struct cdp_packet));

    packet->version = 2;
    packet->ttl = 180;
    packet->device_id = session->hostname;
    packet->ios_version = session->uts_str;
    packet->platform = session->uts->sysname;
    packet->port_id = session->dev;
    packet->mtu = session->mtu;

    if (session->cap & CAP_BRIDGE)
    	packet->capabilities |= CDP_CAP_TRANSPARENT_BRIDGE;
    if (session->cap & CAP_HOST)
    	packet->capabilities |= CDP_CAP_HOST;
    if (session->cap & CAP_ROUTER)
    	packet->capabilities |= CDP_CAP_ROUTER;
    if (session->cap & CAP_SWITCH)
    	packet->capabilities |= CDP_CAP_SWITCH;

    if (session->ipaddr4 != -1)
    	packet->address4 = session->ipaddr4;

    if (session->duplex != -1)
    	packet->duplex = session->duplex;

    session->cdp_data = malloc(BUFSIZ);
    bzero(session->cdp_data, BUFSIZ);

    session->cdp_length = cdp_encode(packet, session->cdp_data, BUFSIZ);
    if (session->cdp_length == 0) {
	log_str(0, "generated cdp packet too large");
	return(EXIT_FAILURE);
    }

    return(EXIT_SUCCESS);
}

int cdp_send(struct session *session) {

    libnet_t *l = session->libnet;

    if (libnet_build_data(session->cdp_data, session->cdp_length, l, 0) == -1) {
        log_str(0, "can't build cdp ethernet data: %s", libnet_geterror(l));
        goto fail;
    }

    if (libnet_build_802_2snap(0xaa, 0xaa, 0x03, cdp_snap_oui, 
			       0x2000, NULL, 0, l, 0) == -1) {
        log_str(0, "can't build cdp snap header: %s", libnet_geterror(l));
	goto fail;
    }

    /* length is 802.2 SNAP header + CDP's length */
    if(libnet_build_802_3(cdp_mac, session->hwaddr,
			LIBNET_802_2SNAP_H + session->cdp_length,
			NULL, 0, l, 0) == -1) {

	log_str(0, "can't build cdp ethernet header: %s", libnet_geterror(l));
	goto fail;
    }

    /*
     *  Write it to the wire.
     */
    if (libnet_write(l) == -1) {
        log_str(0, "network transmit error: %s", libnet_geterror(l));
        goto fail;
    }

    libnet_clear_packet(l);
    return (EXIT_SUCCESS);

    fail:
    libnet_clear_packet(l);
    return (EXIT_FAILURE);
}

