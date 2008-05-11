/*
 $Id$
*/

#include "main.h"
#include "lldp.h"
#include "tlv.h"

size_t lldp_encode(struct lldp_packet *packet, void *data, size_t length) {
    uint8_t *pos;
    uint8_t *tlv;

    pos = data;

    if (!(
	START_LLDP_TLV(LLDP_CHASSIS_ID_TLV) &&
	PUSH_UINT8(LLDP_CHASSIS_MAC_ADDR_SUBTYPE) &&
	PUSH_BYTES(packet->hwaddr, sizeof(packet->hwaddr))
    ))
	return 0;
    END_LLDP_TLV;

    if (!(
	START_LLDP_TLV(LLDP_PORT_ID_TLV) &&
	PUSH_UINT8(LLDP_PORT_INTF_NAME_SUBTYPE) &&
	PUSH_BYTES(packet->port_id, strlen(packet->port_id))
    ))
	return 0;
    END_LLDP_TLV;

    if (!(
	START_LLDP_TLV(LLDP_TTL_TLV) &&
	PUSH_UINT16(packet->ttl)
    ))
	return 0;
    END_LLDP_TLV;

    if (!(
	START_LLDP_TLV(LLDP_SYSTEM_NAME_TLV) &&
	PUSH_BYTES(packet->system_name, strlen(packet->system_name))
    ))
	return 0;
    END_LLDP_TLV;

    if (!(
	START_LLDP_TLV(LLDP_SYSTEM_DESCR_TLV) &&
	PUSH_BYTES(packet->system_descr, strlen(packet->system_descr))
    ))
	return 0;
    END_LLDP_TLV;

    if (!(
	START_LLDP_TLV(LLDP_SYSTEM_CAP_TLV) &&
	PUSH_UINT16(packet->system_cap) &&
	PUSH_UINT16(packet->system_cap)
    ))
	return 0;
    END_LLDP_TLV;

    if (packet->mgmt_addr4 != 0) {
	if (!(
	    START_LLDP_TLV(LLDP_MGMT_ADDR_TLV) &&
	    PUSH_UINT8(1 + sizeof(packet->mgmt_addr4)) &&
	    PUSH_UINT8(LLDP_AFNUM_INET) &&
	    PUSH_UINT32(packet->mgmt_addr4) &&
	    PUSH_UINT8(1) &&
	    PUSH_UINT32(0) &&
	    PUSH_UINT8(0)
	))
	    return 0;
	END_LLDP_TLV;
    }

    if (packet->autoneg != -1) {
	if (!(
	    START_LLDP_TLV(LLDP_PRIVATE_TLV) &&
	    PUSH_BYTES(OUI_IEEE_8023_PRIVATE, sizeof(OUI_IEEE_8023_PRIVATE) -1) &&
	    PUSH_UINT8(LLDP_PRIVATE_8023_SUBTYPE_MACPHY) &&
	    PUSH_UINT8(packet->autoneg) &&
	    PUSH_UINT16(0) &&
	    PUSH_UINT16(0)
	))
	    return 0;
	END_LLDP_TLV;
    }

    if (packet->mtu != 0) {
	if (!(
	    START_LLDP_TLV(LLDP_PRIVATE_TLV) &&
	    PUSH_BYTES(OUI_IEEE_8023_PRIVATE, sizeof(OUI_IEEE_8023_PRIVATE) -1) &&
	    PUSH_UINT8(LLDP_PRIVATE_8023_SUBTYPE_MTU) &&
	    PUSH_UINT16(packet->mtu)
	))
	    return 0;
	END_LLDP_TLV;
    }

    // the end
    if (!(
	START_LLDP_TLV(LLDP_END_TLV)
    ))
	return 0;
    END_LLDP_TLV;

    return VOIDP_DIFF(pos, data);
}


int lldp_packet(struct session *session) {
    struct lldp_packet *packet;

    packet = malloc(sizeof(struct lldp_packet));
    bzero(packet, sizeof(struct lldp_packet));

    memcpy(packet->hwaddr, session->hwaddr, sizeof(packet->hwaddr));
    packet->port_id = session->dev;
    packet->ttl = 120;
    packet->system_name = session->uts->nodename;
    packet->system_descr = session->uts_str;

    if (session->cap_router == 1)
	packet->system_cap = LLDP_CAP_ROUTER;
    else
	packet->system_cap = LLDP_CAP_STATION_ONLY;

    if (session->ipaddr4 != -1)
	packet->mgmt_addr4 = session->ipaddr4; 
    // TODO: ipv6

    if (session->mtu)
	packet->mtu = session->mtu + 22; 

    if (session->autoneg_supported != -1) {
	packet->autoneg = session->autoneg_supported + 
	    (session->autoneg_enabled << 1);
    } else {
	packet->autoneg = -1;
    }

    session->lldp_data = malloc(BUFSIZ);
    bzero(session->lldp_data, BUFSIZ);

    session->lldp_length = lldp_encode(packet, session->lldp_data, BUFSIZ);
    if (session->lldp_length == 0) {
	log_str(1, "Generated lldp packet too large");
	return(EXIT_FAILURE);
   } 

    return(EXIT_SUCCESS);
}

int lldp_send(struct session *session) {

    libnet_t *l = session->libnet;

    if (libnet_build_data(session->lldp_data, session->lldp_length, l, 0)==-1) {
        log_str(0, "Can't build lldp frame data: %s", libnet_geterror(l));
        goto fail;
    }

    if(libnet_build_ethernet(lldp_mac, session->hwaddr, 0x88cc,
			     NULL, 0, l, 0) == -1) {

	log_str(0, "Can't build lldp ethernet header: %s", libnet_geterror(l));
	goto fail;
    }

    /*
     *  Write it to the wire.
     */
    if (libnet_write(l) == -1) {
        log_str(0, "Network transmit error: %s", libnet_geterror(l));
        goto fail;
    }

    libnet_clear_packet(l);
    return (EXIT_SUCCESS);

    fail:
    libnet_clear_packet(l);
    return (EXIT_FAILURE);
}

