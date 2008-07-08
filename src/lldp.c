/*
 $Id$
*/

#include "main.h"
#include "lldp.h"
#include "tlv.h"

static uint8_t lldp_mac[] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e };

size_t lldp_encode(struct lldp_packet *packet, void *data, size_t length) {
    uint8_t *pos;
    uint8_t *tlv;

    pos = data;

    if (!(
	START_LLDP_TLV(LLDP_CHASSIS_ID_TLV) &&
	PUSH_UINT8(LLDP_CHASSIS_INTF_NAME_SUBTYPE) &&
	PUSH_BYTES(packet->port_id, strlen(packet->port_id))
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
	    PUSH(packet->mgmt_addr4, uint32_t,) &&
	    PUSH_UINT8(LLDP_INTF_NUMB_IFX_SUBTYPE) &&
	    PUSH_UINT32(packet->ifindex) &&
	    PUSH_UINT8(0)
	))
	    return 0;
	END_LLDP_TLV;
    }

    if (!IN6_IS_ADDR_UNSPECIFIED(packet->mgmt_addr6)) {
	if (!(
	    START_LLDP_TLV(LLDP_MGMT_ADDR_TLV) &&
	    PUSH_UINT8(1 + sizeof(packet->mgmt_addr6)) &&
	    PUSH_UINT8(LLDP_AFNUM_INET6) &&
	    PUSH_BYTES(packet->mgmt_addr6, sizeof(packet->mgmt_addr6)) &&
	    PUSH_UINT8(LLDP_INTF_NUMB_IFX_SUBTYPE) &&
	    PUSH_UINT32(packet->ifindex) &&
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
	    PUSH_UINT16(packet->mau)
	))
	    return 0;
	END_LLDP_TLV;
    }

    if (packet->lacp != 0) {
	if (!(
	    START_LLDP_TLV(LLDP_PRIVATE_TLV) &&
	    PUSH_BYTES(OUI_IEEE_8023_PRIVATE, sizeof(OUI_IEEE_8023_PRIVATE) -1) &&
	    PUSH_UINT8(LLDP_PRIVATE_8023_SUBTYPE_LINKAGGR) &&
	    PUSH_UINT8(packet->lacp) &&
	    PUSH_UINT32(packet->lacp_ifindex)
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


int lldp_packet(struct session *csession, struct session *session,
		struct sysinfo *sysinfo) {
    struct lldp_packet packet;

    // sysinfo
    packet.ttl = LADVD_TTL;
    packet.system_name = sysinfo->hostname;
    packet.system_descr = sysinfo->uts_str;

    if (sysinfo->cap & CAP_HOST) {
	packet.system_cap = LLDP_CAP_STATION_ONLY;
    } else {
	if (sysinfo->cap & CAP_BRIDGE)
	    packet.system_cap |= LLDP_CAP_BRIDGE;
	if (sysinfo->cap & CAP_ROUTER)
	    packet.system_cap |= LLDP_CAP_ROUTER;
	if (sysinfo->cap & CAP_SWITCH)
	    packet.system_cap |= LLDP_CAP_BRIDGE;
	if (sysinfo->cap & CAP_WLAN)
	    packet.system_cap |= LLDP_CAP_WLAN_AP;
    }

    // master interface
    if (session->ipaddr4 != 0)
	packet.mgmt_addr4 = session->ipaddr4; 
    if (!IN6_IS_ADDR_UNSPECIFIED(session->ipaddr6))
	bcopy(session->ipaddr6, packet.mgmt_addr6, sizeof(session->ipaddr6)); 

    // lacp
    if (session->if_lacp != 0) {
	packet.lacp |= LLDP_AGGREGATION_CAPABILTIY;
	packet.lacp |= LLDP_AGGREGATION_STATUS;
	packet.lacp_ifindex = csession->if_lacp_ifindex;
    }


    // physical
    packet.ifindex = csession->if_index;
    packet.port_id = csession->if_name;

    if (csession->autoneg_supported != -1) {
	packet.autoneg = csession->autoneg_supported + 
	    (csession->autoneg_enabled << 1);
	packet.mau = csession->mau;
    } else {
	packet.autoneg = -1;
    }

    if (csession->mtu)
	packet.mtu = csession->mtu + 22; 

    // clear
    bzero(csession->lldp_msg, BUFSIZ);

    if(libnet_build_ethernet(lldp_mac, libnet_get_hwaddr(l), 0x88cc,
			     NULL, 0, l, 0) == -1) {
	my_log(0, "can't build lldp ethernet header: %s", libnet_geterror(l));
    }

    csession->lldp_len = lldp_encode(&packet, csession->lldp_msg, BUFSIZ);
    if (csession->lldp_len == 0) {
	my_log(1, "generated lldp packet too large");
	return(EXIT_FAILURE);
   } 

    return(EXIT_SUCCESS);
}

int lldp_send(struct session *session) {

    // write it to the wire.
    if (my_rsendto(session->sockfd, session->lldp_msg, session->lldp_len) == -1) {
	my_log(0, "network transmit error on %s", session->if_name);
	return (EXIT_FAILURE);
    }

    return (EXIT_SUCCESS);
}

