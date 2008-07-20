/*
 $Id$
*/

#include "main.h"
#include "util.h"
#include "lldp.h"
#include "tlv.h"

static uint8_t lldp_dst[] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e };
static uint8_t lldp_ether[] = { 0x88, 0xcc };

int lldp_packet(struct packet *packet,
		struct session *csession, struct session *session,
		struct sysinfo *sysinfo) {

    size_t length;
    uint8_t *pos, *tlv;
    uint8_t capabilities = 0;

    // init
    memset(packet, 0, sizeof(packet));
    pos = packet->data;
    length = sizeof(packet->data);


    // chassis id
    if (!(
	START_LLDP_TLV(LLDP_CHASSIS_ID_TLV) &&
	PUSH_UINT8(LLDP_CHASSIS_INTF_NAME_SUBTYPE) &&
	PUSH_BYTES(csession->name, strlen(csession->name))
    ))
	return 0;
    END_LLDP_TLV;


    // port id
    if (!(
	START_LLDP_TLV(LLDP_PORT_ID_TLV) &&
	PUSH_UINT8(LLDP_PORT_INTF_NAME_SUBTYPE) &&
	PUSH_BYTES(csession->name, strlen(csession->name))
    ))
	return 0;
    END_LLDP_TLV;


    // ttl
    if (!(
	START_LLDP_TLV(LLDP_TTL_TLV) &&
	PUSH_UINT16(LADVD_TTL)
    ))
	return 0;
    END_LLDP_TLV;


    // system name
    if (!(
	START_LLDP_TLV(LLDP_SYSTEM_NAME_TLV) &&
	PUSH_BYTES(sysinfo->hostname, strlen(sysinfo->hostname))
    ))
	return 0;
    END_LLDP_TLV;


    // system description
    if (!(
	START_LLDP_TLV(LLDP_SYSTEM_DESCR_TLV) &&
	PUSH_BYTES(sysinfo->uts_str, strlen(sysinfo->uts_str))
    ))
	return 0;
    END_LLDP_TLV;


    // capabilities
    if (sysinfo->cap & CAP_HOST) {
	capabilities = LLDP_CAP_STATION_ONLY;
    } else {
	if (sysinfo->cap & CAP_BRIDGE)
	    capabilities |= LLDP_CAP_BRIDGE;
	if (sysinfo->cap & CAP_ROUTER)
	    capabilities |= LLDP_CAP_ROUTER;
	if (sysinfo->cap & CAP_SWITCH)
	    capabilities |= LLDP_CAP_BRIDGE;
	if (sysinfo->cap & CAP_WLAN)
	    capabilities |= LLDP_CAP_WLAN_AP;
    }

    if (!(
	START_LLDP_TLV(LLDP_SYSTEM_CAP_TLV) &&
	PUSH_UINT16(capabilities) &&
	PUSH_UINT16(capabilities)
    ))
	return 0;
    END_LLDP_TLV;


    // ipv4 management addr
    if (session->ipaddr4 != 0) {
	if (!(
	    START_LLDP_TLV(LLDP_MGMT_ADDR_TLV) &&
	    PUSH_UINT8(1 + sizeof(session->ipaddr4)) &&
	    PUSH_UINT8(LLDP_AFNUM_INET) &&
	    PUSH_BYTES(&session->ipaddr4, sizeof(session->ipaddr4)) &&
	    PUSH_UINT8(LLDP_INTF_NUMB_IFX_SUBTYPE) &&
	    PUSH_UINT32(csession->index) &&
	    PUSH_UINT8(0)
	))
	    return 0;
	END_LLDP_TLV;
    }


    // ipv6 management addr
    if (!IN6_IS_ADDR_UNSPECIFIED((struct in6_addr *)session->ipaddr6)) {
	if (!(
	    START_LLDP_TLV(LLDP_MGMT_ADDR_TLV) &&
	    PUSH_UINT8(1 + sizeof(session->ipaddr6)) &&
	    PUSH_UINT8(LLDP_AFNUM_INET6) &&
	    PUSH_BYTES(session->ipaddr6, sizeof(session->ipaddr6)) &&
	    PUSH_UINT8(LLDP_INTF_NUMB_IFX_SUBTYPE) &&
	    PUSH_UINT32(csession->index) &&
	    PUSH_UINT8(0)
	))
	    return 0;
	END_LLDP_TLV;
    }


    // autoneg
    if (csession->autoneg_supported != -1) {
	if (!(
	    START_LLDP_TLV(LLDP_PRIVATE_TLV) &&
	    PUSH_BYTES(OUI_IEEE_8023_PRIVATE, OUI_LEN) &&
	    PUSH_UINT8(LLDP_PRIVATE_8023_SUBTYPE_MACPHY) &&
	    PUSH_UINT8(csession->autoneg_supported +
		       (csession->autoneg_enabled << 1)) &&
	    PUSH_UINT16(0) &&
	    PUSH_UINT16(csession->mau)
	))
	    return 0;
	END_LLDP_TLV;
    }


    // lacp
    if (session->lacp != 0) {
	if (!(
	    START_LLDP_TLV(LLDP_PRIVATE_TLV) &&
	    PUSH_BYTES(OUI_IEEE_8023_PRIVATE, OUI_LEN) &&
	    PUSH_UINT8(LLDP_PRIVATE_8023_SUBTYPE_LINKAGGR) &&
	    PUSH_UINT8(LLDP_AGGREGATION_CAPABILTIY|LLDP_AGGREGATION_STATUS) &&
	    PUSH_UINT32(csession->lacp_index)
	))
	    return 0;
	END_LLDP_TLV;
    }


    // mtu
    if (csession->mtu != 0) {
	if (!(
	    START_LLDP_TLV(LLDP_PRIVATE_TLV) &&
	    PUSH_BYTES(OUI_IEEE_8023_PRIVATE, OUI_LEN) &&
	    PUSH_UINT8(LLDP_PRIVATE_8023_SUBTYPE_MTU) &&
	    PUSH_UINT16(csession->mtu + 22)
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


    // ethernet header
    bcopy(lldp_dst, packet->dst, ETHER_ADDR_LEN);
    bcopy(csession->hwaddr, packet->src, ETHER_ADDR_LEN);
    bcopy(lldp_ether, packet->type, ETHER_TYPE_LEN);

    // packet length
    return(VOIDP_DIFF(pos, packet));
}

