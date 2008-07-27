/*
 $Id$
*/

#include "main.h"
#include "util.h"
#include "lldp.h"
#include "tlv.h"

static uint8_t lldp_dst[] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e };
static uint8_t lldp_ether[] = { 0x88, 0xcc };

int lldp_packet(struct packet *packet, struct netif *netif,
		struct sysinfo *sysinfo) {

    size_t length;
    uint8_t *pos, *tlv;
    uint8_t cap = 0, cap_active = 0;
    struct netif *master;

    // init
    memset(packet, 0, sizeof(packet));
    pos = packet->data;
    length = sizeof(packet->data);


    if (netif->master != NULL)
	master = netif->master;
    else
	master = netif;


    // chassis id
    if (!(
	START_LLDP_TLV(LLDP_CHASSIS_ID_TLV) &&
	PUSH_UINT8(LLDP_CHASSIS_MAC_ADDR_SUBTYPE) &&
	PUSH_BYTES(sysinfo->hwaddr, ETHER_ADDR_LEN)
    ))
	return 0;
    END_LLDP_TLV;


    // port id
    if (!(
	START_LLDP_TLV(LLDP_PORT_ID_TLV) &&
	PUSH_UINT8(LLDP_PORT_INTF_NAME_SUBTYPE) &&
	PUSH_BYTES(netif->name, strlen(netif->name))
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
    if (sysinfo->cap == CAP_HOST) {
	cap = cap_active = LLDP_CAP_STATION_ONLY;
    } else {
	cap |= (sysinfo->cap & CAP_BRIDGE) ? LLDP_CAP_BRIDGE : 0;
	cap_active |= (sysinfo->cap_active & CAP_BRIDGE) ? LLDP_CAP_BRIDGE : 0;

	cap |= (sysinfo->cap & CAP_ROUTER) ? LLDP_CAP_ROUTER : 0;
	cap_active |= (sysinfo->cap_active & CAP_ROUTER) ? LLDP_CAP_ROUTER : 0;

	cap |= (sysinfo->cap & CAP_SWITCH) ? LLDP_CAP_BRIDGE : 0;
	cap_active |= (sysinfo->cap_active & CAP_SWITCH) ? LLDP_CAP_BRIDGE : 0;

	cap |= (sysinfo->cap & CAP_WLAN) ? LLDP_CAP_WLAN_AP : 0;
	cap_active |= (sysinfo->cap_active & CAP_WLAN) ? LLDP_CAP_WLAN_AP : 0;
    }

    if (!(
	START_LLDP_TLV(LLDP_SYSTEM_CAP_TLV) &&
	PUSH_UINT16(cap) && PUSH_UINT16(cap_active)
    ))
	return 0;
    END_LLDP_TLV;


    // ipv4 management addr
    if (master->ipaddr4 != 0) {
	if (!(
	    START_LLDP_TLV(LLDP_MGMT_ADDR_TLV) &&
	    PUSH_UINT8(1 + sizeof(master->ipaddr4)) &&
	    PUSH_UINT8(LLDP_AFNUM_INET) &&
	    PUSH_BYTES(&master->ipaddr4, sizeof(master->ipaddr4)) &&
	    PUSH_UINT8(LLDP_INTF_NUMB_IFX_SUBTYPE) &&
	    PUSH_UINT32(netif->index) &&
	    PUSH_UINT8(0)
	))
	    return 0;
	END_LLDP_TLV;
    }


    // ipv6 management addr
    if (!IN6_IS_ADDR_UNSPECIFIED((struct in6_addr *)master->ipaddr6)) {
	if (!(
	    START_LLDP_TLV(LLDP_MGMT_ADDR_TLV) &&
	    PUSH_UINT8(1 + sizeof(master->ipaddr6)) &&
	    PUSH_UINT8(LLDP_AFNUM_INET6) &&
	    PUSH_BYTES(master->ipaddr6, sizeof(master->ipaddr6)) &&
	    PUSH_UINT8(LLDP_INTF_NUMB_IFX_SUBTYPE) &&
	    PUSH_UINT32(netif->index) &&
	    PUSH_UINT8(0)
	))
	    return 0;
	END_LLDP_TLV;
    }


    // autoneg
    if (netif->autoneg_supported != -1) {
	if (!(
	    START_LLDP_TLV(LLDP_PRIVATE_TLV) &&
	    PUSH_BYTES(OUI_IEEE_8023_PRIVATE, OUI_LEN) &&
	    PUSH_UINT8(LLDP_PRIVATE_8023_SUBTYPE_MACPHY) &&
	    PUSH_UINT8(netif->autoneg_supported +
		       (netif->autoneg_enabled << 1)) &&
	    PUSH_UINT16(0) &&
	    PUSH_UINT16(netif->mau)
	))
	    return 0;
	END_LLDP_TLV;
    }


    // lacp
    if (master->lacp != 0) {
	if (!(
	    START_LLDP_TLV(LLDP_PRIVATE_TLV) &&
	    PUSH_BYTES(OUI_IEEE_8023_PRIVATE, OUI_LEN) &&
	    PUSH_UINT8(LLDP_PRIVATE_8023_SUBTYPE_LINKAGGR) &&
	    PUSH_UINT8(LLDP_AGGREGATION_CAPABILTIY|LLDP_AGGREGATION_STATUS) &&
	    PUSH_UINT32(netif->lacp_index)
	))
	    return 0;
	END_LLDP_TLV;
    }


    // mtu
    if (netif->mtu != 0) {
	if (!(
	    START_LLDP_TLV(LLDP_PRIVATE_TLV) &&
	    PUSH_BYTES(OUI_IEEE_8023_PRIVATE, OUI_LEN) &&
	    PUSH_UINT8(LLDP_PRIVATE_8023_SUBTYPE_MTU) &&
	    PUSH_UINT16(netif->mtu + 22)
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
    memcpy(packet->dst, lldp_dst, ETHER_ADDR_LEN);
    memcpy(packet->src, netif->hwaddr, ETHER_ADDR_LEN);
    memcpy(packet->type, lldp_ether, ETHER_TYPE_LEN);

    // packet length
    return(VOIDP_DIFF(pos, packet));
}

