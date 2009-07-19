/*
 $Id$
*/

#include "common.h"
#include "util.h"
#include "proto/lldp.h"
#include "proto/tlv.h"

size_t lldp_packet(void *packet, struct netif *netif, struct sysinfo *sysinfo) {

    struct ether_hdr ether;

    char *tlv;
    char *pos = packet;
    size_t length = ETHER_MAX_LEN;
    tlv_t type;

    uint8_t cap = 0, cap_active = 0;
    struct netif *master;

    const uint8_t lldp_dst[] = LLDP_MULTICAST_ADDR;

    // fixup master netif
    if (netif->master != NULL)
	master = netif->master;
    else
	master = netif;


    // ethernet header
    memcpy(ether.dst, lldp_dst, ETHER_ADDR_LEN);
    memcpy(ether.src, netif->hwaddr, ETHER_ADDR_LEN);
    ether.type = htons(ETHERTYPE_LLDP);
    memcpy(pos, &ether, sizeof(struct ether_hdr));
    pos += sizeof(struct ether_hdr);

    // update tlv counters
    length -= VOIDP_DIFF(pos, packet);


    // chassis id
    if (!(
	START_LLDP_TLV(LLDP_TYPE_CHASSIS_ID) &&
	PUSH_UINT8(LLDP_CHASSIS_MAC_ADDR_SUBTYPE) &&
	PUSH_BYTES(sysinfo->hwaddr, ETHER_ADDR_LEN)
    ))
	return 0;
    END_LLDP_TLV;


    // port id
    if (!(
	START_LLDP_TLV(LLDP_TYPE_PORT_ID) &&
	PUSH_UINT8(LLDP_PORT_INTF_NAME_SUBTYPE) &&
	PUSH_BYTES(netif->name, strlen(netif->name))
    ))
	return 0;
    END_LLDP_TLV;


    // ttl
    if (!(
	START_LLDP_TLV(LLDP_TYPE_TTL) &&
	PUSH_UINT16(LADVD_TTL)
    ))
	return 0;
    END_LLDP_TLV;


    // port description
    if (((options & OPT_DESCR) == 0) && (strlen(netif->description) > 0)) {
	if (!(
	    START_LLDP_TLV(LLDP_TYPE_PORT_DESCR) &&
	    PUSH_BYTES(netif->description, strlen(netif->description))
	))
	    return 0;
	END_LLDP_TLV;
    }


    // system name
    if (!(
	START_LLDP_TLV(LLDP_TYPE_SYSTEM_NAME) &&
	PUSH_BYTES(sysinfo->hostname, strlen(sysinfo->hostname))
    ))
	return 0;
    END_LLDP_TLV;


    // system description
    if (!(
	START_LLDP_TLV(LLDP_TYPE_SYSTEM_DESCR) &&
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
	START_LLDP_TLV(LLDP_TYPE_SYSTEM_CAP) &&
	PUSH_UINT16(cap) && PUSH_UINT16(cap_active)
    ))
	return 0;
    END_LLDP_TLV;


    // ipv4 management addr
    if (master->ipaddr4 != 0) {
	if (!(
	    START_LLDP_TLV(LLDP_TYPE_MGMT_ADDR) &&
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
	    START_LLDP_TLV(LLDP_TYPE_MGMT_ADDR) &&
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



    // IEEE 802.3 Organizationally Specific TLV set

    // autoneg
    if (netif->autoneg_supported != -1) {
	if (!(
	    START_LLDP_TLV(LLDP_TYPE_PRIVATE) &&
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
	    START_LLDP_TLV(LLDP_TYPE_PRIVATE) &&
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
	    START_LLDP_TLV(LLDP_TYPE_PRIVATE) &&
	    PUSH_BYTES(OUI_IEEE_8023_PRIVATE, OUI_LEN) &&
	    PUSH_UINT8(LLDP_PRIVATE_8023_SUBTYPE_MTU) &&
	    PUSH_UINT16(netif->mtu + 22)
	))
	    return 0;
	END_LLDP_TLV;
    }



    // TIA Location Identification TLv

    // LOC ("location", CAtype 22): unstructured additional information
    if ((strlen(sysinfo->country) == 2) && (strlen(sysinfo->location) != 0)) {
	if (!(
	    START_LLDP_TLV(LLDP_TYPE_PRIVATE) &&
	    PUSH_BYTES(OUI_TIA, OUI_LEN) &&
	    PUSH_UINT8(LLDP_PRIVATE_TIA_SUBTYPE_LOCAL_ID) &&
	    PUSH_UINT8(LLDP_TIA_LOCATION_DATA_FORMAT_CIVIC_ADDRESS) &&
	    PUSH_UINT8(5 + strlen(sysinfo->location)) &&
	    PUSH_UINT8(LLDP_TIA_LOCATION_LCI_WHAT_CLIENT) &&
	    PUSH_BYTES(sysinfo->country, 2) &&
	    PUSH_UINT8(LLDP_TIA_LOCATION_LCI_CATYPE_LOC) &&
	    PUSH_UINT8(strlen(sysinfo->location)) &&
	    PUSH_BYTES(sysinfo->location, strlen(sysinfo->location))
	))
	    return 0;
	END_LLDP_TLV;
    }



    // TIA Inventory Management TLV Set

    // hardware revision
    if (strlen(sysinfo->hw_revision) > 0) {
	if (!(
	    START_LLDP_TLV(LLDP_TYPE_PRIVATE) &&
	    PUSH_BYTES(OUI_TIA, OUI_LEN) &&
	    PUSH_UINT8(LLDP_PRIVATE_TIA_SUBTYPE_INVENTORY_HARDWARE_REV) &&
	    PUSH_BYTES(sysinfo->hw_revision, strlen(sysinfo->hw_revision))
	))
	    return 0;
	END_LLDP_TLV;
    }


    // firmware revision
    if (strlen(sysinfo->fw_revision) > 0) {
	if (!(
	    START_LLDP_TLV(LLDP_TYPE_PRIVATE) &&
	    PUSH_BYTES(OUI_TIA, OUI_LEN) &&
	    PUSH_UINT8(LLDP_PRIVATE_TIA_SUBTYPE_INVENTORY_FIRMWARE_REV) &&
	    PUSH_BYTES(sysinfo->fw_revision, strlen(sysinfo->fw_revision))
	))
	    return 0;
	END_LLDP_TLV;
    }


    // software revision
    if (strlen(sysinfo->sw_revision) > 0) {
	if (!(
	    START_LLDP_TLV(LLDP_TYPE_PRIVATE) &&
	    PUSH_BYTES(OUI_TIA, OUI_LEN) &&
	    PUSH_UINT8(LLDP_PRIVATE_TIA_SUBTYPE_INVENTORY_SOFTWARE_REV) &&
	    PUSH_BYTES(sysinfo->sw_revision, strlen(sysinfo->sw_revision))
	))
	    return 0;
	END_LLDP_TLV;
    }


    // serial number
    if (strlen(sysinfo->serial_number) > 0) {
	if (!(
	    START_LLDP_TLV(LLDP_TYPE_PRIVATE) &&
	    PUSH_BYTES(OUI_TIA, OUI_LEN) &&
	    PUSH_UINT8(LLDP_PRIVATE_TIA_SUBTYPE_INVENTORY_SERIAL_NUMBER) &&
	    PUSH_BYTES(sysinfo->serial_number, strlen(sysinfo->serial_number))
	))
	    return 0;
	END_LLDP_TLV;
    }


    // manufacturer
    if (strlen(sysinfo->manufacturer) > 0) {
	if (!(
	    START_LLDP_TLV(LLDP_TYPE_PRIVATE) &&
	    PUSH_BYTES(OUI_TIA, OUI_LEN) &&
	    PUSH_UINT8(LLDP_PRIVATE_TIA_SUBTYPE_INVENTORY_MANUFACTURER_NAME) &&
	    PUSH_BYTES(sysinfo->manufacturer, strlen(sysinfo->manufacturer))
	))
	    return 0;
	END_LLDP_TLV;
    }


    // model name
    if (strlen(sysinfo->model_name) > 0) {
	if (!(
	    START_LLDP_TLV(LLDP_TYPE_PRIVATE) &&
	    PUSH_BYTES(OUI_TIA, OUI_LEN) &&
	    PUSH_UINT8(LLDP_PRIVATE_TIA_SUBTYPE_INVENTORY_MODEL_NAME) &&
	    PUSH_BYTES(sysinfo->model_name, strlen(sysinfo->model_name))
	))
	    return 0;
	END_LLDP_TLV;
    }


    // asset id
    if (strlen(sysinfo->asset_id) > 0) {
	if (!(
	    START_LLDP_TLV(LLDP_TYPE_PRIVATE) &&
	    PUSH_BYTES(OUI_TIA, OUI_LEN) &&
	    PUSH_UINT8(LLDP_PRIVATE_TIA_SUBTYPE_INVENTORY_ASSET_ID) &&
	    PUSH_BYTES(sysinfo->asset_id, strlen(sysinfo->asset_id))
	))
	    return 0;
	END_LLDP_TLV;
    }



    // the end
    if (!(
	START_LLDP_TLV(LLDP_TYPE_END)
    ))
	return 0;
    END_LLDP_TLV;


    // return the packet length
    return(VOIDP_DIFF(pos, packet));
}

char * lldp_check(void *packet, size_t length) {
    struct ether_hdr ether;
    static uint8_t lldp_dst[] = LLDP_MULTICAST_ADDR;

    assert(packet);
    assert(length > sizeof(ether));
    assert(length <= ETHER_MAX_LEN);

    memcpy(&ether, packet, sizeof(ether));

    if ((memcmp(ether.dst, lldp_dst, ETHER_ADDR_LEN) == 0) &&
	(ether.type == htons(ETHERTYPE_LLDP))) {
	return(packet + sizeof(ether));
    }

    return(NULL);
}

size_t lldp_peer(struct master_msg *msg) {

    char *packet = NULL;
    size_t length;
    char *tlv;
    char *pos;
    tlv_t type;

    uint16_t tlv_type;
    uint16_t tlv_length;

    char *tlv_str = NULL;

    assert(msg);

    packet = msg->msg;
    length = msg->len;

    assert(packet);
    assert((pos = lldp_check(packet, length)) != NULL);
    length -= VOIDP_DIFF(pos, packet);

    if (!GRAB_LLDP_TLV(tlv_type, tlv_length) ||
	tlv_type != LLDP_TYPE_CHASSIS_ID) {
	my_log(INFO, "Invalid LLDP packet: missing Chassis ID TLV");
	return 0;
    }
    if ((tlv_length <= 1) || (tlv_length > 256)) {
	my_log(INFO, "Invalid LLDP packet: invalid Chassis ID TLV");
	return 0;
    }
    if (!SKIP(tlv_length))
	return 0;

    if (!GRAB_LLDP_TLV(tlv_type, tlv_length) ||
	tlv_type != LLDP_TYPE_PORT_ID) {
	my_log(INFO, "Invalid LLDP packet: missing Port ID TLV");
	return 0;
    }
    if ((tlv_length <= 1) || (tlv_length > 256)) {
	my_log(INFO, "Corrupt LLDP packet: invalid Port ID TLV");
	return 0;
    }
    // skip the subtype
    if (!SKIP(1)) {
	my_log(INFO, "Corrupt LLDP packet: invalid Port ID TLV");
	return 0;
    }
    if (!GRAB_STRING(tlv_str, tlv_length - 1)) {
	my_log(INFO, "Corrupt LLDP packet: invalid Port ID TLV");
	return 0;
    }
    strlcpy(msg->peer.port, tlv_str, IFDESCRSIZE);
    free(tlv_str);
    if (!SKIP(tlv_length))
	return 0;

    if (!GRAB_LLDP_TLV(tlv_type, tlv_length) ||
	tlv_type != LLDP_TYPE_TTL) {
	my_log(INFO, "Invalid LLDP packet: missing TTL TLV");
	return 0;
    }
    if (tlv_length != 2 || !GRAB_UINT16(msg->ttl)) {
	my_log(INFO, "Invalid LLDP packet: invalid TTL TLV");
	return 0;
    }

    while (length) {
	if (!GRAB_LLDP_TLV(tlv_type, tlv_length)) {
	    my_log(INFO, "Corrupt LLDP packet: invalid TLV");
	    return 0;
	}

	switch(tlv_type) {
	case LLDP_TYPE_END:
	    if ((tlv_length != 0) || (length != 0)) {
		my_log(INFO, "Corrupt LLDP packet: invalid END TLV");
		return 0;
	    }
	    break;
	case LLDP_TYPE_SYSTEM_NAME:
	    if (tlv_length > 255) {
		my_log(INFO, "Corrupt LLDP packet: invalid System Name TLV");
		return 0;
	    }
	    if (strlen(msg->peer.name) != 0) {
		my_log(INFO, "Corrupt LLDP packet: duplicate System Name TLV");
		return 0;
	    }
	    if (!GRAB_STRING(tlv_str, tlv_length)) {
		my_log(INFO, "Corrupt LLDP packet: invalid System Name TLV");
		return 0;
	    }
	    strlcpy(msg->peer.name, tlv_str, IFDESCRSIZE);
	    free(tlv_str);
	    break;
	default:
	    if (8 < tlv_type && tlv_type < 127) {
		my_log(INFO, "Corrupt LLDP packet: invalid TLV Type");
		return 0;
	    }
	    if (!SKIP(tlv_length)) {
		my_log(INFO, "Corrupt LLDP packet: invalid TLV Length");
		return 0;
	    }
	    break;
	}
    }

    if (tlv_type != 0) {
	my_log(INFO, "Corrupt LLDP packet: missing END TLV");
	return 0;
    }

    // return the packet length
    return(VOIDP_DIFF(pos, packet));
}

