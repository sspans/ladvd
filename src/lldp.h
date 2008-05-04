
static uint8_t lldp_mac[] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e };

/*
 * TLV type codes
 */
#define LLDP_END_TLV             0
#define LLDP_CHASSIS_ID_TLV      1
#define LLDP_PORT_ID_TLV         2
#define LLDP_TTL_TLV             3
#define LLDP_PORT_DESCR_TLV      4
#define LLDP_SYSTEM_NAME_TLV     5
#define LLDP_SYSTEM_DESCR_TLV    6
#define LLDP_SYSTEM_CAP_TLV      7
#define LLDP_MGMT_ADDR_TLV       8
#define LLDP_PRIVATE_TLV       127

/*
 * Chassis ID subtypes
 */
#define LLDP_CHASSIS_CHASSIS_COMP_SUBTYPE  1
#define LLDP_CHASSIS_INTF_ALIAS_SUBTYPE    2
#define LLDP_CHASSIS_PORT_COMP_SUBTYPE     3
#define LLDP_CHASSIS_MAC_ADDR_SUBTYPE      4
#define LLDP_CHASSIS_NETWORK_ADDR_SUBTYPE  5
#define LLDP_CHASSIS_INTF_NAME_SUBTYPE     6
#define LLDP_CHASSIS_LOCAL_SUBTYPE         7

/*
 * Port ID subtypes
 */
#define LLDP_PORT_INTF_ALIAS_SUBTYPE       1
#define LLDP_PORT_PORT_COMP_SUBTYPE        2
#define LLDP_PORT_MAC_ADDR_SUBTYPE         3
#define LLDP_PORT_NETWORK_ADDR_SUBTYPE     4
#define LLDP_PORT_INTF_NAME_SUBTYPE        5
#define LLDP_PORT_AGENT_CIRC_ID_SUBTYPE    6
#define LLDP_PORT_LOCAL_SUBTYPE            7

/*
 * System Capabilities
 */
#define LLDP_CAP_OTHER              (1 <<  0)
#define LLDP_CAP_REPEATER           (1 <<  1)
#define LLDP_CAP_BRIDGE             (1 <<  2)
#define LLDP_CAP_WLAN_AP            (1 <<  3)
#define LLDP_CAP_ROUTER             (1 <<  4)
#define LLDP_CAP_PHONE              (1 <<  5)
#define LLDP_CAP_DOCSIS             (1 <<  6)
#define LLDP_CAP_STATION_ONLY       (1 <<  7)

/*
 * Managment Addr Families
 */
#define LLDP_AFNUM_INET			   1
#define LLDP_AFNUM_INET6		   2

/*
 * Organizationally Unique Identifiers
 */
#define OUI_IEEE_8021_PRIVATE 0x0080c2      /* IEEE 802.1 - Annex F */
#define OUI_IEEE_8023_PRIVATE 0x00120f      /* IEEE 802.3 - Annex G */
#define OUI_TIA		      0x0012bb	    /* TIA - ANSI/TIA-1057- 2006 */

/*
 * 802.3 TLV Subtypes
 */
#define LLDP_PRIVATE_8023_SUBTYPE_MACPHY        1
#define LLDP_PRIVATE_8023_SUBTYPE_MDIPOWER      2
#define LLDP_PRIVATE_8023_SUBTYPE_LINKAGGR      3
#define LLDP_PRIVATE_8023_SUBTYPE_MTU           4


struct lldp_packet {
	uint8_t hwaddr[6];
	char *port_id;
	uint16_t ttl;
	char *system_name;
	char *system_descr;
	uint16_t system_cap;
	uint32_t mgmt_addr4;
	//v6
	uint32_t mtu;
};

