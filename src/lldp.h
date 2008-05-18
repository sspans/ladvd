
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
#define OUI_IEEE_8021_PRIVATE "\x00\x80\xc2"	/* IEEE 802.1 - Annex F */
#define OUI_IEEE_8023_PRIVATE "\x00\x12\x0f"	/* IEEE 802.3 - Annex G */
#define OUI_TIA		      "\x00\x12\xbb"	/* TIA - ANSI/TIA-1057- 2006 */

/*
 * 802.3 TLV Subtypes
 */
#define LLDP_PRIVATE_8023_SUBTYPE_MACPHY        1
#define LLDP_PRIVATE_8023_SUBTYPE_MDIPOWER      2
#define LLDP_PRIVATE_8023_SUBTYPE_LINKAGGR      3
#define LLDP_PRIVATE_8023_SUBTYPE_MTU           4

/*
 * From RFC 3636 - dot3MauType
 */
#define         LLDP_MAU_TYPE_UNKNOWN           0
#define         LLDP_MAU_TYPE_AUI               1
#define         LLDP_MAU_TYPE_10BASE_5          2
#define         LLDP_MAU_TYPE_FOIRL             3
#define         LLDP_MAU_TYPE_10BASE_2          4
#define         LLDP_MAU_TYPE_10BASE_T          5
#define         LLDP_MAU_TYPE_10BASE_FP         6
#define         LLDP_MAU_TYPE_10BASE_FB         7
#define         LLDP_MAU_TYPE_10BASE_FL         8
#define         LLDP_MAU_TYPE_10BROAD36         9
#define         LLDP_MAU_TYPE_10BASE_T_HD       10
#define         LLDP_MAU_TYPE_10BASE_T_FD       11
#define         LLDP_MAU_TYPE_10BASE_FL_HD      12
#define         LLDP_MAU_TYPE_10BASE_FL_FD      13
#define         LLDP_MAU_TYPE_100BASE_T4        14
#define         LLDP_MAU_TYPE_100BASE_TX_HD     15
#define         LLDP_MAU_TYPE_100BASE_TX_FD     16
#define         LLDP_MAU_TYPE_100BASE_FX_HD     17
#define         LLDP_MAU_TYPE_100BASE_FX_FD     18
#define         LLDP_MAU_TYPE_100BASE_T2_HD     19
#define         LLDP_MAU_TYPE_100BASE_T2_FD     20
#define         LLDP_MAU_TYPE_1000BASE_X_HD     21
#define         LLDP_MAU_TYPE_1000BASE_X_FD     22
#define         LLDP_MAU_TYPE_1000BASE_LX_HD    23
#define         LLDP_MAU_TYPE_1000BASE_LX_FD    24
#define         LLDP_MAU_TYPE_1000BASE_SX_HD    25
#define         LLDP_MAU_TYPE_1000BASE_SX_FD    26
#define         LLDP_MAU_TYPE_1000BASE_CX_HD    27
#define         LLDP_MAU_TYPE_1000BASE_CX_FD    28
#define         LLDP_MAU_TYPE_1000BASE_T_HD     29
#define         LLDP_MAU_TYPE_1000BASE_T_FD     30
#define         LLDP_MAU_TYPE_10GBASE_X         31
#define         LLDP_MAU_TYPE_10GBASE_LX4       32
#define         LLDP_MAU_TYPE_10GBASE_R         33
#define         LLDP_MAU_TYPE_10GBASE_ER        34
#define         LLDP_MAU_TYPE_10GBASE_LR        35
#define         LLDP_MAU_TYPE_10GBASE_SR        36
#define         LLDP_MAU_TYPE_10GBASE_W         37
#define         LLDP_MAU_TYPE_10GBASE_EW        38
#define         LLDP_MAU_TYPE_10GBASE_LW        39
#define         LLDP_MAU_TYPE_10GBASE_SW        40


struct lldp_packet {
	uint8_t hwaddr[6];
	char *port_id;
	uint16_t ttl;
	char *system_name;
	char *system_descr;
	uint16_t system_cap;
	uint32_t mgmt_addr4;
	//v6
	int8_t autoneg;
	uint16_t mau;
	uint16_t mtu;
};

