/*
 * $Id$
 *
 * Copyright (c) 2008, 2009, 2010
 *      Sten Spans <sten@blinkenlights.nl>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _lldp_h
#define _lldp_h


#define LLDP_MULTICAST_ADDR     { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e }


// LLDP TLV types
#define LLDP_TYPE_END             0
#define LLDP_TYPE_CHASSIS_ID      1
#define LLDP_TYPE_PORT_ID         2
#define LLDP_TYPE_TTL             3
#define LLDP_TYPE_PORT_DESCR      4
#define LLDP_TYPE_SYSTEM_NAME     5
#define LLDP_TYPE_SYSTEM_DESCR    6
#define LLDP_TYPE_SYSTEM_CAP      7
#define LLDP_TYPE_MGMT_ADDR       8
#define LLDP_TYPE_PRIVATE       127

// Chassis ID subtypes
#define LLDP_CHASSIS_CHASSIS_COMP_SUBTYPE  1
#define LLDP_CHASSIS_INTF_ALIAS_SUBTYPE    2
#define LLDP_CHASSIS_PORT_COMP_SUBTYPE     3
#define LLDP_CHASSIS_MAC_ADDR_SUBTYPE      4
#define LLDP_CHASSIS_NETWORK_ADDR_SUBTYPE  5
#define LLDP_CHASSIS_INTF_NAME_SUBTYPE     6
#define LLDP_CHASSIS_LOCAL_SUBTYPE         7

// Port ID subtypes
#define LLDP_PORT_INTF_ALIAS_SUBTYPE       1
#define LLDP_PORT_PORT_COMP_SUBTYPE        2
#define LLDP_PORT_MAC_ADDR_SUBTYPE         3
#define LLDP_PORT_NETWORK_ADDR_SUBTYPE     4
#define LLDP_PORT_INTF_NAME_SUBTYPE        5
#define LLDP_PORT_AGENT_CIRC_ID_SUBTYPE    6
#define LLDP_PORT_LOCAL_SUBTYPE            7

// System Capabilities
#define LLDP_CAP_OTHER              (1 <<  0)
#define LLDP_CAP_REPEATER           (1 <<  1)
#define LLDP_CAP_BRIDGE             (1 <<  2)
#define LLDP_CAP_WLAN_AP            (1 <<  3)
#define LLDP_CAP_ROUTER             (1 <<  4)
#define LLDP_CAP_PHONE              (1 <<  5)
#define LLDP_CAP_DOCSIS             (1 <<  6)
#define LLDP_CAP_STATION_ONLY       (1 <<  7)

// Managment Addr Families
#define LLDP_AFNUM_INET			   1
#define LLDP_AFNUM_INET6		   2

// Organizationally Unique Identifiers
#define OUI_LEN		      3
#define OUI_IEEE_8021_PRIVATE "\x00\x80\xc2"	/* IEEE 802.1 - Annex F */
#define OUI_IEEE_8023_PRIVATE "\x00\x12\x0f"	/* IEEE 802.3 - Annex G */
#define OUI_TIA		      "\x00\x12\xbb"	/* TIA - ANSI/TIA-1057- 2006 */

// 802.3 TLV Subtypes
#define LLDP_PRIVATE_8023_SUBTYPE_MACPHY        1
#define LLDP_PRIVATE_8023_SUBTYPE_MDIPOWER      2
#define LLDP_PRIVATE_8023_SUBTYPE_LINKAGGR      3
#define LLDP_PRIVATE_8023_SUBTYPE_MTU           4

// From RFC 3636 - dot3MauType
#define LLDP_MAU_TYPE_UNKNOWN           0
#define LLDP_MAU_TYPE_AUI               1
#define LLDP_MAU_TYPE_10BASE_5          2
#define LLDP_MAU_TYPE_FOIRL             3
#define LLDP_MAU_TYPE_10BASE_2          4
#define LLDP_MAU_TYPE_10BASE_T          5
#define LLDP_MAU_TYPE_10BASE_FP         6
#define LLDP_MAU_TYPE_10BASE_FB         7
#define LLDP_MAU_TYPE_10BASE_FL         8
#define LLDP_MAU_TYPE_10BROAD36         9
#define LLDP_MAU_TYPE_10BASE_T_HD       10
#define LLDP_MAU_TYPE_10BASE_T_FD       11
#define LLDP_MAU_TYPE_10BASE_FL_HD      12
#define LLDP_MAU_TYPE_10BASE_FL_FD      13
#define LLDP_MAU_TYPE_100BASE_T4        14
#define LLDP_MAU_TYPE_100BASE_TX_HD     15
#define LLDP_MAU_TYPE_100BASE_TX_FD     16
#define LLDP_MAU_TYPE_100BASE_FX_HD     17
#define LLDP_MAU_TYPE_100BASE_FX_FD     18
#define LLDP_MAU_TYPE_100BASE_T2_HD     19
#define LLDP_MAU_TYPE_100BASE_T2_FD     20
#define LLDP_MAU_TYPE_1000BASE_X_HD     21
#define LLDP_MAU_TYPE_1000BASE_X_FD     22
#define LLDP_MAU_TYPE_1000BASE_LX_HD    23
#define LLDP_MAU_TYPE_1000BASE_LX_FD    24
#define LLDP_MAU_TYPE_1000BASE_SX_HD    25
#define LLDP_MAU_TYPE_1000BASE_SX_FD    26
#define LLDP_MAU_TYPE_1000BASE_CX_HD    27
#define LLDP_MAU_TYPE_1000BASE_CX_FD    28
#define LLDP_MAU_TYPE_1000BASE_T_HD     29
#define LLDP_MAU_TYPE_1000BASE_T_FD     30
#define LLDP_MAU_TYPE_10GBASE_X         31
#define LLDP_MAU_TYPE_10GBASE_LX4       32
#define LLDP_MAU_TYPE_10GBASE_R         33
#define LLDP_MAU_TYPE_10GBASE_ER        34
#define LLDP_MAU_TYPE_10GBASE_LR        35
#define LLDP_MAU_TYPE_10GBASE_SR        36
#define LLDP_MAU_TYPE_10GBASE_W         37
#define LLDP_MAU_TYPE_10GBASE_EW        38
#define LLDP_MAU_TYPE_10GBASE_LW        39
#define LLDP_MAU_TYPE_10GBASE_SW        40

// From RFC 3636 - ifMauAutoNegCapAdvertisedBits
#define	LLDP_MAU_PMD_OTHER		(1 <<  15)
#define	LLDP_MAU_PMD_10BASE_T		(1 <<  14)
#define	LLDP_MAU_PMD_10BASE_T_FD	(1 <<  13)
#define	LLDP_MAU_PMD_100BASE_T4		(1 <<  12)
#define	LLDP_MAU_PMD_100BASE_TX		(1 <<  11)
#define	LLDP_MAU_PMD_100BASE_TX_FD	(1 <<  10)
#define	LLDP_MAU_PMD_100BASE_T2		(1 <<  9)
#define	LLDP_MAU_PMD_100BASE_T2_FD	(1 <<  8)
#define	LLDP_MAU_PMD_FDXPAUSE		(1 <<  7)
#define	LLDP_MAU_PMD_FDXAPAUSE		(1 <<  6)
#define	LLDP_MAU_PMD_FDXSPAUSE		(1 <<  5)
#define	LLDP_MAU_PMD_FDXBPAUSE		(1 <<  4)
#define	LLDP_MAU_PMD_1000BASE_X		(1 <<  3)
#define	LLDP_MAU_PMD_1000BASE_X_FD	(1 <<  2)
#define	LLDP_MAU_PMD_1000BASE_T		(1 <<  1)
#define	LLDP_MAU_PMD_1000BASE_T_FD	(1 <<  0)

// LACP options
#define LLDP_AGGREGATION_CAPABILTIY     (1 <<  0)
#define LLDP_AGGREGATION_STATUS         (1 <<  1)

// Interface numbering subtypes.
#define LLDP_INTF_NUMB_IFX_SUBTYPE         2
#define LLDP_INTF_NUMB_SYSPORT_SUBTYPE     3

// TIA TLV Subtypes
#define LLDP_PRIVATE_TIA_SUBTYPE_CAPABILITIES                   1
#define LLDP_PRIVATE_TIA_SUBTYPE_NETWORK_POLICY                 2
#define LLDP_PRIVATE_TIA_SUBTYPE_LOCAL_ID                       3
#define LLDP_PRIVATE_TIA_SUBTYPE_EXTENDED_POWER_MDI             4
#define LLDP_PRIVATE_TIA_SUBTYPE_INVENTORY_HARDWARE_REV         5
#define LLDP_PRIVATE_TIA_SUBTYPE_INVENTORY_FIRMWARE_REV         6
#define LLDP_PRIVATE_TIA_SUBTYPE_INVENTORY_SOFTWARE_REV         7
#define LLDP_PRIVATE_TIA_SUBTYPE_INVENTORY_SERIAL_NUMBER        8
#define LLDP_PRIVATE_TIA_SUBTYPE_INVENTORY_MANUFACTURER_NAME    9
#define LLDP_PRIVATE_TIA_SUBTYPE_INVENTORY_MODEL_NAME           10
#define LLDP_PRIVATE_TIA_SUBTYPE_INVENTORY_ASSET_ID             11

#define LLDP_TIA_LOCATION_DATA_FORMAT_COORDINATE_BASED  1
#define LLDP_TIA_LOCATION_DATA_FORMAT_CIVIC_ADDRESS     2
#define LLDP_TIA_LOCATION_DATA_FORMAT_ECS_ELIN          3

#define LLDP_TIA_LOCATION_LCI_WHAT_CLIENT   2
#define LLDP_TIA_LOCATION_LCI_CATYPE_LOC    22

#endif /* _lldp_h */
