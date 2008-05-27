
/*
 * CDP capabilities.
 */
#define CDP_CAP_ROUTER             0x01
#define CDP_CAP_TRANSPARENT_BRIDGE 0x02
#define CDP_CAP_SOURCE_BRIDGE      0x04
#define CDP_CAP_SWITCH             0x08
#define CDP_CAP_HOST               0x10
#define CDP_CAP_IGMP               0x20
#define CDP_CAP_REPEATER           0x40

/*
 * CDP chunk types.
 */
#define CDP_TYPE_DEVICE_ID         0x0001
#define CDP_TYPE_ADDRESS           0x0002
#define CDP_TYPE_PORT_ID           0x0003
#define CDP_TYPE_CAPABILITIES      0x0004
#define CDP_TYPE_IOS_VERSION       0x0005
#define CDP_TYPE_PLATFORM          0x0006
#define CDP_TYPE_IP_PREFIX         0x0007
#define CDP_TYPE_PROTOCOL_HELLO    0x0008
#define CDP_TYPE_VTP_MGMT_DOMAIN   0x0009
#define CDP_TYPE_NATIVE_VLAN       0x000a
#define CDP_TYPE_DUPLEX            0x000b
#define CDP_TYPE_UNKNOWN_0x000c    0x000c
#define CDP_TYPE_UNKNOWN_0x000d    0x000d
#define CDP_TYPE_APPLIANCE_REPLY   0x000e
#define CDP_TYPE_APPLIANCE_QUERY   0x000f
#define CDP_TYPE_POWER_CONSUMPTION 0x0010
#define CDP_TYPE_MTU               0x0011
#define CDP_TYPE_EXTENDED_TRUST    0x0012
#define CDP_TYPE_UNTRUSTED_COS     0x0013
#define CDP_TYPE_SYSTEM_NAME       0x0014
#define CDP_TYPE_SYSTEM_OID        0x0015
#define CDP_TYPE_MGMT_ADDRESS      0x0016
#define CDP_TYPE_LOCATION          0x0017

/*
 * CDP Addr types.
 */

#define CDP_ADDR_PROTO_CLNP      0
#define CDP_ADDR_PROTO_IPV4      1
#define CDP_ADDR_PROTO_IPV6      2
#define CDP_ADDR_PROTO_DECNET    3
#define CDP_ADDR_PROTO_APPLETALK 4
#define CDP_ADDR_PROTO_IPX       5
#define CDP_ADDR_PROTO_VINES     6
#define CDP_ADDR_PROTO_XNS       7
#define CDP_ADDR_PROTO_APOLLO    8

struct cdp_predef {
	uint8_t protocol_type;
	uint8_t protocol_length;
	void *protocol;
};

struct cdp_predef cdp_predefs[] = {
	/* CDP_ADDR_PROTO_CLNP      */
	{ 0x01, 1, "\x81" },
	/* CDP_ADDR_PROTO_IPV4      */
	{ 0x01, 1, "\xcc" },
	/* CDP_ADDR_PROTO_IPV6      */
	{ 0x02, 8, "\xaa\xaa\x03\x00\x00\x00\x80\xdd" },
};


struct cdp_packet {
	uint8_t version;
	uint8_t ttl;
	uint16_t checksum;
	char *device_id;
	uint32_t address4;
	char *port_id;
	uint32_t capabilities;
	char *ios_version;
	char *platform;
	uint8_t duplex;
	uint16_t mtu;
	char *system_name;
};

