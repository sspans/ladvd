/*
 $Id$
*/

#include "common.h"
#include "util.h"
#include "edp.h"
#include "tlv.h"

int edp_count = 0;

size_t edp_packet(void *packet, struct netif *netif, struct sysinfo *sysinfo) {

    struct ether_hdr ether;
    struct ether_llc llc;
    struct edp_header edp;

    uint8_t *tlv;
    uint8_t *pos = packet;
    size_t length = ETHER_MAX_LEN;

    void *edp_start;
    struct netif *master;

    const uint8_t edp_dst[] = EDP_MULTICAST_ADDR;
    const uint8_t llc_org[] = LLC_ORG_EXTREME;

    // fixup master netif
    if (netif->master != NULL)
	master = netif->master;
    else
	master = netif;

    // ethernet header
    memcpy(ether.dst, edp_dst, ETHER_ADDR_LEN);
    memcpy(ether.src, netif->hwaddr, ETHER_ADDR_LEN);
    pos += sizeof(struct ether_hdr);

    // llc snap header
    llc.dsap = llc.ssap = 0xaa;
    llc.control = 0x03;
    memcpy(llc.org, llc_org, sizeof(llc.org));
    llc.protoid = htons(LLC_PID_EDP);
    memcpy(pos, &llc, sizeof(struct ether_llc));
    pos += sizeof(struct ether_llc);

    // edp header
    memset(&edp, 0, sizeof(edp));
    edp.version = 1;
    edp.sequence = htons(edp_count++);
    memcpy(&edp.hwaddr, sysinfo->hwaddr, ETHER_ADDR_LEN);
    edp_start = pos;

    // update tlv counters
    pos += sizeof(struct edp_header);
    length -= VOIDP_DIFF(pos, packet);


    // display
    if (!(
	START_EDP_TLV(EDP_TYPE_DISPLAY) &&
	PUSH_BYTES(sysinfo->hostname, strlen(sysinfo->hostname))
    ))
	return 0;
    END_EDP_TLV;


    // info
    if (!(
	START_EDP_TLV(EDP_TYPE_INFO) &&
	PUSH_UINT16(0) && PUSH_UINT16(netif->index) && PUSH_UINT16(0) &&
	PUSH_UINT16(0) && PUSH_UINT32(0) &&
	PUSH_UINT8(sysinfo->uts_rel[0]) && PUSH_UINT8(sysinfo->uts_rel[1]) &&
	PUSH_UINT8(sysinfo->uts_rel[2]) && PUSH_UINT8(0) &&
	PUSH_UINT16(0xffff) && PUSH_UINT16(0) &&
	PUSH_UINT32(0) && PUSH_UINT32(0) && PUSH_UINT32(0)
    ))
	return 0;
    END_EDP_TLV;


    // vlan
    if (master->ipaddr4 != 0) {
	if (!(
	    START_EDP_TLV(EDP_TYPE_VLAN) && PUSH_UINT8(1 << 7) &&
	    PUSH_BYTES("\x00\x00\x00", 3) && PUSH_UINT16(0) && PUSH_UINT16(0) &&
	    PUSH_BYTES(&master->ipaddr4, sizeof(master->ipaddr4)) &&
	    PUSH_BYTES(netif->name, strlen(netif->name))
	))
	    return 0;
	END_EDP_TLV;
    }


    // the end
    if (!(
	START_EDP_TLV(EDP_TYPE_NULL)
    ))
	return 0;
    END_EDP_TLV;


    // edp header
    edp.length = htons(VOIDP_DIFF(pos, edp_start));
    memcpy(edp_start, &edp, sizeof(struct edp_header));
    edp.checksum = my_chksum(edp_start, VOIDP_DIFF(pos, edp_start), 0);
    memcpy(edp_start, &edp, sizeof(struct edp_header));

    // ethernet header
    ether.length = htons(VOIDP_DIFF(pos, packet + sizeof(struct ether_hdr)));
    memcpy(packet, &ether, sizeof(struct ether_hdr));

    // packet length
    return(VOIDP_DIFF(pos, packet));
}

