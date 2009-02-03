/*
 $Id$
*/

#include "common.h"
#include "util.h"
#include "proto/ndp.h"
#include "proto/tlv.h"


size_t ndp_packet(void *packet, struct netif *netif, struct sysinfo *sysinfo) {

    struct ether_hdr ether;
    struct ether_llc llc;
    struct ndp_header ndp;

    uint8_t *pos = packet;

    struct netif *master;

    const uint8_t ndp_dst[] = NDP_MULTICAST_ADDR;
    const uint8_t llc_org[] = LLC_ORG_NORTEL;

    // fixup master netif
    if (netif->master != NULL)
	master = netif->master;
    else
	master = netif;

    // ethernet header
    memcpy(ether.dst, ndp_dst, ETHER_ADDR_LEN);
    memcpy(ether.src, netif->hwaddr, ETHER_ADDR_LEN);
    pos += sizeof(struct ether_hdr);

    // llc snap header
    llc.dsap = llc.ssap = 0xaa;
    llc.control = 0x03;
    memcpy(llc.org, llc_org, sizeof(llc.org));
    llc.protoid = htons(LLC_PID_NDP_HELLO);
    memcpy(pos, &llc, sizeof(struct ether_llc));
    pos += sizeof(struct ether_llc);

    // ndp header
    memset(&ndp, 0, sizeof(struct ndp_header));
    ndp.addr = master->ipaddr4;
    ndp.seg[2] = netif->index;
    ndp.chassis = NDP_CHASSIS_OTHER;
    ndp.backplane = NDP_BACKPLANE_ETH_FE_GE;
    ndp.links = sysinfo->physif_count;
    ndp.state = NDP_TOPOLOGY_NEW;
    memcpy(pos, &ndp, sizeof(struct ndp_header));
    pos += sizeof(struct ndp_header);


    // ethernet header
    ether.length = htons(VOIDP_DIFF(pos, packet + sizeof(struct ether_hdr)));
    memcpy(packet, &ether, sizeof(struct ether_hdr));

    // packet length
    return(VOIDP_DIFF(pos, packet));
}

