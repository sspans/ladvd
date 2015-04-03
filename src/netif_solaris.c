/*
 * Copyright (c) 2012
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

#include <strings.h>
#include <libdladm.h>
#include <libdllink.h>

#include <net/if_arp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>

#include "common.h"
#include "util.h"

static dladm_handle_t dla_handle = NULL;

// detect interface type
static int netif_type(int sockfd, uint32_t index,
	struct ifaddrs *ifaddr, struct ifreq *ifr) {

    // default
    return(NETIF_REGULAR);
}

static void netif_device_id(int sockfd, struct netif *netif, struct ifreq *ifr) {
    return;
}

// handle aggregated interfaces
static void netif_bond(int sockfd, struct nhead *netifs, struct netif *parent,
		struct ifreq *ifr) {
    return;
}


// handle bridge interfaces
static void netif_bridge(int sockfd, struct nhead *netifs, struct netif *parent,
		  struct ifreq *ifr) {
    return;
}


// handle vlan interfaces
static void netif_vlan(int sockfd, struct nhead *netifs, struct netif *vlan,
		  struct ifreq *ifr) {

    return;
}



// perform media detection on physical interfaces
static int netif_physical(int sockfd, struct netif *netif) {

    return(EXIT_SUCCESS);
}

static boolean_t sockaddr_cb(void *start, dladm_macaddr_attr_t *addr) {
    struct ifaddrs **end = start;
    struct sockaddr_ll *saddrll = NULL;

    saddrll = my_malloc(sizeof(*saddrll));
    *end = my_malloc(sizeof(**end));

    saddrll->sll_family = AF_PACKET;
    saddrll->sll_hatype = ARPHRD_ETHER;
    saddrll->sll_ifindex = if_nametoindex(addr->ma_client_name);
    saddrll->sll_halen = addr->ma_addrlen;
    memcpy(saddrll->sll_addr, addr->ma_addr, addr->ma_addrlen);

    (*end)->ifa_next = NULL;
    (*end)->ifa_name = my_strdup(addr->ma_client_name);
    (*end)->ifa_addr = (struct sockaddr *)saddrll;
    (*end)->ifa_netmask = NULL;
    (*end)->ifa_data = NULL;

    end = &(*end)->ifa_next;

    return 0;
}

static int dl_cb(dladm_handle_t dh, datalink_id_t linkid, void *start) {
    return (dladm_walk_macaddr(dh, linkid, start, sockaddr_cb));
}

int getifaddrs(struct ifaddrs **ifap) {
    struct ifaddrs *start;

    (void) dladm_walk_datalink_id(dl_cb, dla_handle, &start,
	DATALINK_CLASS_PHYS, DL_ETHER, DLADM_OPT_ACTIVE);

    *ifap = start;
    return 0;
}

void freeifaddrs(struct ifaddrs *ifp) {
    struct ifaddrs *p, *q;

    for(p = ifp; p; ) {
	free(p->ifa_name);
	if(p->ifa_addr)
	    free(p->ifa_addr);
	q = p;
	p = p->ifa_next;
	free(q);
    }
}

void netif_init_custom() {
    dladm_status_t status;
    struct ifaddrs *ifaddrs = NULL;

    if (dla_handle != NULL)
	return;
    if ((status = dladm_open(&dla_handle, NULL)) != DLADM_STATUS_OK)
	my_fatale("dladm_open failed");

    // open the DLMGMT_DOOR
    if (getifaddrs(&ifaddrs) == 0)
	freeifaddrs(ifaddrs);
}
