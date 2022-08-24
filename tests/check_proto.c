/*
 * $Id$
 *
 * Copyright (c) 2008, 2009
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

#include "config.h"
#include <check.h>
#include <pcap.h>

#include "common.h"
#include "util.h"
#include "proto/protos.h"
#include "main.h"
#include "check_wrap.h"

uint32_t options = OPT_DAEMON | OPT_CHECK;

START_TEST(test_proto_packet) {
    struct parent_msg msg = {};
    struct netif parent, netif, vlan1, vlan2;
    struct nhead netifs;
    struct my_sysinfo sysinfo = {};

    mark_point();
    strlcpy(sysinfo.uts_str, "Testing", sizeof(sysinfo.uts_str));
    sysinfo.cap_active = CAP_ROUTER;
    sysinfo.country[0] = 'Z';
    sysinfo.country[1] = 'Z';
    sysinfo.uts_rel[0] = 12;
    sysinfo.uts_rel[1] = 34;
    sysinfo.uts_rel[2] = 56;
    memset(sysinfo.hwaddr, 77, ETHER_ADDR_LEN);
    strlcpy(sysinfo.uts_str, "Testing", sizeof(sysinfo.uts_str));
    strlcpy(sysinfo.uts.sysname, "Testing", sizeof(sysinfo.uts.sysname));
    strlcpy(sysinfo.platform, "Testing VAX", sizeof(sysinfo.platform));
    strlcpy(sysinfo.hostname, "Blanket", sizeof(sysinfo.hostname));
    strlcpy(sysinfo.location, "Towel", sizeof(sysinfo.location));
    strlcpy(sysinfo.hinv.hw_revision, "lala", LLDP_INVENTORY_SIZE);  
    strlcpy(sysinfo.hinv.fw_revision, "lala", LLDP_INVENTORY_SIZE);  
    strlcpy(sysinfo.hinv.sw_revision, "lala", LLDP_INVENTORY_SIZE);  
    strlcpy(sysinfo.hinv.serial_number, "lala", LLDP_INVENTORY_SIZE);  
    strlcpy(sysinfo.hinv.manufacturer, "lala", LLDP_INVENTORY_SIZE);  
    strlcpy(sysinfo.hinv.model_name, "lala", LLDP_INVENTORY_SIZE);  
    strlcpy(sysinfo.hinv.asset_id, "lala", LLDP_INVENTORY_SIZE);  

    sysinfo.mnetif = &parent;

    memset(&parent, 0, sizeof(struct netif));
    parent.index = 3;
    parent.argv = 1;
    parent.child = 0;
    parent.bonding_mode = NETIF_BONDING_LACP;
    parent.type = NETIF_BONDING;
    netif.mtu = 1500;
    parent.subif = &netif;
    parent.parent = NULL;
    parent.ipaddr4 = htonl(0x7f000001);
    memset(parent.ipaddr6, 'a', sizeof(parent.ipaddr6));
    strlcpy(parent.name, "bond0", IFNAMSIZ);

    memset(&netif, 0, sizeof(struct netif));
    netif.index = 1;
    netif.argv = 0;
    netif.child = 1;
    netif.type = NETIF_REGULAR;
    netif.mtu = 9000;
    netif.duplex = 1;
    netif.subif = NULL;
    netif.parent = &parent;
    parent.ipaddr4 = htonl(0xa0000001);
    memset(parent.ipaddr6, 'b', sizeof(parent.ipaddr6));
    strlcpy(netif.name, "eth0", IFNAMSIZ);
    strlcpy(netif.device_name, "KittenNic Turbo", IFDESCRSIZE);
    strlcpy(netif.description, "utp naar de buren", IFNAMSIZ);

    memset(&vlan1, 0, sizeof(struct netif));
    vlan1.index = 4;
    vlan1.argv = 0;
    vlan2.type = NETIF_VLAN;
    vlan1.vlan_id = 1;
    vlan1.vlan_parent = 3;
    strlcpy(vlan1.name, "vlan1", IFNAMSIZ);

    memset(&vlan2, 0, sizeof(struct netif));
    vlan2.index = 6;
    vlan2.argv = 0;
    vlan2.type = NETIF_VLAN;
    vlan2.vlan_id = 42;
    vlan2.vlan_parent = 1;
    strlcpy(vlan2.name, "eth0.42", IFNAMSIZ);


    TAILQ_INIT(&netifs);
    TAILQ_INSERT_TAIL(&netifs, &netif, entries);
    TAILQ_INSERT_TAIL(&netifs, &parent, entries);
    TAILQ_INSERT_TAIL(&netifs, &vlan1, entries);
    TAILQ_INSERT_TAIL(&netifs, &vlan2, entries);

    mark_point();
    memset(msg.msg, 0, ETHER_MAX_LEN);
    msg.len = lldp_packet(PROTO_LLDP, msg.msg, &netif, &netifs, &sysinfo);
    ck_assert_msg(msg.len == 276, "length should not be %ld", msg.len);
    msg.len = cdp_packet(PROTO_CDP, msg.msg, &netif, &netifs, &sysinfo);
    ck_assert_msg(msg.len == 203, "length should not be %ld", msg.len);
    msg.len = edp_packet(PROTO_EDP, msg.msg, &netif, &netifs, &sysinfo);
    ck_assert_msg(msg.len == 131, "length should not be %ld", msg.len);
    msg.len = fdp_packet(PROTO_FDP, msg.msg, &netif, &netifs, &sysinfo);
    ck_assert_msg(msg.len == 126, "length should not be %ld", msg.len);
    msg.len = ndp_packet(PROTO_NDP, msg.msg, &netif, &netifs, &sysinfo);
    ck_assert_msg(msg.len == 64, "length should not be %ld", msg.len);

    mark_point();
    sysinfo.cap = CAP_HOST;
    sysinfo.cap_active = CAP_HOST;
    netif.parent = NULL;
    msg.len = lldp_packet(PROTO_LLDP, msg.msg, &netif, &netifs, &sysinfo);
    ck_assert_msg(msg.len == 265, "length should not be %ld", msg.len);
    msg.len = cdp_packet(PROTO_CDP, msg.msg, &netif, &netifs, &sysinfo);
    ck_assert_msg(msg.len == 158, "length should not be %ld", msg.len);
    msg.len = edp_packet(PROTO_EDP, msg.msg, &netif, &netifs, &sysinfo);
    ck_assert_msg(msg.len == 110, "length should not be %ld", msg.len);
    msg.len = fdp_packet(PROTO_FDP, msg.msg, &netif, &netifs, &sysinfo);
    ck_assert_msg(msg.len == 124, "length should not be %ld", msg.len);
    msg.len = ndp_packet(PROTO_NDP, msg.msg, &netif, &netifs, &sysinfo);
    ck_assert_msg(msg.len == 64, "length should not be %ld", msg.len);

    mark_point();
    sysinfo.cap_active = CAP_BRIDGE;
    msg.len = lldp_packet(PROTO_LLDP, msg.msg, &netif, &netifs, &sysinfo);
    ck_assert_msg(msg.len == 265, "length should not be %ld", msg.len);
    msg.len = cdp_packet(PROTO_CDP, msg.msg, &netif, &netifs, &sysinfo);
    ck_assert_msg(msg.len == 158, "length should not be %ld", msg.len);
    msg.len = edp_packet(PROTO_EDP, msg.msg, &netif, &netifs, &sysinfo);
    ck_assert_msg(msg.len == 110, "length should not be %ld", msg.len);
    msg.len = fdp_packet(PROTO_FDP, msg.msg, &netif, &netifs, &sysinfo);
    ck_assert_msg(msg.len == 126, "length should not be %ld", msg.len);
    msg.len = ndp_packet(PROTO_NDP, msg.msg, &netif, &netifs, &sysinfo);
    ck_assert_msg(msg.len == 64, "length should not be %ld", msg.len);

    mark_point();
    sysinfo.cap_active = CAP_SWITCH;
    msg.len = lldp_packet(PROTO_LLDP, msg.msg, &netif, &netifs, &sysinfo);
    ck_assert_msg(msg.len == 265, "length should not be %ld", msg.len);
    msg.len = cdp_packet(PROTO_CDP, msg.msg, &netif, &netifs, &sysinfo);
    ck_assert_msg(msg.len == 158, "length should not be %ld", msg.len);
    msg.len = edp_packet(PROTO_EDP, msg.msg, &netif, &netifs, &sysinfo);
    ck_assert_msg(msg.len == 110, "length should not be %ld", msg.len);
    msg.len = fdp_packet(PROTO_FDP, msg.msg, &netif, &netifs, &sysinfo);
    ck_assert_msg(msg.len == 126, "length should not be %ld", msg.len);
    msg.len = ndp_packet(PROTO_NDP, msg.msg, &netif, &netifs, &sysinfo);
    ck_assert_msg(msg.len == 64, "length should not be %ld", msg.len);

    mark_point();
    sysinfo.cap = CAP_HOST;
    sysinfo.cap_active = CAP_HOST;
    options |= OPT_IFDESCR;
    netif.parent = NULL;
    msg.len = lldp_packet(PROTO_LLDP, msg.msg, &netif, &netifs, &sysinfo);
    ck_assert_msg(msg.len == 265, "length should not be %ld", msg.len);
    options &= ~OPT_IFDESCR;
    memset(netif.description, 0, IFNAMSIZ);
    strlcpy(netif.device_name, "KittenNic Turbo 2", IFDESCRSIZE);
    msg.len = lldp_packet(PROTO_LLDP, msg.msg, &netif, &netifs, &sysinfo);
    ck_assert_msg(msg.len == 267, "length should not be %ld", msg.len);
}
END_TEST

START_TEST(test_lldp_check) {
    struct parent_msg msg = {};
    struct ether_hdr ether = {};
    static uint8_t lldp_dst[] = LLDP_MULTICAST_ADDR;

    mark_point();
    msg.len = ETHER_MIN_LEN;
    ck_assert_msg(lldp_check(msg.msg, msg.len) == NULL,
	    "empty packets should generate a NULL");

    mark_point();
    memcpy(ether.dst, lldp_dst, ETHER_ADDR_LEN);
    memcpy(msg.msg, &ether, sizeof(ether));
    ck_assert_msg(lldp_check(msg.msg, msg.len) == NULL,
	    "packets without an ethertype should generate a NULL");

    mark_point();
    ether.type = htons(ETHERTYPE_VLAN);
    memcpy(msg.msg, &ether, sizeof(ether));
    ck_assert_msg(lldp_check(msg.msg, msg.len) == NULL,
	    "packets without an encapsulated ethertype should generate a NULL");

    ether.type = htons(ETHERTYPE_LLDP);
    memcpy(msg.msg + offsetof(struct ether_hdr, type) + ETHER_VLAN_ENCAP_LEN, 
	    &ether.type, sizeof(ether.type));
    ck_assert_msg(lldp_check(msg.msg, msg.len) ==
	    msg.msg + sizeof(ether) + ETHER_VLAN_ENCAP_LEN,
	    "valid encapsulated packets should return a correct ptr");

    memcpy(msg.msg, &ether, sizeof(ether));
    ck_assert_msg(lldp_check(msg.msg, msg.len) == msg.msg + sizeof(ether),
	    "valid packets should return a correct ptr");
}
END_TEST

START_TEST(test_cdp_check) {
    struct parent_msg msg = {};
    struct ether_hdr ether = {};
    struct ether_llc llc = {};
    static uint8_t cdp_dst[] = CDP_MULTICAST_ADDR;
    static uint8_t cdp_org[] = LLC_ORG_CISCO;

    mark_point();
    msg.len = ETHER_MIN_LEN;
    ck_assert_msg(cdp_check(msg.msg, msg.len) == NULL,
	    "empty packets should generate a NULL");

    mark_point();
    memcpy(ether.dst, cdp_dst, ETHER_ADDR_LEN);
    memcpy(msg.msg, &ether, sizeof(ether));
    ck_assert_msg(cdp_check(msg.msg, msg.len) == NULL,
	    "packets without an llc header should generate a NULL");

    mark_point();
    llc.dsap = llc.ssap = LLC_SNAP_LSAP;
    llc.control = LLC_UI;
    memcpy(msg.msg + sizeof(ether), &llc, sizeof(llc));
    ck_assert_msg(cdp_check(msg.msg, msg.len) == NULL,
	    "packets with an incomplete llc header should generate a NULL");

    mark_point();
    memcpy(llc.org, cdp_org, sizeof(llc.org));
    memcpy(msg.msg + sizeof(ether), &llc, sizeof(llc));
    ck_assert_msg(cdp_check(msg.msg, msg.len) == NULL,
	    "packets with an invalid llc header should generate a NULL");

    mark_point();
    llc.protoid = htons(LLC_PID_CDP);
    memcpy(msg.msg + sizeof(ether), &llc, sizeof(llc));
    ck_assert_msg(cdp_check(msg.msg, msg.len) == 
		 msg.msg + sizeof(ether) + sizeof(llc),
	    "valid packets should return a correct ptr");

    mark_point();
    ether.type = htons(ETHERTYPE_VLAN);
    memcpy(msg.msg, &ether, sizeof(ether));
    ck_assert_msg(cdp_check(msg.msg, msg.len) == NULL,
	    "packets without an encapsulated llc should generate a NULL");

    mark_point();
    memcpy(msg.msg + sizeof(ether) + ETHER_VLAN_ENCAP_LEN, &llc, sizeof(llc));
    ck_assert_msg(cdp_check(msg.msg, msg.len) == 
		 msg.msg + sizeof(ether) + ETHER_VLAN_ENCAP_LEN + sizeof(llc),
	    "valid packets should return a correct ptr");
}
END_TEST

START_TEST(test_edp_check) {
    struct parent_msg msg = {};
    struct ether_hdr ether = {};
    struct ether_llc llc = {};
    static uint8_t edp_dst[] = EDP_MULTICAST_ADDR;
    static uint8_t edp_org[] = LLC_ORG_EXTREME;

    mark_point();
    msg.len = ETHER_MIN_LEN;
    ck_assert_msg(edp_check(msg.msg, msg.len) == NULL,
	    "empty packets should generate a NULL");

    mark_point();
    memcpy(ether.dst, edp_dst, ETHER_ADDR_LEN);
    memcpy(msg.msg, &ether, sizeof(ether));
    ck_assert_msg(edp_check(msg.msg, msg.len) == NULL,
	    "packets without an llc header should generate a NULL");

    mark_point();
    llc.dsap = llc.ssap = LLC_SNAP_LSAP;
    llc.control = LLC_UI;
    memcpy(msg.msg + sizeof(ether), &llc, sizeof(llc));
    ck_assert_msg(edp_check(msg.msg, msg.len) == NULL,
	    "packets with an incomplete llc header should generate a NULL");

    mark_point();
    memcpy(llc.org, edp_org, sizeof(llc.org));
    memcpy(msg.msg + sizeof(ether), &llc, sizeof(llc));
    ck_assert_msg(edp_check(msg.msg, msg.len) == NULL,
	    "packets with an invalid llc header should generate a NULL");

    mark_point();
    llc.protoid = htons(LLC_PID_EDP);
    memcpy(msg.msg + sizeof(ether), &llc, sizeof(llc));
    ck_assert_msg(edp_check(msg.msg, msg.len) == 
		 msg.msg + sizeof(ether) + sizeof(llc),
	    "valid packets should return a correct ptr");

    mark_point();
    ether.type = htons(ETHERTYPE_VLAN);
    memcpy(msg.msg, &ether, sizeof(ether));
    ck_assert_msg(edp_check(msg.msg, msg.len) == NULL,
	    "packets without an encapsulated llc should generate a NULL");

    mark_point();
    memcpy(msg.msg + sizeof(ether) + ETHER_VLAN_ENCAP_LEN, &llc, sizeof(llc));
    ck_assert_msg(edp_check(msg.msg, msg.len) == 
		 msg.msg + sizeof(ether) + ETHER_VLAN_ENCAP_LEN + sizeof(llc),
	    "valid packets should return a correct ptr");
}
END_TEST

START_TEST(test_fdp_check) {
    struct parent_msg msg = {};
    struct ether_hdr ether = {};
    struct ether_llc llc = {};
    static uint8_t fdp_dst[] = FDP_MULTICAST_ADDR;
    static uint8_t fdp_org[] = LLC_ORG_FOUNDRY;

    mark_point();
    msg.len = ETHER_MIN_LEN;
    ck_assert_msg(fdp_check(msg.msg, msg.len) == NULL,
	    "empty packets should generate a NULL");

    mark_point();
    memcpy(ether.dst, fdp_dst, ETHER_ADDR_LEN);
    memcpy(msg.msg, &ether, sizeof(ether));
    ck_assert_msg(fdp_check(msg.msg, msg.len) == NULL,
	    "packets without an llc header should generate a NULL");

    mark_point();
    llc.dsap = llc.ssap = LLC_SNAP_LSAP;
    llc.control = LLC_UI;
    memcpy(msg.msg + sizeof(ether), &llc, sizeof(llc));
    ck_assert_msg(fdp_check(msg.msg, msg.len) == NULL,
	    "packets with an incomplete llc header should generate a NULL");

    mark_point();
    memcpy(llc.org, fdp_org, sizeof(llc.org));
    memcpy(msg.msg + sizeof(ether), &llc, sizeof(llc));
    ck_assert_msg(fdp_check(msg.msg, msg.len) == NULL,
	    "packets with an invalid llc header should generate a NULL");

    mark_point();
    llc.protoid = htons(LLC_PID_FDP);
    memcpy(msg.msg + sizeof(ether), &llc, sizeof(llc));
    ck_assert_msg(fdp_check(msg.msg, msg.len) == 
		 msg.msg + sizeof(ether) + sizeof(llc),
	    "valid packets should return a correct ptr");

    mark_point();
    ether.type = htons(ETHERTYPE_VLAN);
    memcpy(msg.msg, &ether, sizeof(ether));
    ck_assert_msg(fdp_check(msg.msg, msg.len) == NULL,
	    "packets without an encapsulated llc should generate a NULL");

    mark_point();
    memcpy(msg.msg + sizeof(ether) + ETHER_VLAN_ENCAP_LEN, &llc, sizeof(llc));
    ck_assert_msg(fdp_check(msg.msg, msg.len) == 
		 msg.msg + sizeof(ether) + ETHER_VLAN_ENCAP_LEN + sizeof(llc),
	    "valid packets should return a correct ptr");
}
END_TEST

START_TEST(test_ndp_check) {
    struct parent_msg msg = {};
    struct ether_hdr ether = {};
    struct ether_llc llc = {};
    static uint8_t ndp_dst[] = NDP_MULTICAST_ADDR;
    static uint8_t ndp_org[] = LLC_ORG_NORTEL;

    mark_point();
    msg.len = ETHER_MIN_LEN;
    ck_assert_msg(ndp_check(msg.msg, msg.len) == NULL,
	    "empty packets should generate a NULL");

    mark_point();
    memcpy(ether.dst, ndp_dst, ETHER_ADDR_LEN);
    memcpy(msg.msg, &ether, sizeof(ether));
    ck_assert_msg(ndp_check(msg.msg, msg.len) == NULL,
	    "packets without an llc header should generate a NULL");

    mark_point();
    llc.dsap = llc.ssap = LLC_SNAP_LSAP;
    llc.control = LLC_UI;
    memcpy(msg.msg + sizeof(ether), &llc, sizeof(llc));
    ck_assert_msg(ndp_check(msg.msg, msg.len) == NULL,
	    "packets with an incomplete llc header should generate a NULL");

    mark_point();
    memcpy(llc.org, ndp_org, sizeof(llc.org));
    memcpy(msg.msg + sizeof(ether), &llc, sizeof(llc));
    ck_assert_msg(ndp_check(msg.msg, msg.len) == NULL,
	    "packets with an invalid llc header should generate a NULL");

    mark_point();
    llc.protoid = htons(LLC_PID_NDP_HELLO);
    memcpy(msg.msg + sizeof(ether), &llc, sizeof(llc));
    ck_assert_msg(ndp_check(msg.msg, msg.len) == 
		 msg.msg + sizeof(ether) + sizeof(llc),
	    "valid packets should return a correct ptr");

    mark_point();
    ether.type = htons(ETHERTYPE_VLAN);
    memcpy(msg.msg, &ether, sizeof(ether));
    ck_assert_msg(ndp_check(msg.msg, msg.len) == NULL,
	    "packets without an encapsulated llc should generate a NULL");

    mark_point();
    memcpy(msg.msg + sizeof(ether) + ETHER_VLAN_ENCAP_LEN, &llc, sizeof(llc));
    ck_assert_msg(ndp_check(msg.msg, msg.len) == 
		 msg.msg + sizeof(ether) + ETHER_VLAN_ENCAP_LEN + sizeof(llc),
	    "valid packets should return a correct ptr");
}
END_TEST

START_TEST(test_lldp_decode) {
    struct parent_msg msg = {};
    const char *errstr = NULL;
    char sobuf[1024];
    int spair[2], fd = -1;

    loglevel = DEBUG;
    msg.decode = DECODE_STR;

    errstr = "Invalid LLDP packet: missing Chassis ID TLV";
    read_packet(&msg, "proto/lldp/00.empty");
    ck_assert_msg(lldp_decode(&msg) == 0, "empty packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    my_log(CRIT, "check");
    errstr = "Invalid LLDP packet: invalid Chassis ID TLV";
    read_packet(&msg, "proto/lldp/01.chassis_id.broken");
    ck_assert_msg(lldp_decode(&msg) == 0, "broken packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    errstr = "Invalid LLDP packet: missing Port ID TLV";
    read_packet(&msg, "proto/lldp/02.chassis_id.only");
    ck_assert_msg(lldp_decode(&msg) == 0, "incomplete packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    errstr = "Invalid LLDP packet: missing Chassis ID TLV";
    read_packet(&msg, "proto/lldp/03.chassis_id.missing");
    ck_assert_msg(lldp_decode(&msg) == 0, "incomplete packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    errstr = "Corrupt LLDP packet: invalid Port ID TLV";
    my_log(CRIT, errstr);
    read_packet(&msg, "proto/lldp/11.port_id.broken");
    ck_assert_msg(lldp_decode(&msg) == 0, "broken packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    errstr = "Invalid LLDP packet: missing TTL TLV";
    read_packet(&msg, "proto/lldp/12.port_id.only");
    ck_assert_msg(lldp_decode(&msg) == 0, "incomplete packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    errstr = "Invalid LLDP packet: missing Port ID TLV";
    read_packet(&msg, "proto/lldp/13.port_id.missing");
    ck_assert_msg(lldp_decode(&msg) == 0, "incomplete packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    errstr = "Corrupt LLDP packet: invalid Port ID TLV";
    read_packet(&msg, "proto/lldp/14.port_id.long");
    ck_assert_msg(lldp_decode(&msg) == 0, "incomplete packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    errstr = "Corrupt LLDP packet: invalid Port ID TLV";
    read_packet(&msg, "proto/lldp/15.port_id.broken");
    ck_assert_msg(lldp_decode(&msg) == 0, "incomplete packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    errstr = "Corrupt LLDP packet: invalid Port ID TLV";
    read_packet(&msg, "proto/lldp/16.port_id.broken");
    ck_assert_msg(lldp_decode(&msg) == 0, "incomplete packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    errstr = "Corrupt LLDP packet: invalid Port ID TLV";
    read_packet(&msg, "proto/lldp/17.port_id.broken");
    ck_assert_msg(lldp_decode(&msg) == 0, "incomplete packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    errstr = "Invalid LLDP packet: invalid TTL TLV";
    read_packet(&msg, "proto/lldp/21.ttl.broken");
    ck_assert_msg(lldp_decode(&msg) == 0, "broken packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    errstr = "Corrupt LLDP packet: missing END TLV";
    read_packet(&msg, "proto/lldp/22.ttl.only");
    ck_assert_msg(lldp_decode(&msg) == 0, "incomplete packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    errstr = "Invalid LLDP packet: missing TTL TLV";
    read_packet(&msg, "proto/lldp/23.ttl.missing");
    ck_assert_msg(lldp_decode(&msg) == 0, "incomplete packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    errstr = "Corrupt LLDP packet: duplicate System Name TLV";
    read_packet(&msg, "proto/lldp/31.system_name.dup");
    ck_assert_msg(lldp_decode(&msg) == 0, "broken packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    errstr = "Corrupt LLDP packet: invalid TLV length";
    read_packet(&msg, "proto/lldp/32.system_name.broken");
    ck_assert_msg(lldp_decode(&msg) == 0, "broken packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    errstr = "Corrupt LLDP packet: invalid TLV length";
    read_packet(&msg, "proto/lldp/33.system_name.broken");
    ck_assert_msg(lldp_decode(&msg) == 0, "broken packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    errstr = "Corrupt LLDP packet: invalid TLV Type";
    read_packet(&msg, "proto/lldp/91.tlv.unknown");
    ck_assert_msg(lldp_decode(&msg) == 0, "unknown tlv's should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    errstr = "Corrupt LLDP packet: invalid TLV";
    read_packet(&msg, "proto/lldp/92.tlv.broken");
    ck_assert_msg(lldp_decode(&msg) == 0, "broken packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    errstr = "Corrupt LLDP packet: invalid TLV length";
    read_packet(&msg, "proto/lldp/93.tlv.long");
    ck_assert_msg(lldp_decode(&msg) == 0, "broken packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    errstr = "Invalid LLDP packet: unknown adress family";
    read_packet(&msg, "proto/lldp/94.mgt.af");
    ck_assert_msg(lldp_decode(&msg) == 0, "broken packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    errstr = "Corrupt LLDP packet: invalid END TLV";
    read_packet(&msg, "proto/lldp/97.end.invalid");
    ck_assert_msg(lldp_decode(&msg) == 0, "invalid packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    errstr = "Corrupt LLDP packet: invalid TLV";
    read_packet(&msg, "proto/lldp/98.end.broken");
    ck_assert_msg(lldp_decode(&msg) == 0, "broken packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    errstr = "Corrupt LLDP packet: missing END TLV";
    read_packet(&msg, "proto/lldp/99.end.missing");
    ck_assert_msg(lldp_decode(&msg) == 0, "incomplete packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    mark_point();
    errstr = "check";
    my_log(CRIT, errstr);
    read_packet(&msg, "proto/lldp/41.good.small");
    ck_assert_msg(lldp_decode(&msg) == msg.len, "packet length incorrect");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    ck_assert_msg(msg.ttl == 120, "ttl should be 120");
    ck_assert_msg(strcmp(msg.peer[PEER_HOSTNAME], "test") == 0,
	"system name should be 'test'");
    ck_assert_msg(strcmp(msg.peer[PEER_PORTNAME], "1/3") == 0,
	"port id should be '1/3' not '%s'", msg.peer[PEER_PORTNAME]);
    ck_assert_msg(msg.peer[PEER_VLAN_ID] == NULL,
	"vlan id should be empty, not '%s'", msg.peer[PEER_VLAN_ID]);

    mark_point();
    read_packet(&msg, "proto/lldp/42.good.big");
    ck_assert_msg(lldp_decode(&msg) == msg.len, "packet length incorrect");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    ck_assert_msg(msg.ttl == 120, "ttl should be 120");
    ck_assert_msg(strcmp(msg.peer[PEER_HOSTNAME], "Summit300-48") == 0,
		"system name should be 'Summit300-48'");
    ck_assert_msg(strcmp(msg.peer[PEER_PORTNAME], "1/1") == 0,
	"port id should be '1/1' not '%s'", msg.peer[PEER_PORTNAME]);
    ck_assert_msg(
	strcmp(msg.peer[PEER_PORTDESCR], "Summit300-48-Port 1001") == 0,
	"port descr should be 'Summit300-48-Port 1001' not '%s'",
		    msg.peer[PEER_PORTDESCR]);
    ck_assert_msg(strcmp(msg.peer[PEER_VLAN_ID], "488") == 0,
	"vlan id should be '488' not '%s'", msg.peer[PEER_VLAN_ID]);

    mark_point();
    read_packet(&msg, "proto/lldp/43.good.lldpmed");
    ck_assert_msg(lldp_decode(&msg) == msg.len, "packet length incorrect");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    ck_assert_msg(msg.ttl == 120, "ttl should be 120");
    ck_assert_msg(strcmp(msg.peer[PEER_HOSTNAME], "ProCurve Switch 2600-8-PWR") == 0,
		"system name should be 'ProCurve Switch 2600-8-PWR'");
    ck_assert_msg(strcmp(msg.peer[PEER_PORTNAME], "1") == 0,
	"port id should be '1' not '%s'", msg.peer[PEER_PORTNAME]);
    ck_assert_msg(strcmp(msg.peer[PEER_PORTDESCR], "1") == 0,
	"port descr should be '1' not '%s'", msg.peer[PEER_PORTDESCR]);
    ck_assert_msg(msg.peer[PEER_VLAN_ID] == NULL,
	"vlan id should be empty, not '%s'", msg.peer[PEER_VLAN_ID]);

    mark_point();
    read_packet(&msg, "proto/lldp/44.good.spaces");
    ck_assert_msg(lldp_decode(&msg) == msg.len, "packet length incorrect");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    ck_assert_msg(msg.ttl == 120, "ttl should be 120");
    ck_assert_msg(strcmp(msg.peer[PEER_HOSTNAME], "HP ProCurve Switch 2626") == 0,
		"system name should be 'HP ProCurve Switch 2626'");
    ck_assert_msg(strcmp(msg.peer[PEER_PORTNAME], "25") == 0,
	"port id should be '25' not '%s'", msg.peer[PEER_PORTNAME]);
    ck_assert_msg(strcmp(msg.peer[PEER_PORTDESCR], "25") == 0,
	"port descr should be '25' not '%s'", msg.peer[PEER_PORTDESCR]);
    ck_assert_msg(msg.peer[PEER_VLAN_ID] == NULL,
	"vlan id should be empty, not '%s'", msg.peer[PEER_VLAN_ID]);

    mark_point();
    read_packet(&msg, "proto/lldp/45.good.vlan");
    ck_assert_msg(lldp_decode(&msg) == msg.len, "packet length incorrect");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    ck_assert_msg(msg.ttl == 120, "ttl should be 120");
    ck_assert_msg(strcmp(msg.peer[PEER_HOSTNAME], "trillian.blinkenlights.nl") == 0,
		"system name should be 'trillian.blinkenlights.nl'");
    ck_assert_msg(strcmp(msg.peer[PEER_PORTNAME], "Gi0/1") == 0,
	"port id should be 'Gi0/1' not '%s'", msg.peer[PEER_PORTNAME]);
    ck_assert_msg(
	strcmp(msg.peer[PEER_PORTDESCR], "GigabitEthernet0/1") == 0,
	"port descr should be 'GigabitEthernet0/1' not '%s'",
		    msg.peer[PEER_PORTDESCR]);

    mark_point();
    read_packet(&msg, "proto/lldp/46.good.d-link");
    ck_assert_msg(lldp_decode(&msg) == 35, "packet length incorrect");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    ck_assert_msg(msg.ttl == 120, "ttl should be 120");
    ck_assert_msg(strcmp(msg.peer[PEER_PORTNAME], "23") == 0,
	"port id should be '23' not '%s'", msg.peer[PEER_PORTNAME]);
    ck_assert_msg(msg.peer[PEER_PORTDESCR] == NULL,
	"port descr should be NULL not '%s'", msg.peer[PEER_PORTDESCR]);
    ck_assert_msg(msg.peer[PEER_VLAN_ID] == NULL,
	"vlan id should be empty, not '%s'", msg.peer[PEER_VLAN_ID]);

    mark_point();
    read_packet(&msg, "proto/lldp/47.good.nexus");
    ck_assert_msg(lldp_decode(&msg) == 268, "packet length incorrect");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    ck_assert_msg(msg.ttl == 120, "ttl should be 120");
    ck_assert_msg(strcmp(msg.peer[PEER_HOSTNAME], "XdasdXZ") == 0,
		"system name should be 'XdasdXZ'");
    ck_assert_msg(strcmp(msg.peer[PEER_PORTNAME], "Eth110/1/13") == 0,
	"port id should be 'Eth110/1/13' not '%s'", msg.peer[PEER_PORTNAME]);
    ck_assert_msg(
	strcmp(msg.peer[PEER_PORTDESCR], "Ethernet110/1/13") == 0,
	"port descr should be 'Ethernet110/1/13' not '%s'",
		    msg.peer[PEER_PORTDESCR]);
    ck_assert_msg(msg.peer[PEER_VLAN_ID] == NULL,
	"vlan id should be empty, not '%s'", msg.peer[PEER_VLAN_ID]);

    mark_point();
    read_packet(&msg, "proto/lldp/48.good.4500G");
    ck_assert_msg(lldp_decode(&msg) == 359, "packet length incorrect");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    ck_assert_msg(msg.ttl == 120, "ttl should be 120");
    ck_assert_msg(strcmp(msg.peer[PEER_HOSTNAME], "sw2.blat") == 0,
		"system name should be 'sw2.blat'");
    ck_assert_msg(msg.peer[PEER_PORTNAME] == NULL,
	"port id should be NULL not '%s'", msg.peer[PEER_PORTNAME]);
    ck_assert_msg(strcmp(msg.peer[PEER_PORTDESCR],
			"GigabitEthernet1/0/9 Interface") == 0,
	"port descr should not be '%s'", msg.peer[PEER_PORTDESCR]);
    ck_assert_msg(strcmp(msg.peer[PEER_VLAN_ID], "1") == 0,
	"vlan id should be '1' not '%s'", msg.peer[PEER_VLAN_ID]);

    mark_point();
    read_packet(&msg, "proto/lldp/49.good.ipmi");
    ck_assert_msg(lldp_decode(&msg) == 118, "packet length incorrect");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    ck_assert_msg(msg.ttl == 120, "ttl should be 120");
    ck_assert_msg(strcmp(msg.peer[PEER_HOSTNAME], "(none).(none)") == 0,
		"system name should be '(none).(none)'");
    ck_assert_msg(strcmp(msg.peer[PEER_PORTNAME], "bond0") == 0,
	"port id should not be '%s'", msg.peer[PEER_PORTNAME]);
    ck_assert_msg(strcmp(msg.peer[PEER_PORTDESCR], "bond0") == 0,
	"port descr should not be '%s'", msg.peer[PEER_PORTDESCR]);
    ck_assert_msg(msg.peer[PEER_VLAN_ID] == NULL,
	"vlan id should be empty, not '%s'", msg.peer[PEER_VLAN_ID]);

    mark_point();
    read_packet(&msg, "proto/lldp/51.good.chassis");
    ck_assert_msg(lldp_decode(&msg) == 118, "packet length incorrect");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    ck_assert_msg(msg.ttl == 120, "ttl should be 120");
    ck_assert_msg(strcmp(msg.peer[PEER_HOSTNAME], "(none).(none)") == 0,
		"system name should be '(none).(none)'");
    ck_assert_msg(msg.peer[PEER_VLAN_ID] == NULL,
	"vlan id should be empty, not '%s'", msg.peer[PEER_VLAN_ID]);

    mark_point();
    read_packet(&msg, "proto/lldp/52.good.chassis");
    ck_assert_msg(lldp_decode(&msg) == 117, "packet length incorrect");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    ck_assert_msg(msg.ttl == 120, "ttl should be 120");
    ck_assert_msg(strcmp(msg.peer[PEER_HOSTNAME], "(none).(none)") == 0,
		"system name should be '(none).(none)'");
    ck_assert_msg(msg.peer[PEER_VLAN_ID] == NULL,
	"vlan id should be empty, not '%s'", msg.peer[PEER_VLAN_ID]);

    mark_point();
    read_packet(&msg, "proto/lldp/53.good.ipv6");
    ck_assert_msg(lldp_decode(&msg) == msg.len, "packet length incorrect");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    ck_assert_msg(msg.ttl == 120, "ttl should be 120");
    ck_assert_msg(strcmp(msg.peer[PEER_HOSTNAME], "(none).(none)") == 0,
		"system name should be '(none).(none)'");
    ck_assert_msg(msg.peer[PEER_VLAN_ID] == NULL,
	"vlan id should be empty, not '%s'", msg.peer[PEER_VLAN_ID]);

    mark_point();
    my_log(CRIT, "check");
    errstr = "Invalid LLDP packet: invalid Chassis ID TLV";
    read_packet(&msg, "proto/lldp/A1.fuzzer.chassis_id.long");
    ck_assert_msg(lldp_decode(&msg) == 0, "invalid packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    my_log(CRIT, "check");
    errstr = "Invalid LLDP packet: invalid Chassis ID TLV";
    read_packet(&msg, "proto/lldp/A2.fuzzer.chassis_id.short");
    ck_assert_msg(lldp_decode(&msg) == 0, "invalid packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    my_log(CRIT, "check");
    errstr = "Invalid LLDP packet: invalid Chassis ID TLV";
    read_packet(&msg, "proto/lldp/A3.fuzzer.chassis_id.broken");
    ck_assert_msg(lldp_decode(&msg) == 0, "invalid packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    my_log(CRIT, "check");
    errstr = "Invalid LLDP packet: invalid Chassis ID TLV";
    read_packet(&msg, "proto/lldp/A4.fuzzer.chassis_id.one");
    ck_assert_msg(lldp_decode(&msg) == 0, "invalid packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    errstr = "check";
    my_log(CRIT, errstr);
    read_packet(&msg, "proto/lldp/A6.fuzzer.end.short");
    ck_assert_msg(lldp_decode(&msg) != 0, "we should allow trailing bytes");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    my_log(CRIT, "check");
    errstr = "Corrupt LLDP packet: invalid END TLV";
    read_packet(&msg, "proto/lldp/A7.fuzzer.end.trail");
    ck_assert_msg(lldp_decode(&msg) == 0, "invalid packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    my_log(CRIT, "check");
    errstr = "Invalid LLDP packet: unavailable cap enabled";
    read_packet(&msg, "proto/lldp/A8.fuzzer.cap.conflict");
    ck_assert_msg(lldp_decode(&msg) == 0, "invalid packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    my_log(CRIT, "check");
    errstr = "Invalid LLDP packet: host-only cap combined";
    read_packet(&msg, "proto/lldp/A8.fuzzer.cap.host");
    ck_assert_msg(lldp_decode(&msg) == 0, "invalid packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    my_log(CRIT, "check");
    errstr = "Corrupt LLDP packet: invalid TLV length";
    read_packet(&msg, "proto/lldp/A8.fuzzer.cap.short");
    ck_assert_msg(lldp_decode(&msg) == 0, "invalid packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    my_log(CRIT, "check");
    errstr = "Invalid LLDP packet: missing Port ID TLV";
    read_packet(&msg, "proto/lldp/A9.fuzzer.port_id.missing");
    ck_assert_msg(lldp_decode(&msg) == 0, "invalid packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    mark_point();
    // make sure stdout is not a tty
    fd = dup(STDOUT_FILENO);
    close(STDOUT_FILENO);
    my_socketpair(spair);

    msg.decode = DECODE_PRINT;
    my_log(CRIT, "check");
    errstr = "Chassis id: 00:01:30:f9:ad:a0";
    memset(sobuf, 0, sizeof(sobuf));
    read_packet(&msg, "proto/lldp/42.good.big");
    ck_assert_msg(lldp_decode(&msg) == msg.len, "packet length incorrect");
    fflush(stdout);
    ck_assert_msg(read(spair[1], sobuf, sizeof(sobuf)) >= 0, "read failed");
    ck_assert_msg(strncmp(sobuf, errstr, strlen(errstr)) == 0,
	"invalid output: %s", sobuf);
    ck_assert_msg(strcmp(check_wrap_errstr, "check") == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    close(spair[0]);
    close(spair[1]);

    mark_point();
    my_socketpair(spair);
    errstr = "Chassis id: foobar";
    memset(sobuf, 0, sizeof(sobuf));
    read_packet(&msg, "proto/lldp/53.good.ipv6");
    ck_assert_msg(lldp_decode(&msg) == msg.len, "packet length incorrect");
    fflush(stdout);
    ck_assert_msg(read(spair[1], sobuf, sizeof(sobuf)) >= 0, "read failed");
    ck_assert_msg(strncmp(sobuf, errstr, strlen(errstr)) == 0,
	"invalid output: %s", sobuf);
    ck_assert_msg(strcmp(check_wrap_errstr, "check") == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    close(spair[0]);
    close(spair[1]);
    fd = dup(fd);
}
END_TEST

START_TEST(test_cdp_decode) {
    struct parent_msg msg = {};
    const char *errstr = NULL;
    char sobuf[1024];
    int spair[2], fd = -1;

    loglevel = INFO;
    msg.decode = DECODE_STR;

    errstr = "missing CDP header";
    read_packet(&msg, "proto/cdp/00.empty");
    ck_assert_msg(cdp_decode(&msg) == 0, "empty packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    errstr = "missing CDP header";
    read_packet(&msg, "proto/cdp/01.header.broken");
    ck_assert_msg(cdp_decode(&msg) == 0, "broken packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    errstr = "invalid CDP version";
    read_packet(&msg, "proto/cdp/02.header.invalid");
    ck_assert_msg(cdp_decode(&msg) == 0, "broken packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    read_packet(&msg, "proto/cdp/03.header.only");
    ck_assert_msg(cdp_decode(&msg) == msg.len, "packet length incorrect");

    errstr = "Corrupt CDP packet: invalid TLV length";
    read_packet(&msg, "proto/cdp/21.device_id.broken");
    ck_assert_msg(cdp_decode(&msg) == 0, "broken packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    read_packet(&msg, "proto/cdp/91.tlv.unknown");
    ck_assert_msg(cdp_decode(&msg) == msg.len, "packet length incorrect");
    errstr = "Corrupt CDP packet: invalid TLV";
    read_packet(&msg, "proto/cdp/92.tlv.broken");
    ck_assert_msg(cdp_decode(&msg) == 0, "broken packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    errstr = "Corrupt CDP packet: invalid TLV length";
    read_packet(&msg, "proto/cdp/93.tlv.long");
    ck_assert_msg(cdp_decode(&msg) == 0, "broken packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    mark_point();
    errstr = "check";
    my_log(CRIT, errstr);
    read_packet(&msg, "proto/cdp/41.good.small");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    ck_assert_msg(cdp_decode(&msg) == msg.len, "packet length incorrect");
    ck_assert_msg(msg.proto == PROTO_CDP1, "CDP version should be 1");
    ck_assert_msg(msg.ttl == 180, "ttl should be 180");
    ck_assert_msg(strcmp(msg.peer[PEER_HOSTNAME], "R1") == 0,
	"system name should be 'R1'");
    ck_assert_msg(msg.peer[PEER_PORTNAME] == NULL,
	"port id should be empty, not '%s'", msg.peer[PEER_PORTNAME]);
    ck_assert_msg(msg.peer[PEER_VLAN_ID] == NULL,
	"vlan id should be empty, not '%s'", msg.peer[PEER_VLAN_ID]);

    mark_point();
    read_packet(&msg, "proto/cdp/42.good.medium");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    ck_assert_msg(cdp_decode(&msg) == msg.len, "packet length incorrect");
    ck_assert_msg(msg.proto == PROTO_CDP1, "CDP version should be 1");
    ck_assert_msg(msg.ttl == 180, "ttl should be 180");
    ck_assert_msg(strcmp(msg.peer[PEER_HOSTNAME], "R2D2") == 0,
		"system name should be 'R2D2'");
    ck_assert_msg(strcmp(msg.peer[PEER_PORTNAME], "Ethernet0") == 0,
	"port id should be 'Ethernet0' not '%s'", msg.peer[PEER_PORTNAME]);
    ck_assert_msg(msg.peer[PEER_VLAN_ID] == NULL,
	"vlan id should be empty, not '%s'", msg.peer[PEER_VLAN_ID]);

    mark_point();
    read_packet(&msg, "proto/cdp/43.good.big");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    ck_assert_msg(cdp_decode(&msg) == msg.len, "packet length incorrect");
    ck_assert_msg(msg.proto == PROTO_CDP, "CDP version should be 2");
    ck_assert_msg(msg.ttl == 180, "ttl should be 180");
    ck_assert_msg(strcmp(msg.peer[PEER_HOSTNAME], "xpfs1.yapkjn.network.bla.nl") == 0,
		"system name should be 'xpfs1.yapkjn.network.bla.nl'");
    ck_assert_msg(strcmp(msg.peer[PEER_PORTNAME], "FastEthernet6/20") == 0,
	"port id should be 'FastEthernet6/20' not '%s'",
	msg.peer[PEER_PORTNAME]);
    ck_assert_msg(strcmp(msg.peer[PEER_VLAN_ID], "389") == 0,
	"vlan id should be '389' not '%s'", msg.peer[PEER_VLAN_ID]);

    mark_point();
    read_packet(&msg, "proto/cdp/44.good.bcm");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    ck_assert_msg(cdp_decode(&msg) == msg.len, "packet length incorrect");
    ck_assert_msg(msg.proto == PROTO_CDP, "CDP version should be 2");
    ck_assert_msg(msg.ttl == 180, "ttl should be 180");
    ck_assert_msg(strcmp(msg.peer[PEER_HOSTNAME], "0060B9C14027") == 0,
		"system name should be '0060B9C14027'");
    ck_assert_msg(msg.peer[PEER_PORTNAME] == NULL,
	"port id should be empty, not '%s'", msg.peer[PEER_PORTNAME]);
    ck_assert_msg(msg.peer[PEER_VLAN_ID] == NULL,
	"vlan id should be empty, not '%s'", msg.peer[PEER_VLAN_ID]);

    mark_point();
    read_packet(&msg, "proto/cdp/45.good.6504");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    ck_assert_msg(cdp_decode(&msg) == msg.len, "packet length incorrect");
    ck_assert_msg(msg.proto == PROTO_CDP, "CDP version should be 2");
    ck_assert_msg(msg.ttl == 180, "ttl should be 180");
    ck_assert_msg(strcmp(msg.peer[PEER_HOSTNAME], "mpls-sbp-ams1.leazewep.nat") == 0,
		"system name should be 'mpls-sbp-ams1.leazewep.nat'");
    ck_assert_msg(strcmp(msg.peer[PEER_PORTNAME], "FastEthernet4/11") == 0,
	"port id should be 'FastEthernet4/11' not '%s'",
	msg.peer[PEER_PORTNAME]);
    ck_assert_msg(strcmp(msg.peer[PEER_VLAN_ID], "971") == 0,
	"vlan id should be '971' not '%s'", msg.peer[PEER_VLAN_ID]);

    mark_point();
    read_packet(&msg, "proto/cdp/46.good.2811");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    ck_assert_msg(cdp_decode(&msg) == msg.len, "packet length incorrect");
    ck_assert_msg(msg.proto == PROTO_CDP, "CDP version should be 2");
    ck_assert_msg(msg.ttl == 180, "ttl should be 180");
    ck_assert_msg(strcmp(msg.peer[PEER_HOSTNAME], "c2811.ttttrnal.lottlloou.nl") == 0,
		"system name should be 'c2811.ttttrnal.lottlloou.nl'");
    ck_assert_msg(strcmp(msg.peer[PEER_PORTNAME], "FastEthernet0/0") == 0,
	"port id should be 'FastEthernet0/0' not '%s'",
	msg.peer[PEER_PORTNAME]);
    ck_assert_msg(msg.peer[PEER_VLAN_ID] == NULL,
	"vlan id should be empty, not '%s'", msg.peer[PEER_VLAN_ID]);

    mark_point();
    read_packet(&msg, "proto/cdp/47.good.vlan");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    ck_assert_msg(cdp_decode(&msg) == msg.len, "packet length incorrect");
    ck_assert_msg(msg.proto == PROTO_CDP, "CDP version should be 2");
    ck_assert_msg(msg.ttl == 180, "ttl should be 180");
    ck_assert_msg(strcmp(msg.peer[PEER_HOSTNAME], "sw1.bit-2b.notwork.bot.nl") == 0,
		"system name should be 'sw1.bit-2b.notwork.bot.nl'");
    ck_assert_msg(strcmp(msg.peer[PEER_PORTNAME], "GigabitEthernet0/2") == 0,
	"port id should be 'GigabitEthernet0/2' not '%s'",
	msg.peer[PEER_PORTNAME]);
    ck_assert_msg(strcmp(msg.peer[PEER_VLAN_ID], "30") == 0,
	"vlan id should be '30' not '%s'", msg.peer[PEER_VLAN_ID]);

    mark_point();
    read_packet(&msg, "proto/cdp/48.good.vlan");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    ck_assert_msg(cdp_decode(&msg) == msg.len, "packet length incorrect");
    ck_assert_msg(msg.proto == PROTO_CDP, "CDP version should be 2");
    ck_assert_msg(msg.ttl == 180, "ttl should be 180");
    ck_assert_msg(strcmp(msg.peer[PEER_HOSTNAME], "trillian.blinkenlights.nl") == 0,
		"system name should be 'trillian.blinkenlights.nl'");
    ck_assert_msg(strcmp(msg.peer[PEER_PORTNAME], "GigabitEthernet0/1") == 0,
	"port id should be 'GigabitEthernet0/1' not '%s'",
	msg.peer[PEER_PORTNAME]);
    ck_assert_msg(strcmp(msg.peer[PEER_VLAN_ID], "2") == 0,
	"vlan id should be '2' not '%s'", msg.peer[PEER_VLAN_ID]);

    mark_point();
    read_packet(&msg, "proto/cdp/49.good.phone");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    ck_assert_msg(cdp_decode(&msg) == msg.len, "packet length incorrect");
    ck_assert_msg(msg.proto == PROTO_CDP, "CDP version should be 2");
    ck_assert_msg(msg.ttl == 180, "ttl should be 180");
    ck_assert_msg(strcmp(msg.peer[PEER_HOSTNAME], "SEP001B53489EE0") == 0,
		"system name should be 'SEP001B53489EE0'");
    ck_assert_msg(strcmp(msg.peer[PEER_PORTNAME], "Port 1") == 0,
	"port id should be 'Port 1' not '%s'",
	msg.peer[PEER_PORTNAME]);
    ck_assert_msg(msg.peer[PEER_VLAN_ID] == NULL,
	"vlan id should be empty, not '%s'", msg.peer[PEER_VLAN_ID]);

    mark_point();
    read_packet(&msg, "proto/cdp/50.good.mikrotik");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    ck_assert_msg(cdp_decode(&msg) == msg.len, "packet length incorrect");
    ck_assert_msg(msg.proto == PROTO_CDP1, "CDP version should be 1");
    ck_assert_msg(msg.ttl == 120, "ttl should be 120");
    ck_assert_msg(strcmp(msg.peer[PEER_HOSTNAME], "MikroTik") == 0,
		"system name should be 'MikroTik'");
    ck_assert_msg(strcmp(msg.peer[PEER_PORTNAME], "ether2") == 0,
	"port id should be 'ether2' not '%s'",
	msg.peer[PEER_PORTNAME]);
    ck_assert_msg(msg.peer[PEER_VLAN_ID] == NULL,
	"vlan id should be empty, not '%s'", msg.peer[PEER_VLAN_ID]);

    mark_point();
    // make sure stdout is not a tty
    fd = dup(STDOUT_FILENO);
    close(STDOUT_FILENO);
    my_socketpair(spair);

    msg.decode = DECODE_PRINT;
    my_log(CRIT, "check");
    errstr = "CDP Version: 2";
    memset(sobuf, 0, sizeof(sobuf));
    read_packet(&msg, "proto/cdp/43.good.big");
    ck_assert_msg(cdp_decode(&msg) == msg.len, "packet length incorrect");
    fflush(stdout);
    ck_assert_msg(read(spair[1], sobuf, sizeof(sobuf)) >= 0, "read failed");
    ck_assert_msg(strncmp(sobuf, errstr, strlen(errstr)) == 0, "invalid output: %s", sobuf);
    ck_assert_msg(strcmp(check_wrap_errstr, "check") == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    close(spair[0]);
    close(spair[1]);
    fd = dup(fd);
    peer_free(msg.peer);
}
END_TEST

START_TEST(test_edp_decode) {
    struct parent_msg msg = {};
    const char *errstr = NULL;

    loglevel = INFO;
    msg.decode = DECODE_STR;

    errstr = "missing EDP header";
    read_packet(&msg, "proto/edp/00.empty");
    ck_assert_msg(edp_decode(&msg) == 0, "empty packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    my_log(CRIT, "check");
    read_packet(&msg, "proto/edp/01.header.broken");
    ck_assert_msg(edp_decode(&msg) == 0, "broken packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    errstr = "unsupported EDP version";
    read_packet(&msg, "proto/edp/02.header.invalid");
    ck_assert_msg(edp_decode(&msg) == 0, "broken packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    errstr = "check";
    my_log(CRIT, errstr);
    read_packet(&msg, "proto/edp/03.header.only");
    ck_assert_msg(edp_decode(&msg) == msg.len, "packet length incorrect");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    errstr = "Corrupt EDP packet: invalid Display TLV";
    read_packet(&msg, "proto/edp/21.display.broken");
    ck_assert_msg(edp_decode(&msg) == 0, "broken packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    errstr = "check";
    my_log(CRIT, errstr);
    read_packet(&msg, "proto/edp/91.tlv.unknown");
    ck_assert_msg(edp_decode(&msg) == msg.len, "packet length incorrect");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    errstr = "Corrupt EDP packet: invalid TLV";
    read_packet(&msg, "proto/edp/92.tlv.invalid");
    ck_assert_msg(edp_decode(&msg) == 0, "broken packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    errstr = "Corrupt EDP packet: invalid TLV length";
    read_packet(&msg, "proto/edp/93.tlv.long");
    ck_assert_msg(edp_decode(&msg) == 0, "broken packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    errstr = "check";
    my_log(CRIT, errstr);
    read_packet(&msg, "proto/edp/41.good.small");
    ck_assert_msg(edp_decode(&msg) == msg.len, "packet length incorrect");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    ck_assert_msg(msg.ttl == 180, "ttl should be 180");
    ck_assert_msg(strcmp(msg.peer[PEER_HOSTNAME], "HD000002") == 0,
		"system name should be 'HD000002'");
    ck_assert_msg(msg.peer[PEER_PORTNAME] == NULL,
	"port id should be empty, not '%s'", msg.peer[PEER_PORTNAME]);
    read_packet(&msg, "proto/edp/42.good.medium");
    ck_assert_msg(edp_decode(&msg) == msg.len, "packet length incorrect");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    ck_assert_msg(msg.ttl == 180, "ttl should be 180");
    ck_assert_msg(strcmp(msg.peer[PEER_HOSTNAME], "SW1") == 0,
	"system name should be 'SW1'");
    ck_assert_msg(msg.peer[PEER_PORTNAME] == NULL,
	"port id should be empty, not '%s'", msg.peer[PEER_PORTNAME]);

    peer_free(msg.peer);
}
END_TEST

START_TEST(test_fdp_decode) {
    struct parent_msg msg = {};
    const char *errstr = NULL;

    loglevel = INFO;
    msg.decode = DECODE_STR;

    errstr = "missing FDP header";
    read_packet(&msg, "proto/fdp/00.empty");
    ck_assert_msg(fdp_decode(&msg) == 0, "empty packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    my_log(CRIT, "check");
    read_packet(&msg, "proto/fdp/01.header.broken");
    ck_assert_msg(fdp_decode(&msg) == 0, "broken packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    errstr = "unsupported FDP version";
    read_packet(&msg, "proto/fdp/02.header.invalid");
    ck_assert_msg(fdp_decode(&msg) == 0, "broken packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    errstr = "check";
    my_log(CRIT, errstr);
    read_packet(&msg, "proto/fdp/03.header.only");
    ck_assert_msg(fdp_decode(&msg) == msg.len, "packet length incorrect");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    errstr = "Corrupt FDP packet: invalid Device ID TLV";
    read_packet(&msg, "proto/fdp/21.device_id.broken");
    ck_assert_msg(fdp_decode(&msg) == 0, "broken packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    errstr = "check";
    my_log(CRIT, errstr);
    read_packet(&msg, "proto/fdp/91.tlv.unknown");
    ck_assert_msg(fdp_decode(&msg) == msg.len, "packet length incorrect");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    errstr = "Corrupt FDP packet: invalid TLV";
    read_packet(&msg, "proto/fdp/92.tlv.invalid");
    ck_assert_msg(fdp_decode(&msg) == 0, "broken packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    errstr = "Corrupt FDP packet: invalid TLV length";
    read_packet(&msg, "proto/fdp/93.tlv.long");
    ck_assert_msg(fdp_decode(&msg) == 0, "broken packets should return 0");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    mark_point();
    errstr = "check";
    my_log(CRIT, errstr);
    read_packet(&msg, "proto/fdp/41.good.bi");
    ck_assert_msg(fdp_decode(&msg) == msg.len, "packet length incorrect");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    ck_assert_msg(msg.ttl == 10, "ttl should be 10");
    ck_assert_msg(strcmp(msg.peer[PEER_HOSTNAME], "doetnix") == 0,
		"system name should be 'doetnix'");
    ck_assert_msg(strcmp(msg.peer[PEER_PORTNAME], "ethernet3/1") == 0,
	"port id should be 'ethernet3/1' not '%s'", msg.peer[PEER_PORTNAME]);

    mark_point();
    read_packet(&msg, "proto/fdp/42.good.rx");
    ck_assert_msg(fdp_decode(&msg) == msg.len, "packet length incorrect");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    ck_assert_msg(msg.ttl == 10, "ttl should be 10");
    ck_assert_msg(strcmp(msg.peer[PEER_HOSTNAME], "erix") == 0,
		"system name should be 'erix'");
    ck_assert_msg(strcmp(msg.peer[PEER_PORTNAME], "ethernet1/1") == 0,
	"port id should be 'ethernet1/1' not '%s'", msg.peer[PEER_PORTNAME]);

    mark_point();
    read_packet(&msg, "proto/fdp/43.good.mlx");
    ck_assert_msg(fdp_decode(&msg) == msg.len, "packet length incorrect");
    ck_assert_msg(strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    ck_assert_msg(msg.ttl == 10, "ttl should be 10");
    ck_assert_msg(strcmp(msg.peer[PEER_HOSTNAME], "emmerix") == 0,
		"system name should be 'emmerix'");
    ck_assert_msg(strcmp(msg.peer[PEER_PORTNAME], "ethernet1/1") == 0,
	"port id should be 'ethernet1/1' not '%s'", msg.peer[PEER_PORTNAME]);

    peer_free(msg.peer);
}
END_TEST

Suite * proto_suite (void) {
    Suite *s = suite_create("libproto");

    loglevel = DEBUG;

    // proto_packet test cases
    TCase *tc_packet = tcase_create("proto_packet");
    tcase_add_test(tc_packet, test_proto_packet);
    suite_add_tcase(s, tc_packet);

    // proto_check test cases
    TCase *tc_check = tcase_create("proto_check");
    tcase_add_test(tc_check, test_lldp_check);
    tcase_add_test(tc_check, test_cdp_check);
    tcase_add_test(tc_check, test_edp_check);
    tcase_add_test(tc_check, test_fdp_check);
    tcase_add_test(tc_check, test_ndp_check);
    suite_add_tcase(s, tc_check);

    // proto_peer test cases
    TCase *tc_decode = tcase_create("proto_decode");
    tcase_add_test(tc_decode, test_lldp_decode);
    tcase_add_test(tc_decode, test_cdp_decode);
    tcase_add_test(tc_decode, test_edp_decode);
    tcase_add_test(tc_decode, test_fdp_decode);
    suite_add_tcase(s, tc_decode);

    return s;
}

int main (void) {
    int number_failed;
    Suite *s = proto_suite ();
    SRunner *sr = srunner_create (s);
    srunner_run_all (sr, CK_NORMAL);
    number_failed = srunner_ntests_failed (sr);
    srunner_free (sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

