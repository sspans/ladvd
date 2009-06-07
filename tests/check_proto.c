
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <check.h>

#include "../src/common.h"
#include "../src/proto/protos.h"

uint32_t options = OPT_DAEMON;

START_TEST(test_lldp_check) {
    struct master_msg mreq;
    struct ether_hdr ether;
    static uint8_t lldp_dst[] = LLDP_MULTICAST_ADDR;

    mreq.len = ETHER_MIN_LEN;
    fail_unless (lldp_check(mreq.msg, mreq.len) == NULL,
	    "empty packets should generate a NULL");

    memcpy(ether.dst, lldp_dst, ETHER_ADDR_LEN);
    memcpy(mreq.msg, &ether, sizeof(ether));
    fail_unless (lldp_check(mreq.msg, mreq.len) == NULL,
	    "packets without an ethertype should generate a NULL");

    ether.type = htons(ETHERTYPE_LLDP);
    memcpy(mreq.msg, &ether, sizeof(ether));
    fail_unless (lldp_check(mreq.msg, mreq.len) == mreq.msg + sizeof(ether),
	    "valid packets should return a correct ptr");
}
END_TEST

START_TEST(test_cdp_check) {
    struct master_msg mreq;
    struct ether_hdr ether;
    struct ether_llc llc;
    static uint8_t cdp_dst[] = CDP_MULTICAST_ADDR;
    static uint8_t cdp_org[] = LLC_ORG_CISCO;

    mreq.len = ETHER_MIN_LEN;
    fail_unless (cdp_check(mreq.msg, mreq.len) == NULL,
	    "empty packets should generate a NULL");

    memcpy(ether.dst, cdp_dst, ETHER_ADDR_LEN);
    memcpy(mreq.msg, &ether, sizeof(ether));
    fail_unless (cdp_check(mreq.msg, mreq.len) == NULL,
	    "packets without an llc header should generate a NULL");

    memcpy(llc.org, cdp_org, sizeof(llc.org));
    memcpy(mreq.msg + sizeof(ether), &llc, sizeof(llc));
    fail_unless (cdp_check(mreq.msg, mreq.len) == NULL,
	    "packets with an invalid llc header should generate a NULL");

    llc.protoid = htons(LLC_PID_CDP);
    memcpy(mreq.msg + sizeof(ether), &llc, sizeof(llc));
    fail_unless (cdp_check(mreq.msg, mreq.len) == 
		 mreq.msg + sizeof(ether) + sizeof(llc),
	    "valid packets should return a correct ptr");
}
END_TEST

START_TEST(test_edp_check) {
    struct master_msg mreq;
    struct ether_hdr ether;
    struct ether_llc llc;
    static uint8_t edp_dst[] = EDP_MULTICAST_ADDR;
    static uint8_t edp_org[] = LLC_ORG_EXTREME;

    mreq.len = ETHER_MIN_LEN;
    fail_unless (edp_check(mreq.msg, mreq.len) == NULL,
	    "empty packets should generate a NULL");

    memcpy(ether.dst, edp_dst, ETHER_ADDR_LEN);
    memcpy(mreq.msg, &ether, sizeof(ether));
    fail_unless (edp_check(mreq.msg, mreq.len) == NULL,
	    "packets without an llc header should generate a NULL");

    memcpy(llc.org, edp_org, sizeof(llc.org));
    memcpy(mreq.msg + sizeof(ether), &llc, sizeof(llc));
    fail_unless (edp_check(mreq.msg, mreq.len) == NULL,
	    "packets with an invalid llc header should generate a NULL");

    llc.protoid = htons(LLC_PID_EDP);
    memcpy(mreq.msg + sizeof(ether), &llc, sizeof(llc));
    fail_unless (edp_check(mreq.msg, mreq.len) == 
		 mreq.msg + sizeof(ether) + sizeof(llc),
	    "valid packets should return a correct ptr");
}
END_TEST

START_TEST(test_fdp_check) {
    struct master_msg mreq;
    struct ether_hdr ether;
    struct ether_llc llc;
    static uint8_t fdp_dst[] = FDP_MULTICAST_ADDR;
    static uint8_t fdp_org[] = LLC_ORG_FOUNDRY;

    mreq.len = ETHER_MIN_LEN;
    fail_unless (fdp_check(mreq.msg, mreq.len) == NULL,
	    "empty packets should generate a NULL");

    memcpy(ether.dst, fdp_dst, ETHER_ADDR_LEN);
    memcpy(mreq.msg, &ether, sizeof(ether));
    fail_unless (fdp_check(mreq.msg, mreq.len) == NULL,
	    "packets without an llc header should generate a NULL");

    memcpy(llc.org, fdp_org, sizeof(llc.org));
    memcpy(mreq.msg + sizeof(ether), &llc, sizeof(llc));
    fail_unless (fdp_check(mreq.msg, mreq.len) == NULL,
	    "packets with an invalid llc header should generate a NULL");

    llc.protoid = htons(LLC_PID_FDP);
    memcpy(mreq.msg + sizeof(ether), &llc, sizeof(llc));
    fail_unless (fdp_check(mreq.msg, mreq.len) == 
		 mreq.msg + sizeof(ether) + sizeof(llc),
	    "valid packets should return a correct ptr");
}
END_TEST

START_TEST(test_ndp_check) {
    struct master_msg mreq;
    struct ether_hdr ether;
    struct ether_llc llc;
    static uint8_t ndp_dst[] = NDP_MULTICAST_ADDR;
    static uint8_t ndp_org[] = LLC_ORG_NORTEL;

    mreq.len = ETHER_MIN_LEN;
    fail_unless (ndp_check(mreq.msg, mreq.len) == NULL,
	    "empty packets should generate a NULL");

    memcpy(ether.dst, ndp_dst, ETHER_ADDR_LEN);
    memcpy(mreq.msg, &ether, sizeof(ether));
    fail_unless (ndp_check(mreq.msg, mreq.len) == NULL,
	    "packets without an llc header should generate a NULL");

    memcpy(llc.org, ndp_org, sizeof(llc.org));
    memcpy(mreq.msg + sizeof(ether), &llc, sizeof(llc));
    fail_unless (ndp_check(mreq.msg, mreq.len) == NULL,
	    "packets with an invalid llc header should generate a NULL");

    llc.protoid = htons(LLC_PID_NDP_HELLO);
    memcpy(mreq.msg + sizeof(ether), &llc, sizeof(llc));
    fail_unless (ndp_check(mreq.msg, mreq.len) == 
		 mreq.msg + sizeof(ether) + sizeof(llc),
	    "valid packets should return a correct ptr");
}
END_TEST

Suite * proto_suite (void) {
    Suite *s = suite_create("libproto");

    // proto_check test cases
    TCase *tc_proto = tcase_create("proto_check");
    tcase_add_test(tc_proto, test_lldp_check);
    tcase_add_test(tc_proto, test_cdp_check);
    tcase_add_test(tc_proto, test_edp_check);
    tcase_add_test(tc_proto, test_fdp_check);
    tcase_add_test(tc_proto, test_ndp_check);

    suite_add_tcase(s, tc_proto);

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

