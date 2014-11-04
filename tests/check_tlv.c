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
#include "proto/tlv.h"
#include "main.h"
#include "check_wrap.h"

uint32_t options = OPT_DAEMON | OPT_CHECK;

START_TEST(test_value_str) {
    struct master_msg msg = {};
    uint16_t type = 0;
    uint16_t length = 0;
    char value[32] = {};
    const char *errstr = NULL;

    mark_point();
    type = PEER_ADDR_INET4;
    length = 0;
    tlv_value_str(&msg, type, length, value);
    fail_unless (msg.peer[type] == NULL, "a NULL pointer should be returned");
    length = 5;
    tlv_value_str(&msg, type, length, value);
    fail_unless (msg.peer[type] == NULL, "a NULL pointer should be returned");
    length = 4;
    tlv_value_str(&msg, type, length, value);
    fail_unless (msg.peer[type] != NULL, "a valid pointer should be returned");

    mark_point();
    type = PEER_ADDR_INET6;
    length = 0;
    tlv_value_str(&msg, type, length, value);
    fail_unless (msg.peer[type] == NULL, "a NULL pointer should be returned");
    length = 17;
    tlv_value_str(&msg, type, length, value);
    fail_unless (msg.peer[type] == NULL, "a NULL pointer should be returned");
    length = 16;
    tlv_value_str(&msg, type, length, value);
    fail_unless (msg.peer[type] != NULL, "a valid pointer should be returned");

    mark_point();
    type = PEER_ADDR_802;
    length = 0;
    tlv_value_str(&msg, type, length, value);
    fail_unless (msg.peer[type] == NULL, "a NULL pointer should be returned");
    length = 7;
    tlv_value_str(&msg, type, length, value);
    fail_unless (msg.peer[type] == NULL, "a NULL pointer should be returned");
    length = 6;
    tlv_value_str(&msg, type, length, value);
    fail_unless (msg.peer[type] != NULL, "a valid pointer should be returned");

    mark_point();
    type = PEER_MAX + 1;
    length = 0;
    errstr = "unhandled type";
    WRAP_FATAL_START();
    tlv_value_str(&msg, type, length, value);
    WRAP_FATAL_END();
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    peer_free(msg.peer);
}
END_TEST

START_TEST(test_str_addr) {
    char *str = NULL;
    void *pos;

    mark_point();
    pos = "foob";
    str = tlv_str_addr(PEER_ADDR_INET4, pos, 3);
    fail_unless (str == NULL, "a NULL pointer should be returned");

    str = tlv_str_addr(PEER_ADDR_INET4, pos, 5);
    fail_unless (str == NULL, "a NULL pointer should be returned");

    str = tlv_str_addr(PEER_ADDR_INET4, pos, 4);
    fail_unless (str != NULL, "a string pointer should be returned");
    free(str);
    str = NULL;

    mark_point();
    pos = "foobfoobfoobfoob";
    str = tlv_str_addr(PEER_ADDR_INET6, pos, 3);
    fail_unless (str == NULL, "a NULL pointer should be returned");

    str = tlv_str_addr(PEER_ADDR_INET6, pos, 17);
    fail_unless (str == NULL, "a NULL pointer should be returned");

    str = tlv_str_addr(PEER_ADDR_INET6, pos, 16);
    fail_unless (str != NULL, "a string pointer should be returned");
    free(str);
    str = NULL;

    mark_point();
    pos = "foobfo";
    str = tlv_str_addr(PEER_ADDR_802, pos, 5);
    fail_unless (str == NULL, "a NULL pointer should be returned");

    str = tlv_str_addr(PEER_ADDR_802, pos, 7);
    fail_unless (str == NULL, "a NULL pointer should be returned");

    str = tlv_str_addr(PEER_ADDR_802, pos, 6);
    fail_unless (str != NULL, "a string pointer should be returned");
    free(str);
    str = NULL;

    str = tlv_str_addr(PEER_MAX, pos, 9);
    fail_unless (str == NULL, "a NULL pointer should be returned");
}
END_TEST

Suite * tlv_suite (void) {
    Suite *s = suite_create("proto/tlv.c");

    // tlv test case
    TCase *tc_tlv = tcase_create("tlv");
    tcase_add_test(tc_tlv, test_value_str);
    tcase_add_test(tc_tlv, test_str_addr);
    suite_add_tcase(s, tc_tlv);

    return s;
}

int main (void) {
    int number_failed;
    Suite *s = tlv_suite ();
    SRunner *sr = srunner_create (s);
    srunner_run_all (sr, CK_NORMAL);
    number_failed = srunner_ntests_failed (sr);
    srunner_free (sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

