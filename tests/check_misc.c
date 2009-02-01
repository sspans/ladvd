
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <check.h>

#include "../src/common.h"
#include "../src/util.h"

START_TEST(test_netif) {
    struct netif netifs[6];
    struct netif *netif, *subif;
    int argc;

    netifs[0].index = 0;
    netifs[0].argv = 0;
    netifs[0].slave = 0;
    netifs[0].type = NETIF_BONDING;
    netifs[0].next = &netifs[1];
    netifs[0].subif = &netifs[1];
    strlcpy(netifs[0].name, "bond0", IFNAMSIZ); 

    netifs[1].index = 1;
    netifs[1].argv = 1;
    netifs[1].slave = 1;
    netifs[1].type = NETIF_REGULAR;
    netifs[1].next = &netifs[2];
    netifs[1].subif = &netifs[2];
    strlcpy(netifs[1].name, "eth0", IFNAMSIZ); 

    netifs[2].index = 2;
    netifs[2].argv = 0;
    netifs[2].slave = 1;
    netifs[2].type = NETIF_REGULAR;
    netifs[2].next = &netifs[3];
    netifs[2].subif = NULL,
    strlcpy(netifs[2].name, "eth2", IFNAMSIZ); 

    netifs[3].index = 4;
    netifs[3].argv = 0;
    netifs[3].slave = 0;
    netifs[3].type = NETIF_BRIDGE;
    netifs[3].next = &netifs[4],
    netifs[3].subif = NULL,
    strlcpy(netifs[3].name, "bridge0", IFNAMSIZ); 

    netifs[4].index = 5;
    netifs[4].argv = 1;
    netifs[4].slave = 0;
    netifs[4].type = NETIF_BONDING;
    netifs[4].next = &netifs[5],
    netifs[4].subif = NULL,
    strlcpy(netifs[4].name, "lagg0", IFNAMSIZ); 

    netifs[5].index = 3;
    netifs[5].argv = 1;
    netifs[5].slave = 0;
    netifs[5].type = NETIF_REGULAR;
    netifs[5].next = NULL;
    netifs[5].subif = NULL,
    strlcpy(netifs[5].name, "eth1", IFNAMSIZ); 


    // netif_iter checks
    netif = NULL;
    argc = 0;
    fail_unless (netif_iter(netif, netif, argc) == NULL,
	"NULL should be returned on invalid netifs");

    netif = NULL;
    argc = 0;
    netif = netif_iter(netif, netifs, argc);
    fail_unless (netif == &netifs[0], "the first netif should be returned");
    netif = netif_iter(netif, netifs, argc);
    fail_unless (netif == &netifs[5], "the sixth netif should be returned");
    netif = netif_iter(netif, netifs, argc);
    fail_unless (netif == NULL, "NULL should be returned");

    netif = NULL;
    argc = 2;
    netif = netif_iter(netif, netifs, argc);
    fail_unless (netif == &netifs[1], "the second netif should be returned");
    netif = netif_iter(netif, netifs, argc);
    fail_unless (netif == &netifs[5], "the sixth netif should be returned");
    netif = netif_iter(netif, netifs, argc);
    fail_unless (netif == NULL, "NULL should be returned");


    // subif_iter checks
    netif = &netifs[0];
    subif = NULL;
    subif = subif_iter(subif, netif);
    fail_unless (subif == &netifs[1], "the second netif should be returned");
    subif = subif_iter(subif, netif);
    fail_unless (subif == &netifs[2], "the third netif should be returned");
    subif = subif_iter(subif, netif);
    fail_unless (subif == NULL, "NULL should be returned");

    netif = &netifs[3];
    subif = NULL;
    subif = subif_iter(subif, netif);
    fail_unless (subif == NULL, "NULL should be returned");

    netif = &netifs[4];
    subif = NULL;
    subif = subif_iter(subif, netif);
    fail_unless (subif == NULL, "NULL should be returned");

    netif = &netifs[5];
    subif = NULL;
    subif = subif_iter(subif, netif);
    fail_unless (subif == &netifs[5], "the sixth netif should be returned");
    subif = subif_iter(subif, netif);
    fail_unless (subif == NULL, "NULL should be returned");


    // netif_byindex checks
    fail_unless (netif_byindex(NULL, 0) == NULL,
	"NULL should be returned on invalid netifs");
    fail_unless (netif_byindex(netifs, 0) == &netifs[0],
	"incorrect netif struct returned");
    fail_unless (netif_byindex(netifs, 1) == &netifs[1],
	"incorrect netif struct returned");
    fail_unless (netif_byindex(netifs, 2) == &netifs[2],
	"incorrect netif struct returned");
    fail_unless (netif_byindex(netifs, 3) == &netifs[5],
	"incorrect netif struct returned");
    fail_unless (netif_byindex(netifs, 6) == NULL,
	"NULL should be returned on not found netif");


    // netif_byname checks
    fail_unless (netif_byname(NULL, "bond0") == NULL,
	"NULL should be returned on invalid netifs");
    fail_unless (netif_byname(netifs, NULL) == NULL,
	"NULL should be returned on invalid name");
    fail_unless (netif_byname(netifs, "bond0") == &netifs[0],
	"incorrect netif struct returned");
    fail_unless (netif_byname(netifs, "eth0") == &netifs[1],
	"incorrect netif struct returned");
    fail_unless (netif_byname(netifs, "eth2") == &netifs[2],
	"incorrect netif struct returned");
    fail_unless (netif_byname(netifs, "eth1") == &netifs[5],
	"incorrect netif struct returned");
    fail_unless (netif_byname(netifs, "eth3") == NULL,
	"NULL should be returned on not found netif");
}
END_TEST

START_TEST(test_read_line) {
    char line[128];
    const char *data = "0123456789ABCDEF";
    const char *null = "/dev/null";
    const char *file = "testfile";

    fail_unless (read_line(NULL, line, 0) == -1,
	"-1 should be returned on a invalid path");

    fail_unless (read_line(file, NULL, 0) == -1,
	"-1 should be returned on an invalid line");

    fail_unless (read_line(null, line, 10) == -1,
	"-1 should be returned on a unreadable file");

    fail_unless (read_line(file, line, 0) == -1,
	"-1 should be returned on zero len request");

    fail_unless (read_line(file, line, 1) == 0,
	"0 bytes should be returned");

    fail_unless (read_line(file, line, 2) == 1,
	"1 bytes should be returned");

    fail_unless (read_line(file, line, 10) == 9,
	"9 bytes should be returned");

    fail_unless (read_line(file, line, 17) == 16,
	"16 bytes should be returned");

    fail_unless (strncmp(line, data, strlen(data)) == 0,
	"invalid line returned");

    fail_unless (read_line(file, line, 18) == 16,
	"16 bytes should be returned");

    fail_unless (strncmp(line, data, strlen(data)) == 0,
	"invalid line returned");
}
END_TEST

START_TEST(test_my_cksum) {
    const char *data = "0123456789ABCDEF";
    uint16_t sum;
    uint8_t cisco;

    cisco = 0;
    sum = my_chksum(data, strlen(data), cisco);
    fail_unless(sum == 10545,
	"IP checksum result should be 10545 not %d", sum);

    cisco = 1;
    sum = my_chksum(data, strlen(data), cisco);
    fail_unless(sum == 10545,
	"(Cisco) IP checksum result should be 10545 not %d", sum);

    cisco = 0;
    sum = my_chksum(data, strlen(data) - 1, cisco);
    fail_unless(sum == 28465,
	"IP checksum result should be 28465 not %d", sum);

    cisco = 1;
    sum = my_chksum(data, strlen(data) - 1, cisco);
    fail_unless(sum ==  10870,
	"(Cisco) IP checksum result should be 10870 not %d", sum);
}
END_TEST

Suite * misc_suite (void) {
    Suite *s = suite_create("misc");

    // util test case
    TCase *tc_util = tcase_create("util");
    tcase_add_test(tc_util, test_netif);
    tcase_add_test(tc_util, test_read_line);
    tcase_add_test(tc_util, test_my_cksum);
    suite_add_tcase(s, tc_util);

    return s;
}

int main (void) {
    int number_failed;
    Suite *s = misc_suite ();
    SRunner *sr = srunner_create (s);
    srunner_run_all (sr, CK_NORMAL);
    number_failed = srunner_ntests_failed (sr);
    srunner_free (sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

