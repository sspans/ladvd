
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <check.h>

#include "../src/common.h"
#include "../src/util.h"

uint32_t options = OPT_DAEMON;

START_TEST(test_my) {
    char *ptr = NULL;
    int s = 0;
    extern int check_fail_exit;
    extern int check_fail_malloc;
    extern int check_fail_calloc;

    my_log(INFO, "foo\n");
    check_fail_exit = 1;
    my_fatal("test fatal");
    check_fail_exit = 0;

    ptr = my_malloc(100);
    fail_unless (ptr != NULL, "a valid pointer should be returned");
    free(ptr);
    ptr = NULL;

    ptr = my_calloc(10, 10);
    fail_unless (ptr != NULL, "a valid pointer should be returned");
    free(ptr);
    ptr = NULL;

    check_fail_exit = 1;
    check_fail_calloc = 1;
    ptr = my_calloc(10, 10);
    check_fail_calloc = 0;
    check_fail_exit = 0;

    ptr = my_strdup("foo");
    fail_unless (ptr != NULL, "a valid pointer should be returned");
    free(ptr);
    ptr = NULL;

    s = my_socket(AF_INET, SOCK_DGRAM, 0);
    fail_unless (s != -1, "a valid socket should be returned");
    close(s);
    s = 0;

    s = my_socket(AF_INET6, SOCK_DGRAM, 0);
    fail_unless (s != -1, "a valid socket should be returned");
    close(s);
    s = 0;

    check_fail_exit = 1;
    s = my_socket(AF_MAX, 0, 0);
    check_fail_exit = 0;
}
END_TEST

START_TEST(test_netif) {
    struct nhead nqueue;
    struct nhead *netifs = &nqueue;
    struct netif tnetifs[6];
    struct netif *netif, *subif;
    int argc;

    TAILQ_INIT(netifs);

    tnetifs[0].index = 0;
    tnetifs[0].argv = 0;
    tnetifs[0].slave = 0;
    tnetifs[0].type = NETIF_BONDING;
    tnetifs[0].subif = &tnetifs[1];
    strlcpy(tnetifs[0].name, "bond0", IFNAMSIZ); 

    tnetifs[1].index = 1;
    tnetifs[1].argv = 1;
    tnetifs[1].slave = 1;
    tnetifs[1].type = NETIF_REGULAR;
    tnetifs[1].subif = &tnetifs[2];
    strlcpy(tnetifs[1].name, "eth0", IFNAMSIZ); 

    tnetifs[2].index = 2;
    tnetifs[2].argv = 0;
    tnetifs[2].slave = 1;
    tnetifs[2].type = NETIF_REGULAR;
    tnetifs[2].subif = NULL,
    strlcpy(tnetifs[2].name, "eth2", IFNAMSIZ); 

    tnetifs[3].index = 4;
    tnetifs[3].argv = 0;
    tnetifs[3].slave = 0;
    tnetifs[3].type = NETIF_BRIDGE;
    tnetifs[3].subif = NULL,
    strlcpy(tnetifs[3].name, "bridge0", IFNAMSIZ); 

    tnetifs[4].index = 5;
    tnetifs[4].argv = 1;
    tnetifs[4].slave = 0;
    tnetifs[4].type = NETIF_BONDING;
    tnetifs[4].subif = NULL,
    strlcpy(tnetifs[4].name, "lagg0", IFNAMSIZ); 

    tnetifs[5].index = 3;
    tnetifs[5].argv = 1;
    tnetifs[5].slave = 0;
    tnetifs[5].type = NETIF_REGULAR;
    tnetifs[5].subif = NULL,
    strlcpy(tnetifs[5].name, "eth1", IFNAMSIZ); 

    TAILQ_INSERT_TAIL(netifs, &tnetifs[0], entries);
    TAILQ_INSERT_TAIL(netifs, &tnetifs[1], entries);
    TAILQ_INSERT_TAIL(netifs, &tnetifs[2], entries);
    TAILQ_INSERT_TAIL(netifs, &tnetifs[3], entries);
    TAILQ_INSERT_TAIL(netifs, &tnetifs[4], entries);
    TAILQ_INSERT_TAIL(netifs, &tnetifs[5], entries);

    // netif_iter checks
    netif = NULL;
    argc = 0;
    fail_unless (netif_iter(netif, NULL, argc) == NULL,
	"NULL should be returned on invalid netifs");

    netif = NULL;
    argc = 0;
    netif = netif_iter(netif, netifs, argc);
    fail_unless (netif == &tnetifs[0], "the first netif should be returned");
    netif = netif_iter(netif, netifs, argc);
    fail_unless (netif == &tnetifs[5], "the sixth netif should be returned");
    netif = netif_iter(netif, netifs, argc);
    fail_unless (netif == NULL, "NULL should be returned");

    netif = NULL;
    argc = 2;
    netif = netif_iter(netif, netifs, argc);
    fail_unless (netif == &tnetifs[1], "the second netif should be returned");
    netif = netif_iter(netif, netifs, argc);
    fail_unless (netif == &tnetifs[5], "the sixth netif should be returned");
    netif = netif_iter(netif, netifs, argc);
    fail_unless (netif == NULL, "NULL should be returned");


    // subif_iter checks
    netif = &tnetifs[0];
    subif = NULL;
    subif = subif_iter(subif, subif);
    fail_unless (subif == NULL, "NULL should be returned");
    subif = subif_iter(subif, netif);
    fail_unless (subif == &tnetifs[1], "the second netif should be returned");
    subif = subif_iter(subif, netif);
    fail_unless (subif == &tnetifs[2], "the third netif should be returned");
    subif = subif_iter(subif, netif);
    fail_unless (subif == NULL, "NULL should be returned");

    netif = &tnetifs[3];
    subif = NULL;
    subif = subif_iter(subif, netif);
    fail_unless (subif == NULL, "NULL should be returned");

    netif = &tnetifs[4];
    subif = NULL;
    subif = subif_iter(subif, netif);
    fail_unless (subif == NULL, "NULL should be returned");

    netif = &tnetifs[5];
    subif = NULL;
    subif = subif_iter(subif, netif);
    fail_unless (subif == &tnetifs[5], "the sixth netif should be returned");
    subif = subif_iter(subif, netif);
    fail_unless (subif == NULL, "NULL should be returned");


    // netif_byindex checks
    fail_unless (netif_byindex(NULL, 0) == NULL,
	"NULL should be returned on invalid netifs");
    fail_unless (netif_byindex(netifs, 0) == &tnetifs[0],
	"incorrect netif struct returned");
    fail_unless (netif_byindex(netifs, 1) == &tnetifs[1],
	"incorrect netif struct returned");
    fail_unless (netif_byindex(netifs, 2) == &tnetifs[2],
	"incorrect netif struct returned");
    fail_unless (netif_byindex(netifs, 3) == &tnetifs[5],
	"incorrect netif struct returned");
    fail_unless (netif_byindex(netifs, 6) == NULL,
	"NULL should be returned on not found netif");


    // netif_byname checks
    fail_unless (netif_byname(NULL, "bond0") == NULL,
	"NULL should be returned on invalid netifs");
    fail_unless (netif_byname(netifs, NULL) == NULL,
	"NULL should be returned on invalid name");
    fail_unless (netif_byname(netifs, "bond0") == &tnetifs[0],
	"incorrect netif struct returned");
    fail_unless (netif_byname(netifs, "eth0") == &tnetifs[1],
	"incorrect netif struct returned");
    fail_unless (netif_byname(netifs, "eth2") == &tnetifs[2],
	"incorrect netif struct returned");
    fail_unless (netif_byname(netifs, "eth1") == &tnetifs[5],
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
	"-1 should be returned on an invalid path");

    fail_unless (read_line(file, NULL, 0) == -1,
	"-1 should be returned on an invalid line");

    fail_unless (read_line("non-existant", line, 0) == -1,
	"-1 should be returned on a missing file");

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
    sum = ntohs(my_chksum(data, strlen(data), cisco));
    fail_unless(sum == 12585,
	"IP checksum result should be 12585 not %d", sum);

    cisco = 1;
    sum = ntohs(my_chksum(data, strlen(data), cisco));
    fail_unless(sum == 12585,
	"(Cisco) IP checksum result should be 12585 not %d", sum);

    cisco = 0;
    sum = ntohs(my_chksum(data, strlen(data) - 1, cisco));
    fail_unless(sum == 12655,
	"IP checksum result should be 12655 not %d", sum);

    cisco = 1;
    sum = ntohs(my_chksum(data, strlen(data) - 1, cisco));
    fail_unless(sum ==  30250,
	"(Cisco) IP checksum result should be 30250 not %d", sum);
}
END_TEST


START_TEST(test_my_priv) {
    struct passwd *pwd;
    extern int check_fail_priv;
    extern int check_fail_exit;
    extern int check_fail_chdir;

    pwd = getpwnam("root");
    errno = EPERM;

    check_fail_exit = 1;
    check_fail_priv = 1;
    my_drop_privs(pwd);
    check_fail_priv = 0;
    check_fail_exit = 0;

    check_fail_exit = 1;
    check_fail_chdir = 1;
    my_chroot("/nonexistent");
    check_fail_chdir = 0;
    check_fail_exit = 0;
}
END_TEST

Suite * util_suite (void) {
    Suite *s = suite_create("util.c");

    // util test case
    TCase *tc_util = tcase_create("util");
    tcase_add_test(tc_util, test_my);
    tcase_add_test(tc_util, test_netif);
    tcase_add_test(tc_util, test_read_line);
    tcase_add_test(tc_util, test_my_cksum);
    tcase_add_test(tc_util, test_my_priv);
    suite_add_tcase(s, tc_util);

    return s;
}

int main (void) {
    int number_failed;
    Suite *s = util_suite ();
    SRunner *sr = srunner_create (s);
    srunner_run_all (sr, CK_NORMAL);
    number_failed = srunner_ntests_failed (sr);
    srunner_free (sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

