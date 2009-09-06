
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <check.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "common.h"
#include "util.h"
#include "proto/protos.h"
#include "main.h"
#include "child.h"

#include "check_wrap.h"

uint32_t options = OPT_DAEMON | OPT_CHECK;
extern struct nhead netifs;
extern struct mhead mqueue;
extern struct sysinfo sysinfo;

void read_packet(struct master_msg *msg, const char *suffix) {
    int fd;
    char *prefix, *path = NULL;

    memset(msg->msg, 0, ETHER_MAX_LEN);
    msg->len = 0;
    msg->ttl = 0;
    memset(msg->peer.name, 0, IFDESCRSIZE);
    memset(msg->peer.port, 0, IFDESCRSIZE);

    if ((prefix = getenv("srcdir")) == NULL)
	prefix = ".";

    fail_if(asprintf(&path, "%s/%s", prefix, suffix) == -1,
	    "asprintf failed");

    mark_point();
    fail_if((fd = open(path, O_RDONLY)) == -1, "failed to open %s", path);
    msg->len = read(fd, msg->msg, ETHER_MAX_LEN);

    free(path);
}

START_TEST(test_child_send) {
}
END_TEST

START_TEST(test_child_queue) {
    struct master_msg msg;
    struct netif netif;
    struct ether_hdr *ether;
    static uint8_t lldp_dst[] = LLDP_MULTICAST_ADDR;
    int spair[2];
    short event = 0;
    const char *errstr = NULL;

    loglevel = INFO;
    my_socketpair(spair);
    memset(&msg, 0, sizeof(struct master_msg));
    msg.cmd = MASTER_RECV;
    msg.len = ETHER_MIN_LEN;
    msg.proto = PROTO_LLDP;

    // unknown interface
    mark_point();
    errstr = "receiving message from master";
    write(spair[0], &msg, MASTER_MSG_SIZE);
    child_queue(spair[1], event);
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    
    // locally generated packet
    mark_point();
    memset(&netif, 0, sizeof(struct netif));
    netif.index = 1;
    strlcpy(netif.name, "lo0", IFNAMSIZ);
    TAILQ_INSERT_TAIL(&netifs, &netif, entries);
    msg.index = 1;
    write(spair[0], &msg, MASTER_MSG_SIZE);
    child_queue(spair[1], event);
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    // invalid message contents
    mark_point();
    errstr = "Invalid LLDP packet";
    ether = (struct ether_hdr *)msg.msg;
    memset(ether->src, 'A', ETHER_ADDR_LEN);
    memcpy(ether->dst, lldp_dst, ETHER_ADDR_LEN);
    ether->type = htons(ETHERTYPE_LLDP);
    write(spair[0], &msg, MASTER_MSG_SIZE);
    child_queue(spair[1], event);
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    // valid message contents
    mark_point();
    read_packet(&msg, "proto/lldp/42.good.big");
    write(spair[0], &msg, MASTER_MSG_SIZE);
    child_queue(spair[1], event);

    // and the same peer again
    mark_point();
    read_packet(&msg, "proto/lldp/42.good.big");
    write(spair[0], &msg, MASTER_MSG_SIZE);
    child_queue(spair[1], event);

    // test with OPT_AUTO
    mark_point();
    options |= OPT_AUTO;
    read_packet(&msg, "proto/lldp/43.good.lldpmed");
    write(spair[0], &msg, MASTER_MSG_SIZE);
    child_queue(spair[1], event);

    // test with OPT_ARGV
    mark_point();
    options |= OPT_ARGV;
    msg.proto = PROTO_CDP;
    read_packet(&msg, "proto/cdp/45.good.6504");
    write(spair[0], &msg, MASTER_MSG_SIZE);
    child_queue(spair[1], event);

    options = OPT_DAEMON | OPT_CHECK;
    TAILQ_REMOVE(&netifs, &netif, entries);
}
END_TEST

START_TEST(test_child_expire) {
}
END_TEST

Suite * child_suite (void) {
    Suite *s = suite_create("child.c");

    TAILQ_INIT(&netifs);
    TAILQ_INIT(&mqueue);
    sysinfo_fetch(&sysinfo);

    // child test case
    TCase *tc_child = tcase_create("child");
    tcase_add_test(tc_child, test_child_send);
    tcase_add_test(tc_child, test_child_queue);
    tcase_add_test(tc_child, test_child_expire);
    suite_add_tcase(s, tc_child);

    return s;
}

int main (void) {
    int number_failed;
    Suite *s = child_suite ();
    SRunner *sr = srunner_create (s);
    srunner_run_all (sr, CK_NORMAL);
    number_failed = srunner_ntests_failed (sr);
    srunner_free (sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

