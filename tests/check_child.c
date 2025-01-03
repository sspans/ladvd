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
#include <paths.h>

#include "common.h"
#include "util.h"
#include "proto/protos.h"
#include "main.h"
#include "child.h"
#include "check_wrap.h"

const char *ifname = NULL;
unsigned int ifindex = 0;

uint32_t options = OPT_DAEMON | OPT_CHECK;
extern struct nhead netifs;
extern struct mhead mqueue;
extern struct my_sysinfo sysinfo;
extern int msock;

START_TEST(test_child_init) {
    struct parent_req *mreq;
    struct netif *netif, *nnetif;
    const char *errstr = NULL;
    int spair[2], null;
    struct passwd *pwd;
    pid_t pid;

    options |= OPT_ONCE|OPT_DEBUG;
    loglevel = CRIT;
    my_socketpair(spair);

    // start a dummy replier
    pid = fork();
    if (pid == 0) {
	close(spair[0]);
	mreq = my_malloc(PARENT_REQ_MAX);
	while (read(spair[1], mreq, PARENT_REQ_MAX) > 0) {
	    mreq->len = 1;
	    if (write(spair[1], mreq, PARENT_REQ_LEN(mreq->len)) == -1)
		exit(1);
	}
	exit (0);
    }
    close(spair[1]);

    msock = spair[0];

    // skip the test if there are no ethernet interfaces
    netif_init();
    if (netif_fetch(0, NULL, &sysinfo, &netifs) == 0)
	return;

    mark_point();
    null = open(_PATH_DEVNULL, O_WRONLY);
    pwd = getpwnam("nobody");
    WRAP_FATAL_START();
    child_init(spair[0], null, 0, NULL, pwd);
    WRAP_FATAL_END();

    errstr = PACKAGE_STRING " running";
    ck_assert_msg(strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    // reset
    kill(pid, SIGTERM);
    loglevel = INFO;
    options = OPT_DAEMON | OPT_CHECK;
    TAILQ_FOREACH_SAFE(netif, &netifs, entries, nnetif) {
	TAILQ_REMOVE(&netifs, netif, entries);
    }
    close(spair[0]);
}
END_TEST

START_TEST(test_child_send) {
    struct parent_req *mreq;
    struct netif *netif, *nnetif;
    int spair[2], null;
    struct child_send_args args = { .index = -1 };
    pid_t pid;

    loglevel = INFO;
    my_socketpair(spair);
    msock = spair[0];
    null = open(_PATH_DEVNULL, O_WRONLY);

    // init netif sockets
    netif_init();

    // initialize the event library
    event_init();
    evtimer_set(&args.event, (void *)child_send, &args);

    // start a dummy replier
    pid = fork();
    if (pid == 0) {
	close(spair[0]);
	mreq = my_malloc(PARENT_REQ_MAX);
	while (read(spair[1], mreq, PARENT_REQ_MAX) > 0) {
	    if (mreq->op == PARENT_DEVICE)
		mreq->len = 1;
	    if (write(spair[1], mreq, PARENT_REQ_LEN(mreq->len)) == -1)
		exit(1);
	}
	exit (0);
    }
    close(spair[1]);

    // no protocols enabled
    mark_point();
    protos[PROTO_LLDP].enabled = 0;
    child_send(null, EV_TIMEOUT, &args);

    // LLDP enabled
    mark_point();
    protos[PROTO_LLDP].enabled = 1;
    child_send(null, EV_TIMEOUT, &args);

    // CDP enabled
    mark_point();
    protos[PROTO_CDP].enabled = 1;
    child_send(null, EV_TIMEOUT, &args);

    // reset
    kill(pid, SIGTERM);
    TAILQ_FOREACH_SAFE(netif, &netifs, entries, nnetif) {
	TAILQ_REMOVE(&netifs, netif, entries);
    }
}
END_TEST

START_TEST(test_child_queue) {
    struct parent_msg msg, *dmsg, *nmsg;
    struct netif netif;
    struct ether_hdr ether;
    static uint8_t lldp_dst[] = LLDP_MULTICAST_ADDR;
    int spair[2];
    short event = 0;
    const char *errstr = NULL;

    loglevel = INFO;
    my_socketpair(spair);
    memset(&msg, 0, sizeof(struct parent_msg));
    msg.len = ETHER_MIN_LEN;
    msg.proto = PROTO_LLDP;

    // unknown interface
    mark_point();
    errstr = "receiving message from parent";
    WRAP_WRITE(spair[0], &msg, PARENT_MSG_LEN(msg.len));
    child_queue(spair[1], event);
    ck_assert_msg(strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    // locally generated packet
    mark_point();
    memset(&netif, 0, sizeof(struct netif));
    netif.index = ifindex;
    strlcpy(netif.name, ifname, IFNAMSIZ);
    TAILQ_INSERT_TAIL(&netifs, &netif, entries);
    msg.index = ifindex;
    WRAP_WRITE(spair[0], &msg, PARENT_MSG_LEN(msg.len));
    child_queue(spair[1], event);
    ck_assert_msg(strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    // invalid message contents
    mark_point();
    errstr = "Invalid LLDP packet";
    memset(&ether.src, 'A', ETHER_ADDR_LEN);
    memcpy(&ether.dst, lldp_dst, ETHER_ADDR_LEN);
    ether.type = htons(ETHERTYPE_LLDP);
    memcpy(msg.msg, &ether, sizeof(ether));
    WRAP_WRITE(spair[0], &msg, PARENT_MSG_LEN(msg.len));
    child_queue(spair[1], event);
    ck_assert_msg(strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    // valid shutdown message contents
    mark_point();
    read_packet(&msg, "proto/lldp/50.good.shutdown");
    WRAP_WRITE(spair[0], &msg, PARENT_MSG_LEN(msg.len));
    child_queue(spair[1], event);

    // valid message contents
    mark_point();
    read_packet(&msg, "proto/lldp/42.good.big");
    WRAP_WRITE(spair[0], &msg, PARENT_MSG_LEN(msg.len));
    child_queue(spair[1], event);

    // and the same peer again
    mark_point();
    read_packet(&msg, "proto/lldp/42.good.big");
    WRAP_WRITE(spair[0], &msg, PARENT_MSG_LEN(msg.len));
    child_queue(spair[1], event);

    // test with OPT_AUTO
    mark_point();
    options |= OPT_AUTO;
    read_packet(&msg, "proto/lldp/43.good.lldpmed");
    WRAP_WRITE(spair[0], &msg, PARENT_MSG_LEN(msg.len));
    child_queue(spair[1], event);

    // test with OPT_ARGV
    mark_point();
    options |= OPT_ARGV;
    msg.proto = PROTO_CDP;
    read_packet(&msg, "proto/cdp/45.good.6504");
    WRAP_WRITE(spair[0], &msg, PARENT_MSG_LEN(msg.len));
    child_queue(spair[1], event);

    // reset
    options = OPT_DAEMON | OPT_CHECK;
    TAILQ_REMOVE(&netifs, &netif, entries);
    TAILQ_FOREACH_SAFE(dmsg, &mqueue, entries, nmsg) {
	TAILQ_REMOVE(&mqueue, dmsg, entries);
    }
}
END_TEST

START_TEST(test_child_expire) {
    const char *errstr = NULL;
    struct parent_msg msg, *dmsg;
    struct netif netif;
    int spair[2], count;
    short event = 0;

    loglevel = INFO;
    my_socketpair(spair);

    memset(&netif, 0, sizeof(struct netif));
    netif.index = ifindex;
    strlcpy(netif.name, ifname, IFNAMSIZ);
    TAILQ_INSERT_TAIL(&netifs, &netif, entries);

    memset(&msg, 0, sizeof(struct parent_msg));
    msg.index = ifindex;
    msg.len = ETHER_MIN_LEN;
    msg.proto = PROTO_LLDP;

    ck_assert_msg(TAILQ_EMPTY(&mqueue), "the queue should be empty");

    // add an lldp message
    mark_point();
    read_packet(&msg, "proto/lldp/42.good.big");
    WRAP_WRITE(spair[0], &msg, PARENT_MSG_LEN(msg.len));
    child_queue(spair[1], event);
    child_expire();

    // check the message count
    count = 0;
    TAILQ_FOREACH(dmsg, &mqueue, entries) {
	count++;
    }
    ck_assert_msg(count == 1, "invalid message count: %d != 1", count);

    // add an cdp message
    mark_point();
    msg.proto = PROTO_CDP;
    read_packet(&msg, "proto/cdp/45.good.6504");
    WRAP_WRITE(spair[0], &msg, PARENT_MSG_LEN(msg.len));
    child_queue(spair[1], event);
    child_expire();

    // try ifdescr
    errstr = "only -1 bytes written:";
    options = OPT_DAEMON | OPT_CHECK | OPT_IFDESCR;
    msg.proto = PROTO_LLDP;
    read_packet(&msg, "proto/lldp/47.good.nexus");
    WRAP_WRITE(spair[0], &msg, PARENT_MSG_LEN(msg.len));
    WRAP_FATAL_START();
    child_queue(spair[1], event);
    WRAP_FATAL_END();
    ck_assert_msg(strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    options = OPT_DAEMON | OPT_CHECK;

    // check the message count
    count = 0;
    TAILQ_FOREACH(dmsg, &mqueue, entries) {
	count++;
    }
    ck_assert_msg(count == 3, "invalid message count: %d != 3", count);

    // expire a locked message
    mark_point();
    options |= OPT_AUTO;
    dmsg = TAILQ_FIRST(&mqueue);
    dmsg->received  -= dmsg->ttl * 2;
    dmsg->lock = 1;
    child_expire();

    // check the message count
    count = 0;
    TAILQ_FOREACH(dmsg, &mqueue, entries) {
	count++;
    }
    ck_assert_msg(count == 3, "invalid message count: %d != 3", count);

    // expire a message
    mark_point();
    dmsg = TAILQ_FIRST(&mqueue);
    dmsg->lock = 0;
    child_expire();

    // check the message count
    count = 0;
    TAILQ_FOREACH(dmsg, &mqueue, entries) {
	count++;
    }
    ck_assert_msg(count == 2, "invalid message count: %d != 2", count);

    // expire a message
    mark_point();
    dmsg = TAILQ_FIRST(&mqueue);
    dmsg->received -= dmsg->ttl * 2;
    child_expire();

    mark_point();
    dmsg = TAILQ_FIRST(&mqueue);
    dmsg->received -= dmsg->ttl * 2;
    child_expire();

    // check the message count
    ck_assert_msg(TAILQ_EMPTY(&mqueue), "the queue should be empty");

    // reset
    options = OPT_DAEMON | OPT_CHECK;
    TAILQ_REMOVE(&netifs, &netif, entries);
}
END_TEST

START_TEST(test_child_cli) {
    const char *errstr = NULL;
    int sock, spair[2], i;
    struct sockaddr_in sa;
    socklen_t len = sizeof(sa);
    pid_t pid;
    struct parent_msg msg;
    struct ether_hdr ether;
    static uint8_t lldp_dst[] = LLDP_MULTICAST_ADDR;
    struct netif netif;

    loglevel = INFO;
    sock = my_socket(AF_INET, SOCK_STREAM, 0);
    my_socketpair(spair);

    // initialize the event library
    event_init();

    // create netif, queue messages
    memset(&netif, 0, sizeof(struct netif));
    netif.index = ifindex;
    strlcpy(netif.name, ifname, IFNAMSIZ);
    TAILQ_INSERT_TAIL(&netifs, &netif, entries);

    memset(&msg, 0, sizeof(struct parent_msg));
    msg.len = ETHER_MIN_LEN;
    msg.index = ifindex;

    // valid message contents
    mark_point();
    msg.proto = PROTO_LLDP;
    read_packet(&msg, "proto/lldp/42.good.big");
    WRAP_WRITE(spair[0], &msg, PARENT_MSG_LEN(msg.len));
    child_queue(spair[1], 0);
    msg.proto = PROTO_CDP;
    read_packet(&msg, "proto/cdp/45.good.6504");
    WRAP_WRITE(spair[0], &msg, PARENT_MSG_LEN(msg.len));
    child_queue(spair[1], 0);

    // configure socket
    memset(&sa, 0, sizeof(struct sockaddr_in));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;

    mark_point();
    ck_assert_msg(bind(sock,(struct sockaddr *)&sa, len) == 0,
	"socket bind failed");
    ck_assert_msg(getsockname(sock, (struct sockaddr *)&sa, &len) == 0,
	"socket getsockname failed");
    ck_assert_msg(listen(sock, 10) == 0,
	"socket listen failed");

    // start a dummy reader
    mark_point();
    pid = fork();
    if (pid == 0) {
	close(sock);
	while(1) {
	    sock = my_socket(AF_INET, SOCK_STREAM, 0);
	    if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) == -1)
		exit(EXIT_FAILURE);
	    while (read(sock, &msg, PARENT_MSG_MAX) > 0) {
		continue;
	    }
	    close(sock);
	}
	exit (EXIT_SUCCESS);
    }

    // incorrect socket
    mark_point();
    errstr = "cli connection failed";
    WRAP_FATAL_START();
    child_cli_accept(-1, 0);
    WRAP_FATAL_END();
    ck_assert_msg(strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    // accept the connection
    mark_point();
    child_cli_accept(sock, 0);

    // handle the write event
    mark_point();
    event_loop(EVLOOP_ONCE);

    // test EAGAIN too
    mark_point();
    msg.proto = PROTO_LLDP;
    read_packet(&msg, "proto/lldp/42.good.big");
    memcpy(&ether.dst, lldp_dst, ETHER_ADDR_LEN);
    ether.type = htons(ETHERTYPE_LLDP);

    for (i = 0; i < 64; i++) {
	memset(&ether.src, i, ETHER_ADDR_LEN);
	memcpy(msg.msg, &ether, sizeof(ether));
	WRAP_WRITE(spair[0], &msg, PARENT_MSG_LEN(msg.len));
	child_queue(spair[1], 0);
    }

    // accept the connection
    mark_point();
    child_cli_accept(sock, 0);

    // handle the write events
    mark_point();
    //event_loop(EVLOOP_ONCE);

    // reset
    kill(pid, SIGTERM);
}
END_TEST

START_TEST(test_child_link) {
    mark_point();
    child_link_fd();
}
END_TEST

START_TEST(test_child_free) {
    mark_point();
    child_free(0, 0, NULL);
}
END_TEST

Suite * child_suite (void) {
    Suite *s = suite_create("child.c");

    TAILQ_INIT(&netifs);
    TAILQ_INIT(&mqueue);
    memset(&sysinfo, 0, sizeof(struct my_sysinfo));
    WRAP_FATAL_START();
    sysinfo_fetch(&sysinfo);
    WRAP_FATAL_END();
    strlcpy(sysinfo.hostname, "myhostname", sizeof(sysinfo.hostname));

    // child test case
    TCase *tc_child = tcase_create("child");
    tcase_add_test(tc_child, test_child_init);
    tcase_add_test(tc_child, test_child_send);
    tcase_add_test(tc_child, test_child_queue);
    tcase_add_test(tc_child, test_child_expire);
    tcase_add_test(tc_child, test_child_cli);
    tcase_add_test(tc_child, test_child_link);
    tcase_add_test(tc_child, test_child_free);
    suite_add_tcase(s, tc_child);

    ifname = "lo";
    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
	ifname = "lo0";
	ifindex = if_nametoindex(ifname);
    }

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

