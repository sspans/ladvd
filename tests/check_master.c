
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <check.h>
#include <sys/param.h>
#include <signal.h>

#define _EVENT_H_
struct event { };

#include "common.h"
#include "util.h"
#include "proto/protos.h"
#include "main.h"
#include "master.h"

#ifdef USE_CAPABILITIES
#include <sys/prctl.h>
#include <sys/capability.h>
#endif

#if HAVE_LINUX_ETHTOOL_H
#include <linux/ethtool.h>
#endif /* HAVE_LINUX_ETHTOOL_H */
#ifdef HAVE_NET_BPF_H
#include <net/bpf.h>
#endif /* HAVE_NET_BPF_H */

#include "check_wrap.h"

uint32_t options = OPT_DAEMON | OPT_CHECK;

// stub functions
// linking with libevent introduces threads which breaks check_wrap
// so instead use stubs since we don't test library functions anyway
void *event_init(void) {
    return(NULL);
}
int event_dispatch(void) {
    return(0);
}
int event_add(struct event *ev, struct timeval *tv) {
    return(0);
}
int event_del(struct event *ev) {
    return(0);
}
void event_set(struct event *ev, int i, short s,
    void (*v1)(int, short, void *), void *v2) {
}

#ifdef USE_CAPABILITIES
cap_t cap_from_text(const char *str) {
    cap_t cap;
    return (cap);
}
int cap_set_proc(cap_t cap) {
    return(0);
}
int cap_free(void *arg) {
    return(0);
}
#endif /* USE_CAPABILITIES */


START_TEST(test_master_signal) {
    int sig = 0;
    short event = 0;
    pid_t pid = 1;
    const char *errstr = NULL;

    loglevel = INFO;

    mark_point();
    sig = SIGCHLD;
    errstr = "child has exited";
    WRAP_FATAL_START();
    master_signal(sig, event, NULL);
    WRAP_FATAL_END();
    fail_unless (strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    mark_point();
    check_wrap_fake |= FAKE_KILL;
    sig = SIGINT;
    errstr = "quitting";
    WRAP_FATAL_START();
    master_signal(sig, event, &pid);
    WRAP_FATAL_END();
    fail_unless (strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    mark_point();
    sig = SIGTERM;
    errstr = "quitting";
    WRAP_FATAL_START();
    master_signal(sig, event, &pid);
    WRAP_FATAL_END();
    fail_unless (strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    check_wrap_fake &= ~FAKE_KILL;

    mark_point();
    sig = SIGHUP;
    errstr = "check";
    my_log(CRIT, errstr);
    master_signal(sig, event, NULL);
    fail_unless (strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    mark_point();
    sig = 0;
    errstr = "unexpected signal";
    WRAP_FATAL_START();
    master_signal(sig, event, NULL);
    WRAP_FATAL_END();
    fail_unless (strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
}
END_TEST

START_TEST(test_master_cmd) {
    struct master_msg mreq;
    struct ether_hdr ether;
    static uint8_t lldp_dst[] = LLDP_MULTICAST_ADDR;
    const char *errstr = NULL;
    int spair[2], fd = -1;
    extern int dfd;
    short event = 0;

    // supply an invalid fd, resulting in a read error
    mark_point();
    errstr = "check";
    my_log(CRIT, errstr);
    master_cmd(fd, event);
    fail_unless (strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    // test a message with an incorrect size
    mark_point();
    my_socketpair(spair);
    write(spair[0], &mreq, 1);
    errstr = "invalid request received";
    WRAP_FATAL_START();
    master_cmd(spair[1], event);
    WRAP_FATAL_END();
    fail_unless (strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    // test a message with incorrect content
    mark_point();
    memset(&mreq, 0, sizeof(struct master_msg));
    mreq.cmd = MASTER_SEND;
    mreq.len = ETHER_MIN_LEN;
    mreq.proto = PROTO_LLDP;

    write(spair[0], &mreq, MASTER_MSG_SIZE);

    errstr = "invalid request supplied";
    WRAP_FATAL_START();
    master_cmd(spair[1], event);
    WRAP_FATAL_END();
    fail_unless (strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    // test a correct MASTER_SEND
    mark_point();
    dfd = spair[1];
    options |= OPT_DEBUG;
    mreq.cmd = MASTER_SEND;
    mreq.index = 1;
    memcpy(ether.dst, lldp_dst, ETHER_ADDR_LEN);
    ether.type = htons(ETHERTYPE_LLDP);
    memcpy(mreq.msg, &ether, sizeof(struct ether_hdr));
    write(spair[0], &mreq, MASTER_MSG_SIZE);

    errstr = "check";
    my_log(CRIT, errstr);
    WRAP_FATAL_START();
    master_cmd(spair[1], event);
    WRAP_FATAL_END();
    fail_unless (strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    // test a correct ETHTOOL / DESCR
    mark_point();
#ifdef HAVE_LINUX_ETHTOOL_H
    mreq.cmd = MASTER_ETHTOOL;
    mreq.len = sizeof(struct ethtool_cmd);
#elif defined SIOCSIFDESCR
    mreq.cmd = MASTER_DESCR;
    mreq.len = 0;
#endif

#if defined(HAVE_LINUX_ETHTOOL_H) || defined(SIOCSIFDESCR)
    write(spair[0], &mreq, MASTER_MSG_SIZE);

    errstr = "check";
    my_log(CRIT, errstr);
    WRAP_FATAL_START();
    master_cmd(spair[1], event);
    WRAP_FATAL_END();
    fail_unless (strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    // test a failing return message
    mark_point();
    write(spair[0], &mreq, MASTER_MSG_SIZE);
    close(spair[0]);

    errstr = "failed to return message to child";
    WRAP_FATAL_START();
    master_cmd(spair[1], event);
    WRAP_FATAL_END();
    fail_unless (strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
#endif
}
END_TEST

START_TEST(test_master_check) {
    struct master_msg mreq;
    struct ether_hdr ether;
    static uint8_t lldp_dst[] = LLDP_MULTICAST_ADDR;

    memset(&mreq, 0, sizeof(struct master_msg));

    mark_point();
    mreq.cmd = MASTER_SEND;
    mreq.len = ETHER_MIN_LEN;
    mreq.proto = PROTO_LLDP;

    fail_unless(master_check(&mreq) == EXIT_FAILURE,
	"MASTER_SEND check failed");

    // lo0 mostly
    mark_point();
    mreq.index = 1;
    memcpy(ether.dst, lldp_dst, ETHER_ADDR_LEN);
    ether.type = htons(ETHERTYPE_LLDP);
    memcpy(mreq.msg, &ether, sizeof(struct ether_hdr));

    fail_unless(master_check(&mreq) == EXIT_SUCCESS,
	"MASTER_SEND check failed");

#ifdef HAVE_LINUX_ETHTOOL_H
    mark_point();
    mreq.cmd = MASTER_ETHTOOL;
    mreq.len = sizeof(struct ethtool_cmd);
    fail_unless(master_check(&mreq) == EXIT_SUCCESS,
	"MASTER_ETHTOOL check failed");
#endif

#ifdef SIOCSIFDESCR
    mark_point();
    mreq.cmd = MASTER_DESCR;
    mreq.len = 0;
    fail_unless(master_check(&mreq) == EXIT_SUCCESS,
	"MASTER_DESCR check failed");
#endif

    mark_point();
#ifndef HAVE_LINUX_ETHTOOL_H
    mreq.cmd = MASTER_ETHTOOL;
#elif !defined SIOCSIFDESCR
    mreq.cmd = MASTER_DESCR;
#endif
    fail_unless(master_check(&mreq) == EXIT_FAILURE,
	"master_check should fail");
}
END_TEST

START_TEST(test_master_send) {
    extern struct rfdhead rawfds;
    struct rawfd rfd;
    struct master_msg mreq;
    int spair[2];
    extern int dfd;
    ssize_t len;
    const char *errstr;

    TAILQ_INIT(&rawfds);
    loglevel = INFO;
    my_socketpair(spair);
    mreq.index = 1;
    mreq.len = ETHER_MIN_LEN;

    dfd = spair[1];
    rfd.fd = spair[1];
    rfd.index = 1;
    strlcpy(rfd.name, "lo0", IFNAMSIZ);
    TAILQ_INSERT_TAIL(&rawfds, &rfd, entries);

    mark_point();
    options |= OPT_DEBUG;
    len = master_send(&mreq);
    fail_unless(len == ETHER_MIN_LEN,
	"incorrect length returned: %ld", len);

    mark_point();
    errstr = "failed to write pcap record header";
    dfd = -1;
    WRAP_FATAL_START();
    len = master_send(&mreq);
    WRAP_FATAL_END();
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    mark_point();
    errstr = "only -1 bytes written";
    rfd.fd = -1;
    options &= ~OPT_DEBUG;
    check_wrap_fake |= FAKE_IOCTL;
    master_send(&mreq);
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
}
END_TEST

START_TEST(test_master_open) {
}
END_TEST

START_TEST(test_master_close) {
}
END_TEST

START_TEST(test_master_socket) {
    extern struct rfdhead rawfds;
    struct rawfd rfd;
    const char *errstr;

    TAILQ_INIT(&rawfds);

    rfd.fd = -1;
    rfd.index = 1;
    strlcpy(rfd.name, "lo0", IFNAMSIZ);
    TAILQ_INSERT_TAIL(&rawfds, &rfd, entries);

    mark_point();
    errstr = "failed to bind socket to";
    check_wrap_fake |= FAKE_SOCKET|FAKE_OPEN;
    check_wrap_fail |= FAIL_BIND|FAIL_IOCTL;
    WRAP_FATAL_START();
    master_socket(&rfd);
    WRAP_FATAL_END();
    check_wrap_fail &= ~(FAIL_BIND|FAIL_IOCTL);
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    mark_point();
    errstr = "check";
    my_log(CRIT, errstr);
    check_wrap_fake |= FAKE_BIND|FAKE_IOCTL;

#ifdef HAVE_LINUX_FILTER_H
    errstr = "unable to configure socket filter for";
    check_wrap_fail |= FAIL_SETSOCKOPT;
    WRAP_FATAL_START();
    master_socket(&rfd);
    WRAP_FATAL_END();
    check_wrap_fail &= ~FAIL_SETSOCKOPT;
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
#elif HAVE_NET_BPF_H
    errstr = "unable to configure immediate mode for";
    check_wrap_fail |= FAIL_IOCTL;
    WRAP_FATAL_START();
    master_socket(&rfd);
    WRAP_FATAL_END();
    check_wrap_fail &= ~FAIL_IOCTL;
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
#endif

#ifdef AF_PACKET
    mark_point();
    errstr = "check";
    my_log(CRIT, errstr);
    check_wrap_fake |= FAKE_SETSOCKOPT;
    master_socket(&rfd);
    check_wrap_fake &= ~FAKE_SETSOCKOPT;
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
#elif defined AF_LINK
    mark_point();
    errstr = "check";
    my_log(CRIT, errstr);
    check_wrap_fake |= FAKE_IOCTL;
    master_socket(&rfd);
    check_wrap_fake &= ~FAKE_IOCTL;
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
#endif
}
END_TEST

START_TEST(test_master_multi) {
    struct rawfd rfd;
    int spair[2];
    const char *errstr;

    my_socketpair(spair);
    rfd.fd = spair[1];
    rfd.index = 1;
    strlcpy(rfd.name, "lo0", IFNAMSIZ);

    mark_point();
    options |= OPT_DEBUG;
    errstr = "check";
    my_log(CRIT, errstr);
    master_multi(&rfd, protos, 0);
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    mark_point();
    errstr = "check";
    my_log(CRIT, errstr);
    check_wrap_fake |= FAKE_IOCTL|FAKE_SETSOCKOPT;
    master_multi(&rfd, protos, 1);
    check_wrap_fake = 0;
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
}
END_TEST

START_TEST(test_master_recv) {
    extern struct rfdhead rawfds;
    struct rawfd rfd;
    int spair[2];
    extern int mfd;
    short event = 0;
    const char *errstr = NULL;
    char buf[ETHER_MAX_LEN * 2];
    char *msg;
    int hlen = 0;
#ifdef HAVE_NET_BPF_H
    struct bpf_hdr *bhp, *ebhp;
    void *endp;
    extern struct bpf_buf bpf_buf;
#endif /* HAVE_NET_BPF_H */
    struct ether_hdr ether;
    static uint8_t lldp_dst[] = CDP_MULTICAST_ADDR;

    loglevel = INFO;
    TAILQ_INIT(&rawfds);

#ifdef HAVE_NET_BPF_H
    // create a sensible bpf buffer
    bpf_buf.len = roundup(ETHER_MAX_LEN, getpagesize());
    bpf_buf.data = my_malloc(bpf_buf.len);
#endif

    // test a failing receive
    mark_point();
    errstr = "receiving message failed";
    memset(&rfd, 0, sizeof(rfd));
    rfd.fd = -1;
    WRAP_FATAL_START();
    master_recv(rfd.fd, event, &rfd);
    WRAP_FATAL_END();
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    memset(&buf, 0, sizeof(buf));
#ifdef HAVE_NET_BPF_H
    bhp = (struct bpf_hdr *)buf;
    hlen = BPF_WORDALIGN(sizeof(struct bpf_hdr));
    bhp->bh_hdrlen = hlen;
    bhp->bh_caplen = ETHER_MIN_LEN;
    msg = buf + hlen;

    // create an end bhp covering the rest of buf
    ebhp = (struct bpf_hdr *)buf;
    ebhp += BPF_WORDALIGN(bhp->bh_hdrlen + bhp->bh_caplen);
    ebhp->bh_hdrlen = hlen;
    ebhp->bh_caplen = sizeof(buf);
    ebhp->bh_caplen -= BPF_WORDALIGN(bhp->bh_hdrlen + bhp->bh_caplen);
    ebhp->bh_caplen -= hlen;
#elif defined HAVE_NETPACKET_PACKET_H
    msg = buf;
#endif
    my_socketpair(spair);
    mfd = spair[1];
    rfd.fd = spair[1];
    TAILQ_INSERT_TAIL(&rawfds, &rfd, entries);

    // too short
    mark_point();
    errstr = "check";
    my_log(CRIT, errstr);
    write(spair[0], &buf, 1 + hlen);
    master_recv(rfd.fd, event, &rfd);
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    // empty message
    mark_point();
    errstr = "unknown message type received";
    write(spair[0], &buf, ETHER_MIN_LEN + hlen);
    master_recv(rfd.fd, event, &rfd);
    fail_unless (strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    // valid message
    mark_point();
    errstr = "received CDP message (64 bytes)";
    memcpy(ether.dst, lldp_dst, ETHER_ADDR_LEN);
    memcpy(msg, &ether, sizeof(struct ether_hdr));
    mark_point();
    write(spair[0], &buf, ETHER_MIN_LEN + hlen);
    master_recv(rfd.fd, event, &rfd);
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    // too long (or multiple messages with bpf)
    mark_point();
    write(spair[0], &buf, sizeof(buf));
    master_recv(rfd.fd, event, &rfd);

    // closed child socket
    mark_point();
    errstr = "failed to send message to child";
    write(spair[0], &buf, ETHER_MIN_LEN + hlen);
    close(spair[0]);
    WRAP_FATAL_START();
    master_recv(rfd.fd, event, &rfd);
    WRAP_FATAL_END();
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
}
END_TEST

Suite * master_suite (void) {
    Suite *s = suite_create("master.c");

    // master test case
    TCase *tc_master = tcase_create("master");
    tcase_add_test(tc_master, test_master_signal);
    tcase_add_test(tc_master, test_master_cmd);
    tcase_add_test(tc_master, test_master_check);
    tcase_add_test(tc_master, test_master_send);
    tcase_add_test(tc_master, test_master_open);
    tcase_add_test(tc_master, test_master_close);
    tcase_add_test(tc_master, test_master_socket);
    tcase_add_test(tc_master, test_master_multi);
    tcase_add_test(tc_master, test_master_recv);
    suite_add_tcase(s, tc_master);

    return s;
}

int main (void) {
    int number_failed;
    Suite *s = master_suite ();
    SRunner *sr = srunner_create (s);
    srunner_run_all (sr, CK_NORMAL);
    number_failed = srunner_ntests_failed (sr);
    srunner_free (sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

