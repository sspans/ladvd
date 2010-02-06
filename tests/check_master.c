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

#include <check.h>

#include "common.h"
#include "util.h"
#include "proto/protos.h"
#include "main.h"
#include "master.h"
#include "check_wrap.h"

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

uint32_t options = OPT_DAEMON | OPT_CHECK;
extern int dfd;
extern int mfd;
extern struct rfdhead rawfds;

START_TEST(test_master_signal) {
    int sig = 0;
    short event = 0;
    pid_t pid = 1;
    const char *errstr = NULL;

    loglevel = INFO;

    mark_point();
    sig = SIGCHLD;
    errstr = "quitting";
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

    // reset
    check_wrap_fake = 0;
}
END_TEST

START_TEST(test_master_req) {
    struct master_req mreq;
    struct master_msg msg;
    struct ether_hdr ether;
    static uint8_t lldp_dst[] = LLDP_MULTICAST_ADDR;
    struct rawfd *rfd;
    const char *errstr = NULL;
    int spair[2], fd = -1;
    short event = 0;

    loglevel = INFO;
    my_socketpair(spair);
    memset(&mreq, 0, MASTER_REQ_MAX);

    // supply an invalid fd, resulting in a read error
    mark_point();
    errstr = "invalid request received";
    my_log(CRIT, errstr);
    WRAP_FATAL_START();
    master_req(fd, event);
    WRAP_FATAL_END();
    fail_unless (strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    // test a message with an incorrect size
    mark_point();
    errstr = "invalid request received";
    WRAP_WRITE(spair[0], &mreq, 1);
    WRAP_FATAL_START();
    master_req(spair[1], event);
    WRAP_FATAL_END();
    fail_unless (strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    // test a message with incorrect content
    mark_point();
    mreq.op = MASTER_MAX - 1;
    mreq.len = ETHER_MIN_LEN;

    errstr = "invalid request supplied";
    WRAP_WRITE(spair[0], &mreq, MASTER_REQ_LEN(mreq.len));
    WRAP_FATAL_START();
    master_req(spair[1], event);
    WRAP_FATAL_END();
    fail_unless (strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    // test a correct CLOSE
    mark_point();
    dfd = spair[1];
    options |= OPT_DEBUG;
    mreq.op = MASTER_CLOSE;
    mreq.index = 1;
    mreq.len = 0;
    memcpy(ether.dst, lldp_dst, ETHER_ADDR_LEN);
    ether.type = htons(ETHERTYPE_LLDP);
    memcpy(mreq.buf, &ether, sizeof(struct ether_hdr));
    WRAP_WRITE(spair[0], &mreq, MASTER_REQ_LEN(mreq.len));

    errstr = "check";
    my_log(CRIT, errstr);
    WRAP_FATAL_START();
    master_req(spair[1], event);
    WRAP_FATAL_END();
    fail_unless (strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    // test a correct CLOSE
    mark_point();
    fail_unless (rfd_byindex(&rawfds, 1) == NULL,
    	"the queue should be empty");

    options |= OPT_DEBUG;
    msg.index = 1;
    strlcpy(msg.name, "lo0", IFNAMSIZ);

    master_open(&msg);
    fail_unless (rfd_byindex(&rawfds, 1) != NULL,
    	"rfd should be added to the queue");

    errstr = "check";
    my_log(CRIT, errstr);
    mreq.op = MASTER_CLOSE;
    mreq.index = 1;
    strlcpy(mreq.name, "lo0", IFNAMSIZ);
    WRAP_WRITE(spair[0], &mreq, MASTER_REQ_LEN(mreq.len));
    master_req(spair[1], event);
    fail_unless (strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    fail_unless (rfd_byindex(&rawfds, 1) == NULL,
    	"rfd should be removed from the queue");
 
    // test a correct ETHTOOL / DESCR
    mark_point();
#ifdef HAVE_LINUX_ETHTOOL_H
    mreq.op = MASTER_ETHTOOL;
    mreq.len = sizeof(struct ethtool_cmd);
#elif defined SIOCSIFDESCR
    mreq.op = MASTER_DESCR;
    mreq.len = 0;
#endif

#if defined(HAVE_LINUX_ETHTOOL_H) || defined(SIOCSIFDESCR)
    WRAP_WRITE(spair[0], &mreq, MASTER_REQ_LEN(mreq.len));

    errstr = "check";
    my_log(CRIT, errstr);
    WRAP_FATAL_START();
    master_req(spair[1], event);
    WRAP_FATAL_END();
    fail_unless (strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
#endif

#ifdef HAVE_SYSFS
    // test a correct DEVICE
    mreq.op = MASTER_DEVICE;
    mreq.len = 0;
    WRAP_WRITE(spair[0], &mreq, MASTER_REQ_LEN(mreq.len));
    master_req(spair[1], event);
    fail_unless (strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
#endif /* HAVE_SYSFS */

    // test a failing return message
    mark_point();
    master_open(&msg);
    rfd = rfd_byindex(&rawfds, 1);
    fail_unless (rfd != NULL, "rfd should be added to the queue");
    mreq.op = MASTER_CLOSE;
    fd = dup(spair[1]);
    rfd->fd = fd;
    WRAP_WRITE(spair[0], &mreq, MASTER_REQ_LEN(mreq.len));
    close(spair[0]);

    errstr = "failed to return request to child";
    WRAP_FATAL_START();
    master_req(spair[1], event);
    WRAP_FATAL_END();
    fail_unless (strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    fail_unless (close(fd) == -1, "rfd->fd should be closed");
    fail_unless (rfd_byindex(&rawfds, 1) == NULL,
    	"rfd should be removed from the queue");
}
END_TEST

START_TEST(test_master_check) {
    struct master_req mreq;

    memset(&mreq, 0, MASTER_REQ_MAX);

    mark_point();
    mreq.op = MASTER_CLOSE;
    fail_unless(master_check(&mreq) == EXIT_SUCCESS,
	"MASTER_CLOSE check failed");

    mark_point();
    mreq.op = MASTER_MAX - 1;
    mreq.len = ETHER_MIN_LEN;

    fail_unless(master_check(&mreq) == EXIT_FAILURE,
	"master_check should fail");

#ifdef HAVE_LINUX_ETHTOOL_H
    mark_point();
    mreq.op = MASTER_ETHTOOL;
    mreq.index = 1;
    mreq.len = sizeof(struct ethtool_cmd);
    fail_unless(master_check(&mreq) == EXIT_SUCCESS,
	"MASTER_ETHTOOL check failed");
#endif

#ifdef SIOCSIFDESCR
    mark_point();
    mreq.op = MASTER_DESCR;
    mreq.index = 1;
    mreq.len = 0;
    fail_unless(master_check(&mreq) == EXIT_SUCCESS,
	"MASTER_DESCR check failed");
#endif

    mark_point();
#ifndef HAVE_LINUX_ETHTOOL_H
    mreq.op = MASTER_ETHTOOL;
#elif !defined SIOCSIFDESCR
    mreq.op = MASTER_DESCR;
#endif
    fail_unless(master_check(&mreq) == EXIT_FAILURE,
	"master_check should fail");
}
END_TEST

START_TEST(test_master_send) {
    struct rawfd *rfd;
    struct master_msg msg;
    struct ether_hdr ether;
    static uint8_t lldp_dst[] = LLDP_MULTICAST_ADDR;
    int spair[2];
    const char *errstr;
    short event = 0;

    loglevel = INFO;
    options |= OPT_DEBUG;
    my_socketpair(spair);
    msg.index = 1;
    msg.len = ETHER_MIN_LEN;
    strlcpy(msg.name, "lo0", IFNAMSIZ);

    dfd = spair[1];
    master_open(&msg);
    rfd = rfd_byindex(&rawfds, 1);
    fail_unless (rfd != NULL, "rfd should be added to the queue");
    rfd->fd = spair[1];

    // incorrect msend msg.len should be skipped
    mark_point();
    errstr = "check";
    my_log(CRIT, errstr);
    WRAP_WRITE(spair[0], &msg, MASTER_MSG_LEN(msg.len) - 1); 
    WRAP_FATAL_START();
    master_send(spair[1], event);
    WRAP_FATAL_END();
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    mark_point();
    msg.proto = PROTO_LLDP;
    memcpy(ether.dst, lldp_dst, ETHER_ADDR_LEN);
    ether.type = htons(ETHERTYPE_LLDP);
    memcpy(msg.msg, &ether, sizeof(ether));
    errstr = "failed to write pcap record header";
    dfd = -1;
    WRAP_FATAL_START();
    WRAP_WRITE(spair[0], &msg, MASTER_MSG_LEN(msg.len)); 
    master_send(spair[1], event);
    WRAP_FATAL_END();
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    mark_point();
    errstr = "only -1 bytes written";
    rfd->fd = -1;
    options &= ~OPT_DEBUG;
    WRAP_WRITE(spair[0], &msg, MASTER_MSG_LEN(msg.len)); 
    master_send(spair[1], event);
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    options |= OPT_DEBUG;
    rfd = rfd_byindex(&rawfds, 1);
    master_close(rfd);
}
END_TEST

START_TEST(test_master_open_close) {
    struct rawfd *rfd;
    struct master_msg mreq;

    options |= OPT_DEBUG;

    mark_point();
    mreq.index = 1;
    strlcpy(mreq.name, "lo0", IFNAMSIZ);
    master_open(&mreq);
    rfd = rfd_byindex(&rawfds, 1);
    fail_unless (rfd != NULL,
    	"rfd should be added to the queue");
    master_close(rfd);
    fail_unless (rfd_byindex(&rawfds, 1) == NULL,
    	"rfd should be removed from the queue");

    mark_point();
    master_open(&mreq);
    rfd = rfd_byindex(&rawfds, 1);
    fail_unless (rfd != NULL,
    	"rfd should be added to the queue");

    mreq.index = 2;
    strlcpy(mreq.name, "lo1", IFNAMSIZ);
    master_open(&mreq);
    rfd = rfd_byindex(&rawfds, 2);
    fail_unless (rfd != NULL,
    	"rfd should be added to the queue");

    rfd_closeall(&rawfds);
    fail_unless (TAILQ_EMPTY(&rawfds),
    	"the queue should be empty");
}
END_TEST

START_TEST(test_master_socket) {
    struct master_msg mreq;
    struct rawfd *rfd;
    const char *errstr;

    mark_point();
    options |= OPT_DEBUG;
    mreq.index = 1;
    strlcpy(mreq.name, "lo0", IFNAMSIZ);

    master_open(&mreq);
    rfd = rfd_byindex(&rawfds, 1);
    fail_unless (rfd != NULL, "rfd should be added to the queue");

#ifdef HAVE_NET_BPF_H
    // create a sensible bpf buffer
    rfd->bpf_buf.len = roundup(ETHER_MAX_LEN, getpagesize());
    rfd->bpf_buf.data = my_malloc(rfd->bpf_buf.len);
#endif

    mark_point();
    options &= ~OPT_DEBUG;
    errstr = "failed to bind socket to";
    check_wrap_fake |= FAKE_SOCKET|FAKE_OPEN;
    check_wrap_fail |= FAIL_BIND|FAIL_IOCTL;
    WRAP_FATAL_START();
    master_socket(rfd);
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
    master_socket(rfd);
    WRAP_FATAL_END();
    check_wrap_fail &= ~FAIL_SETSOCKOPT;
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
#elif HAVE_NET_BPF_H
    errstr = "check";
    my_log(CRIT, errstr);
    WRAP_FATAL_START();
    master_socket(rfd);
    WRAP_FATAL_END();
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
#endif

#ifdef AF_PACKET
    mark_point();
    errstr = "check";
    my_log(CRIT, errstr);
    check_wrap_fake |= FAKE_SETSOCKOPT;
    master_socket(rfd);
    check_wrap_fake &= ~FAKE_SETSOCKOPT;
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
#elif defined AF_LINK
    mark_point();
    errstr = "check";
    my_log(CRIT, errstr);
    check_wrap_fake |= FAKE_IOCTL;
    master_socket(rfd);
    check_wrap_fake &= ~FAKE_IOCTL;
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
#endif

    // reset
    rfd = rfd_byindex(&rawfds, 1);
    master_close(rfd);
    check_wrap_fake = 0;
    check_wrap_fail = 0;
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
    options &= ~OPT_DEBUG;
    errstr = "unable to change LLDP multicast on";
    WRAP_FATAL_START();
    master_multi(&rfd, protos, 1);
    WRAP_FATAL_END();
    check_wrap_fake = 0;
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    mark_point();
    check_wrap_fake |= FAKE_IOCTL|FAKE_SETSOCKOPT;
    errstr = "check";
    my_log(CRIT, errstr);
    master_multi(&rfd, protos, 1);
    check_wrap_fake = 0;
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    // reset
    check_wrap_fake = 0;
}
END_TEST

START_TEST(test_master_recv) {
    struct master_msg mreq;
    struct rawfd *rfd;
    int spair[2];
    short event = 0;
    const char *errstr = NULL;
    char buf[ETHER_MAX_LEN * 2];
    char *msg;
    int hlen = 0;
#ifdef HAVE_NET_BPF_H
    struct bpf_hdr *bhp, *ebhp;
#endif /* HAVE_NET_BPF_H */
    struct ether_hdr ether;
    static uint8_t lldp_dst[] = CDP_MULTICAST_ADDR;


    options |= OPT_DEBUG;
    loglevel = INFO;

    mark_point();
    mreq.index = 1;
    strlcpy(mreq.name, "lo0", IFNAMSIZ);
    master_open(&mreq);
    rfd = rfd_byindex(&rawfds, 1);
    fail_unless (rfd != NULL, "rfd should be added to the queue");

#ifdef HAVE_NET_BPF_H
    // create a sensible bpf buffer
    rfd->bpf_buf.len = roundup(ETHER_MAX_LEN, getpagesize());
    rfd->bpf_buf.data = my_malloc(rfd->bpf_buf.len);
#endif /* HAVE_NET_BPF_H */

    // test a failing receive
    mark_point();
    errstr = "receiving message failed";
    rfd->fd = -1;
    WRAP_FATAL_START();
    master_recv(rfd->fd, event, rfd);
    WRAP_FATAL_END();
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    memset(&buf, 0, sizeof(buf));
#ifdef HAVE_NET_BPF_H
    bhp = (struct bpf_hdr *)buf;
    hlen = BPF_WORDALIGN(sizeof(struct bpf_hdr));
    bhp->bh_hdrlen = hlen;
    bhp->bh_caplen = ETHER_MIN_LEN - 1;
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
    rfd->fd = spair[1];

    // too short
    mark_point();
    errstr = "check";
    my_log(CRIT, errstr);
    WRAP_WRITE(spair[0], &buf, 1 + hlen);
    master_recv(rfd->fd, event, rfd);
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
#ifdef HAVE_NET_BPF_H
    bhp->bh_caplen = ETHER_MIN_LEN;
#endif /* HAVE_NET_BPF_H */

    // empty message
    mark_point();
    errstr = "unknown message type received";
    WRAP_WRITE(spair[0], &buf, ETHER_MIN_LEN + hlen);
    master_recv(rfd->fd, event, rfd);
    fail_unless (strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    // valid message
    mark_point();
    errstr = "received CDP message (64 bytes)";
    memcpy(ether.dst, lldp_dst, ETHER_ADDR_LEN);
    memcpy(msg, &ether, sizeof(struct ether_hdr));
    mark_point();
    WRAP_WRITE(spair[0], &buf, ETHER_MIN_LEN + hlen);
    master_recv(rfd->fd, event, rfd);
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    // too long (or multiple messages with bpf)
    mark_point();
    WRAP_WRITE(spair[0], &buf, sizeof(buf));
    master_recv(rfd->fd, event, rfd);

    // closed child socket
    mark_point();
    errstr = "failed to send message to child";
    WRAP_WRITE(spair[0], &buf, ETHER_MIN_LEN + hlen);
    close(spair[0]);
    WRAP_FATAL_START();
    master_recv(rfd->fd, event, rfd);
    WRAP_FATAL_END();
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    rfd = rfd_byindex(&rawfds, 1);
    master_close(rfd);
}
END_TEST

Suite * master_suite (void) {
    Suite *s = suite_create("master.c");

    TAILQ_INIT(&rawfds);

    // master test case
    TCase *tc_master = tcase_create("master");
    tcase_add_test(tc_master, test_master_signal);
    tcase_add_test(tc_master, test_master_req);
    tcase_add_test(tc_master, test_master_check);
    tcase_add_test(tc_master, test_master_send);
    tcase_add_test(tc_master, test_master_open_close);
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

