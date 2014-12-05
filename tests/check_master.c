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
#ifdef HAVE_PCI_PCI_H
#include <pci/pci.h>
#endif /* HAVE_PCI_PCI_H */

const char *ifname = NULL;
unsigned int ifindex = 0;

uint32_t options = OPT_DAEMON | OPT_CHECK;
extern int dfd;
extern int mfd;
extern struct rfdhead rawfds;

START_TEST(test_master_init) {
    const char *errstr = NULL;
    int spair[2], fd = -1;

    options |= OPT_DEBUG;

    // make sure stdout is not a tty
    fd = dup(STDOUT_FILENO);
    close(STDOUT_FILENO);
    my_socketpair(spair);

    errstr = "test";
    my_log(CRIT, errstr);
    WRAP_FATAL_START();
    master_init(0, 0, 0);
    WRAP_FATAL_END();
    fail_unless (strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    close(spair[0]);
    close(spair[1]);
    fd = dup(fd);
    options &= ~OPT_DEBUG;
}
END_TEST

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
    master_signal(sig, event, &pid);
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
    struct master_req mreq = {};
    struct ether_hdr ether = {};
    static uint8_t lldp_dst[] = LLDP_MULTICAST_ADDR;
    struct rawfd *rfd;
    const char *errstr = NULL;
    int spair[2], fd = -1;
    short event = 0;

    loglevel = INFO;
    my_socketpair(spair);

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

    // test a message with incorrect ifindex
    mark_point();
    mreq.op = MASTER_MAX - 1;
    mreq.len = ETHER_MIN_LEN;

    errstr = "check";
    my_log(CRIT, errstr);
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
    mreq.index = ifindex;
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
    fail_unless (rfd_byindex(&rawfds, ifindex) == NULL,
    	"the queue should be empty");

    options |= OPT_DEBUG;
    master_open(ifindex, ifname);
    fail_unless (rfd_byindex(&rawfds, ifindex) != NULL,
    	"rfd should be added to the queue");

    errstr = "check";
    my_log(CRIT, errstr);
    mreq.op = MASTER_CLOSE;
    mreq.index = ifindex;
    strlcpy(mreq.name, ifname, IFNAMSIZ);
    WRAP_WRITE(spair[0], &mreq, MASTER_REQ_LEN(mreq.len));
    master_req(spair[1], event);
    fail_unless (strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    fail_unless (rfd_byindex(&rawfds, ifindex) == NULL,
    	"rfd should be removed from the queue");
 
#if defined(SIOCSIFDESCR) || defined(HAVE_SYSFS)
    // test a correct DESCR
    mark_point();
    mreq.op = MASTER_DESCR;
    mreq.len = 1;

    WRAP_WRITE(spair[0], &mreq, MASTER_REQ_LEN(mreq.len));

    errstr = "check";
    my_log(CRIT, errstr);
    master_req(spair[1], event);
    fail_unless (strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
#endif

#ifdef HAVE_SYSFS
    mark_point();
    mreq.op = MASTER_ALIAS;
    mreq.len = 1;

    WRAP_WRITE(spair[0], &mreq, MASTER_REQ_LEN(mreq.len));

    errstr = "check";
    my_log(CRIT, errstr);
    master_req(spair[1], event);
    fail_unless (strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

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
    master_open(ifindex, ifname);
    rfd = rfd_byindex(&rawfds, ifindex);
    fail_unless (rfd != NULL, "rfd should be added to the queue");
    mreq.op = MASTER_CLOSE;
    close(rfd->fd);
    rfd->fd = dup(spair[1]);
    WRAP_WRITE(spair[0], &mreq, MASTER_REQ_LEN(mreq.len));
    close(spair[0]);

    errstr = "failed to return request to child";
    WRAP_FATAL_START();
    master_req(spair[1], event);
    WRAP_FATAL_END();
    fail_unless (strcmp(check_wrap_errstr, errstr) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    fail_unless (close(fd) == -1, "rfd->fd should be closed");
    fail_unless (rfd_byindex(&rawfds, ifindex) == NULL,
    	"rfd should be removed from the queue");

    close(spair[1]);
}
END_TEST

START_TEST(test_master_check) {
    struct master_req mreq = {};

    mark_point();
    mreq.op = MASTER_OPEN;
    fail_unless(master_check(&mreq) == EXIT_SUCCESS,
	"MASTER_OPEN check failed");

    mark_point();
    mreq.op = MASTER_CLOSE;
    fail_unless(master_check(&mreq) == EXIT_SUCCESS,
	"MASTER_CLOSE check failed");

#ifdef HAVE_LINUX_ETHTOOL_H
    mark_point();
    mreq.op = MASTER_ETHTOOL_GSET;
    mreq.index = ifindex;
    mreq.len = sizeof(struct ethtool_cmd);
    fail_unless(master_check(&mreq) == EXIT_SUCCESS,
	"MASTER_ETHTOOL_GSET check failed");

    mark_point();
    mreq.op = MASTER_ETHTOOL_GDRV;
    mreq.index = ifindex;
    mreq.len = sizeof(struct ethtool_drvinfo);
    fail_unless(master_check(&mreq) == EXIT_SUCCESS,
	"MASTER_ETHTOOL_GDRV check failed");
#endif

#ifdef SIOCSIFDESCR
    mark_point();
    mreq.op = MASTER_DESCR;
    mreq.index = ifindex;
    mreq.len = 0;
    fail_unless(master_check(&mreq) == EXIT_SUCCESS,
	"MASTER_DESCR check failed");
#endif

#ifndef HAVE_LINUX_ETHTOOL_H
    mark_point();
    mreq.op = MASTER_ETHTOOL_GSET;
    fail_unless(master_check(&mreq) == EXIT_FAILURE,
	"master_check should fail");
#endif
}
END_TEST

START_TEST(test_master_send) {
    struct rawfd *rfd;
    struct master_msg msg = {};
    struct ether_hdr ether = {};
    static uint8_t lldp_dst[] = LLDP_MULTICAST_ADDR;
    int spair[2];
    const char *errstr;
    short event = 0;

    loglevel = INFO;
    options |= OPT_DEBUG;
    my_socketpair(spair);
    msg.index = ifindex;
    msg.len = ETHER_MIN_LEN;
    strlcpy(msg.name, ifname, IFNAMSIZ);

    dfd = spair[1];
    master_open(ifindex, ifname);
    rfd = rfd_byindex(&rawfds, ifindex);
    fail_unless (rfd != NULL, "rfd should be added to the queue");

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

    // incorrect msend msg.index should fail
    mark_point();
    errstr = "invalid ifindex supplied";
    msg.index = UINT32_MAX;
    WRAP_WRITE(spair[0], &msg, MASTER_MSG_LEN(msg.len));
    WRAP_FATAL_START();
    master_send(spair[1], event);
    WRAP_FATAL_END();
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    mark_point();
    msg.index = ifindex;
    msg.proto = PROTO_LLDP;
    memcpy(ether.dst, lldp_dst, ETHER_ADDR_LEN);
    ether.type = htons(ETHERTYPE_LLDP);
    memcpy(msg.msg, &ether, sizeof(ether));
    errstr = "only -1 bytes written";
    close(rfd->fd);
    rfd->fd = -1;
    options &= ~OPT_DEBUG;
    WRAP_WRITE(spair[0], &msg, MASTER_MSG_LEN(msg.len));
    master_send(spair[1], event);
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    options |= OPT_DEBUG;

    close(spair[0]);
    close(spair[1]);
    rfd_closeall(&rawfds);
}
END_TEST

START_TEST(test_master_open_close) {
    struct rawfd *rfd;

    options |= OPT_DEBUG;
    dfd = STDOUT_FILENO;

    mark_point();
    master_open(ifindex, ifname);
    rfd = rfd_byindex(&rawfds, ifindex);
    fail_unless (rfd != NULL,
    	"rfd should be added to the queue");
    master_close(rfd);
    fail_unless (rfd_byindex(&rawfds, ifindex) == NULL,
    	"rfd should be removed from the queue");

    mark_point();
    master_open(ifindex, ifname);
    rfd = rfd_byindex(&rawfds, ifindex);
    fail_unless (rfd != NULL,
    	"rfd should be added to the queue");

    master_open(2, "lo1");
    rfd = rfd_byindex(&rawfds, 2);
    fail_unless (rfd != NULL,
    	"rfd should be added to the queue");

    rfd_closeall(&rawfds);
    fail_unless (TAILQ_EMPTY(&rawfds),
    	"the queue should be empty");
}
END_TEST

START_TEST(test_master_socket) {
    struct rawfd *rfd;
    const char *errstr;

    options |= OPT_DEBUG;
    dfd = STDOUT_FILENO;

    mark_point();
    master_open(ifindex, ifname);
    rfd = rfd_byindex(&rawfds, ifindex);
    fail_unless (rfd != NULL, "rfd should be added to the queue");

    mark_point();
    // only run this as a regular user
    if (!geteuid())
	return;

    options &= ~OPT_DEBUG;
    errstr = "pcap_activate";
    WRAP_FATAL_START();
    master_socket(rfd);
    WRAP_FATAL_END();
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    rfd = rfd_byindex(&rawfds, ifindex);
    fail_unless (rfd != NULL,
    	"rfd not found");
    master_close(rfd);
    fail_unless (TAILQ_EMPTY(&rawfds),
    	"the queue should be empty");
}
END_TEST

START_TEST(test_master_multi) {
    struct rawfd rfd;
    int spair[2];
    const char *errstr;

    my_socketpair(spair);
    rfd.fd = spair[1];
    rfd.index = ifindex;
    strlcpy(rfd.name, ifname, IFNAMSIZ);

    check_wrap_fake = 0;
    protos[PROTO_LLDP].enabled = 1;

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
    close(spair[0]);
    close(spair[1]);
}
END_TEST

START_TEST(test_master_recv) {
    struct rawfd *rfd;
    short event = 0;
    const char *errstr = NULL;
    char *prefix, *suffix, *path = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    int spair[2];

    my_socketpair(spair);

    options |= OPT_DEBUG;
    loglevel = INFO;
    dfd = STDOUT_FILENO;

    mark_point();
    master_open(ifindex, ifname);
    rfd = rfd_byindex(&rawfds, ifindex);
    fail_unless (rfd != NULL, "rfd should be added to the queue");

    if ((prefix = getenv("srcdir")) == NULL)
        prefix = ".";

    mark_point();
    suffix = "proto/broken/00.unknown";
    fail_if(asprintf(&path, "%s/%s.pcap", prefix, suffix) == -1,
            "asprintf failed");
    fail_if((rfd->p_handle = pcap_open_offline(path, errbuf)) == NULL,
        "failed to open %s: %s", path, errbuf);

    errstr = "unknown message type received";
    my_log(CRIT, "test");
    WRAP_FATAL_START();
    master_recv(rfd->fd, event, rfd);
    WRAP_FATAL_END();
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    pcap_close(rfd->p_handle);
    rfd->p_handle = NULL;
    free(path);

    mark_point();
    suffix = "proto/broken/01.empty";
    fail_if(asprintf(&path, "%s/%s.pcap", prefix, suffix) == -1,
            "asprintf failed");
    fail_if((rfd->p_handle = pcap_open_offline(path, errbuf)) == NULL,
        "failed to open %s: %s", path, errbuf);

    errstr = "test";
    my_log(CRIT, errstr);
    WRAP_FATAL_START();
    master_recv(rfd->fd, event, rfd);
    WRAP_FATAL_END();
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    pcap_close(rfd->p_handle);
    rfd->p_handle = NULL;
    free(path);

    mark_point();
    suffix = "proto/cdp/43.good.big";
    fail_if(asprintf(&path, "%s/%s.pcap", prefix, suffix) == -1,
            "asprintf failed");
    fail_if((rfd->p_handle = pcap_open_offline(path, errbuf)) == NULL,
        "failed to open %s: %s", path, errbuf);

    // closed child socket
    mark_point();
    errstr = "failed to send message to child";
    my_log(CRIT, "test");
    WRAP_FATAL_START();
    master_recv(rfd->fd, event, rfd);
    WRAP_FATAL_END();
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    pcap_close(rfd->p_handle);
    rfd->p_handle = NULL;

    // working
    mark_point();
    mfd = spair[0];

    fail_if((rfd->p_handle = pcap_open_offline(path, errbuf)) == NULL,
        "failed to open %s: %s", path, errbuf);

    errstr = "received CDP message (422 bytes)";
    my_log(CRIT, "test");
    WRAP_FATAL_START();
    master_recv(rfd->fd, event, rfd);
    WRAP_FATAL_END();
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    pcap_close(rfd->p_handle);
    rfd->p_handle = NULL;
    free(path);

    mark_point();
    rfd_closeall(&rawfds);
    close(spair[0]);
    close(spair[1]);
}
END_TEST

Suite * master_suite (void) {
    Suite *s = suite_create("master.c");

    TAILQ_INIT(&rawfds);

    // master test case
    TCase *tc_master = tcase_create("master");
    tcase_add_test(tc_master, test_master_init);
    tcase_add_test(tc_master, test_master_signal);
    tcase_add_test(tc_master, test_master_req);
    tcase_add_test(tc_master, test_master_check);
    tcase_add_test(tc_master, test_master_send);
    tcase_add_test(tc_master, test_master_open_close);
    tcase_add_test(tc_master, test_master_socket);
    tcase_add_test(tc_master, test_master_multi);
    tcase_add_test(tc_master, test_master_recv);
    suite_add_tcase(s, tc_master);

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
    Suite *s = master_suite ();
    SRunner *sr = srunner_create (s);
    srunner_run_all (sr, CK_NORMAL);
    number_failed = srunner_ntests_failed (sr);
    srunner_free (sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

