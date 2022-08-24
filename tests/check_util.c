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
#include <pcap.h>

#include "common.h"
#include "util.h"
#include "proto/protos.h"
#include "main.h"
#include "check_wrap.h"

uint32_t options = OPT_DAEMON | OPT_CHECK;

START_TEST(test_my) {
    char *ptr = NULL;
    int s = -1, spair[2];
    const char *errstr = NULL;
    char buf[1024], *bp = NULL;
    ssize_t len = 0;
    size_t left;

    mark_point();
    loglevel = INFO;
    errstr = "empty";
    my_log(CRIT, errstr);
    my_log(DEBUG, "0123456789");
    ck_assert_msg (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    mark_point();
    loglevel = DEBUG;
    errstr = "0123456789";
    my_log(INFO, errstr);
    ck_assert_msg (strcmp(check_wrap_errstr, errstr) == 0, "message not logged");

    mark_point();
    s = dup(STDERR_FILENO);
    close(STDERR_FILENO);
    my_socketpair(spair);
    my_nonblock(spair[1]);
    options &= ~OPT_DAEMON;
    errstr = "test_my: debug\n";
    memset(buf, 0, 1024);
    my_log(INFO, "debug");
    fflush(stderr);

    bp = buf;
    left = 1024;
    while (left > 0) {
	len = read(spair[1], bp, left);
	if (len <= 0)
	    break;
	left -= len;
	bp += len;
    }
    ck_assert_msg(strcmp(buf, errstr) == 0, "invalid output: %s", buf);
    options |= OPT_DAEMON;
    close(spair[0]);
    ck_assert_msg(dup(s) == STDERR_FILENO, "dup should re-create stderr");
    close(s);
    close(spair[1]);

    mark_point();
    WRAP_FATAL_START();
    my_fatal("error");
    WRAP_FATAL_END();
    ck_assert_msg (strcmp(check_wrap_errstr, "error") == 0,
	"error not logged");

    mark_point();
    ptr = my_malloc(100);
    ck_assert_msg (ptr != NULL, "a valid pointer should be returned");
    free(ptr);
    ptr = NULL;

    mark_point();
    ptr = my_calloc(10, 10);
    ck_assert_msg (ptr != NULL, "a valid pointer should be returned");
    free(ptr);
    ptr = NULL;

    check_wrap_fail |= FAIL_CALLOC;
    WRAP_FATAL_START();
    ptr = my_calloc(10, 10);
    WRAP_FATAL_END();
    check_wrap_fail &= ~FAIL_CALLOC;
    ck_assert_msg (strcmp(check_wrap_errstr, "calloc failed") == 0,
	"error not logged");

    mark_point();
    ptr = my_strdup("foo");
    ck_assert_msg (ptr != NULL, "a valid pointer should be returned");
    free(ptr);
    ptr = NULL;

    check_wrap_fail |= FAIL_STRDUP;
    WRAP_FATAL_START();
    ptr = my_strdup("bar");
    WRAP_FATAL_END();
    check_wrap_fail &= ~FAIL_STRDUP;
    ck_assert_msg (strcmp(check_wrap_errstr, "strdup failed") == 0,
	"error not logged");

    // skip the socket tests if there is no networking
    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	return;
    close(s);

    mark_point();
    s = my_socket(AF_INET, SOCK_DGRAM, 0);
    ck_assert_msg (s != -1, "a valid socket should be returned");
    close(s);
    s = 0;

    errstr = "opening socket failed";
    WRAP_FATAL_START();
    s = my_socket(AF_MAX, 0, 0);
    WRAP_FATAL_END();
    ck_assert_msg (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
}
END_TEST

START_TEST(test_my_mreq) {
    struct parent_req mreq = {};
    int spair[2];
    extern int msock;
    size_t ret;
    const char *errstr = NULL;

    loglevel = INFO;
    my_socketpair(spair);

    mark_point();
    msock = -1;
    errstr = "only -1 bytes written";
    WRAP_FATAL_START();
    my_mreq(&mreq);
    WRAP_FATAL_END();
    ck_assert_msg (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    mark_point();
    msock = spair[1];
    errstr = "check";
    my_log(CRIT, errstr);
    mreq.len = ETHER_MIN_LEN; 
    WRAP_WRITE(spair[0], &mreq, PARENT_REQ_LEN(mreq.len));
    ret = my_mreq(&mreq);
    ck_assert_msg (ret == ETHER_MIN_LEN,
	"incorrect size %lu returned from my_mreq", ret);

    mark_point();
    errstr = "invalid reply received from parent";
    WRAP_WRITE(spair[0], &mreq, ETHER_MIN_LEN);
    WRAP_FATAL_START();
    my_mreq(&mreq);
    WRAP_FATAL_END();
    ck_assert_msg (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    close(spair[0]);
    close(spair[1]);
}
END_TEST

START_TEST(test_netif) {
    struct nhead nqueue;
    struct nhead *netifs = &nqueue;
    struct netif tnetifs[6];
    struct netif *netif = NULL, *subif = NULL;
    struct mhead mqueue;
    struct parent_msg *msg = NULL, *nmsg = NULL;
    struct parent_req *mreq = NULL;
    char *descr = NULL;
    int spair[2];
    ssize_t len;
    extern int msock;

    TAILQ_INIT(&nqueue);
    TAILQ_INIT(&mqueue);
    my_socketpair(spair);

    tnetifs[0].index = 0;
    tnetifs[0].argv = 0;
    tnetifs[0].child = 0;
    tnetifs[0].type = NETIF_BONDING;
    tnetifs[0].subif = &tnetifs[1];
    strlcpy(tnetifs[0].name, "bond0", IFNAMSIZ); 
    strlcpy(tnetifs[0].description, "bond0", IFDESCRSIZE); 

    tnetifs[1].index = 1;
    tnetifs[1].argv = 1;
    tnetifs[1].child = 1;
    tnetifs[1].type = NETIF_REGULAR;
    tnetifs[1].subif = &tnetifs[2];
    strlcpy(tnetifs[1].name, "eth0", IFNAMSIZ); 
    strlcpy(tnetifs[1].description, "eth0", IFDESCRSIZE); 

    tnetifs[2].index = 2;
    tnetifs[2].argv = 0;
    tnetifs[2].child = 1;
    tnetifs[2].type = NETIF_REGULAR;
    tnetifs[2].subif = NULL,
    strlcpy(tnetifs[2].name, "eth2", IFNAMSIZ); 
    strlcpy(tnetifs[2].description, "eth2", IFDESCRSIZE); 

    tnetifs[3].index = 4;
    tnetifs[3].argv = 0;
    tnetifs[3].child = 0;
    tnetifs[3].type = NETIF_BRIDGE;
    tnetifs[3].subif = NULL,
    strlcpy(tnetifs[3].name, "bridge0", IFNAMSIZ); 

    tnetifs[4].index = 5;
    tnetifs[4].argv = 1;
    tnetifs[4].child = 0;
    tnetifs[4].type = NETIF_BONDING;
    tnetifs[4].subif = NULL,
    strlcpy(tnetifs[4].name, "lagg0", IFNAMSIZ); 
    strlcpy(tnetifs[4].description, "lagg0", IFDESCRSIZE); 

    tnetifs[5].index = 3;
    tnetifs[5].argv = 1;
    tnetifs[5].child = 0;
    tnetifs[5].type = NETIF_REGULAR;
    tnetifs[5].subif = NULL,
    strlcpy(tnetifs[5].name, "eth1", IFNAMSIZ); 
    strlcpy(tnetifs[5].description, "eth1", IFDESCRSIZE); 

    TAILQ_INSERT_TAIL(netifs, &tnetifs[0], entries);
    TAILQ_INSERT_TAIL(netifs, &tnetifs[1], entries);
    TAILQ_INSERT_TAIL(netifs, &tnetifs[2], entries);
    TAILQ_INSERT_TAIL(netifs, &tnetifs[3], entries);
    TAILQ_INSERT_TAIL(netifs, &tnetifs[4], entries);
    TAILQ_INSERT_TAIL(netifs, &tnetifs[5], entries);

    // netif_iter checks
    mark_point();
    netif = NULL;
    ck_assert_msg (netif_iter(netif, NULL) == NULL,
	"NULL should be returned on invalid netifs");

    netif = NULL;
    netif = netif_iter(netif, netifs);
    ck_assert_msg (netif == &tnetifs[0], "the first netif should be returned");
    netif = netif_iter(netif, netifs);
    ck_assert_msg (netif == &tnetifs[5], "the sixth netif should be returned");
    netif = netif_iter(netif, netifs);
    ck_assert_msg (netif == NULL, "NULL should be returned");

    netif = NULL;
    options |= OPT_ARGV;
    netif = netif_iter(netif, netifs);
    ck_assert_msg (netif == &tnetifs[1], "the second netif should be returned");
    netif = netif_iter(netif, netifs);
    ck_assert_msg (netif == &tnetifs[5], "the sixth netif should be returned");
    netif = netif_iter(netif, netifs);
    ck_assert_msg (netif == NULL, "NULL should be returned");


    // subif_iter checks
    mark_point();
    netif = &tnetifs[0];
    subif = NULL;
    subif = subif_iter(subif, subif);
    ck_assert_msg (subif == NULL, "NULL should be returned");
    subif = subif_iter(subif, netif);
    ck_assert_msg (subif == &tnetifs[1], "the second netif should be returned");
    subif = subif_iter(subif, netif);
    ck_assert_msg (subif == &tnetifs[2], "the third netif should be returned");
    subif = subif_iter(subif, netif);
    ck_assert_msg (subif == NULL, "NULL should be returned");

    netif = &tnetifs[3];
    subif = NULL;
    subif = subif_iter(subif, netif);
    ck_assert_msg (subif == NULL, "NULL should be returned");

    netif = &tnetifs[4];
    subif = NULL;
    subif = subif_iter(subif, netif);
    ck_assert_msg (subif == NULL, "NULL should be returned");

    netif = &tnetifs[5];
    subif = NULL;
    subif = subif_iter(subif, netif);
    ck_assert_msg (subif == &tnetifs[5], "the sixth netif should be returned");
    subif = subif_iter(subif, netif);
    ck_assert_msg (subif == NULL, "NULL should be returned");


    // netif_byindex checks
    mark_point();
    ck_assert_msg (netif_byindex(netifs, 0) == &tnetifs[0],
	"incorrect netif struct returned");
    ck_assert_msg (netif_byindex(netifs, 1) == &tnetifs[1],
	"incorrect netif struct returned");
    ck_assert_msg (netif_byindex(netifs, 2) == &tnetifs[2],
	"incorrect netif struct returned");
    ck_assert_msg (netif_byindex(netifs, 3) == &tnetifs[5],
	"incorrect netif struct returned");
    ck_assert_msg (netif_byindex(netifs, 6) == NULL,
	"NULL should be returned on not found netif");


    // netif_byname checks
    mark_point();
    ck_assert_msg (netif_byname(netifs, "bond0") == &tnetifs[0],
	"incorrect netif struct returned");
    ck_assert_msg (netif_byname(netifs, "eth0") == &tnetifs[1],
	"incorrect netif struct returned");
    ck_assert_msg (netif_byname(netifs, "eth2") == &tnetifs[2],
	"incorrect netif struct returned");
    ck_assert_msg (netif_byname(netifs, "eth1") == &tnetifs[5],
	"incorrect netif struct returned");
    ck_assert_msg (netif_byname(netifs, "eth3") == NULL,
	"NULL should be returned on not found netif");

    // XXX: netif_byaddr checks

    msg = my_malloc(PARENT_MSG_SIZ);
    netif = netif_byname(netifs, "eth0");
    msg->index = netif->index;
    msg->proto = PROTO_LLDP;
    memcpy(msg->msg + ETHER_ADDR_LEN, "\x02\x00\x01", 3);
    msg->peer[PEER_HOSTNAME] = my_strdup("foo");
    msg->peer[PEER_PORTNAME] = my_strdup("FastEthernet6/20");
    TAILQ_INSERT_TAIL(&mqueue, msg, entries);

    msg = my_malloc(PARENT_MSG_SIZ);
    netif = netif_byname(netifs, "eth2");
    msg->index = netif->index;
    msg->proto = PROTO_CDP;
    memcpy(msg->msg + ETHER_ADDR_LEN, "\x02\x00\x02", 3);
    msg->peer[PEER_HOSTNAME] = my_strdup("bar");
    TAILQ_INSERT_TAIL(&mqueue, msg, entries);

    msg = my_malloc(PARENT_MSG_SIZ);
    netif = netif_byname(netifs, "eth1");
    msg->index = netif->index;
    msg->proto = PROTO_LLDP;
    memcpy(msg->msg + ETHER_ADDR_LEN, "\x02\x00\x03", 3);
    msg->peer[PEER_HOSTNAME] = my_strdup("baz");
    msg->peer[PEER_PORTNAME] = my_strdup("Ethernet4");
    TAILQ_INSERT_TAIL(&mqueue, msg, entries);

    msg = my_malloc(PARENT_MSG_SIZ);
    netif = netif_byname(netifs, "eth1");
    msg->index = netif->index;
    msg->proto = PROTO_LLDP;
    memcpy(msg->msg + ETHER_ADDR_LEN, "\x02\x00\x04", 3);
    msg->peer[PEER_HOSTNAME] = my_strdup("quux");
    msg->peer[PEER_PORTNAME] = my_strdup("Ethernet5");
    TAILQ_INSERT_TAIL(&mqueue, msg, entries);

    msg = my_malloc(PARENT_MSG_SIZ);
    netif = netif_byname(netifs, "eth1");
    msg->index = netif->index;
    msg->proto = PROTO_FDP;
    memcpy(msg->msg + ETHER_ADDR_LEN, "\x02\x00\x04", 3);
    msg->peer[PEER_HOSTNAME] = my_strdup("quux");
    msg->peer[PEER_PORTNAME] = my_strdup("Ethernet5");
    TAILQ_INSERT_TAIL(&mqueue, msg, entries);

    msg = my_malloc(PARENT_MSG_SIZ);
    netif = netif_byname(netifs, "lagg0");
    msg->index = netif->index;
    msg->proto = PROTO_LLDP;
    memcpy(msg->msg + ETHER_ADDR_LEN, "\x02\x00\x05", 3);
    TAILQ_INSERT_TAIL(&mqueue, msg, entries);

    // netif_protos checks
    mark_point();
    netif = netif_byname(netifs, "bond0");
    netif_protos(netif, &mqueue);
    ck_assert_msg (netif->protos == ((1 << PROTO_LLDP)|(1 << PROTO_CDP)),
	"incorrect protos calculation");

    netif = netif_byname(netifs, "eth1");
    netif_protos(netif, &mqueue);
    ck_assert_msg (netif->protos == ((1 << PROTO_LLDP)|(1 << PROTO_FDP)),
	"incorrect protos calculation");

    netif = netif_byname(netifs, "lagg0");
    netif_protos(netif, &mqueue);
    ck_assert_msg (netif->protos == 0, "incorrect protos calculation");

    // netif_descr checks
    mark_point();
    msock = spair[1];
    mreq = my_malloc(PARENT_REQ_MAX);
    mreq->len = IFDESCRSIZE;

    netif = netif_byname(netifs, "bond0");
    descr = "";
    WRAP_WRITE(spair[0], mreq, PARENT_REQ_LEN(mreq->len));
    netif_descr(netif, &mqueue);
    WRAP_REQ_READ(spair[0], mreq, len);
    ck_assert_msg (mreq->op == PARENT_DESCR,
	"incorrect command: %d", mreq->op);
    ck_assert_msg (mreq->index == netif->index,
	"incorrect interface index: %d", mreq->index);
    ck_assert_msg (mreq->len == strlen(descr) + 1,
	"incorrect message length: %ld", mreq->len);
    ck_assert_msg (strncmp(mreq->buf, descr, IFDESCRSIZE) == 0,
	"incorrect interface description: %s", mreq->buf);

    netif = netif_byname(netifs, "eth0");
    descr = "connected to foo (Fa6/20)";
    WRAP_WRITE(spair[0], mreq, PARENT_REQ_LEN(mreq->len));
    netif_descr(netif, &mqueue);
    WRAP_REQ_READ(spair[0], mreq, len);
    ck_assert_msg (mreq->op == PARENT_DESCR,
	"incorrect command: %d", mreq->op);
    ck_assert_msg (mreq->index == netif->index,
	"incorrect interface index: %d", mreq->index);
    ck_assert_msg (mreq->len == strlen(descr) + 1,
	"incorrect message length: %ld", mreq->len);
    ck_assert_msg (strncmp(mreq->buf, descr, IFDESCRSIZE) == 0,
	"incorrect interface description: %s", mreq->buf);

    netif = netif_byname(netifs, "eth2");
    descr = "connected to bar";
    WRAP_WRITE(spair[0], mreq, PARENT_REQ_LEN(mreq->len));
    netif_descr(netif, &mqueue);
    WRAP_REQ_READ(spair[0], mreq, len);
    ck_assert_msg (mreq->op == PARENT_DESCR,
	"incorrect command: %d", mreq->op);
    ck_assert_msg (mreq->index == netif->index,
	"incorrect interface index: %d", mreq->index);
    ck_assert_msg (mreq->len == strlen(descr) + 1,
	"incorrect message length: %ld", mreq->len);
    ck_assert_msg (strncmp(mreq->buf, descr, IFDESCRSIZE) == 0,
	"incorrect interface description: %s", mreq->buf);

    netif = netif_byname(netifs, "eth1");
    descr = "connected to 2 peers";
    WRAP_WRITE(spair[0], mreq, PARENT_REQ_LEN(mreq->len));
    netif_descr(netif, &mqueue);
    WRAP_REQ_READ(spair[0], mreq, len);
    ck_assert_msg (mreq->op == PARENT_DESCR,
	"incorrect command: %d", mreq->op);
    ck_assert_msg (mreq->index == netif->index,
	"incorrect interface index: %d", mreq->index);
    ck_assert_msg (mreq->len == strlen(descr) + 1,
	"incorrect message length: %ld", mreq->len);
    ck_assert_msg (strncmp(mreq->buf, descr, IFDESCRSIZE) == 0,
	"incorrect interface description: %s", mreq->buf);

    netif = netif_byname(netifs, "lagg0");
    descr = "";
    WRAP_WRITE(spair[0], mreq, PARENT_REQ_LEN(mreq->len));
    netif_descr(netif, &mqueue);
    WRAP_REQ_READ(spair[0], mreq, len);
    ck_assert_msg (mreq->op == PARENT_DESCR,
	"incorrect command: %d", mreq->op);
    ck_assert_msg (mreq->index == netif->index,
	"incorrect interface index: %d", mreq->index);
    ck_assert_msg (mreq->len == strlen(descr) + 1,
	"incorrect message length: %ld", mreq->len);
    ck_assert_msg (strncmp(mreq->buf, descr, IFDESCRSIZE) == 0,
	"incorrect interface description: %s", mreq->buf);

    free(mreq);
    TAILQ_FOREACH_SAFE(msg, &mqueue, entries, nmsg) {
	TAILQ_REMOVE(&mqueue, msg, entries);
	peer_free(msg->peer);
	free(msg);
    }
    TAILQ_FOREACH_SAFE(netif, &nqueue, entries, subif) {
	TAILQ_REMOVE(&nqueue, netif, entries);
    }

    close(spair[0]);
    close(spair[1]);
}
END_TEST

START_TEST(test_read_line) {
    char line[128];
    const char *data = "0123456789ABCDEF";
    const char *null =  _PATH_DEVNULL;
    const char *file = "testfile";
    char *prefix, *path = NULL;

    if ((prefix = getenv("srcdir")) == NULL)
	prefix = ".";

    ck_assert_msg(asprintf(&path, "%s/%s", prefix, file) != -1, "asprintf failed");

    ck_assert_msg (read_line("non-existant", line, 0) == 0,
	"0 should be returned on a missing file");

    ck_assert_msg (read_line(null, line, 10) == 0,
	"0 should be returned on a unreadable file");

    ck_assert_msg (read_line(path, line, 0) == 0,
	"0 should be returned on zero len request");

    ck_assert_msg (read_line(path, line, 1) == 0,
	"0 bytes should be returned");

    ck_assert_msg (read_line(path, line, 2) == 1,
	"1 bytes should be returned");

    ck_assert_msg (read_line(path, line, 10) == 9,
	"9 bytes should be returned");

    ck_assert_msg (read_line(path, line, 17) == 16,
	"16 bytes should be returned");

    ck_assert_msg (strncmp(line, data, strlen(data)) == 0,
	"invalid line returned");

    ck_assert_msg (read_line(path, line, 18) == 16,
	"16 bytes should be returned");

    ck_assert_msg (strncmp(line, data, strlen(data)) == 0,
	"invalid line returned");

    free(path);
}
END_TEST

START_TEST(test_my_cksum) {
    const char *data = "0123456789ABCDEF";
    uint16_t sum;
    uint8_t cisco;

    cisco = 0;
    sum = ntohs(my_chksum(data, strlen(data), cisco));
    ck_assert_msg(sum == 12585,
	"IP checksum result should be 12585 not %d", sum);

    cisco = 1;
    sum = ntohs(my_chksum(data, strlen(data), cisco));
    ck_assert_msg(sum == 12585,
	"(Cisco) IP checksum result should be 12585 not %d", sum);

    cisco = 0;
    sum = ntohs(my_chksum(data, strlen(data) - 1, cisco));
    ck_assert_msg(sum == 12655,
	"IP checksum result should be 12655 not %d", sum);

    cisco = 1;
    sum = ntohs(my_chksum(data, strlen(data) - 1, cisco));
    ck_assert_msg(sum ==  30250,
	"(Cisco) IP checksum result should be 30250 not %d", sum);
}
END_TEST

START_TEST(test_my_priv) {
    struct passwd *pwd = NULL;
    struct stat sb;
    const char *errstr = NULL;
    char path[PATH_MAX + 1] = {};

    loglevel = INFO;
    errno = EPERM;

    if ((pwd = getpwnam("root")) == NULL)
	return;
    if (stat(_PATH_DEVNULL, &sb) != 0)
	return;

    mark_point();
    errstr = "unable to setgroups";
    check_wrap_fail |= FAIL_SETGRP;
    WRAP_FATAL_START();
    my_drop_privs(pwd);
    WRAP_FATAL_END();
    check_wrap_fail &= ~FAIL_SETGRP;
    ck_assert_msg (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    mark_point();
#ifdef HAVE_SETRESGID
    errstr = "unable to setresgid";
#elif defined(HAVE_SETREGID)
    errstr = "unable to setregid";
#endif
    check_wrap_fail |= FAIL_SETRESGID;
    check_wrap_fake |= FAKE_SETGRP;
    WRAP_FATAL_START();
    my_drop_privs(pwd);
    WRAP_FATAL_END();
    check_wrap_fail &= ~FAIL_SETRESGID;
    ck_assert_msg (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    mark_point();
#ifdef HAVE_SETRESUID
    errstr = "unable to setresuid";
#elif defined(HAVE_SETREUID)
    errstr = "unable to setreuid";
#endif
    check_wrap_fail |= FAIL_SETRESUID;
    check_wrap_fake |= FAKE_SETRESGID;
    WRAP_FATAL_START();
    my_drop_privs(pwd);
    WRAP_FATAL_END();
    check_wrap_fail &= ~FAIL_SETRESUID;
    ck_assert_msg (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    mark_point();
    errno = 0;
    errstr = "check";
    my_log(CRIT, errstr);
    check_wrap_fake |= FAKE_SETRESUID;
    WRAP_FATAL_START();
    my_drop_privs(pwd);
    WRAP_FATAL_END();
    check_wrap_fail = 0;
    check_wrap_fake = 0;
    ck_assert_msg (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    mark_point();
    errstr = "chroot path does not begin at root";
    memset(path, 'a', PATH_MAX);
    WRAP_FATAL_START();
    my_chroot(path);
    WRAP_FATAL_END();
    ck_assert_msg (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    mark_point();
    errstr = "chroot path too long";
    path[0] = '/';
    WRAP_FATAL_START();
    my_chroot(path);
    WRAP_FATAL_END();
    ck_assert_msg (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    mark_point();
    errstr = "stat(\"/inexistant\"): ";
    WRAP_FATAL_START();
    my_chroot("/inexistant");
    WRAP_FATAL_END();
    ck_assert_msg (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    mark_point();
    errstr = "bad ownership or modes for chroot";
    WRAP_FATAL_START();
    my_chroot(_PATH_DEVNULL);
    WRAP_FATAL_END();
    ck_assert_msg (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    mark_point();
    if (stat(_PATH_DEV, &sb) != 0)
	return;
    if (sb.st_uid != 0 || (sb.st_mode & 022) != 0)
	return;
    if (stat(_PATH_CONSOLE, &sb) != 0)
	return;
    if (sb.st_uid != 0 || (sb.st_mode & 022) != 0)
	return;

    mark_point();
    errstr = "chroot path \"" _PATH_CONSOLE "\" is not a directory";
    WRAP_FATAL_START();
    my_chroot(_PATH_CONSOLE);
    WRAP_FATAL_END();
    ck_assert_msg (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    mark_point();
    errstr = "unable to chdir to chroot path";
    strlcpy(path, "/", PATH_MAX);
    check_wrap_fail |= FAIL_CHDIR;
    WRAP_FATAL_START();
    my_chroot(path);
    WRAP_FATAL_END();
    check_wrap_fail &= ~FAIL_CHDIR;
    ck_assert_msg (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    mark_point();
    errstr = "chroot(\"/\"):";
    check_wrap_fail |= FAIL_CHROOT;
    check_wrap_fake |= FAKE_CHDIR;
    WRAP_FATAL_START();
    my_chroot(path);
    WRAP_FATAL_END();
    check_wrap_fail &= ~FAIL_CHROOT;
    ck_assert_msg (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    mark_point();
    errno = 0;
    errstr = "check";
    my_log(CRIT, errstr);
    check_wrap_fake |= FAKE_CHROOT;
    WRAP_FATAL_START();
    my_chroot(path);
    WRAP_FATAL_END();
    check_wrap_fail = 0;
    check_wrap_fake = 0;
    ck_assert_msg (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
}
END_TEST

START_TEST(test_portname_abbr) {
    char *portname = NULL;

    portname = my_strdup("FastEthernet42/42");
    portname_abbr(portname);
    ck_assert_msg(strcmp(portname, "Fa42/42") == 0,
	"unexpected portname: %s", portname);
    free(portname);

    portname = my_strdup("GigabitEthernet42");
    portname_abbr(portname);
    ck_assert_msg(strcmp(portname, "Gi42") == 0,
	"unexpected portname: %s", portname);
    free(portname);

    portname = my_strdup("TenGigabitEthernet0/86");
    portname_abbr(portname);
    ck_assert_msg(strcmp(portname, "Te0/86") == 0,
	"unexpected portname: %s", portname);
    free(portname);

    portname = my_strdup("Ethernet0/86");
    portname_abbr(portname);
    ck_assert_msg(strcmp(portname, "Eth0/86") == 0,
	"unexpected portname: %s", portname);
    free(portname);

    portname = my_strdup("eth0");
    portname_abbr(portname);
    ck_assert_msg(strcmp(portname, "eth0") == 0,
	"unexpected portname: %s", portname);
    free(portname);
}
END_TEST

START_TEST(test_pcap) {
    int spair[2];
    ssize_t len;
    const char *errstr = NULL;
    char buf[1024];
    struct pcap_file_header pcap_fhdr = {};
    struct parent_msg msg = {};

    loglevel = INFO;
    my_socketpair(spair);

    mark_point();
    errstr = "stdin fd not available";
    my_log(CRIT, "check");
    WRAP_FATAL_START();
    my_pcap_init(-1);
    WRAP_FATAL_END();
    ck_assert_msg (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    mark_point();
    my_pcap_init(spair[0]);
    len = read(spair[1], &pcap_fhdr, sizeof(pcap_fhdr));
    ck_assert_msg(len == sizeof(pcap_fhdr),
		"failed to read pcap header");
    ck_assert_msg(pcap_fhdr.magic == PCAP_MAGIC,
		"invalid pcap header returned");
    ck_assert_msg(pcap_fhdr.snaplen == ETHER_MAX_LEN,
		"invalid pcap header returned");
    ck_assert_msg(pcap_fhdr.linktype == DLT_EN10MB,
		"invalid pcap header returned");

    mark_point();
    errstr = "check";
    my_log(CRIT, errstr);
    msg.len = 1;
    my_pcap_write(&msg);
    ck_assert_msg (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    len = read(spair[1], buf, 1024);
    ck_assert_msg(len == (PCAP_PKTHDR_SIZ + msg.len),
		"failed to read pcap record");

    mark_point();
    msg.len = ETHER_MIN_LEN;
    my_pcap_write(&msg);
    ck_assert_msg (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    len = read(spair[1], buf, 1024);
    ck_assert_msg(len == (PCAP_PKTHDR_SIZ + msg.len),
		"failed to read pcap record");

    close(spair[0]);
    close(spair[1]);
}
END_TEST

Suite * util_suite (void) {
    Suite *s = suite_create("util.c");

    // util test case
    TCase *tc_util = tcase_create("util");
    tcase_add_test(tc_util, test_my);
    tcase_add_test(tc_util, test_my_mreq);
    tcase_add_test(tc_util, test_netif);
    tcase_add_test(tc_util, test_read_line);
    tcase_add_test(tc_util, test_my_cksum);
    tcase_add_test(tc_util, test_my_priv);
    tcase_add_test(tc_util, test_portname_abbr);
    tcase_add_test(tc_util, test_pcap);
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

