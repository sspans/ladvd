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
#include "cli.h"
#include "check_wrap.h"

unsigned int ifindex = 0;
uint32_t options = OPT_DAEMON | OPT_CHECK;

void fake_log_cb(int severity, const char *msg) {
}


START_TEST(test_cli_main) {
    const char *errstr = NULL;
    int ofd[3], spair[6];
    int argc;
    char *argv[7], ifname[IFNAMSIZ];
    char buf[8192];
    struct parent_msg msg = {};
    int sobuf = PARENT_MSG_MAX * 10;
    time_t now;
#if HAVE_EVHTTP_H
    extern char *http_host, *http_path;
#endif /* HAVE_EVHTTP_H */

    argc = 6;
    argv[0] = PACKAGE_CLI;
    argv[1] = "-LCEF";
#if HAVE_EVHTTP_H
    argv[2] = "-p";
    argv[3] = "http://foo/bar";
#else
    argv[2] = "-f";
    argv[3] = "-f";
#endif /* HAVE_EVHTTP_H */
    argv[4] = "-bdf";
    argv[5] = "";
    argv[6] = NULL;

    check_wrap_fail = 0;
    check_wrap_fake = 0;
    now = time(NULL);

    fail_if(socketpair(AF_UNIX, SOCK_STREAM, 0, &spair[0]) == -1,
	    "socketpair creation failed");
    setsockopt(spair[0], SOL_SOCKET, SO_RCVBUF, &sobuf, sizeof(sobuf));
    setsockopt(spair[1], SOL_SOCKET, SO_SNDBUF, &sobuf, sizeof(sobuf));
    ofd[0] = dup(STDIN_FILENO);
    dup2(spair[0], STDIN_FILENO);

    sobuf = 8192;
    fail_if(socketpair(AF_UNIX, SOCK_STREAM, 0, &spair[2]) == -1,
	    "socketpair creation failed");
    setsockopt(spair[2], SOL_SOCKET, SO_SNDBUF, &sobuf, sizeof(sobuf));
    setsockopt(spair[3], SOL_SOCKET, SO_RCVBUF, &sobuf, sizeof(sobuf));
    ofd[1] = dup(STDOUT_FILENO);
    dup2(spair[2], STDOUT_FILENO);

    fail_if(socketpair(AF_UNIX, SOCK_STREAM, 0, &spair[4]) == -1,
	    "socketpair creation failed");
    setsockopt(spair[4], SOL_SOCKET, SO_SNDBUF, &sobuf, sizeof(sobuf));
    setsockopt(spair[5], SOL_SOCKET, SO_RCVBUF, &sobuf, sizeof(sobuf));
    ofd[2] = dup(STDERR_FILENO);
    dup2(spair[4], STDERR_FILENO);

    mark_point();
    memset(buf, 0, sizeof(buf));
    argv[5] = "-Noq";
    WRAP_FATAL_START();
    cli_main(argc, argv);
    WRAP_FATAL_END();
    fflush(stderr);
    fail_if(read(spair[5], buf, sizeof(buf)) < 0,
	    "cli_main read failed");
    fail_if(strstr(buf, "Usage:") == NULL,
    	    "invalid usage output: %s", buf);

    mark_point();
    options = OPT_DAEMON | OPT_CHECK;
    memset(buf, 0, sizeof(buf));
    argv[5] = "invalid";
    optind = 1;
    WRAP_FATAL_START();
    cli_main(argc, argv);
    WRAP_FATAL_END();
    fflush(stderr);
    fail_if(read(spair[5], buf, sizeof(buf)) < 0,
	    "cli_main read failed");
    fail_if(strstr(buf, "Usage:") == NULL,
    	    "invalid usage output: %s", buf);

    // cleanup
#if HAVE_EVHTTP_H
    free(http_host);
    http_host = NULL;
    free(http_path);
    http_path = NULL;
#endif /* HAVE_EVHTTP_H */

    mark_point();
    fail_unless(ifindex, "missing loopback interface");

#ifndef __sun__
    mark_point();
    memset(buf, 0, sizeof(buf));
    argv[5] = if_indextoname(ifindex, ifname);
    optind = 1;
    errstr = "failed to create socket:";
    check_wrap_fail |= FAIL_SOCKET;
    WRAP_FATAL_START();
    cli_main(argc, argv);
    WRAP_FATAL_END();
    fflush(stderr);
    fail_if(read(spair[5], buf, sizeof(buf)) < 0,
	    "cli_main read failed");
    fail_unless (strncmp(buf, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", buf);

    // cleanup
#if HAVE_EVHTTP_H
    free(http_host);
    http_host = NULL;
    free(http_path);
    http_path = NULL;
#endif /* HAVE_EVHTTP_H */

    mark_point();
    memset(buf, 0, sizeof(buf));
    optind = 1;
    errstr = "failed to open " PACKAGE_SOCKET ":";
    check_wrap_fail &= ~FAIL_SOCKET;
    check_wrap_fail |= FAIL_CONNECT;
    check_wrap_fake |= FAKE_SOCKET;
    WRAP_FATAL_START();
    cli_main(argc, argv);
    WRAP_FATAL_END();
    fflush(stderr);
    fail_if(read(spair[5], buf, sizeof(buf)) < 0,
	    "cli_main read failed");
    fail_unless (strncmp(buf, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", buf);
#endif

    // cleanup
#if HAVE_EVHTTP_H
    free(http_host);
    http_host = NULL;
    free(http_path);
    http_path = NULL;
#endif /* HAVE_EVHTTP_H */

    // valid lldp
    mark_point();
    read_packet(&msg, "proto/lldp/41.good.small");
    msg.received = now;
    msg.proto = PROTO_LLDP;
    msg.index = 1;
    strlcpy(msg.name, ifname, IFNAMSIZ);
    fail_if(write(spair[1], &msg, PARENT_MSG_MAX) < 0,
	    "write failed");

    // invalid proto
    mark_point();
    read_packet(&msg, "proto/cdp/43.good.big");
    msg.proto = PROTO_MAX;
    fail_if(write(spair[1], &msg, PARENT_MSG_MAX) < 0,
	    "write failed");

    // invalid len
    mark_point();
    msg.proto = PROTO_CDP;
    msg.len += ETHER_MAX_LEN;
    fail_if(write(spair[1], &msg, PARENT_MSG_MAX) < 0,
	    "write failed");

    // invalid ifindex
    mark_point();
    msg.len -= ETHER_MAX_LEN;
    msg.index = 0;
    fail_if(write(spair[1], &msg, PARENT_MSG_MAX) < 0,
	    "write failed");

    // unwanted proto
    mark_point();
    msg.index = 1;
    msg.proto = PROTO_NDP;
    fail_if(write(spair[1], &msg, PARENT_MSG_MAX) < 0,
	    "write failed");

    // invalid packet
    mark_point();
    msg.proto = PROTO_LLDP;
    read_packet(&msg, "proto/lldp/A3.fuzzer.chassis_id.broken");
    fail_if(write(spair[1], &msg, PARENT_MSG_MAX) < 0,
	    "write failed");

    // old message
    mark_point();
    msg.proto = PROTO_LLDP;
    read_packet(&msg, "proto/lldp/45.good.vlan");
    msg.received = 0;
    fail_if(write(spair[1], &msg, PARENT_MSG_MAX) < 0,
	    "write failed");

    // valid
    mark_point();
    msg.received = now;
    strlcpy(msg.name, ifname, IFNAMSIZ);
    fail_if(write(spair[1], &msg, PARENT_MSG_MAX) < 0,
	    "write failed");

    mark_point();
    memset(buf, 0, sizeof(buf));
    optind = 1;
    shutdown(spair[1], SHUT_WR);
    signal(SIGPIPE, SIG_IGN);
    check_wrap_fail &= ~FAIL_CONNECT;
    check_wrap_fake |= FAKE_CONNECT;
    errstr = "check";
    my_log(CRIT, errstr);
    WRAP_FATAL_START();
    cli_main(argc, argv);
    WRAP_FATAL_END();
    fflush(stderr);
    fail_if(read(spair[5], buf, sizeof(buf)) < 0,
	"cli_main read failed");
    fail_unless (strncmp(buf, errstr, strlen(errstr)) == 0,
    	"incorrect message logged: %s", buf);

    // cleanup
#if HAVE_EVHTTP_H
    free(http_host);
    http_host = NULL;
    free(http_path);
    http_path = NULL;
#endif /* HAVE_EVHTTP_H */

    // close fds
    close(spair[0]);
    close(spair[1]);
    dup2(ofd[0], STDIN_FILENO);
    close(ofd[0]);

    close(spair[2]);
    close(spair[3]);
    dup2(ofd[1], STDOUT_FILENO);
    close(ofd[1]);

    close(spair[4]);
    close(spair[5]);
    dup2(ofd[2], STDERR_FILENO);
    close(ofd[2]);

    check_wrap_fail = 0;
    check_wrap_fake = 0;
    options = OPT_DAEMON | OPT_CHECK;
}
END_TEST

START_TEST(test_batch_write) {
    struct parent_msg msg = {};
    int ostdout, spair[2];
    char buf[8192];
    int sobuf = 8192;

    ostdout = dup(STDOUT_FILENO);
    fail_if(ostdout == -1, "dup failed: %s", strerror(errno));
    fail_if(socketpair(AF_UNIX, SOCK_STREAM, 0, spair) == -1,
	    "socketpair creation failed: %s", strerror(errno));
    setsockopt(spair[0], SOL_SOCKET, SO_SNDBUF, &sobuf, sizeof(sobuf));
    setsockopt(spair[1], SOL_SOCKET, SO_RCVBUF, &sobuf, sizeof(sobuf));
    dup2(spair[0], STDOUT_FILENO);

    mark_point();
    batch_write(&msg, 42);
    fflush(stdout);
    fail_if(read(spair[1], buf, sizeof(buf)) < 0,
	"read failed");
    fail_if(strstr(buf, "INTERFACE_0=") != buf,
	    "invalid batch_write output");
    fail_if(strstr(buf, "HOLDTIME_0=") == NULL,
    	    "invalid batch_write output");
	
    
    mark_point();
    strlcpy(msg.name, "eth0", IFNAMSIZ);
    msg.proto = PROTO_CDP;
    msg.peer[PEER_HOSTNAME] = strdup("router");
    msg.peer[PEER_PORTNAME] = strdup("Fas'tEthernet42/64");
    batch_write(&msg, 42);
    fflush(stdout);
    fail_if(read(spair[1], buf, sizeof(buf)) < 0,
	"read failed");
    fail_if(strstr(buf, "INTERFACE_1=") != buf,
	    "invalid batch_write output");
    fail_if(strstr(buf, "HOLDTIME_1=") == NULL,
	    "invalid batch_write output");
	
    
    close(spair[0]);
    close(spair[1]);
    dup2(ostdout, STDOUT_FILENO);
    close(ostdout);
    peer_free(msg.peer);
}
END_TEST

START_TEST(test_cli) {
    int ostdout, spair[2];
    struct parent_msg msg = {};
    char buf[2048];
    int sobuf = 2048;

    ostdout = dup(STDOUT_FILENO);
    fail_if(ostdout == -1, "dup failed: %s", strerror(errno));
    fail_if(socketpair(AF_UNIX, SOCK_STREAM, 0, spair) == -1,
	    "socketpair creation failed: %s", strerror(errno));
    setsockopt(spair[0], SOL_SOCKET, SO_SNDBUF, &sobuf, sizeof(sobuf));
    setsockopt(spair[1], SOL_SOCKET, SO_RCVBUF, &sobuf, sizeof(sobuf));
    dup2(spair[0], STDOUT_FILENO);

    mark_point();
    cli_header();
    fflush(stdout);
    fail_if(read(spair[1], buf, sizeof(buf)) < 0,
	"read failed");
    fail_if(strstr(buf, "Capability Codes:") != buf,
	    "invalid cli_header output");
    fail_if(strstr(buf, "Device ID") == NULL,
	    "invalid cli_header output");
	
    mark_point();
    strlcpy(msg.name, "eth0", IFNAMSIZ);
    msg.proto = PROTO_CDP;
    msg.peer[PEER_HOSTNAME] = strdup("router.local");
    msg.peer[PEER_PORTNAME] = strdup("TenGigabitEthernet42/64");
    cli_write(&msg, 42);
    fflush(stdout);
    fail_if(read(spair[1], buf, sizeof(buf)) < 0,
	"read failed");
    fail_if(strstr(buf, "router") != buf,
	    "invalid cli_write output");
    fail_if(strstr(buf, "Te42/64") == NULL,
	    "invalid cli_write output");
	
    close(spair[0]);
    close(spair[1]);
    dup2(ostdout, STDOUT_FILENO);
    close(ostdout);
    peer_free(msg.peer);
}
END_TEST

START_TEST(test_debug) {
    const char *errstr = NULL;
    int ostdout, spair[2];
    ssize_t len;
    struct pcap_file_header pcap_fhdr = {};
    struct parent_msg msg = {};
    char buf[2048];

    mark_point();
    if (isatty(STDOUT_FILENO)) { 
	errstr = "please redirect stdout to tcpdump or a file";
	my_log(CRIT, "check");
	WRAP_FATAL_START();
	debug_header();
	WRAP_FATAL_END();
	fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	    "incorrect message logged: %s", check_wrap_errstr);
    }

    ostdout = dup(STDOUT_FILENO);
    my_socketpair(spair);
    dup2(spair[0], STDOUT_FILENO);
    close(ostdout);
    errstr = "check";
    my_log(CRIT, errstr);

    mark_point();
    debug_header();
    fflush(stdout);
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
        "incorrect message logged: %s", check_wrap_errstr);
    len = read(spair[1], &pcap_fhdr, sizeof(pcap_fhdr));
    fail_unless(len == sizeof(pcap_fhdr),
                "failed to read pcap header");
    fail_unless(pcap_fhdr.magic == PCAP_MAGIC,
                "invalid pcap header returned");
    fail_unless(pcap_fhdr.snaplen == ETHER_MAX_LEN,
                "invalid pcap header returned");
    fail_unless(pcap_fhdr.linktype == DLT_EN10MB,
                "invalid pcap header returned");

    mark_point();
    msg.len = ETHER_MIN_LEN;
    debug_write(&msg, 0);
    fflush(stdout);
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
        "incorrect message logged: %s", check_wrap_errstr);
    len = read(spair[1], buf, sizeof(buf));
    fail_unless(len == (PCAP_PKTHDR_SIZ + msg.len),
                "failed to read pcap record"); 

    close(spair[0]);
    close(spair[1]);
    dup2(ostdout, STDOUT_FILENO);
    close(ostdout);
}
END_TEST

#if HAVE_EVHTTP_H
START_TEST(test_http) {
    struct parent_msg msg = {};
    const char *errstr = NULL;
    extern char *http_host, *http_path;
    static struct event_base *base;
    struct evhttp *httpd;
    extern struct evhttp_request *lreq;
    extern struct evhttp_connection *evcon;
    extern int status;
    extern short http_port;
    int sock = -1;

    // check for ipv4 before running the test
    mark_point();
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	return;
    else
	close(sock);

    // this assumes libevent can connect to localhost
    // sounds silly, but I've seen it fail...
    http_host = "127.0.0.1";
    http_path = "/cgi-bin/test.cgi";
    event_set_log_callback(&fake_log_cb);

    mark_point();
    base = event_init();
    httpd = evhttp_new(base);
    for (http_port = 8080; http_port < 8090; http_port++) {
        if (evhttp_bind_socket(httpd, http_host, http_port) != -1)
	    break;
    }
    fail_unless (http_port < 8090, "failed to start httpd on %s", http_host);

    // If either of these two fail then we're screwed anyway
    mark_point();
    http_connect();

    mark_point();
    http_request(&msg, 0);

    mark_point();
    strlcpy(msg.name, "eth0", IFNAMSIZ);
    msg.proto = PROTO_CDP;
    msg.decode = (1 << PEER_HOSTNAME)|(1 << PEER_PORTNAME);
    msg.peer[PEER_HOSTNAME] = strdup("router");
    msg.peer[PEER_PORTNAME] = strdup("Fas'tEthernet42/64");
    http_request(&msg, 0);

    mark_point();
    errstr = "HTTP request failed";
    my_log(CRIT, "check");
    WRAP_FATAL_START();
    http_reply(lreq, NULL);
    WRAP_FATAL_END();
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    mark_point();
    lreq->response_code = 200;
    http_reply(lreq, NULL);
    fail_unless (status == EXIT_SUCCESS,
	"incorrect exit status returned: %d", status);

    mark_point();
    lreq->response_code = 404;
    errstr = "HTTP error 404 received";
    my_log(CRIT, "check");
    http_reply(lreq, NULL);
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);
    fail_unless (status == EXIT_FAILURE,
	"incorrect exit status returned: %d", status);

    mark_point();
    evhttp_connection_free(evcon);
    lreq = NULL;


    mark_point();
    errstr = "failed";
    my_log(CRIT, "check");
    evcon = evhttp_connection_new("256.256.256.256", 0);
    WRAP_FATAL_START();
    http_request(&msg, 0);
    WRAP_FATAL_END();
    fail_unless (strstr(check_wrap_errstr, errstr) != NULL,
	"incorrect message logged: %s", check_wrap_errstr);
    evhttp_connection_free(evcon);

    mark_point();
    errstr = "failed";
    my_log(CRIT, "check");
    evcon = evhttp_connection_new("localhost", 0);
    WRAP_FATAL_START();
    http_request(&msg, 0);
    http_dispatch();
    WRAP_FATAL_END();
    fail_unless (strstr(check_wrap_errstr, errstr) != NULL,
	"incorrect message logged: %s", check_wrap_errstr);

    mark_point();
    // free the active connection
    evhttp_connection_free(evcon);
    lreq = NULL;
    evcon = evhttp_connection_new(http_host, 80);
    http_dispatch();

    evhttp_free(httpd);
    event_base_free(base);
    peer_free(msg.peer);
}
END_TEST
#endif /* HAVE_EVHTTP_H */

Suite * cli_suite (void) {
    Suite *s = suite_create("cli.c");

    // cli test case
    TCase *tc_cli = tcase_create("cli");
    tcase_add_test(tc_cli, test_cli_main);
    tcase_add_test(tc_cli, test_batch_write);
    tcase_add_test(tc_cli, test_cli);
    tcase_add_test(tc_cli, test_debug);
#if HAVE_EVHTTP_H
    tcase_add_test(tc_cli, test_http);
#endif /* HAVE_EVHTTP_H */
    suite_add_tcase(s, tc_cli);

    ifindex = if_nametoindex("lo");
    if (!ifindex)
	ifindex = if_nametoindex("lo0");

    return s;
}

int main (void) {
    int number_failed;
    Suite *s = cli_suite();
    SRunner *sr = srunner_create (s);
    srunner_run_all (sr, CK_NORMAL);
    number_failed = srunner_ntests_failed (sr);
    srunner_free (sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

