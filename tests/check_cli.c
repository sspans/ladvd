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
#include "cli.h"
#include "check_wrap.h"

uint32_t options = OPT_DAEMON | OPT_CHECK;
extern struct sysinfo sysinfo;

void read_packet(struct master_msg *msg, const char *suffix) {
    int fd;
    char *prefix, *path = NULL;

    memset(msg->msg, 0, ETHER_MAX_LEN);
    msg->len = 0;
    msg->ttl = 0;
    peer_free(msg->peer);

    if ((prefix = getenv("srcdir")) == NULL)
	prefix = ".";

    fail_if(asprintf(&path, "%s/%s", prefix, suffix) == -1,
	    "asprintf failed");

    mark_point();
    fail_if((fd = open(path, O_RDONLY)) == -1, "failed to open %s", path);
    msg->len = read(fd, msg->msg, ETHER_MAX_LEN);

    free(path);
}

START_TEST(test_batch_write) {
    struct master_msg msg = {};
    int ostdout, spair[2];
    ssize_t len;
    char buf[1024];

    options |= OPT_DEBUG;

    ostdout= dup(fileno(stdout));
    close(fileno(stdout));
    fail_if(socketpair(AF_UNIX, SOCK_STREAM, 0, spair) == -1,
	    "socketpair creation failed");

    mark_point();
    batch_write(&msg, 42);
    len = read(spair[1], buf, 1024);
    fail_if(strstr(buf, "INTERFACE0=") != buf,
	    "invalid batch_write output");
    fail_if(strstr(buf, "HOLDTIME0=") == NULL,
    	    "invalid batch_write output");
	
    
    mark_point();
    strlcpy(msg.name, "eth0", IFNAMSIZ);
    msg.proto = PROTO_CDP;
    msg.peer[PEER_HOSTNAME] = strdup("router");
    msg.peer[PEER_PORTNAME] = strdup("Fas'tEthernet42/64");
    batch_write(&msg, 42);
    len = read(spair[1], buf, 1024);
    fail_if(strstr(buf, "INTERFACE1=") != buf,
	    "invalid batch_write output");
    fail_if(strstr(buf, "HOLDTIME1=") == NULL,
	    "invalid batch_write output");
	
    
    close(spair[0]);
    close(spair[1]);
    len = dup(ostdout);
    close(ostdout);
    peer_free(msg.peer);
}
END_TEST

START_TEST(test_cli) {
    int ostdout, spair[2];
    ssize_t len;
    struct master_msg msg = {};
    char buf[1024];

    options |= OPT_DEBUG;

    ostdout = dup(fileno(stdout));
    close(fileno(stdout));
    fail_if(socketpair(AF_UNIX, SOCK_STREAM, 0, spair) == -1,
	    "socketpair creation failed");

    mark_point();
    cli_header();
    len = read(spair[1], buf, 1024);
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
    len = read(spair[1], buf, 1024);
    fail_if(strstr(buf, "router") != buf,
	    "invalid cli_write output");
    fail_if(strstr(buf, "Te42/64") == NULL,
	    "invalid cli_write output");
	
    close(spair[0]);
    close(spair[1]);
    len = dup(ostdout);
    close(ostdout);
    peer_free(msg.peer);
}
END_TEST

START_TEST(test_debug) {
    const char *errstr = NULL;
    int ostdout, spair[2];
    ssize_t len;
    pcap_hdr_t pcap_hdr = {};
    struct master_msg msg = {};
    char buf[1024];

    options |= OPT_DEBUG;

    mark_point();
    errstr = "please redirect stdout to tcpdump or a file";
    my_log(CRIT, "check");
    WRAP_FATAL_START();
    debug_header();
    WRAP_FATAL_END();
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
	"incorrect message logged: %s", check_wrap_errstr);

    ostdout = dup(fileno(stdout));
    close(fileno(stdout));
    my_socketpair(spair);
    errstr = "check";
    my_log(CRIT, errstr);

    mark_point();
    debug_header();
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
        "incorrect message logged: %s", check_wrap_errstr);
    len = read(spair[1], &pcap_hdr, sizeof(pcap_hdr));
    fail_unless(len == sizeof(pcap_hdr),
                "failed to read pcap header");
    fail_unless(pcap_hdr.magic_number == PCAP_MAGIC,
                "invalid pcap header returned");
    fail_unless(pcap_hdr.snaplen == ETHER_MAX_LEN,
                "invalid pcap header returned");
    fail_unless(pcap_hdr.network == 1,
                "invalid pcap header returned");

    mark_point();
    msg.len = ETHER_MIN_LEN;
    debug_write(&msg, 0);
    fail_unless (strncmp(check_wrap_errstr, errstr, strlen(errstr)) == 0,
        "incorrect message logged: %s", check_wrap_errstr);
    len = read(spair[1], buf, 1024);
    fail_unless(len == (sizeof(pcaprec_hdr_t) + msg.len),
                "failed to read pcap record"); 

    close(spair[0]);
    close(spair[1]);
    len = dup(ostdout);
    close(ostdout);
}
END_TEST

Suite * cli_suite (void) {
    Suite *s = suite_create("cli.c");

    sysinfo_fetch(&sysinfo);

    // cli test case
    TCase *tc_cli = tcase_create("cli");
    tcase_add_test(tc_cli, test_batch_write);
    tcase_add_test(tc_cli, test_cli);
    tcase_add_test(tc_cli, test_debug);
    suite_add_tcase(s, tc_cli);

    return s;
}

int main (void) {
    int number_failed;
    Suite *s = cli_suite ();
    SRunner *sr = srunner_create (s);
    srunner_run_all (sr, CK_NORMAL);
    number_failed = srunner_ntests_failed (sr);
    srunner_free (sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

