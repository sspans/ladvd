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
    int backup, null;

    options |= OPT_DEBUG;

    backup = dup(fileno(stdout));
    close(fileno(stdout));
    null = open(_PATH_DEVNULL, O_WRONLY);

    batch_write(&msg, 42);

    close(null);
    null = dup(backup);
    close(backup);
}
END_TEST

Suite * cli_suite (void) {
    Suite *s = suite_create("cli.c");

    sysinfo_fetch(&sysinfo);

    // cli test case
    TCase *tc_cli = tcase_create("cli");
    tcase_add_test(tc_cli, test_batch_write);
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

