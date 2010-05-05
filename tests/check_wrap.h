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

#include <setjmp.h>

#define FAIL_SETRESGID	(1 << 0)
#define FAIL_SETRESUID	(1 << 1)
#define FAIL_SETGRP	(1 << 2)
#define FAIL_CHDIR	(1 << 3)
#define FAIL_CHROOT	(1 << 4)
#define FAIL_IOCTL	(1 << 5)
#define FAIL_SOCKET	(1 << 6)
#define FAIL_BIND	(1 << 7)
#define FAIL_CONNECT	(1 << 8)
#define FAIL_SETSOCKOPT	(1 << 9)
#define FAIL_OPEN	(1 << 10)
#define FAIL_KILL	(1 << 11)
#define FAIL_MALLOC	(1 << 29)
#define FAIL_CALLOC	(1 << 30)
#define FAIL_STRDUP	(1 << 31)

#define FAKE_SETRESGID	(1 << 0)
#define FAKE_SETRESUID	(1 << 1)
#define FAKE_SETGRP	(1 << 2)
#define FAKE_CHDIR	(1 << 3)
#define FAKE_CHROOT	(1 << 4)
#define FAKE_IOCTL	(1 << 5)
#define FAKE_SOCKET	(1 << 6)
#define FAKE_BIND	(1 << 7)
#define FAKE_CONNECT	(1 << 8)
#define FAKE_SETSOCKOPT	(1 << 9)
#define FAKE_OPEN	(1 << 10)
#define FAKE_KILL	(1 << 11)
#define FAKE_EXIT	(1 << 31)

#define WRAP_FATAL_START() \
    if (!setjmp(check_wrap_env)) { \
	check_wrap_fake |= FAKE_EXIT;
#define WRAP_FATAL_END() \
    } \
    check_wrap_fake &= ~FAKE_EXIT;

extern jmp_buf check_wrap_env;
extern uint32_t check_wrap_fake;
extern uint32_t check_wrap_fail;
extern char check_wrap_errstr[];

#define WRAP_WRITE(sock, msg, size)	\
    fail_unless(write(sock, msg, size) == size, "message write failed");
#define WRAP_REQ_READ(sock, mreq, len)	\
    len = read(sock, mreq, MASTER_REQ_MAX); \
    fail_if(len < MASTER_REQ_MIN, "message read failed"); \
    fail_if(len != MASTER_REQ_LEN(mreq->len), "message read failed");

