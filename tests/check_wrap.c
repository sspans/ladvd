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

#include "common.h"
#include "check_wrap.h"

jmp_buf check_wrap_env;
uint32_t check_wrap_fail = 0;
uint32_t check_wrap_fake = 0;
char check_wrap_errstr[1024];

#define WRAP(name, cond, params, args) \
int __real_##name params ;\
int __wrap_##name params {\
    if (check_wrap_fail & FAIL_##cond) \
	return -1; \
    if (check_wrap_fake & FAKE_##cond) \
	return 0; \
    return __real_##name args;\
}

#define VWRAP(name, cond, params, args) \
void * __real_##name params ;\
void * __wrap_##name params {\
    if (check_wrap_fail & FAIL_##cond) \
	return NULL; \
    return __real_##name args;\
}

#define MWRAP(name, ret, params) \
ret __real_##name params ;\
ret __wrap_##name params 

WRAP(setresgid, SETRESGID, (gid_t r, gid_t e, gid_t s), (r, e, s));
WRAP(setresuid, SETRESUID, (uid_t r, uid_t e, uid_t s), (r, e, s));
WRAP(setgroups, SETGRP, (int n, const gid_t *s), (n, s));
WRAP(chdir, CHDIR, (const char *path), (path));
WRAP(chroot, CHROOT, (const char *dirname), (dirname));
WRAP(socket, SOCKET, (int d, int t, int p), (d,t,p));
WRAP(bind, BIND, (int s, const struct sockaddr *a, socklen_t al), (s,a,al));
WRAP(connect, CONNECT, (int s, const struct sockaddr *a, socklen_t al),
    (s,a,al));
WRAP(setsockopt, SETSOCKOPT,
    (int s, int level, int optname, const void *optval, socklen_t optlen),
    (s, level, optname, optval, optlen));
WRAP(kill, KILL, (pid_t pid, int sig), (pid, sig));

VWRAP(malloc, MALLOC, (size_t size), (size));
VWRAP(calloc, CALLOC, (size_t nmemb, size_t size), (nmemb, size));
VWRAP(strdup, STRDUP, (const char *s1), (s1));
#ifdef HAVE___STRDUP
VWRAP(__strdup, STRDUP, (const char *s1), (s1));
#endif

MWRAP(ioctl, int, (int fd, unsigned long int request, ...)) {
    va_list ap;
    int ret;

    if (check_wrap_fail & FAIL_IOCTL)
	return -1;
    if (check_wrap_fake & FAKE_IOCTL)
	return 0;

    va_start(ap, request);
    ret = __real_ioctl(fd, request, va_arg(ap, void *));
    va_end(ap);

    return(ret);
}

MWRAP(open, int, (const char *pathname, int flags, ...)) {

    if (check_wrap_fail & FAIL_OPEN)
	return -1;
    if (check_wrap_fake & FAKE_OPEN)
	return 0;

    if (flags & O_CREAT) {
	mode_t mode;
	va_list ap;

	va_start(ap, flags);
	mode = (mode_t) va_arg(ap, int);
	va_end(ap);

	return __real_open(pathname, flags, mode);
    } else {
	return __real_open(pathname, flags);
    }
}

MWRAP(exit, void, (int status)) {

    if (check_wrap_fake & FAKE_EXIT)
	longjmp(check_wrap_env,1);
    __real_exit(status);
}

MWRAP(vsyslog, void, (int p, const char *fmt, va_list ap)) {
    vsnprintf(check_wrap_errstr, 1024, fmt, ap);
}

MWRAP(__vsyslog_chk, void, (int p, int __flag, const char *fmt, va_list ap)) {
    vsnprintf(check_wrap_errstr, 1024, fmt, ap);
}

