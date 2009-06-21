
#include <setjmp.h>

#define FAIL_MALLOC	(1 << 0)
#define FAIL_CALLOC	(1 << 1)
#define FAIL_STRDUP	(1 << 2)
#define FAIL_SETGID	(1 << 3)
#define FAIL_SETUID	(1 << 4)
#define FAIL_SETGRP	(1 << 5)
#define FAIL_CHDIR	(1 << 6)
#define FAIL_CHROOT	(1 << 7)
#define FAIL_SETSOCKOPT	(1 << 8)
#define FAIL_IOCTL	(1 << 9)
#define FAKE_SETGID	(1 << 16)
#define FAKE_SETUID	(1 << 17)
#define FAKE_SETGRP	(1 << 18)
#define FAKE_CHDIR	(1 << 19)
#define FAKE_CHROOT	(1 << 20)
#define FAKE_SETSOCKOPT	(1 << 21)
#define FAKE_IOCTL	(1 << 22)
#define FAKE_KILL	(1 << 30)
#define FAIL_EXIT	(1 << 31)

#define WRAP_FATAL_START() \
    if (!setjmp(check_wrap_env)) { \
	check_wrap_opt |= FAIL_EXIT;
#define WRAP_FATAL_END() \
    } \
    check_wrap_opt &= ~FAIL_EXIT;

