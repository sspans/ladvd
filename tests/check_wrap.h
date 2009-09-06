
#include <setjmp.h>

#define FAIL_MALLOC	(1 << 0)
#define FAIL_CALLOC	(1 << 1)
#define FAIL_STRDUP	(1 << 2)
#define FAIL_SETRESGID	(1 << 3)
#define FAIL_SETRESUID	(1 << 4)
#define FAIL_SETGRP	(1 << 5)
#define FAIL_CHDIR	(1 << 6)
#define FAIL_CHROOT	(1 << 7)
#define FAIL_SETSOCKOPT	(1 << 8)
#define FAIL_IOCTL	(1 << 9)
#define FAIL_SOCKET	(1 << 10)
#define FAIL_BIND	(1 << 11)
#define FAIL_OPEN	(1 << 12)
#define FAIL_KILL	(1 << 13)

#define FAKE_SETRESGID	(1 << 0)
#define FAKE_SETRESUID	(1 << 1)
#define FAKE_SETGRP	(1 << 2)
#define FAKE_CHDIR	(1 << 3)
#define FAKE_CHROOT	(1 << 4)
#define FAKE_SETSOCKOPT	(1 << 5)
#define FAKE_IOCTL	(1 << 6)
#define FAKE_SOCKET	(1 << 7)
#define FAKE_BIND	(1 << 8)
#define FAKE_OPEN	(1 << 9)
#define FAKE_KILL	(1 << 30)
#define FAIL_EXIT	(1 << 31)

#define WRAP_FATAL_START() \
    if (!setjmp(check_wrap_env)) { \
	check_wrap_fail |= FAIL_EXIT;
#define WRAP_FATAL_END() \
    } \
    check_wrap_fail &= ~FAIL_EXIT;

extern jmp_buf check_wrap_env;
extern uint32_t check_wrap_fake;
extern uint32_t check_wrap_fail;
extern char check_wrap_errstr[];

