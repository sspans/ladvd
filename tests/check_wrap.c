
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>

#define __USE_GNU
#include <dlfcn.h>

#include "check_wrap.h"

static void *(*libc_malloc) (size_t size);
static void *(*libc_calloc) (size_t nmemb, size_t size);
static void (*libc_exit) (int status);
static int (*libc_setgid) (gid_t gid);
static int (*libc_setuid) (uid_t uid);
static int (*libc_setgroups) (int ngroups, const gid_t *gidset);
static int (*libc_chdir) (const char *path);
static void (*libc_vsyslog) (int priority, const char *message, va_list args);

jmp_buf check_wrap_env;
uint32_t check_wrap_opt = 0;
char check_wrap_errstr[1024];

void
__attribute__ ((constructor))
_init (void) {
    libc_malloc = dlsym(RTLD_NEXT, "malloc");
    libc_calloc = dlsym(RTLD_NEXT, "calloc");
    libc_exit = dlsym(RTLD_NEXT, "exit");
    libc_setgid = dlsym(RTLD_NEXT, "setgid");
    libc_setuid = dlsym(RTLD_NEXT, "setuid");
    libc_setgroups = dlsym(RTLD_NEXT, "setgroups");
    libc_chdir = dlsym(RTLD_NEXT, "chdir");
    libc_vsyslog = dlsym(RTLD_NEXT, "vsyslog");
}

void *malloc(size_t size) {
    if (check_wrap_opt & FAIL_MALLOC)
	return NULL;
    return libc_malloc(size);
}

void *calloc(size_t nmemb, size_t size) {
    if (check_wrap_opt & FAIL_CALLOC)
	return NULL;
    return libc_calloc(nmemb, size);
}

void exit (int status) {
    if (check_wrap_opt & FAIL_EXIT)
	longjmp(check_wrap_env,1);
    libc_exit(status);
}

int setgid (gid_t gid) {
    if (check_wrap_opt & FAIL_SETGID)
	return -1;
    if (check_wrap_opt & FAKE_SETGID)
	return 0;
    return libc_setgid(gid);
}

int setuid (uid_t uid) {
    if (check_wrap_opt & FAIL_SETUID)
	return -1;
    if (check_wrap_opt & FAKE_SETUID)
	return 0;
    return libc_setuid(uid);
}

int setgroups (int ngroups, const gid_t *gidset) {
    if (check_wrap_opt & FAIL_SETGRP)
	return -1;
    if (check_wrap_opt & FAKE_SETGRP)
	return 0;
    return libc_setgroups(ngroups, gidset);
}

int chdir (const char *path) {
    if (check_wrap_opt & FAIL_CHDIR)
	return -1;
    return libc_chdir(path);
}

void vsyslog(int priority, const char *fmt, va_list ap) {
    vsnprintf(check_wrap_errstr, 1024, fmt, ap);
}

