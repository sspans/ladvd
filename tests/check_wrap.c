
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>

#define __USE_GNU
#include <dlfcn.h>

#include "check_wrap.h"

static void *(*libc_malloc) (size_t size);
static void *(*libc_calloc) (size_t nmemb, size_t size);
static char *(*libc_strdup) (const char *s1);
static void (*libc_exit) (int status);
static int (*libc_setgid) (gid_t gid);
static int (*libc_setuid) (uid_t uid);
static int (*libc_setgroups) (int ngroups, const gid_t *gidset);
static int (*libc_chdir) (const char *path);
static int (*libc_chroot) (const char *dirname);
static int (*libc_kill) (pid_t pid, int sig);

jmp_buf check_wrap_env;
uint32_t check_wrap_opt = 0;
char check_wrap_errstr[1024];

void *malloc(size_t size) {
    libc_malloc = dlsym(RTLD_NEXT, "malloc");

    if (check_wrap_opt & FAIL_MALLOC)
	return NULL;
    return libc_malloc(size);
}

void *calloc(size_t nmemb, size_t size) {
    libc_calloc = dlsym(RTLD_NEXT, "calloc");

    if (check_wrap_opt & FAIL_CALLOC)
	return NULL;
    return libc_calloc(nmemb, size);
}

char *strdup(const char *s1) {
    libc_strdup = dlsym(RTLD_NEXT, "strdup");

    if (check_wrap_opt & FAIL_STRDUP)
	return NULL;
    return libc_strdup(s1);
}

char *__strdup(const char *s1) {
    libc_strdup = dlsym(RTLD_NEXT, "__strdup");

    if (check_wrap_opt & FAIL_STRDUP)
	return NULL;
    return libc_strdup(s1);
}

void exit (int status) {
    libc_exit = dlsym(RTLD_NEXT, "exit");

    if (check_wrap_opt & FAIL_EXIT)
	longjmp(check_wrap_env,1);
    libc_exit(status);
}

int setgid (gid_t gid) {
    libc_setgid = dlsym(RTLD_NEXT, "setgid");

    if (check_wrap_opt & FAIL_SETGID)
	return -1;
    if (check_wrap_opt & FAKE_SETGID)
	return 0;
    return libc_setgid(gid);
}

int setuid (uid_t uid) {
    libc_setuid = dlsym(RTLD_NEXT, "setuid");

    if (check_wrap_opt & FAIL_SETUID)
	return -1;
    if (check_wrap_opt & FAKE_SETUID)
	return 0;
    return libc_setuid(uid);
}

int setgroups (int ngroups, const gid_t *gidset) {
    libc_setgroups = dlsym(RTLD_NEXT, "setgroups");

    if (check_wrap_opt & FAIL_SETGRP)
	return -1;
    if (check_wrap_opt & FAKE_SETGRP)
	return 0;
    return libc_setgroups(ngroups, gidset);
}

int chdir (const char *path) {
    libc_chdir = dlsym(RTLD_NEXT, "chdir");

    if (check_wrap_opt & FAIL_CHDIR)
	return -1;
    if (check_wrap_opt & FAKE_CHDIR)
	return 0;
    return libc_chdir(path);
}

int chroot (const char *dirname) {
    libc_chroot = dlsym(RTLD_NEXT, "chroot");

    if (check_wrap_opt & FAIL_CHROOT)
	return -1;
    if (check_wrap_opt & FAKE_CHROOT)
	return 0;
    return libc_chroot(dirname);
}

int kill (pid_t pid, int sig) {
    libc_kill = dlsym(RTLD_NEXT, "kill");

    if (check_wrap_opt & FAKE_KILL)
	return 0;
    return libc_kill(pid, sig);
}

void vsyslog(int priority, const char *fmt, va_list ap) {
    vsnprintf(check_wrap_errstr, 1024, fmt, ap);
}

void __vsyslog_chk(int priority, int __flag, const char *fmt, va_list ap) {
    vsnprintf(check_wrap_errstr, 1024, fmt, ap);
}

