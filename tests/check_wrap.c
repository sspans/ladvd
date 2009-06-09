
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>

#define __USE_GNU
#include <dlfcn.h>

static void *(*libc_malloc) (size_t size);
static void *(*libc_calloc) (size_t nmemb, size_t size);
static void (*libc_exit) (int status);
static int (*libc_setgid) (gid_t gid);
static int (*libc_setuid) (uid_t uid);
static int (*libc_setgroups) (int ngroups, const gid_t *gidset);
static int (*libc_chdir) (const char *path);
static void (*libc_vsyslog) (int priority, const char *message, va_list args);

int check_fail_malloc = 0;
int check_fail_calloc = 0;
int check_fail_exit = 0;
int check_fail_priv = 0;
int check_fail_chdir = 0;

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
    if (check_fail_malloc)
	return NULL;
    return libc_malloc(size);
}

void *calloc(size_t nmemb, size_t size) {
    if (check_fail_calloc)
	return NULL;
    return libc_calloc(nmemb, size);
}

void exit (int status) {
    if (check_fail_exit)
	return;
    libc_exit(status);
}

int setgid (gid_t gid) {
    if (check_fail_priv)
	return -1;
    return libc_setgid(gid);
}

int setuid (uid_t uid) {
    if (check_fail_priv)
	return -1;
    return libc_setuid(uid);
}

int setgroups (int ngroups, const gid_t *gidset) {
    if (check_fail_priv)
	return -1;
    return libc_setgroups(ngroups, gidset);
}

int chdir (const char *path) {
    if (check_fail_chdir)
	return -1;
    return libc_chdir(path);
}

void vsyslog(int priority, const char *fmt, va_list ap) {
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
}

