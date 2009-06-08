
#include <stdio.h>
#include <unistd.h>

#define __USE_GNU
#include <dlfcn.h>

static void *(*libc_malloc) (size_t size) = 0;
static void *(*libc_calloc) (size_t nmemb, size_t size) = 0;

void
__attribute__ ((constructor))
_init (void) {
    libc_malloc = dlsym(RTLD_NEXT, "malloc");
    libc_calloc = dlsym(RTLD_NEXT, "calloc");
}

void *malloc(size_t size) {
    if(getenv("CHECK_FAIL_MALLOC")) {
	return NULL;
    }
    return libc_malloc(size);
}

void *calloc(size_t nmemb, size_t size) {
    if(getenv("CHECK_FAIL_CALLOC")) {
	return NULL;
    }
    return libc_calloc(nmemb, size);
}

