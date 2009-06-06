TESTS = check_util
check_PROGRAMS = check_util

check_util_SOURCES = check_util.c \
	$(top_builddir)/src/common.h \
	$(top_builddir)/src/util.h
check_util_CFLAGS = @CHECK_CFLAGS@
check_util_LDADD = @CHECK_LIBS@ $(top_builddir)/src/libmisc.la \
	$(top_builddir)/src/libcompat.la

