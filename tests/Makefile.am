TESTS = check_misc
check_PROGRAMS = check_misc

check_misc_SOURCES = check_misc.c \
	$(top_builddir)/src/common.h \
	$(top_builddir)/src/util.h
check_misc_CFLAGS = @CHECK_CFLAGS@
check_misc_LDADD = @CHECK_LIBS@ $(top_builddir)/src/libmisc.la \
	$(top_builddir)/src/libcompat.la

