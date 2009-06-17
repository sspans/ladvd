TESTS = check_compat check_proto check_util
check_PROGRAMS = check_compat check_proto check_util

LDADD = @CHECK_LIBS@ $(noinst_LTLIBRARIES) \
	$(top_builddir)/src/libmisc.la $(top_builddir)/src/libcompat.la \
	$(top_builddir)/src/libproto.la

check_compat_SOURCES = check_compat.c \
	$(top_builddir)/src/compat/compat.h
check_compat_CFLAGS = @CHECK_CFLAGS@

check_proto_SOURCES = check_proto.c \
	$(top_builddir)/src/proto/protos.h
check_proto_CFLAGS = @CHECK_CFLAGS@

check_util_SOURCES = check_util.c \
	$(top_builddir)/src/common.h \
	$(top_builddir)/src/util.h
check_util_CFLAGS = @CHECK_CFLAGS@

noinst_LTLIBRARIES = libcheckwrap.la
libcheckwrap_la_SOURCES = check_wrap.h check_wrap.c
libcheckwrap_la_LDFLAGS = -rpath `pwd` -shared $(DL_LIB) \
		-Xcompiler -nostartfiles

