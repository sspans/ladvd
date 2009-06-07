TESTS = check_compat check_proto check_util
check_PROGRAMS = check_compat check_proto check_util

check_compat_SOURCES = check_compat.c \
	$(top_builddir)/src/compat/compat.h
check_compat_CFLAGS = @CHECK_CFLAGS@
check_compat_LDADD = @CHECK_LIBS@ $(top_builddir)/src/libcompat.la

check_proto_SOURCES = check_proto.c \
	$(top_builddir)/src/proto/protos.h
check_proto_CFLAGS = @CHECK_CFLAGS@
check_proto_LDADD = @CHECK_LIBS@ $(top_builddir)/src/libproto.la \
	$(top_builddir)/src/libmisc.la $(top_builddir)/src/libcompat.la

check_util_SOURCES = check_util.c \
	$(top_builddir)/src/common.h \
	$(top_builddir)/src/util.h
check_util_CFLAGS = @CHECK_CFLAGS@
check_util_LDADD = @CHECK_LIBS@ $(top_builddir)/src/libmisc.la \
	$(top_builddir)/src/libcompat.la

