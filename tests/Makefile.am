TESTS = $(check_PROGRAMS)
check_PROGRAMS = check_compat check_master check_proto check_util

EXTRA_DIST = proto testfile
dist-hook:
	-rm -rf `find $(distdir)/proto -name .svn`

# auto-generate the list of wrap functions
check_WRAPFLAGS = `$(EGREP) '^[MV]?WRAP' $srcdir/check_wrap.c | \
	$(SED) -e 's/^[MV]*WRAP(\([_a-z]*\)\,.*/-Wl,--wrap,\1/g'`

AM_CPPFLAGS = -I$(top_srcdir)/src
LDADD =  @CHECK_LIBS@ $(check_LTLIBRARIES) $(EVENT_LIB) $(CAP_LIB) \
	$(top_builddir)/src/libproto.la $(top_builddir)/src/libmisc.la \
	$(top_builddir)/src/libcompat.la

check_compat_SOURCES = check_compat.c \
	$(top_srcdir)/src/compat/compat.h
check_compat_CFLAGS = @CHECK_CFLAGS@
check_compat_LDFLAGS = $(check_WRAPFLAGS)

check_master_SOURCES = check_master.c \
	$(top_srcdir)/src/common.h \
	$(top_srcdir)/src/master.h \
	$(top_srcdir)/src/util.h
check_master_CFLAGS = @CHECK_CFLAGS@
check_master_LDFLAGS = $(check_WRAPFLAGS)

check_proto_SOURCES = check_proto.c \
	$(top_srcdir)/src/proto/protos.h
check_proto_CFLAGS = @CHECK_CFLAGS@
check_proto_LDFLAGS = $(check_WRAPFLAGS)

check_util_SOURCES = check_util.c \
	$(top_srcdir)/src/common.h \
	$(top_srcdir)/src/util.h
check_util_CFLAGS = @CHECK_CFLAGS@
check_util_LDFLAGS = $(check_WRAPFLAGS)

check_LTLIBRARIES = libcheckwrap.la
libcheckwrap_la_SOURCES = check_wrap.h check_wrap.c
libcheckwrap_la_LDFLAGS = $(DL_LIB)

