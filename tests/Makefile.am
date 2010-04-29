

TESTS = $(check_PROGRAMS)
check_PROGRAMS = check_compat check_proto check_util \
		check_master check_child check_cli

EXTRA_DIST = proto testfile
dist-hook:
	-rm -rf `find $(distdir)/proto -name .svn`

# auto-generate the list of wrap functions
check_WRAPFLAGS = `$(EGREP) '^[MV]?WRAP' $(srcdir)/check_wrap.c | \
	$(SED) -e 's/^[MV]*WRAP(\([_a-z]*\)\,.*/-Wl,--wrap,\1/g'`

AM_CFLAGS = $(WARN_CFLAGS) @CHECK_CFLAGS@
AM_LDFLAGS = $(check_WRAPFLAGS)
AM_CPPFLAGS = -I$(top_srcdir)/src

LDADD = $(check_LTLIBRARIES) $(top_builddir)/src/libmisc.la \
    $(top_builddir)/src/libproto.la $(top_builddir)/src/libcompat.la \
    $(EVENT_LIB) $(CAP_LIB) @CHECK_LIBS@
common_headers = $(top_srcdir)/src/common.h $(top_srcdir)/src/util.h \
	    $(top_srcdir)/proto/protos.h

check_compat_SOURCES = check_compat.c $(top_srcdir)/src/compat/compat.h
check_util_SOURCES = check_util.c $(common_headers)
check_proto_SOURCES = check_proto.c $(common_headers)
check_master_SOURCES = check_master.c $(common_headers) \
	$(top_srcdir)/src/main.h $(top_srcdir)/src/master.h
check_child_SOURCES = check_child.c $(common_headers) \
	$(top_srcdir)/src/main.h $(top_srcdir)/src/child.h
check_cli_SOURCES = check_cli.c $(common_headers) $(top_srcdir)/src/cli.c

check_LTLIBRARIES = libcheckwrap.la
libcheckwrap_la_SOURCES = check_wrap.h check_wrap.c
libcheckwrap_la_LDFLAGS = $(DL_LIB)

