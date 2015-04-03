

TESTS = $(check_PROGRAMS)
check_PROGRAMS = check_compat check_proto check_util check_tlv \
		check_parent check_child check_cli

EXTRA_DIST = proto testfile

# auto-generate the list of wrap functions
check_WRAPFLAGS = `$(EGREP) '^[MV]?WRAP' $(srcdir)/check_wrap.c | \
	$(SED) -e 's/^[MV]*WRAP(\([_a-z]*\)\,.*/-Wl,--wrap,\1/g'`

AM_CFLAGS = $(WARN_CFLAGS) @CHECK_CFLAGS@
AM_LDFLAGS = $(check_WRAPFLAGS)
AM_CPPFLAGS = -I$(top_srcdir)/src

LDADD = $(top_builddir)/src/libproto.la $(top_builddir)/src/libmisc.la \
    $(top_builddir)/src/libcompat.la $(check_LTLIBRARIES) \
    $(EVENT_LIB) $(PCI_LIBS) $(PCAP_LIB) $(CAPNG_LDADD) $(CAP_LDADD) \
    $(LIBMNL_LIBS) $(LIBTEAM_LIBS) $(DLADM_LIBS) @CHECK_LIBS@
common_headers = $(top_srcdir)/src/common.h $(top_srcdir)/src/util.h \
	    $(top_srcdir)/src/proto/protos.h

check_compat_SOURCES = check_compat.c $(top_srcdir)/src/compat/compat.h
check_util_SOURCES = check_util.c $(common_headers)
check_tlv_SOURCES = check_tlv.c $(common_headers)
check_proto_SOURCES = check_proto.c $(common_headers)
check_parent_SOURCES = check_parent.c $(common_headers) \
	$(top_srcdir)/src/main.h $(top_srcdir)/src/parent.h
check_child_SOURCES = check_child.c $(common_headers) \
	$(top_srcdir)/src/main.h $(top_srcdir)/src/child.h
check_cli_SOURCES = check_cli.c $(common_headers) $(top_srcdir)/src/cli.h

check_LTLIBRARIES = libcheckwrap.la
libcheckwrap_la_SOURCES = check_wrap.h check_wrap.c
libcheckwrap_la_LDFLAGS = $(DL_LIB)

