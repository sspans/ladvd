
AM_CFLAGS = $(WARN_CFLAGS)
AM_LDFLAGS = $(WARN_LDFLAGS)

common_headers = common.h ether.h filter.h util.h \
	compat/compat.h compat/sys-queue.h proto/protos.h

noinst_LTLIBRARIES = libmisc.la libproto.la libcompat.la 
nodist_libcompat_la_SOURCES = config.h
libcompat_la_SOURCES = compat/compat.h compat/vis.h \
	compat/strlcpy.c compat/strlcat.c compat/setproctitle.c compat/vis.c
nodist_libproto_la_SOURCES = config.h
libproto_la_SOURCES = proto/protos.h proto/tlv.c proto/tlv.h \
	proto/lldp.c proto/lldp.h \
	proto/cdp.c proto/cdp.h \
	proto/edp.c proto/edp.h \
	proto/fdp.c proto/fdp.h \
	proto/ndp.c proto/ndp.h
nodist_libmisc_la_SOURCES = config.h
libmisc_la_SOURCES = $(common_headers) child.h child.c master.h master.c \
	cli.h cli.c util.c sysinfo.c netif.c

sbin_PROGRAMS = ladvd
nodist_ladvd_SOURCES = config.h
ladvd_SOURCES = $(common_headers) main.h main.c
ladvd_LDADD = $(noinst_LTLIBRARIES) $(EVENT_LIB) $(PCAP_LIB) $(PCI_LIBS) \
	$(CAPNG_LDADD) $(CAP_LDADD) $(LIBMNL_LIBS)

install-exec-hook:
	$(LN_S) @PACKAGE_NAME@$(EXEEXT) \
	    $(DESTDIR)$(sbindir)/@PACKAGE_CLI@$(EXEEXT)

