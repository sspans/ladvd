
AM_CFLAGS = $(WARN_CFLAGS) @XOPEN_DEFINES@
AM_LDFLAGS = $(WARN_LDFLAGS)

EXTRA_DIST = netif_bsd.c netif_linux.c

common_headers = common.h ether.h filter.h util.h \
	compat/compat.h compat/sys-queue.h proto/protos.h

noinst_LTLIBRARIES = libmisc.la libproto.la libcompat.la 
libcompat_la_SOURCES = compat/compat.h compat/imsg.h compat/vis.h \
	compat/strlcpy.c compat/strlcat.c compat/setproctitle.c \
	compat/vis.c compat/imsg.c compat/imsg-buffer.c
libproto_la_SOURCES = proto/protos.h proto/tlv.c proto/tlv.h \
	proto/lldp.c proto/lldp.h \
	proto/cdp.c proto/cdp.h \
	proto/edp.c proto/edp.h \
	proto/fdp.c proto/fdp.h \
	proto/ndp.c proto/ndp.h
libmisc_la_SOURCES = $(common_headers) child.h child.c parent.h parent.c \
	cli.h cli.c util.c sysinfo.c netif.c

sbin_PROGRAMS = ladvd
ladvd_SOURCES = $(common_headers) main.h main.c
ladvd_LDADD = $(noinst_LTLIBRARIES) $(EVENT_LIB) $(PCAP_LIB) $(PCI_LIBS) \
	$(CAPNG_LDADD) $(CAP_LDADD) $(LIBMNL_LIBS) $(LIBTEAM_LIBS)

install-exec-hook:
	$(LN_S) @PACKAGE_NAME@$(EXEEXT) \
	    $(DESTDIR)$(sbindir)/@PACKAGE_CLI@$(EXEEXT)

