
AM_CFLAGS = $(WARN_CFLAGS)
AM_LDFLAGS = $(WARN_LDFLAGS)

common_headers = config.h common.h ether.h filter.h util.h \
	compat/compat.h compat/sys-queue.h proto/protos.h

noinst_LTLIBRARIES = libmisc.la libcompat.la libproto.la
libcompat_la_SOURCES = config.h compat/compat.h compat/vis.h \
	compat/strlcpy.c compat/strlcat.c compat/setproctitle.c compat/vis.c
libproto_la_SOURCES = config.h proto/protos.h proto/tlv.h \
	proto/lldp.c proto/lldp.h \
	proto/cdp.c proto/cdp.h \
	proto/edp.c proto/edp.h \
	proto/fdp.c proto/fdp.h \
	proto/ndp.c proto/ndp.h
libmisc_la_SOURCES = $(common_headers) child.h child.c master.h master.c \
	util.c sysinfo.c netif.c

sbin_PROGRAMS = ladvd
ladvd_SOURCES = $(common_headers) main.h main.c cli.c
ladvd_LDADD = $(noinst_LTLIBRARIES) $(EVENT_LIB) $(CAP_LIB)

install-exec-hook:
	ln $(DESTDIR)$(sbindir)/@PACKAGE_NAME@$(EXEEXT) \
	    $(DESTDIR)$(sbindir)/@PACKAGE_CLI@$(EXEEXT)

