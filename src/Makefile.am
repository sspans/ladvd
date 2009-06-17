
AM_CFLAGS = $(WARN_CFLAGS)
AM_LDFLAGS = $(WARN_LDFLAGS)

common_headers = config.h common.h ether.h master.h util.h \
	compat/compat.h proto/protos.h

noinst_LTLIBRARIES = libcompat.la libproto.la libmisc.la
libcompat_la_SOURCES = config.h compat/compat.h \
	compat/strlcpy.c compat/strlcat.c compat/setproctitle.c
libproto_la_SOURCES = config.h proto/protos.h proto/tlv.h \
	proto/lldp.c proto/lldp.h \
	proto/cdp.c proto/cdp.h \
	proto/edp.c proto/edp.h \
	proto/fdp.c proto/fdp.h \
	proto/ndp.c proto/ndp.h
libmisc_la_SOURCES = $(common_headers) master.c \
	util.c sysinfo.c netif.c

sbin_PROGRAMS = ladvd
ladvd_SOURCES = $(common_headers) main.c main.h
ladvd_LDADD = $(noinst_LTLIBRARIES) $(EVENT_LIB) $(CAP_LIB)
