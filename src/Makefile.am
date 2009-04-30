
AM_CFLAGS = $(WARN_CFLAGS)
AM_LDFLAGS = $(WARN_LIBS)

common_headers = common.h ether.h master.h util.h

noinst_LTLIBRARIES = libcompat.la libproto.la libmisc.la
libcompat_la_SOURCES = compat.h \
	compat/strlcpy.c compat/strlcat.c compat/setproctitle.c
libproto_la_SOURCES = $(common_headers) protos/tlv.h \
	proto/lldp.c protos/lldp.h \
	proto/cdp.c protos/cdp.h \
	proto/edp.c protos/edp.h \
	proto/fdp.c protos/fdp.h \
	proto/ndp.c protos/ndp.h
libmisc_la_SOURCES = $(common_headers) master.c \
	util.c sysinfo.c netif.c

sbin_PROGRAMS = ladvd
ladvd_SOURCES = $(common_headers) main.c main.h
ladvd_LDADD = $(noinst_LTLIBRARIES) $(EVENT_LIB) $(CAP_LIB)
