
common_headers = common.h ether.h util.h

lib_LTLIBRARIES = libcompat.la libproto.la
libcompat_la_SOURCES = compat.h \
	compat/strlcpy.c compat/strlcat.c compat/setproctitle.c
libproto_la_SOURCES = $(common_headers) protos/tlv.h \
	proto/lldp.c protos/lldp.h \
	proto/cdp.c protos/cdp.h \
	proto/edp.c protos/edp.h \
	proto/fdp.c protos/fdp.h \
	proto/ndp.c protos/ndp.h

sbin_PROGRAMS = ladvd
ladvd_SOURCES = $(common_headers) main.c main.h \
		master.c master.h util.c sysinfo.c netif.c
ladvd_LDADD = $(lib_LTLIBRARIES) $(LIBOBJS) @CAP_LIBS@
