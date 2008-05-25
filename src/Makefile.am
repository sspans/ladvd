AM_CPPFLAGS = @NET_CFLAGS@
sbin_PROGRAMS = ladvd
ladvd_SOURCES = main.c main.h ifinfo.c cdp.c cdp.h lldp.c lldp.h tlv.h
ladvd_LDADD = $(LIBOBJS) @NET_LIBS@ @CAP_LIBS@
