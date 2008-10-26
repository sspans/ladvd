sbin_PROGRAMS = ladvd
ladvd_SOURCES = common.h ether.h tlv.h main.c main.h util.c util.h \
		sysinfo.c netif.c \
		lldp.c lldp.h cdp.c cdp.h edp.c edp.h fdp.c fdp.h ndp.c ndp.h
ladvd_LDADD = $(LIBOBJS) @CAP_LIBS@
