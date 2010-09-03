
dist_doc_DATA = LICENSE ChangeLog README TODO HACKING
man_MANS = ladvd.8 ladvdc.8

EXTRA_DIST = ladvd.8.in ladvdc.8.in

ladvd.8: ladvd.8.in
	$(SED) -e s/PACKAGE_USER/@PACKAGE_USER@/ \
		< @top_srcdir@/doc/$@.in > $@
ladvdc.8: ladvdc.8.in
if HTTP_ENABLED
	$(SED) -e 's/^HTTP_POST //' -e s/PACKAGE_USER/@PACKAGE_USER@/ \
		< @top_srcdir@/doc/$@.in > $@
else
	$(SED) -e '/^HTTP_POST .*/d' -e s/PACKAGE_USER/@PACKAGE_USER@/ \
		< @top_srcdir@/doc/$@.in > $@
endif

clean-local:
	-rm $(man_MANS)

