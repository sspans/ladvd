
dist_doc_DATA = LICENSE ChangeLog README TODO
man_MANS = ladvd.8 ladvdc.8

EXTRA_DIST = ladvd.8.in ladvdc.8.in

ladvd.8: ladvd.8.in
	sed -e s/PACKAGE_USER/@PACKAGE_USER@/ \
		< @top_srcdir@/doc/$@.in > $@
ladvdc.8: ladvdc.8.in
if HTTP_ENABLED
	sed -e 's/^HTTP_POST //' -e s/PACKAGE_USER/@PACKAGE_USER@/ \
		< @top_srcdir@/doc/$@.in > $@
else
	sed -e 's/^HTTP_POST .*/d' -e s/PACKAGE_USER/@PACKAGE_USER@/ \
		< @top_srcdir@/doc/$@.in > $@
endif

clean-local:
	-rm $(man_MANS)

