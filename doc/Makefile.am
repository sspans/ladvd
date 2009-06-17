
dist_doc_DATA = LICENSE ChangeLog README TODO
man_MANS = ladvd.8

EXTRA_DIST = ladvd.8.in

ladvd.8: ladvd.8.in
	sed -e s/PACKAGE_USER/@PACKAGE_USER@/ \
		< @top_srcdir@/doc/$@.in > $@

