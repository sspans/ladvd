SUBDIRS = src
dist_doc_DATA = LICENSE doc/ChangeLog doc/README
dist_man_MANS = doc/ladvd.8

MAINTAINERCLEANFILES = $(dist_man_MANS)
EXTRA_DIST = debian doc/ladvd.8.in

dist-hook:
	rm -rf `find $(distdir)/debian -name .svn`

doc/ladvd.8: doc/ladvd.8.in
	sed -e s/PACKAGE_USER/@PACKAGE_USER@/ < doc/ladvd.8.in > $@

