SUBDIRS = src
dist_doc_DATA = LICENSE doc/ChangeLog doc/README
man_MANS = doc/ladvd.8

EXTRA_DIST = doc/ladvd.8.in

doc/ladvd.8: doc/ladvd.8.in
	sed -e s/PACKAGE_USER/@PACKAGE_USER@/ < doc/ladvd.8.in > $@

