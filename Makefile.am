SUBDIRS = src
dist_doc_DATA = LICENSE doc/ChangeLog doc/README
dist_man_MANS = doc/ladvd.8

EXTRA_DIST = debian
dist-hook:
	rm -rf `find $(distdir)/debian -name .svn`

