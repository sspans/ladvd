ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src . tests
dist_doc_DATA = LICENSE doc/ChangeLog doc/README
man_MANS = doc/ladvd.8

EXTRA_DIST = doc/ladvd.8.in

doc/ladvd.8: doc/ladvd.8.in
	sed -e s/PACKAGE_USER/@PACKAGE_USER@/ < doc/ladvd.8.in > $@

if GCOV_ENABLED
lcov-reset:
	lcov -d @top_srcdir@/src --zerocounters

lcov-report:
	lcov -b @top_srcdir@/src -d @top_srcdir@/src --capture \
		--no-checksum --output-file @top_builddir@/lcov.info.tmp
	lcov -b @top_srcdir@/src -d @top_srcdir@/src \
		--output-file @top_builddir@/lcov.info \
		--remove @top_builddir@/lcov.info.tmp
	rm @top_builddir@/lcov.info.tmp
	$(mkdir_p) @top_builddir@/lcov
	revision=`svnversion | cut -f1 -d:`;\
	genhtml --title "@PACKAGE_STRING@ $$revision" \
		--output-directory @top_builddir@/lcov lcov.info
	@echo
	@echo 'lcov report can be found in:'
	@echo 'file://@abs_top_builddir@/lcov/index.html'
	@echo

lcov-check:
	$(MAKE) lcov-reset
	$(MAKE) check
	$(MAKE) lcov-report
endif

