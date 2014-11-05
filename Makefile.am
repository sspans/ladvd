ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src . doc systemd @TESTS_SUBDIR@

if TESTS_ENABLED

check-uml:
	-chmod +x @top_srcdir@/tests/uml/linux @top_srcdir@/tests/uml/uml.sh
	-@top_srcdir@/tests/uml/linux quiet mem=256M rootfstype=hostfs rw eth0=slirp,,/usr/bin/slirp-fullbolt init=@abs_srcdir@/tests/uml/uml.sh WORKDIR=$(abs_builddir)

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
	revision=`hg heads --template="{rev}" tip`;\
	genhtml --title "@PACKAGE_STRING@ - Rev $$revision" \
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
endif

