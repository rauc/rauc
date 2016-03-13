ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_MAKEFLAGS = --no-print-directory
AUTOMAKE_OPTIONS = color-tests parallel-tests

EXTRA_DIST = $(top_srcdir)/.version
BUILT_SOURCES = $(top_srcdir)/.version
$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@
dist-hook:
	echo $(VERSION) > $(distdir)/.tarball-version

CODE_COVERAGE_IGNORE_PATTERN = "*-generated.c"
@CODE_COVERAGE_RULES@
@VALGRIND_CHECK_RULES@

AM_CFLAGS = $(WARN_CFLAGS) $(GLIB_CFLAGS) $(CURL_CFLAGS)
AM_LDFLAGS = $(WARN_LDFLAGS) $(GLIB_LDFLAGS) $(CURL_LDFLAGS) $(OPENSSL_LDFLAGS)
AM_CPPFLAGS = -I${top_srcdir}/include $(OPENSSL_INCLUDES)

gdbus_installer_generated = \
	rauc-installer-generated.c \
	rauc-installer-generated.h

BUILT_SOURCES += $(gdbus_installer_generated)
EXTRA_DIST += src/rauc-installer.xml

$(gdbus_installer_generated): src/rauc-installer.xml
	$(AM_V_GEN) gdbus-codegen \
		--generate-c-code rauc-installer-generated \
		--c-namespace R \
		--interface-prefix de.pengutronix.rauc. \
		$<

noinst_LTLIBRARIES = librauc.la

librauc_la_SOURCES = \
	src/bootchooser.c \
	src/bundle.c \
	src/checksum.c \
	src/config_file.c \
	src/context.c \
	src/install.c \
	src/manifest.c \
	src/mount.c \
	src/network.c \
	src/service.c \
	src/signature.c \
	src/utils.c
nodist_librauc_la_SOURCES = \
	$(gdbus_installer_generated)
librauc_la_CFLAGS = $(AM_CFLAGS) $(CODE_COVERAGE_CFLAGS)
librauc_la_LDFLAGS = $(AM_LDFLAGS) $(CODE_COVERAGE_LDFLAGS)
librauc_la_LIBADD = $(GLIB_LIBS) $(CURL_LIBS) $(OPENSSL_LIBS)

bin_PROGRAMS = rauc

rauc_SOURCES = \
	src/main.c
rauc_CFLAGS = $(AM_CFLAGS) $(CODE_COVERAGE_CFLAGS)
rauc_LDFLAGS = $(AM_LDFLAGS) $(CODE_COVERAGE_LDFLAGS)
rauc_LDADD = $(librauc_la_LIBADD) librauc.la

AM_TESTS_ENVIRONMENT = \
	AM_TAP_AWK='$(AWK)'; export AM_TAP_AWK; \
	CATCHSEGV='$(CATCHSEGV)'; export CATCHSEGV;
TEST_EXTENSIONS = .t .test
T_LOG_DRIVER = $(top_srcdir)/build-aux/tap-driver.sh
T_LOG_COMPILER = $(top_srcdir)/tap-t
TEST_LOG_DRIVER = $(top_srcdir)/build-aux/tap-driver.sh
TEST_LOG_COMPILER = $(top_srcdir)/tap-test

check_PROGRAMS = \
	test/checksum.test \
	test/config_file.test \
	test/manifest.test \
	test/signature.test \
	test/install.test \
	test/network.test \
	test/service.test \
	test/bundle.test \
	test/progress.test
check_LTLIBRARIES = librauctest.la

librauctest_la_SOURCES = \
	test/common.c
librauctest_la_LIBADD = $(GLIB_LIBS)

TESTS = $(check_PROGRAMS) test/rauc.t

test_bundle_test_SOURCES = test/bundle.c
test_bundle_test_LDADD = librauc.la librauctest.la

test_checksum_test_SOURCES = test/checksum.c
test_checksum_test_LDADD = librauc.la

test_config_file_test_SOURCES = test/config_file.c
test_config_file_test_LDADD = librauc.la

test_manifest_test_SOURCES = test/manifest.c
test_manifest_test_LDADD = librauc.la

test_service_test_CFLAGS = $(AM_CFLAGS) -DTEST_SERVICES=\""$(abs_top_builddir)/test/services"\"
test_service_test_SOURCES = test/service.c
test_service_test_LDADD = librauctest.la librauc.la

test_signature_test_SOURCES = test/signature.c
test_signature_test_LDADD = librauctest.la librauc.la

test_install_test_SOURCES = test/install.c
test_install_test_LDADD = librauc.la librauctest.la

test_network_test_SOURCES = test/network.c
test_network_test_LDADD = librauc.la

test_progress_test_SOURCES = test/progress.c
test_progress_test_LDADD = librauc.la

SPHINXOPTS          =
SPHINXBUILD         = sphinx-build
PAPER               =
DOCDIR              = docs
SPHINXBUILDDIR      = $(DOCDIR)/build

.PHONY: check-valgrind check-valgrind-tool

doc:
	$(SPHINXBUILD) -b html $(ALLSPHINXOPTS) $(DOCDIR) $(SPHINXBUILDDIR)/html
	@echo
	@echo "Build finished. The HTML pages are in $(SPHINXBUILDDIR)/html."


CLEANFILES = $(gdbus_installer_generated)
