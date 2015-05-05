ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_MAKEFLAGS = --no-print-directory
AUTOMAKE_OPTIONS = color-tests parallel-tests

@CODE_COVERAGE_RULES@
@VALGRIND_CHECK_RULES@

TEST_LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) $(top_srcdir)/build-aux/tap-driver.sh
TEST_LOG_COMPILER = $(top_srcdir)/tap-test

AM_CFLAGS = $(WARN_CFLAGS) $(GLIB_CFLAGS) $(CURL_CFLAGS)
AM_LDFLAGS = $(WARN_LDFLAGS) $(GLIB_LDFLAGS) $(CURL_LDFLAGS) $(OPENSSL_LDFLAGS)
AM_CPPFLAGS = -I${top_srcdir}/include $(OPENSSL_INCLUDES)

noinst_LTLIBRARIES = librauc.la

librauc_la_SOURCES = \
	src/bundle.c \
	src/checksum.c \
	src/config_file.c \
	src/context.c \
	src/install.c \
	src/manifest.c \
	src/mount.c \
	src/network.c \
	src/signature.c \
	src/utils.c
librauc_la_CFLAGS = $(AM_CFLAGS) $(CODE_COVERAGE_CFLAGS)
librauc_la_LDFLAGS = $(AM_LDFLAGS) $(CODE_COVERAGE_LDFLAGS)
librauc_la_LIBADD = $(GLIB_LIBS) $(CURL_LIBS) $(OPENSSL_LIBS)

bin_PROGRAMS = rauc

rauc_SOURCES = \
	src/main.c src/install.c
rauc_CFLAGS = $(AM_CFLAGS) $(CODE_COVERAGE_CFLAGS)
rauc_LDFLAGS = $(AM_LDFLAGS) $(CODE_COVERAGE_LDFLAGS)
rauc_LDADD = $(librauc_la_LIBADD) librauc.la

check_PROGRAMS = \
	test/checksum.test \
	test/config_file.test \
	test/signature.test \
	test/install.test \
	test/network.test \
	test/bundle.test

TESTS = $(check_PROGRAMS)

test_bundle_test_SOURCES = test/bundle.c
test_bundle_test_LDADD = librauc.la

test_checksum_test_SOURCES = test/checksum.c
test_checksum_test_LDADD = librauc.la

test_config_file_test_SOURCES = test/config_file.c
test_config_file_test_LDADD = librauc.la

test_signature_test_SOURCES = test/signature.c
test_signature_test_LDADD = librauc.la

test_install_test_SOURCES = test/install.c
test_install_test_LDADD = librauc.la

test_network_test_SOURCES = test/network.c
test_network_test_LDADD = librauc.la
