ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_MAKEFLAGS = --no-print-directory
AUTOMAKE_OPTIONS = color-tests parallel-tests

@CODE_COVERAGE_RULES@
@VALGRIND_CHECK_RULES@

TEST_LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) $(top_srcdir)/build-aux/tap-driver.sh
TEST_LOG_COMPILER = $(top_srcdir)/tap-test

AM_CFLAGS = $(WARN_CFLAGS) $(GLIB_CFLAGS)
AM_LDFLAGS = $(WARN_LDFLAGS)
AM_CPPFLAGS = -I${top_srcdir}/include

noinst_LTLIBRARIES = librauc.la

librauc_la_SOURCES = src/config_file.c
librauc_la_CFLAGS = $(AM_CFLAGS) $(CODE_COVERAGE_CFLAGS)
librauc_la_LDFLAGS = $(AM_LDFLAGS) $(CODE_COVERAGE_LDFLAGS)
librauc_la_LIBADD = $(GLIB_LIBS)

bin_PROGRAMS = rauc

rauc_SOURCES = \
	src/main.c
rauc_CFLAGS = $(AM_CFLAGS) $(CODE_COVERAGE_CFLAGS)
rauc_LDFLAGS = $(AM_LDFLAGS) $(CODE_COVERAGE_LDFLAGS)
rauc_LDADD = $(GLIB_LIBS) librauc.la

check_PROGRAMS = test/config_file.test

TESTS = rauc $(check_PROGRAMS)

test_config_file_test_SOURCES = test/config_file.c
test_config_file_test_LDADD = librauc.la
