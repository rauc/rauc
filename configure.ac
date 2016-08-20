#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([rauc], m4_esyscmd([./build-aux/git-version-gen .tarball-version]), [ejo@pengutronix.de])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

# Use subdir-object for single-Makefile build
# Use foreign to prevent warnings for missing files
# such as README, NEWS
AM_INIT_AUTOMAKE([1.11 subdir-objects foreign no-dist-gzip dist-xz])
AM_MAINTAINER_MODE([enable])
AM_SILENT_RULES([yes])
AC_REQUIRE_AUX_FILE([tap-driver.sh])

AX_IS_RELEASE([git-directory])
AX_CHECK_ENABLE_DEBUG([yes])

AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AX_COMPILER_FLAGS

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CC_C99
AM_PROG_CC_C_O
AC_CHECK_PROGS(CATCHSEGV, [catchsegv])

LT_PREREQ(2.2)
LT_INIT([disable-static])

AX_CODE_COVERAGE
AX_VALGRIND_CHECK

# Check for features.
AC_ARG_ENABLE([service],
	AS_HELP_STRING([--disable-service], [Disable background service])
)
AS_IF([test "x$enable_service" != "xno"], [
	AC_DEFINE([ENABLE_SERVICE], [1], [Define to 1 to enable background service])
], [
	AC_DEFINE([ENABLE_SERVICE], [0])
])

# Checks for libraries.
PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.40 gio-2.0 gio-unix-2.0])
PKG_CHECK_MODULES([CURL], [libcurl])
PKG_CHECK_MODULES([JSON_GLIB], [json-glib-1.0])

AX_CHECK_OPENSSL([],[AC_MSG_ERROR([OpenSSL not found])])

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_CONFIG_FILES([
	Makefile
	test/services/de.pengutronix.rauc.service
])
AC_OUTPUT
