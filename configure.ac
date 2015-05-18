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

# Checks for programs.
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE

AC_REQUIRE_AUX_FILE([tap-driver.sh])
AC_PROG_AWK

AC_PROG_CC
AC_PROG_CC_C99
AM_PROG_CC_C_O

AC_CHECK_PROGS([MKSQUASHFS], [mksquashfs])
if test -z "$MKSQUASHFS";
  then AC_MSG_ERROR([mksquashfs not found])
fi
AC_DEFINE_UNQUOTED([CMD_MKSQUASHFS], ["$MKSQUASHFS"], [Define to the path of the mksquashfs executable])
AC_CHECK_PROGS([UNSQUASHFS], [unsquashfs])
if test -z "$UNSQUASHFS";
  then AC_MSG_WARN([unsquashfs not found])
fi
AC_DEFINE_UNQUOTED([CMD_UNSQUASHFS], ["$UNSQUASHFS"], [Define to the path of the unsquashfs executable])

AX_IS_RELEASE([git-directory])
AX_COMPILER_FLAGS()

LT_PREREQ(2.2)
LT_INIT([disable-static])

AX_CODE_COVERAGE
AX_VALGRIND_CHECK

# Checks for libraries.
PKG_CHECK_MODULES([GLIB], [glib-2.0 gio-2.0])
PKG_CHECK_MODULES([CURL], [libcurl])

AX_CHECK_OPENSSL([],[AC_MSG_ERROR([OpenSSL not found])])

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
