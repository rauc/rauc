#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([rauc], [2015.04.0], [ejo@pengutronix.de])

# Use subdir-object for single-Makefile build
# Use foreign to prevent warnings for missing files
# such as README, NEWS
AM_INIT_AUTOMAKE([subdir-objects foreign])


# Checks for programs.
AC_PROG_CC

# Checks for libraries.
PKG_CHECK_MODULES([RAUCDEPS], glib-2.0)

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_CONFIG_FILES(Makefile)
AC_OUTPUT
