#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([rauc], m4_esyscmd([./build-aux/git-version-gen .tarball-version]), [rauc@pengutronix.de])
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
AC_REQUIRE_AUX_FILE([git-version-gen])

AX_IS_RELEASE([git-directory])
AX_CHECK_ENABLE_DEBUG([yes])

AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AX_COMPILER_FLAGS

# Checks for programs.
AC_PROG_AWK
AC_PROG_MKDIR_P
AC_PROG_SED
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
	PKG_CHECK_MODULES([DBUS1], [dbus-1])
], [
	AC_DEFINE([ENABLE_SERVICE], [0])
])

# Checks for libraries.
PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.45.8 gio-2.0 gio-unix-2.0])

AC_ARG_ENABLE([network],
       AS_HELP_STRING([--disable-network], [Disable network update mode])
)
AM_CONDITIONAL([WANT_NETWORK], [test x$enable_network != xno])
AS_IF([test "x$enable_network" != "xno"], [
       AC_DEFINE([ENABLE_NETWORK], [1], [Define to 1 to enable building with network update support])
       PKG_CHECK_MODULES([CURL], [libcurl])
], [
       AC_DEFINE([ENABLE_NETWORK], [0])
])


AC_ARG_ENABLE([json],
       AS_HELP_STRING([--disable-json], [Disable JSON support])
)
AM_CONDITIONAL([WANT_JSON], [test x$enable_json != xno])
AS_IF([test "x$enable_json" != "xno"], [
       AC_DEFINE([ENABLE_JSON], [1], [Define to 1 to enable building with JSON support])
       PKG_CHECK_MODULES([JSON_GLIB], [json-glib-1.0])
], [
       AC_DEFINE([ENABLE_JSON], [0])
])


AX_CHECK_OPENSSL([],[AC_MSG_ERROR([OpenSSL not found])])

AC_ARG_WITH([systemdunitdir],
        AC_HELP_STRING([--with-systemdunitdir=DIR], [path to systemd service directory]),
        [],
        [with_systemdunitdir="$($PKG_CONFIG --variable=systemdsystemunitdir systemd)"])
if (test -n "${with_systemdunitdir}"); then
	SYSTEMD_UNITDIR="${with_systemdunitdir}"
	AC_SUBST(SYSTEMD_UNITDIR)
fi
AM_CONDITIONAL(SYSTEMD, test -n "${with_systemdunitdir}")

AC_ARG_WITH([dbuspolicydir],
        AS_HELP_STRING([--with-dbuspolicydir=DIR], [D-Bus policy directory]),
        [],
        [with_dbuspolicydir="$($PKG_CONFIG --variable=datadir dbus-1)/dbus-1/system.d"])
DBUS_POLICYDIR="${with_dbuspolicydir}"
AC_SUBST(DBUS_POLICYDIR)

AC_ARG_WITH([dbussystemservicedir],
        AS_HELP_STRING([--with-dbussystemservicedir=DIR], [D-Bus system service directory]),
        [],
        [with_dbussystemservicedir="$($PKG_CONFIG --variable=system_bus_services_dir dbus-1)"])
DBUS_SYSTEMSERVICEDIR="${with_dbussystemservicedir}"
AC_SUBST(DBUS_SYSTEMSERVICEDIR)

# Checks for header files.

AC_CHECK_HEADER([linux/mmc/ioctl.h],
	AC_DEFINE([ENABLE_EMMC_BOOT_SUPPORT], [1], [Define to 1 to enable eMMC boot support]),
	AC_DEFINE([ENABLE_EMMC_BOOT_SUPPORT], [0]))

AM_CONDITIONAL([WANT_EMMC_BOOT_SUPPORT], [test x$ac_cv_header_linux_mmc_ioctl_h != xno])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_CONFIG_LINKS([test/test.conf:test/test.conf])
AC_CONFIG_LINKS([test/test-global.conf:test/test-global.conf])
AC_CONFIG_LINKS([test/bin/postinstall.sh:test/bin/postinstall.sh])
AC_CONFIG_LINKS([test/bin/efibootmgr:test/bin/efibootmgr])
AC_CONFIG_LINKS([test/bin/fw_setenv:test/bin/fw_setenv])
AC_CONFIG_LINKS([test/bin/fw_printenv:test/bin/fw_printenv])
AC_CONFIG_LINKS([test/bin/grub-editenv:test/bin/grub-editenv])
AC_CONFIG_LINKS([test/bin/barebox-state:test/bin/barebox-state])
AC_CONFIG_LINKS([test/bin/preinstall.sh:test/bin/preinstall.sh])
AC_CONFIG_LINKS([test/bin/systeminfo.sh:test/bin/systeminfo.sh])
AC_CONFIG_LINKS([test/good-bundle.raucb:test/good-bundle.raucb])
AC_CONFIG_LINKS([test/manifest.raucm:test/manifest.raucm])
AC_CONFIG_LINKS([test/openssl-ca/manifest:test/openssl-ca/manifest])
AC_CONFIG_LINKS([test/openssl-ca/root/ca.cert.pem:test/openssl-ca/root/ca.cert.pem])
AC_CONFIG_LINKS([test/openssl-ca/root/private/ca.key.pem:test/openssl-ca/root/private/ca.key.pem])
AC_CONFIG_LINKS([test/openssl-ca/dev/autobuilder-1.cert.pem:test/openssl-ca/dev/autobuilder-1.cert.pem])
AC_CONFIG_LINKS([test/openssl-ca/dev/autobuilder-2.cert.pem:test/openssl-ca/dev/autobuilder-2.cert.pem])
AC_CONFIG_LINKS([test/openssl-ca/dev/private/autobuilder-1.pem:test/openssl-ca/dev/private/autobuilder-1.pem])
AC_CONFIG_LINKS([test/openssl-ca/dev/private/autobuilder-2.pem:test/openssl-ca/dev/private/autobuilder-2.pem])
AC_CONFIG_LINKS([test/openssl-ca/dev-ca.pem:test/openssl-ca/dev-ca.pem])
AC_CONFIG_LINKS([test/openssl-ca/dev-only-ca.pem:test/openssl-ca/dev-only-ca.pem])
AC_CONFIG_LINKS([test/openssl-ca/rel-ca.pem:test/openssl-ca/rel-ca.pem])
AC_CONFIG_LINKS([test/openssl-ca/provisioning-ca.pem:test/openssl-ca/provisioning-ca.pem])
AC_CONFIG_LINKS([test/openssl-ca/rel/release-1.cert.pem:test/openssl-ca/rel/release-1.cert.pem])
AC_CONFIG_LINKS([test/openssl-ca/rel/release-2018.cert.pem:test/openssl-ca/rel/release-2018.cert.pem])
AC_CONFIG_LINKS([test/openssl-ca/rel/private/release-1.pem:test/openssl-ca/rel/private/release-1.pem])
AC_CONFIG_LINKS([test/openssl-ca/rel/private/release-2018.pem:test/openssl-ca/rel/private/release-2018.pem])
AC_CONFIG_LINKS([test/openssl-ca/rel/ca.cert.pem:test/openssl-ca/rel/ca.cert.pem])
AC_CONFIG_LINKS([test/openssl-ca/manifest-r1.sig:test/openssl-ca/manifest-r1.sig])
AC_CONFIG_LINKS([test/openssl-ca/dir/a.cert.pem:test/openssl-ca/dir/a.cert.pem])
AC_CONFIG_LINKS([test/openssl-ca/dir/b.cert.pem:test/openssl-ca/dir/b.cert.pem])
AC_CONFIG_LINKS([test/openssl-ca/dir/private/a.key.pem:test/openssl-ca/dir/private/a.key.pem])
AC_CONFIG_LINKS([test/openssl-ca/dir/private/b.key.pem:test/openssl-ca/dir/private/b.key.pem])
AC_CONFIG_LINKS([test/openssl-ca/dir/hash/a/0c65607a.0:test/openssl-ca/dir/hash/a/0c65607a.0])
AC_CONFIG_LINKS([test/openssl-ca/dir/hash/ab/0c65607a.0:test/openssl-ca/dir/hash/ab/0c65607a.0])
AC_CONFIG_LINKS([test/openssl-ca/dir/hash/ab/2c846a75.0:test/openssl-ca/dir/hash/ab/2c846a75.0])
AC_CONFIG_LINKS([test/rauc.t:test/rauc.t])
AC_CONFIG_LINKS([test/rootfs.raucs:test/rootfs.raucs])
AC_CONFIG_LINKS([test/sharness.sh:test/sharness.sh])
AC_CONFIG_LINKS([test/install-content/appfs.img:test/install-content/appfs.img])
AC_CONFIG_LINKS([test/install-content/rootfs.img:test/install-content/rootfs.img])
AC_CONFIG_LINKS([test/install-content/hook.sh:test/install-content/hook.sh])
AC_CONFIG_LINKS([test/install-content/custom_handler.sh:test/install-content/custom_handler.sh])
AC_CONFIG_LINKS([test/install-content/manifest.raucm:test/install-content/manifest.raucm])

AC_CONFIG_FILES([
	Makefile
])
AC_OUTPUT
