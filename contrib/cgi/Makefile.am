ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_MAKEFLAGS = --no-print-directory
AUTOMAKE_OPTIONS = color-tests parallel-tests

EXTRA_DIST = $(top_srcdir)/.version
BUILT_SOURCES = $(top_srcdir)/.version
$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@
dist-hook:
	echo $(VERSION) > $(distdir)/.tarball-version

AM_CFLAGS = -DG_LOG_DOMAIN=\"rauc\" $(WARN_CFLAGS) $(GLIB_CFLAGS)
AM_LDFLAGS = $(WARN_LDFLAGS) $(GLIB_LDFLAGS)
AM_CPPFLAGS = -include ${top_builddir}/config.h

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


bin_PROGRAMS = rauc-cgi

dbuswrapperdir = $(libexecdir)

rauc_cgi_SOURCES = \
	rauc-installer-generated.h \
	rauc-installer-generated.c \
	src/cgi.c
rauc_cgi_CFLAGS = $(AM_CFLAGS) $(JSON_GLIB_CFLAGS)
rauc_cgi_LDFLAGS = $(AM_LDFLAGS) $(JSON_GLIB_LDFLAGS)
rauc_cgi_LDADD = $(JSON_GLIB_LIBS)


CLEANFILES = $(gdbus_installer_generated)
