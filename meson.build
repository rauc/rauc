project(
  'rauc',
  'c',
  version : '1.10.1',
  meson_version : '>=0.51',
  default_options: [
    'c_std=gnu11',
    'warning_level=2',
  ],
  license : 'LGPL-2.1-or-later',
)

cc = meson.get_compiler('c')

conf = configuration_data()
conf.set_quoted('PACKAGE_NAME', 'rauc')
conf.set_quoted('STREAMING_USER', get_option('streaming_user'))

prefixdir = get_option('prefix')
if not prefixdir.startswith('/')
        error('Prefix is not absolute: "@0@"'.format(prefixdir))
endif
bindir = join_paths(prefixdir, get_option('bindir'))
conf.set('bindir', bindir)
libexecdir = join_paths(prefixdir, get_option('libexecdir'))
conf.set('libexecdir', libexecdir)

glibdep = dependency('glib-2.0', version : '>=2.56')

# Sanity checks to not use new glib methods unintentionally.
# package check, minimum and maximum required version must be updated
# explicitly when using newer glib APIs
c_flags = [
  '-DGLIB_VERSION_MAX_ALLOWED=G_ENCODE_VERSION(2,56)',
  '-DGLIB_VERSION_MIN_REQUIRED=G_ENCODE_VERSION(2,56)'
]

giodep = dependency('gio-2.0', version : '>=2.56')
giounixdep = dependency('gio-unix-2.0', version : '>=2.56')
openssldep = dependency('openssl', version : '>=1.1.1')
jsonglibdep = dependency('json-glib-1.0', required : get_option('json'))
dbusdep = dependency('dbus-1', required : get_option('service'))
fdiskdep = dependency('fdisk', version : '>=2.29', required : get_option('gpt'))
libcurldep = dependency('libcurl', version : '>=7.32.0', required : get_option('network'))
libnlgenldep = dependency('libnl-genl-3.0', version : '>=3.1', required : get_option('streaming'))
threaddep = dependency('threads', required : get_option('streaming'))
systemddep = dependency('systemd', required : false)

conf.set10('ENABLE_SERVICE', get_option('service'))
conf.set10('ENABLE_CREATE', get_option('create'))
conf.set10('ENABLE_JSON', jsonglibdep.found())

c_warn_flags = '''
  -Wundef
  -Wnested-externs
  -Wwrite-strings
  -Wpointer-arith
  -Wmissing-declarations
  -Wmissing-prototypes
  -Wstrict-prototypes
  -Wredundant-decls
  -Wno-unused-parameter
  -Wno-missing-field-initializers
  -Wdeclaration-after-statement
  -Wformat=2
  -Wold-style-definition
  -Wcast-align
  -Wformat-nonliteral
  -Wformat-security
  -Wsign-compare
  -Wstrict-aliasing
  -Wshadow
  -Winline
  -Wpacked
  -Wmissing-format-attribute
  -Wmissing-noreturn
  -Winit-self
  -Wmissing-include-dirs
  -Wunused-but-set-variable
  -Warray-bounds
  -Wimplicit-function-declaration
  -Wreturn-type
  -Wswitch-enum
  -Wswitch-default
  -Wno-error=unused-parameter
  -Wno-error=missing-field-initializers
'''.split()
# To allow building against OpenSSL 3.0, we still need to allow deprecated
# declarations
c_warn_flags += '-Wno-error=deprecated-declarations'
c_flags += cc.get_supported_arguments(c_warn_flags)
c_flags += ['-fdata-sections', '-ffunction-sections', '-fno-strict-aliasing']
ld_flags = ['-Wl,--gc-sections', '-Wl,-Map,$@.map']
add_project_arguments(c_flags, language : 'c')
add_project_link_arguments(ld_flags, language : 'c')
# set logging domain to 'rauc'
add_project_arguments('-DG_LOG_DOMAIN="rauc"', language : 'c')
# enable GNU extensions (required!)
add_project_arguments('-D_GNU_SOURCE', language : 'c')

incdir = include_directories('include')

sources_rauc = files([
  'src/bootchooser.c',
  'src/bundle.c',
  'src/checksum.c',
  'src/config_file.c',
  'src/context.c',
  'src/crypt.c',
  'src/dm.c',
  'src/emmc.c',
  'src/hash_index.c',
  'src/install.c',
  'src/manifest.c',
  'src/mark.c',
  'src/mbr.c',
  'src/mount.c',
  'src/service.c',
  'src/signature.c',
  'src/stats.c',
  'src/status_file.c',
  'src/slot.c',
  'src/update_handler.c',
  'src/update_utils.c',
  'src/utils.c',
  'src/verity_hash.c',
])

conf.set10('ENABLE_NETWORK', get_option('network'))
if get_option('network')
  sources_rauc += files('src/network.c')
endif

if (get_option('streaming') and not get_option('network'))
  error('streaming support requested but network support not enabled')
endif
conf.set10('ENABLE_STREAMING', get_option('streaming'))
if get_option('streaming')
  if not cc.has_header('linux/nbd-netlink.h')
    error('streaming support requested but linux/nbd-netlink.h not found')
  endif
  sources_rauc += files('src/nbd.c')
endif

conf.set10('ENABLE_EMMC_BOOT_SUPPORT', cc.has_header('linux/mmc/ioctl.h'))

conf.set10('ENABLE_GPT', fdiskdep.found())
if fdiskdep.found()
  sources_rauc += files('src/gpt.c')
endif

gnome = import('gnome')
dbus_ifaces = files('src/de.pengutronix.rauc.Installer.xml')
dbus_sources = gnome.gdbus_codegen(
  'rauc-installer-generated',
  sources : dbus_ifaces,
  interface_prefix : 'de.pengutronix.rauc.',
  namespace : 'R',
  install_header : true,
)

config_h = configure_file(
  output : 'config.h',
  configuration : conf
)
add_project_arguments('-include', meson.current_build_dir() / 'config.h', language : 'c')

version_h = vcs_tag(
  input : 'version.h.in',
  output : 'version.h',
)
versiondep = declare_dependency(sources: version_h)

meson.add_dist_script('version-gen', meson.project_version())

rauc_deps = [threaddep, libcurldep, libnlgenldep, jsonglibdep, dbusdep, glibdep, giodep, giounixdep, openssldep, fdiskdep]

librauc = static_library('rauc',
  sources_rauc,
  dbus_sources,
  include_directories : incdir,
  c_args : ['-include', meson.current_build_dir() / 'version.h'],
  dependencies : rauc_deps + [versiondep],
  )

executable('rauc',
  'src/main.c',
  dbus_sources,
  include_directories : incdir,
  c_args : ['-include', meson.current_build_dir() / 'version.h'],
  dependencies : rauc_deps + [versiondep],
  link_with : librauc,
  install : true)

systemdunitdir = get_option('systemdunitdir')
if systemdunitdir == ''
  if systemddep.found()
    systemdunitdir = systemddep.get_variable(pkgconfig : 'systemdsystemunitdir')
  endif
endif

datadir = get_option('datadir')

dbussystemservicedir = get_option('dbussystemservicedir')
if dbussystemservicedir == ''
  dbussystemservicedir = datadir / 'dbus-1' / 'system-services'
  if dbusdep.found()
    dbussystemservicedir = dbusdep.get_variable(pkgconfig : 'system_bus_services_dir', default_value : dbussystemservicedir)
  endif
endif

dbuspolicydir = get_option('dbuspolicydir')
if dbuspolicydir == ''
  dbuspolicydir = datadir / 'dbus-1' / 'system.d'
endif

dbusinterfacesdir = get_option('dbusinterfacesdir')
if dbusinterfacesdir == ''
  dbusinterfacesdir = datadir / 'dbus-1' / 'interfaces'
  if dbusdep.found()
    dbusinterfacesdir = dbusdep.get_variable(pkgconfig: 'interfaces_dir', default_value : dbusinterfacesdir)
  endif
endif

dbuswrapperdir = get_option('libexecdir')

install_data('src/de.pengutronix.rauc.Installer.xml', install_dir : dbusinterfacesdir)

install_data('rauc.1', install_dir : get_option('mandir'))

subdir('data')
subdir('docs')
subdir('test')
