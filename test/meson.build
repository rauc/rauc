if not get_option('tests')
  subdir_done()
endif

tests = [
  'boot_raw_fallback',
  'bootchooser',
  'checksum',
  'config_file',
  'context',
  'dm',
  'event_log',
  'hash_index',
  'manifest',
  'signature',
  'update_handler',
  'utils',
  'install',
  'status_file',
  'bundle',
  'progress',
  'slot',
  'stats',
]

if get_option('service')
  tests += 'service'
endif

if get_option('network')
  tests += 'network'
endif

if get_option('streaming')
  tests += 'nbd'
endif

if jsonglibdep.found()
  tests += 'boot_switch'
endif

extra_test_sources = files([
  'common.c',
  'install_fixtures.c',
])

foreach test_name : tests
  exe = executable(
    test_name + '-test',
    test_name + '.c',
    extra_test_sources, dbus_sources,
    link_with : librauc,
    c_args : '-DTEST_SERVICES="' + meson.build_root() + '"',
    include_directories : incdir,
    install_mode : 'rwxr-xr-x',
    install : get_option('install-tests'),
    install_dir : get_option('libdir') / 'rauc' / 'tests',
    dependencies : rauc_deps)

  test(
    test_name,
    exe,
    is_parallel : false,
    timeout : 240,
    workdir : meson.source_root())
endforeach

fakerand = executable(
  'fakerand',
  'fakerand.c',
  install_mode : 'rwxr-xr-x',
  install : get_option('install-tests'),
  install_dir : get_option('libdir') / 'rauc' / 'tests',
)

rauc_t = find_program(
  'rauc.t'
)

test(
  'rauc.t',
  rauc_t,
  args : '-v',
  is_parallel : false,
  timeout : 360,
  env : ['SHARNESS_BUILD_DIRECTORY=' + meson.build_root()],
  workdir : meson.current_source_dir(),
)

install_data(
  meson.build_root() / 'config.h',
  install_dir: get_option('libdir') / 'rauc' / 'tests',
)

install_subdir(
  meson.source_root() / 'test',
  install_dir: get_option('libdir') / 'rauc' / 'tests',
)
