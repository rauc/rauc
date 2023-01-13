sphinx = find_program('sphinx-build', required: false)

if not sphinx.found()
  subdir_done()
endif

custom_target(
  'doc',
  output: 'html',
  command: [sphinx, '-b', 'html', meson.current_source_dir(), meson.current_build_dir() / 'html'],
  build_by_default: false
)
