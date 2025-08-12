sphinx = find_program('sphinx-build', required: get_option('htmldocs') or get_option('manpages'))

if not sphinx.found()
  subdir_done()
endif

sources_doc = files([
  'conf.py',
  'advanced.rst',
  'basic.rst',
  'changes.rst',
  'checklist.rst',
  'contributing.rst',
  'examples.rst',
  'faq.rst',
  'index.rst',
  'integration.rst',
  'man.rst',
  'reference.rst',
  'scenarios.rst',
  'terminology.rst',
  'updating.rst',
  'using.rst',
  '../CHANGES',
])

custom_target(
  'doc',
  output: 'html',
  depend_files: sources_doc,
  command: [sphinx, '-b', 'html', meson.current_source_dir(), meson.current_build_dir() / 'html'],
  build_by_default: get_option('htmldocs'),
  install_dir: join_paths(datadir, 'doc', 'rauc'),
  install: get_option('htmldocs'),
)

custom_target(
  'manpages',
  output: ['rauc.1'],
  depend_files: sources_doc,
  command: [sphinx, '-b', 'man', meson.current_source_dir(), '@OUTDIR@'],
  build_by_default: get_option('manpages'),
  install: get_option('manpages'),
  install_dir: join_paths(get_option('mandir'), 'man1'),
)
