sphinx = find_program('sphinx-build', required: false)

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
  'reference.rst',
  'scenarios.rst',
  'terminology.rst',
  'updating.rst',
  'using.rst',
])

custom_target(
  'doc',
  output: 'html',
  depend_files: sources_doc,
  command: [sphinx, '-b', 'html', meson.current_source_dir(), meson.current_build_dir() / 'html'],
  build_by_default: false
)
