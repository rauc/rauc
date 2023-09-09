if not get_option('fuzzing')
  subdir_done()
endif

fuzzers = [
  'manifest',
  'bundle',
]

fuzzer_c_args = [cc.get_supported_arguments('-Wno-missing-prototypes')]
fuzzer_link_args = []
fuzzer_extra_sources = []

have_cxx = add_languages('cpp', required : true)
cxx = meson.get_compiler('cpp')
fuzzing_engine = cxx.find_library('FuzzingEngine', required: false)
fuzzer_as_test = false
if not fuzzing_engine.found()
  if cxx.has_argument('-fsanitize=fuzzer')
    # clang has a built-in fuzzer
    fuzzer_c_args += '-fsanitize=fuzzer'
    fuzzer_link_args += '-fsanitize=fuzzer'
  else
    # otherwise we need to link our own
    fuzzer_extra_sources += 'localfuzzer.c'
    fuzzer_as_test = true
  endif
endif

foreach fuzzer_name : fuzzers
  exe = executable(
    fuzzer_name + '_fuzzer',
    fuzzer_name + '.c',
    fuzzer_extra_sources,
    c_args : fuzzer_c_args,
    link_args : fuzzer_link_args,
    link_with : librauc,
    include_directories : incdir,
    dependencies : [rauc_deps, fuzzing_engine])

  if fuzzer_as_test
    test(
      fuzzer_name + '_fuzzer',
      exe,
      args : files('manifest_fuzzer.dict'), # just to have some input
      suite : 'fuzzing',
    )
  endif
endforeach

summary({
  'cpp compiler': cxx.get_id(),
  'fuzzer_c_args' : fuzzer_c_args,
  'fuzzer_link_args' : fuzzer_link_args,
  'fuzzer_extra_sources' : fuzzer_extra_sources,
  'fuzzer_as_test' : fuzzer_as_test,
}, section: 'Fuzzing')
