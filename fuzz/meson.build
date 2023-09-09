if not get_option('fuzzing')
  subdir_done()
endif

fuzzers = [
  'manifest',
  'bundle',
]

fuzzer_c_args = [cc.get_supported_arguments('-Wno-missing-prototypes')]
fuzzer_link_args = []

have_cxx = add_languages('cpp', required : true)
cxx = meson.get_compiler('cpp')
fuzzing_engine = cxx.find_library('FuzzingEngine', required: false)
if not fuzzing_engine.found()
  fuzzer_c_args += '-fsanitize=fuzzer'
  fuzzer_link_args += '-fsanitize=fuzzer'
endif

foreach fuzzer_name : fuzzers
  exe = executable(
    fuzzer_name + '_fuzzer',
    fuzzer_name + '.c',
    c_args : fuzzer_c_args,
    link_args : fuzzer_link_args,
    link_with : librauc,
    include_directories : incdir,
    dependencies : [rauc_deps, fuzzing_engine])
endforeach

summary({
  'cpp compiler': cxx.get_id(),
  'fuzzer_c_args' : fuzzer_c_args,
  'fuzzer_link_args' : fuzzer_link_args,
}, section: 'Fuzzing')
