if not get_option('fuzzing')
  subdir_done()
endif

fuzzers = [
  'manifest',
  'bundle',
]

foreach fuzzer_name : fuzzers
  exe = executable(
    fuzzer_name + '_fuzzer',
    fuzzer_name + '.c',
    extra_test_sources,
    c_args : ['-fsanitize=fuzzer,address'],
    link_args : ['-fsanitize=fuzzer,address'],
    link_with : librauc,
    include_directories : incdir,
    dependencies : rauc_deps)
endforeach
