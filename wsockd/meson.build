wsockd_exe = executable('wsockd',
  'wsockd.c',
  'sha1.c',
  link_with: [librb_lib],
  install: true,
  install_rpath: get_option('libdir'),
  include_directories: [librb_inc, base_inc])
