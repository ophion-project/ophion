ssld_exe = executable('ssld',
  'ssld.c',
  link_with: [librb_lib],
  install: true,
  install_rpath: get_option('libdir'),
  include_directories: [librb_inc, base_inc])
