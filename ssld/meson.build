ssld_exe = executable('ssld',
  'ssld.c',
  dependencies: [zlib_dep],
  link_with: [librb_lib],
  install: true,
  install_rpath: get_option('libdir'),
  include_directories: [librb_inc, base_inc])
