ircd_exe = executable(meson.project_name(),
  'main.c',
  include_directories: [librb_inc, base_inc],
  install: true,
  install_rpath: get_option('libdir'),
  link_with: [librb_lib, ircd_lib])
