mkpasswd_exe = executable(meson.project_name() + '-mkpasswd',
  'mkpasswd.c',
  link_with: [librb_lib],
  install: true,
  install_rpath: get_option('libdir'),
  include_directories: [librb_inc])

mkfingerprint_exe = executable(meson.project_name() + '-mkfingerprint',
  'mkfingerprint.c',
  link_with: [librb_lib, ircd_lib],
  install: true,
  install_rpath: get_option('libdir'),
  include_directories: [librb_inc, base_inc])
