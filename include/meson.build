configure_file(input: 'setup.h.meson',
  output: 'setup.h',
  configuration: cdata)

serno_h = custom_target(
  'serno.h',
  input: 'serno.h.SH',
  output: 'serno.h',
  command: ['sh', '@INPUT@', '@OUTPUT@']
)

base_inc = include_directories('.')
