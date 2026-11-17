bsd_syscall_nr = custom_target('bsd-syscall-h',
    output: '@BASENAME@_nr.h',
    input: ['/usr/include/sys/syscall.h'],
    command: [sh, meson.current_source_dir() / 'scripts/syscallhdr.sh', '@INPUT@', '@OUTPUT@', 'FREEBSD'])

bsd_user_ss.add(files(
  'os-stat.c',
  'os-proc.c',
  'os-sys.c',
  'os-syscall.c'),
  bsd_syscall_nr
)
