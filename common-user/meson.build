if not have_user
   subdir_done()
endif

common_user_inc += include_directories('host/' / host_arch)

user_ss.add(files(
  'mmap-min-addr.c',
  'probe-guest-base.c',
  'safe-syscall.S',
  'safe-syscall-error.c',
  'selfmap.c',
))
