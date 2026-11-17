fsdev_ss = ss.source_set()
fsdev_ss.add(files('qemu-fsdev-opts.c', 'qemu-fsdev-throttle.c'))
fsdev_ss.add(when: ['CONFIG_FSDEV_9P'], if_true: files(
  '9p-iov-marshal.c',
  '9p-marshal.c',
  'qemu-fsdev.c',
))
if host_os in ['linux', 'darwin', 'freebsd']
  system_ss.add_all(fsdev_ss)
  stub_ss.add(files('qemu-fsdev-dummy.c'))
endif
