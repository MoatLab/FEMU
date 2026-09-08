# FEMU's own tests.
#
# Declared here rather than in QEMU's tests/ tree so that everything FEMU adds
# lives under hw/femu/ and rebasing onto a newer QEMU stays a matter of moving
# one directory. The root meson.build reaches this with a single subdir() call,
# placed after qemuutil is declared because these link against it.

femu_unit_tests = {
  'test-femu-nand-media': files('unit/test-nand-media.c',
                                '../nand/nand-media.c'),
  'test-femu-pqueue': files('unit/test-pqueue.c', '../lib/pqueue.c'),
}

foreach test_name, test_src : femu_unit_tests
  exe = executable(test_name, test_src, genh, dependencies: [qemuutil])
  test(test_name, exe,
       env: test_env,
       args: ['--tap', '-k'],
       protocol: 'tap',
       timeout: 30,
       suite: ['unit'])
endforeach
