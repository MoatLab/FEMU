gen = decodetree.process('insns.decode')

microblaze_common_ss = ss.source_set()
microblaze_common_ss.add(gen)
microblaze_common_ss.add(files(
  'cpu.c',
  'gdbstub.c',
  'helper.c',
  'op_helper.c',
  'translate.c',
))

microblaze_user_ss = ss.source_set()
microblaze_user_ss.add_all(microblaze_common_ss)

microblaze_common_system_ss = ss.source_set()
microblaze_common_system_ss.add_all(microblaze_common_ss)

microblaze_system_ss = ss.source_set()
microblaze_system_ss.add(files(
  'mmu.c',
  'machine.c',
))

target_user_arch += {'microblaze': microblaze_user_ss}
target_system_arch += {'microblaze': microblaze_system_ss}
target_common_system_arch += {'microblaze': microblaze_common_system_ss}
