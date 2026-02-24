# Cylon CXL-SSD and cache (cylon/); shared FTL (ftl/); BBSSD (bbssd/)
cylon_sources = files(
  'cylon/cxlssd.c',
  'cylon/ftl_thread.c',
  'cylon/der_kvm.c',
  'cylon/cache/cache.c',
  'cylon/cache/policy/cache_policy_registry.c',
  'cylon/cache/policy/fifo.c',
  'cylon/cache/policy/lifo.c',
  'cylon/cache/policy/clock.c',
  'cylon/cache/policy/s3fifo.c',
)
system_ss.add(when: 'CONFIG_FEMU_PCI', if_true: files(
  'dma.c', 'intr.c', 'nvme-util.c', 'nvme-admin.c', 'nvme-io.c', 'femu.c',
  'nossd/nop.c', 'nand/nand.c', 'timing-model/timing.c', 'ocssd/oc12.c', 'ocssd/oc20.c', 'zns/zns.c',
  'ftl/ftl.c', 'bbssd/bb.c', 'bbssd/ftl_thread.c',
  'lib/pqueue.c', 'lib/rte_ring.c', 'backend/dram.c'
) + cylon_sources)
