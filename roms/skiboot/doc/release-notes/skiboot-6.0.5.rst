.. _skiboot-6.0.5:

=============
skiboot-6.0.5
=============

skiboot 6.0.5 was released on Wednesday July 11th, 2018. It replaces
:ref:`skiboot-6.0.4` as the current stable release in the 6.0.x series.

It is recommended that 6.0.5 be used instead of any previous 6.0.x version.

Over :ref:`skiboot-6.0.4` we have several bug fixes, including important ones
for NVLINK2 and NX.

PCI/PHB4
========

- phb4: Delay training till after PERST is deasserted

  This helps some cards train on the second PERST (ie fast-reboot). The
  reason is not clear why but it helps, so YOLO!
- pci: Fix PCI_DEVICE_ID()

  The vendor ID is 16 bits not 8. This error leaves the top of the vendor
  ID in the bottom bits of the device ID, which resulted in e.g. a failure
  to run the PCI quirk for the AST VGA device.

  Fixes: 2b841bf0ef1b (present in v5.7-rc1)

PHB4/CAPI
=========
- phb4/capp: Calculate STQ/DMA read engines based on link-width for PEC

  Presently in CAPI mode the number of STQ/DMA-read engines allocated on
  PEC2 for CAPP is fixed to 6 and 0-30 respectively irrespective of the
  PCI link width. These values are only suitable for x8 cards and
  quickly run out if a x16 card is plugged to a PEC2 attached slot. This
  usually manifests as CAPP reporting TLBI timeout due to these messages
  getting stalled due to insufficient STQs.

  To fix this we update enable_capi_mode() to check if PEC2 chiplet is
  in x16 mode and if yes then we allocate 4/0-47 STQ/DMA-read engines
  for the CAPP traffic.
- capi: Select the correct IODA table entry for the mbt cache.

  With the current code, the capi mmio window is not correctly configured
  in the IODA table entry. The first entry (generally the non-prefetchable
  BAR) is overwrriten.
  This patch sets the capi window bar at the right place.

Sensors
=======

- occ: sensors: Fix the size of the phandle array 'sensors' in DT

  Fixes: 99505c03f493 (present in v5.10-rc4)

NPU2/NVLINK2
============

- npu2/hw-procedures: Fence bricks via NTL instead of MISC

  There are a couple of places we can set/unset fence for a brick:

  1. MISC register: NPU2_MISC_FENCE_STATE
  2. NTL register for the brick: NPU2_NTL_MISC_CFG1(ndev)

  Recent testing of ATS in combination with GPU reset has exposed a side
  effect of using (1); if fence is set for all six bricks, it triggers a
  sticky nmmu latch which prevents the NPU from getting ATR responses.
  This manifests as a hang in the tests.

  We have npu2_dev_fence_brick() which uses (1), and only two calls to it.
  Replace the call which sets fence with a write to (2). Remove the
  corresponding unset call entirely. It's unneeded because the procedures
  already do a progression from full fence to half to idle using (2).
- opal/hmi: Display correct chip id while printing NPU FIRs.

  HMIs for NPU xstops are broadcasted to all chips. All cores on all the
  chips receive HMI. HMI handler correctly identifies and extracts the
  NPU FIR details from affected chip, but while printing FIR data it
  prints chip id and location code details of this_cpu()->chip_id which
  may not be correct. This patch fixes this issue.

  Fixes: 7bcbc78c (present in v6.0.1)

VPD
===

- vpd: Add vendor property to processor node

  Processor FRU vpd doesn't contain vendor detail. We have to parse
  module VPD to get vendor detail.
- vpd: Sanitize VPD data

  On OpenPower system, VPD keyword size tells us the maximum size of the data.
  But they fill trailing end with space (0x20) instead of NULL. Also spec
  doesn't stop user to have space (0x20) within actual data.

  This patch discards trailing spaces before populating device tree.

NX/VAS for POWER9
=================

- NX: Add NX coprocessor init opal call

  The read offset (4:11) in Receive FIFO control register is incremented
  by FIFO size whenever CRB read by NX. But the index in RxFIFO has to
  match with the corresponding entry in FIFO maintained by VAS in kernel.
  VAS entry is reset to 0 when opening the receive window during driver
  initialization. So when NX842 is reloaded or in kexec boot, possibility
  of mismatch between RxFIFO control register and VAS entries in kernel.
  It could cause CRB failure / timeout from NX.

  This patch adds nx_coproc_init opal call for kernel to initialize
  readOffset (4:11) and Queued (15:23) in RxFIFO control register.

  Fixes: 3b3c5962f432 (present in v5.8-rc1)
