.. _skiboot-6.0.15:

==============
skiboot-6.0.15
==============

skiboot 6.0.15 was released on Monday December 17th, 2018. It replaces
:ref:`skiboot-6.0.14` as the current stable release in the 6.0.x series.

It is recommended that 6.0.15 be used instead of any previous 6.0.x version
due to the bug fixes it contains.

Bug fixes included in this release are:

- i2c: Fix i2c request hang during opal init if timers are not checked

  If an i2c request cannot go through the first time, because the bus is
  found in error and need a reset or it's locked by the OCC for example,
  the underlying i2c implementation is using timers to manage the
  request. However during opal init, opal pollers may not be called, it
  depends in the context in which the i2c request is made. If the
  pollers are not called, the timers are not checked and we can end up
  with an i2c request which will not move foward and skiboot hangs.

  Fix it by explicitly checking the timers if we are waiting for an i2c
  request to complete and it seems to be taking a while.

- opal-prd: hservice: Enable hservice->wakeup() in BMC

  This patch enables HBRT to use HYP special wakeup register in openBMC
  which until now was only used in FSP based machines.

  This patch also adds a capability check for opal-prd so that HBRT can
  decide if the host special wakeup register can be used.

- npu2: Advertise correct TCE page size

  The P9 NPU workbook says that only 4K/64K/16M/256M page size are supported
  and in fact npu2_map_pe_dma_window() supports just these but in absence of
  the "ibm,supported-tce-sizes" property Linux assumes the default P9 PHB4
  page sizes - 4K/64K/2M/1G - so when Linux tries 2M/1G TCEs, we get lots of
  "Unexpected TCE size" from npu2_tce_kill().

  This advertises TCE page sizes so Linux could handle it correctly, i.e.
  fall back to 4K/64K TCEs.
