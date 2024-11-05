.. _skiboot-5.9.2:

=============
skiboot-5.9.2
=============

skiboot 5.9.2 was released on Thursday November 16th, 2017. It replaces
:ref:`skiboot-5.9.1` as the current stable release in the 5.9.x series.

Over :ref:`skiboot-5.9.1`, we have a few PHB4 (PCI) fixes, an i2c fix for
POWER9 platforms to avoid conflicting with the OCC use and an important
NPU2 (NVLink2) fix.

- phb4: Fix lane equalisation setting

  Fix cut and paste from phb3. The sizes have changes now we have GEN4,
  so the check here needs to change also

  Without this we end up with the default settings (all '7') rather
  than what's in HDAT.

- phb4: Fix PE mapping of M32 BAR

  The M32 BAR is the PHB4 region used to map all the non-prefetchable
  or 32-bit device BARs. It's supposed to have its segments remapped
  via the MDT and Linux relies on that to assign them individual PE#.

  However, we weren't configuring that properly and instead used the
  mode where PE# == segment#, thus causing EEH to freeze the wrong
  device or PE#.
- phb4: Fix lost bit in PE number on config accesses

  A PE number can be up to 9 bits, using a uint8_t won't fly..

  That was causing error on config accesses to freeze the
  wrong PE.
- phb4: Update inits

  New init value from HW folks for the fence enable register.

  This clears bit 17 (CFG Write Error CA or UR response) and bit 22 (MMIO Write
  DAT_ERR Indication) and sets bit 21 (MMIO CFG Pending Error)
- npu2: Move to new GPU memory map

  There are three different ways we configure the MCD and memory map.

  1) Old way (current way)
     Skiboot configures the MCD and puts GPUs at 4TB and below
  2) New way with MCD
     Hostboot configures the MCD and skiboot puts GPU at 4TB and above
  3) New way without MCD
     No one configures the MCD and skiboot puts GPU at 4TB and below

  The change keeps option 1 and adds options 2 and 3.

  The different configurations are detected using certain scoms (see
  patch).

  Option 1 will go away eventually as it's a configuration that can
  cause xstops or data integrity problems. We are keeping it around to
  support existing hostboot.

  Option 2 supports only 4 GPUs and 512GB of memory per socket.

  Option 3 supports 6 GPUs and 4TB of memory but may have some
  performance impact.

- p8-i2c: Don't write the watermark register at init

  On P9 the I2C master is shared with the OCC. Currently the watermark
  values are set once at init time which is bad for two reasons:

  a) We don't take the OCC master lock before setting it. Which
     may cause issues if the OCC is currently using the master.
  b) The OCC might change the watermark levels and we need to reset
     them.

  Change this so that we set the watermark value when a new transaction
  is started rather than at init time.

