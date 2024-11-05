.. _skiboot-5.4.0-rc2:

=================
skiboot-5.4.0-rc2
=================

skiboot-5.4.0-rc2 was released on Wednesday October 26th 2016. It is the
second release candidate of skiboot 5.4, which will become the new stable
release of skiboot following the 5.3 release, first released August 2nd 2016.

skiboot-5.4.0-rc2 contains all bug fixes as of :ref:`skiboot-5.3.7`
and :ref:`skiboot-5.1.18` (the currently maintained stable releases).

For how the skiboot stable releases work, see :ref:`stable-rules` for details.

Since this is a release candidate, it should *NOT* be put into production.

The current plan is to release a new release candidate every week until we
feel good about it. The aim is for skiboot-5.4.x to be in op-build v1.13, which
is due by November 23rd 2016.

Over :ref:`skiboot-5.4.0-rc1`, we have a few changes:

Secure and Trusted Boot
=======================

skiboot 5.4.0-rc2 improves upon the progress towards Secure and Trusted Boot
in rc1. It is important to note that this is *not* a complete, end-to-end
secure/trusted boot implementation.

With the current code, it is now possible to verify and measure resources
loaded from PNOR by skiboot (namely the CAPP and BOOTKERNEL partitions).

Note that this functionality is currently *only* available on systems that
use the libflash backend. It is *NOT* enabled on IBM FSP based systems.
There is some support for some simulators though.

- libstb/stb.c: ignore the secure mode flag unless forced in NVRAM

  For this stage in Trusted Boot development, we are wishing to not
  force Secure Mode through the whole firmware boot process, but we
  are wanting to be able to test it (classic chicken and egg problem with
  build infrastructure).

  We disabled secure mode if the secure-enabled devtree property is
  read from the device tree *IF* we aren't overriding it through NVRAM.
  Seeing as we can only increase (not decrease) what we're checking through
  the NVRAM variable, it is safe.

  The NVRAM setting is force-secure-mode=true in the ibm,skiboot partition.

  However, if you want to force secure mode even if Hostboot has *not* set
  the secure-enabled proprety in the device tree, set force-secure-mode
  to "always".

  There is also a force-trusted-mode NVRAM setting to force trusted mode
  even if Hostboot has not enabled it int the device tree.

  To indicate to Linux that we haven't gone through the whole firmware
  process in secure mode, we replace the 'secure-enabled' property with
  'partial-secure-enabled', to indicate that only part of the firmware
  boot process has gone through secure mode.


Command line arguments to BOOTKERNEL
====================================

- core/init.c: Fix bootargs parsing

  Currently the bootargs are unconditionally deleted, which causes
  a bug where the bootargs passed in by the device tree are lost.

  This patch deletes bootargs only if it needs to be replaced by the NVRAM
  entry.

  This patch also removes KERNEL_COMMAND_LINE config option in favour of
  using the NVRAM or a device tree.

pflash utility
==============

- external/pflash: Make MTD accesses the default

  Now that BMC and host kernel mtd drivers exist and have matured we
  should use them by default.

  This is especially important since we seem to be telling everyone to use
  pflash (pflash world domination plans are continuing on schedule).
- external/pflash: Catch incompatible combination of flags
- external/common: arm: Don't error trying to wrprotect with MTD access
- libflash/libffs: Use blocklevel_smart_write() when updating partitions

Other changes
=============
- extract-gcov: build with -m64 if compiler supports it.

  Fixes build break on 32bit ppc64 (e.g. PowerMac G5, where user space
  is mostly 32bit).

Fast Reset
==========

- fast-reset: disable fast reboot in event of platform error

  Most of the time, if we're rebooting due to a platform error, we should
  trigger a checkstop. However, if we haven't been told what we should do
  to trigger a checkstop (e.g. on an FSP machine), then we should still
  fail to fast-reboot.

  So, disable fast-reboot in the OPAL_CEC_REBOOT2 code path
  for OPAL_REBOOT_PLATFORM_ERROR reboot type.
- fast-reboot: disable on FSP code update or unrecoverable HMI
- fast-reboot: abort fast reboot if CAPP attached

  If a PHB is in CAPI mode, we cannot safely fast reboot - the PHB will be
  fenced during the reboot resulting in major problems when we load the new
  kernel.

  In order to handle this safely, we need to disable CAPI mode before
  resetting PHBs during the fast reboot. However, we don't currently support
  this.

  In the meantime, when fast rebooting, check if there are any PHBs with a
  CAPP attached, and if so, abort the fast reboot and revert to a normal
  reboot instead.

OpenPOWER Platforms
===================

For all hardware platforms that aren't IBM FSP machines:

- Revert "flash: Move flash node under ibm,opal/flash/"

  This reverts commit e1e6d009860d0ef60f9daf7a0fbe15f869516bd0.

  Breaks DT enough that it makes people cranky, reverting for now.
  This could break access to flash with existing kernels in POWER9 simulators

- flash: rework flash_load_resource to correctly read FFS/STB

  This fixes the previous reverts of loading the CAPP partition with
  STB headers (which broke CAPP partitions without STB headers).

  The new logic fixes both CAPP partition loading with STB headers *and*
  addresses a long standing bug due to differing interpretations of FFS.

  The f_part utility that *constructs* PNOR files just sets actualSize=totalSize
  no matter on what the size of the partition is. Prior to this patch,
  skiboot would always load actualSize, leading to longer than needed IPL.

  The pflash utility updates actualSize, so no developer has really ever
  noticed this, apart from maybe an inkling that it's odd that a freshly
  baked PNOR from op-build takes ever so slightly longer to boot than one
  that has had individual partitions pflashed in.

  With this patch, we now compute actualSize. For partitions with a STB
  header, we take the payload size from the STB header. For partitions
  that don't have a STB header, we compute the size either by parsing
  the ELF header or by looking at the subpartition header and computing it.

  We now need to read the entire partition for partitions with subpartitions
  so that we pass consistent values to be measured as part of Trusted Boot.

  As of this patch, the actualSize field in FFS is *not* relied on for
  partition size, we determine it from the content of the partition.

  However, this patch *will* break loading of partitions that are not ELF
  and do not contain subpartitions. Luckily, nothing in-tree makes use of
  that.

PCI
===
- pci: Check power state before powering off slot

  Prevents the erroneous "Error -1 powering off slot" error message.

Contributors
============
Since :ref:`skiboot-5.4.0-rc1`, we have 23 csets from 8 developers.

A total of 876 lines added, 621 removed (delta 255)

Developers with the most changesets

============================ = =======
Developer                    # %
============================ = =======
Stewart Smith                7 (30.4%)
Cyril Bur                    5 (21.7%)
Mukesh Ojha                  3 (13.0%)
Gavin Shan                   3 (13.0%)
Claudio Carvalho             2 (8.7%)
Chris Smart                  1 (4.3%)
Andrew Donnellan             1 (4.3%)
Nageswara R Sastry           1 (4.3%)
============================ = =======

Developers with the most changed lines

========================== === =======
Developer                    # %
========================== === =======
Stewart Smith              424 (45.7%)
Mukesh Ojha                204 (22.0%)
Gavin Shan                 173 (18.6%)
Cyril Bur                   69 (7.4%)
Claudio Carvalho            35 (3.8%)
Andrew Donnellan            13 (1.4%)
Chris Smart                  8 (0.9%)
Nageswara R Sastry           2 (0.2%)
========================== === =======

Developers with the most lines removed

============================ = =======
Developer                    # %
============================ = =======
Gavin Shan                   9 (1.4%)
Chris Smart                  4 (0.6%)
============================ = =======

Developers with the most signoffs (total 16)

=========================== == ========
Developer                    # %
=========================== == ========
Stewart Smith               16 (100.0%)
=========================== == ========

Developers with the most reviews (total 4)

============================ = =======
Developer                    # %
============================ = =======
Vasant Hegde                 2 (50.0%)
Andrew Donnellan             2 (50.0%)
============================ = =======

Developers with the most test credits (total 1)

============================ = =======
Developer                    # %
============================ = =======
Pridhiviraj Paidipeddi       1 (100.0%)
============================ = =======

Developers who gave the most tested-by credits (total 1)

============================ = =======
Developer                    # %
============================ = =======
Gavin Shan                   1 (100.0%)
============================ = =======

Developers with the most report credits (total 3)

============================ = =======
Developer                    # %
============================ = =======
Pridhiviraj Paidipeddi       1 (33.3%)
Andrei Warkenti              1 (33.3%)
Michael Neuling              1 (33.3%)
============================ = =======

Developers who gave the most report credits (total 3)

============================ = =======
Developer                    # %
============================ = =======
Stewart Smith                2 (66.7%)
Gavin Shan                   1 (33.3%)
============================ = =======
