.. _skiboot-5.4.0-rc4:

=================
skiboot-5.4.0-rc4
=================

skiboot-5.4.0-rc4 was released on Tuesday November 8th 2016. It is the
fourth (and hopefully final) release candidate of skiboot 5.4, which will
become the new stable release of skiboot following the 5.3 release, first
released August 2nd 2016.

skiboot-5.4.0-rc4 contains all bug fixes as of :ref:`skiboot-5.3.7`
and :ref:`skiboot-5.1.18` (the currently maintained stable releases).

For how the skiboot stable releases work, see :ref:`stable-rules` for details.

Since this is a release candidate, it should *NOT* be put into production.

With this release candidate, I'm hoping that it's the last one, and that within
the week we're able to tag a final 5.4.0 release. There is one bit of code I'm
hoping to merge in before the final 5.4.0, and that's the p8dtu platform
definition. The aim is for skiboot-5.4.x to be in op-build v1.13, which is due
by November 23rd 2016.

Over :ref:`skiboot-5.4.0-rc3`, we have a few changes:

- Add BMC platform to enable correct OEM IPMI commands

  An out of tree platform (p8dtu) uses a different IPMI OEM command
  for IPMI_PARTIAL_ADD_ESEL. This exposed some assumptions about the BMC
  implementation in our core code.

  Now, with platform.bmc, each platform can dictate (or detect) the BMC
  that is present. We allow it to be set at runtime rather than purely
  statically in struct platform as it's possible to have differing BMC
  implementations on the one machine (e.g. AMI BMC or OpenBMC).

- hw/ipmi-sensor: Fix setting of firmware progress sensor properly.

  On FSP systems, OPAL was incorrectly setting firmware status
  on a sensor id "00" which doesn't exist.

- pflash: remove stray d in from info message
- libflash/pflash: support whole chip erase on mtd access
- boot_test: fix typo in console message
- core/pci: Fix criteria in pci_cfg_reg_filter(), i.e. NVLink didn't work.

- Remove KERNEL_COMMAND_LINE mention from config.h

  We removed the functionality but not the define.
