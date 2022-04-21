.. _skiboot-5.9-rc5:

skiboot-5.9-rc5
===============

skiboot v5.9-rc5 was released on Monday October 23rd 2017 approximately
32,000ft above somewhere north of Tucson, Arizona. It is the fifth
release candidate of skiboot 5.9, which will become the new stable release
of skiboot following the 5.8 release, first released August 31st 2017.

skiboot v5.9-rc5 contains all bug fixes as of :ref:`skiboot-5.4.8`
and :ref:`skiboot-5.1.21` (the currently maintained stable releases). We
do not currently expect to do any 5.8.x stable releases.

For how the skiboot stable releases work, see :ref:`stable-rules` for details.

The current plan is to cut the final 5.9 very shortly, with skiboot 5.9
being for all POWER8 and POWER9 platforms in op-build v1.20 (Due October 18th,
so we're running a bit behind there).
This release will be targetted to early POWER9 systems.

Over :ref:`skiboot-5.9-rc3`, we have the following changes:

- opal/hmi: Workaround Power9 hw logic bug for couple of TFMR TB errors.
- opal/hmi: Fix TB reside and HDEC parity error recovery for power9
- phb4: Escalate freeze to fence to avoid checkstop

  Freeze events such as MMIO loads can cause the PHB to lose it's
  limited powerbus credits. If all credits are used and a further MMIO
  will cause a checkstop.

  To work around this, we escalate the troublesome freeze events to a
  fence. The fence will cause a full PHB reset which resets the powerbus
  credits and avoids the checkstop.
- phb4: Update some init registers

  New inits based on next PHB4 workbook. Increases some timeouts to
  avoid some spurious error conditions.
- phb4: Enable PHB MMIO in phb4_root_port_init()

  Linux EEH flow is somewhat broken. It saves the PCIe config space of
  the PHB on boot, which it then uses to restore on EEH recovery. It
  does this to restore MMIO bars and some other pieces.

  Unfortunately this save is done before any drivers are bound to
  devices under the PHB. A number of other things are configured in the
  PHB after drivers start, hence some configuration space settings
  aren't saved correctly. These include bus master and MMIO bits in the
  command register.

  Linux tried to hack around this in this linux commit
  ``bf898ec5cb`` powerpc/eeh: Enable PCI_COMMAND_MASTER for PCI bridges
  This sets the bus master bit but ignores the MMIO bit.

  Hence we lose MMIO after a full PHB reset. This causes the next MMIO
  access to the device to fail and for us to perform a PE freeze
  recovery, which still doesn't set the MMIO bit and hence we still
  fail.

  This works around this by forcing MMIO on during
  phb4_root_port_init().

  With this we can recovery from a PHB fence event on POWER9.
- phb4: Reduce link degraded message log level to debug

  If we hit this message we'll retry and fix the problem. If we run out
  of retries and can't fix the problem, we'll still print a log message
  at error level indicating a problem.
- phb4: Fix GEN3 for DD2.00

  In this fix:  ``62ac7631ae`` "phb4: Fix PCIe GEN4 on DD2.1 and above",
  We fixed DD2.1 GEN4 but broke DD2.00 as GEN3.

  This fixes DD2.00 back to GEN3. This time for sure!
