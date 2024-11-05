.. _skiboot-5.9-rc4:

skiboot-5.9-rc4
===============

skiboot v5.9-rc4 was released on Thursday October 19th 2017. It is the fourth
release candidate of skiboot 5.9, which will become the new stable release
of skiboot following the 5.8 release, first released August 31st 2017.

skiboot v5.9-rc4 contains all bug fixes as of :ref:`skiboot-5.4.8`
and :ref:`skiboot-5.1.21` (the currently maintained stable releases). We
do not currently expect to do any 5.8.x stable releases.

For how the skiboot stable releases work, see :ref:`stable-rules` for details.

The current plan is to cut the final 5.9 by October 20th, with skiboot 5.9
being for all POWER8 and POWER9 platforms in op-build v1.20 (Due October 18th,
so we're running a bit behind there).
This release will be targetted to early POWER9 systems.

Over :ref:`skiboot-5.9-rc3`, we have the following changes:

- phb4: Fix PCIe GEN4 on DD2.1 and above

  In this change:
      eef0e197ab PHB4: Default to PCIe GEN3 on POWER9 DD2.00

  We clamped DD2.00 parts to GEN3 but unfortunately this change also
  applies to DD2.1 and above.

  This fixes this to only apply to DD2.00.
- occ-sensors : Add OCC inband sensor region to exports
  (useful for debugging)

Two SRESET fixes:

- core: direct-controls: Fix clearing of special wakeup

  'special_wakeup_count' is incremented on successfully asserting
  special wakeup. So we will never clear the special wakeup if we
  check 'special_wakeup_count' to be zero. Fix this issue by checking
  the 'special_wakeup_count' to 1 in dctl_clear_special_wakeup().
- core/direct-controls: increase special wakeup timeout on POWER9

  Some instances have been observed where the special wakeup assert
  times out. The current timeout is too short for deeper sleep states.
  Hostboot uses 100ms, so match that.
