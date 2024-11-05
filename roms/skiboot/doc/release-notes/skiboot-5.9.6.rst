.. _skiboot-5.9.6:

=============
skiboot-5.9.6
=============

skiboot 5.9.6 was released on Friday December 15th, 2017. It replaces
:ref:`skiboot-5.9.5` as the current stable release in the 5.9.x series.

Over :ref:`skiboot-5.9.5`, we have a few bug fixes, they are:

- sensors: occ: Skip counter type of sensors

  Don't add counter type of sensors to device-tree as they don't
  fit into hwmon sensor interface.
- p9_stop_api updates to support IMC across deep stop states.
- opal/xscom: Add recovery for lost core wakeup scom failures.

  Due to a hardware issue where core responding to scom was delayed due to
  thread reconfiguration, leaves the SCOM logic in a state where the
  subsequent scom to that core can get errors. This is affected for Core
  PC scom registers in the range of 20010A80-20010ABF

  The solution is if a xscom timeout occurs to one of Core PC scom registers
  in the range of 20010A80-20010ABF, a clearing scom write is done to
  0x20010800 with data of '0x00000000' which will also get a timeout but
  clears the scom logic errors. After the clearing write is done the original
  scom operation can be retried.

  The scom timeout is reported as status 0x4 (Invalid address) in HMER[21-23].
