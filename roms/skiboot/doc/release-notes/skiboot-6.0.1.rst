.. _skiboot-6.0.1:

=============
skiboot-6.0.1
=============

skiboot 6.0.1 was released on Wednesday May 16th, 2018. It replaces
:ref:`skiboot-6.0` as the current stable release in the 6.0.x series.

It is recommended that 6.0.1 be used instead of any previous 6.0.x version
due to the bug fixes and debugging enhancements in it.

Over :ref:`skiboot-6.0`, we have two bug fixes:

- OpenBMC: use 0x3a as OEM command for partial add esel.

  This fixes the bug where skiboot would never send an eSEL to the BMC.
- Add location code to NPU2 HMI logging

  The current HMI error message does not specifiy where the HMI
  error occured.

  The original error message was ::

    NPU: FIR#0 FIR 0x0080100000000000 mask 0x009a48180f01ffff

  The enhanced error message is ::

    NPU2: [Loc: UOPWR.0000000-Node0-Proc0] P:0 FIR#0 FIR 0x0000100000000000 mask 0x009a48180f03ffff
