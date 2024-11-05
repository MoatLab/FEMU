.. _skiboot-5.9.3:

=============
skiboot-5.9.3
=============

skiboot 5.9.3 was released on Wednesday November 22nd, 2017. It replaces
:ref:`skiboot-5.9.2` as the current stable release in the 5.9.x series.

Over :ref:`skiboot-5.9.2`, we have one NPU2/NVLink2 fix that causes the
machine to crash hard in the event of hardware error rather than crash
mysteriously later on whenever the NVLink2 links are used.

That fix is:

- npu2: hw-procedures: Add check_credits procedure

  As an immediate mitigator for a current hardware glitch, add a procedure
  that can be used to validate NTL credit values. This will be called as a
  safeguard to check that link training succeeded.

  Assert that things are exactly as we expect, because if they aren't, the
  system will experience a catastrophic failure shortly after the start of
  link traffic.
