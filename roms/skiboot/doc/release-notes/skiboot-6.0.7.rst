.. _skiboot-6.0.7:

=============
skiboot-6.0.7
=============

skiboot 6.0.7 was released on Friday August 3rd, 2018. It replaces
:ref:`skiboot-6.0.6` as the current stable release in the 6.0.x series.

It is recommended that 6.0.7 be used instead of any previous 6.0.x version
due to it containing a workaround for hardware errata in the XIVE interrupt
controller (present on POWER9 systems).

The bug fix is:

- xive: Disable block tracker

  Due to some HW errata, the block tracking facility (performance optimisation
  for large systems) should be disabled on Nimbus chips. Disable it unconditionally
  for now.
