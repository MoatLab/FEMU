skiboot-5.1.10
--------------

skiboot-5.1.10 was released on Friday November 13th, 2015.

skiboot-5.1.10 is the 11th stable release of 5.1, it follows skiboot-5.1.9
(which was released October 30th, 2015).

Skiboot 5.1.10 contains all fixes from skiboot-5.1.9 and is a minor bug
fix release.

Over skiboot-5.1.9, we have the following change:

IBM FSP machines
^^^^^^^^^^^^^^^^

- FSP: Handle Delayed Power Off initiated CEC shutdown with FSP in Reset/Reload

  In a scenario where the DPO has been initiated, but the FSP then went into
  reset before the CEC power down came in, OPAL may not give up the link since
  it may never see the PSI interrupt. So, if we are in dpo_pending and an FSP
  reset is detected via the DISR, give up the PSI link voluntarily.

Generic
^^^^^^^

- sensor: add a compatible property
  OPAL needs an extra compatible property "ibm,opal-sensor" to make
  module autoload work smoothly in Linux for ibmpowernv driver.
- console: Completely flush output buffer before power down and reboot
  Completely flush the output buffer of the console driver before
  power down and reboot.  Implements the flushing function for uart
  consoles, which includes the astbmc and rhesus platforms.

  This fixes an issue where some console output is sometimes lost before
  power down or reboot in uart consoles. If this issue is also prevalent
  in other console types then it can be fixed later by adding a .flush
  to that driver's con_ops.
