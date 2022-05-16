skiboot-5.1.16
==============

skiboot-5.1.16 was released on Friday April 29th, 2016.

skiboot-5.1.16 is the 17th stable release of 5.1, it follows skiboot-5.1.15
(which was released March 16th, 2016).

This release contains a few bug fixes and is a recommended upgrade.

Changes
-------

PHB3 (all POWER8 platforms)
^^^^^^^^^^^^^^^^^^^^^^^^^^^

- hw/phb3: Ensure PQ bits are cleared in the IVC when masking IRQ
  When we mask an interrupt, we may race with another interrupt coming
  in from the hardware.  If this occurs, the P and/or Q bit may end up
  being set but we never EOI/clear them.  This could result in a lost
  interrupt or the next interrupt that comes in after re-enabling never
  being presented.

  This fixes a bug seen with some CAPI workloads which have lots of
  interrupt masking at the same time as high interrupt load.  The fix is
  not specific to CAPI though.
- hw/phb3: Fix potential race in EOI
    When we EOI we need to clear the present (P) bit in the Interrupt
    Vector Cache (IVC).  We must clear P ensuring that any additional
    interrupts that come in aren't lost while also maintaining coherency
    with the Interrupt Vector Table (IVT).

  To do this, the hardware provides a conditional update bit in the
  IVC. This bit ensures that generation counts between the IVT and the
  IVC updates are synchronised.

  Unfortunately we never set this the bit to conditionally update the P
  bit in the IVC based on the generation count.  Also, we didn't set
  what we wanted the new generation count to be if the update was
  successful.

FSP platforms
^^^^^^^^^^^^^

- OPAL:Handle mbox response with bad status:0x24 during FSP termination
  OPAL committed a predictive log with SRC BB822411 in some situations.

Generic
^^^^^^^

- hmi: Fix a bug where partial hmi event was reported to host.
  This bug fix ensures the CPU PIR is reported correctly: ::

     [  305.628283] Fatal Hypervisor Maintenance interrupt [Not recovered]
     [  305.628341]  Error detail: Malfunction Alert
     [  305.628388] 	HMER: 8040000000000000
   - [  305.628423]      CPU PIR: 00000000
   + [  200.123021]    CPU PIR: 000008e8
     [  305.628458]  [Unit: VSU] Logic core check stop

