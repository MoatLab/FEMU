skiboot-5.2.1
=============

skiboot-5.2.1 was released on Wednesday April 27th, 2016.

skiboot-5.2.1 is the second stable release of skiboot 5.2, the new stable
release of skiboot, which will take over from the 5.1.x series which was
first released August 17th, 2015.

skiboot-5.2.1 contains all bug fixes as of skiboot-5.1.15.

This is the second release that will follow the (now documented) Skiboot
stable rules - see :ref:`stable-rules`.

Changes
-------
Over skiboot-5.2.0, the following fixes are included:

pflash
^^^^^^

- Allow building under yocto.
  Makefile fixes to enable building as part of an OpenBMC build.

Garrison platform
^^^^^^^^^^^^^^^^^

- Add PCIe and NPU slot location names
- hw/npu.c: Add ibm, npu-index property to npu device tree
- hmi: Add handling for NPU checkstops

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
    - [  305.628423] 	CPU PIR: 00000000
    + [  200.123021] 	CPU PIR: 000008e8
      [  305.628458] 	[Unit: VSU] Logic core check stop

- xscom: Return OPAL_WRONG_STATE on XSCOM ops if CPU is asleep


Contributors
------------

Processed 15 csets from 7 developers
A total of 436 lines added, 59 removed (delta 377)

Developers with the most changesets

============================ ==========
============================ ==========
Russell Currey               7 (46.7%)
Alistair Popple              2 (13.3%)
Michael Neuling              2 (13.3%)
Patrick Williams             1 (6.7%)
Stewart Smith                1 (6.7%)
Mamatha                      1 (6.7%)
Mahesh Salgaonkar            1 (6.7%)
============================ ==========

Developers with the most changed lines

========================== ============
========================== ============
Alistair Popple            215 (48.3%)
Russell Currey             140 (31.5%)
Michael Neuling             55 (12.4%)
Mamatha                     15 (3.4%)
Patrick Williams             9 (2.0%)
Mahesh Salgaonkar            8 (1.8%)
Stewart Smith                3 (0.7%)
========================== ============

Developers with the most lines removed

========================== ============
========================== ============
Patrick Williams             5 (8.5%)
========================== ============

Developers with the most signoffs (total 30)

========================== ============
========================== ============
Stewart Smith               15 (50.0%)
Russell Currey               7 (23.3%)
Michael Neuling              2 (6.7%)
Alistair Popple              2 (6.7%)
Patrick Williams             1 (3.3%)
Oliver O'Halloran            1 (3.3%)
Mahesh Salgaonkar            1 (3.3%)
Mamatha                      1 (3.3%)
========================== ============

Developers with the most reviews (total 11)

========================== ============
========================== ============
Alistair Popple              5 (45.5%)
Andrew Donnellan             3 (27.3%)
Mahesh Salgaonkar            2 (18.2%)
Joel Stanley                 1 (9.1%)
========================== ============

Developers with the most Acked-by (total 1)

========================== ============
========================== ============
Alistair Popple              1 (100.0%)
========================== ============

Developers with the most test credits (total 3)

========================== ============
========================== ============
Andrew Donnellan             2 (66.7%)
Vaibhav Jain                 1 (33.3%)
========================== ============

Developers who received the most tested-by credits (total 3)

========================== ============
========================== ============
Michael Neuling              3 (100.0%)
========================== ============
