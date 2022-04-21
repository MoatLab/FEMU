.. _skiboot-6.3.4:

==============
skiboot-6.3.4
==============

skiboot 6.3.4 was released on Thursday Oct 3rd, 2019. It replaces
:ref:`skiboot-6.3.3` as the current stable release in the 6.3.x series.

It is recommended that 6.3.4 be used instead of any previous 6.3.x version
due to the bug fixes it contains.

Bug fixes included in this release are:

- hw/phb4: Prevent register accesses when in reset

- core/platform: Actually disable fast-reboot on P8

- xive: fix return value of opal_xive_allocate_irq()

- hw/phb4: Use standard MIN/MAX macro definitions

  The max() macro definition incorrectly returns the minimum value.  The
  max() macro is used to ensure that PERST has been asserted for 250ms and
  that we wait 100ms seconds for the ETU logic in the CRESET_START PHB4
  PCI slot state.  However, by returning the minimum value there is no
  guarantee that either of these requirements are met.

- doc/requirements.txt: pin docutils at 0.14
