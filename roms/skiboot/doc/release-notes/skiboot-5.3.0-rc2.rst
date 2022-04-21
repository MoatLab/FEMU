skiboot-5.3.0-rc2
=================

skiboot-5.3.0-rc2 was released on Thursday July 28th, 2016.

The current plan is to release skiboot-5.3.0 August 1st 2016.

Over skiboot-5.3.0-rc1, we have the following changes:

pflash
------

- pflash: Clean up makefiles and resolve build race
- pflash: use atexit for musl compatibility

General
-------

- core/flash: Fix passing pointer instead of value

POWER9
------

- mambo: Update Radix Tree Size as per ISA 3.0
   In Linux we recently changed to this encoding, so we no longer boot.
   The associated Linux commit is b23d9c5b9c83c05e013aa52460f12a8365062cf4

FSP Platforms
-------------

- platforms/ibm-fsp: Fix incorrect struct member access and comparison
- FSP/MDST: Fix TCE alignment issue
  In some corner cases (like source memory size = 4097) we may
  endup doing wrong mapping and corrupting part of SYSDUMP.
- hdat/vpd: Add chip-id property to processor chip node under vpd

CAPI
----

- hw/phb3: Increase AIB TX command credit for DMA read in CAPP DMA mode
