.. _skiboot-6.6.1:

==============
skiboot-6.6.1
==============

skiboot 6.6.1 was released on Saturday June 06, 2020. It replaces
:ref:`skiboot-6.6` as the current stable release in the 6.6.x series.

It is recommended that 6.6.1 be used instead of 6.6 version due to the
bug fixes it contains.

Bug fixes included in this release are:

- occ: Fix false negatives in wait_for_all_occ_init()

- uart: Drop console write data if BMC becomes unresponsive

- hw/phys-map: Fix OCAPI_MEM BAR values

- Detect fused core mode and bail out

- platform/mihawk: Tune equalization settings for opencapi

- hdata/memory.c: Fix "Inconsistent MSAREA" warnings

- PSI: Convert prerror to PR_NOTICE

- sensors: occ: Fix a bug when sensor values are zero

- sensors: occ: Fix the GPU detection code
