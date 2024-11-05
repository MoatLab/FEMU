.. _skiboot-6.5.1:

==============
skiboot-6.5.1
==============

skiboot 6.5.1 was released on Thursday October 24th, 2019. It replaces
:ref:`skiboot-6.5` as the current stable release in the 6.5.x series.

It is recommended that 6.5.1 be used instead of 6.5 version due to the
bug fixes it contains.

Bug fixes included in this release are:

- core/ipmi: Fix use-after-free

- blocklevel: smart_write: Fix unaligned writes to ECC partitions

- gard: Fix data corruption when clearing single records

- core/platform: Actually disable fast-reboot on P8

- xive: fix return value of opal_xive_allocate_irq()

- MPIPL: struct opal_mpipl_fadump doesn't needs to be packed

- core/flash: Validate secure boot content size
