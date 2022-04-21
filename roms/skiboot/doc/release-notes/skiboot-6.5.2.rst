.. _skiboot-6.5.2:

==============
skiboot-6.5.2
==============

skiboot 6.5.2 was released on Monday December 9th, 2019. It replaces
:ref:`skiboot-6.5.1` as the current stable release in the 6.5.x series.

It is recommended that 6.5.2 be used instead of 6.5.1 version due to the
bug fixes it contains.

Bug fixes included in this release are:
- libstb/tpm: block access to unknown i2c devs on the tpm bus

- slw: slw_reinit fix array overrun

- IPMI: Trigger OPAL TI in abort path.

- platform/mihawk: Add system VPD EEPROM to I2C bus

- platform/mihawk: Detect old system compatible string

- npu2/hw-procedures: Remove assertion from check_credits()

- npu2-opencapi: Fix integer promotion bug in LPC allocation

- hw/port80: Squash No SYNC error
