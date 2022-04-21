.. _skiboot-6.7.2:

==============
skiboot-6.7.2
==============

skiboot 6.7.2 was released on Wednesday June 30, 2021. It replaces
:ref:`skiboot-6.7.1` as the current stable release in the 6.7.x series.

It is recommended that 6.7.2 be used instead of 6.7.1 version due to the
bug fixes it contains.

Bug fixes included in this release are:

- secvar: fix endian conversion

- secvar/secvar_util: Properly free memory on zalloc fail

- edk2-compat-process.c: Remove repetitive debug print statements

- phb4: Avoid MMIO load freeze escalation on every chip

- phb4: Disable TCE cache line buffer

- hw/imc: Disable only nest_imc devices if pause_microcode() fail

- hw/imc: move imc_init() towards end main_cpu_entry()

- Fix lock error when BT IRQ preempt BT timer
