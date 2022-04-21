.. _skiboot-6.5.3:

==============
skiboot-6.5.3
==============

skiboot 6.5.3 was released on Tuesday March 10th, 2020. It replaces
:ref:`skiboot-6.5.2` as the current stable release in the 6.5.x series.

It is recommended that 6.5.3 be used instead of 6.5.2 version due to the
bug fixes it contains.

Bug fixes included in this release are:
- npu2-opencapi: Don't drive reset signal permanently

- mpipl: Rework memory reservation for OPAL dump

- mpipl: Disable fast-reboot during post MPIPL boot

- hdata: Update MPIPL support IPL parameter

- xscom: Don't log xscom errors caused by OPAL calls

- npu2: Clear fence on all bricks
