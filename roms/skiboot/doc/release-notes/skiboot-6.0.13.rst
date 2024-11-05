.. _skiboot-6.0.13:

==============
skiboot-6.0.13
==============

skiboot 6.0.13 was released on Wednesday November 14th, 2018. It replaces
:ref:`skiboot-6.0.12` as the current stable release in the 6.0.x series.

This release includes one pflash change. This release does not modify skiboot
itself, so there is no reason to upgrade to this version if you're on 6.0.12
already. This release is made exclusively so OpenBMC can ship an updated pflash
from a tagged release.

The pflash change is:

- pflash: Add --skip option for reading

  Add a --skip=N option to pflash to skip N number of bytes when reading.
  This would allow users to print the VERSION partition without the STB
  header by specifying the --skip=4096 argument, and it's a more generic
  solution rather than making pflash depend on secure/trusted boot code.
