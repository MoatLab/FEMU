.. _skiboot-7.1:

skiboot-7.1
===========

skiboot v7.1 was released on Monday Sep 18th 2023. It is the first release of
the skiboot 7.1 series, which becomes the new stable release following the
:ref:`skiboot-7.0` release, first released Tuesday Oct 26th 2021.

Changes in this release are mostly bug fixes, refactoring improvements, and
some code deprecation/obsoletion.

New Features
------------
Removed OPAL calls
^^^^^^^^^^^^^^^^^^
The OPAL_PCI_SET_MVE_ENABLE and OPAL_PCI_SET_MVE calls were removed, as they
were noops. Support for IODA1 and both calls was removed from the Linux kernel
in v6.5-rc1.

Optional POWER8 support
^^^^^^^^^^^^^^^^^^^^^^^
Most POWER8 code has been conditionalized, making it possible to omit support by
building with `CONFIG_P8=0`. The result is a smaller binary targeting POWER9 as
the baseline CPU.
