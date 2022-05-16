.. _skiboot-6.6:

skiboot-6.6
===========

skiboot v6.6 was released on Wednesday April 22nd 2020. It is the first release
of skiboot 6.6 series, which becomes the new stable release following the
:ref:`skiboot-6.5` release, first released August 16th 2019.

There hasn't been a skiboot release in a while and this release doesn't contain
a huge number of new features for users, just a lot of bug fixes, and additional
platform support. The next release should be a little more lively with a number
of internal refactorings and new features on the way.

.. _skiboot-6.6-new-features:

New features
------------

- Skiboot is now dual licensed as Apache 2.0 -OR- GPLv2+

  There are some files still licensed Apache 2.0 only due to contributions
  that we are unable to change the license of, but they are the minority.

- Skiboot can now be built as little endian, thanks to Team Nick.

  Doing so requires building with: make LITTLE_ENDIAN=1

- OpenCAPI reset support
  
  This is to allow FPGA-based OpenCAPI devices to be re-flashed with a new
  device image, then reset to activate the new image. Although it is based
  on top of the existing PCI Hotplug support it does require some OS changes
  to function.

- The :ref:`OPAL_PHB_SET_OPTION` and :ref:`OPAL_PHB_GET_OPTION` OPAL calls

  These OPAL calls provide the OS with a means for controlling per-PHB
  settings. Currently this allows the OS to enable or disable the the "Global
  MMIO EEH Disable" and "4GTE" settings which are available on Power9 / PHB4.
  See the PHB specification for more details.

Removed features
----------------

- Fast-reboot is now disabled by default.

  Fast-reboot will continue to be supported, but as an opt-in feature rather
  than the default. From the commit (ee07f2c68160) message::

    This has two user visible changes:
    
    1. Full reboot is now the default. In order to get fast-reboot as the
       default the nvram option needs to be set:
    
            nvram -p ibm,skiboot --update-config fast-reset=1
    
    2. The nvram option to force a fast-reboot even when some part of
       skiboot has called disable_fast_reboot() has changed from
       'fast-reset=im-feeling-lucky' to 'force-fast-reset=1' because
       it's impossible to actually use that 'feature' if fast-reboot is
       off by default.
    
            nvram -p ibm,skiboot --update-config force-fast-reset=1

