skiboot-5.1.0-beta1
===================

skiboot-5.1.0-beta1 was released on July 21st, 2015.

skiboot-5.1.0-beta1 is the first beta release of skiboot 5.1, which will
become a new stable release, replacing skiboot-5.0 (released April 14th 2015)

Skiboot 5.1-beta1 contains all fixes from skiboot-5.0 stable branch up to
skiboot-5.0.5.

New features
^^^^^^^^^^^^
Over skiboot-5.0, the following features have been added:

* Centaur i2c support
* Add Naples chip (CPU, PHB, LPC serial interrupts) support
* Added qemu platform
* improvements to FSI error handling
* improvements in chip TOD failover (some only on FSP systems)
* Set Relative Priority Register (RPR) to recommended value

  * this affects thread priority in SMT modes
* greatly reduce memory consumption by CPU stacks for non-present CPUs

  * Previously we would reserve enough memory for max PIR for each CPU type.
  * This fix frees up 77MB of RAM on a typical P8 system.
* increased OPAL API documentation
* Asynchronous preloading of resources from FSP/flash

  * improves boot time on some systems
* Basic Garrison platform support
* Add Mambo platform (P8 Functional Simulator, systemsim)

  * includes fake NVRAM, RTC
* Support building with GCOV, increasing memory for skiboot binary to 2MB

  * includes boot code coverage testing
* Increased skiboot HEAP size.

  * We are not aware of any system where you would run out, but on large
    systems it was getting closer than we liked.
* add boot_tests.sh for helping automate boot testing on FSP and BMC machines
* Versioning of pflash and gard utilities to help Linux (or other OS)
  distributions with packaging.
* OCC throttle status messages to host
* CAPP timebase sync ("ibm,capp-timebase-sync" in DT to indicate CAPP timebase
  was synced by OPAL)

New features for FSP based machines
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
* in-band IPMI support
* ethernet adaptor location codes
* add DIMM frequency information to device tree
* improvements in FSP error log code paths
* fix some boot time memory leaks

  * harmless to end user

New features for AMI BMC based machines
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
* PCIe power workaround for K80
* Added support for Macronix 128Mbit flash chips
* Initial PRD support for Firestone platform
* improved reliability when BMC reboots

Bug Fixes
^^^^^^^^^
The following bugs have been fixed:

* Increase PHB3 timeout for electrical links coming up to 2 seconds.

  * fixes issues with some Mellanox cards
* Hang in opal_reinit_cpus() that could prevent kdump from functioning
* PHB3: fix crash in phb3_init
* PHB3: fix crash with fenced PHB in phb3_init_hw()
* Fix bugs in hw/bt.c (interface for IPMI on BMC machines) that could possibly
  lead to a crash (dereferencing invalid address, deadlock)
* ipmi/sel: fix use-after-free
* Bug fixes in EEH handling

  * opal_pci_next_error() cleared OPAL_EVENT_PCI_ERROR unconditionally, possibly leading to missed errors.

FSP-specific bugs fixed:
^^^^^^^^^^^^^^^^^^^^^^^^
* (also fixed in skiboot-5.0.2) Fix race in firenze_get_slot_info() leading to
  assert() with many PCI cards

  With many PCI cards, we'd hit a race where calls to
  firenze_add_pcidev_to_fsp_inventory would step on each other leading to
  memory corruption and finally an assert() in the allocator being hit
  during boot.
* PCIe power workaround for K80 cards
* /ibm,opal/led renamed to /ibm,opal/leds in Device Tree

  * compatible change as no FSP based systems shipped with skiboot-5.0

General improvements:
^^^^^^^^^^^^^^^^^^^^^
* don't run pollers on non-boot CPUs in time_wait
* improvements to opal-prd, pflash, libflash

  * including new blocklevel interface in libflash
* many minor fixes to issues found by static analysis
* improvements in FSP error log code paths
* code cleanup in memory allocator
* Don't expose individual nvram partitions in the device tree, just the whole
  flash device.
* build improvements for building on ppc64el host
* improvements in cpu_relax() for idle threads, needed for GCOV on large
  machines.
* Optimized memset() for POWER8, greatly reducing number of instructions
  executed for boot, which helps boot time in simulators.
* Major improvements in hello_world kernel

  * Bloat of huge 17 instruction test case reduced to 10.
* Disable bust_locks for general calls of abort()

  * Should enable better error messages during abort() when other users of
    LPC bus exist (e.g. flash)

Contributors
------------

Thanks to everyone who has made skiboot-5.1.0-beta1 happen!


Processed 321 csets from 25 developers
3 employers found
A total of 13696 lines added, 2754 removed (delta 10942)

Developers with the most changesets

========================== ===========
Developer                  Changesets
========================== ===========
Stewart Smith              101 (31.5%)
Benjamin Herrenschmidt      32 (10.0%)
Cyril Bur                   31 (9.7%)
Vasant Hegde                28 (8.7%)
Jeremy Kerr                 27 (8.4%)
Kamalesh Babulal            19 (5.9%)
Alistair Popple             12 (3.7%)
Mahesh Salgaonkar           12 (3.7%)
Neelesh Gupta                8 (2.5%)
Cédric Le Goater             8 (2.5%)
Joel Stanley                 8 (2.5%)
Ananth N Mavinakayanahalli   8 (2.5%)
Gavin Shan                   6 (1.9%)
Michael Neuling              6 (1.9%)
Frederic Bonnard             3 (0.9%)
Vipin K Parashar             2 (0.6%)
Vaidyanathan Srinivasan      2 (0.6%)
Philippe Bergheaud           1 (0.3%)
Shilpasri G Bhat             1 (0.3%)
Daniel Axtens                1 (0.3%)
Hari Bathini                 1 (0.3%)
Michael Ellerman             1 (0.3%)
Andrei Warkentin             1 (0.3%)
Dan Horák                    1 (0.3%)
Anton Blanchard              1 (0.3%)
========================== ===========

Developers with the most changed lines

========================== =============
Developer                  Changed Lines
========================== =============
Stewart Smith              3987 (27.9%)
Benjamin Herrenschmidt     3811 (26.6%)
Cyril Bur                  1918 (13.4%)
Jeremy Kerr                1307 (9.1%)
Mahesh Salgaonkar           886 (6.2%)
Vasant Hegde                764 (5.3%)
Neelesh Gupta               473 (3.3%)
Vipin K Parashar            176 (1.2%)
Alistair Popple             175 (1.2%)
Philippe Bergheaud          171 (1.2%)
Shilpasri G Bhat            165 (1.2%)
Cédric Le Goater             89 (0.6%)
Frederic Bonnard             78 (0.5%)
Gavin Shan                   73 (0.5%)
Joel Stanley                 65 (0.5%)
Kamalesh Babulal             63 (0.4%)
Michael Neuling              47 (0.3%)
Daniel Axtens                31 (0.2%)
Ananth N Mavinakayanahalli   22 (0.2%)
Anton Blanchard               3 (0.0%)
Vaidyanathan Srinivasan       2 (0.0%)
Hari Bathini                  2 (0.0%)
Michael Ellerman              1 (0.0%)
Andrei Warkentin              1 (0.0%)
Dan Horák                     1 (0.0%)
========================== =============

Developers with the most lines removed:

========================= ==============
========================= ==============
Vipin K Parashar           105 (3.8%)
Michael Neuling             24 (0.9%)
Hari Bathini                 1 (0.0%)
========================= ==============

Developers with the most signoffs (total 214)

========================= ==============
Stewart Smith              214 (100.0%)
========================= ==============

Developers with the most reviews (total 21)

========================== ==============
========================== ==============
Vasant Hegde                 7 (33.3%)
Joel Stanley                 3 (14.3%)
Gavin Shan                   2 (9.5%)
Kamalesh Babulal             2 (9.5%)
Alistair Popple              2 (9.5%)
Stewart Smith                1 (4.8%)
Andrei Warkentin             1 (4.8%)
Preeti U Murthy              1 (4.8%)
Samuel Mendoza-Jonas         1 (4.8%)
Ananth N Mavinakayanahalli    1 (4.8%)
========================== ==============

Developers with the most test credits (total 1)

========================= ==============
========================= ==============
Chad Larson                  1 (100.0%)
========================= ==============

Developers who gave the most tested-by credits (total 1)

========================= ==============
========================= ==============
Gavin Shan                   1 (100.0%)
========================= ==============

Developers with the most report credits (total 4)

========================= ==============
========================= ==============
Benjamin Herrenschmidt       2 (50.0%)
Chad Larson                  1 (25.0%)
Andrei Warkentin             1 (25.0%)
========================= ==============

Developers who gave the most report credits (total 4)

========================= ==============
========================= ==============
Stewart Smith                3 (75.0%)
Gavin Shan                   1 (25.0%)
========================= ==============

Top changeset contributors by employer

========================== ==============
========================== ==============
IBM                        319 (99.4%)
dan@danny.cz                 1 (0.3%)
andrey.warkentin@gmail.com    1 (0.3%)
========================== ==============

Top lines changed by employer

========================== ==============
========================== ==============
IBM                        14309 (100.0%)
dan@danny.cz                   1 (0.0%)
andrey.warkentin@gmail.com     1 (0.0%)
========================== ==============

Employers with the most signoffs (total 214)

========================= ==============
IBM                        214 (100.0%)
========================= ==============

Employers with the most hackers (total 25)

========================== ==============
========================== ==============
IBM                         23 (92.0%)
dan@danny.cz                 1 (4.0%)
andrey.warkentin@gmail.com    1 (4.0%)
========================== ==============

