.. _skiboot-5.1.0:

skiboot-5.1.0
=============

skiboot-5.1.0 was released on August 17th, 2015.

skiboot-5.1.0 is the first stable release of 5.1.0 following two beta releases.
This new stable release replaces skiboot-5.0 as the current stable skiboot
release (5.0 was released April 14th 2015).

Skiboot 5.1.0 contains all fixes from skiboot-5.0 stable branch up to
skiboot-5.0.5 and everything from 5.1.0-beta1 and 5.1.0-beta2.

Over skiboot-5.1.0-beta2, we have the following changes:

- opal_prd now supports multiple socket systems
- fix compiler warnings in gard and libflash

Below are the changes introduced in previous skiboot-5.1.0 releases over
the previous stable release, skiboot-5.0:

New features
^^^^^^^^^^^^

- Add Naples chip (CPU, PHB, LPC serial interrupts) support
- Added qemu platform
- improvements to FSI error handling
- improvements in chip TOD failover (some only on FSP systems)
- Set Relative Priority Register (RPR) to recommended value

  - this affects thread priority in SMT modes

- greatly reduce memory consumption by CPU stacks for non-present CPUs

  - Previously we would reserve enough memory for max PIR for each CPU
    type.
  - This fix frees up 77MB of RAM on a typical P8 system.

- increased OPAL API documentation
- Asynchronous preloading of resources from FSP/flash

  - improves boot time on some systems

- Basic Garrison platform support
- Add Mambo platform (P8 Functional Simulator, systemsim)

  - includes fake NVRAM, RTC

- Support building with GCOV, increasing memory for skiboot binary to 2MB

  - includes boot code coverage testing

- Increased skiboot HEAP size.

  - We are not aware of any system where you would run out, but on large
    systems it was getting closer than we liked.

- add boot_tests.sh for helping automate boot testing on FSP and BMC machines
- Versioning of pflash and gard utilities to help Linux (or other OS)
  distributions with packaging.
- OCC throttle status messages to host
- CAPP timebase sync ("ibm,capp-timebase-sync" in DT to indicate CAPP timebase
  was synced by OPAL)
- opal-api: Add OPAL call to handle abnormal reboots.

``OPAL_CEC_REBOOT2`` currently supports two reboot types:

   0. normal reboot, that will behave similar to that of opal_cec_reboot() call
   1. platform error reboot.

Long term, this is designed to replace OPAL_CEC_REBOOT.

New features for FSP based machines
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
- in-band IPMI support
- ethernet adaptor location codes
- add DIMM frequency information to device tree
- improvements in FSP error log code paths
- fix some boot time memory leaks

  - harmless to end user

New features for AMI BMC based machines
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
- PCIe power workaround for K80
- Added support for Macronix 128Mbit flash chips
- Initial PRD support for Firestone platform
- improved reliability when BMC reboots

The following bugs have been fixed
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
- Increase PHB3 timeout for electrical links coming up to 2 seconds.

  - fixes issues with some Mellanox cards

- Hang in opal_reinit_cpus() that could prevent kdump from functioning
- PHB3: fix crash in phb3_init
- PHB3: fix crash with fenced PHB in phb3_init_hw()
- Fix bugs in hw/bt.c (interface for IPMI on BMC machines) that could possibly
  lead to a crash (dereferencing invalid address, deadlock)
- ipmi/sel: fix use-after-free
- Bug fixes in EEH handling

  - opal_pci_next_error() cleared OPAL_EVENT_PCI_ERROR unconditionally,
    possibly leading to missed errors.

- external/opal-prd: Only map each PRD range once

  - could eventually lead to failing to map PRD ranges

- On skiboot crash, don't try to print symbol when we didn't find one

  - makes backtrace prettier

- On skiboot crash, dump hssr0 and hsrr1 registers correctly.
- Better support old and biarch compilers

  - test "new" compiler flags before using them
  - Specify -mabi=elfv1 if supported (which means it's needed)

- fix boot-coverage-report makefile target
- ipmi: Fix the opal_ipmi_recv() call to handle the error path

- Could make kernel a sad panda when in continues with other IPMI commands
- IPMI: truncate SELs at 2kb

  - it's the limit of the astbmc. We think.

- IPMI/SEL/PEL:

  - As per PEL spec, we should log events with severity >= 0x22 and "service
    action flag" is "on". But in our case, all logs OPAL originagted logs
    are makred as report externally.
    We now only report logs with severity >= 0x22

- IPMI: fixes to eSEL logging
- hw/phb3: Change reserved PE to 255

  -  Currently, we have reserved PE#0 to which all RIDs are mapped prior
     to PE assignment request from kernel. The last M64 BAR is configured
     to have shared mode. So we have to cut off the first M64 segment,
     which corresponds to reserved PE#0 in kernel. If the first BAR
     (for example PF's IOV BAR) requires huge alignment in kernel, we
     have to waste huge M64 space to accommodate the alignment. If we
     have reserved PE#256, the waste of M64 space will be avoided.

FSP-specific bugs fixed
^^^^^^^^^^^^^^^^^^^^^^^
- (also fixed in skiboot-5.0.2) Fix race in firenze_get_slot_info() leading to
  assert() with many PCI cards

  With many PCI cards, we'd hit a race where calls to
  firenze_add_pcidev_to_fsp_inventory would step on each other leading to
  memory corruption and finally an assert() in the allocator being hit
  during boot.

- PCIe power workaround for K80 cards
- /ibm,opal/led renamed to /ibm,opal/leds in Device Tree

  - compatible change as no FSP based systems shipped with skiboot-5.0

General improvements
^^^^^^^^^^^^^^^^^^^^
- Preliminary Centaur i2c support

  - lays framework for supporting Centaur i2c

- don't run pollers on non-boot CPUs in time_wait
- improvements to opal-prd, pflash, libflash

  - including new blocklevel interface in libflash

- many minor fixes to issues found by static analysis
- improvements in FSP error log code paths
- code cleanup in memory allocator
- Don't expose individual nvram partitions in the device tree, just the whole
  flash device.
- build improvements for building on ppc64el host
- improvements in cpu_relax() for idle threads, needed for GCOV on large
  machines.
- Optimized memset() for POWER8, greatly reducing number of instructions
  executed for boot, which helps boot time in simulators.
- Major improvements in hello_world kernel

  - Bloat of huge 17 instruction test case reduced to 10.

- Disable bust_locks for general calls of abort()

  - Should enable better error messages during abort() when other users of
    LPC bus exist (e.g. flash)

- unified version numbers for bundled utilities
- external/boot_test/boot_test.sh

  - better usable for automated boot testing

Contributors
------------
Since skiboot-5.0, we've had the following changesets:

Processed 372 csets from 27 developers
2 employers found
A total of 15868 lines added, 3359 removed (delta 12509)

Developers with the most changesets

========================== =============
Developer                  Changesets
========================== =============
Stewart Smith              117 (31.5%)
Jeremy Kerr                 37 (9.9%)
Cyril Bur                   33 (8.9%)
Vasant Hegde                32 (8.6%)
Benjamin Herrenschmidt      32 (8.6%)
Kamalesh Babulal            22 (5.9%)
Joel Stanley                12 (3.2%)
Mahesh Salgaonkar           12 (3.2%)
Alistair Popple             12 (3.2%)
Neelesh Gupta                9 (2.4%)
Gavin Shan                   8 (2.2%)
Cédric Le Goater            8 (2.2%)
Ananth N Mavinakayanahalli    8 (2.2%)
Vipin K Parashar             6 (1.6%)
Michael Neuling              6 (1.6%)
Samuel Mendoza-Jonas         3 (0.8%)
Frederic Bonnard             3 (0.8%)
Andrew Donnellan             2 (0.5%)
Vaidyanathan Srinivasan      2 (0.5%)
Philippe Bergheaud           1 (0.3%)
Shilpasri G Bhat             1 (0.3%)
Daniel Axtens                1 (0.3%)
Hari Bathini                 1 (0.3%)
Michael Ellerman             1 (0.3%)
Andrei Warkentin             1 (0.3%)
Dan Horák                   1 (0.3%)
Anton Blanchard              1 (0.3%)
========================== =============


Developers with the most changed lines

========================== ============
========================== ============
Stewart Smith              4499 (27.3%)
Benjamin Herrenschmidt     3782 (22.9%)
Jeremy Kerr                1887 (11.4%)
Cyril Bur                  1654 (10.0%)
Vasant Hegde               959 (5.8%)
Mahesh Salgaonkar          886 (5.4%)
Neelesh Gupta              473 (2.9%)
Samuel Mendoza-Jonas       387 (2.3%)
Vipin K Parashar           332 (2.0%)
Philippe Bergheaud         171 (1.0%)
Shilpasri G Bhat           165 (1.0%)
Alistair Popple            151 (0.9%)
Joel Stanley               105 (0.6%)
Cédric Le Goater            89 (0.5%)
Gavin Shan                  83 (0.5%)
Frederic Bonnard            76 (0.5%)
Kamalesh Babulal            65 (0.4%)
Michael Neuling             46 (0.3%)
Daniel Axtens               31 (0.2%)
Andrew Donnellan            22 (0.1%)
Ananth N Mavinakayanahalli   20 (0.1%)
Anton Blanchard              3 (0.0%)
Vaidyanathan Srinivasan      2 (0.0%)
Hari Bathini                 2 (0.0%)
Michael Ellerman             1 (0.0%)
Andrei Warkentin             1 (0.0%)
Dan Horák                   1 (0.0%)
========================== ============

Developers with the most lines removed

=========================== ============
=========================== ============
Michael Neuling             24 (0.7%)
Hari Bathini                 1 (0.0%)
=========================== ============

Developers with the most signoffs (total 253)

=========================== ============
=========================== ============
Stewart Smith               249 (98.4%)
Mahesh Salgaonkar            4 (1.6%)
=========================== ============

Developers with the most reviews (total 24)

=========================== ============
=========================== ============
Vasant Hegde                 9 (37.5%)
Joel Stanley                 3 (12.5%)
Gavin Shan                   2 (8.3%)
Kamalesh Babulal             2 (8.3%)
Samuel Mendoza-Jonas         2 (8.3%)
Alistair Popple              2 (8.3%)
Stewart Smith                1 (4.2%)
Andrei Warkentin             1 (4.2%)
Preeti U Murthy              1 (4.2%)
Ananth N Mavinakayanahalli    1 (4.2%)
=========================== ============

Developers with the most test credits (total 1)

=========================== ============
=========================== ============
Chad Larson                  1 (100.0%)
=========================== ============

Developers who gave the most tested-by credits (total 1)

=========================== ============
=========================== ============
Gavin Shan                   1 (100.0%)
=========================== ============

Developers with the most report credits (total 4)

=========================== ============
=========================== ============
Benjamin Herrenschmidt       2 (50.0%)
Chad Larson                  1 (25.0%)
Andrei Warkentin             1 (25.0%)
=========================== ============

Developers who gave the most report credits (total 4)

=========================== ============
=========================== ============
Stewart Smith                3 (75.0%)
Gavin Shan                   1 (25.0%)
=========================== ============

Top changeset contributors by employer

========================== ============
========================== ============
IBM                        369 (99.2%)
(Unknown)                    3 (0.8%)
========================== ============

Top lines changed by employer

========================= ==============
========================= ==============
IBM                       16497 (100.0%)
(Unknown)                    3 (0.0%)
========================= ==============

Employers with the most signoffs (total 253)

========================= =============
========================= =============
IBM                        253 (100.0%)
========================= =============

Employers with the most hackers (total 27)

========================= ============
========================= ============
IBM                         24 (88.9%)
(Unknown)                    3 (11.1%)
========================= ============

