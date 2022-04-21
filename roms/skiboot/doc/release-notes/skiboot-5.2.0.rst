.. _skiboot-5.2.0:

skiboot-5.2.0
=============

skiboot-5.2.0 was released on Wednesday March 16th, 2016.

skiboot-5.2.0 is the first stable release of skiboot 5.2, the new stable
release of skiboot, which will take over from the 5.1.x series which was
first released August 17th, 2015.

skiboot-5.2.0 contains all bug fixes as of skiboot-5.1.15.

This is the second release that will follow the (now documented) Skiboot
stable rules - see :ref:`stable-rules`.

Changes since rc2
-----------------
Over skiboot-5.2.0-rc2, the following fixes are included:

- Include 'extract-gcov' in make clean.
- ipmi-sel: Fix esel event logger to handle early boot PANIC events
- IPMI: Enable synchronous eSEL logging option (for PANIC events)
- libflash/libffs: Reporting seeing all 0xFF bytes during init.
- ipmi-sel: Fix memory leak in error path

Changes since rc1
-----------------
Over skiboot-5.2.0-rc1, we have the following changes:

- Add Barreleye platform

Generic
^^^^^^^

- hw/p8-i2c: Speed up SMBUS_WRITE
- Fix early backtraces

FSP Platforms
^^^^^^^^^^^^^

- fsp-sensor: rework device tree for sensors
- platforms/firenze: Fix I2C clock source frequency

Simics simulator
^^^^^^^^^^^^^^^^

- Enable Simics UART console

Mambo simulator
^^^^^^^^^^^^^^^

- platforms/mambo: Add terminate callback

  - fix hang in multi-threaded mambo
  - add multithreaded mambo tests

IPMI
^^^^

- hw/ipmi: fix event data 1 for System Firmware Progress sensor
- ipmi: Log exact NetFn value in OPAL logs

AST BMC based platforms
^^^^^^^^^^^^^^^^^^^^^^^

- hw/bt: allow BT driver to use different buffer size

opal-prd utility
^^^^^^^^^^^^^^^^

- opal-prd: Add debug output for firmware-driven OCC events
    We indicate when we have a user-driven event, so add corresponding
    outputs for firmware-driven ones too.

getscom utility
^^^^^^^^^^^^^^^

- Add Naples chip support

New Features
^^^^^^^^^^^^
Over skiboot-5.1, the following features have been added:

- Naples (P8', i.e. P8 with NVLINK) processor support, including NVLINK.
- Improvements in gard, libflash/pflash and opal-prd utilities

  - increased testing
  - increased usability
  - systemd scripts for opal-prd
  - pflash can now use the /dev/mtd device to access BMC flash rather than
    accessing it directly. It is *important* that you use --mtd if your
    BMC may otherwise know how to interact with its own flash.
- support for Micron N25Q256Ax and N25Qx256Ax NOR flash.
- support for Winbond W25Q256BV NOR flash
- support for an emulated ("fake") RTC clock, useful in simulators
  and during bringup
- Explicit 1:1 mapping in ranges properties have been added to PCI
  bridges. This allows a neat trick with offb and VGA ports that should
  probably not be told to young children.
- Added support to read the V2 format of the OCC-OPAL memory region,
  which supports Workload Optimized Frequency (WOF)

Changes in behavior
^^^^^^^^^^^^^^^^^^^

- Assigning OPAL IDs to PHBs is now fixed and based on the chip id and PHB
  index on that chip. On POWER7, we continue to use allocated numbers.
- We now query the BMC for BT capabilities rather than making assumptions

Removed support
^^^^^^^^^^^^^^^

- p5ioc2 is no longer supported.
  This affects a grand total of two POWER7 systems in the world.

**NOTE**: It is planned that skiboot-5.2 will be the last release supporting
POWER7 machines.

Bugs fixed
^^^^^^^^^^

- PHB3: Fix unexpected ER (all) on errinjct by PCI config
- hw/bt: timeout messages when BT interface isn't functional
- On Habanero, Slot3 should have been "Slot 3".
- We now completely flush the console buffer before power down and reboot
- For chips with ibm,occ-functional-state set to false, we don't wait
  for the OCC to start. This caused needless delay in booting on simulators
  which did not simulate OCCs.
- Change OCC reset order to always reset slave OCCs first.
- slw: Remove overwrites for EX_PM_CORE_ECO_VRET and EX_PM_CORE_PFET_VRET
  (these were already initialized in hostboot)
- p8-i2c: send stop bit on timeouts.
  Some devices can otherwise leave the bus in a held state.

Other improvements
^^^^^^^^^^^^^^^^^^

- many fixes of compiler and static analysis warnings
- increased unit test coverage
- Unit test of "boot debian jessie installer"
- ability to plug in other simulators to run existing tests (e.g. simulator for
  non pegasus p8)
- Support using (patched) Qemu with PowerNV platform support for running
  unit tests.
- increased support for running with sparse
- We now build with -fstack-protector-strong if supported by the compiler
- We now build with -Werror for -Wformat
- pflash is now built as part of travis-ci and for Coverity Scan.
- There is now a RPM SPEC file that can be used as the basis for packaging
  skiboot and associated utilities.

Contributors
------------

We have had a number of improvements in workflow over skiboot-5.1.0. Looking
back, we have roughly the same number of changesets (372 for 5.1.0, 334 for
5.2.0-rc1 - even closer for 5.1.0-beta1) which indicates a relatively stable
rate of development.

Complete statistics are included below (generated by gitdm), but I'd like to
draw attention to a couple of stats:

======== ====== ======= ======= ======  ========
Release	 csets	Ack	Reviews	Tested	Reported
======== ====== ======= ======= ======  ========
5.0	 329	 15	     20	     1	       0
5.1	 372	 13	     38	     1	       4
5.2-rc1	 334	 20	     34	     6	      11
======== ====== ======= ======= ======  ========

Overall, it looks like we're on the right trajectory for increasing the number
of eyeballs looking at code before it heads in tree, especially around testing.
Largely, this increase in Tested-by can be attributed to encouraging the
existing test teams to start commenting on the patches themselves.

Anyway, here's the full stats from skiboot 5.1.0 to 5.2.0-rc1:

Processed 334 csets from 27 developers
2 employers found
A total of 46172 lines added, 23274 removed (delta 22898)

Developers with the most changesets

========================== ===========
========================== ===========
Stewart Smith              146 (43.7%)
Cyril Bur                   52 (15.6%)
Benjamin Herrenschmidt      15 (4.5%)
Joel Stanley                12 (3.6%)
Gavin Shan                  12 (3.6%)
Alistair Popple             10 (3.0%)
Vasant Hegde                10 (3.0%)
Michael Neuling             10 (3.0%)
Russell Currey               9 (2.7%)
Cédric Le Goater             8 (2.4%)
Jeremy Kerr                  8 (2.4%)
Samuel Mendoza-Jonas         6 (1.8%)
Neelesh Gupta                6 (1.8%)
Shilpasri G Bhat             4 (1.2%)
Oliver O'Halloran            4 (1.2%)
Mahesh Salgaonkar            4 (1.2%)
Vipin K Parashar             3 (0.9%)
Daniel Axtens                3 (0.9%)
Andrew Donnellan             2 (0.6%)
Philippe Bergheaud           2 (0.6%)
Ananth N Mavinakayanahalli   2 (0.6%)
Vaibhav Jain                 1 (0.3%)
Sam Mendoza-Jonas            1 (0.3%)
Adriana Kobylak              1 (0.3%)
Shreyas B. Prabhu            1 (0.3%)
Vaidyanathan Srinivasan      1 (0.3%)
Ian Munsie                   1 (0.3%)
========================== ===========

Developers with the most changed lines


========================== =============
========================== =============
Stewart Smith              19533 (39.4%)
Oliver O'Halloran          17920 (36.1%)
Alistair Popple             3285 (6.6%)
Daniel Axtens               2154 (4.3%)
Cyril Bur                   2028 (4.1%)
Benjamin Herrenschmidt       941 (1.9%)
Neelesh Gupta                434 (0.9%)
Gavin Shan                   294 (0.6%)
Russell Currey               261 (0.5%)
Vasant Hegde                 245 (0.5%)
Cédric Le Goater             209 (0.4%)
Vipin K Parashar             155 (0.3%)
Shilpasri G Bhat             153 (0.3%)
Joel Stanley                 140 (0.3%)
Vaidyanathan Srinivasan      135 (0.3%)
Michael Neuling              111 (0.2%)
Samuel Mendoza-Jonas          81 (0.2%)
Jeremy Kerr                   60 (0.1%)
Mahesh Salgaonkar             58 (0.1%)
Vaibhav Jain                  50 (0.1%)
Ananth N Mavinakayanahalli    43 (0.1%)
Shreyas B. Prabhu             17 (0.0%)
Sam Mendoza-Jonas             12 (0.0%)
Andrew Donnellan              10 (0.0%)
Ian Munsie                     8 (0.0%)
Philippe Bergheaud             6 (0.0%)
Adriana Kobylak                6 (0.0%)
========================== =============

Developers with the most lines removed

========================= =============
========================= =============
Daniel Axtens             2149 (9.2%)
Shreyas B. Prabhu           17 (0.1%)
Andrew Donnellan             9 (0.0%)
Vipin K Parashar             2 (0.0%)
========================= =============

Developers with the most signoffs (total 190)

========================= =============
========================= =============
Stewart Smith              188 (98.9%)
Gavin Shan                   1 (0.5%)
Neelesh Gupta                1 (0.5%)
========================= =============

Developers with the most reviews (total 34)

========================= =============
========================= =============
Patrick Williams             5 (14.7%)
Joel Stanley                 5 (14.7%)
Cédric Le Goater            5 (14.7%)
Vasant Hegde                 4 (11.8%)
Alistair Popple              4 (11.8%)
Sam Mendoza-Jonas            3 (8.8%)
Samuel Mendoza-Jonas         3 (8.8%)
Andrew Donnellan             2 (5.9%)
Cyril Bur                    2 (5.9%)
Vaibhav Jain                 1 (2.9%)
========================= =============

Developers with the most test credits (total 6)

========================= =============
========================= =============
Vipin K Parashar             3 (50.0%)
Vaibhav Jain                 2 (33.3%)
Gajendra B Bandhu1           1 (16.7%)
========================= =============

Developers who gave the most tested-by credits (total 6)

=========================== =============
=========================== =============
Gavin Shan                   2 (33.3%)
Ananth N Mavinakayanahalli    2 (33.3%)
Alistair Popple              1 (16.7%)
Stewart Smith                1 (16.7%)
=========================== =============

Developers with the most report credits (total 11)

========================= =============
========================= =============
Vaibhav Jain                 2 (18.2%)
Paul Nguyen                  2 (18.2%)
Alistair Popple              1 (9.1%)
Cédric Le Goater            1 (9.1%)
Aneesh Kumar K.V             1 (9.1%)
Dionysius d. Bell            1 (9.1%)
Pradeep Ramanna              1 (9.1%)
John Walthour                1 (9.1%)
Benjamin Herrenschmidt       1 (9.1%)
========================= =============

Developers who gave the most report credits (total 11)

========================= =============
========================= =============
Gavin Shan                   6 (54.5%)
Stewart Smith                3 (27.3%)
Samuel Mendoza-Jonas         1 (9.1%)
Shilpasri G Bhat             1 (9.1%)
========================= =============
