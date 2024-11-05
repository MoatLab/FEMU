skiboot-5.3.0-rc1
=================

skiboot-5.3.0-rc1 was released on Monday July 25th, 2016

skiboot-5.3.0-rc1 is the first release candidate of skiboot 5.3, which will
become the new stable release of skiboot following the 5.2 release, first
released March 16th 2016.

skiboot-5.3.0-rc1 contains all bug fixes as of skiboot-5.1.16
and skiboot-5.2.4 (the existing stable releases).

For how the skiboot stable releases work, see :ref:`stable-rules`.

The current plan is to release skiboot-5.3.0 August 1st 2016.

Over skiboot-5.2, we have the following changes:

OPAL API/Device Tree
--------------------

- Reserve OPAL API numbers for XICS emulation for XIVE
   Additionally, we put in some skeleton docs for what's coming,
   key points being that this is for P9 and above, relies on a device
   being present in the device tree and is modelled on the PAPR calls.
- interrupts: Remove #interrupt-cells from ICP nodes
- Stop adding legacy linux, phandle to device tree, just add phandle
  No Linux kernel has ever existed for powernv that only knows linux,phandle.

POWER9
------

- Add base POWER9 support
  In *NO WAY* is this geared towards real POWER9 hardware.
  Suitable for use in simulators *only*, and even then, only if you
  intensely know what you're doing.
- Document changes in OPAL API for POWER9
  Some things are going to change, we start documenting them.
- cpu: supply ibm,dec-bits via devicetree
- power9: Add example device tree for phb4
- device-tree: Only advertise ibm, opal-v3 (not v2) on POWER9 and above

CAPI
----

- phb3: Test CAPI mode on both CAPP units on Naples
- hmi: Recover both CAPP units on Naples after malfunction alert
- chiptod: Sync timebase in both CAPP units on Naples
- phb3: Set CAPI mode for both CAPP units on Naples
- phb3: Load CAPP ucode to both CAPP units on Naples
- phb3: Add support for CAPP DMA mode
    The XSL used in the Mellanox CX4 card uses a DMA mode of CAPI, which
    requires a few registers configured specially. This adds a new mode to
    the OPAL_PCI_SET_PHB_CAPI_MODE API to enable CAPI in DMA mode.

PCI
---

- pci: Do a dummy config write to devices to establish bus number
- phb: Work around XSL bug sending PTE updates with wrong scope
- Support for PCI hotplug (if a platform supports it)

Garrison
--------

- NVLink/NPU support
- Full garrison platform support.

BMC based platforms
-------------------

- bt: use the maximum retry count returned by the BMC
- SEL: Fix eSEL ID while logging eSEL event
    Commit 127a7dac added eSEL ID to SEL event in reverse order (0700 instead
    of 0007). This code fixes this issue by adding ID in proper order.

Tests/Simulation
----------------

- test/hello_world: always use shutdown type zero
- make check: make test runs less noisy
- boot-tests: force booting from primary (non-golden) side
- mambo: Enable multicore configurations
- mambo: Flatten device tree at the end
- mambo: Increase memory to 4GB and change memory map
- Timebase quirk for slow simulators like AWAN and SIMICS
- chip: Add simics specific quirks
- mambo: Flash driver using bogus disk
- platform/mambo: Add a heartbeat time, making console more responsive
- mambo: Fix bt command and add little endian support

FSP platforms
-------------

- beginnings of support for SPIRA-S structure
- Handle mbox response with bad status:0x24 during FSP termination
- FSP: Validate fsp_msg response memory allocation
- FSP/ELOG: Fix OPAL generated elog event notification
- FSP/ELOG: Disable event notification during kexec
  Possible crash if error log timing around kexec is unfortunate
- fsp/console: Ignore data on unresponsive consoles

    Linux kernels from v4.1 onwards will try to request an irq for each hvc
    console using OPAL_EVENT_CONSOLE_INPUT, however because the IRQF_SHARED
    flag is not set any console after the first will fail. If there is data
    on one of these failed consoles OPAL will set OPAL_EVENT_CONSOLE_INPUT
    every time fsp_console_read is called, leading to RCU stalls in the
    kernel.

    As a workaround for unpatched kernels, cease setting
    OPAL_EVENT_CONSOLE_INPUT for consoles that we have noticed are not being
    read.

HMI
---

- hmi: Fix a bug where partial hmi event was reported to host.
- hmi: Add handling for NPU checkstops
- hmi: Only raise a catchall HMI if no other components have
- hmi: Rework HMI event handling of FIR read failure

Tools
-----

- external: Add a getsram command
    The getsram command reads the OCC SRAM. This is useful for debug.
- bug fixes in flash utilities (pflash/gard)
- pflash: Allow building under yocto.
- external/opal-prd: Ensure that struct host_interfaces matches the thunk
- external/pflash: Handle incorrect cmd-line options better
- libflash: fix bug on reading truncated flash file
- pflash: add support for manipulating file rather than flash
- gard: fix compile error on ARM
- libflash: Add sanity checks to ffs init code.
- external: Add dynamically linked pflash

Mambo
-----

- Test device tree for kernel location
    This can reduce the boot time since the kernel no longer needs to
    relocate itself when loaded directly at 0.

Generic
-------

- hw/lpc: Log LPC SYNC errors as OPAL_PLATFORM_ERR_EVT errors
- Explicitly disable the attn instruction on all CPUs on boot.
- hw/xscom: Reset XSCOM engine after finite number of retries when busy
- hw/xscom: Reset XSCOM engine after querying sleeping core FIR
- core/timer: Add support for platform specific heartbeat
- Fix GCOV_COUNTERS ifdef logic for GCC 6.0
- core: Fix backtrace for gcc 6
  fixes a compiler warning on GCC 6 and above
- cpu: Don't call time_wait with lock held
    Also make the locking around re-init safer, properly block the
    OS from restarting a thread that was caught for re-init.
- flash: Increase the maximum number of flash devices

Contributors
------------

Extending the analysis done for the last few releases, we can see our trends
in code review across versions:

======== ====== ======= ======= ======  ========
Release	 csets	Ack	Reviews	Tested	Reported
======== ====== ======= ======= ======  ========
5.0	 329	 15	     20	     1	       0
5.1	 372	 13	     38	     1	       4
5.2-rc1	 334	 20	     34	     6	      11
5.3-rc1  302     36          53      4         5
======== ====== ======= ======= ======  ========

An increase in reviews this cycle is great!

Detailed statistics for 5.3.0-rc1 are below:

Processed 302 csets from 31 developers
A total of 20887 lines added, 4540 removed (delta 16347)

Developers with the most changesets

=========================== ============
=========================== ============
Stewart Smith               82 (27.2%)
Gavin Shan                  36 (11.9%)
Benjamin Herrenschmidt      28 (9.3%)
Michael Neuling             25 (8.3%)
Vasant Hegde                24 (7.9%)
Russell Currey              14 (4.6%)
Brad Bishop                 12 (4.0%)
Vipin K Parashar            10 (3.3%)
Cédric Le Goater             9 (3.0%)
Shreyas B. Prabhu            8 (2.6%)
Jeremy Kerr                  7 (2.3%)
Philippe Bergheaud           6 (2.0%)
Cyril Bur                    5 (1.7%)
Mukesh Ojha                  4 (1.3%)
Alistair Popple              4 (1.3%)
Ian Munsie                   4 (1.3%)
Oliver O'Halloran            3 (1.0%)
Chris Smart                  3 (1.0%)
Sam Mendoza-Jonas            2 (0.7%)
Joel Stanley                 2 (0.7%)
Dinar Valeev                 2 (0.7%)
Shilpasri G Bhat             2 (0.7%)
Patrick Williams             2 (0.7%)
Deb McLemore                 1 (0.3%)
Balbir Singh                 1 (0.3%)
Andrew Donnellan             1 (0.3%)
Suraj Jitindar Singh         1 (0.3%)
Frederic Bonnard             1 (0.3%)
Kamalesh Babulal             1 (0.3%)
Mamatha                      1 (0.3%)
Mahesh Salgaonkar            1 (0.3%)
=========================== ============

Developers with the most changed lines

========================= ============
========================= ============
Benjamin Herrenschmidt    7491 (34.4%)
Gavin Shan                4821 (22.1%)
Vasant Hegde              4740 (21.7%)
Stewart Smith             1294 (5.9%)
Michael Neuling            620 (2.8%)
Cédric Le Goater           470 (2.2%)
Jeremy Kerr                338 (1.6%)
Shreyas B. Prabhu          330 (1.5%)
Vipin K Parashar           305 (1.4%)
Russell Currey             295 (1.4%)
Alistair Popple            229 (1.1%)
Philippe Bergheaud         170 (0.8%)
Ian Munsie                 133 (0.6%)
Dinar Valeev               126 (0.6%)
Brad Bishop                 80 (0.4%)
Oliver O'Halloran           80 (0.4%)
Cyril Bur                   62 (0.3%)
Frederic Bonnard            61 (0.3%)
Sam Mendoza-Jonas           32 (0.1%)
Chris Smart                 27 (0.1%)
Shilpasri G Bhat            20 (0.1%)
Patrick Williams            18 (0.1%)
Suraj Jitindar Singh        17 (0.1%)
Mamatha                     15 (0.1%)
Mukesh Ojha                  8 (0.0%)
Mahesh Salgaonkar            8 (0.0%)
Joel Stanley                 4 (0.0%)
Balbir Singh                 4 (0.0%)
Kamalesh Babulal             2 (0.0%)
Deb McLemore                 1 (0.0%)
Andrew Donnellan             1 (0.0%)
========================= ============

Developers with the most lines removed

========================= ============
========================= ============
Dinar Valeev                68 (1.5%)
Patrick Williams            10 (0.2%)
Mukesh Ojha                  4 (0.1%)
Kamalesh Babulal             1 (0.0%)
========================= ============

Developers with the most signoffs (total 249)

========================= ============
========================= ============
Stewart Smith              236 (94.8%)
Vaidyanathan Srinivasan      6 (2.4%)
Benjamin Herrenschmidt       3 (1.2%)
Michael Neuling              2 (0.8%)
Oliver O'Halloran            1 (0.4%)
Vipin K Parashar             1 (0.4%)
========================= ============

Developers with the most reviews (total 53)

========================= ============
========================= ============
Andrew Donnellan            11 (20.8%)
Russell Currey               9 (17.0%)
Joel Stanley                 7 (13.2%)
Alistair Popple              7 (13.2%)
Mukesh Ojha                  5 (9.4%)
Cyril Bur                    3 (5.7%)
Mahesh Salgaonkar            2 (3.8%)
Gavin Shan                   2 (3.8%)
Vasant Hegde                 2 (3.8%)
Stewart Smith                1 (1.9%)
Vaidyanathan Srinivasan      1 (1.9%)
Vipin K Parashar             1 (1.9%)
Frederic Barrat              1 (1.9%)
Cédric Le Goater             1 (1.9%)
========================= ============

Developers with the most test credits (total 4)

========================= ============
========================= ============
Andrew Donnellan             2 (50.0%)
Russell Currey               1 (25.0%)
Vaibhav Jain                 1 (25.0%)
========================= ============

Developers who gave the most tested-by credits (total 4)

========================= ============
========================= ============
Michael Neuling              3 (75.0%)
Gavin Shan                   1 (25.0%)
========================= ============

Developers with the most report credits (total 5)

========================= ============
========================= ============
Mukesh Ojha                  2 (40.0%)
Russell Currey               1 (20.0%)
Pridhiviraj Paidipeddi       1 (20.0%)
Balbir Singh                 1 (20.0%)
========================= ============

Developers who gave the most report credits (total 5)

========================= ============
========================= ============
Gavin Shan                   2 (40.0%)
Stewart Smith                2 (40.0%)
Vasant Hegde                 1 (20.0%)
========================= ============
