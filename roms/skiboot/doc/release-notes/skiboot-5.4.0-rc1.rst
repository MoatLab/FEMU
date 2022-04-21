.. _skiboot-5.4.0-rc1:

skiboot-5.4.0-rc1
=================

skiboot-5.4.0-rc1 was released on Monday October 17th 2016. It is the first
release candidate of skiboot 5.4, which will become the new stable release
of skiboot following the 5.3 release, first released August 2nd 2016.

skiboot-5.4.0-rc1 contains all bug fixes as of :ref:`skiboot-5.3.7`
and :ref:`skiboot-5.1.18` (the currently maintained stable releases).

For how the skiboot stable releases work, see :ref:`stable-rules` for details.

The current plan is to release a new release candidate every week until we
feel good about it. The aim is for skiboot-5.4.x to be in op-build v1.13, which
is due by November 23rd 2016.

Over skiboot-5.3, we have the following changes:

New Features
------------
- Initial Trusted Boot support (see :ref:`stb-overview`).
  There are several limitations with this initial release:

    - CAPP partition is not measured correctly
    - Only Nuvoton TPM 2.0 is supported
    - Requires hardware rework on late revision Habanero or Firestone boards
      in order to install TPM.

  - Add i2c Nuvoton TPM 2.0 Driver
  - romcode driver for POWER8 secure ROM
  - See Device tree docs for tpm and ibm,secureboot nodes
  - See main secure and trusted boot documentation.


- Fast reboot for P8

  This makes reboot take an *awful* lot less time, somewhere between four
  and ten times faster than a full IPL. It is currently experimental and not
  enabled by default.
  You can enable the experimental support via nvram option: ::

   # nvram -p ibm,skiboot --update-config experimental-fast-reset=feeling-lucky

  **WARNING**: This has *known* bugs. For example, if you have used a device
  in CAPI mode, we will currently *NOT* reset it back to plain PCI. There
  are also some known issues in most simulators.

- Support ``ibm,skiboot`` NVRAM partition with skiboot configuration options.

  - These should generally only be used if you either completely know what
    you are doing or need to work around a skiboot bug. They are **not**
    intended for end users.
  - Add support for supplying the kernel boot arguments from the ``bootargs``
    configuration string in the ``ibm,skiboot`` NVRAM partition.
  - Enabling the experimental fast reset feature is done via this method.

- Add support for nap mode on P8 while in skiboot

  - While nap has been exposed to the Operating System since day 1, we have
    not utilized low power states when in skiboot itself, leading to higher
    power consumption during boot.
    We only enable the functionality after the 0x100 vector has been
    patched, and we disable it before transferring control to Linux.

- libflash: add 128MB MX66L1G45G part

- Pointer validation of OPAL API call arguments.

  - If the kernel called an OPAL API with vmalloc'd address
    or any other address range in real mode, we would hit
    a problem with aliasing. Since the top 4 bits are ignored
    in real mode, pointers from 0xc.. and 0xd.. (and other ranges)
    could collide and lead to hard to solve bugs. This patch
    adds the infrastructure for pointer validation and a simple
    test case for testing the API
  - The checks validate pointers sent in using ``opal_addr_valid()``

Documentation
-------------

There have been a number of documentation fixes this release. Most prominent
is the switch to Sphinx (from the Python project) and ReStructured Text (RST)
as the documentation format. RST and Sphinx enable both production of pretty
documentation in HTML and PDF formats while remaining readable in their raw
form to those with no knowledge of RST.

You can build a HTML site by doing the following: ::

 cd doc/
 make html

As always, documentation patches are very, *very* welcome as we attempt to
document the OPAL API, the device tree bindings and important parts of
OPAL internals.

We would like the Device Tree documentation to follow the style that can be
included in the Device Tree Specification.


General
-------
- Make console-log time more readable: seconds rather than timebase
  Log format is now ``[SECONDS.(tb%512000000),LEVEL]``

- Flash (PNOR) code improvements

  - flash: Make size 64 bit safe
    This makes the size of flash 64 bit safe so that we can have flash
    devices greater than 4GB. This is especially useful for mambo disks
    passed through to Linux.
  - core/flash.c: load actual partition size
    We are downloading 0x20000 bytes from PNOR for CAPP, but currently the
    CAPP lid is only 40K.
  - flash: Rework error paths and messages for multiple flash controllers
    Now that we have mambo bogusdisk flash, we can have many flash chips.
    This is resulting in some confusing output messages.

- core/init: Fix "failure of getting node in the free list" warning on boot.
- slw: improve error message for SLW timer stuck

- Centaur / XSCOM error handling

  - print message on disabling xscoms to centaur due to many errors
  - Mark centaur offline after 10 consecutive access errors

- XSCOM improvements

  - xscom: Map all HMER status codes to OPAL errors
  - xscom: Initialize the data to a known value in ``xscom_read``
    In case of error, don't leave the data random. It helps debugging when
    the user fails to check the error code. This happens due to a bug in the
    PRD wrapper app.
  - chip: Add a quirk for when core direct control XSCOMs are missing

- p8-i2c: Don't crash if a centaur errored out

- cpu: Make endian switch message more informative
- cpu: Display number of started CPUs during boot
- core/init: ensure that HRMOR is zero at boot
- asm: Fix backtrace for unexpected exception

- cpu: Remove pollers calling heuristics from ``cpu_wait_job``
  This will be handled by ``time_wait_ms()``. Also remove a useless
  ``smt_medium()``.
  Note that this introduce a difference in behaviour: time_wait
  will only call the pollers on the boot CPU while ``cpu_wait_job()``
  could call them on any. However, I can't think of a case where
  this is a problem.

- cpu: Remove global job queue
  Instead, target a specific CPU for a global job at queuing time.
  This will allow us to wake up the target using an interrupt when
  implementing nap mode.
  The algorithm used is to look for idle primary threads first, then
  idle secondaries, and finally the less loaded thread. If nothing can
  be found, we fallback to a synchronous call.
- lpc: Log LPC SYNC errors as unrecoverable ones for manufacturing
- lpc: Optimize SerIRQ dispatch based on which PSI IRQ fired
- interrupts: Add new source ``->attributes()`` callback
    This allows a given source to provide per-interrupt attributes
    such as whether it targets OPAL or Linux and it's estimated
    frequency.

    The former allows to get rid of the double set of ops used to
    decide which interrupts go where on some modules like the PHBs
    and the latter will be eventually used to implement smart
    caching of the source lookups.
- opal/hmi: Fix a TOD HMI failure during a race condition.
- platform: Add BT to Generic platform


NVRAM
-----
- Support ``ibm,skiboot`` partition for skiboot specific configuration options
- flash: Size NVRAM based on ECC for OpenPOWER platforms
    If NVRAM has ECC (as per the ffs header) then the actual size of the
    partition is less than reported by the ffs header in the PNOR then the
    actual size of the partition is less than reported by the ffs header.

NVLink/NPU
----------

- Fix reserved PE#
- NPU bdfn allocation bugfix
- Fix bad PE number check
    NPUs have 4 PEs which are zero indexed, so {0, 1, 2, 3}.  A bad PE number
    check in npu_err_inject checks if the PE number is greater than 4 as a
    fail case, so it would wrongly perform operations on a non-existant PE 4.
- Use PCI virtual device
- assert the NPU irq min is aligned.
- program NPU BUID reg properly
- npu: reword "error" to indicate it's actually a warning
   Incorrect FWTS annotation.
   Without this patch, you get spurious FirmWare Test Suite (FWTS) warnings
   about NVLink not working on machines that aren't fully populated with
   GPUs.
- external: NPU hardware procedure script
   Performing NPU hardware procedures requires some config space magic.
   Put all that magic into a script, so you can just specify the target
   device and the procedure number.

PCI
---

- Generic fixes

  - Claim surprise hotplug capability
  - Reserve PCI buses for RC's slot
  - Update PCI topology after power change
  - Return slot cached power state
  - Cache power state on slot without power control
  - Avoid hot resets at boot time
  - Fix initial PCIe slot power state
  - Print CRS retry times
    It's useful to know the CRS retry times before the PCI device is
    detected successfully. In PCI hot add case, it usually indicates
    time consumed for the adapter's firmware to be partially ready
    (responsive PCI config space).
  - core/pci: Fix the power-off timeout in ``pci_slot_power_off()``
    The timeout should be 1000ms instead of 1000 ticks while powering
    off PCI slot in ``pci_slot_power_off()``. Otherwise, it's likely to
    hit timeout powering off the PCI slot as below skiboot logs reveal: ::

      [5399576870,5] PHB#0005:02:11.0 Timeout powering off slot

- PHB3

  - Override root slot's ``prepare_link_change()`` with PHB's
  - Disable surprise link down event on PCI slots
  - Disable ECRC on Broadcom adapter behind PMC switch

- astbmc platforms

  - Support dynamic PCI slot. We might insert a PCIe switch to PHB direct slot
    and the downstream ports of the PCIe switch supports PCI hotplug.


CAPI
----

- hw/phb3: Update capi initialization sequence
    The capi initialization sequence was revised in a circumvention
    document when a 'link down' error was converted from fatal to Endpoint
    Recoverable. Other, non-capi, register setup was corrected even before
    the initial open-source release of skiboot, but a few capi-related
    registers were not updated then, so this patch fixes it.

IPMI
----

- core/ipmi: Set interrupt-parent property
    This allows ipmi-opal to properly use the OPAL irqchip rather than
    falling back to the event interface in Linux.

Mambo Simulator
---------------

- Helpers for POWER9 Mambo.
- mambo: Advertise available RADIX page sizes
- mambo: Add section for kernel command line boot args
  Users can set kernel command line boot arguments for Mambo in a tcl
  script.
- mambo: add exception and qtrace helpers
- external/mambo: Update skiboot.tcl to add page-sizes nodes to device tree

Simics Simulator
----------------

- chiptod: Enable ChipTOD in SIMICS

Utilities
---------

- pflash

  - fix harmless buffer overflow: ``fl_total_size`` was ``uint32_t`` not ``uint64_t``.
  - Don't try to write protect when writing to flash file
  - Misc small improvements to code and code style
  - makefile bug fixes


- external/boot_tests

  - remove lid from the BMC after flashing
  - add the nobooting option -N
  - add arbitrary lid option -F

- ``getscom`` / ``getsram`` / ``putscom``: Parse chip-id as hex
    We print the chip-id in hex (without a leading 0x), but we fail to
    parse that same value correctly in ``getscom`` / ``getsram`` / ``putscom`` ::

     # getscom -l
     ...
     80000000 | DD2.0 | Centaur memory buffer
     # getscom -c 80000000 201140a
     Error -19 reading XSCOM

    Fix this by assuming base 16 when parsing chip-id.

PRD
---

- opal-prd: Fix error code from ``scom_read`` and ``scom_write``
- opal-prd: Add get_interface_capabilities to host interfaces
- opal-prd: fix for 64-bit pnor sizes
- occ/prd/opal-prd: Queue OCC_RESET event message to host in OpenPOWER
    During an OCC reset cycle the system is forced to Psafe pstate.
    When OCC becomes active, the system has to be restored to its
    last pstate as requested by host. So host needs to be notified
    of OCC_RESET event or else system will continue to remian in
    Psafe state until host requests a new pstate after the OCC
    reset cycle.

IBM FSP Based Platforms
-----------------------

- fsp/console: Allocate irq for each hvc console
    Allocate an irq number for each hvc console and set its interrupt-parent
    property so that Linux can use the opal irqchip instead of the
    OPAL_EVENT_CONSOLE_INPUT interface.
- platforms/firenze: Fix clock frequency dt property: ::

    [ 1.212366090,3] DT: Unexpected property length /xscom@3fc0000000000/i2cm@a0020/clock-frequency

- HDAT: Fix typo in nest-frequency property
    nest-frquency -> nest-frequency
- platforms/ibm-fsp: Use power_ctl bit when determining slot reset method
    The power_ctl bit is used to represent if power management is available.
    If power_ctl is set to true, then the I2C based external power management
    functionality will be populated on the PCI slot. Otherwise we will try to
    use the inband PERST as the fundamental reset, as before.
- FSP/ELOG: Fix elog timeout issue
    Presently we set timeout value as soon as we add elog to queue. If
    we have multiple elogs to write, it doesn't consider queue wait time.
    Instead set timeout value when we are actually sending elog to FSP.
- FSP/ELOG: elog_enable flag should be false by default
    This issue is one of the corner case, which is related to recent change
    went upstream and only observed in the petitboot prompt, where we see
    only one error log instead of getting all error log in
    ``/sys/firmware/opal/elog``.



POWER9
------

- mambo: Make POWER9 look like DD2
- flash: Move flash node under ``ibm,opal/flash/``
    This changes the boot ABI, so it's only active for P9 and later systems,
    even though it's unrelated to hardware changes. There is an associated
    Linux change to properly search for this node as well.
- core/cpu.c: Add OPAL call to setup Nest MMU
- psi: On p9, create an interrupt-map for routing PSI interrupts
- lpc: Add P9 LPC interrupts support
- chiptod: Basic P9 support
- psi: Add P9 support

Testing and Debugging
---------------------

- test/qemu: bump qemu version used in CI, adds IPMI support
- platform/qemu: add BT and IPMI support
  Enables testing BT and IPMI functionality in the Qemu simulator
- init: In debug builds, enable debug output to console
- mem_region: Be a bit smarter about poisoning
    Don't poison chunks that are already free and poison regions on
    first allocation. This speeds things up dramatically.
- libc: Use 8-bytes stores for non-0 memset too
    Memory poisoning hammers this, so let's be a bit smart about it and
    avoid falling back to byte stores when the data is not 0
- fwts: add annotation for manufacturing mode
- check: Fix bugs in mem region tests
- Don't set -fstack-protector-all unconditionally
    We set it already in DEBUG builds and we use -fstack-protector-strong
    in release builds which provides most of the benefits and is more
    efficient.
- Build host programs (and checks) with debug enabled
    This enables memory poisoning in allocations and list checking
    among other things.
- Add global DEBUG make flag


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
5.4-rc1  278      8          19      0         4
======== ====== ======= ======= ======  ========

This release has fewer changesets over previous 5.x first release candidates,
but that is not indicative of the size or complexity of these changes.


Processed 278 csets from 31 developers
A total of 17052 lines added, 4745 removed (delta 12307)

Developers with the most changesets

=========================== == =======
=========================== == =======
Stewart Smith               71 (25.5%)
Benjamin Herrenschmidt      50 (18.0%)
Claudio Carvalho            38 (13.7%)
Gavin Shan                  20 (7.2%)
Oliver O'Halloran           18 (6.5%)
Mukesh Ojha                  9 (3.2%)
Cyril Bur                    7 (2.5%)
Russell Currey               7 (2.5%)
Vasant Hegde                 7 (2.5%)
Pridhiviraj Paidipeddi       6 (2.2%)
Michael Neuling              6 (2.2%)
Alistair Popple              4 (1.4%)
Sam Mendoza-Jonas            3 (1.1%)
Vipin K Parashar             3 (1.1%)
Balbir Singh                 3 (1.1%)
Mahesh Salgaonkar            3 (1.1%)
Frederic Barrat              3 (1.1%)
Chris Smart                  2 (0.7%)
Jack Miller                  2 (0.7%)
Patrick Williams             2 (0.7%)
Jeremy Kerr                  2 (0.7%)
Suraj Jitindar Singh         2 (0.7%)
Milton Miller                2 (0.7%)
Shilpasri G Bhat             1 (0.4%)
Frederic Bonnard             1 (0.4%)
Joel Stanley                 1 (0.4%)
Breno Leitao                 1 (0.4%)
Anton Blanchard              1 (0.4%)
Nicholas Piggin              1 (0.4%)
Nageswara R Sastry           1 (0.4%)
Cédric Le Goater             1 (0.4%)
=========================== == =======

Developers with the most changed lines

========================= ==== =======
========================= ==== =======
Claudio Carvalho          6817 (38.2%)
Stewart Smith             4677 (26.2%)
Benjamin Herrenschmidt    2586 (14.5%)
Gavin Shan                1005 (5.6%)
Cyril Bur                  509 (2.9%)
Mukesh Ojha                361 (2.0%)
Oliver O'Halloran          343 (1.9%)
Russell Currey             343 (1.9%)
Balbir Singh               227 (1.3%)
Pridhiviraj Paidipeddi     194 (1.1%)
Michael Neuling            121 (0.7%)
Cédric Le Goater           115 (0.6%)
Vipin K Parashar            68 (0.4%)
Alistair Popple             66 (0.4%)
Vasant Hegde                65 (0.4%)
Shilpasri G Bhat            45 (0.3%)
Suraj Jitindar Singh        41 (0.2%)
Nicholas Piggin             34 (0.2%)
Sam Mendoza-Jonas           33 (0.2%)
Jack Miller                 32 (0.2%)
Nageswara R Sastry          32 (0.2%)
Jeremy Kerr                 23 (0.1%)
Mahesh Salgaonkar           21 (0.1%)
Chris Smart                 20 (0.1%)
Milton Miller               19 (0.1%)
Patrick Williams            11 (0.1%)
Frederic Barrat              6 (0.0%)
Anton Blanchard              3 (0.0%)
Frederic Bonnard             2 (0.0%)
Joel Stanley                 2 (0.0%)
Breno Leitao                 2 (0.0%)
========================= ==== =======

Developers with the most lines removed

========================= ==== =======
========================= ==== =======
Cyril Bur                  299 (6.3%)
========================= ==== =======

Developers with the most signoffs (total 226)

========================= ==== =======
========================= ==== =======
Stewart Smith              219 (96.9%)
Alistair Popple              4 (1.8%)
Cyril Bur                    1 (0.4%)
Jeremy Kerr                  1 (0.4%)
Benjamin Herrenschmidt       1 (0.4%)
========================= ==== =======

Developers with the most reviews (total 19)

========================= ==== =======
========================= ==== =======
Mukesh Ojha                  5 (26.3%)
Andrew Donnellan             4 (21.1%)
Vasant Hegde                 3 (15.8%)
Russell Currey               3 (15.8%)
Balbir Singh                 2 (10.5%)
Cyril Bur                    1 (5.3%)
Vaidyanathan Srinivasan      1 (5.3%)
========================= ==== =======

Developers with the most test credits (total 0)

Developers who gave the most tested-by credits (total 0)

Developers with the most report credits (total 4)

========================= ==== =======
========================= ==== =======
Benjamin Herrenschmidt       1 (25.0%)
Li Meng                      1 (25.0%)
Pridhiviraj Paidipeddi       1 (25.0%)
Gavin Shan                   1 (25.0%)
========================= ==== =======

Developers who gave the most report credits (total 4)

========================= ==== =======
========================= ==== =======
Gavin Shan                   1 (25.0%)
Vasant Hegde                 1 (25.0%)
Russell Currey               1 (25.0%)
Stewart Smith                1 (25.0%)
========================= ==== =======
