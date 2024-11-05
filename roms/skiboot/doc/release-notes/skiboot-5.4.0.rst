.. _skiboot-5.4.0:

=============
skiboot-5.4.0
=============

skiboot-5.4.0 was released on Friday November 11th 2016. It is the new stable
skiboot release, taking over from the 5.3.x series (first released August 2nd,
2016). It comes after four release candidates, which have helped to shake out
a few issues.

skiboot-5.4.0 contains all bug fixes as of :ref:`skiboot-5.3.7`
and :ref:`skiboot-5.1.18` (the currently maintained stable releases).

Skiboot 5.4.x becomes the new stable release. For how the skiboot stable
releases work, see :ref:`stable-rules` for details.

Over :ref:`skiboot-5.4.0-rc4`, we have a few changes:

- libstb: bump up the byte timeout for tpm i2c requests

  This bumps up the byte timeout for tpm i2c requests from 10ms to 30ms.
  Some p8dtu systems are getting i2c request timeout.

- external/pflash: Perform the correct cleanup when -F is used to operate on
  a file.

- Add SuperMicro p8dtu1u and p8dtu2u platforms

- Revert "core/ipmi: Set interrupt-parent property".
  This reverts commit d997e482705d9fdff8e25fcbe07fb56008f96ae1 (introduced
  in 5.4.0-rc1)

  A problem was found with pre 4.2 linux kernels where a spurious WARNING
  would be emitted. This change doesn't matter enough to scare users
  so we can just revert it. ::

        Warning was:
        [    0.947741] irq: irq-62==>hwirq-0x3e mapping failed: -22
        [    0.947793] ------------[ cut here ]------------
        [    0.947838] WARNING: at kernel/irq/irqdomain.c:485

- libflash/libffs: Fix possible NULL dereference

Previous Release Candidates
---------------------------

There were four release candidates for skiboot 5.4.0:

- :ref:`skiboot-5.4.0-rc4`
- :ref:`skiboot-5.4.0-rc3`
- :ref:`skiboot-5.4.0-rc2`
- :ref:`skiboot-5.4.0-rc1`

Changes since skiboot 5.3
=========================

Over skiboot-5.3, we have the following changes:

New Features
------------

- Add SuperMicro p8dtu1u and p8dtu2u platforms
- Initial Trusted Boot support (see :ref:`stb-overview`).
  There are several limitations with this initial release:

    - Only Nuvoton TPM 2.0 is supported
    - Requires hardware rework on late revision Habanero or Firestone boards
      in order to install TPM.

  - Add i2c Nuvoton TPM 2.0 Driver
  - romcode driver for POWER8 secure ROM
  - See Device tree docs: :ref:`device-tree/tpm` and :ref:`device-tree/ibm,secureboot`
  - See :ref:`stb-overview`

- Support ``ibm,skiboot`` NVRAM partition with skiboot configuration options.

  - These should generally only be used if you either completely know what
    you are doing or need to work around a skiboot bug. They are **not**
    intended for end users and are *explicitly* **NOT ABI**.
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

- Fast reboot for P8

  This makes reboot take an *awful* lot less time, somewhere between four
  and ten times faster than a full IPL. It is currently experimental and not
  enabled by default.
  You can enable the experimental support via nvram option: ::

   # nvram -p ibm,skiboot --update-config experimental-fast-reset=feeling-lucky

  **WARNING**: While we *think* we've managed to work out or around most of
  the kinks with fast-reset, we are *not* enabling it by default in 5.4.

  Notably, fast reset will *not* happen in the following scenarios:

  - platform error

    Most of the time, if we're rebooting due to a platform error, we should
    trigger a checkstop. However, if we haven't been told what we should do
    to trigger a checkstop (e.g. on an FSP machine), then we should still
    fail to fast-reboot.

    So, fast-reboot is disabled in the OPAL_CEC_REBOOT2 code path
    for the OPAL_REBOOT_PLATFORM_ERROR reboot type.
  - FSP code update
  - Unrecoverable HMI
  - A PHB is in CAPI mode

    If a PHB is in CAPI mode, we cannot safely fast reboot - the PHB will be
    fenced during the reboot resulting in major problems when we load the new
    kernel.

    In order to handle this safely, we need to disable CAPI mode before
    resetting PHBs during the fast reboot. However, we don't currently support
    this.

    In the meantime, when fast rebooting, check if there are any PHBs with a
    CAPP attached, and if so, abort the fast reboot and revert to a normal
    reboot instead.


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

  - pci: Check power state before powering off slot.
    Prevents the erroneous "Error -1 powering off slot" error message.

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
  - external/pflash: Make MTD accesses the default

    Now that BMC and host kernel mtd drivers exist and have matured we
    should use them by default.

    This is especially important since we seem to be telling everyone to use
    pflash (pflash world domination plans are continuing on schedule).
  - external/pflash: Catch incompatible combination of flags
  - external/common: arm: Don't error trying to wrprotect with MTD access
  - libflash/libffs: Use blocklevel_smart_write() when updating partitions

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

Skiboot 5.4 contains only *preliminary* support for POWER9. It's suitable
only for use in simulators. If working on hardware, use more recent skiboot
or development branches. We will not be backporting POWER9 fixes to 5.4.x.

- mambo: Make POWER9 look like DD2
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



Command line arguments to BOOTKERNEL
====================================

- core/init.c: Fix bootargs parsing

  Currently the bootargs are unconditionally deleted, which causes
  a bug where the bootargs passed in by the device tree are lost.

  This patch deletes bootargs only if it needs to be replaced by the NVRAM
  entry.

  This patch also removes KERNEL_COMMAND_LINE config option in favour of
  using the NVRAM or a device tree.


Other changes
=============
- extract-gcov: build with -m64 if compiler supports it.

  Fixes build break on 32bit ppc64 (e.g. PowerMac G5, where user space
  is mostly 32bit).


Flash on OpenPOWER platforms
============================

- flash: rework flash_load_resource to correctly read FFS/STB

  This fixes the previous reverts of loading the CAPP partition with
  STB headers (which broke CAPP partitions without STB headers).

  The new logic fixes both CAPP partition loading with STB headers *and*
  addresses a long standing bug due to differing interpretations of FFS.

  The f_part utility that *constructs* PNOR files just sets actualSize=totalSize
  no matter on what the size of the partition is. Prior to this patch,
  skiboot would always load actualSize, leading to longer than needed IPL.

  The pflash utility updates actualSize, so no developer has really ever
  noticed this, apart from maybe an inkling that it's odd that a freshly
  baked PNOR from op-build takes ever so slightly longer to boot than one
  that has had individual partitions pflashed in.

  With this patch, we now compute actualSize. For partitions with a STB
  header, we take the payload size from the STB header. For partitions
  that don't have a STB header, we compute the size either by parsing
  the ELF header or by looking at the subpartition header and computing it.

  We now need to read the entire partition for partitions with subpartitions
  so that we pass consistent values to be measured as part of Trusted Boot.

  As of this patch, the actualSize field in FFS is *not* relied on for
  partition size, we determine it from the content of the partition.

  However, this patch *will* break loading of partitions that are not ELF
  and do not contain subpartitions. Luckily, nothing in-tree makes use of
  that.

Contributors
============

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
5.4.0    361     16          28      1         9
======== ====== ======= ======= ======  ========

Interesting is the stats of 5.4.0-rc1 versus the final 5.4.0, there's been
a doubling of Acks, an increase in reviewed-by and reported-by. There's
nothing like an impending release to get people to look closer.

Processed 361 csets from 34 developers
A total of 20206 lines added, 5843 removed (delta 14363)

Developers with the most changesets:

========================== === =======
Developer                    # %
========================== === =======
Stewart Smith              105 (29.1%)
Benjamin Herrenschmidt      50 (13.9%)
Claudio Carvalho            47 (13.0%)
Gavin Shan                  24 (6.6%)
Cyril Bur                   20 (5.5%)
Oliver O'Halloran           18 (5.0%)
Michael Neuling             12 (3.3%)
Mukesh Ojha                 12 (3.3%)
Pridhiviraj Paidipeddi       7 (1.9%)
Vasant Hegde                 7 (1.9%)
Russell Currey               7 (1.9%)
Joel Stanley                 4 (1.1%)
Alistair Popple              4 (1.1%)
Mahesh Salgaonkar            4 (1.1%)
Nageswara R Sastry           4 (1.1%)
Chris Smart                  3 (0.8%)
Sam Mendoza-Jonas            3 (0.8%)
Vipin K Parashar             3 (0.8%)
Balbir Singh                 3 (0.8%)
Frederic Barrat              3 (0.8%)
leoluo                       2 (0.6%)
Rafael Fonseca               2 (0.6%)
Jack Miller                  2 (0.6%)
Patrick Williams             2 (0.6%)
Jeremy Kerr                  2 (0.6%)
Suraj Jitindar Singh         2 (0.6%)
Milton Miller                2 (0.6%)
Andrew Donnellan             1 (0.3%)
Shilpasri G Bhat             1 (0.3%)
Frederic Bonnard             1 (0.3%)
Breno Leitao                 1 (0.3%)
Anton Blanchard              1 (0.3%)
Nicholas Piggin              1 (0.3%)
Cédric Le Goater             1 (0.3%)
========================== === =======

Developers with the most changed lines:

========================= ==== =======
Developer                    # %
========================= ==== =======
Claudio Carvalho          6947 (32.9%)
Stewart Smith             6667 (31.6%)
Benjamin Herrenschmidt    2586 (12.3%)
Gavin Shan                1185 (5.6%)
Cyril Bur                  692 (3.3%)
Mukesh Ojha                565 (2.7%)
Oliver O'Halloran          343 (1.6%)
Russell Currey             343 (1.6%)
leoluo                     269 (1.3%)
Pridhiviraj Paidipeddi     236 (1.1%)
Balbir Singh               227 (1.1%)
Michael Neuling            211 (1.0%)
Nageswara R Sastry         132 (0.6%)
Cédric Le Goater           115 (0.5%)
Vipin K Parashar            68 (0.3%)
Alistair Popple             66 (0.3%)
Vasant Hegde                65 (0.3%)
Mahesh Salgaonkar           50 (0.2%)
Shilpasri G Bhat            45 (0.2%)
Suraj Jitindar Singh        41 (0.2%)
Nicholas Piggin             34 (0.2%)
Sam Mendoza-Jonas           33 (0.2%)
Jack Miller                 32 (0.2%)
Chris Smart                 28 (0.1%)
Jeremy Kerr                 23 (0.1%)
Milton Miller               19 (0.1%)
Joel Stanley                13 (0.1%)
Andrew Donnellan            13 (0.1%)
Rafael Fonseca              12 (0.1%)
Patrick Williams            11 (0.1%)
Frederic Barrat              6 (0.0%)
Anton Blanchard              3 (0.0%)
Frederic Bonnard             2 (0.0%)
Breno Leitao                 2 (0.0%)
========================= ==== =======

Developers with the most lines removed:

========================== === ======
Developer                    # %
========================== === ======
Cyril Bur                  206 (3.5%)
Rafael Fonseca               8 (0.1%)
========================== === ======

Developers with the most signoffs (total 278):

========================== === =======
Developer                    # %
========================== === =======
Stewart Smith              268 (96.4%)
Alistair Popple              4 (1.4%)
Jim Yuan                     2 (0.7%)
Cyril Bur                    1 (0.4%)
Michael Neuling              1 (0.4%)
Jeremy Kerr                  1 (0.4%)
Benjamin Herrenschmidt       1 (0.4%)
========================== === =======

Developers with the most reviews (total 28):

========================== === =======
Developer                    # %
========================== === =======
Andrew Donnellan             6 (21.4%)
Vasant Hegde                 5 (17.9%)
Mukesh Ojha                  5 (17.9%)
Joel Stanley                 3 (10.7%)
Russell Currey               3 (10.7%)
Cyril Bur                    2 (7.1%)
Balbir Singh                 2 (7.1%)
Alistair Popple              1 (3.6%)
Vaidyanathan Srinivasan      1 (3.6%)
========================== === =======

Developers with the most test credits (total 1):

========================== === ========
Developer                    # %
========================== === ========
Pridhiviraj Paidipeddi       1 (100.0%)
========================== === ========

Developers who gave the most tested-by credits (total 1):

========================== === ========
Developer                    # %
========================== === ========
Gavin Shan                   1 (100.0%)
========================== === ========


Developers with the most report credits (total 9):

========================== === ========
Developer                    # %
========================== === ========
Pridhiviraj Paidipeddi       3 (33.3%)
Gavin Shan                   1 (11.1%)
Vasant Hegde                 1 (11.1%)
Michael Neuling              1 (11.1%)
Benjamin Herrenschmidt       1 (11.1%)
Andrei Warkenti              1 (11.1%)
Li Meng                      1 (11.1%)
========================== === ========
