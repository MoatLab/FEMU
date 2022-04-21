.. _skiboot-5.6.0-rc1:

skiboot-5.6.0-rc1
=================

skiboot-5.6.0-rc1 was released on Tuesday May 16th 2017. It is the first
release candidate of skiboot 5.6, which will become the new stable release
of skiboot following the 5.5 release, first released April 7th 2017.

skiboot-5.6.0-rc1 contains all bug fixes as of :ref:`skiboot-5.4.4`
and :ref:`skiboot-5.1.19` (the currently maintained stable releases). We
do not currently expect to do any 5.5.x stable releases.

For how the skiboot stable releases work, see :ref:`stable-rules` for details.

The current plan is to cut the final 5.6.0 by May 22nd, with skiboot 5.6.0
being for all POWER8 and POWER9 platforms in op-build v1.17 (Due May 24th).
This is a short cycle as this release is mainly targetted towards POWER9
bringup efforts.

This is the first release using the new regular six week release cycle,
similar to op-build, but slightly offset to allow for a short stabilisation
period. Expected release dates and contents are tracked using GitHub milestone
and issues: https://github.com/open-power/skiboot/milestones

Over skiboot-5.5, we have the following changes:

New Platforms
-------------

Thanks to SuperMicro for submitting support for the p9dsu platform, AKA Boston.

POWER9
------

XIVE:

  - xive: Clear emulation mode queue on reset
  - xive: Fixes/improvements to xive reset for multi-chip systems
  - xive: Synchronize after disable IRQs in opal_xive_reset()
  - xive: Workaround a problem with indirect TM access
  - hdata: Make FSPv1 work again
    One less thing to work around for those crazy enough to try.
  - xive: Log more information in opal_xive_dump() for emulation state

    Add a counter of total interrupts taken by a CPU, dump the
    queue buffer both before and after the current pointer,
    and also display the HW state of the queue descriptor and
    the PQ state of the IPI.
  - xive: Add a per-cpu logging mechanism to XICS emulation

    This is a small 32-entries rolling buffer that logs a few
    operations. It's useful to debug odd problems. The output
    is printed when opal_xive_dump() is called.
  - xive: Check queues for duplicates in DEBUG builds.

    There should never be duplicate interrupts in a queue.
    This adds code to check that when looking at the queue
    content. Since it can be a performance loss, this is only
    done for debug builds.
  - xive+phb4: Fix exposing trigger page to Linux

HDAT Parsing:

  - hdata/spira.c: Add device-tree bindings for nest mmu
  - hdata/i2c: Workaround broken i2c devices
  - hdata: indicate when booted with elevated risk level

    When the system is IPLed with an elevated risk level Hostboot will
    set a flag in the IPL parameters structure. Parse and export this
    in the device tree at: /ipl-params/sys-params/elevated-risk-level
  - hdata: Respect OCC and HOMER resevations

    In the past we've ignored these since Hostboot insisted in exporting
    broken reservations and the OCC was not being used yet. This situation
    seems to have resolved itself so we should respect the reservations that
    hostboot provides.

I2C:

- i2c: Add interrupts support on P9

  Some older revisions of hostboot populate the host i2c device fields
  with all zero entires. Detect and ignore these so we don't crash on
  boot.

  Without this we get: ::

    [  151.251240444,3] DT: dt_attach_root failed, duplicate unknown@0
    [  151.251300274,3] ***********************************************
    [  151.251339330,3] Unexpected exception 200 !
    [  151.251363654,3] SRR0 : 0000000030090c28 SRR1 : 9000000000201000
    [  151.251409207,3] HSRR0: 0000000000000010 HSRR1: 9000000000001000
    [  151.251444114,3] LR   : 30034018300c5ab0 CTR  : 30034018300a343c
    [  151.251478314,3] CFAR : 0000000030024804
    [  151.251500346,3] CR   : 40004208  XER: 00000000
        <snip GPRS>
    [  151.252083372,0] Aborting!
    CPU 0034 Backtrace:
     S: 0000000031cd36a0 R: 000000003001364c   .backtrace+0x2c
     S: 0000000031cd3730 R: 0000000030018db8   ._abort+0x4c
     S: 0000000031cd37b0 R: 0000000030025c6c   .exception_entry+0x114
     S: 0000000031cd3840 R: 0000000000001f00 * +0x1f00
     S: 0000000031cd3a10 R: 0000000031cd3ab0 *
     S: 0000000031cd3aa0 R: 00000000300248b8   .new_property+0x90
     S: 0000000031cd3b30 R: 0000000030024b50   .__dt_add_property_cells+0x30
     S: 0000000031cd3bd0 R: 000000003009abec   .parse_i2c_devs+0x350
     S: 0000000031cd3cf0 R: 0000000030093ffc   .parse_hdat+0x11e4
     S: 0000000031cd3e30 R: 00000000300144c8   .main_cpu_entry+0x138
     S: 0000000031cd3f00 R: 0000000030002648   boot_entry+0x198

PHB4:

  - phb4: Enforce root complex config space size of 2048

    The root complex config space size on PHB4 is 2048. This patch sets
    that size and enforces it when trying to read/write the config space
    in the root complex.

    Without this someone reading the config space via /sysfs in linux will
    cause an EEH on the PHB.

    If too high, reads returns 1s and writes are silently dropped.
  - phb4: Add an option for disabling EEH MMIO in nvram

    Having the option to disable EEH for MMIO without rebuilding skiboot
    could be useful for testing, so check for pci-eeh-mmio=disabled in nvram.

    This is not designed to be a supported option or configuration, just
    an option that's useful in bringup and development of POWER9 systems.
  - phb4: Fix slot presence detect

    This has the nice side effect of improving boot times since we no
    longer waste time tring to train links that don't have anything
    present.
  - phb4: Enable EEH for MMIO
  - phb4: Implement fence check
  - phb4: Implement diag data

OCC:

  - occ/irq: Fix SCOM address and irq reasons for P9 OCC

    This patch fixes the SCOM address for OCC_MISC register which is used
    for OCC interupts. In P9, OCC sends an interrupt to notify change in
    the shared memory like throttle status. This patch handles this
    interrupt reason.

PRD:

  - prd: Fix PRD scoms for P9

NX/DARN:

  - nx: Add POWER9 DARN support

NPU2:

  - npu2: Do not attempt to initialise non DD1 hardware

    There are significant changes to hardware register addresses and
    meanings on newer chip revisions making them unlikely to work
    correctly with the existing code. Better to fail clearly and early.

  - npu, npu2: Describe diag data size in device tree

Memory Reservation:

  - mem_region: Add reserved regions after memory init

    When a new memory region is added (e.g for memory reserved by firmware)
    the list of existing memory regions is iterated through and a cut-out is
    made in any existing region that overlaps with the new one. Prior to the
    HDAT reservations being made the region init process was always:

      1) Create regions from the memory@<addr> DT nodes. (mostly large)
      2) Create reserved regions from the device-tree. (mostly small)

    When adding new regions we have assumed that the new region will only
    every intersect with at most one existing region, which it will split.
    Adding reservations inside the HDAT parser breaks this because when
    adding the memory@<addr> node regions we can potentially overlap with
    multiple reserved regions. This patch fixes this by maintaining a
    seperate list of memory reservations and delaying merging them until
    after the normal memory init has finished, similar to how DT
    reservations are handled.

PCI
---

- pci: Describe PHB diag data size in device tree

  Linux hardcodes the PHB diag data buffer at (as of this commit) 8192 bytes.
  This has been enough for P7IOC and PHB3, but the 512 PEs of PHB4 pushes
  the diag data blob over this size.  Rather than just increasing the
  hardcoded size in Linux, provide the size of the diag data blob in the
  device tree so that the OS can dynamically allocate as much as it needs.
  This both enables more space for PHB4 and less wasted memory for P7IOC
  and PHB3.

  P7IOC communicates both hub and PHB data using this buffer, so when
  setting the size, use whichever struct is largest.
- hdata/i2c: Fix bus and clock frequencies
- ibm-fsp: use opal-prd on p9 and above

  Previously the PRD tooling ran on the FSP, but it was moved into
  userspace on the host for OpenPower systems. For P9 this system
  was adopted for FSP systems too.


I2C
---
- i2c: Remove old hack for bad clock frequency

  This hack dates back to ancient P8 hostboots. The value
  it would use if it detected the "bad" value was incorrect
  anyway.

- i2c: Log the engine clock frequency at boot

FSP Systems
-----------

These include the Apollo, Firenze and ZZ platforms.

- Remove multiple logging for un-handled fsp sub commands.

  If any new or unknown command need to be handled, just log
  un-hnadled message from only fsp, not required from fsp-dpo. ::

    cat /sys/firmware/opal/msglog | grep -i ,3
    [  110.232114723,3] FSP: fsp_trigger_reset() entry
    [  188.431793837,3] FSP #0: Link down, starting R&R
    [  464.109239162,3] FSP #0: Got XUP with no pending message !
    [  466.340598554,3] FSP-DPO: Unknown command 0xce0900
    [  466.340600126,3] FSP: Unhandled message ce0900

- FSP: Notify FSP of Platform Log ID after Host Initiated Reset Reload

  Trigging a Host Initiated Reset (when the host detects the FSP has gone
  out to lunch and should be rebooted), would cause "Unknown Command" messages
  to appear in the OPAL log.

  This patch implements those messages

  How to trigger FSP RR(HIR): ::

    $ putmemproc 300000f8 0x00000000deadbeef
    s1      k0:n0:s0:p00
    ecmd_ppc putmemproc 300000f8 0x00000000deadbeef

    Log showing unknown command:
    / # cat /sys/firmware/opal/msglog | grep -i ,3
    [  110.232114723,3] FSP: fsp_trigger_reset() entry
    [  188.431793837,3] FSP #0: Link down, starting R&R
    [  464.109239162,3] FSP #0: Got XUP with no pending message !
    [  466.340598554,3] FSP-DPO: Unknown command 0xce0900
    [  466.340600126,3] FSP: Unhandled message ce0900

  The message we need to handle is "Get PLID after host initiated FipS
  reset/reload". When the FSP comes back from HIR, it asks "hey, so, which
  error log explains why you rebooted me?". So, we tell it.

Misc
----

- hdata_to_dt: Misc improvements in the utility and unit test
- GCC7: fixes for -Wimplicit-fallthrough expected regexes

  It turns out GCC7 adds a useful warning and does fancy things like
  parsing your comments to work out that you intended to do the fallthrough.
  There's a few places where we don't match the regex. Fix them, as it's
  harmless to do so.

  Found by building on Fedora Rawhide in Travis.

  While we do not have everything needed to start building successfully
  with GCC7 (well, at least doing so warning clean), it's a start.
- hdata/i2c: avoid possible int32_t overflow

  We're safe up until engine number 524288. Found by static analysis (of course)
- tpm_i2c_nuvoton: fix use-after-free in tpm_register_chip failure path
- mambo: Fix reserved-ranges node
- external/mambo: add helper for machine checks
- console: Set log level from nvram

  This adds two new nvram options to set the console log level for the
  driver/uart and in memory.  These are called log-level-memory and
  log-level-driver.

  These are only set once we have nvram inited.

  To set them you do: ::

    nvram -p ibm,skiboot --update-config log-level-memory=9
    nvram -p ibm,skiboot --update-config log-level-driver=9

  You can also use the named versions of emerg, alert, crit, err,
  warning, notice, printf, info, debug, trace or insane.  ie. ::

    nvram -p ibm,skiboot --update-config log-level-driver=insane

- npu: Implement Function Level Reset (FLR)
- mbox: Sanitize interrupts registers
- xive: Fix potential for lost IPIs when manipulating CPPR
- xive: Don't double EOI interrupts that have an EOI override
- libflash/file: Only use 64bit MTD erase ioctl() when needed

  We recently made MTD 64 bit safe in e5720d3fe94 which now requires the
  64 bit MTD erase ioctl. Unfortunately this ioctl is not present in
  older kernels used by some BMC vendors that use pflash.

  This patch addresses this by only using the 64bit version of the erase
  ioctl() if the parameters exceed 32bit in size.

  If an erase requires the 64bit ioctl() on a kernel which does not
  support it, the code will still attempt it. There is no way of knowing
  beforehand if the kernel supports it. The ioctl() will fail and an error
  will be returned from from the function.

Contributors
------------

This release contains 81 csets from 15 developers, working at 2 employers.
A total of 2496 lines added, 641 removed (delta 1855)

Developers with the most changesets
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

=========================== == =======
Developer                    # %
=========================== == =======
Oliver O'Halloran           17 (21.0%)
Benjamin Herrenschmidt      17 (21.0%)
Michael Neuling             16 (19.8%)
Stewart Smith                9 (11.1%)
Russell Currey               8 (9.9%)
Alistair Popple              5 (6.2%)
ppaidipe@linux.vnet.ibm.com  1 (1.2%)
Dave Heller                  1 (1.2%)
Jeff Scheel                  1 (1.2%)
Nicholas Piggin              1 (1.2%)
Ananth N Mavinakayanahalli   1 (1.2%)
Cyril Bur                    1 (1.2%)
Alexey Kardashevskiy         1 (1.2%)
Jim Yuan                     1 (1.2%)
Shilpasri G Bhat             1 (1.2%)
=========================== == =======

Developers with the most changed lines
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

=========================== === =======
Developer                     # %
=========================== === =======
Michael Neuling             748 (28.4%)
Benjamin Herrenschmidt      405 (15.4%)
Russell Currey              360 (13.7%)
Oliver O'Halloran           297 (11.3%)
Nicholas Piggin             187 (7.1%)
Alistair Popple             183 (7.0%)
Stewart Smith               175 (6.6%)
Shilpasri G Bhat             79 (3.0%)
Jim Yuan                     56 (2.1%)
Ananth N Mavinakayanahalli   45 (1.7%)
Cyril Bur                    38 (1.4%)
Alexey Kardashevskiy         37 (1.4%)
Jeff Scheel                  19 (0.7%)
Dave Heller                   2 (0.1%)
Pridhiviraj Paidipeddi        1 (0.0%)
=========================== === =======

Developers with the most lines removed
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

===========================  === =======
Developer                      # %
===========================  === =======
Pridhiviraj Paidipeddi         1 (0.2%)
===========================  === =======

Developers with the most signoffs
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Total of 73.

=========================  === =======
Developer                    # %
=========================  === =======
Stewart Smith               56 (76.7%)
Michael Neuling             16 (21.9%)
Oliver O'Halloran            1 (1.4%)
=========================  === =======

Developers with the most reviews
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Total of 6.

=========================  === =======
Developer                    # %
=========================  === =======
Oliver O'Halloran            3 (50.0%)
Andrew Donnellan             1 (16.7%)
Gavin Shan                   1 (16.7%)
Cyril Bur                    1 (16.7%)
=========================  === =======

Developers with the most test credits
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Total of 5.

=========================  === =======
Developer                    # %
=========================  === =======
Oliver O'Halloran            2 (40.0%)
Vaidyanathan Srinivasan      1 (20.0%)
Vasant Hegde                 1 (20.0%)
Michael Ellerman             1 (20.0%)
=========================  === =======

Developers who gave the most tested-by credits
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Total of 5.

=========================  === =======
Developer                    # %
=========================  === =======
Oliver O'Halloran            2 (40.0%)
Benjamin Herrenschmidt       2 (40.0%)
Nicholas Piggin              1 (20.0%)
=========================  === =======

Developers with the most report credits
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Total of 2.

===========================  === =======
Developer                      # %
===========================  === =======
Benjamin Herrenschmidt         1 (50.0%)
Pridhiviraj Paidipeddi         1 (50.0%)
===========================  === =======

Developers who gave the most report credits
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Total of 2.

=========================  === =======
Developer                    # %
=========================  === =======
Stewart Smith                2 (100.0%)
=========================  === =======

Top changeset contributors by employer
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Total of 2.

=========================  === =======
Employer                     # %
=========================  === =======
IBM                         80 (98.8%)
SuperMicro                   1 (1.2%)
=========================  === =======

Top lines changed by employer
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

========================= ==== =======
Employer                     # %
========================= ==== =======
IBM                       2576 (97.9%)
SuperMicro                  56 (2.1%)
========================= ==== =======

Employers with the most signoffs
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Total 73.

=========================  === =======
Employer                     # %
=========================  === =======
IBM                         73 (100.0%)
=========================  === =======

Employers with the most hackers
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Total 15.

=========================  === =======
Employer                     # %
=========================  === =======
IBM                         14 (93.3%)
SuperMicro                   1 (6.7%)
=========================  === =======
