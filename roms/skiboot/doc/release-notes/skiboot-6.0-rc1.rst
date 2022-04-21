.. _skiboot-6.0-rc1:

skiboot-6.0-rc1
================

skiboot v6.0-rc1 was released on Tuesday May 1st 2018. It is the first
release candidate of skiboot 6.0, which will become the new stable release
of skiboot following the 5.11 release, first released April 6th 2018.

Skiboot 6.0 will mark the basis for op-build v2.0 and will be required for
POWER9 systems.

skiboot v6.0-rc1 contains all bug fixes as of :ref:`skiboot-5.11`,
:ref:`skiboot-5.10.5`, and :ref:`skiboot-5.4.9` (the currently maintained
stable releases). Once 6.0 is released, we do *not* expect any further
stable releases in the 5.10.x series, nor in the 5.11.x series.

For how the skiboot stable releases work, see :ref:`stable-rules` for details.

The current plan is to cut the final 6.0 in early May, with skiboot 6.0
being for all POWER8 and POWER9 platforms in op-build v2.0.

Over skiboot-5.11, we have the following changes:

New Features
------------
- Disable stop states from OPAL

  On ZZ, stop4,5,11 are enabled for PowerVM, even though doing
  so may cause problems with OPAL due to bugs in hcode.

  For other platforms, this isn't so much of an issue as
  we can just control stop states by the MRW. However the
  rebuild-the-world approach to changing values there is a bit
  annoying if you just want to rule out a specific stop state
  from being problematic.

  Provide an nvram option to override what's disabled in OPAL.

  The OPAL mask is currently ~0xE0000000 (i.e. all but stop 0,1,2)

  You can set an NVRAM override with: ::

      nvram -p ibm,skiboot --update-config opal-stop-state-disable-mask=0xFFFFFFF

  This nvram override will disable *all* stop states.
- interrupts: Create an "interrupts" property in the OPAL node

  Deprecate the old "opal-interrupts", it's still there, but the new
  property follows the standard and allow us to specify whether an
  interrupt is level or edge sensitive.

  Similarly create "interrupt-names" whose content is identical to
  "opal-interrupts-names".
- SBE: Add timer support on POWER9

  SBE on P9 provides one shot programmable timer facility. We can use this
  to implement OPAL timers and hence limit the reliance on the Linux
  heartbeat (similar to HW timer facility provided by SLW on P8).
- Add SBE driver support

  SBE (Self Boot Engine) on P9 has two different jobs:
  - Boot the chip up to the point the core is functional
  - Provide various services like timer, scom, stash MPIPL, etc., at runtime

  We will use SBE for various purposes like timer, MPIPL, etc.

- opal:hmi: Add missing processor recovery reason string.

  With this patch now we see reason string printed for CORE_WOF[43] bit. ::

    [  477.352234986,7] HMI: [Loc: U78D3.001.WZS004A-P1-C48]: P:8 C:22 T:3: Processor recovery occurred.
    [  477.352240742,7] HMI: Core WOF = 0x0000000000100000 recovered error:
    [  477.352242181,7] HMI: PC - Thread hang recovery
- Add DIMM actual speed to device tree

  Recent HDAT provides DIMM actuall speed. Lets add this to device tree.
- Fix DIMM size property

  Today we parse vpd blob to get DIMM size information. This is limited
  to FSP based system. HDAT provides DIMM size value. Lets use that to
  populate device tree. So that we can get size information on BMC based
  system as well.

- PCI: Set slot power limit when supported

  The PCIe slot capability can be implemented in a root or switch
  downstream port to set the maximum power a card is allowed to draw
  from the system. This patch adds support for setting the power limit
  when the platform has defined one.
- hdata/spira: parse vpd to add part-number and serial-number to xscom@ node

  Expected by FWTS and associates our processor with the part/serial
  number, which is obviously a good thing for one's own sanity.


Improved HMI Handling
^^^^^^^^^^^^^^^^^^^^^

- opal/hmi: Add documentation for opal_handle_hmi2 call
- opal/hmi: Generate hmi event for recovered HDEC parity error.
- opal/hmi: check thread 0 tfmr to validate latched tfmr errors.

  Due to P9 errata, HDEC parity and TB residue errors are latched for
  non-zero threads 1-3 even if they are cleared. But these are not
  latched on thread 0. Hence, use xscom SCOMC/SCOMD to read thread 0 tfmr
  value and ignore them on non-zero threads if they are not present on
  thread 0.
- opal/hmi: Print additional debug information in rendezvous.
- opal/hmi: Fix handling of TFMR parity/corrupt error.

  While testing TFMR parity/corrupt error it has been observed that HMIs are
  delivered twice for this error

    - First time HMI is delivered with HMER[4,5]=1 and TFMR[60]=1.
    - Second time HMI is delivered with HMER[4,5]=1 and TFMR[60]=0 with valid TB.

  On second HMI we end up throwing "HMI: TB invalid without core error
  reported" even though TB is in a valid state.
- opal/hmi: Stop flooding HMI event for TOD errors.

  Fix the issue where every thread on the chip sends HMI event to host for
  TOD errors. TOD errors are reported to all the core/threads on the chip.
  Any one thread can fix the error and send event. Rest of the threads don't
  need to send HMI event unnecessarily.
- opal/hmi: Fix soft lockups during TOD errors

  There are some TOD errors which do not affect working of TOD and TB. They
  stay in valid state. Hence we don't need rendez vous for TOD errors that
  does not affect TB working.

  TOD errors that affects TOD/TB will report a global error on TFMR[44]
  alongwith bit 51, and they will go in rendez vous path as expected.

  But the TOD errors that does not affect TB register sets only TFMR bit 51.
  The TFMR bit 51 is cleared when any single thread clears the TOD error.
  Once cleared, the bit 51 is reflected to all the cores on that chip. Any
  thread that reads the TFMR register after the error is cleared will see
  TFMR bit 51 reset. Hence the threads that see TFMR[51]=1, falls through
  rendez-vous path and threads that see TFMR[51]=0, returns doing
  nothing. This ends up in a soft lockups in host kernel.

  This patch fixes this issue by not considering TOD interrupt (TFMR[51])
  as a core-global error and hence avoiding rendez-vous path completely.
  Instead threads that see TFMR[51]=1 will now take different path that
  just do the TOD error recovery.
- opal/hmi: Do not send HMI event if no errors are found.

  For TOD errors, all the cores in the chip get HMIs. Any one thread from any
  core can fix the issue and TFMR will have error conditions cleared. Rest of
  the threads need take any action if TOD errors are already cleared. Hence
  thread 0 of every core should get a fresh copy of TFMR before going ahead
  recovery path. Initialize recover = -1, so that if no errors found that
  thread need not send a HMI event to linux. This helps in stop flooding host
  with hmi event by every thread even there are no errors found.
- opal/hmi: Initialize the hmi event with old value of HMER.

  Do this before we check for TFAC errors. Otherwise the event at host console
  shows no error reported in HMER register.

  Without this patch the console event show HMER with all zeros ::

    [  216.753417] Severe Hypervisor Maintenance interrupt [Recovered]
    [  216.753498]  Error detail: Timer facility experienced an error
    [  216.753509]  HMER: 0000000000000000
    [  216.753518]  TFMR: 3c12000870e04000

  After this patch it shows old HMER values on host console: ::

    [ 2237.652533] Severe Hypervisor Maintenance interrupt [Recovered]
    [ 2237.652651]  Error detail: Timer facility experienced an error
    [ 2237.652766]  HMER: 0840000000000000
    [ 2237.652837]  TFMR: 3c12000870e04000
- opal/hmi: Rework HMI handling of TFAC errors

  This patch reworks the HMI handling for TFAC errors by introducing
  4 rendez-vous points improve the thread synchronization while handling
  timebase errors that requires all thread to clear dirty data from TB/HDEC
  register before clearing the errors.
- opal/hmi: Don't bother passing HMER to pre-recovery cleanup

  The test for TFAC error is now redundant so we remove it and
  remove the HMER argument.
- opal/hmi: Move timer related error handling to a separate function

  Currently no functional change. This is a first step to completely
  rewriting how these things are handled.
- opal/hmi: Add a new opal_handle_hmi2 that returns direct info to Linux

  It returns a 64-bit flags mask currently set to provide info
  about which timer facilities were lost, and whether an event
  was generated.
- opal/hmi: Remove races in clearing HMER

  Writing to HMER acts as an "AND". The current code writes back the
  value we originally read with the bits we handled cleared. This is
  racy, if a new bit gets set in HW after the original read, we'll end
  up clearing it without handling it.

  Instead, use an all 1's mask with only the bit handled cleared.
- opal/hmi: Don't re-read HMER multiple times

  We want to make sure all reporting and actions are based
  upon the same snapshot of HMER in case bits get added
  by HW while we are in OPAL.

libflash and ffspart
^^^^^^^^^^^^^^^^^^^^

Many improvements to the `ffspart` utility and `libflash` have come
in this release, making `ffspart` suitable for building bit-identical
PNOR images as the existing tooling used by `op-build`. The plan is to
switch `op-build` to use this infrastructure in the not too distant
future.

- libflash/blocklevel: Make read/write be ECC agnostic for callers

  The blocklevel abstraction allows for regions of the backing store to be
  marked as ECC protected so that blocklevel can decode/encode the ECC
  bytes into the buffer automatically without the caller having to be ECC
  aware.

  Unfortunately this abstraction is far from perfect, this is only useful
  if reads and writes are performed at the start of the ECC region or in
  some circumstances at an ECC aligned position - which requires the
  caller be aware of the ECC regions.

  The problem that has arisen is that the blocklevel abstraction is
  initialised somewhere but when it is later called the caller is unaware
  if ECC exists in the region it wants to arbitrarily read and write to.
  This should not have been a problem since blocklevel knows. Currently
  misaligned reads will fail ECC checks and misaligned writes will
  overwrite ECC bytes and the backing store will become corrupted.

  This patch add the smarts to blocklevel_read() and blocklevel_write() to
  cope with the problem. Note that ECC can always be bypassed by calling
  blocklevel_raw_() functions.

  All this work means that the gard tool can can safely call
  blocklevel_read() and blocklevel_write() and as long as the blocklevel
  knows of the presence of ECC then it will deal with all cases.

  This also commit removes code in the gard tool which compensated for
  inadequacies no longer present in blocklevel.
- libflash/blocklevel: Return region start from ecc_protected()

  Currently all ecc_protected() does is say if a region is ECC protected
  or not. Knowing a region is ECC protected is one thing but there isn't
  much that can be done afterwards if this is the only known fact. A lot
  more can be done if the caller is told where the ECC region begins.

  Knowing where the ECC region start it allows to caller to align its
  read/and writes. This allows for more flexibility calling read and write
  without knowing exactly how the backing store is organised.
- libflash/ecc: Add helpers to align a position within an ecc buffer

  As part of ongoing work to make ECC invisible to higher levels up the
  stack this function converts a 'position' which should be ECC agnostic
  to the equivalent position within an ECC region starting at a specified
  location.
- libflash/ecc: Add functions to deal with unaligned ECC memcpy
- external/ffspart: Improve error output
- libffs: Fix bad checks for partition overlap

  Not all TOCs are written at zero
- libflash/libffs: Allow caller to specifiy header partition

  An FFS TOC is comprised of two parts. A small header which has a magic
  and very minimmal information about the TOC which will be common to all
  partitions, things like number of patritions, block sizes and the like.
  Following this small header are a series of entries. Importantly there
  is always an entry which encompases the TOC its self, this is usually
  called the 'part' partition.

  Currently libffs always assumes that the 'part' partition is at zero.
  While there is always a TOC and zero there doesn't actually have to be.
  PNORs may have multiple TOCs within them, therefore libffs needs to be
  flexible enough to allow callers to specify TOCs not at zero.

  The 'part' partition is otherwise a regular partition which may have
  flags associated with it. libffs should allow the user to set the flags
  for the 'part' partition.

  This patch achieves both by allowing the caller to specify the 'part'
  partition. The caller can not and libffs will provide a sensible
  default.
- libflash/libffs: Refcount ffs entries

  Currently consumers can add an new ffs entry to multiple headers, this
  is fine but freeing any of the headers will cause the entry to be freed,
  this causes double free problems.

  Even if only one header is uses, the consumer of the library still has a
  reference to the entry, which they may well reuse at some other point.

  libffs will now refcount entries and only free when there are no more
  references.

  This patch also removes the pointless return value of ffs_hdr_free()
- libflash/libffs: Switch to storing header entries in an array

  Since the libffs no longer needs to sort the entries as they get added
  it makes little sense to have the complexity of a linked list when an
  array will suffice.
- libflash/libffs: Remove backup partition from TOC generation code

  It turns out this code was messy and not all that reliable. Doing it at
  the library level adds complexity to the library and restrictions to the
  caller.

  A simpler approach can be achived with the just instantiating multiple
  ffs_header structures pointing to different parts of the same file.
- libflash/libffs: Remove the 'sides' from the FFS TOC generation code

  It turns out this code was messy and not all that reliable. Doing it at
  the library level adds complexity to the library and restrictions to the
  caller.

  A simpler approach can be achived with the just instantiating multiple
  ffs_header structures pointing to different parts of the same file.
- libflash/libffs: Always add entries to the end of the TOC

  It turns out that sorted order isn't the best idea. This removes
  flexibility from the caller. If the user wants their partitions in
  sorted order, they should insert them in sorted order.
- external/ffspart: Remove side, order and backup options

  These options are currently flakey in libflash/libffs so there isn't
  much point to being able to use them in ffspart.

  Future reworks planned for libflash/libffs will render these options
  redundant anyway.
- libflash/libffs: ffs_close() should use ffs_hdr_free()
- libflash/libffs: Add setter for a partitions actual size
- pflash: Use ffs_entry_user_to_string() to standardise flag strings
- libffs: Standardise ffs partition flags

  It seems we've developed a character respresentation for ffs partition
  flags. Currently only pflash really prints them so it hasn't been a
  problem but now ffspart wants to read them in from user input.

  It is important that what libffs reads and what pflash prints remain
  consistent, we should move the code into libffs to avoid problems.
- external/ffspart: Allow # comments in input file\

p9dsu Platform changes
----------------------

The p9dsu platform from SuperMicro (also known as 'Boston') has received
a number of updates, and the patches once carried by SuperMicro are now
upstream.

- p9dsu: detect p9dsu variant even when hostboot doesn't tell us

  The SuperMicro BMC can tell us what riser type we have, which dictates
  the PCI slot tables. Usually, in an environment that a customer would
  experience, Hostboot will do the query with an SMC specific patch
  (not upstream as there's no platform specific code in hostboot)
  and skiboot knows what variant it is based on the compatible string.

  However, if you're using upstream hostboot, you only get the bare
  'p9dsu' compatible type. We can work around this by asking the BMC
  ourselves and setting the slot table appropriately. We do this
  syncronously in platform init so that we don't start probing
  PCI before we setup the slot table.
- p9dsu: add slot power limit.
- p9dsu: add pci slot table for Boston LC 1U/2U and Boston LA/ESS.
- p9dsu HACK: fix system-vpd eeprom
- p9dsu: change esel command from AMI to IBM 0x3a.

ZZ Platform Changes
-------------------

- hdata/i2c: Fix up pci hotplug labels

  These labels are used on the devices used to do PCIe slot power control
  for implementing PCIe hotplug. I'm not sure how they ended up as
  "eeprom-pgood" and "eeprom-controller" since that doesn't make any sense.
- hdata/i2c: Ignore multi-port I2C devices

  Recent FSP firmware builds add support for multi-port I2C devices such
  as the GPIO expanders used for the presence detect of OpenCAPI devices
  and the PCIe hotplug controllers used to power cycle PCIe slots on ZZ.

  The OpenCAPI driver inside of skiboot currently uses a platform-specific
  method to talk to the relevant I2C device rather than relying on HDAT
  since not all platforms correctly report the I2C devices (hello Zaius).
  Additionally the nature of multi-port devices require that we a device
  specific handler so that we generate the correct DT bindings. Currently
  we don't and there is no immediate need for this support so just ignore
  the multi-port devices for now.
- hdata/i2c: Replace `i2c_` prefix with `dev_`

  The current naming scheme makes it easy to conflate "i2cm_port" and
  "i2c_port." The latter is used to describe multi-port I2C devices such
  as GPIO expanders and multi-channel PCIe hotplug controllers. Rename
  i2c_port to dev_port to make the two a bit more distinct.

  Also rename i2c_addr to dev_addr for consistency.
- hdata/i2c: Ignore CFAM I2C master

  Recent FSP firmware builds put in information about the CFAM I2C master
  in addition the to host I2C masters accessible via XSCOM. Odds are this
  information should not be there since there's no handshaking between the
  FSP/BMC and the host over who controls that I2C master, but it is so
  we need to deal with it.

  This patch adds filtering to the HDAT parser so it ignores the CFAM I2C
  master. Without this it will create a bogus i2cm@<addr> which migh cause
  issues.
- ZZ: hw/imc: Add support to load imc catalog lid file

  Add support to load the imc catalog from a lid file packaged
  as part of the system firmware. Lid number allocated
  is 0x80f00103.lid.


Bugs Fixed
----------
- core: Fix iteration condition to skip garded cpu
- uart: fix uart_opal_flush to take console lock over uart_con_flush
  This bug meant that OPAL_CONSOLE_FLUSH didn't take the appropriate locks.
  Luckily, since this call is only currently used in the crash path.
- xive: fix missing unlock in error path
- OPAL_PCI_SET_POWER_STATE: fix locking in error paths

  Otherwise we could exit OPAL holding locks, potentially leading
  to all sorts of problems later on.
- hw/slw: Don't assert on a unknown chip

  For some reason skiboot populates nodes in /cpus/ for the cores on
  chips that are deconfigured. As a result Linux includes the threads
  of those cores in it's set of possible CPUs in the system and attempts
  to set the SPR values that should be used when waking a thread from
  a deep sleep state.

  However, in the case where we have deconfigured chip we don't create
  a xscom node for that chip and as a result we don't have a proc_chip
  structure for that chip either. In turn, this results in an assertion
  failure when calling opal_slw_set_reg() since it expects the chip
  structure to exist. Fix this up and print an error instead.
- opal/hmi: Generate one event per core for processor recovery.

  Processor recovery is per core error. All threads on that core receive
  HMI. All threads don't need to generate HMI event for same error.

  Let thread 0 only generate the event.
- sensors: Dont add DTS sensors when OCC inband sensors are available

  There are two sets of core temperature sensors today. One is DTS scom
  based core temperature sensors and the second group is the sensors
  provided by OCC. DTS is the highest temperature among the different
  temperature zones in the core while OCC core temperature sensors are
  the average temperature of the core. DTS sensors are read directly by
  the host by SCOMing the DTS sensors while OCC sensors are read and
  updated by OCC to main memory.

  Reading DTS sensors by SCOMing is a heavy and slower operation as
  compared to reading OCC sensors which is as good as reading memory.
  So dont add DTS sensors when OCC sensors are available.
- core/fast-reboot: Increase timeout for dctl sreset to 1sec

  Direct control xscom can take more time to complete. We seem to
  wait too little on Boston failing fast-reboot for no good reason.

  Increase timeout to 1 sec as a reasonable value for sreset to be delivered
  and core to start executing instructions.
- occ: sensors-groups: Add DT properties to mark HWMON sensor groups

  Fix the sensor type to match HWMON sensor types. Add compatible flag
  to indicate the environmental sensor groups so that operations on
  these groups can be handled by HWMON linux interface.
- core: Correctly load initramfs in stb container

  Skiboot does not calculate the actual size and start location of the
  initramfs if it is wrapped by an STB container (for example if loading
  an initramfs from the ROOTFS partition).

  Check if the initramfs is in an STB container and determine the size and
  location correctly in the same manner as the kernel. Since
  load_initramfs() is called after load_kernel() move the call to
  trustedboot_exit_boot_services() into load_and_boot_kernel() so it is
  called after both of these.
- hdat/i2c.c: quieten "v2 found, parsing as v1"
- hw/imc: Check for pause_microcode_at_boot() return status

  pause_microcode_at_boot() loops through all the chip's ucode
  control block and pause the ucode if it is in the running state.
  But it does not fail if any of the chip's ucode is not initialised.

  Add code to return a failure if ucode is not initialized in any
  of the chip. Since pause_microcode_at_boot() is called just before
  attaching the IMC device nodes in imc_init(), add code to check for
  the function return.


Slot location code fixes:

- npu2: Use ibm, loc-code rather than ibm, slot-label

  The ibm,slot-label property is to name the slot that appears under a
  PCIe bridge. In the past we (ab)used the slot tables to attach names
  to GPU devices and their corresponding NVLinks which resulted in npu2.c
  using slot-label as a location code rather than as a way to name slots.

  Fix this up since it's confusing.
- hdata/slots: Apply slot label to the parent slot

  Slot names only really make sense when applied to an actual slot rather
  than a device. On witherspoon the GPU devices have a name associated with
  the device rather than the slot for the GPUs. Add a hack that moves the
  slot label to the parent slot rather than on the device itself.
- pci-dt-slot: Big ol' cleanup

  The underlying data that we get from HDAT can only really describe a
  PCIe system. As such we can simplify the devicetree slot lookup code
  by only caring about the important cases, namly, root ports and switch
  downstream ports.

  This also fixes a bug where root port didn't get a Slot label applied
  which results in devices under that port not having ibm,loc-code set.
  This results in the EEH core being unable to report the location of
  EEHed devices under that port.

opal-prd
^^^^^^^^
- opal-prd: Insert powernv_flash module

  Explictly load powernv_flash module on BMC based system so that we are sure
  that flash device is created before starting opal-prd daemon.

  Note that I have replaced pnor_available() check with is_fsp_system(). As we
  want to load module on BMC system only. Also pnor_init has enough logic to
  detect flash device. Hence pnor_available() becomes redundant check.

NPU2/NVLINK2
^^^^^^^^^^^^
- npu2/hw-procedures: fence bricks on GPU reset

  The NPU workbook defines a way of fencing a brick and
  getting the brick out of fence state. We do have an implementation
  of bringing the brick out of fenced/quiesced state. We do
  the latter in our procedures, but to support run time reset
  we need to do the former.

  The fencing ensures that access to memory behind the links
  will not lead to HMI's, but instead SUE's will be populated
  in cache (in the case of speculation). The expectation is then
  that prior to and after reset, the operating system components
  will flush the cache for the region of memory behind the GPU.

  This patch does the following:

  1. Implements a npu2_dev_fence_brick() function to set/clear
     fence state
  2. Clear FIR bits prior to clearing the fence status
  3. Clear's the fence status
  4. We take the powerbus out of CQ fence much later now,
     in credits_check() which is the last hardware procedure
     called after link training.
- hw/npu2.c: Remove static configuration of NPU2 register

  The NPU_SM_CONFIG0 register currently needs to be configured in Skiboot to
  select NVLink mode, however Hostboot should configure other bits in this
  register.

  For some reason Skiboot was explicitly clearing bit-6
  (CONFIG_DISABLE_VG_NOT_SYS). It is unclear why this bit was getting cleared
  as recent Hostboot versions explicitly set it to the correct value based on
  the specific system configuration. Therefore Skiboot should not alter it.

  Bit-58 (CONFIG_NVLINK_MODE) selects if NVLink mode should be enabled or
  not. Hostboot does not configure this bit so Skiboot should continue to
  configure it.
- npu2: Improve log output of GPU-to-link mapping

  Debugging issues related to unconnected NVLinks can be a little less
  irritating if we use the NPU2DEV{DBG,INF}() macros instead of prlog().

  In short, change this: ::

      NPU2: comparing GPU 'GPU2' and NPU2 'GPU1'
      NPU2: comparing GPU 'GPU3' and NPU2 'GPU1'
      NPU2: comparing GPU 'GPU4' and NPU2 'GPU1'
      NPU2: comparing GPU 'GPU5' and NPU2 'GPU1'
            :
      npu2_dev_bind_pci_dev: No PCI device for NPU2 device 0006:00:01.0 to bind to. If you expect a GPU to be there, this is a problem.

  to this: ::

      NPU6:0:1.0 Comparing GPU 'GPU2' and NPU2 'GPU1'
      NPU6:0:1.0 Comparing GPU 'GPU3' and NPU2 'GPU1'
      NPU6:0:1.0 Comparing GPU 'GPU4' and NPU2 'GPU1'
      NPU6:0:1.0 Comparing GPU 'GPU5' and NPU2 'GPU1'
            :
      NPU6:0:1.0 No PCI device found for slot 'GPU1'
- npu2: Move NPU2_XTS_BDF_MAP_VALID assignment to context init

  A bad GPU or other condition may leave us with a subset of links that
  never get initialized. If an ATSD is sent to one of those bricks, it
  will never complete, leaving us waiting forever for a response: ::

    watchdog: BUG: soft lockup - CPU#23 stuck for 23s! [acos:2050]
    ...
    Modules linked in: nvidia_uvm(O) nvidia(O)
    CPU: 23 PID: 2050 Comm: acos Tainted: G        W  O    4.14.0 #2
    task: c0000000285cfc00 task.stack: c000001fea860000
    NIP:  c0000000000abdf0 LR: c0000000000acc48 CTR: c0000000000ace60
    REGS: c000001fea863550 TRAP: 0901   Tainted: G        W  O     (4.14.0)
    MSR:  9000000000009033 <SF,HV,EE,ME,IR,DR,RI,LE>  CR: 28004484  XER: 20040000
    CFAR: c0000000000abdf4 SOFTE: 1
    GPR00: c0000000000acc48 c000001fea8637d0 c0000000011f7c00 c000001fea863820
    GPR04: 0000000002000000 0004100026000000 c0000000012778c8 c00000000127a560
    GPR08: 0000000000000001 0000000000000080 c000201cc7cb7750 ffffffffffffffff
    GPR12: 0000000000008000 c000000003167e80
    NIP [c0000000000abdf0] mmio_invalidate_wait+0x90/0xc0
    LR [c0000000000acc48] mmio_invalidate.isra.11+0x158/0x370


  ATSDs are only sent to bricks which have a valid entry in the XTS_BDF
  table. So to prevent the hang, don't set NPU2_XTS_BDF_MAP_VALID unless
  we make it all the way to creating a context for the BDF.

Secure and Trusted Boot
^^^^^^^^^^^^^^^^^^^^^^^
- hdata/tpmrel: detect tpm not present by looking up the stinfo->status

  Skiboot detects if tpm is present by checking if a secureboot_tpm_info
  entry exists. However, if a tpm is not present, hostboot also creates a
  secureboot_tpm_info entry. In this case, hostboot creates an empty
  entry, but setting the field tpm_status to TPM_NOT_PRESENT.

  This detects if tpm is not present by looking up the stinfo->status.

  This fixes the "TPMREL: TPM node not found for chip_id=0 (HB bug)"
  issue, reproduced when skiboot is running on a system that has no tpm.

PCI
^^^
- phb4: Restore bus numbers after CRS

  Currently we restore PCIe bus numbers right after the link is
  up. Unfortunately as this point we haven't done CRS so config space
  may not be accessible.

  This moves the bus number restore till after CRS has happened.
- romulus: Add a barebones slot table
- phb4: Quieten and improve "Timeout waiting for electrical link"

  This happens normally if a slot doesn't have a working HW presence
  detect and relies instead of inband presence detect.

  The message we display is scary and not very useful unless ou
  are debugging, so quiten it up and change it to something more
  meaningful.
- pcie-slot: Don't fail powering on an already on switch

  If the power state is already the required value, return
  OPAL_SUCCESS rather than OPAL_PARAMETER to avoid spurrious
  errors during boot.

CAPI/OpenCAPI
^^^^^^^^^^^^^
- capi: Keep the current mmio windows in the mbt cache table.

  When the phb is used as a CAPI interface, the current mmio windows list
  is cleaned before adding the capi and the prefetchable memory (M64)
  windows, which implies that the non-prefetchable BAR is no more
  configured.
  This patch allows to set only the mbt bar to pass capi mmio window and
  to keep, as defined, the other mmio values (M32 and M64).
- npu2-opencapi: Fix 'link internal error' FIR, take 2

  When setting up an opencapi link, we set the transport muxes first,
  then set the PHY training config register, which includes disabling
  nvlink mode for the bricks. That's the order of the init sequence, as
  found in the NPU workbook.

  In reality, doing so works, but it raises 2 FIR bits in the PowerBus
  OLL FIR Register for the 2 links when we configure the transport
  muxes. Presumably because nvlink is not disabled yet and we are
  configuring the transport muxes for opencapi.

  bit 60:
    link0 internal error
  bit 61:
    link1 internal error

  Overall the current setup ends up being correct and everything works,
  but we raise 2 FIR bits.

  So tweak the order of operations to disable nvlink before configuring
  the transport muxes. Incidentally, this is what the scripts from the
  opencapi enablement team were doing all along.
- npu2-opencapi: Fix 'link internal error' FIR, take 1

  When we setup a link, we always enable ODL0 and ODL1 at the same time
  in the PHY training config register, even though we are setting up
  only one OTL/ODL, so it raises a "link internal error" FIR bit in the
  PowerBus OLL FIR Register for the second link. The error is harmless,
  as we'll eventually setup the second link, but there's no reason to
  raise that FIR bit.

  The fix is simply to only enable the ODL we are using for the link.
- phb4: Do not set the PBCQ Tunnel BAR register when enabling capi mode.

  The cxl driver will set the capi value, like other drivers already do.
- phb4: set TVT1 for tunneled operations in capi mode

  The ASN indication is used for tunneled operations (as_notify and
  atomics). Tunneled operation messages can be sent in PCI mode as
  well as CAPI mode.

  The address field of as_notify messages is hijacked to encode the
  LPID/PID/TID of the target thread, so those messages should not go
  through address translation. Therefore bit 59 is part of the ASN
  indication.

  This patch sets TVT#1 in bypass mode when capi mode is enabled,
  to prevent as_notify messages from being dropped.

Debugging/Testing improvements
------------------------------
- core/stack: backtrace unwind basic OPAL call details

  Put OPAL callers' r1 into the stack back chain, and then use that to
  unwind back to the OPAL entry frame (as opposed to boot entry, which
  has a 0 back chain).

  From there, dump the OPAL call token and the caller's r1. A backtrace
  looks like this: ::

      CPU 0000 Backtrace:
       S: 0000000031c03ba0 R: 000000003001a548   ._abort+0x4c
       S: 0000000031c03c20 R: 000000003001baac   .opal_run_pollers+0x3c
       S: 0000000031c03ca0 R: 000000003001bcbc   .opal_poll_events+0xc4
       S: 0000000031c03d20 R: 00000000300051dc   opal_entry+0x12c
       --- OPAL call entry token: 0xa caller R1: 0xc0000000006d3b90 ---

  This is pretty basic for the moment, but it does give you the bottom
  of the Linux stack. It will allow some interesting improvements in
  future.

  First, with the eframe, all the call's parameters can be printed out
  as well.  The ___backtrace / ___print_backtrace API needs to be
  reworked in order to support this, but it's otherwise very simple
  (see opal_trace_entry()).

  Second, it will allow Linux's stack to be passed back to Linux via
  a debugging opal call. This will allow Linux's BUG() or xmon to
  also print the Linux back trace in case of a NMI or MCE or watchdog
  lockup that hits in OPAL.
- asm/head: implement quiescing without stack or clobbering regs

  Quiescing currently is implmeented in C in opal_entry before the
  opal call handler is called. This works well enough for simple
  cases like fast reset when one CPU wants all others out of the way.

  Linux would like to use it to prevent an sreset IPI from
  interrupting firmware, which could lead to deadlocks when crash
  dumping or entering the debugger. Linux interrupts do not recover
  well when returning back to general OPAL code, due to r13 not being
  restored. OPAL also can't be re-entered, which may happen e.g.,
  from the debugger.

  So move the quiesce hold/reject to entry code, beore the stack or
  r1 or r13 registers are switched. OPAL can be interrupted and
  returned to or re-entered during this period.

  This does not completely solve all such problems. OPAL will be
  interrupted with sreset if the quiesce times out, and it can be
  interrupted by MCEs as well. These still have the issues above.
- core/opal: Allow poller re-entry if OPAL was re-entered

  If an NMI interrupts the middle of running pollers and the OS
  invokes pollers again (e.g., for console output), the poller
  re-entrancy check will prevent it from running and spam the
  console.

  That check was designed to catch a poller calling opal_run_pollers,
  OPAL re-entrancy is something different and is detected elsewhere.
  Avoid the poller recursion check if OPAL has been re-entered. This
  is a best-effort attempt to cope with errors.
- core/opal: Emergency stack for re-entry

  This detects OPAL being re-entered by the OS, and switches to an
  emergency stack if it was. This protects the firmware's main stack
  from re-entrancy and allows the OS to use NMI facilities for crash
  / debug functionality.

  Further nested re-entry will destroy the previous emergency stack
  and prevent returning, but those should be rare cases.

  This stack is sized at 16kB, which doubles the size of CPU stacks,
  so as not to introduce a regression in primary stack size. The 16kB
  stack originally had a 4kB machine check stack at the top, which was
  removed by 80eee1946 ("opal: Remove machine check interrupt patching
  in OPAL."). So it is possible the size could be tightened again, but
  that would require further analysis.

- hdat_to_dt: hash_prop the same on all platforms
  Fixes this unit test on ppc64le hosts.
- mambo: Add persistent memory disk support

  This adds support to for mapping disks images using persistent
  memory. Disks can be added by setting this ENV variable:

    PMEM_DISK="/mydisks/disk1.img,/mydisks/disk2.img"

  These will show up in Linux as /dev/pmem0 and /dev/pmem1.

  This uses a new feature in mambo "mysim memory mmap .." which is only
  available since mambo commit 0131f0fc08 (from 24/4/2018).

  This also needs the of_pmem.c driver in Linux which is only available
  since v4.17. It works with powernv_defconfig + CONFIG_OF_PMEM.
- external/mambo: Add di command to decode instructions

  By default you get 16 instructions but you can specify the number you
  want.  i.e. ::

      systemsim % di 0x100 4
      0x0000000000000100: Enc:0xA64BB17D : mtspr   HSPRG1,r13
      0x0000000000000104: Enc:0xA64AB07D : mfspr   r13,HSPRG0
      0x0000000000000108: Enc:0xF0092DF9 : std     r9,0x9F0(r13)
      0x000000000000010C: Enc:0xA6E2207D : mfspr   r9,PPR

  Using di since it's what xmon uses.
- mambo/mambo_utils.tcl: Inject an MCE at a specified address

  Currently we don't support injecting an MCE on a specific address.
  This is useful for testing functionality like memcpy_mcsafe()
  (see https://patchwork.ozlabs.org/cover/893339/)

  The core of the functionality is a routine called
  inject_mce_ue_on_addr, which takes an addr argument and injects
  an MCE (load/store with UE) when the specified address is accessed
  by code. This functionality can easily be enhanced to cover
  instruction UE's as well.

  A sample use case to create an MCE on stack access would be ::

    set addr [mysim display gpr 1]
    inject_mce_ue_on_addr $addr

  This would cause an mce on any r1 or r1 based access
- external/mambo: improve helper for machine checks

  Improve workarounds for stop injection, because mambo often will
  trigger on 0x104/204 when injecting sreset/mces.

  This also adds a workaround to skip injecting on reservations to
  avoid infinite loops when doing inject_mce_step.
- travis: Enable ppc64le builds

  At least on the IBM Travis Enterprise instance, we can now do
  ppc64le builds!

  We can only build a subset of our matrix due to availability of
  ppc64le distros. The Dockerfiles need some tweaking to only
  attempt to install (x86_64 only) Mambo binaries, as well as the
  build scripts.
- external: Add "lpc" tool

  This is a little front-end to the lpc debugfs files to access
  the LPC bus from userspace on the host.
- core/test/run-trace: fix on ppc64el


