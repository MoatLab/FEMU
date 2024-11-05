.. _skiboot-6.3-rc1:

skiboot-6.3-rc1
===============

skiboot v6.3-rc1 was released on Friday March 29th 2019. It is the first
release candidate of skiboot 6.3, which will become the new stable release
of skiboot following the 6.2 release, first released December 14th 2018.

Skiboot 6.3 will mark the basis for op-build v2.3. I expect to tag the final
skiboot 6.3 in the next week.

skiboot v6.3-rc1 contains all bug fixes as of :ref:`skiboot-6.0.19`,
and :ref:`skiboot-6.2.3` (the currently maintained
stable releases).

For how the skiboot stable releases work, see :ref:`stable-rules` for details.

This release has been a longer cycle than typical for a variety of reasons. It
also contains a lot of cleanup work and minor bug fixes (much like skiboot 6.2
did).

Over skiboot 6.2, we have the following changes:

.. _skiboot-6.3-rc1-new-features:

New Features
------------

- hw/imc: Enable opal calls to init/start/stop IMC Trace mode

  New OPAL APIs for In-Memory Collection Counter infrastructure(IMC),
  including a new device type called OPAL_IMC_COUNTERS_TRACE.
- xive: Add calls to save/restore the queues and VPs HW state

  To be able to support migration of guests using the XIVE native
  exploitation mode, (where the queue is effectively owned by the
  guest), KVM needs to be able to save and restore the HW-modified
  fields of the queue, such as the current queue producer pointer and
  generation bit, and to retrieve the modified thread context registers
  of the VP from the NVT structure : the VP interrupt pending bits.

  However, there is no need to set back the NVT structure on P9. P10
  should be the same.
- witherspoon: Add nvlink2 interconnect information

  GPUs on Redbud and Sequoia platforms are interconnected in groups of
  2 or 3 GPUs. The problem with that is if the user decides to pass a single
  GPU from a group to the userspace, we need to ensure that links between
  GPUs do not get enabled.

  A V100 GPU provides a way to disable selected links. In order to only
  disable links to peer GPUs, we need a topology map.

  This adds an "ibm,nvlink-peers" property to a GPU DT node with phandles
  of peer GPUs and NVLink2 bridges. The index in the property is a GPU link
  number.
- platforms/romulus: Also support talos

  The two are similar enough and I'd like to have a slot table for our
  Talos.
- OpenCAPI support! (see :ref:`skiboot-6.3-rc1-OpenCAPI` section)
- opal/hmi: set a flag to inform OS that TOD/TB has failed.

  Set a flag to indicate OS about TOD/TB failure as part of new
  opal_handle_hmi2 handler. This flag then can be used by OS to make sure
  functions depending on TB value (e.g. udelay()) are aware of TB not
  ticking.
- astbmc: Enable IPMI HIOMAP for AMI platforms

  Required for Habanero, Palmetto and Romulus.
- power-mgmt : occ : Add 'freq-domain-mask' DT property

  Add a new device-tree property freq-domain-indicator to define group of
  CPUs which would share same frequency. This property has been added under
  power-mgmt node. It is a bitmask.

  Bitwise AND is taken between this bitmask value and PIR of cpu. All the
  CPUs lying in the same frequency domain will have same result for AND.

  For example, For POWER9, 0xFFF0 indicates quad wide frequency domain.
  Taking AND with the PIR of CPUs will yield us frequency domain which is
  quad wise distribution as last 4 bits have been masked which represent the
  cores.

  Similarly, 0xFFF8 will represent core wide frequency domain for P8.

  Also, Add a new device-tree property domain-runs-at which will denote the
  strategy OCC is using to change the frequency of a frequency-domain. There
  can be two strategy - FREQ_MOST_RECENTLY_SET and FREQ_MAX_IN_DOMAIN.

  FREQ_MOST_RECENTLY_SET : the OCC sets the frequency of the quad to the most
  recent frequency value requested by the CPUs in the quad.

  FREQ_MAX_IN_DOMAIN : the OCC sets the frequency of the CPUs in
  the Quad to the maximum of the latest frequency requested by each of
  the component cores.
- powercap: occ: Fix the powercapping range allowed for user

  OCC provides two limits for minimum powercap. One being hard powercap
  minimum which is guaranteed by OCC and the other one is a soft
  powercap minimum which is lesser than hard-min and may or may not be
  asserted due to various power-thermal reasons. So to allow the users
  to access the entire powercap range, this patch exports soft powercap
  minimum as the "powercap-min" DT property. And it also adds a new
  DT property called "powercap-hard-min" to export the hard-min powercap
  limit.
- Add NVDIMM support

  NVDIMMs are memory modules that use a battery backup system to allow the
  contents RAM to be saved to non-volatile storage if system power goes
  away unexpectedly. This allows them to be used a high-performance
  storage device, suitable for serving as a cache for SSDs and the like.

  Configuration of NVDIMMs is handled by hostboot and communicated to OPAL
  via the HDAT. We need to parse out the NVDIMM memory ranges and create
  memory regions with the "pmem-region" compatible label to make them
  available to the host.
- core/exceptions: implement support for MCE interrupts in powersave

  The ISA specifies that MCE interrupts in power saving modes will enter
  at 0x200 with powersave bits in SRR1 set. This is not currently
  supported properly, the MCE will just happen like a normal interrupt,
  but GPRs could be lost, which would lead to crashes (e.g., r1, r2, r13
  etc).

  So check the power save bits similarly to the sreset vector, and
  handle this properly.
- core/exceptions: allow recoverable sreset exceptions

  This requires implementing the MSR[RI] bit. Then just allow all
  non-fatal sreset exceptions to recover.
- core/exceptions: implement an exception handler for non-powersave sresets

  Detect non-powersave sresets and send them to the normal exception
  handler which prints registers and stack.
- Add PVR_TYPE_P9P

  Enable a new PVR to get us running on another p9 variant.

Deprecated/Removed Features
---------------------------

- opal: Deprecate reading the PHB status

  The OPAL_PCI_EEH_FREEZE_STATUS call takes a bunch of parameters, one of
  them is @phb_status. It is defined as __be64* and always NULL in
  the current Linux upstream but if anyone ever decides to read that status,
  then the PHB3's handler will assume it is struct OpalIoPhb3ErrorData*
  (which is a lot bigger than 8 bytes) and zero it causing the stack
  corruption; p7ioc-phb has the same issue.

  This removes @phb_status from all eeh_freeze_status() hooks and moves
  the error message from PHB4 to the affected OPAL handlers.

  As far as we can tell, nobody has ever used this and thus it's safe to remove.
- Remove POWER9N DD1 support

  This is not a shipping product and is no longer supported by Linux
  or other firmware components.

General
-------

- core/i2c: Various bits of refactoring
- refactor backtrace generation infrastructure
- astbmc: Handle failure to initialise raw flash

  Initialising raw flash lead to a dead assignment to rc. Check the return
  code and take the failure path as necessary. Both before and after the
  fix we see output along the lines of the following when flash_init()
  fails: ::

    [   53.283182881,7] IRQ: Registering 0800..0ff7 ops @0x300d4b98 (data 0x3052b9d8)
    [   53.283184335,7] IRQ: Registering 0ff8..0fff ops @0x300d4bc8 (data 0x3052b9d8)
    [   53.283185513,7] PHB#0000: Initializing PHB...
    [   53.288260827,4] FLASH: Can't load resource id:0. No system flash found
    [   53.288354442,4] FLASH: Can't load resource id:1. No system flash found
    [   53.342933439,3] CAPP: Error loading ucode lid. index=200ea
    [   53.462749486,2] NVRAM: Failed to load
    [   53.462819095,2] NVRAM: Failed to load
    [   53.462894236,2] NVRAM: Failed to load
    [   53.462967071,2] NVRAM: Failed to load
    [   53.463033077,2] NVRAM: Failed to load
    [   53.463144847,2] NVRAM: Failed to load

  Eventually followed by: ::

    [   57.216942479,5] INIT: platform wait for kernel load failed
    [   57.217051132,5] INIT: Assuming kernel at 0x20000000
    [   57.217127508,3] INIT: ELF header not found. Assuming raw binary.
    [   57.217249886,2] NVRAM: Failed to load
    [   57.221294487,0] FATAL: Kernel is zeros, can't execute!
    [   57.221397429,0] Assert fail: core/init.c:615:0
    [   57.221471414,0] Aborting!
    CPU 0028 Backtrace:
     S: 0000000031d43c60 R: 000000003001b274   ._abort+0x4c
     S: 0000000031d43ce0 R: 000000003001b2f0   .assert_fail+0x34
     S: 0000000031d43d60 R: 0000000030014814   .load_and_boot_kernel+0xae4
     S: 0000000031d43e30 R: 0000000030015164   .main_cpu_entry+0x680
     S: 0000000031d43f00 R: 0000000030002718   boot_entry+0x1c0
     --- OPAL boot ---

  Analysis of the execution paths suggests we'll always "safely" end this
  way due the setup sequence for the blocklevel callbacks in flash_init()
  and error handling in blocklevel_get_info(), and there's no current risk
  of executing from unexpected memory locations. As such the issue is
  reduced to down to a fix for poor error hygene in the original change
  and a resolution for a Coverity warning (famous last words etc).
- core/flash: Retry requests as necessary in flash_load_resource()

  We would like to successfully boot if we have a dependency on the BMC
  for flash even if the BMC is not current ready to service flash
  requests. On the assumption that it will become ready, retry for several
  minutes to cover a BMC reboot cycle and *eventually* rather than
  *immediately* crash out with: ::

        [  269.549748] reboot: Restarting system
        [  390.297462587,5] OPAL: Reboot request...
        [  390.297737995,5] RESET: Initiating fast reboot 1...
        [  391.074707590,5] Clearing unused memory:
        [  391.075198880,5] PCI: Clearing all devices...
        [  391.075201618,7] Clearing region 201ffe000000-201fff800000
        [  391.086235699,5] PCI: Resetting PHBs and training links...
        [  391.254089525,3] FFS: Error 17 reading flash header
        [  391.254159668,3] FLASH: Can't open ffs handle: 17
        [  392.307245135,5] PCI: Probing slots...
        [  392.363723191,5] PCI Summary:
        ...
        [  393.423255262,5] OCC: All Chip Rdy after 0 ms
        [  393.453092828,5] INIT: Starting kernel at 0x20000000, fdt at
        0x30800a88 390645 bytes
        [  393.453202605,0] FATAL: Kernel is zeros, can't execute!
        [  393.453247064,0] Assert fail: core/init.c:593:0
        [  393.453289682,0] Aborting!
        CPU 0040 Backtrace:
         S: 0000000031e03ca0 R: 000000003001af60   ._abort+0x4c
         S: 0000000031e03d20 R: 000000003001afdc   .assert_fail+0x34
         S: 0000000031e03da0 R: 00000000300146d8   .load_and_boot_kernel+0xb30
         S: 0000000031e03e70 R: 0000000030026cf0   .fast_reboot_entry+0x39c
         S: 0000000031e03f00 R: 0000000030002a4c   fast_reset_entry+0x2c
         --- OPAL boot ---

  The OPAL flash API hooks directly into the blocklevel layer, so there's
  no delay for e.g. the host kernel, just for asynchronously loaded
  resources during boot.
- fast-reboot: occ: Call occ_pstates_init() on fast-reset on all machines

  Commit 815417dcda2e ("init, occ: Initialise OCC earlier on BMC systems")
  conditionally invoked occ_pstates_init() only on FSP based systems in
  load_and_boot_kernel(). Due to this pstate table is re-parsed on FSP
  system and skipped on BMC system during fast-reboot. So this patch fixes
  this by invoking occ_pstates_init() on all boxes during fast-reboot.
- opal/hmi: Don't retry TOD recovery if it is already in failed state.

  On TOD failure, all cores/thread receives HMI and very first thread that
  gets interrupt fixes the TOD where as others just resets the respective
  HMER error bit and return. But when TOD is unrecoverable, all the threads
  try to do TOD recovery one by one causing threads to spend more time inside
  opal. Set a global flag when TOD is unrecoverable so that rest of the
  threads go back to linux immediately avoiding lock ups in system
  reboot/panic path.
- hw/bt: Do not disable ipmi message retry during OPAL boot

  Currently OPAL doesn't know whether BMC is functioning or not. If BMC is
  down (like BMC reboot), then we keep on retry sending message to BMC. So
  in some corner cases we may hit hard lockup issue in kernel.

  Ideally we should avoid using synchronous path as much as possible. But
  for now commit 01f977c3 added option to disable message retry in synchronous.
  But this fix is not required during boot. Hence lets disable IPMI message
  retry during OPAL boot.
- hdata/memory: Fix warning message

  Even though we added memory to device tree, we are getting below warning. ::

    [   57.136949696,3] Unable to use memory range 0 from MSAREA 0
    [   57.137049753,3] Unable to use memory range 0 from MSAREA 1
    [   57.137152335,3] Unable to use memory range 0 from MSAREA 2
    [   57.137251218,3] Unable to use memory range 0 from MSAREA 3
- hw/bt: Add backend interface to disable ipmi message retry option

  During boot OPAL makes IPMI_GET_BT_CAPS call to BMC to get BT interface
  capabilities which includes IPMI message max resend count, message
  timeout, etc,. Most of the time OPAL gets response from BMC within
  specified timeout. In some corner cases (like mboxd daemon reset in BMC,
  BMC reboot, etc) OPAL may not get response within timeout period. In
  such scenarios, OPAL resends message until max resend count reaches.

  OPAL uses synchronous IPMI message (ipmi_queue_msg_sync()) for few
  operations like flash read, write, etc. Thread will wait in OPAL until
  it gets response from BMC. In some corner cases like BMC reboot, thread
  may wait in OPAL for long time (more than 20 seconds) and results in
  kernel hardlockup.

  This patch introduces new interface to disable message resend option. We
  will disable message resend option for synchrous message. This will
  greatly reduces kernel hardlock up issues.

  This is short term fix. Long term solution is to convert all synchronous
  messages to asynhrounous one.
- ipmi/power: Fix system reboot issue

  Kernel makes reboot/shudown OPAL call for reboot/shutdown. Once kernel
  gets response from OPAL it runs opal_poll_events() until firmware
  handles the request.

  On BMC based system, OPAL makes IPMI call (IPMI_CHASSIS_CONTROL) to
  initiate system reboot/shutdown. At present OPAL queues IPMI messages
  and return SUCESS to Host. If BMC is not ready to accept command (like
  BMC reboot), then these message will fail. We have to manually
  reboot/shutdown the system using BMC interface.

  This patch adds logic to validate message return value. If message failed,
  then it will resend the message. At some stage BMC will be ready to accept
  message and handles IPMI message.
- firmware-versions: Add test case for parsing VERSION

  Also make it possible to use with afl-lop/afl-fuzz just to help make
  *sure* we're all good.

  Additionally, if we hit a entry in VERSION that is larger than our
  buffer size, we skip over it gracefully rather than overwriting the
  stack. This is only a problem if VERSION isn't trusted, which as of
  4b8cc05a94513816d43fb8bd6178896b430af08f it is verified as part of
  Secure Boot.
- core/fast-reboot: improve NMI handling during fast reset

  Improve sreset and MCE handling in fast reboot. Switch the HILE bit
  off before copying OPAL's exception vectors, so NMIs can be handled
  properly. Also disable MSR[ME] while the vectors are being overwritten
- core/cpu: HID update race

  If the per-core HID register is updated concurrently by multiple
  threads, updates can get lost. This has been observed during fast
  reboot where the HILE bit does not get cleared on all cores, which
  can cause machine check exception interrupts to crash.

  Fix this by only updating HID on thread0.
- SLW: Print verbose info on errors only

  Change print level from debug to warning for reporting
  bad EC_PPM_SPECIAL_WKUP_* scom values. To reduce cluttering
  in the log print only on error.

IBM FSP based platforms
-----------------------

- platforms/firenze: Rework I2C controller fixups
- platforms/zz: Re-enable LXVPD slot information parsing

  From memory this was disabled in the distant past since we were waiting
  for an updates to the LXPVD format. It looks like that never happened
  so re-enable it for the ZZ platform so that we can get PCI slot location
  codes on ZZ.

HIOMAP
------
- astbmc: Try IPMI HIOMAP for P8

  The HIOMAP protocol was developed after the release of P8 in preparation
  for P9. As a consequence P9 always uses it, but it has rarely been
  enabled for P8. P8DTU has recently added IPMI HIOMAP support to its BMC
  firmware, so enable its use in skiboot with P8 machines. Doing so
  requires some rework to ensure fallback works correctly as in the past
  the fallback was to mbox, which will only work for P9.
- libflash/ipmi-hiomap: Enforce message size for empty response

  The protocol defines the response to the associated messages as empty
  except for the command ID and sequence fields. If the BMC is returning
  extra data consider the message malformed.
- libflash/ipmi-hiomap: Remove unused close handling

  Issuing a HIOMAP_C_CLOSE is not required by the protocol specification,
  rather a close can be implicit in a subsequent
  CREATE_{READ,WRITE}_WINDOW request. The implicit close provides an
  opportunity to reduce LPC traffic and the implementation takes up that
  optimisation, so remove the case from the IPMI callback handler.
- libflash/ipmi-hiomap: Overhaul event handling

  Reworking the event handling was inspired by a bug report by Vasant
  where the host would get wedged on multiple flash access attempts in the
  face of a persistent error state on the BMC-side. The cause of this bug
  was the early-exit based on ctx->update, which erronously assumed that
  all events had been completely handled in prior calls to
  ipmi_hiomap_handle_events(). This is not true if e.g.
  HIOMAP_E_DAEMON_READY is clear in the prior calls.

  Regardless, there were other correctness and efficiency problems with
  the handling strategy:

  * Ack-able event state was not restored in the face of errors in the
    process of re-establishing protocol state
  * It forced needless window restoration with respect to the context in
    which ipmi_hiomap_handle_events() was called.
  * Tests for HIOMAP_E_DAEMON_READY and HIOMAP_E_FLASH_LOST were redundant
    with the overhauled error handling introduced in the previous patch

  Fix all of the above issues and add comments to explain the event
  handling flow.
- libflash/ipmi-hiomap: Overhaul error handling

  The aim is to improve the robustness with respect to absence of the
  BMC-side daemon. The current error handling roughly mirrors what was
  done for the mailbox implementation, but there's room for improvement.

  Errors are split into two classes, those that affect the transport state
  and those that affect the window validity. From here, we push the
  transport state error checks right to the bottom of the stack, to ensure
  the link is known to be in a good state before any message is sent.
  Window validity tests remain as they were in the hiomap_window_move()
  and ipmi_hiomap_read() functions. Validity tests are not necessary in
  the write and erase paths as we will receive an error response from the
  BMC when performing a dirty or flush on an invalid window.

  Recovery also remains as it was, done on entry to the blocklevel
  callbacks. If an error state is encountered in the middle of an
  operation no attempt is made to recover it on the spot, instead the
  error is returned up the stack and the caller can choose how it wishes
  to respond.
- libflash/ipmi-hiomap: Fix leak of msg in callback

POWER8
------
- hw/phb3/naples: Disable D-states

  Putting "Mellanox Technologies MT27700 Family [ConnectX-4] [15b3:1013]"
  (more precisely, the second of 2 its PCI functions, no matter in what
  order) into the D3 state causes EEH with the "PCT timeout" error.
  This has been noticed on garrison machines only and firestones do not
  seem to have this issue.

  This disables D-states changing for devices on root buses on Naples by
  installing a config space access filter (copied from PHB4).
- cpufeatures: Always advertise POWER8NVL as DD2

  Despite the major version of PVR being 1 (0x004c0100) for POWER8NVL,
  these chips are functionally equalent to P8/P8E DD2 levels.

  This advertises POWER8NVL as DD2. As the result, skiboot adds
  ibm,powerpc-cpu-features/processor-control-facility for such CPUs and
  the linux kernel can use hypervisor doorbell messages to wake secondary
  threads; otherwise "KVM: CPU %d seems to be stuck" would appear because
  of missing LPCR_PECEDH.

p8dtu Platform
^^^^^^^^^^^^^^
- p8dtu: Configure BMC graphics

  We can no-longer read the values from the BMC in the way we have in the
  past. Values were provided by Eric Chen of SMC.
- p8dtu: Enable HIOMAP support

Vesnin Platform
^^^^^^^^^^^^^^^
- platforms/vesnin: Disable PCIe port bifurcation

  PCIe ports connected to CPU1 and CPU3 now work as x16 instead of x8x8.

- Fix hang in pnv_platform_error_reboot path due to TOD failure.

  On TOD failure, with TB stuck, when linux heads down to
  pnv_platform_error_reboot() path due to unrecoverable hmi event, the panic
  cpu gets stuck in OPAL inside ipmi_queue_msg_sync(). At this time, rest
  all other cpus are in smp_handle_nmi_ipi() waiting for panic cpu to proceed.
  But with panic cpu stuck inside OPAL, linux never recovers/reboot. ::

    p0 c1 t0
    NIA : 0x000000003001dd3c <.time_wait+0x64>
    CFAR : 0x000000003001dce4 <.time_wait+0xc>
    MSR : 0x9000000002803002
    LR : 0x000000003002ecf8 <.ipmi_queue_msg_sync+0xec>

    STACK: SP NIA
    0x0000000031c236e0 0x0000000031c23760 (big-endian)
    0x0000000031c23760 0x000000003002ecf8 <.ipmi_queue_msg_sync+0xec>
    0x0000000031c237f0 0x00000000300aa5f8 <.hiomap_queue_msg_sync+0x7c>
    0x0000000031c23880 0x00000000300aaadc <.hiomap_window_move+0x150>
    0x0000000031c23950 0x00000000300ab1d8 <.ipmi_hiomap_write+0xcc>
    0x0000000031c23a90 0x00000000300a7b18 <.blocklevel_raw_write+0xbc>
    0x0000000031c23b30 0x00000000300a7c34 <.blocklevel_write+0xfc>
    0x0000000031c23bf0 0x0000000030030be0 <.flash_nvram_write+0xd4>
    0x0000000031c23c90 0x000000003002c128 <.opal_write_nvram+0xd0>
    0x0000000031c23d20 0x00000000300051e4 <opal_entry+0x134>
    0xc000001fea6e7870 0xc0000000000a9060 <opal_nvram_write+0x80>
    0xc000001fea6e78c0 0xc000000000030b84 <nvram_write_os_partition+0x94>
    0xc000001fea6e7960 0xc0000000000310b0 <nvram_pstore_write+0xb0>
    0xc000001fea6e7990 0xc0000000004792d4 <pstore_dump+0x1d4>
    0xc000001fea6e7ad0 0xc00000000018a570 <kmsg_dump+0x140>
    0xc000001fea6e7b40 0xc000000000028e5c <panic_flush_kmsg_end+0x2c>
    0xc000001fea6e7b60 0xc0000000000a7168 <pnv_platform_error_reboot+0x68>
    0xc000001fea6e7bd0 0xc0000000000ac9b8 <hmi_event_handler+0x1d8>
    0xc000001fea6e7c80 0xc00000000012d6c8 <process_one_work+0x1b8>
    0xc000001fea6e7d20 0xc00000000012da28 <worker_thread+0x88>
    0xc000001fea6e7db0 0xc0000000001366f4 <kthread+0x164>
    0xc000001fea6e7e20 0xc00000000000b65c <ret_from_kernel_thread+0x5c>

  This is because, there is a while loop towards the end of
  ipmi_queue_msg_sync() which keeps looping until "sync_msg" does not match
  with "msg". It loops over time_wait_ms() until exit condition is met. In
  normal scenario time_wait_ms() calls run pollers so that ipmi backend gets
  a chance to check ipmi response and set sync_msg to NULL. ::

            while (sync_msg == msg)
                    time_wait_ms(10);

  But in the event when TB is in failed state time_wait_ms()->time_wait_poll()
  returns immediately without calling pollers and hence we end up looping
  forever. This patch fixes this hang by calling opal_run_pollers() in TB
  failed state as well.


.. _skiboot-6.3-rc1-power9:

POWER9
------

- Retry link training at PCIe GEN1 if presence detected but training repeatedly failed

  Certain older PCIe 1.0 devices will not train unless the training process starts at GEN1 speeds.
  As a last resort when a device will not train, fall back to GEN1 speed for the last training attempt.

  This is verified to fix devices based on the Conexant CX23888 on the Talos II platform.
- hw/phb4: Drop FRESET_DEASSERT_DELAY state

  The delay between the ASSERT_DELAY and DEASSERT_DELAY states is set to
  one timebase tick. This state seems to have been a hold over from PHB3
  where it was used to add a 1s delay between de-asserting PERST and
  polling the link for the CAPI FPGA. There's no requirement for that here
  since the link polling on PHB4 is a bit smarter so we should be fine.
- hw/phb4: Factor out PERST control

  Some time ago Mikey added some code work around a bug we found where a
  certain RAID card wouldn't come back again after a fast-reboot. The
  workaround is setting the Link Disable bit before asserting PERST and
  clear it after de-asserting PERST.

  Currently we do this in the FRESET path, but not in the CRESET path.
  This patch moves the PERST control into its own function to reduce
  duplication and to the workaround is applied in all circumstances.
- hw/phb4: Remove FRESET presence check

  When we do an freset the first step is to check if a card is present in
  the slot. However, this only occurs when we enter phb4_freset() with the
  slot state set to SLOT_NORMAL. This occurs in:

  a) The creset path, and
  b) When the OS manually requests an FRESET via an OPAL call.

  (a) is problematic because in the boot path the generic code will put the
  slot into FRESET_START manually before calling into phb4_freset(). This
  can result in a situation where a device is detected on boot, but not
  after a CRESET.

  I've noticed this occurring on systems where the PHB's slot presence
  detect signal is not wired to an adapter. In this situation we can rely
  on the in-band presence mechanism, but the presence check will make
  us exit before that has a chance to work.

  Additionally, if we enter from the CRESET path this early exit leaves
  the slot's PERST signal being left asserted. This isn't currently an issue,
  but if we want to support hotplug of devices into the root port it will
  be.
- hw/phb4: Skip FRESET PERST when coming from CRESET

  PERST is asserted at the beginning of the CRESET process to prevent
  the downstream device from interacting with the host while the PHB logic
  is being reset and re-initialised. There is at least a 100ms wait during
  the CRESET processing so it's not necessary to wait this time again
  in the FRESET handler.

  This patch extends the delay after re-setting the PHB logic to extend
  to the 250ms PERST wait period that we typically use and sets the
  skip_perst flag so that we don't wait this time again in the FRESET
  handler.
- hw/phb4: Look for the hub-id from in the PBCQ node

  The hub-id is stored in the PBCQ node rather than the stack node so we
  never add it to the PHB node. This breaks the lxvpd slot lookup code
  since the hub-id is encoded in the VPD record that we need to find the
  slot information.
- hdata/iohub: Look for IOVPD on P9

  P8 and P9 use the same IO VPD setup, so we need to load the IOHUB VPD on
  P9 systems too.

CAPI2
^^^^^
- capp/phb4: Prevent HMI from getting triggered when disabling CAPP

  While disabling CAPP an HMI gets triggered as soon as ETU is put in
  reset mode. This is caused as before we can disabled CAPP, it detects
  PHB link going down and triggers an HMI requesting Opal to perform
  CAPP recovery. This has an un-intended side effect of spamming the
  Opal logs with malfunction alert messages and may also confuse the
  user.

  To prevent this we mask the CAPP FIR error 'PHB Link Down' Bit(31)
  when we are disabling CAPP just before we put ETU in reset in
  phb4_creset(). Also now since bringing down the PHB link now wont
  trigger an HMI and CAPP recovery, hence we manually set the
  PHB4_CAPP_RECOVERY flag on the phb to force recovery during creset.

- phb4/capp: Implement sequence to disable CAPP and enable fast-reset

  We implement h/w sequence to disable CAPP in disable_capi_mode() and
  with it also enable fast-reset for CAPI mode in phb4_set_capi_mode().

  Sequence to disable CAPP is executed in three phases. The first two
  phase is implemented in disable_capi_mode() where we reset the CAPP
  registers followed by PEC registers to their init values. The final
  third final phase is to reset the PHB CAPI Compare/Mask Register and
  is done in phb4_init_ioda3(). The reason to move the PHB reset to
  phb4_init_ioda3() is because by the time Opal PCI reset state machine
  reaches this function the PHB is already un-fenced and its
  configuration registers accessible via mmio.
- capp/phb4: Force CAPP to PCIe mode during kernel shutdown

  This patch introduces a new opal syncer for PHB4 named
  phb4_host_sync_reset(). We register this opal syncer when CAPP is
  activated successfully in phb4_set_capi_mode() so that it will be
  called at kernel shutdown during fast-reset.

  During kernel shutdown the function will then repeatedly call
  phb->ops->set_capi_mode() to switch switch CAPP to PCIe mode. In case
  set_capi_mode() indicates its OPAL_BUSY, which indicates that CAPP is
  still transitioning to new state; it calls slot->ops.run_sm() to
  ensure that Opal slot reset state machine makes forward progress.


Witherspoon Platform
^^^^^^^^^^^^^^^^^^^^
- platforms/witherspoon: Make PCIe shared slot error message more informative

  If we're missing chips for some reason, we print a warning when configuring
  the PCIe shared slot.

  The warning doesn't really make it clear what "shared slot" is, and if it's
  printed, it'll come right after a bunch of messages about NPU setup, so
  let's clarify the message to explicitly mention PCI.
- witherspoon: Add nvlink2 interconnect information

  See :ref:`skiboot-6.3-rc1-new-features` for details.

Zaius Platform
^^^^^^^^^^^^^^

- zaius: Add BMC description

  Frederic reported that Zaius was failing with a NULL dereference when
  trying to initialise IPMI HIOMAP. It turns out that the BMC wasn't
  described at all, so add a description.

p9dsu platform
^^^^^^^^^^^^^^
- p9dsu: Fix p9dsu default variant

  Add the default when no riser_id is returned from the ipmi query.

  Allow a little more time for BMC reply and cleanup some label strings.


PCIe
----

See :ref:`skiboot-6.3-rc1-power9` for POWER9 specific PCIe changes.

- core/pcie-slot: Don't bail early in the power on case

  Exiting early in the power off case makes sense since we can't disable
  slot power (or assert PERST) for suprise hotplug slots. However, we
  should not exit early in the power-on case since it's possible slot
  power may have been disabled (or just not enabled at boot time).
- firenze-pci: Always init slot info from LXVPD

  We can slot information from the LXVPD without having power control
  information about that slot. This patch changes the init path so that
  we always override the add_properties() call rather than only when we
  have power control information about the slot.
- fsp/lxvpd: Print more LXVPD slot information

  Useful to know since it changes the behaviour of the slot core.
- core/pcie-slot: Set power state from the PWRCTL flag

  For some reason we look at the power control indicator and use that to
  determine if the slot is "off" rather than the power control flag that
  is used to power down the slot.

  While we're here change the default behaviour so that the slot is
  assumed to be powered on if there's no slot capability, or if there's
  no power control available.
- core/pci: Increase the max slot string size

  The maximum string length for the slot label / device location code in
  the PCI summary is currently 32 characters. This results in some IBM
  location codes being truncated due to their length, e.g. ::

    PHB#0001:02:11.0 [SWDN]  SLOT=C11  x8
    PHB#0001:13:00.0 [EP  ] *snip* LOC_CODE=U78D3.ND1.WZS004A-P1-C
    PHB#0001:13:00.1 [EP  ] *snip* LOC_CODE=U78D3.ND1.WZS004A-P1-C
    PHB#0001:13:00.2 [EP  ] *snip* LOC_CODE=U78D3.ND1.WZS004A-P1-C
    PHB#0001:13:00.3 [EP  ] *snip* LOC_CODE=U78D3.ND1.WZS004A-P1-C

  Which obscure the actual location of the card, and it looks bad. This
  patch increases the maximum length of the label string to 80 characters
  since that's the maximum length for a location code.



.. _skiboot-6.3-rc1-OpenCAPI:

OpenCAPI
--------
- npu2/hw-procedures: Fix parallel zcal for opencapi

  For opencapi, we currently do impedance calibration when initializing
  the PHY for the device, which could run in parallel if we have
  multiple opencapi devices. But if 2 devices are on the same
  obus, the 2 calibration sequences could overlap, which likely yields
  bad results and is useless anyway since it only needs to be done once
  per obus.

  This patch splits the opencapi PHY reset in 2 parts:

  - a 'init' part called serially at boot. That's when zcal is done. If
    we have 2 devices on the same socket, the zcal won't be redone,
    since we're called serially and we'll see it has already be done for
    the obus
  - a 'reset' part called during fundamental reset as a prereq for link
    training. It does the PHY setup for a set of lanes and the dccal.

  The PHY team confirmed there's no dependency between zcal and the
  other reset steps and it can be moved earlier.
- npu2-hw-procedures: Fix zcal in mixed opencapi and nvlink mode

  The zcal procedure needs to be run once per obus. We keep track of
  which obus is already calibrated in an array indexed by the obus
  number. However, the obus number is inferred from the brick index,
  which works well for nvlink but not for opencapi.

  Create an obus_index() function, which, from a device, returns the
  correct obus index, irrespective of the device type.
- npu2-opencapi: Fix adapter reset when using 2 adapters

  If two opencapi adapters are on the same obus, we may try to train the
  two links in parallel at boot time, when all the PCI links are being
  trained. Both links use the same i2c controller to handle the reset
  signal, so some care is needed to make sure resetting one doesn't
  interfere with the reset of the other. We need to keep track of the
  current state of the i2c controller (and use locking).

  This went mostly unnoticed as you need to have 2 opencapi cards on the
  same socket and links tended to train anyway because of the retries.
- npu2-opencapi: Extend delay after releasing reset on adapter

  Give more time to the FPGA to process the reset signal. The previous
  delay, 5ms, is too short for newer adapters with bigger FPGAs. Extend
  it to 250ms.
  Ultimately, that delay will likely end up being added to the opencapi
  specification, but we are not there yet.
- npu2-opencapi: ODL should be in reset when enabled

  We haven't hit any problem so far, but from the ODL designer, the ODL
  should be in reset when it is enabled.

  The ODL remains in reset until we start a fundamental reset to
  initiate link training. We still assert and deassert the ODL reset
  signal as part of the normal procedure just before training the
  link. Asserting is therefore useless at boot, since the ODL is already
  in reset, but we keep it as it's only a scom write and it's needed
  when we reset/retrain from the OS.
- npu2-opencapi: Keep ODL and adapter in reset at the same time

  Split the function to assert and deassert the reset signal on the ODL,
  so that we can keep the ODL in reset while we reset the adapter,
  therefore having a window where both sides are in reset.

  It is actually not required with our current DLx at boot time, but I
  need to split the ODL reset function for the following patch and it
  will become useful/required later when we introduce resetting an
  opencapi link from the OS.
- npu2-opencapi: Setup perf counters to detect CRC errors

  It's possible to set up performance counters for the PLL to detect
  various conditions for the links in nvlink or opencapi mode. Since
  those counters are currently unused, let's configure them when an obus
  is in opencapi mode to detect CRC errors on the link. Each link has
  two counters:
  - CRC error detected by the host
  - CRC error detected by the DLx (NAK received by the host)

  We also dump the counters shortly after the link trains, but they can
  be read multiple times through cronus, pdbg or linux. The counters are
  configured to be reset after each read.

NVLINK2
-------
- npu2: Allow ATSD for LPAR other than 0

  Each XTS MMIO ATSD# register is accompanied by another register -
  XTS MMIO ATSD0 LPARID# - which controls LPID filtering for ATSD
  transactions.

  When a host system passes a GPU through to a guest, we need to enable
  some ATSD for an LPAR. At the moment the host assigns one ATSD to
  a NVLink bridge and this maps it to an LPAR when GPU is assigned to
  the LPAR. The link number is used for an ATSD index.

  ATSD6&7 stay mapped to the host (LPAR=0) all the time which seems to be
  acceptable price for the simplicity.
- npu2: Add XTS_BDF_MAP wildcard refcount

  Currently PID wildcard is programmed into the NPU once and never cleared
  up. This works for the bare metal as MSR does not change while the host
  OS is running.

  However with the device virtualization, we need to keep track of wildcard
  entries use and clear them up before switching a GPU from a host to
  a guest or vice versa.

  This adds refcount to a NPU2, one counter per wildcard entry. The index
  is a short lparid (4 bits long) which is allocated in opal_npu_map_lpar()
  and should be smaller than NPU2_XTS_BDF_MAP_SIZE (defined as 16).



Debugging and simulation
------------------------

- external/mambo: Error out if kernel is too large

  If you're trying to boot a gigantic kernel in mambo (which you can
  reproduce by building a kernel with CONFIG_MODULES=n) you'll get
  misleading errors like: ::

    WARNING: 0: (0): [0:0]: Invalid/unsupported instr 0x00000000[INVALID]
    WARNING: 0: (0):  PC(EA): 0x0000000030000010 PC(RA):0x0000000030000010 MSR: 0x9000000000000000 LR: 0x0000000000000000
    WARNING: 0: (0):  numInstructions = 0
    WARNING: 1: (1): [0:0]: Invalid/unsupported instr 0x00000000[INVALID]
    WARNING: 1: (1):  PC(EA): 0x0000000000000E40 PC(RA):0x0000000000000E40 MSR: 0x9000000000000000 LR: 0x0000000000000000
    WARNING: 1: (1):  numInstructions = 1
    WARNING: 1: (1): Interrupt to 0x0000000000000E40 from 0x0000000000000E40
    INFO: 1: (2): ** Execution stopped: Continuous Interrupt, Instruction caused exception,  **

  So add an error to skiboot.tcl to warn the user before this happens.
  Making PAYLOAD_ADDR further back is one way to do this but if there's a
  less gross way to generally work around this very niche problem, I can
  suggest that instead.
- external/mambo: Populate kernel-base-address in the DT

  skiboot.tcl defines PAYLOAD_ADDR as 0x20000000, which is the default in
  skiboot.  This is also the default in skiboot unless kernel-base-address
  is set in the device tree.

  If you change PAYLOAD_ADDR to something else for mambo, skiboot won't
  see it because it doesn't set that DT property, so fix it so that it does.
- external/mambo: allow CPU targeting for most debug utils

  Debug util functions target CPU 0:0:0 by default Some can be
  overidden explicitly per invocation, and others can't at all.
  Even for those that can be overidden, it is a pain to type
  them out when you're debugging a particular thread.

  Provide a new 'target' function that allows the default CPU
  target to be changed. Wire that up that default to all other utils.
  Provide a new 'S' step command which only steps the target CPU.
- qemu: bt device isn't always hanging off /

  Just use the normal for_each_compatible instead.

  Otherwise in the qemu model as executed by op-test,
  we wouldn't go down the astbmc_init() path, thus not having flash.
- devicetree: Add p9-simics.dts

  Add a p9-based devicetree that's suitable for use with Simics.
- devicetree: Move power9-phb4.dts

  Clean up the formatting of power9-phb4.dts and move it to
  external/devicetree/p9.dts. This sets us up to include it as the basis
  for other trees.
- devicetree: Add nx node to power9-phb4.dts

  A (non-qemu) p9 without an nx node will assert in p9_darn_init(): ::

      dt_for_each_compatible(dt_root, nx, "ibm,power9-nx")
              break;
      if (!nx) {
              if (!dt_node_is_compatible(dt_root, "qemu,powernv"))
                    assert(nx);
              return;
      }

  Since NX is this essential, add it to the device tree.
- devicetree: Fix typo in power9-phb4.dts

  Change "impi" to "ipmi".
- devicetree: Fix syntax error in power9-phb4.dts

  Remove the extra space causing this: ::

      Error: power9-phb4.dts:156.15-16 syntax error
      FATAL ERROR: Unable to parse input tree
- core/init: enable machine check on secondaries

  Secondary CPUs currently run with MSR[ME]=0 during boot, whih means
  if they take a machine check, the system will checkstop.

  Enable ME where possible and allow them to print registers.

Utilities
---------
- pflash: Don't try update RO ToC

  In the future it's likely the ToC will be marked as read-only. Don't
  error out by assuming its writable.
- pflash: Support encoding/decoding ECC'd partitions

  With the new --ecc option, pflash can add/remove ECC when
  reading/writing flash partitions protected by ECC.

  This is *not* flawless with current PNORs out in the wild though, as
  they do not typically fill the whole partition with valid ECC data, so
  you have to know how big the valid ECC'd data is and specify the size
  manually. Note that for some partitions this is pratically impossible
  without knowing the details of the content of the partition.

  A future patch is likely to introduce an option to "stop reading data
  when ECC starts failing and assume everything is okay rather than error
  out" to support reading the "valid" data from existing PNOR images.

