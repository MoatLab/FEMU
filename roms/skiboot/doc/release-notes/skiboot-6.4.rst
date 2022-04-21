.. _skiboot-6.4:

skiboot-6.4
===========

skiboot v6.4 was released on Tuesday July 16th 2019. It is the first
release of skiboot 6.4, which becomes the new stable release
of skiboot following the 6.3 release, first released May 3rd 2019.

Skiboot 6.4 will mark the basis for op-build v2.4.

skiboot v6.4 contains all bug fixes as of :ref:`skiboot-6.0.20`,
and :ref:`skiboot-6.3.2` (the currently maintained stable releases).

For how the skiboot stable releases work, see :ref:`stable-rules` for details.

Over skiboot 6.3, we have the following changes:

.. _skiboot-6.4-new-features:

New features
------------

Since skiboot v6.4-rc1:

- npu2-opencapi: Add opencapi support on ZZ

  This patch adds opencapi support on ZZ. It hard-codes the required
  device tree entries for the NPU and links. The alternative was to use
  HDAT, but it somehow proved too painful to do.

  The new device tree entries activate the npu2 init code on ZZ. On
  systems with no opencapi adapters, it should go unnoticed, as presence
  detection will skip link training.

Since skiboot v6.3:

- platforms/nicole: Add new platform

  The platform is a new platform from YADRO, it's a storage controller for
  TATLIN server. It's Based on IBM Romulus reference design (POWER9).

- platform/zz: Add new platform type

  We have new platform type under ZZ. Lets add them. With this fix
- nvram: Flag dangerous NVRAM options

  Most nvram options used by skiboot are just for debug or testing for
  regressions. They should never be used long term.

  We've hit a number of issues in testing and the field where nvram
  options have been set "temporarily" but haven't been properly cleared
  after, resulting in crashes or real bugs being masked.

  This patch marks most nvram options used by skiboot as dangerous and
  prints a chicken to remind users of the problem.

- hw/phb3: Add verbose EEH output

  Add support for the pci-eeh-verbose NVRAM flag on PHB3. We've had this
  on PHB4 since forever and it has proven very useful when debugging EEH
  issues. When testing changes to the Linux kernel's EEH implementation
  it's fairly common for the kernel to crash before printing the EEH log
  so it's helpful to have it in the OPAL log where it can be dumped from
  XMON.

  Note that unlike PHB4 we do not enable verbose mode by default. The
  nvram option must be used to explicitly enable it.

- Experimental support for building without FSP code

  Now, with CONFIG_FSP=0/1 we have:

  - 1.6M/1.4M skiboot.lid
  - 323K/375K skiboot.lid.xz

- doc: travis-ci deploy docs!

  Documentation is now automatically deployed if you configure Travis CI
  appropriately (we have done this for the open-power branch of skiboot)

- Big OPAL API Documentation improvement

  A lot more OPAL API calls are now (at least somewhat) documented.
- opal/hmi: Report NPU2 checkstop reason

  The NPU2 is currently not passing any information to linux to explain
  the cause of an HMI. NPU2 has three Fault Isolation Registers and over
  30 of those FIR bits are configured to raise an HMI by default. We
  won't be able to fit all possible state in the 32-bit xstop_reason
  field of the HMI event, but we can still try to encode up to 4 HMI
  reasons.
- opal-msg: Enhance opal-get-msg API

  Linux uses :ref:`OPAL_GET_MSG` API to get OPAL messages. This interface
  supports upto 8 params (64 bytes). We have a requirement to send bigger data to
  Linux. This patch enhances OPAL to send bigger data to Linux.

  - Linux will use "opal-msg-size" device tree property to allocate memory for
    OPAL messages (previous patch increased "opal-msg-size" to 64K).
  - Replaced `reserved` field in "struct opal_msg" with `size`. So that Linux
    side opal_get_msg user can detect actual data size.
  - If buffer size < actual message size, then opal_get_msg will copy partial
    data and return OPAL_PARTIAL to Linux.
  - Add new variable "extended" to "opal_msg_entry" structure to keep track
    of messages that has more than 64byte data. We will allocate separate
    memory for these messages and once kernel consumes message we will
    release that memory.
- core/opal: Increase opal-msg-size size

  Kernel will use `opal-msg-size` property to allocate memory for opal_msg.
  We want to send bigger data from OPAL to kernel. Hence increase
  opal-msg-size to 64K.
- hw/npu2-opencapi: Add initial support for allocating OpenCAPI LPC memory

  Lowest Point of Coherency (LPC) memory allows the host to access memory on
  an OpenCAPI device.

  Define 2 OPAL calls, :ref:`OPAL_NPU_MEM_ALLOC` and :ref:`OPAL_NPU_MEM_RELEASE`, for
  assigning and clearing the memory BAR. (We try to avoid using the term
  "LPC" to avoid confusion with Low Pin Count.)

  At present, we use a fixed location in the address space, which means we
  are restricted to a single range of 4TB, on a single OpenCAPI device per
  chip. In future, we'll use some chip ID extension magic to give us more
  space, and some sort of allocator to assign ranges to more than one device.
- core/fast-reboot: Add im-feeling-lucky option

  Fast reboot gets disabled for a number of reasons e.g. the availability
  of nvlink. However this doesn't actually affect the ability to perform fast
  reboot if no nvlink device is actually present.

  Add a nvram option for fast-reset where if it's set to
  "im-feeling-lucky" then perform the fast-reboot irrespective of if it's
  previously been disabled.

- platforms/astbmc: Check for SBE validation step

  On some POWER8 astbmc systems an update to the SBE requires pausing at
  runtime to ensure integrity of the SBE. If this is required the BMC will
  set a chassis boot option IPMI flag using the OEM parameter 0x62. If
  Skiboot sees this flag is set it waits until the SBE update is complete
  and the flag is cleared.

  Unfortunately the mystery operation that validates the SBE also leaves
  it in a bad state and unable to be used for timer operations. To
  workaround this the flag is checked as soon as possible (ie. when IPMI
  and the console are set up), and once complete the system is rebooted.
- Add P9 DIO interrupt support

  On P9 there are GPIO port 0, 1, 2 for GPIO interrupt, and DIO interrupt
  is used to handle the interrupts.

  Add support to the DIO interrupts:

  1. Add dio_interrupt_register(chip, port, callback) to register the
     interrupt
  2. Add dio_interrupt_deregister(chip, port, callback) to deregister;
  3. When interrupt on the port occurs, callback is invoked, and the
     interrupt status is cleared.


Removed features
----------------

Since skiboot v6.3:

- pci/iov: Remove skiboot VF tracking

  This feature was added a few years ago in response to a request to make
  the MaxPayloadSize (MPS) field of a Virtual Function match the MPS of the
  Physical Function that hosts it.

  The SR-IOV specification states the the MPS field of the VF is "ResvP".
  This indicates the VF will use whatever MPS is configured on the PF and
  that the field should be treated as a reserved field in the config space
  of the VF. In other words, a SR-IOV spec compliant VF should always return
  zero in the MPS field.  Adding hacks in OPAL to make it non-zero is...
  misguided at best.

  Additionally, there is a bug in the way pci_device structures are handled
  by VFs that results in a crash on fast-reboot that occurs if VFs are
  enabled and then disabled prior to rebooting. This patch fixes the bug by
  removing the code entirely. This patch has no impact on SR-IOV support on
  the host operating system.
- Remove POWER7 and POWER7+ support

  It's been a good long while since either OPAL POWER7 user touched a
  machine, and even longer since they'd have been okay using an old
  version rather than tracking master.

  There's also been no testing of OPAL on POWER7 systems for an awfully
  long time, so it's pretty safe to assume that it's very much bitrotted.

  It also saves a whole 14kb of xz compressed payload space.
- Remove remnants of :ref:`OPAL_PCI_GET_PHB_DIAG_DATA`

  Never present in a public OPAL release, and only kernels prior to 3.11
  would ever attempt to call it.
- Remove unused :ref:`OPAL_GET_XIVE_SOURCE`

  While this call was technically implemented by skiboot, no code has ever called
  it, and it was only ever implemented for the p7ioc-phb back-end (i.e. POWER7).
  Since this call was unused in Linux, and that  POWER7 with OPAL was only ever
  available internally, so it should be safe to remove the call.
- Remove unused :ref:`OPAL_PCI_GET_XIVE_REISSUE` and :ref:`OPAL_PCI_SET_XIVE_REISSUE`

  These seem to be remnants of one of the OPAL incarnations prior to
  OPALv3. These calls have never been implemented in skiboot, and never
  used by an upstream kernel (nor a PowerKVM kernel).

  It's rather safe to just document them as never existing.
- Remove never implemented :ref:`OPAL_PCI_SET_PHB_TABLE_MEMORY` and document why

  Not ever used by upstream linux or PowerKVM tree. Never implemented in
  skiboot (not even in ancient internal only tree).

  So, it's incredibly safe to remove.
- Remove unused :ref:`OPAL_PCI_EEH_FREEZE_STATUS2`

  This call was introduced all the way back at the end of 2012, before
  OPAL was public. The #define for the OPAL call was introduced to the
  Linux kernel in June 2013, and the call was never used in any kernel
  tree ever (as far as we can find).

  Thus, it's quite safe to remove this completely unused and completely
  untested OPAL call.
- Document the long removed :ref:`OPAL_REGISTER_OPAL_EXCEPTION_HANDLER` call

  I'm pretty sure this was removed in one of our first ever service packs.

  Fixes: https://github.com/open-power/skiboot/issues/98
- Remove last remnants of :ref:`OPAL_PCI_SET_PHB_TCE_MEMORY` and :ref:`OPAL_PCI_SET_HUB_TCE_MEMORY`

  Since we have not supported p5ioc systems since skiboot 5.2, it's pretty
  safe to just wholesale remove these OPAL calls now.
- Remove remnants of :ref:`OPAL_PCI_SET_PHB_TCE_MEMORY`

  There's no reason we need remnants hanging around that aren't used, so
  remove them and save a handful of bytes at runtime.

  Simultaneously, document the OPAL call removal.


Secure and Trusted Boot
-----------------------

Since skiboot v6.3:

- trustedboot: Change PCR and event_type for the skiboot events

  The existing skiboot events are being logged as EV_ACTION, however, the
  TCG PC Client spec says that EV_ACTION events should have one of the
  pre-defined strings in the event field recorded in the event log. For
  instance:

  - "Calling Ready to Boot",
  - "Entering ROM Based Setup",
  - "User Password Entered", and
  - "Start Option ROM Scan.

  None of the EV_ACTION pre-defined strings are applicable to the existing
  skiboot events. Based on recent discussions with other POWER teams, this
  patch proposes a convention on what PCR and event types should be used
  for skiboot events. This also changes the skiboot source code to follow
  the convention.

  The TCG PC Client spec defines several event types, other than
  EV_ACTION. However, many of them are specific to UEFI events and some
  others are related to platform or CRTM events, which is more applicable
  to hostboot events.

  Currently, most of the hostboot events are extended to PCR[0,1] and
  logged as either EV_PLATFORM_CONFIG_FLAGS, EV_S_CRTM_CONTENTS or
  EV_POST_CODE. The "Node Id" and "PAYLOAD" events, though, are extended
  to PCR[4,5,6] and logged as EV_COMPACT_HASH.

  For the lack of an event type that fits the specific purpose,
  EV_COMPACT_HASH seems to be the most adequate one due to its
  flexibility. According to the TCG PC Client spec:

  - May be used for any PCR except 0, 1, 2 and 3.
  - The event field may be informative or may be hashed to generate the
    digest field, depending on the component recording the event.

  Additionally, the PCR[4,5] seem to be the most adequate PCRs. They would
  be used for skiboot and some skiroot events. According to the TCG PC
  Client, PCR[4] is intended to represent the entity that manages the
  transition between the pre-OS and OS-present state of the platform.
  PCR[4], along with PCR[5], identifies the initial OS loader.

  In summary, for skiboot events:

  - Events that represents data should be extended to PCR 4.
  - Events that represents config should be extended to PCR 5.
  - For the lack of an event type that fits the specific purpose,
    both data and config events should be logged as EV_COMPACT_HASH.

Sensors
-------

Since skiboot v6.3:

- occ-sensors: Check if OCC is reset while reading inband sensors

  OCC may not be able to mark the sensor buffer as invalid while going
  down RESET. If OCC never comes back we will continue to read the stale
  sensor data. So verify if OCC is reset while reading the sensor values
  and propagate the appropriate error.

IPMI
----

Since skiboot v6.3:

- ipmi: ensure forward progress on ipmi_queue_msg_sync()

  BT responses are handled using a timer doing the polling. To hope to
  get an answer to an IPMI synchronous message, the timer needs to run.

  We can't just check all timers though as there may be a timer that
  wants a lock that's held by a code path calling ipmi_queue_msg_sync(),
  and if we did enforce that as a requirement, it's a pretty subtle
  API that is asking to be broken.

  So, if we just run a poll function to crank anything that the IPMI
  backend needs, then we should be fine.

  This issue shows up very quickly under QEMU when loading the first
  flash resource with the IPMI HIOMAP backend.

NPU2
----

Since skiboot v6.4-rc1:

- witherspoon: Add nvlink peers in finalise_dt()

  This information is consumed by Linux so it needs to be in the DT. Move
  it to finalise_dt().

Since skiboot v6.3:

- npu2: Increase timeout for L2/L3 cache purging

  On NVLink2 bridge reset, we purge all L2/L3 caches in the system.
  This is an asynchronous operation, we have a 2ms timeout here. There are
  reports that this is not enough and "PURGE L3 on core xxx timed out"
  messages appear (for the reference: on the test setup this takes
  280us..780us).

  This defines the timeout as a macro and changes this from 2ms to 20ms.

  This adds a tracepoint to tell how long it took to purge all the caches.
- npu2: Purge cache when resetting a GPU

  After putting all a GPU's links in reset, do a cache purge in case we
  have CPU cache lines belonging to the now-unaccessible GPU memory.
- npu2-opencapi: Mask 2 XSL errors

  Commit f8dfd699f584 ("hw/npu2: Setup an error interrupt on some
  opencapi FIRs") converted some FIR bits default action from system
  checkstop to raising an error interrupt. For 2 XSL error events that
  can be triggered by a misbehaving AFU, the error interrupt is raised
  twice, once for each link (the XSL logic in the NPU is shared between
  2 links). So a badly behaving AFU could impact another, unsuspecting
  opencapi adapter.

  It doesn't look good and it turns out we can do better. We can mask
  those 2 XSL errors. The error will also be picked up by the OTL logic,
  which is per link. So we'll still get an error interrupt, but only on
  the relevant link, and the other opencapi adapter can stay functional.
- npu2: Clear fence state for a brick being reset

  Resetting a GPU before resetting an NVLink leads to occasional HMIs
  which fence some bricks and prevent the "reset_ntl" procedure from
  succeeding at the "reset_ntl_release" step - the host system requires
  reboot; there may be other cases like this as well.

  This adds clearing of the fence bit in NPU.MISC.FENCE_STATE for
  the NVLink which we are about to reset.
- npu2: Fix clearing the FIR bits

  FIR registers are SCOM-only so they cannot be accesses with the indirect
  write, and yet we use SCOM-based addresses for these; fix this.

- npu2: Reset NVLinks when resetting a GPU

  Resetting a V100 GPU brings its NVLinks down and if an NPU tries using
  those, an HMI occurs. We were lucky not to observe this as the bare metal
  does not normally reset a GPU and when passed through, GPUs are usually
  before NPUs in QEMU command line or Libvirt XML and because of that NPUs
  are naturally reset first. However simple change of the device order
  brings HMIs.

  This defines a bus control filter for a PCI slot with a GPU with NVLinks
  so when the host system issues secondary bus reset to the slot, it resets
  associated NVLinks.
- npu2: Reset PID wildcard and refcounter when mapped to LPID

  Since 105d80f85b "npu2: Use unfiltered mode in XTS tables" we do not
  register every PID in the XTS table so the table has one entry per LPID.
  Then we added a reference counter to keep track of the entry use when
  switching GPU between the host and guest systems (the "Fixes:" tag below).

  The POWERNV platform setup creates such entries and references them
  at the boot time when initializing IOMMUs and only removes it when
  a GPU is passed through to a guest. This creates a problem as POWERNV
  boots via kexec and no defererencing happens; the XTS table state remains
  undefined. So when the host kernel boots, skiboot thinks there are valid
  XTS entries and does not update the XTS table which breaks ATS.

  This adds the reference counter and the XTS entry reset when a GPU is
  assigned to LPID and we cannot rely on the kernel to clean that up.

PHB4
----

Since skiboot v6.3:

- hw/phb4: Make phb4_training_trace() more general

  phb4_training_trace() is used to monitor the Link Training Status
  State Machine (LTSSM) of the PHB's data link layer. Currently it is only
  used to observe the LTSSM while bringing up the link, but sometimes it's
  useful to see what's occurring in other situations (e.g. link disable, or
  secondary bus reset). This patch renames it to phb4_link_trace() and
  allows the target LTSSM state and a flexible timeout to help in these
  situations.
- hw/phb4: Make pci-tracing print at PR_NOTICE

  When pci-tracing is enabled we print each trace status message and the
  final trace status at PR_ERROR. The final status messages are similar to
  those printed when we fail to train in the non-pci-tracing path and this
  has resulted in spurious op-test failures.

  This patch reduces the log-level of the tracing message to PR_NOTICE so
  they're not accidently interpreted as actual error messages. PR_NOTICE
  messages are still printed to the console during boot.
- hw/phb4: Use read/write_reg in assert_perst

  While the PHB is fenced we can't use the MMIO interface to access PHB
  registers. While processing a complete reset we inject a PHB fence to
  isolate the PHB from the rest of the system because the PHB won't
  respond to MMIOs from the rest of the system while being reset.

  We assert PERST after the fence has been erected which requires us to
  use the XSCOM indirect interface to access the PHB registers rather than
  the MMIO interface. Previously we did that when asserting PERST in the
  CRESET path. However in b8b4c79d4419 ("hw/phb4: Factor out PERST
  control"). This was re-written to use the raw in_be64() accessor. This
  means that CRESET would not be asserted in the reset path. On some
  Mellanox cards this would prevent them from re-loading their firmware
  when the system was fast-reset.

  This patch fixes the problem by replacing the raw {in|out}_be64()
  accessors with the phb4_{read|write}_reg() functions.

- hw/phb4: Assert Link Disable bit after ETU init

  The cursed RAID card in ozrom1 has a bug where it ignores PERST being
  asserted. The PCIe Base spec is a little vague about what happens
  while PERST is asserted, but it does clearly specify that when
  PERST is de-asserted the Link Training and Status State Machine
  (LTSSM) of a device should return to the initial state (Detect)
  defined in the spec and the link training process should restart.

  This bug was worked around in 9078f8268922 ("phb4: Delay training till
  after PERST is deasserted") by setting the link disable bit at the
  start of the FRESET process and clearing it after PERST was
  de-asserted. Although this fixed the bug, the patch offered no
  explaination of why the fix worked.

  In b8b4c79d4419 ("hw/phb4: Factor out PERST control") the link disable
  workaround was moved into phb4_assert_perst(). This is called
  always in the CRESET case, but a following patch resulted in
  assert_perst() not being called if phb4_freset() was entered following a
  CRESET since p->skip_perst was set in the CRESET handler. This is bad
  since a side-effect of the CRESET is that the Link Disable bit is
  cleared.

  This, combined with the RAID card ignoring PERST results in the PCIe
  link being trained by the PHB while we're waiting out the 100ms
  ETU reset time. If we hack skiboot to print a DLP trace after returning
  from phb4_hw_init() we get: ::

     PHB#0001[0:1]: Initialization complete
     PHB#0001[0:1]: TRACE:0x0000102101000000  0ms presence GEN1:x16:polling
     PHB#0001[0:1]: TRACE:0x0000001101000000 23ms          GEN1:x16:detect
     PHB#0001[0:1]: TRACE:0x0000102101000000 23ms presence GEN1:x16:polling
     PHB#0001[0:1]: TRACE:0x0000183101000000 29ms training GEN1:x16:config
     PHB#0001[0:1]: TRACE:0x00001c5881000000 30ms training GEN1:x08:recovery
     PHB#0001[0:1]: TRACE:0x00001c5883000000 30ms training GEN3:x08:recovery
     PHB#0001[0:1]: TRACE:0x0000144883000000 33ms presence GEN3:x08:L0
     PHB#0001[0:1]: TRACE:0x0000154883000000 33ms trained  GEN3:x08:L0
     PHB#0001[0:1]: CRESET: wait_time = 100
     PHB#0001[0:1]: FRESET: Starts
     PHB#0001[0:1]: FRESET: Prepare for link down
     PHB#0001[0:1]: FRESET: Assert skipped
     PHB#0001[0:1]: FRESET: Deassert
     PHB#0001[0:1]: TRACE:0x0000154883000000  0ms trained  GEN3:x08:L0
     PHB#0001[0:1]: TRACE: Reached target state
     PHB#0001[0:1]: LINK: Start polling
     PHB#0001[0:1]: LINK: Electrical link detected
     PHB#0001[0:1]: LINK: Link is up
     PHB#0001[0:1]: LINK: Went down waiting for stabilty
     PHB#0001[0:1]: LINK: DLP train control: 0x0000105101000000
     PHB#0001[0:1]: CRESET: Starts

  What has happened here is that the link is trained to 8x Gen3 33ms after
  we return from phb4_init_hw(), and before we've waitined to 100ms
  that we normally wait after re-initialising the ETU. When we "deassert"
  PERST later on in the FRESET handler the link in L0 (normal) state. At
  this point we try to read from the Vendor/Device ID register to verify
  that the link is stable and immediately get a PHB fence due to a PCIe
  Completion Timeout. Skiboot attempts to recover by doing another CRESET,
  but this will encounter the same issue.

  This patch fixes the problem by setting the Link Disable bit (by calling
  phb4_assert_perst()) immediately after we return from phb4_init_hw().
  This prevents the link from being trained while PERST is asserted which
  seems to avoid the Completion Timeout. With the patch applied we get: ::

     PHB#0001[0:1]: Initialization complete
     PHB#0001[0:1]: TRACE:0x0000102101000000  0ms presence GEN1:x16:polling
     PHB#0001[0:1]: TRACE:0x0000001101000000 23ms          GEN1:x16:detect
     PHB#0001[0:1]: TRACE:0x0000102101000000 23ms presence GEN1:x16:polling
     PHB#0001[0:1]: TRACE:0x0000909101000000 29ms presence GEN1:x16:disabled
     PHB#0001[0:1]: CRESET: wait_time = 100
     PHB#0001[0:1]: FRESET: Starts
     PHB#0001[0:1]: FRESET: Prepare for link down
     PHB#0001[0:1]: FRESET: Assert skipped
     PHB#0001[0:1]: FRESET: Deassert
     PHB#0001[0:1]: TRACE:0x0000001101000000  0ms          GEN1:x16:detect
     PHB#0001[0:1]: TRACE:0x0000102101000000  0ms presence GEN1:x16:polling
     PHB#0001[0:1]: TRACE:0x0000001101000000 24ms          GEN1:x16:detect
     PHB#0001[0:1]: TRACE:0x0000102101000000 36ms presence GEN1:x16:polling
     PHB#0001[0:1]: TRACE:0x0000183101000000 97ms training GEN1:x16:config
     PHB#0001[0:1]: TRACE:0x00001c5881000000 97ms training GEN1:x08:recovery
     PHB#0001[0:1]: TRACE:0x00001c5883000000 97ms training GEN3:x08:recovery
     PHB#0001[0:1]: TRACE:0x0000144883000000 99ms presence GEN3:x08:L0
     PHB#0001[0:1]: TRACE: Reached target state
     PHB#0001[0:1]: LINK: Start polling
     PHB#0001[0:1]: LINK: Electrical link detected
     PHB#0001[0:1]: LINK: Link is up
     PHB#0001[0:1]: LINK: Link is stable
     PHB#0001[0:1]: LINK: Card [9005:028c] Optimal Retry:disabled
     PHB#0001[0:1]: LINK: Speed Train:GEN3 PHB:GEN4 DEV:GEN3
     PHB#0001[0:1]: LINK: Width Train:x08 PHB:x08 DEV:x08
     PHB#0001[0:1]: LINK: RX Errors Now:0 Max:8 Lane:0x0000


Simulators
----------

Since skiboot v6.3:

- external/mambo: Bump default POWER9 to Nimbus DD2.3
- external/mambo: fix tcl startup code for mambo bogus net (repost)

  This fixes a couple issues with external/mambo/skiboot.tcl so I can use the
  mambo bogus net.

  * newer distros (ubuntu 18.04) allow tap device to have a user specified
    name instead of just tapN so we need to pass in a name not a number.
  * need some kind of default for net_mac, and need the mconfig for it
    to be set from an env var.
- skiboot.tcl: Add option to wait for GDB server connection

  Add an environment variable which makes Mambo wait for a connection
  from gdb prior to starting simulation.
- mambo: Integrate addr2line into backtrace command

  Gives nice output like this: ::

       systemsim % bt
       pc:                             0xC0000000002BF3D4      _savegpr0_28+0x0
       lr:                             0xC00000000004E0F4      opal_call+0x10
       stack:0x000000000041FAE0        0xC00000000004F054      opal_check_token+0x20
       stack:0x000000000041FB50        0xC0000000000500CC      __opal_flush_console+0x88
       stack:0x000000000041FBD0        0xC000000000050BF8      opal_flush_console+0x24
       stack:0x000000000041FC00        0xC0000000001F9510      udbg_opal_putc+0x88
       stack:0x000000000041FC40        0xC000000000020E78      udbg_write+0x7c
       stack:0x000000000041FC80        0xC0000000000B1C44      console_unlock+0x47c
       stack:0x000000000041FD80        0xC0000000000B2424      register_console+0x320
       stack:0x000000000041FE10        0xC0000000003A5328      register_early_udbg_console+0x98
       stack:0x000000000041FE80        0xC0000000003A4F14      setup_arch+0x68
       stack:0x000000000041FEF0        0xC0000000003A0880      start_kernel+0x74
       stack:0x000000000041FF90        0xC00000000000AC60      start_here_common+0x1c

- mambo: Add addr2func for symbol resolution

  If you supply a VMLINUX_MAP/SKIBOOT_MAP/USER_MAP addr2func can guess
  at your symbol name. i.e. ::

      systemsim % p pc
      0xC0000000002A68F8
      systemsim % addr2func [p pc]
      fdt_offset_ptr+0x78

- lpc-port80h: Don't write port 80h when running under Simics

  Simics doesn't model LPC port 80h. Writing to it terminates the
  simulation due to an invalid LPC memory access. This patch adds a
  check to ensure port 80h isn't accessed if we are running under
  Simics.
- device-tree: speed up fdt building on slow simulators

  Trade size for speed and avoid de-duplicating strings in the fdt.
  This costs about 2kB in fdt size, and saves about 8 million instructions
  (almost half of all instructions) booting skiboot in mambo.
- fast-reboot:: skip read-only memory checksum for slow simulators

  Skip the fast reboot checksum, which costs about 4 million cycles
  booting skiboot in mambo.
- nx: remove check on the "qemu, powernv" property

  commit 95f7b3b9698b ("nx: Don't abort on missing NX when using a QEMU
  machine") introduced a check on the property "qemu,powernv" to skip NX
  initialization when running under a QEMU machine.

  The QEMU platforms now expose a QUIRK_NO_RNG in the chip. Testing the
  "qemu,powernv" property is not necessary anymore.
- plat/qemu: add a POWER8 and POWER9 platform

  These new QEMU platforms have characteristics closer to real OpenPOWER
  systems that we use today and define a different BMC depending on the
  CPU type. New platform properties are introduced for each,
  "qemu,powernv8", "qemu,powernv9" and these should be compatible with
  existing QEMUs which only expose the "qemu,powernv" property
- libc/string: speed up common string functions

  Use compiler builtins for the string functions, and compile the
  libc/string/ directory with -O2.

  This reduces instructions booting skiboot in mambo by 2.9 million in
  slow-sim mode, or 3.8 in normal mode, for less than 1kB image size
  increase.

  This can result in the compiler warning more cases of string function
  problems.
- external/mambo: Add an option to exit Mambo when the system is shutdown

  Automatically exiting can be convenient for scripting. Will also exit
  due to a HW crash (eg. unhandled exception).

VESNIN platform
---------------

Since skiboot v6.3:

- platforms/vesnin: PCI inventory via IPMI OEM

  Replace raw protocol with OEM message supported by OpenBMC's IPMI
  plugins.

  BMC-side implementation (IPMI plug-in):
  https://github.com/YADRO-KNS/phosphor-pci-inventory

Utilities
---------

Since skiboot v6.3:

- opal-gard: Account for ECC size when clearing partition

  When 'opal-gard clear all' is run, it works by erasing the GUARD then
  using blockevel_smart_write() to write nothing to the partition. This
  second write call is needed because we rely on libflash to set the ECC
  bits appropriately when the partition contained ECCed data.

  The API for this is a little odd with the caller specifying how much
  actual data to write, and libflash writing size + size/8 bytes
  since there is one additional ECC byte for every eight bytes of data.

  We currently do not account for the extra space consumed by the ECC data
  in reset_partition() which is used to handle the 'clear all' command.
  Which results in the paritition following the GUARD partition being
  partially overwritten when the command is used. This patch fixes the
  problem by reducing the length we would normally write by the number
  of ECC bytes required.


Build and debugging
-------------------

Since skiboot v6.3:

- Disable -Waddress-of-packed-member for GCC9

  We throw a bunch of errors in errorlog code otherwise, which we should
  fix, but we don't *have* to yet.

- Fix a lot of sparse warnings
- With new GCC comes larger GCOV binaries

  So we need to change our heap size to make more room for data/bss
  without having to change where the console is or have more fun moving
  things about.
- Intentionally discard fini_array sections

  Produced in a SKIBOOT_GCOV=1 build, and never called by skiboot.
- external/trace: Add follow option to dump_trace

  When monitoring traces, an option like the tail command's '-f' (follow)
  is very useful. This option continues to append to the output as more
  data arrives. Add an '-f' option to allow dump_trace to operate
  similarly.

  Tail also provides a '-s' (sleep time) option that
  accompanies '-f'.  This controls how often new input will be polled. Add
  a '-s' option that will make dump_trace sleep for N milliseconds before
  checking for new input.
- external/trace: Add support for dumping multiple buffers

  dump_trace only can dump one trace buffer at a time. It would be handy
  to be able to dump multiple buffers and to see the entries from these
  buffers displayed in correct timestamp order. Each trace buffer is
  already sorted by timestamp so use a heap to implement an efficient
  k-way merge. Use the CCAN heap to implement this sort. However the CCAN
  heap does not have a 'heap_replace' operation. We need to 'heap_pop'
  then 'heap_push' to replace the root which means rebalancing twice
  instead of once.
- external/trace: mmap trace buffers in dump_trace

  The current lseek/read approach used in dump_trace does not correctly
  handle certain aspects of the buffers. It does not use the start and end
  position that is part of the buffer so it will not begin from the
  correct location. It does not move back to the beginning of the trace
  buffer file as the buffer wraps around. It also does not handle the
  overflow case of the writer overwriting when the reader is up to.

  Mmap the trace buffer file so that the existing reading functions in
  extra/trace.c can be used. These functions already handle the cases of
  wrapping and overflow.  This reduces code duplication and uses functions
  that are already unit tested. However this requires a kernel where the
  trace buffer sysfs nodes are able to be mmaped (see
  https://patchwork.ozlabs.org/patch/1056786/)
- core/trace: Export trace buffers to sysfs

  Every property in the device-tree under /ibm,opal/firmware/exports has a
  sysfs node created in /firmware/opal/exports. Add properties with the
  physical address and size for each trace buffer so they are exported.
- core/trace: Add pir number to debug_descriptor

  The names given to the trace buffers when exported to sysfs should show
  what cpu they are associated with to make it easier to understand there
  output.  The debug_descriptor currently stores the address and length of
  each trace buffer and this is used for adding properties to the device
  tree. Extend debug_descriptor to include a cpu associated with each
  trace. This will be used for creating properties in the device-tree
  under /ibm,opal/firmware/exports/.
- core/trace: Change trace buffer size

  We want to be able to mmap the trace buffers to be used by the
  dump_trace tool. As mmaping is done in terms of pages it makes sense
  that the size of the trace buffers should be page aligned.  This is
  slightly complicated by the space taken up by the header at the
  beginning of the trace and the room left for an extra trace entry at the
  end of the buffer. Change the size of the buffer itself so that the
  entire trace buffer size will be page aligned.
- core/trace: Change buffer alignment from 4K to 64K

  We want to be able to mmap the trace buffers to be used by the
  dump_trace tool. This means that the trace bufferes must be page
  aligned.  Currently they are aligned to 4K. Most power systems have a
  64K page size. On systems with a 4K page size, 64K aligned will still be
  page aligned.  Change the allocation of the trace buffers to be 64K
  aligned.

  The trace_info struct that contains the trace buffer is actually what is
  allocated aligned memory. This means the trace buffer itself is not
  actually aligned and this is the address that is currently exposed
  through sysfs.  To get around this change the address that is exposed to
  sysfs to be the trace_info struct. This means the lock in trace_info is
  now visible too.
- external/trace: Use correct width integer byte swapping

  The trace_repeat struct uses be16 for storing the number of repeats.
  Currently be32_to_cpu conversion is used to display this member. This
  produces an incorrect value. Use be16_to_cpu instead.
- core/trace: Put boot_tracebuf in correct location.

  A position for the boot_tracebuf is allocated in skiboot.lds.S.
  However, without a __section attribute the boot trace buffer is not
  placed in the correct location, meaning that it also will not be
  correctly aligned.  Add the __section attribute to ensure it will be
  placed in its allocated position.
- core/lock: Add debug options to store backtrace of where lock was taken

  Contrary to popular belief, skiboot developers are imperfect and
  occasionally write locking bugs. When we exit skiboot, we check if we're
  still holding any locks, and if so, we print an error with a list of the
  locks currently held and the locations where they were taken.

  However, this only tells us the location where lock() was called, which may
  not be enough to work out what's going on. To give us more to go on with,
  we can store backtrace data in the lock and print that out when we
  unexpectedly still hold locks.

  Because the backtrace data is rather big, we only enable this if
  DEBUG_LOCKS_BACKTRACE is defined, which in turn is switched on when
  DEBUG=1.

  (We disable DEBUG_LOCKS_BACKTRACE in some of the memory allocation tests
  because the locks used by the memory allocator take up too much room in the
  fake skiboot heap.)
- libfdt: upgrade to upstream dtc.git 243176c

  Upgrade libfdt/ to github.com/dgibson/dtc.git 243176c ("Fix bogus
  error on rebuild")

  This copies dtc/libfdt/ to skiboot/libfdt/, with the only change in
  that directory being the addition of README.skiboot and Makefile.inc.

  This adds about 14kB text, 2.5kB compressed xz. This could be reduced
  or mostly eliminated by cutting out fdt version checks and unused
  code, but tracking upstream is a bigger benefit at the moment.

  This loses commits:

  - 14ed2b842f61 ("libfdt: add basic sanity check to fdt_open_into")
  - bc7bb3d12bc1 ("sparse: fix declaration of fdt_strerror")

  As well as some prehistoric similar kinds of things, which is the
  punishment for us not being good downstream citizens and sending
  things upstream! Syncing to upstream will make that effort simpler
  in future.

General Fixes
-------------

Since skiboot v6.4-rc1:

- libflash: Fix broken continuations

  Some of the libflash debug messages don't print a newlines at the end of
  the line and assume that the next print will be contigious with the
  last. This isn't true in skiboot since log messages are prefixed with a
  timestamp. This results in funny looking output such as: ::

    LIBFLASH: Verifying...
    LIBFLASH:   reading page 0x01963000..0x01964000...[3.084846885,7]  same !
    LIBFLASH:   reading page 0x01964000..0x01965000...[3.086164489,7]  same !

  Fix this by moving the "same !" debug message to a new line with the
  prefix "LIBFLASH:   ..." to indicate it's a continuation of the last
  statement.

  First reported in https://github.com/open-power/skiboot/issues/51
