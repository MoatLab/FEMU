.. _skiboot-5.10-rc1:

skiboot-5.10-rc1
================

skiboot v5.10-rc1 was released on Tuesday February 6th 2018. It is the first
release candidate of skiboot 5.10, which will become the new stable release
of skiboot following the 5.9 release, first released October 31st 2017.

skiboot v5.10-rc1 contains all bug fixes as of :ref:`skiboot-5.9.8`
and :ref:`skiboot-5.4.9` (the currently maintained stable releases). There
may be more 5.9.x stable releases, it will depend on demand.

For how the skiboot stable releases work, see :ref:`stable-rules` for details.

The current plan is to cut the final 5.10 in February, with skiboot 5.10
being for all POWER8 and POWER9 platforms in op-build v1.21.
This release will be targeted to early POWER9 systems.

Over skiboot-5.9, we have the following changes:

New Features
------------
- hdata: Parse IPL FW feature settings

  Add parsing for the firmware feature flags in the HDAT. This
  indicates the settings of various parameters which are set at IPL time
  by firmware.

- opal/xstop: Use nvram option to enable/disable sw checkstop.

  Add a mechanism to enable/disable sw checkstop by looking at nvram option
  opal-sw-xstop=<enable/disable>.

  For now this patch disables the sw checkstop trigger unless explicitly
  enabled through nvram option 'opal-sw-xstop=enable'i for p9. This will allow
  an opportunity to get host kernel in panic path or xmon for unrecoverable
  HMIs or MCE, to be able to debug the issue effectively.

  To enable sw checkstop in opal issue following command: ::

    nvram -p ibm,skiboot --update-config opal-sw-xstop=enable

  **NOTE:** This is a workaround patch to disable sw checkstop by default to gain
  control in host kernel for better checkstop debugging. Once we have most of
  the checkstop issues stabilized/resolved, revisit this patch to enable sw
  checkstop by default.

  For p8 platform it will remain enabled by default unless explicitly disabled.

  To disable sw checkstop on p8 issue following command: ::

    nvram -p ibm,skiboot --update-config opal-sw-xstop=disable
- hdata: Parse SPD data

    Parse SPD data and populate device tree.

    list of properties parsing from SPD: ::

      [root@ltc-wspoon dimm@d00f]# lsprop .
      memory-id        0000000c (12)      # DIMM type
      product-version  00000032 (50)      # Module Revision Code
      device_type      "memory-dimm-ddr4"
      serial-number    15d9acb6 (366587062)
      status           "okay"
      size             00004000 (16384)
      phandle          000000bd (189)
      ibm,loc-code     "UOPWR.0000000-Node0-DIMM7"
      part-number      "36ASF2G72PZ-2G6B2   "
      reg              0000d007 (53255)
      name             "dimm"
      manufacturer-id  0000802c (32812)  # Vendor ID, we can get vendor name from this ID

    Also update documentation.
- hdata: Add memory hierarchy under xscom node

  We have memory to chip mapping but doesn't have complete memory hierarchy.
  This patch adds memory hierarchy under xscom node. This is specific to
  P9 system as these hierarchy may change between processor generation.

  It uses memory controller ID details and populates nodes like:
      xscom@<addr>/mcbist@<mcbist_id>/mcs@<mcs_id>/mca@<mca_id>/dimm@<resource_id>

  Also this patch adds few properties under dimm node.
  Finally make sure xscom nodes created before calling memory_parse().

Fast Reboot and Quiesce
^^^^^^^^^^^^^^^^^^^^^^^
We have a preliminary fast reboot implementation for POWER9 systems, which
we look to enabling by default in the next release.

The OPAL Quiesce calls are designed to improve reliability and debuggability
around reboot and error conditions. See the full API documentation for details:
:ref:`OPAL_QUIESCE`.

- fast-reboot: bare bones fast reboot implementation for POWER9

  This is an initial fast reboot implementation for p9 which has only been
  tested on the Witherspoon platform, and without the use of NPUs, NX/VAS,
  etc.

  This has worked reasonably well so far, with no failures in about 100
  reboots. It is hidden behind the traditional fast-reboot experimental
  nvram option, until more platforms and configurations are tested.
- fast-reboot: move boot CPU clean-up logically together with secondaries

  Move the boot CPU clean-up and state transition to active, logically
  together with secondaries. Don't release secondaries from fast reboot
  hold until everyone has cleaned up and transitioned to active.

  This is cosmetic, but it is helpful to run the fast reboot state machine
  the same way on all CPUs.
- fast-reboot: improve failure error messages

  Change existing failure error messages to PR_NOTICE so they get
  printed to the console, and add some new ones. It's not a more
  severe class because it falls back to IPL on failure.
- fast-reboot: quiesce opal before initiating a fast reboot

  Switch fast reboot to use quiescing rather than "wait for a while".

  If firmware can not be quiesced, then fast reboot is skipped. This
  significantly improves the robustness of fast reboot in the face of
  bugs or unexpected latencies.

  Complexity of synchronization in fast-reboot is reduced, because we
  are guaranteed to be single-threaded when quiesce succeeds, so locks
  can be removed.

  In the case that firmware can be quiesced, then it will generally
  reduce fast reboot times by nearly 200ms, because quiescing usually
  takes very little time.
- core: Add support for quiescing OPAL

  Quiescing is ensuring all host controlled CPUs (except the current
  one) are out of OPAL and prevented from entering. This can be use in
  debug and shutdown paths, particularly with system reset sequences.

  This patch adds per-CPU entry and exit tracking for OPAL calls, and
  adds logic to "hold" or "reject" at entry time, if OPAL is quiesced.

  An OPAL call is added, to expose the functionality to Linux, where it
  can be used for shutdown, kexec, and before generating sreset IPIs for
  debugging (so the debug code does not recurse into OPAL).
- dctl: p9 increase thread quiesce timeout

  We require all instructions to be completed before a thread is
  considered stopped, by the dctl interface. Long running instructions
  like cache misses and CI loads may take a significant amount of time
  to complete, and timeouts have been observed in stress testing.

  Increase the timeout significantly, to cover this. The workbook
  just says to poll, but we like to have timeouts to avoid getting
  stuck in firmware.


POWER9 power saving
^^^^^^^^^^^^^^^^^^^

There is much improved support for deeper sleep/idle (stop) states on POWER9.

- OCC: Increase max pstate check on P9 to 255

  This has changed from P8, we can now have > 127 pstates.

  This was observed on Boston during WoF bring up.
- SLW: Add idle state stop5 for DD2.0 and above

  Adding stop5 idle state with rough residency and latency numbers.
- SLW: Add p9_stop_api calls for IMC

  Add p9_stop_api for EVENT_MASK and PDBAR scoms. These scoms are lost on
  wakeup from stop11.

- SCOM restore for DARN and XIVE

  While waking up from stop11, we want NCU_DARN_BAR to have enable bit set.
  Without this stop_api call, the value restored is without enable bit set.
  We loose NCU_SPEC_BAR when the quad goes into stop11, stop_api will
  restore while waking up from stop11.

- SLW: Call p9_stop_api only if deep_states are enabled

  All init time p9_stop_api calls have been isolated to slw_late_init. If
  p9_stop_api fails, then the deep states can be excluded from device tree.

  For p9_stop_api called after device-tree for cpuidle is created ,
  has_deep_states will be used to check if this call is even required.
- Better handle errors in setting up sleep states (p9_stop_api)

  We won't put affected stop states in the device tree if the wakeup
  engine is not present or has failed.
- SCOM Restore: Increased the EQ SCOM restore limit.

  Commit increases the SCOM restore limit from 16 to 31.
- hw/dts: retry special wakeup operation if core still gated

  It has been observed that in some cases the special wakeup
  operation can "succeed" but the core is still in a gated/offline
  state.

  Check for this state after attempting to wakeup a core and retry
  the wakeup if necessary.
- core/direct-controls: add function to read core gated state
- core/direct-controls: wait for core special wkup bit cleared

  When clearing special wakeup bit on a core, wait until the
  bit is actually cleared by the hardware in the status register
  until returning success.

  This may help avoid issues with back-to-back reads where the
  special wakeup request is cleared but the firmware is still
  processing the request and the next attempt to set the bit
  reads an immediate success from the previous operation.
- p9_stop_api: PM: Added support for version control in SCOM restore entries.

  - adds version info in SCOM restore entry header
  - adds version specific details in SCOM restore entry header
  - retains old behaviour of SGPE Hcode's base version
- p9_stop_api: EQ SCOM Restore: Introduced version control in SCOM restore entry.

  - introduces version control in header of SCOM restore entry
  - ensures backward compatibility
  - introduces flexibility to handle any number of SCOM restore entry.

Secure and Trusted Boot for POWER9
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

We introduce support for Secure and Trusted Boot for POWER9 systems, with equal
functionality that we have on POWER8 systems, that is, we have the mechanisms in
place to boot to petitboot (i.e. to BOOTKERNEL).

See the :ref:`stb-overview` for full documentation of OPAL secure and trusted boot.

- allow secure boot if not enforcing it

  We check the secure boot containers no matter what, only *enforcing*
  secure boot if we're booting in secure mode. This gives us an extra
  layer of checking firmware is legit even when secure mode isn't enabled,
  as well as being really useful for testing.
- libstb/(create|print)-container: Sync with sb-signing-utils

  The sb-signing-utils project has improved upon the skeleton
  create-container tool that existed in skiboot, including
  being able to (quite easily) create *signed* images.

  This commit brings in that code (and makes it build in the
  skiboot build environment) and updates our skiboot.*.stb
  generating code to use the development keys. This means that by
  default, skiboot build process will let you build firmware that can
  do a secure boot with *development* keys.

  See :ref:`signing-firmware-code` for details on firmware signing.

  We also update print-container as well, syncing it with the
  upstream project.

  Derived from github.com:open-power/sb-signing-utils.git
  at v0.3-5-gcb111c03ad7f
  (Some discussion ongoing on the changes, another sync will come shortly)

- doc: update libstb documentation with POWER9 changes.
  See: :ref:`stb-overview`.

  POWER9 changes reflected in the libstb:

    - bumped ibm,secureboot node to v2
    - added ibm,cvc node
    - hash-algo superseded by hw-key-hash-size

- libstb/cvc: update memory-region to point to /reserved-memory

  The linux documentation, reserved-memory.txt, says that memory-region is
  a phandle that pairs to a children of /reserved-memory.

  This updates /ibm,secureboot/ibm,cvc/memory-region to point to
    /reserved-memory/secure-crypt-algo-code instead of
    /ibm,hostboot/reserved-memory/secure-crypt-algo-code.
- libstb: add support for ibm,secureboot-v2

  ibm,secureboot-v2 changes:

    - The Container Verification Code is represented by the ibm,cvc node.
    - Each ibm,cvc child describes a CVC service.
    - hash-algo is superseded by hw-key-hash-size.
- hdata/tpmrel.c: add ibm, cvc device tree node

  In P9, the Container Verification Code is stored in a hostboot reserved
  memory and the list of provided CVC services is stored in the
  TPMREL_IDATA_HASH_VERIF_OFFSETS idata array. Each CVC service has an
  offset and version.

  This adds the ibm,cvc device tree node and its documentation.
- hdata/tpmrel.c: add firmware event log info to the tpm node

  This parses the firmware event log information from the
  secureboot_tpm_info HDAT structure and add it to the tpm device tree
  node.

  There can be multiple secureboot_tpm_info entries with each entry
  corresponding to a master processor that has a tpm device, however,
  multiple tpm is not supported.
- hdata/spira: add ibm,secureboot node in P9

  In P9, skiboot builds the device tree from the HDAT. These are the
  "ibm,secureboot" node changes compared to P8:

    - The Container-Verification-Code (CVC), a.k.a. ROM code, is no longer
      stored in a secure ROM with static address. In P9, it is stored in a
      hostboot reserved memory and each service provided also has a version,
      not only an offset.
    - The hash-algo property is not provided via HDAT, instead it provides
      the hw-key-hash-size, which is indeed the information required by the
      CVC to verify containers.

  This parses the iplparams_sysparams HDAT structure and creates the
  "ibm,secureboot", which is bumped to "ibm,secureboot-v2".

  In "ibm,secureboot-v2":

    - hash-algo property is superseded by hw-key-hash-size.
    - container verification code is explicitly described by a child node.
      Added in a subsequent patch.

  See :ref:`device-tree/ibm,secureboot` for documentation.
- libstb/tpm_chip.c: define pr_fmt and fix messages logged

  This defines pr_fmt and also fix messages logged:

    - EV_SEPARATOR instead of 0xFFFFFFFF
    - when an event is measured it also prints the tpm id, event type and
      event log length

  Now we can filter the messages logged by libstb and its
  sub-modules by running: ::

    grep STB /sys/firmware/opal/msglog
- libstb/tss: update the list of event types supported

  Skiboot, precisely the tpmLogMgr, initializes the firmware event log by
  calculating its length so that a new event can be recorded without
  exceeding the log size. In order to calculate the size, it walks through
  the log until it finds a specific event type. However, if the log has
  an unknown event type, the tpmLogMgr will not be able to reach the end
  of the log.

  This updates the list of event types with all of those supported by
  hostboot. Thus, skiboot can properly calculate the event log length.
- tpm_i2c_nuvoton: add nuvoton, npct601 to the compatible property

  The linux kernel doesn't have a driver compatible with
  "nuvoton,npct650", but it does have for "nuvoton,npct601", which should
  also be compatible with npct650.

  This adds "nuvoton,npct601" to the compatible devtree property.
- libstb/trustedboot.c: import stb_final() from stb.c

  The stb_final() primary goal is to measure the event EV_SEPARATOR
  into PCR[0-7] when trusted boot is about to exit the boot services.

  This imports the stb_final() from stb.c into trustedboot.c, but making
  the following changes:

    - Rename it to trustedboot_exit_boot_services().
    - As specified in the TCG PC Client specification, EV_SEPARATOR events must
      be logged with the name 0xFFFFFF.
    - Remove the ROM driver clean-up call.
    - Don't allow code to be measured in skiboot after
      trustedboot_exit_boot_services() is called.
- libstb/cvc.c: import softrom behaviour from drivers/sw_driver.c

  Softrom is used only for testing with mambo. By setting
  compatible="ibm,secureboot-v1-softrom" in the "ibm,secureboot" node,
  firmware images can be properly measured even if the
  Container-Verification-Code (CVC) is not available. In this case, the
  mbedtls_sha512() function is used to calculate the sha512 hash of the
  firmware images.

  This imports the softrom behaviour from libstb/drivers/sw_driver.c code
  into cvc.c, but now softrom is implemented as a flag. When the flag is
  set, the wrappers for the CVC services work the same way as in
  sw_driver.c.
- libstb/trustedboot.c: import tb_measure() from stb.c

  This imports tb_measure() from stb.c, but now it calls the CVC sha512
  wrapper to calculate the sha512 hash of the firmware image provided.

  In trustedboot.c, the tb_measure() is renamed to trustedboot_measure().

  The new function, trustedboot_measure(), no longer checks if the
  container payload hash calculated at boot time matches with the hash
  found in the container header. A few reasons:

  - If the system admin wants the container header to be
    checked/validated, the secure boot jumper must be set. Otherwise,
    the container header information may not be reliable.
  - The container layout is expected to change over time. Skiboot
    would need to maintain a parser for each container layout
    change.
  - Skiboot could be checking the hash against a container version that
    is not supported by the Container-Verification-Code (CVC).

    The tb_measure() calls are updated to trustedboot_measure() in a
    subsequent patch.
- libstb/secureboot.c: import sb_verify() from stb.c

  This imports the sb_verify() function from stb.c, but now it calls the
  CVC verify wrapper in order to verify signed firmware images. The
  hw-key-hash and hw-key-hash-size initialized in secureboot.c are passed
  to the CVC verify function wrapper.

  In secureboot.c, the sb_verify() is renamed to secureboot_verify(). The
  sb_verify() calls are updated in a subsequent patch.

XIVE
----
- xive: Don't bother cleaning up disabled EQs in reset

  Additionally, warn if we find an enabled one that isn't one
  of the firmware built-in queues.
- xive: Warn on valid VPs found in abnormal cases

  If an allocated VP is left valid at xive_reset() or Linux tries
  to free a valid (enabled) VP block, print errors. The former happens
  occasionally if kdump'ing while KVM is running so keep it as a debug
  message. The latter is a programming error in Linux so use a an
  error log level.
- xive: Properly reserve built-in VPs in non-group mode

  This is not normally used but if the #define is changed to
  disable block group mode we would incorrectly clear the
  buddy completely without marking the built-in VPs reserved.
- xive: Quieten debug messages in standard builds

  This makes a bunch of messages, especially the per-CPU ones,
  only enabled in debug builds. This avoids clogging up the
  OPAL logs with XIVE related messages that have proven not
  being particularly useful for field defects.
- xive: Implement "single escalation" feature

  This adds a new VP flag to control the new DD2.0
  "single escalation" feature.

  This feature allows us to have a single escalation
  interrupt per VP instead of one per queue.

  It works by hijacking queue 7 (which is this no longer
  usable when that is enabled) and exploiting two new
  hardware bits that will:

  - Make the normal queues (0..6) escalate unconditionally
    thus ignoring the ESe bits.
  - Route the above escalations to queue 7
  - Have queue 7 silently escalate without notification

  Thus the escalation of queue 7 becomes the one escalation
  interrupt for all the other queues.
- xive: When disabling a VP, wipe all of its settings
- xive: Improve cleaning up of EQs

  Factors out the function that sets an EQ back to a clean
  state and add a cleaning pass for queue left enabled
  when freeing a block of VPs.
- xive: When disabling an EQ, wipe all of its settings

  This avoids having configuration bits left over
- xive: Define API for single-escalation VP mode

  This mode allows all queues of a VP to use the same
  escalation interrupt, at the cost of losing priority 7.

  This adds the definition and documentation of the API,
  the implementation will come next.
- xive: Fix ability to clear some EQ flags

  We could never clear "unconditional notify" and "escalate"
- xive: Update inits for DD2.0

  This updates some inits based on information from the HW
  designers. This includes enabling some new DD2.0 features
  that we don't yet exploit.
- xive: Ensure VC informational FIRs are masked

  Some HostBoot versions leave those as checkstop, they are harmless
  and can sometimes occur during normal operations.
- xive: Fix occasional VC checkstops in xive_reset

  The current workaround for the scrub bug described in
  __xive_cache_scrub() has an issue in that it can leave
  dirty invalid entries in the cache.

  When cleaning up EQs or VPs during reset, if we then
  remove the underlying indirect page for these entries,
  the XIVE will checkstop when trying to flush them out
  of the cache.

  This replaces the existing workaround with a new pair of
  workarounds for VPs and EQs:

  - The VP one does the dummy watch on another entry than
    the one we scrubbed (which does the job of pushing old
    stores out) using an entry that is known to be backed by
    a permanent indirect page.
  - The EQ one switches to a more efficient workaround
    which consists of doing a non-side-effect ESB load from
    the EQ's ESe control bits.
- xive: Do not return a trigger page for an escalation interrupt

  This is bogus, we don't support them. (Thankfully the callers
  didn't actually try to use this on escalation interrupts).
- xive: Mark a freed IRQs IVE as valid and masked

  Removing the valid bit means a FIR will trip if it's accessed
  inadvertently. Under some circumstances, the XIVE will speculatively
  access an IVE for a masked interrupt and trip it. So make sure that
  freed entries are still marked valid (but masked).

PCI
---

- pci: Shared slot state synchronisation for hot reset

  When a device is shared between two PHBs, it doesn't get reset properly
  unless both PHBs issue a hot reset at "the same time".  Practically this
  means a hot reset needs to be issued on both sides, and neither should
  bring the link up until the reset on both has completed.
- pci: Track peers of slots

  Witherspoon introduced a new concept where one physical slot is shared
  between two PHBs.  Making a slot aware of its peer enables syncing
  between them where necessary.

PHB4
----
- phb4: Change PCI MMIO timers

  Currently we have a mismatch between the NCU and PCI timers for MMIO
  accesses. The PCI timers must be lower than the NCU timers otherwise
  it may cause checkstops.

  This changes PCI timeouts controlled by skiboot to 33-50ms. It should
  be forwards and backwards compatible with expected hostboot changes to
  the NCU timer.
- phb4: Change default GEN3 lane equalisation setting to 0x54

  Currently our GEN3 lane equalisation settings are set to 0x77. Change
  this to 0x54. This change will allow us to train at GEN3 in a shorter
  time and more consistently.

  This setting gives us a TX preset 0x4 and RX hint 0x5. This gives a
  boost in gain for high frequency signalling. It allows the most optimal
  continuous time linear equalizers (CTLE) for the remote receiver port
  and de-emphasis and pre-shoot for the remote transmitter port.

  Machine Readable Workbooks (MRW) are moving to this new value also.
- phb4: Init changes

  These init changes for phb4 from the HW team.

  Link down are now endpoint recoverable (ERC) rather than PHB fatal
  errors.

  BLIF Completion Timeout Error now generate an interrupt rather than
  causing freeze events.
- phb4: Fix lane equalisation setting

  Fix cut and paste from phb3. The sizes have changes now we have GEN4,
  so the check here needs to change also

  Without this we end up with the default settings (all '7') rather
  than what's in HDAT.
- hdata: Fix copying GEN4 lane equalisation settings

  These aren't copied currently but should be.
- phb4: Fix PE mapping of M32 BAR

  The M32 BAR is the PHB4 region used to map all the non-prefetchable
  or 32-bit device BARs. It's supposed to have its segments remapped
  via the MDT and Linux relies on that to assign them individual PE#.

  However, we weren't configuring that properly and instead used the
  mode where PE# == segment#, thus causing EEH to freeze the wrong
  device or PE#.
- phb4: Fix lost bit in PE number on config accesses

  A PE number can be up to 9 bits, using a uint8_t won't fly..

  That was causing error on config accesses to freeze the
  wrong PE.
- phb4: Update inits

  New init value from HW folks for the fence enable register.

  This clears bit 17 (CFG Write Error CA or UR response) and bit 22 (MMIO Write
  DAT_ERR Indication) and sets bit 21 (MMIO CFG Pending Error)

CAPI
----

- capi: Disable CAPP virtual machines

  When exercising more than one CAPI accelerators simultaneously in
  cache coherency mode, the verification team is seeing a deadlock. To
  fix this a workaround of disabling CAPP virtual machines is
  suggested. These 'virtual machines' let PSL queue multiple CAPP
  commands for servicing by CAPP there by increasing
  throughput. Below is the error scenario described by the h/w team:

  " With virtual machines enabled we had a deadlock scenario where with 2
  or more CAPI's in a system you could get in a deadlock scenario due to
  cast-outs that are required break the deadlock (evict lines that
  another CAPI is requesting) get stuck in the virtual machine queue by
  a command ahead of it that is being retried by the same scenario in
  the other CAPI. "

- capi: Perform capp recovery sequence only when PBCQ is idle

  Presently during a CRESET the CAPP recovery sequence can be executed
  multiple times in case PBCQ on the PEC is still busy processing in/out
  bound in-flight transactions.
- xive: Mask MMIO load/store to bad location FIR

  For opencapi, the trigger page of an interrupt is mapped to user
  space. The intent is to write the page to raise an interrupt but
  there's nothing to prevent a user process from reading it, which has
  the unfortunate consequence of checkstopping the system.

  Mask the FIR bit raised when an MMIO operation targets an invalid
  location. It's the recommendation from recent documentation and
  hostboot is expected to mask it at some point. In the meantime, let's
  play it safe.
- phb4: Dump CAPP error registers when it asserts link down

  This patch introduces a new function phb4_dump_app_err_regs() that
  dumps CAPP error registers in case the PEC nestfir register indicates
  that the fence was due to a CAPP error (BIT-24).

  Contents of these registers are helpful in diagnosing CAPP
  issues. Registers that are dumped in phb4_dump_app_err_regs() are:

    * CAPP FIR Register
    * CAPP APC Master Error Report Register
    * CAPP Snoop Error Report Register
    * CAPP Transport Error Report Register
    * CAPP TLBI Error Report Register
    * CAPP Error Status and Control Register
- capi: move the acknowledge of the HMI interrupt

  We need to acknowledge an eventual HMI initiated by the previous forced
  fence on the PHB to work around a non-existent PE in the phb4_creset()
  function.
  For this reason do_capp_recovery_scoms() is called now at the
  beginning of the step: PHB4_SLOT_CRESET_WAIT_CQ
- capi: update ci store buffers and dma engines

  The number of read (APC type traffic) and mmio store (MSG type traffic)
  resources assigned to the CAPP is controlled by the CAPP control
  register.

  According to the type of CAPI cards present on the server, we have to
  configure differently the CAPP messages and the DMA read engines given
  to the CAPP for use.

HMI
---
- core/hmi: Display chip location code while displaying core FIR.
- core/hmi: Do not display FIR details if none of the bits are set.

  So that we don't flood OPAL console logs with information that is not
  useful.
- opal/hmi: HMI logging with location code info.

  Add few HMI debug prints with location code info few additional info.

  No functionality change.

  With this patch the log messages will look like: ::

    [210612.175196744,7] HMI: Received HMI interrupt: HMER = 0x0840000000000000
    [210612.175200449,7] HMI: [Loc: UOPWR.1302LFA-Node0-Proc1]: P:8 C:16 T:1: TFMR(2d12000870e04020) Timer Facility Error

    [210660.259689526,7] HMI: Received HMI interrupt: HMER = 0x2040000000000000
    [210660.259695649,7] HMI: [Loc: UOPWR.1302LFA-Node0-Proc0]: P:0 C:16 T:1: Processor recovery Done.

- core/hmi: Use pr_fmt macro for tagging log messages

  No functionality changes.
- opal: Get chip location code

  and store it under proc_chip for quick reference during HMI handling
  code.

Sensors
-------
- occ-sensors: Fix up quad/gpu location mix-up

  The GPU and QUAD sensor location types are swapped compared to what
  exists in the OCC code base which is authoritative. Fix them up.
- sensors: occ: Skip counter type of sensors

  Don't add counter type of sensors to device-tree as they don't
  fit into hwmon sensor interface.
- sensors: dts: Assert special wakeup on idle cores while reading temperature

  In P9, when a core enters a stop state, its clocks will be stopped
  to save power and hence we will not be able to perform a SCOM
  operation to read the DTS temperature sensor.  Hence, assert
  a special wakeup on cores that have entered a stop state in order to
  successfully complete the SCOM operation.
- sensors: occ: Skip power sensors with zero sample value

  APSS is not available on platforms like Zaius, Romulus where OCC
  can only measure Vdd (core) and Vdn (nest) power from the AVSbus
  reading. So all the sensors for APSS channels will be populated
  with 0. Different component power sensors like system, memory
  which point to the APSS channels will also be 0.

  As per OCC team (Martha Broyles) zeroed power sensor means that the
  system doesn't have it. So this patch filters out these sensors.
- sensors: occ: Skip GPU sensors for non-gpu systems
- sensors: Fix dtc warning for new occ in-band sensors.

  dtc complains about missing reg property when a DT node is having a
  unit name or address but no reg property. ::

    /ibm,opal/sensors/vrm-in@c00004 has a unit name, but no reg property
    /ibm,opal/sensors/gpu-in@c0001f has a unit name, but no reg property
    /ibm,opal/sensor-groups/occ-js@1c00040 has a unit name, but no reg property

  This patch fixes these warnings for new occ in-band sensors and also for
  sensor-groups by adding necessary properties.
- sensors: Fix dtc warning for dts sensors.

  dtc complains about missing reg property when a DT node is having a
  unit name or address but no reg property.

  Example warning for core dts sensor: ::

    /ibm,opal/sensors/core-temp@5c has a unit name, but no reg property
    /ibm,opal/sensors/core-temp@804 has a unit name, but no reg property

  This patch fixes this by adding necessary properties.
- hw/occ: Fix psr cpu-to-gpu sensors node dtc warning.

  dtc complains about missing reg property when a DT node is having a
  unit name or address but no reg property. ::

    /ibm,opal/power-mgt/psr/cpu-to-gpu@0 has a unit name, but no reg property
    /ibm,opal/power-mgt/psr/cpu-to-gpu@100 has a unit name, but no reg property

  This patch fixes this by adding necessary properties.

General fixes
-------------
- lpc: Clear pending IRQs at boot

  When we come in from hostboot the LPC master has the bus reset indicator
  set. This error isn't handled until the host kernel unmasks interrupts,
  at which point we get the following spurious error: ::

    [   20.053560375,3] LPC: Got LPC reset on chip 0x0 !
    [   20.053564560,3] LPC[000]: Unknown LPC error Error address reg: 0x00000000

  Fix this by clearing the various error bits in the LPC status register
  before we initialise the skiboot LPC bus driver.
- hw/imc: Check ucode state before exposing units to Linux

  disable_unavailable_units() checks whether the ucode
  is in the running state before enabling the nest units
  in the device tree. From a recent debug, it is found
  that on some system boot, ucode is not loaded and
  running in all the chips in the system. And this
  caused a fail in OPAL_IMC_COUNTERS_STOP call where
  we check for ucode state on each chip. Bug here is
  that disable_unavailable_units() checks the state
  of the ucode only in boot cpu chip. Patch adds a
  condition in disable_unavailable_units() to check
  for the ucode state in all the chip before enabling
  the nest units in the device tree node.

- hdata/vpd: Add vendor property

  ibm,vpd blob contains VN field. Use that to populate vendor property
  for various FRU's.
- hdata/vpd: Fix DTC warnings

  All the nodes under the vpd hierarchy have a unit address (their SLCA
  index) but no reg properties. Add them and their size/address cells
  to squash the warnings.
- HDAT/i2c: Fix SPD EEPROM compatible string

  Hostboot doesn't give us accurate information about the DIMM SPD
  devices. Hack around by assuming any EEPROM we find on the SPD I2C
  master is an SPD EEPROM.
- hdata/i2c: Fix 512Kb EEPROM size

  There's no such thing as a 412Kb EEPROM.
- libflash/mbox-flash: fall back to requesting lower MBOX versions from BMC

  Some BMC mbox implementations seem to sometimes mysteriously fail when trying
  to negotiate v3 when they only support v2. To work around this, we
  can fall back to requesting lower mbox protocol versions until we find
  one that works.

  In theory, this should already "just work", but we have a counter example,
  which this patch fixes.
- IPMI: Fix platform.cec_reboot() null ptr checks

  Kudos to Hugo Landau who reported this in:
  https://github.com/open-power/skiboot/issues/142
- hdata: Add location code property to xscom node

  This patch adds chip location code property to xscom node.
- p8-i2c: Limit number of retry attempts

  Current we will attempt to start an I2C transaction until it succeeds.
  In the event that the OCC does not release the lock on an I2C bus this
  results in an async token being held forever and the kernel thread that
  started the transaction will block forever while waiting for an async
  completion message. Fix this by limiting the number of attempts to
  start the transaction.
- p8-i2c: Don't write the watermark register at init

  On P9 the I2C master is shared with the OCC. Currently the watermark
  values are set once at init time which is bad for two reasons:

  a) We don't take the OCC master lock before setting it. Which
     may cause issues if the OCC is currently using the master.
  b) The OCC might change the watermark levels and we need to reset
     them.

  Change this so that we set the watermark value when a new transaction
  is started rather than at init time.
- hdata: Rename 'fsp-ipl-side' as 'sp-ipl-side'

  as OPAL is building device tree for both FSP and BMC system.
  Also I don't see anyone using this property today. Hence renaming
  should be fine.
- hdata/vpd: add support for parsing CPU VRML records

  Allows skiboot to parse out the processor part/serial numbers
  on OpenPOWER P9 machines.
- core/lock: Introduce atomic cmpxchg and implement try_lock with it

  cmpxchg will be used in a subsequent change, and this reduces the
  amount of asm code.
- direct-controls: add xscom error handling for p8

  Add xscom checks which will print something useful and return error
  back to callers (which already have error handling plumbed in).
- direct-controls: p8 implementation of generic direct controls

  This reworks the sreset functionality that was brought over from
  fast-reboot, and fits it under the generic direct controls APIs.

  The fast reboot APIs are implemented using generic direct controls,
  which also makes them available on p9.
- fast-reboot: allow mambo fast reboot independent of CPU type

  Don't tie mambo fast reboot to POWER8 CPU type.
- fast-reboot: remove delay after sreset

  There is a 100ms delay when targets reach sreset which does not appear
  to have a good purpose. Remove it and therefore reduce the sreset timeout
  by the same amount.
- fast-reboot: add more barriers around cpu state changes

  This is a bit of paranoia, but when a CPU changes state to signal it
  has reached a particular point, all previous stores should be visible.
- fast-reboot: add sreset timeout detection and handling

  Have the initiator wait for all its sreset targets to call in, and
  time out after 200ms if they did not. Fail and revert to IPL reboot.

  Testing indicates that after successful sreset_all_others(), it
  takes less than 102ms (in hundreds of fast reboots) for secondaries
  to call in. 100 of that is due to an initial delay, but core
  un-splitting was not measured.
- fast-reboot: make spin loops consistent and SMT friendly
- fast-reboot: add sreset_all_others error handling

  Pass back failures from sreset_all_others, also change return codes to
  OPAL form in sreset_all_prepare to match.

  Errors will revert to the IPL path, so it's not critical to completely
  clean up everything if that would complicate things. Detecting the
  error and failing is the important thing.
- fast-reboot: restore SMT priority on spin loop exit
- Add documentation for ibm, firmware-versions device tree node
- NX: Print read xscom config failures.

  Currently in NX, only write xscom config failures are tracing.
  Add trace statements for read xscom config failures too.
  No functional changes.
- hw/nx: Fix NX BAR assignments

  The NX rng BAR is used by each core to source random numbers for the
  DARN instruction. Currently we configure each core to use the NX rng of
  the chip that it exists on. Unfortunately, the NX can be de-configured by
  hostboot and in this case we need to use the NX of a different chip.

  This patch moves the BAR assignments for the NX into the normal nx-rng
  init path. This lets us check if the normal (chip local) NX is active
  when configuring which NX a core should use so that we can fall back
  gracefully.
- FSP-elog: Reduce verbosity of elog messages

  These messages just fill up the opal console log with useless messages
  resulting in us losing useful information.

  They have been like this since the first commit in skiboot. Make them
  trace.
- core/bitmap: fix bitmap iteration limit corruption

  The bitmap iterators did not reduce the number of bits to scan
  when searching for the next bit, which would result in them
  overrunning their bitmap.

  These are only used in one place, in xive reset, and the effect
  is that the xive reset code will keep zeroing memory until it
  reaches a block of memory of MAX_EQ_COUNT >> 3 bits in length,
  all zeroes.
- hw/imc: always enable "imc_nest_chip" exports property

  imc_dt_update_nest_node() adds a "imc_nest_chip" property
  to the "exports" node (under opal_node) to view nest counter
  region. This comes handy when debugging ucode runtime
  errors (like counter data update or control block update
  so on...). And current code enables the property only if
  the microcode is in running state at system boot. To aid
  the debug of ucode not running/starting issues at boot,
  enable the addition of "imc_nest_chip" property always.

NVLINK2
-------

- npu2-hw-procedures.c: Correct phy lane mapping

  Each NVLINK2 device is associated with a particular group of OBUS lanes via
  a lane mask which is read from HDAT via the device-tree. However Skiboot's
  interpretation of lane mask was different to what is exported from the
  HDAT.

  Specifically the lane mask bits in the HDAT are encoded in IBM bit ordering
  for a 24-bit wide value. So for example in normal bit ordering lane-0 is
  represented by having lane-mask bit 23 set and lane-23 is represented by
  lane-mask bit 0. This patch alters the Skiboot interpretation to match what
  is passed from HDAT.

- npu2-hw-procedures.c: Power up lanes during ntl reset

  Newer versions of Hostboot will not power up the NVLINK2 PHY lanes by
  default. The phy_reset procedure already powers up the lanes but they also
  need to be powered up in order to access the DL.

  The reset_ntl procedure is called by the device driver to bring the DL out
  of reset and get it into a working state. Therefore we also need to add
  lane and clock power up to the reset_ntl procedure.
- npu2.c: Add PE error detection

  Invalid accesses from the GPU can cause a specific PE to be frozen by the
  NPU. Add an interrupt handler which reports the frozen PE to the operating
  system via as an EEH event.
- npu2.c: Fix XIVE IRQ alignment
- npu2: hw-procedures: Refactor reset_ntl procedure

  Change the implementation of reset_ntl to match the latest programming
  guide documentation.
- npu2: hw-procedures: Add phy_rx_clock_sel()

  Change the RX clk mux control to be done by software instead of HW. This
  avoids glitches caused by changing the mux setting.
- npu2: hw-procedures: Change phy_rx_clock_sel values

  The clock selection bits we set here are inputs to a state machine.

  DL clock select (bits 30-31)

  0b00
    lane 0 clock
  0b01
    lane 7 clock
  0b10
    grid clock
  0b11
    invalid/no-op

  To recover from a potential glitch, we need to ensure that the value we
  set forces a state change. Our current sequence is to set 0x3 followed
  by 0x1. With the above now known, that is actually a no-op followed by
  selection of lane 7. Depending on lane reversal, that selection is not a
  state change for some bricks.

  The way to force a state change in all cases is to switch to the grid
  clock, and then back to a lane.
- npu2: hw-procedures: Manipulate IOVALID during training

  Ensure that the IOVALID bit for this brick is raised at the start of
  link training, in the reset_ntl procedure.

  Then, to protect us from a glitch when the PHY clock turns off or gets
  chopped, lower IOVALID for the duration of the phy_reset and
  phy_rx_dccal procedures.
- npu2: hw-procedures: Add check_credits procedure

  As an immediate mitigation for a current hardware glitch, add a procedure
  that can be used to validate NTL credit values. This will be called as a
  safeguard to check that link training succeeded.

  Assert that things are exactly as we expect, because if they aren't, the
  system will experience a catastrophic failure shortly after the start of
  link traffic.
- npu2: Print bdfn in NPU2DEV* logging macros

  Revise the NPU2DEV{DBG,INF,ERR} logging macros to include the device's
  bdfn. It's useful to know exactly which link we're referring to.

    For instance, instead of ::

      [  234.044921238,6] NPU6: Starting procedure reset_ntl
      [  234.048578101,6] NPU6: Starting procedure reset_ntl
      [  234.051049676,6] NPU6: Starting procedure reset_ntl
      [  234.053503542,6] NPU6: Starting procedure reset_ntl
      [  234.057182864,6] NPU6: Starting procedure reset_ntl
      [  234.059666137,6] NPU6: Starting procedure reset_ntl

    we'll get ::

      [  234.044921238,6] NPU6:0:0.0 Starting procedure reset_ntl
      [  234.048578101,6] NPU6:0:0.1 Starting procedure reset_ntl
      [  234.051049676,6] NPU6:0:0.2 Starting procedure reset_ntl
      [  234.053503542,6] NPU6:0:1.0 Starting procedure reset_ntl
      [  234.057182864,6] NPU6:0:1.1 Starting procedure reset_ntl
      [  234.059666137,6] NPU6:0:1.2 Starting procedure reset_ntl
- npu2: Move to new GPU memory map

  There are three different ways we configure the MCD and memory map.

  1) Old way (current way)
       Skiboot configures the MCD and puts GPUs at 4TB and below
  2) New way with MCD
       Hostboot configures the MCD and skiboot puts GPU at 4TB and above
  3) New way without MCD
       No one configures the MCD and skiboot puts GPU at 4TB and below

  The patch keeps option 1 and adds options 2 and 3.

  The different configurations are detected using certain scoms (see
  patch).

  Option 1 will go away eventually as it's a configuration that can
  cause xstops or data integrity problems. We are keeping it around to
  support existing hostboot.

  Option 2 supports only 4 GPUs and 512GB of memory per socket.

  Option 3 supports 6 GPUs and 4TB of memory but may have some
  performance impact.
- phys-map: Rename GPU_MEM to GPU_MEM_4T_DOWN

  This map is soon to be replaced, but we are going to keep it around
  for a little while so that we support older hostboot firmware.

Platform Specific Fixes
-----------------------

Witherspoon
^^^^^^^^^^^
- Witherspoon: Remove old Witherspoon platform definition

  An old Witherspoon platform definition was added to aid the transition from
  versions of Hostboot which didn't have the correct NVLINK2 HDAT information
  available and/or planar VPD. These system should now be updated so remove
  the possibly incorrect default assumption.

  This may disable NVLINK2 on old out-dated systems but it can easily be
  restored with the appropriate FW and/or VPD updates. In any case there is a
  a 50% chance the existing default behaviour was incorrect as it only
  supports 6 GPU systems. Using an incorrect platform definition leads to
  undefined behaviour which is more difficult to detect/debug than not
  creating the NVLINK2 devices so remove the possibly incorrect default
  behaviour.
- Witherspoon: Fix VPD EEPROM type

  There are user-space tools that update the planar VPD via the sysfs
  interface. Currently we do not get correct information from hostboot
  about the exact type of the EEPROM so we need to manually fix it up
  here. This needs to be done as a platform specific fix since there is
  not standardised VPD EEPROM type.

IBM FSP Systems
^^^^^^^^^^^^^^^

- nvram: Fix 'missing' nvram on FSP systems.

  commit ba4d46fdd9eb ("console: Set log level from nvram") wants to read
  from NVRAM rather early. This works fine on BMC based systems as
  nvram_init() is actually synchronous. This is not true for FSP systems
  and it turns out that the query for the console log level simply
  queries blank nvram.

  The simple fix is to wait for the NVRAM read to complete before
  performing any query. Unfortunately it turns out that the fsp-nvram
  code does not inform the generic NVRAM layer when the read is complete,
  rather, it must be prompted to do so.

  This patch addresses both these problems. This patch adds a check before
  the first read of the NVRAM (for the console log level) that the read
  has completed. The fsp-nvram code has been updated to inform the generic
  layer as soon as the read completes.

  The old prompt to the fsp-nvram code has been removed but a check to
  ensure that the NVRAM has been loaded remains. It is conservative but
  if the NVRAM is not done loading before the host is booted it will not
  have an nvram device-tree node which means it won't be able to access
  the NVRAM at all, ever, even after the NVRAM has loaded.


Utilities
----------

- Fix xscom-utils distclean target

  In Debian/Ubuntu, the packaging system likes to have a full clean-up that
  restores the tree back to original one, so add some files to the distclean
  target.
- Add man pages for xscom-utils and pflash

  For the need of Debian/Ubuntu packaging, I inferred some initial man
  pages from their help output.

gard
^^^^
- gard: Add tests

  I hear Stewart likes these for some reason. Dunno why.
- gard: Add OpenBMC vPNOR support

  A big-ol-hack to add some checking for OpenBMC's vPNOR GUARD files under
  /media/pnor-prsv. This isn't ideal since it doesn't handle the create
  case well, but it's better than nothing.
- gard: Always use MTD to access flash

  Direct mode is generally either unsafe or unsupported. We should always
  access the PNOR via an MTD device so make that the default. If someone
  really needs direct mode, then they can use pflash.
- gard: Fix up do_create return values

  The return value of a subcommand is interpreted as a libflash error code
  when it's positive or some subcommand specific error when negative.
  Currently the create subcommand always returns zero when exiting (even
  for errors) so fix that.
- gard: Add usage message for -p

  The -p argument only really makes sense when -f is specified. Print an
  actual error message rather than just the usage blob.
- gard: Fix max instance count

  There's an entire byte for the instance count rather than a nibble. Only
  barf if the instance number is beyond 255 rather than 16.
- gard: Fix up path parsing

  Currently we assume that the Unit ID can be used as an array index into
  the chip_units[] structure. There are holes in the ID space though, so
  this doesn't actually work. Fix it up by walking the array looking for
  the ID.
- gard: Set chip generation based on PVR

  Currently we assume that this tool is being used on a P8 system by
  default and allow the user to override this behaviour using the -8 and
  -9 command line arguments. When running on the host we can use the
  PVR to guess what chip generation so do that.

  This also changes the default behaviour to assume that the host is a P9
  when running on an ARM system. This tool didn't even work when compiled
  for ARM until recently and the OpenBMC vPNOR hack that we have currently
  is broken for P9 systems that don't use vPNOR (Zaius and Romulus).
- gard: Allow records with an ID of 0xffffffff

  We currently assume that a record with an ID of 0xffffffff is invalid.
  Apparently this is incorrect and we should display these records, so
  expand the check to compare the entire record with 0xff rather than
  just the ID.
- gard: create: Allow creating arbitrary GARD records

  Add a new sub-command that allows us to create GARD records for
  arbitrary chip units. There isn't a whole lot of constraints on this and
  that limits how useful it can be, but it does allow a user to GARD out
  individual DIMMs, chips or cores from the BMC (or host) if needed.

  There are a few caveats though:

  1) Not everything can, or should, have a GARD record applied it to.
  2) There is no validation that the unit actually exists. Doing that
     sort of validation requires something that understands the FAPI
     targeting information (I think) and adding support for it here
     would require some knowledge from the system XML file.
  3) There's no way to get a list of paths in the system.
  4) Although we can create a GARD record at runtime it won't be applied
     until the next IPL.
- gard: Add path parsing support

  In order to support manual GARD records we need to be able to parse the
  hardware unit path strings. This patch implements that.
- gard: list: Improve output

  Display the full path to the GARDed hardware unit in each record rather
  than relying on the output of `gard show` and convert do_list() to use
  the iterator while we're here.
- gard: {list, show}: Fix the Type field in the output

  The output of `gard list` has a field named "Type", however this
  doesn't actually indicate the type of the record. Rather, it
  shows the type of the path used to identify the hardware being
  GARDed. This is of pretty dubious value considering the Physical
  path seems to always be used when referring to GARDed hardware.
- gard: Add P9 support
- gard: Update chip unit data

  Source the list of units from the hostboot source rather than the
  previous hard coded list. The list of path element types changes
  between generations so we need to add a level of indirection to
  accommodate P9. This also changes the names used to match those
  printed by Hostboot at IPL time and paves the way to adding support
  for manual GARD record creation.
- gard: show: Remove "Res Recovery" field

  This field has never been populated by hostboot on OpenPower systems
  so there's no real point in reporting it's contents.

libflash / pflash
^^^^^^^^^^^^^^^^^

Anybody shipping libflash or pflash to interact with POWER9 systems must
upgrade to this version.

- pflash: Support for volatile flag

  The volatile flag was added to the PNOR image to
  indicate partitions that are cleared during a host
  power off. Display this flag from the pflash command.
- pflash: Support for clean_on_ecc_error flag

  Add the misc flag clear_on_ecc_error to libflash/pflash. This was
  the only missing flag. The generator of the virtual PNOR image
  relies on libflash/pflash to provide the partition information,
  so all flags are needed to build an accurate virtual PNOR partition
  table.
- pflash: Respect write(2) return values

  The write(2) system call returns the number of bytes written, this is
  important since it is entitled to write less than what we requested.
  Currently we ignore the return value and assume it wrote everything we
  requested. While in practice this is likely to always be the case, it
  isn't actually correct.
- external/pflash: Fix erasing within a single erase block

  It is possible to erase within a single erase block. Currently the
  pflash code assumes that if the erase starts part way into an erase
  block it is because it needs to be aligned up to the boundary with the
  next erase block.

  Doing an erase smaller than a single erase block will cause underflows
  and looping forever on erase.
- external/pflash: Fix non-zero return code for successful read when size%256 != 0

  When performing a read the return value from pflash is non-zero, even for
  a successful read, when the size being read is not a multiple of 256.
  This is because do_read_file returns the value from the write system
  call which is then returned by pflash. When the size is a multiple of
  256 we get lucky in that this wraps around back to zero. However for any
  other value the return code is size % 256. This means even when the
  operation is successful the return code will seem to reflect an error.

  Fix this by returning zero if the entire size was read correctly,
  otherwise return the corresponding error code.
- libflash: Fix parity calculation on ARM

  To calculate the ECC syndrome we need to calculate the parity of a 64bit
  number. On non-powerpc platforms we use the GCC builtin function
  __builtin_parityl() to do this calculation. This is broken on 32bit ARM
  where sizeof(unsigned long) is four bytes. Using __builtin_parityll()
  instead cures this.
- libflash/mbox-flash: Add the ability to lock flash
- libflash/mbox-flash: Understand v3
- libflash/mbox-flash: Use BMC suggested timeout value
- libflash/mbox-flash: Simplify message sending

  hw/lpc-mbox no longer requires that the memory associated with messages
  exist for the lifetime of the message. Once it has been sent to the BMC,
  that is bmc_mbox_enqueue() returns, lpc-mbox does not need the message
  to continue to exist. On the receiving side, lpc-mbox will ensure that a
  message exists for the receiving callback function.

  Remove all code to deal with allocating messages.
- hw/lpc-mbox: Simplify message bookkeeping and timeouts

  Currently the hw/lpc-mbox layer keeps a pointer for the currently
  in-flight message for the duration of the mbox call. This creates
  problems when messages timeout, is that pointer still valid, what can we
  do with it. The memory is owned by the caller but if the caller has
  declared a timeout, it may have freed that memory.

  Another problem is locking. This patch also locks around sending and
  receiving to avoid races with timeouts and possible resends. There was
  some locking previously which was likely insufficient - definitely too
  hard to be sure is correct

  All this is made much easier with the previous rework which moves
  sequence number allocation and verification into lpc-mbox rather than
  the caller.
- libflash/mbox-flash: Allow mbox-flash to tell the driver msg timeouts

  Currently when mbox-flash decides that a message times out the driver
  has no way of knowing to drop the message and will continue waiting for
  a response indefinitely preventing more messages from ever being sent.

  This is a problem if the BMC crashes or has some other issue where it
  won't ever respond to our outstanding message.

  This patch provides a method for mbox-flash to tell the driver how long
  it should wait before it no longer needs to care about the response.
- libflash/mbox-flash: Move sequence handling to driver level
- libflash/mbox-flash: Always close windows before opening a new window

  The MBOX protocol states that if an open window command fails then all
  open windows are closed. Currently, if an open window command fails
  mbox-flash will erroneously assume that the previously open window is
  still open.

  The solution to this is to mark all windows as closed before issuing an
  open window command and then on success we'll mark the new window as
  open.
- libflash/mbox-flash: Add v2 error codes

opal-prd
^^^^^^^^

Anybody shipping `opal-prd` for POWER9 systems must upgrade `opal-prd` to
this new version.

- prd: Log unsupported message type

  Useful for debugging.

  Sample output: ::

      [29155.157050283,7] PRD: Unsupported prd message type : 0xc

- opal-prd: occ: Add support for runtime OCC load/start in ZZ

  This patch adds support to handle OCC load/start event from FSP/PRD.
  During IPL we send a success directly to FSP without invoking any HBRT
  load routines on receiving OCC load mbox message from FSP. At runtime
  we forward this event to host opal-prd.

  This patch provides support for invoking OCC load/start HBRT routines
  like load_pm_complex() and start_pm_complex() from opal-prd.
- opal-prd: Add support for runtime OCC reset in ZZ

  This patch handles OCC_RESET runtime events in host opal-prd and also
  provides support for calling 'hostinterface->wakeup()' which is
  required for doing the reset operation.
- prd: Enable error logging via firmware_request interface

  In P9 HBRT sends error logs to FSP via firmware_request interface.
  This patch adds support to parse error log and send it to FSP.
- prd: Add generic response structure inside prd_fw_msg

  This patch adds generic response structure. Also sync prd_fw_msg type
  macros with hostboot.
- opal-prd: flush after logging to stdio in debug mode

  When in debug mode, flush after each log output. This makes it more
  likely that we'll catch failure reasons on severe errors.

Debugging and reliability improvements
--------------------------------------

- lock: Add additional lock auditing code

  Keep track of lock owner name and replace lock_depth counter
  with a per-cpu list of locks held by the cpu.

  This allows us to print the actual locks held in case we hit
  the (in)famous message about opal_pollers being run with a
  lock held.

  It also allows us to warn (and drop them) if locks are still
  held when returning to the OS or completing a scheduled job.
- Add support for new GCC 7 parametrized stack protector

  This gives us per-cpu guard values as well. For now I just
  XOR a magic constant with the CPU PIR value.
- Mambo: run hello_world and sreset_world tests with Secure and Trusted Boot

  We *disable* the secure boot part, but we keep the verified boot
  part as we don't currently have container verification code for Mambo.

  We can run a small part of the code currently though.

- core/flash.c: extern function to get the name of a PNOR partition

  This adds the flash_map_resource_name() to allow skiboot subsystems to
  lookup the name of a PNOR partition. Thus, we don't need to duplicate
  the same information in other places (e.g. libstb).
- libflash/mbox-flash: only wait for MBOX_DEFAULT_POLL_MS if busy

  This makes the mbox unit test run 300x quicker and seems to
  shave about 6 seconds from boot time on Witherspoon.
- make check: Make valgrind optional

  To (slightly) lower the barrier for contributions, we can make valgrind
  optional with just a small amount of plumbing.

  This allows make check to run successfully without valgrind.
- libflash/test: Add tests for mbox-flash

  A first basic set of tests for mbox-flash. These tests do their testing
  by stubbing out or otherwise replacing functions not in
  libflash/mbox-flash.c. The stubbed out version of the function can then
  be used to emulate a BMC mbox daemon talking to back to the code in
  mbox-flash and it can ensure that there is some adherence to the
  protocol and that from a block-level api point of view the world appears
  sane.

  This makes these tests simple to run and they have been integrated into
  `make check`. The down side is that these tests rely on duplicated
  feature incomplete BMC daemon behaviour. Therefore these tests are a
  strong indicator of broken behaviour but a very unreliable indicator of
  correctness.

  Full integration tests with a 'real' BMC daemon are probably beyond the
  scope of this repository.
- external/test/test.sh: fix VERSION substitution when no tags

  i.e. we get a hash rather than a version number

  This seems to be occurring in Travis if it doesn't pull a tag.
- external/test: make stripping out version number more robust

  For some bizarre reason, Travis started failing on this
  substitution when there'd been zero code changes in this
  area... This at least papers over whatever the problem is
  for the time being.
- io: Add load_wait() helper

  This uses the standard form twi/isync pair to ensure a load
  is consumed by the core before continuing. This can be necessary
  under some circumstances for example when having the following
  sequence:

  - Store reg A
  - Load reg A (ensure above store pushed out)
  - delay loop
  - Store reg A

  I.E., a mandatory delay between 2 stores. In theory the first store
  is only guaranteed to reach the device after the load from the same
  location has completed. However the processor will start executing
  the delay loop without waiting for the return value from the load.

  This construct enforces that the delay loop isn't executed until
  the load value has been returned.
- chiptod: Keep boot timestamps contiguous

  Currently we reset the timebase value to (almost) zero when
  synchronising the timebase of each chip to the Chip TOD network which
  results in this: ::

    [   42.374813167,5] CPU: All 80 processors called in...
    [    2.222791151,5] FLASH: Found system flash: Macronix MXxxL51235F id:0
    [    2.222977933,5] BT: Interface initialized, IO 0x00e4

  This patch modifies the chiptod_init() process to use the current
  timebase value rather than resetting it to zero. This results in the
  timestamps remaining contiguous from the start of hostboot until
  the petikernel starts. e.g. ::

    [   70.188811484,5] CPU: All 144 processors called in...
    [   72.458004252,5] FLASH: Found system flash:  id:0
    [   72.458147358,5] BT: Interface initialized, IO 0x00e4

- hdata/spira: Add missing newline to prlog() call

  We're missing a \n here.
- opal/xscom: Add recovery for lost core wakeup SCOM failures.

  Due to a hardware issue where core responding to SCOM was delayed due to
  thread reconfiguration, leaves the SCOM logic in a state where the
  subsequent SCOM to that core can get errors. This is affected for Core
  PC SCOM registers in the range of 20010A80-20010ABF

  The solution is if a xscom timeout occurs to one of Core PC SCOM registers
  in the range of 20010A80-20010ABF, a clearing SCOM write is done to
  0x20010800 with data of '0x00000000' which will also get a timeout but
  clears the SCOM logic errors. After the clearing write is done the original
  SCOM operation can be retried.

  The SCOM timeout is reported as status 0x4 (Invalid address) in HMER[21-23].
- opal/xscom: Move the delay inside xscom_reset() function.

  So caller of xscom_reset() does not have to bother about adding a delay
  separately. Instead caller can control whether to add a delay or not using
  second argument to xscom_reset().
- timer: Stop calling list_top() racily

  This will trip the debug checks in debug builds under some circumstances
  and is actually a rather bad idea as we might look at a timer that is
  concurrently being removed and modified, and thus incorrectly assume
  there is no work to do.
- fsp: Bail out of HIR if FSP is resetting voluntarily

  a. Surveillance response times out and OPAL triggers a HIR
  b. Before the HIR process kicks in, OPAL gets a PSI interrupt indicating link down
  c. HIR process continues and OPAL tries to write to DRCR; PSI link inactive => xstop

  OPAL should confirm that the FSP is not already in reset in the HIR path.
- sreset_kernel: only run SMT tests due to not supporting re-entry
- Use systemsim-p9 v1.1
- direct-controls: enable fast reboot direct controls for mambo

  Add mambo direct controls to stop threads, which is required for
  reliable fast-reboot. Enable direct controls by default on mambo.
- core/opal: always verify cpu->pir on entry
- asm/head: add entry/exit calls

  Add entry and exit C functions that can do some more complex
  checks before the opal proper call. This requires saving off
  volatile registers that have arguments in them.
- core/lock: improve bust_locks

  Prevent try_lock from modifying the lock state when bust_locks is set.
  unlock will not unlock it in that case, so locks will get taken and
  never released while bust_locks is set.
- hw/occ: Log proper SCOM register names

  This patch fixes the logging of incorrect SCOM
  register names.
- mambo: Add support for NUMA

  Currently the mambo scripts can do multiple chips, but only the first
  ever has memory.

  This patch adds support for having memory on each chip, with each
  appearing as a separate NUMA node. Each node gets MEM_SIZE worth of
  memory.

  It's opt-in, via ``export MAMBO_NUMA=1``.
- external/mambo: Switch qtrace command to use plug-ins

  The plug-in seems to be the preferred way to do this now, it works
  better, and the qtracer emitter seems to generate invalid traces
  in new mambo versions.
- asm/head: Loop after attn

  We use the attn instruction to raise an error in early boot if OPAL
  don't recognise the PVR. It's possible for hostboot to disable the
  attn instruction before entering OPAL so add an extra busy loop after
  the attn to prevent attempting to boot on an unknown processor.
