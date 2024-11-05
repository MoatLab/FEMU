.. _skiboot-5.10:

skiboot-5.10
============

skiboot v5.10 was released on Friday February 23rd 2018. It is the first
release of skiboot 5.10, and becomes the new stable release
of skiboot following the 5.9 release, first released October 31st 2017.

skiboot v5.10 contains all bug fixes as of :ref:`skiboot-5.9.8`
and :ref:`skiboot-5.4.9`. We do not forsee any further 5.9.x releases.

For how the skiboot stable releases work, see :ref:`stable-rules` for details.

Over skiboot-5.9, we have the following changes:

New Features
------------

Since skiboot-5.10-rc3:

- sensor-groups: occ: Add support to disable/enable sensor group

  This patch adds a new opal call to enable/disable a sensor group. This
  call is used to select the sensor groups that needs to be copied to
  main memory by OCC at runtime.
- sensors: occ: Add energy counters

  Export the accumulated power values as energy sensors. The accumulator
  field of power sensors are used for representing energy counters which
  can be exported as energy counters in Linux hwmon interface.
- sensors: Support reading u64 sensor values

  This patch adds support to read u64 sensor values. This also adds
  changes to the core and the backend implementation code to make this
  API as the base call. Host can use this new API to read sensors
  upto 64bits.

  This adds a list to store the pointer to the kernel u32 buffer, for
  older kernels making async sensor u32 reads.
- dt: add /cpus/ibm,powerpc-cpu-features device tree bindings

  This is a new CPU feature advertising interface that is fine-grained,
  extensible, aware of privilege levels, and gives control of features
  to all levels of the stack (firmware, hypervisor, and OS).

  The design and binding specification is described in detail in doc/.

Since skiboot-5.10-rc2:

- DT: Add "version" property under ibm, firmware-versions node

  First line of VERSION section in PNOR contains firmware version.
  Use that to add "version" property under firmware versions dt node.

  Sample output:

  .. code-block:: console

     root@xxx2:/proc/device-tree/ibm,firmware-versions# lsprop
     version          "witherspoon-ibm-OP9_v1.19_1.94"

Since skiboot-5.10-rc1:

- hw/npu2: Implement logging HMI actions


Since skiboot-5.9:

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

Since skiboot-5.10-rc2:

- stb: Put correct label (for skiboot) into container

  Hostboot will expect the label field of the stb header to contain
  "PAYLOAD" for skiboot or it will fail to load and run skiboot.

  The failure looks something like this: ::

     53.40896|ISTEP 20. 1 - host_load_payload
     53.65840|secure|Secureboot Failure plid = 0x90000755, rc = 0x1E07

     53.65881|System shutting down with error status 0x1E07
     53.67547|================================================
     53.67954|Error reported by secure (0x1E00) PLID 0x90000755
     53.67560|  Container's component ID does not match expected component ID
     53.67561|  ModuleId   0x09 SECUREBOOT::MOD_SECURE_VERIFY_COMPONENT
     53.67845|  ReasonCode 0x1e07 SECUREBOOT::RC_ROM_VERIFY
     53.67998|  UserData1   : 0x0000000000000000
     53.67999|  UserData2   : 0x0000000000000000
     53.67999|------------------------------------------------
     53.68000|  Callout type             : Procedure Callout
     53.68000|  Procedure                : EPUB_PRC_HB_CODE
     53.68001|  Priority                 : SRCI_PRIORITY_HIGH
     53.68001|------------------------------------------------
     53.68002|  Callout type             : Procedure Callout
     53.68003|  Procedure                : EPUB_PRC_FW_VERIFICATION_ERR
     53.68003|  Priority                 : SRCI_PRIORITY_HIGH
     53.68004|------------------------------------------------

Since skiboot-5.10-rc1:

- stb: Enforce secure boot if called before libstb initialized
- stb: Correctly error out when no PCR for resource
- core/init: move imc catalog preload init after the STB init.

  As a safer side move the imc catalog preload after the STB init
  to make sure the imc catalog resource get's verified and measured
  properly during loading when both secure and trusted boot modes
  are on.
- libstb: fix failure of calling trusted measure without STB initialization.

  When we load a flash resource during OPAL init, STB calls trusted measure
  to measure the given resource. There is a situation when a flash gets loaded
  before STB initialization then trusted measure cannot measure properly.

  So this patch fixes this issue by calling trusted measure only if the
  corresponding trusted init was done.

  The ideal fix is to make sure STB init done at the first place during init
  and then do the loading of flash resources, by that way STB can properly
  verify and measure the all resources.
- libstb: fix failure of calling cvc verify without STB initialization.

  Currently in OPAL init time at various stages we are loading various
  PNOR partition containers from the flash device. When we load a flash
  resource STB calls the CVC verify and trusted measure(sha512) functions.
  So when we have a flash resource gets loaded before STB initialization,
  then cvc verify function fails to start the verify and enforce the boot.

  Below is one of the example failure where our VERSION partition gets
  loading early in the boot stage without STB initialization done.

  This is with secure mode off.
  STB: VERSION NOT VERIFIED, invalid param. buf=0x305ed930, len=4096 key-hash=0x0 hash-size=0

  In the same code path when secure mode is on, the boot process will abort.

  So this patch fixes this issue by calling cvc verify only if we have
  STB init was done.

  And also we need a permanent fix in init path to ensure STB init gets
  done at first place and then start loading all other flash resources.
- libstb/tpm_chip: Add missing new line to print messages.
- libstb: increase the log level of verify/measure messages to PR_NOTICE.

  Currently libstb logs the verify and hash caluculation messages in
  PR_INFO level. So when there is a secure boot enforcement happens
  in loading last flash resource(Ex: BOOTKERNEL), the previous verify
  and measure messages are not logged to console, which is not clear
  to the end user which resource is verified and measured.
  So this patch fixes this by increasing the log level to PR_NOTICE.

Since skiboot-5.9:

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

Since skiboot-5.10-rc3:

- phb3/phb4/p7ioc: Document supported TCE sizes in DT

  Add a new property, "ibm,supported-tce-sizes", to advertise to Linux how
  big the available TCE sizes are.  Each value is a bit shift, from
  smallest to largest.
- phb4: Fix TCE page size

  The page sizes for TCEs on P9 were inaccurate and just copied from PHB3,
  so correct them.
- Revert "pci: Shared slot state synchronisation for hot reset"

  An issue was found in shared slot reset where the system can be stuck in
  an infinite loop, pull the code out until there's a proper fix.

  This reverts commit 1172a6c57ff3c66f6361e572a1790cbcc0e5ff37.
- hdata/iohub: Use only wildcard slots for pluggables

  We don't want to cause a VID:DID check against pluggable devices, as
  they may use multiple devids.

  Narrow the condition under which VID:DID is listed in the dt, so that
  we'll end up creating a wildcard slot for these instead.

Since skiboot-5.9:

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

Since skiboot-5.10-rc4:

- phb4: Disable lane eq when retrying some nvidia GEN3 devices

  This fixes these nvidia cards training at only GEN2 spends rather than
  GEN3 by disabling PCIe lane equalisation.

  Firstly we check if the card is in a whitelist.  If it is and the link
  has not trained optimally, retry with lane equalisation off. We do
  this on all POWER9 chip revisions since this is a device issue, not
  a POWER9 chip issue.

Since skiboot-5.10-rc2:

- phb4: Only escalate freezes on MMIO load where necessary

  In order to work around a hardware issue, MMIO load freezes were
  escalated to fences on every chip.  Now that hardware no longer requires
  this, restrict escalation to the chips that actually need it.

Since skiboot-5.9:

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

Since skiboot-5.10-rc2:

- capi: Enable channel tag streaming for PHB in CAPP mode

  We re-enable channel tag streaming for PHB in CAPP mode as without it
  PEC was waiting for cresp for each DMA write command before sending a
  new DMA write command on the Powerbus. This resulted in much lower DMA
  write performance than expected.

  The patch updates enable_capi_mode() to remove the masking of
  channel_streaming_en bit in PBCQ Hardware Configuration Register. Also
  does some re-factoring of the code that updates this register to use
  xscom_write_mask instead of xscom_read followed by a xscom_write.

Since skiboot-5.10-rc1:

- capi: Fix the max tlbi divider and the directory size.

  Switch to 512KB mode (directory size) as we don’t use bit 48 of the tag
  in addressing the array. This mode is controlled by the Snoop CAPI
  Configuration Register.
  Set the maximum of the number of data polls received before signaling
  TLBI hang detect timer expired. The value of '0000' is equal to 16.

Since skiboot-5.9:

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

Since skiboot-5.10-rc3:

- core: Fix mismatched names between reserved memory nodes & properties

  OPAL exposes reserved memory regions through the device tree in both new
  (nodes) and old (properties) formats.

  However, the names used for these don't match - we use a generated cell
  address for the nodes, but the plain region name for the properties.

  This fixes a warning from FWTS

Since skiboot-5.10-rc2:

- vas: Disable VAS/NX-842 on some P9 revisions

  VAS/NX-842 are not functional on some P9 revisions, so disable them
  in hardware and skip creating their device tree nodes.

  Since the intent is to prevent OS from configuring VAS/NX, we remove
  only the platform device nodes but leave the VAS/NX DT nodes under
  xscom (i.e we don't skip add_vas_node() in hdata/spira.c)
- core/device.c: Fix dt_find_compatible_node

  dt_find_compatible_node() and dt_find_compatible_node_on_chip() are used to
  find device nodes under a parent/root node with a given compatible
  property.

  dt_next(root, prev) is used to walk the child nodes of the given parent and
  takes two arguments - root contains the parent node to walk whilst prev
  contains the previous child to search from so that it can be used as an
  iterator over all children nodes.

  The first iteration of dt_find_compatible_node(root, prev) calls
  dt_next(root, root) which is not a well defined operation as prev is
  assumed to be child of the root node. The result is that when a node
  contains no children it will start returning the parent nodes siblings
  until it hits the top of the tree at which point a NULL derefence is
  attempted when looking for the root nodes parent.

  Dereferencing NULL can result in undesirable data exceptions during system
  boot and untimely non-hilarious system crashes. dt_next() should not be
  called with prev == root. Instead we add a check to dt_next() such that
  passing prev = NULL will cause it to start iterating from the first child
  node (if any).

  This manifested itself in a crash on boot on ZZ systems.
- hw/occ: Fix fast-reboot crash in P8 platforms.

  commit 85a1de35cbe4 ("fast-boot: occ: Re-parse the pstate table during fast-boot" )
  breaks the fast-reboot on P8 platforms while reiniting the OCC pstates. On P8
  platforms OPAL adds additional two properties #address-cells and #size-cells
  under ibm,opal/power-mgmt/ DT node. While in fast-reboot same properties adding
  back to the same node results in Duplicate properties and hence fast-reboot fails
  with below traces. ::

    [  541.410373292,5] OCC: All Chip Rdy after 0 ms
    [  541.410488745,3] Duplicate property "#address-cells" in node /ibm,opal/power-mgt
    [  541.410694290,0] Aborting!
    CPU 0058 Backtrace:
     S: 0000000031d639d0 R: 000000003001367c   .backtrace+0x48
     S: 0000000031d63a60 R: 000000003001a03c   ._abort+0x4c
     S: 0000000031d63ae0 R: 00000000300267d8   .new_property+0xd8
     S: 0000000031d63b70 R: 0000000030026a28   .__dt_add_property_cells+0x30
     S: 0000000031d63c10 R: 000000003003ea3c   .occ_pstates_init+0x984
     S: 0000000031d63d90 R: 00000000300142d8   .load_and_boot_kernel+0x86c
     S: 0000000031d63e70 R: 000000003002586c   .fast_reboot_entry+0x358
     S: 0000000031d63f00 R: 00000000300029f4   fast_reset_entry+0x2c

  This patch fixes this issue by removing these two properties on P8 while doing
  OCC pstates re-init in fast-reboot code path.

Since skiboot-5.10-rc1:

- fast-reboot: occ: Re-parse the pstate table during fast-reboot

  OCC shares the frequency list to host by copying the pstate table to
  main memory in HOMER. This table is parsed during boot to create
  device-tree properties for frequency and pstate IDs. OCC can update
  the pstate table to present a new set of frequencies to the host. But
  host will remain oblivious to these changes unless it is re-inited
  with the updated device-tree CPU frequency properties. So this patch
  allows to re-parse the pstate table and update the device-tree
  properties during fast-reboot.

  OCC updates the pstate table when asked to do so using pstate-table
  bias command. And this is mainly used by WOF team for
  characterization purposes.
- fast-reboot: move pci_reset error handling into fast-reboot code

  pci_reset() currently does a platform reboot if it fails. It
  should not know about fast-reboot at this level, so instead have
  it return an error, and the fast reboot caller will do the
  platform reboot.

  The code essentially does the same thing, but flexibility is
  improved. Ideally the fast reboot code should perform pci_reset
  and all such fail-able operations before the CPU resets itself
  and destroys its own stack. That's not the case now, but that
  should be the goal.

Since skiboot-5.9:

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

Since skiboot-5.10-rc2:

- npu2: Disable TVT range check when in bypass mode

  On POWER9 the GPUs need to be able to access the MMIO memory space. Therefore
  the TVT range check needs to include the MMIO address space. As any possible
  range check would cover all of memory anyway this patch just disables the TVT
  range check all together when bypassing the TCE tables.
- hw/npu2: support creset of npu2 devices

  creset calls in the hw procedure that resets the PHY, we don't
  take them out of reset, just put them in reset.

  this fixes a kexec issue.

Since skiboot-5.10-rc1:

- npu2/tce: Fix page size checking

  The page size is encoded in the TVT data [59:63] as @shift+11 but
  the tce_kill handler does not do the math right; this fixes it.

Since skiboot-5.9:

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

Since skiboot-5.10-rc1:

- opal-prd: Fix FTBFS with -Werror=format-overflow

  i2c.c fails to compile with gcc7 and -Werror=format-overflow used in
  Debian Unstable and Ubuntu 18.04 : ::

    i2c.c: In function ‘i2c_init’:
    i2c.c:211:15: error: ‘%s’ directive writing up to 255 bytes into a
    region of size 236 [-Werror=format-overflow=]

Since skiboot-5.9:

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

Since skiboot-5.10-rc2:

- pflash: Fix makefile dependency issue

Since skiboot-5.9:

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

Since skiboot-5.10-rc3:

- increase log verbosity in debug builds
- Add -debug to version on DEBUG builds
- cpu_wait_job: Correctly report time spent waiting for job

Since skiboot-5.10-rc2:

- ATTN: Enable flush instruction cache bit in HID register

  In P9, we have to enable "flush the instruction cache" bit along with
  "attn instruction support" bit to trigger attention.

Since skiboot-5.10-rc1:

- core/init: manage MSR[ME] explicitly, always enable

  The current boot sequence inherits MSR[ME] from the IPL firmware, and
  never changes it. Some environments disable MSR[ME] (e.g., mambo), and
  others can enable it (hostboot).

  This has two problems. First, MSR[ME] must be disabled while in the
  process of taking over the interrupt vector from the previous
  environment.  Second, after installing our machine check handler,
  MSR[ME] should be enabled to get some useful output rather than a
  checkstop.
- core/exception: beautify exception handler, add MCE-involved registers

  Print DSISR and DAR, to help with deciphering machine check exceptions,
  and improve the output a bit, decode NIP symbol, improve alignment, etc.
  Also print a specific header for machine check, because we do expect to
  see these if there is a hardware failure.

  Before: ::

    [    0.005968779,3] ***********************************************
    [    0.005974102,3] Unexpected exception 200 !
    [    0.005978696,3] SRR0 : 000000003002ad80 SRR1 : 9000000000001000
    [    0.005985239,3] HSRR0: 00000000300027b4 HSRR1: 9000000030001000
    [    0.005991782,3] LR   : 000000003002ad80 CTR  : 0000000000000000
    [    0.005998130,3] CFAR : 00000000300b58bc
    [    0.006002769,3] CR   : 40000004  XER: 20000000
    [    0.006008069,3] GPR00: 000000003002ad80 GPR16: 0000000000000000
    [    0.006015170,3] GPR01: 0000000031c03bd0 GPR17: 0000000000000000
    [...]

  After: ::

    [    0.003287941,3] ***********************************************
    [    0.003561769,3] Fatal MCE at 000000003002ad80   .nvram_init+0x24
    [    0.003579628,3] CFAR : 00000000300b5964
    [    0.003584268,3] SRR0 : 000000003002ad80 SRR1 : 9000000000001000
    [    0.003590812,3] HSRR0: 00000000300027b4 HSRR1: 9000000030001000
    [    0.003597355,3] DSISR: 00000000         DAR  : 0000000000000000
    [    0.003603480,3] LR   : 000000003002ad68 CTR  : 0000000030093d80
    [    0.003609930,3] CR   : 40000004         XER  : 20000000
    [    0.003615698,3] GPR00: 00000000300149e8 GPR16: 0000000000000000
    [    0.003622799,3] GPR01: 0000000031c03bc0 GPR17: 0000000000000000
    [...]


Since skiboot-5.9:

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

Contributors
------------

- 302 csets from 32 developers
- 3 employers found
- A total of 15919 lines added, 4786 removed (delta 11133)

Extending the analysis done for some previous releases, we can see our trends
in code review across versions:

======= ====== ======== ========= ========= ===========
Release	csets  Ack %    Reviews % Tested %  Reported %
======= ====== ======== ========= ========= ===========
5.0	329    15 (5%)  20 (6%)   1 (0%)    0 (0%)
5.1	372    13 (3%)  38 (10%)  1 (0%)    4 (1%)
5.2-rc1	334    20 (6%)  34 (10%)  6 (2%)    11 (3%)
5.3-rc1	302    36 (12%) 53 (18%)  4 (1%)    5 (2%)
5.4	361    16 (4%)  28 (8%)   1 (0%)    9 (2%)
5.5	408    11 (3%)  48 (12%)  14 (3%)   10 (2%)
5.6	87     12 (14%)  6 (7%)   5 (6%)    2 (2%)
5.7	232    30 (13%) 32 (14%)  5 (2%)    2 (1%)
5.8     157    13 (8%)  36 (23%)  2 (1%)    6 (4%)
5.9     209    15 (7%)  78 (37%)  3 (1%)    10 (5%)
5.10    302    20 (6%)  62 (21%)  24 (8%)   11 (4%)
======= ====== ======== ========= ========= ===========

The review count for v5.9 is largely bogus, there was a series of 25 whitespace
patches that got "Reviewed-by" and if we exclude them, we're back to 14%,
which is more like what I'd expect.

For 5.10, We've seen an increase in Reviewed-by from 5.9, back to closer to
5.8 levels. I'm hoping we can keep the ~20% up.

Initially I was really pleased with the increase in Tested-by, but with closer
examination, 17 of those are actually from various automated testing on
commits to code we bring in from hostboot/other firmware components. When
you exclude them, we're back down to 2% getting Tested-by, which isn't great.

Developers with the most changesets
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

========================== === =======
Developer                    # %
========================== === =======
Stewart Smith               40 (13.2%)
Nicholas Piggin             37 (12.3%)
Oliver O'Halloran           36 (11.9%)
Benjamin Herrenschmidt      23 (7.6%)
Claudio Carvalho            20 (6.6%)
Cyril Bur                   19 (6.3%)
Michael Neuling             13 (4.3%)
Shilpasri G Bhat            12 (4.0%)
Reza Arbab                  12 (4.0%)
Pridhiviraj Paidipeddi      11 (3.6%)
Vasant Hegde                10 (3.3%)
Akshay Adiga                10 (3.3%)
Mahesh Salgaonkar            8 (2.6%)
Russell Currey               7 (2.3%)
Alistair Popple              7 (2.3%)
Vaibhav Jain                 5 (1.7%)
Prem Shanker Jha             4 (1.3%)
Robert Lippert               4 (1.3%)
Frédéric Bonnard             3 (1.0%)
Christophe Lombard           3 (1.0%)
Jeremy Kerr                  2 (0.7%)
Michael Ellerman             2 (0.7%)
Balbir Singh                 2 (0.7%)
Andrew Donnellan             2 (0.7%)
Madhavan Srinivasan          2 (0.7%)
Adriana Kobylak              2 (0.7%)
Sukadev Bhattiprolu          1 (0.3%)
Alexey Kardashevskiy         1 (0.3%)
Frederic Barrat              1 (0.3%)
Ananth N Mavinakayanahalli   1 (0.3%)
Suraj Jitindar Singh         1 (0.3%)
Guilherme G. Piccoli         1 (0.3%)
========================== === =======

Developers with the most changed lines
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

========================== ==== =======
Developer                     # %
========================== ==== =======
Stewart Smith              4284 (24.5%)
Nicholas Piggin            2924 (16.7%)
Claudio Carvalho           2476 (14.2%)
Shilpasri G Bhat           1490 (8.5%)
Cyril Bur                  1475 (8.4%)
Oliver O'Halloran          1242 (7.1%)
Benjamin Herrenschmidt      736 (4.2%)
Alistair Popple             498 (2.8%)
Vasant Hegde                299 (1.7%)
Akshay Adiga                273 (1.6%)
Reza Arbab                  231 (1.3%)
Mahesh Salgaonkar           225 (1.3%)
Balbir Singh                213 (1.2%)
Frédéric Bonnard            169 (1.0%)
Michael Neuling             142 (0.8%)
Robert Lippert               97 (0.6%)
Pridhiviraj Paidipeddi       93 (0.5%)
Prem Shanker Jha             92 (0.5%)
Christophe Lombard           80 (0.5%)
Russell Currey               78 (0.4%)
Michael Ellerman             72 (0.4%)
Adriana Kobylak              71 (0.4%)
Madhavan Srinivasan          61 (0.3%)
Sukadev Bhattiprolu          58 (0.3%)
Vaibhav Jain                 52 (0.3%)
Jeremy Kerr                  27 (0.2%)
Ananth N Mavinakayanahalli   16 (0.1%)
Frederic Barrat               9 (0.1%)
Andrew Donnellan              5 (0.0%)
Alexey Kardashevskiy          3 (0.0%)
Suraj Jitindar Singh          1 (0.0%)
Guilherme G. Piccoli          1 (0.0%)
========================== ==== =======

Developers with the most lines removed
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

========================= ==== =======
Developer                    # %
========================= ==== =======
Alistair Popple            304 (6.4%)
Andrew Donnellan             1 (0.0%)
========================= ==== =======

Developers with the most signoffs
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

========================== === =======
Developer                    # %
========================== === =======
Stewart Smith              262 (99.2%)
Reza Arbab                   1 (0.4%)
Mahesh Salgaonkar            1 (0.4%)
========================== === =======

Developers with the most reviews
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

================================ ==== =======
Developer                           # %
================================ ==== =======
Andrew Donnellan                    8 (13.6%)
Balbir Singh                        5 (8.5%)
Vasant Hegde                        5 (8.5%)
Gregory S. Still                    4 (6.8%)
Nicholas Piggin                     4 (6.8%)
Reza Arbab                          3 (5.1%)
Alistair Popple                     3 (5.1%)
RANGANATHPRASAD G. BRAHMASAMUDRA    3 (5.1%)
Jennifer A. Stofer                  3 (5.1%)
Oliver O'Halloran                   3 (5.1%)
Vaidyanathan Srinivasan             2 (3.4%)
Hostboot Team                       2 (3.4%)
Christian R. Geddes                 2 (3.4%)
Frederic Barrat                     2 (3.4%)
Cyril Bur                           2 (3.4%)
Stewart Smith                       1 (1.7%)
Cédric Le Goater                    1 (1.7%)
Samuel Mendoza-Jonas                1 (1.7%)
Daniel M. Crowell                   1 (1.7%)
Vaibhav Jain                        1 (1.7%)
Madhavan Srinivasan                 1 (1.7%)
Michael Ellerman                    1 (1.7%)
Shilpasri G Bhat                    1 (1.7%)
**Total**                          59 (100%)
================================ ==== =======

Developers with the most test credits
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

=========================== == =======
Developer                    # %
=========================== == =======
FSP CI Jenkins               4 (16.7%)
Jenkins Server               4 (16.7%)
Hostboot CI                  4 (16.7%)
Oliver O'Halloran            3 (12.5%)
Jenkins OP Build CI          3 (12.5%)
Jenkins OP HW                2 (8.3%)
Pridhiviraj Paidipeddi       2 (8.3%)
Andrew Donnellan             1 (4.2%)
Vaidyanathan Srinivasan      1 (4.2%)
**Total**                   24 (100%)
=========================== == =======

Developers who gave the most tested-by credits
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

=========================== == =======
Developer                    # %
=========================== == =======
Prem Shanker Jha            17 (70.8%)
Benjamin Herrenschmidt       3 (12.5%)
Stewart Smith                2 (8.3%)
Shilpasri G Bhat             1 (4.2%)
Ananth N Mavinakayanahalli   1 (4.2%)
**Total**                   24 (100%)
=========================== == =======


Developers with the most report credits
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

=========================== == =======
Developer                    # %
=========================== == =======
Pridhiviraj Paidipeddi       2 (18.2%)
Benjamin Herrenschmidt       1 (9.1%)
Andrew Donnellan             1 (9.1%)
Michael Ellerman             1 (9.1%)
Deb McLemore                 1 (9.1%)
Brad Bishop                  1 (9.1%)
Michel Normand               1 (9.1%)
Hugo Landau                  1 (9.1%)
Minda Wei                    1 (9.1%)
Francesco A Campisano        1 (9.1%)
**Total**                   11 (100%)
=========================== == =======

Developers who gave the most report credits
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

=========================== == =======
Developer                    # %
=========================== == =======
Stewart Smith                7 (63.6%)
Suraj Jitindar Singh         1 (9.1%)
Jeremy Kerr                  1 (9.1%)
Michael Neuling              1 (9.1%)
Frédéric Bonnard             1 (9.1%)
**Total**                   11 (100%)

=========================== == =======

Changesets and Employers
^^^^^^^^^^^^^^^^^^^^^^^^

Top changeset contributors by employer:

========================== === =======
Employer                     # %
========================== === =======
IBM                        298 (98.7%)
Google                       3 (1.0%)
(Unknown)                    1 (0.3%)
========================== === =======

Top lines changed by employer:

======================== ===== =======
Employer                     # %
======================== ===== =======
IBM                      17396 (99.4%)
Google                      73 (0.4%)
(Unknown)                   24 (0.1%)
======================== ===== =======

Employers with the most signoffs (total 264):

======================== ===== =======
Employer                     # %
======================== ===== =======
IBM                        264 (100.0%)
======================== ===== =======

Employers with the most hackers (total 33)

========================== === =======
Employer                     # %
========================== === =======
IBM                         31 (93.9%)
Google                       1 (3.0%)
(Unknown)                    1 (3.0%)
========================== === =======
