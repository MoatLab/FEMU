.. _skiboot-5.11:

skiboot-5.11
============

skiboot v5.11 was released on Friday April 6th 2018. It is the first
release of skiboot 5.11, which is now the new stable release
of skiboot following the 5.10 release, first released February 23rd 2018.

It is *not* expected to keep the 5.11 branch around for long, and instead
quickly move onto a 6.0, which will mark the basis for op-build v2.0 and
will be required for POWER9 systems.

It is expected that skiboot 6.0 will follow very shortly. Consider 5.11
more of a beta release to 6.0 than anything. For POWER9 systems it should
certainly be more solid than previous releases though.

skiboot v5.11 contains all bug fixes as of :ref:`skiboot-5.10.4`
and :ref:`skiboot-5.4.9` (the currently maintained stable releases). There
may be more 5.10.x stable releases, it will depend on demand.

For how the skiboot stable releases work, see :ref:`stable-rules` for details.

Over skiboot-5.10, we have the following changes:

New Platforms
-------------

- Add VESNIN platform support

  The Vesnin platform from YADRO is a 4 socked POWER8 system with up to 8TB
  of memory with 460GB/s of memory bandwidth in only 2U. Many kudos to the
  team from Yadro for submitting their code upstream!

New Features
------------

- fast-reboot: enable by default for POWER9

  - Fast reboot is disabled if NPU2 is present or CAPI2/OpenCAPI is used

- PCI tunneled operations on PHB4

  - phb4: set PBCQ Tunnel BAR for tunneled operations

    P9 supports PCI tunneled operations (atomics and as_notify) that are
    initiated by devices.

    A subset of the tunneled operations require a response, that must be
    sent back from the host to the device. For example, an atomic compare
    and swap will return the compare status, as swap will only performed
    in case of success.  Similarly, as_notify reports if the target thread
    has been woken up or not, because the operation may fail.

    To enable tunneled operations, a device driver must tell the host where
    it expects tunneled operation responses, by setting the PBCQ Tunnel BAR
    Response register with a specific value within the range of its BARs.

    This register is currently initialized by enable_capi_mode(). But, as
    tunneled operations may also operate in PCI mode, a new API is required
    to set the PBCQ Tunnel BAR Response register, without switching to CAPI
    mode.

    This patch provides two new OPAL calls to get/set the PBCQ Tunnel
    BAR Response register.

    Note: as there is only one PBCQ Tunnel BAR register, shared between
    all the devices connected to the same PHB, only one of these devices
    will be able to use tunneled operations, at any time.
  - phb4: set PHB CMPM registers for tunneled operations

    P9 supports PCI tunneled operations (atomics and as_notify) that require
    setting the PHB ASN Compare/Mask register with a 16-bit indication.

    This register is currently initialized by enable_capi_mode(). But, as
    tunneled operations may also work in PCI mode, the ASN Compare/Mask
    register should rather be initialized in phb4_init_ioda3().

    This patch also adds "ibm,phb-indications" to the device tree, to tell
    Linux the values of CAPI, ASN, and NBW indications, when supported.

    Tunneled operations tested by IBM in CAPI mode, by Mellanox Technologies
    in PCI mode.

- Tie tm-suspend fw-feature and opal_reinit_cpus() together

  Currently opal_reinit_cpus(OPAL_REINIT_CPUS_TM_SUSPEND_DISABLED)
  always returns OPAL_UNSUPPORTED.

  This ties the tm suspend fw-feature to the
  opal_reinit_cpus(OPAL_REINIT_CPUS_TM_SUSPEND_DISABLED) so that when tm
  suspend is disabled, we correctly report it to the kernel.  For
  backwards compatibility, it's assumed tm suspend is available if the
  fw-feature is not present.

  Currently hostboot will clear fw-feature(TM_SUSPEND_ENABLED) on P9N
  DD2.1. P9N DD2.2 will set fw-feature(TM_SUSPEND_ENABLED).  DD2.0 and
  below has TM disabled completely (not just suspend).

  We are using opal_reinit_cpus() to determine this setting (rather than
  the device tree/HDAT) as some future firmware may let us change this
  dynamically after boot. That is not the case currently though.

Power Management
----------------

- SLW: Increase stop4-5 residency by 10x

  Using DGEMM benchmark we observed there was a drop of 5-9% throughput with
  and without stop4/5. In this benchmark the GPU waits on the cpu to wakeup
  and provide the subsequent data block to compute. The wakup latency
  accumulates over the run and shows up as a performance drop.

  Linux enters stop4/5 more aggressively for its wakeup latency. Increasing
  the residency from 1ms to 10ms makes the performance drop <1%
- occ: Set up OCC messaging even if we fail to setup pstates

  This means that we no longer hit this bug if we fail to get valid pstates
  from the OCC. ::

    [console-pexpect]#echo 1 > //sys/firmware/opal/sensor_groups//occ-csm0/clear
    echo 1 > //sys/firmware/opal/sensor_groups//occ-csm0/clear
    [   94.019971181,5] CPU ATTEMPT TO RE-ENTER FIRMWARE! PIR=083d cpu @0x33cf4000 -> pir=083d token=8
    [   94.020098392,5] CPU ATTEMPT TO RE-ENTER FIRMWARE! PIR=083d cpu @0x33cf4000 -> pir=083d token=8
    [   10.318805] Disabling lock debugging due to kernel taint
    [   10.318808] Severe Machine check interrupt [Not recovered]
    [   10.318812]   NIP [000000003003e434]: 0x3003e434
    [   10.318813]   Initiator: CPU
    [   10.318815]   Error type: Real address [Load/Store (foreign)]
    [   10.318817] opal: Hardware platform error: Unrecoverable Machine Check exception
    [   10.318821] CPU: 117 PID: 2745 Comm: sh Tainted: G   M             4.15.9-openpower1 #3
    [   10.318823] NIP:  000000003003e434 LR: 000000003003025c CTR: 0000000030030240
    [   10.318825] REGS: c00000003fa7bd80 TRAP: 0200   Tainted: G   M              (4.15.9-openpower1)
    [   10.318826] MSR:  9000000000201002 <SF,HV,ME,RI>  CR: 48002888  XER: 20040000
    [   10.318831] CFAR: 0000000030030258 DAR: 394a00147d5a03a6 DSISR: 00000008 SOFTE: 1


mbox based platforms
^^^^^^^^^^^^^^^^^^^^

For platforms using the mbox protocol for host flash access (all BMC based
OpenPOWER systems, most OpenBMC based systems) there have been some hardening
efforts in the event of the BMC being poorly behaved.

- mbox: Reduce default BMC timeouts

  Rebooting a BMC can take 70 seconds. Skiboot cannot possibly spin for
  70 seconds waiting for a BMC to come back. This also makes the current
  default of 30 seconds a bit pointless, is it far too short to be a
  worse case wait time but too long to avoid hitting hardlockup detectors
  and wrecking havoc inside host linux.

  Just change it to three seconds so that host linux will survive and
  that, reads and writes will fail but at least the host stays up.

  Also refactored the waiting loop just a bit so that it's easier to read.
- mbox: Harden against BMC daemon errors

  Bugs present in the BMC daemon mean that skiboot gets presented with
  mbox windows of size zero. These windows cannot be valid and skiboot
  already detects these conditions.

  Currently skiboot warns quite strongly about the occurrence of these
  problems. The problem for skiboot is that it doesn't take any action.
  Initially I wanting to avoid putting policy like this into skiboot but
  since these bugs aren't going away and skiboot barfing is leading to
  lockups and ultimately the host going down something needs to be done.

  I propose that when we detect the problem we fail the mbox call and punt
  the problem back up to Linux. I don't like it but at least it will cause
  errors to cascade and won't bring the host down. I'm not sure how Linux
  is supposed to detect this or what it can even do but this is better
  than a crash.

  Diagnosing a failure to boot if skiboot its self fails to read flash may
  be marginally more difficult with this patch. This is because skiboot
  will now only print one warning about the zero sized window rather than
  continuously spitting it out.

Fast Reboot Improvements
------------------------

Around fast-reboot we have made several improvements to harden the fast
reboot code paths and resort to a full IPL if something doesn't look right.

- core/fast-reboot: zero memory after fast reboot

  This improves the security and predictability of the fast reboot
  environment.

  There can not be a secure fence between fast reboots, because a
  malicious OS can modify the firmware itself. However a well-behaved
  OS can have a reasonable expectation that OS memory regions it has
  modified will be cleared upon fast reboot.

  The memory is zeroed after all other CPUs come up from fast reboot,
  just before the new kernel is loaded and booted into. This allows
  image preloading to run concurrently, and will allow parallelisation
  of the clearing in future.
- core/fast-reboot: verify mem regions before fast reboot

  Run the mem_region sanity checkers before proceeding with fast
  reboot.

  This is the beginning of proactive sanity checks on opal data
  for fast reboot (with complements the reactive disable_fast_reboot
  cases). This is encouraged to re-use and share any kind of debug
  code and unit test code.
- fast-reboot: occ: Only delete /ibm, opal/power-mgt nodes if they exist
- core/fast-reboot: disable fast reboot upon fundamental entry/exit/locking errors

  This disables fast reboot in several more cases where serious errors
  like lock corruption or call re-entrancy are detected.
- capp: Disable fast-reboot whenever enable_capi_mode() is called

  This patch updates phb4_set_capi_mode() to disable fast-reboot
  whenever enable_capi_mode() is called, irrespective to its return
  value. This should prevent against a possibility of not disabling
  fast-reboot when some changes to enable_capi_mode() causing return of
  an error and leaving CAPP in enabled mode.
- fast-reboot: occ: Delete OCC child nodes in /ibm, opal/power-mgt

  Fast-reboot in P8 fails to re-init OCC data as there are chipwise OCC
  nodes which are already present in the /ibm,opal/power-mgt node. These
  per-chip nodes hold the voltage IDs for each pstate and these can be
  changed on OCC pstate table biasing. So delete these before calling
  the re-init code to re-parse and populate the pstate data.

Debugging/SRESET improvemens
----------------------------

Since :ref:`skiboot-5.11-rc1`:

- core/cpu: Prevent clobbering of stack guard for boot-cpu

  Commit 90d53934c2da ("core/cpu: discover stack region size before
  initialising memory regions") introduced memzero for struct cpu_thread
  in init_cpu_thread(). This has an unintended side effect of clobbering
  the stack-guard cannery of the boot_cpu stack. This results in opal
  failing to init with this failure message: ::

    CPU: P9 generation processor (max 4 threads/core)
    CPU: Boot CPU PIR is 0x0004 PVR is 0x004e1200
    Guard skip = 0
    Stack corruption detected !
    Aborting!
    CPU 0004 Backtrace:
     S: 0000000031c13ab0 R: 0000000030013b0c   .backtrace+0x5c
     S: 0000000031c13b50 R: 000000003001bd18   ._abort+0x60
     S: 0000000031c13be0 R: 0000000030013bbc   .__stack_chk_fail+0x54
     S: 0000000031c13c60 R: 00000000300c5b70   .memset+0x12c
     S: 0000000031c13d00 R: 0000000030019aa8   .init_cpu_thread+0x40
     S: 0000000031c13d90 R: 000000003001b520   .init_boot_cpu+0x188
     S: 0000000031c13e30 R: 0000000030015050   .main_cpu_entry+0xd0
     S: 0000000031c13f00 R: 0000000030002700   boot_entry+0x1c0

  So the patch provides a fix by tweaking the memset() call in
  init_cpu_thread() to skip over the stack-guard cannery.
- core/lock.c: ensure valid start value for lock spin duration warning

  The previous fix in a8e6cc3f4 only addressed half of the problem, as
  we could also get an invalid value for start, causing us to fail
  in a weird way.

  This was caught by the testcases.OpTestHMIHandling.HMI_TFMR_ERRORS
  test in op-test-framework.

  You'd get to this part of the test and get the erroneous lock
  spinning warnings: ::

    PATH=/usr/local/sbin:$PATH putscom -c 00000000 0x2b010a84 0003080000000000
    0000080000000000
    [  790.140976993,4] WARNING: Lock has been spinning for 790275ms
    [  790.140976993,4] WARNING: Lock has been spinning for 790275ms
    [  790.140976918,4] WARNING: Lock has been spinning for 790275ms

  This patch checks the validity of timebase before setting start,
  and only checks the lock timeout if we got a valid start value.


Since :ref:`skiboot-5.10`:

- core/opal: allow some re-entrant calls

  This allows a small number of OPAL calls to succeed despite re-entering
  the firmware, and rejects others rather than aborting.

  This allows a system reset interrupt that interrupts OPAL to do something
  useful. Sreset other CPUs, use the console, which allows xmon to work or
  stack traces to be printed, reboot the system.

  Use OPAL_INTERNAL_ERROR when rejecting, rather than OPAL_BUSY, which is
  used for many other things that does not mean a serious permanent error.
- core/opal: abort in case of re-entrant OPAL call

  The stack is already destroyed by the time we get here, so there
  is not much point continuing.
- core/lock: Add lock timeout warnings

  There are currently no timeout warnings for locks in skiboot. We assume
  that the lock will eventually become free, which may not always be the
  case.

  This patch adds timeout warnings for locks. Any lock which spins for more
  than 5 seconds will throw a warning and stacktrace for that thread. This is
  useful for debugging siturations where a lock which hang, waiting for the
  lock to be freed.
- core/lock: Add deadlock detection

  This adds simple deadlock detection. The detection looks for circular
  dependencies in the lock requests. It will abort and display a stack trace
  when a deadlock occurs.
  The detection is enabled by DEBUG_LOCKS (enabled by default).
  While the detection may have a slight performance overhead, as there are
  not a huge number of locks in skiboot this overhead isn't significant.
- core/hmi: report processor recovery reason from core FIR bits on P9

  When an error is encountered that causes processor recovery, HMI is
  generated if the recovery was successful. The reason is recorded in
  the core FIR, which gets copied into the WOF.

  In this case dump the WOF register and an error string into the OPAL
  msglog.

  A broken init setting led to HMIs reported in Linux as: ::

    [    3.591547] Harmless Hypervisor Maintenance interrupt [Recovered]
    [    3.591648]  Error detail: Processor Recovery done
    [    3.591714]  HMER: 2040000000000000

  This patch would have been useful because it tells us exactly that
  the problem is in the d-side ERAT: ::

    [  414.489690798,7] HMI: Received HMI interrupt: HMER = 0x2040000000000000
    [  414.489693339,7] HMI: [Loc: UOPWR.0000000-Node0-Proc0]: P:0 C:1 T:1: Processor recovery occurred.
    [  414.489699837,7] HMI: Core WOF = 0x0000000410000000 recovered error:
    [  414.489701543,7] HMI: LSU - SRAM (DCACHE parity, etc)
    [  414.489702341,7] HMI: LSU - ERAT multi hit

  In future it will be good to unify this reporting, so Linux could
  print something more useful. Until then, this gives some good data.

NPU2/NVLink2 Fixes
------------------
- npu2: Add performance tuning SCOM inits

  Peer-to-peer GPU bandwidth latency testing has produced some tunable
  values that improve performance. Add them to our device initialization.

  File these under things that need to be cleaned up with nice #defines
  for the register names and bitfields when we get time.

  A few of the settings are dependent on the system's particular NVLink
  topology, so introduce a helper to determine how many links go to a
  single GPU.
- hw/npu2: Assign a unique LPARSHORTID per GPU

  This gets used elsewhere to index items in the XTS tables.
- NPU2: dump NPU2 registers on npu2 HMI

  Due to the nature of debugging npu2 issues, folk are wanting the
  full list of NPU2 registers dumped when there's a problem.
- npu2: Remove DD1 support

  Major changes in the NPU between DD1 and DD2 necessitated a fair bit of
  revision-specific code.

  Now that all our lab machines are DD2, we no longer test anything on DD1
  and it's time to get rid of it.

  Remove DD1-specific code and abort probe if we're running on a DD1 machine.
- npu2: Disable fast reboot

  Fast reboot does not yet work right with the NPU. It's been disabled on
  NVLink and OpenCAPI machines. Do the same for NVLink2.

  This amounts to a port of 3e4577939bbf ("npu: Fix broken fast reset")
  from the npu code to npu2.
- npu2: Use unfiltered mode in XTS tables

  The XTS_PID context table is limited to 256 possible pids/contexts. To
  relieve this limitation, make use of "unfiltered mode" instead.

  If an entry in the XTS_BDF table has the bit for unfiltered mode set, we
  can just use one context for that entire bdf/lpar, regardless of pid.
  Instead of of searching the XTS_PID table, the NMMU checkout request
  will simply use the entry indexed by lparshort id instead.

  Change opal_npu_init_context() to create these lparshort-indexed
  wildcard entries (0-15) instead of allocating one for each pid. Check
  that multiple calls for the same bdf all specify the same msr value.

  In opal_npu_destroy_context(), continue validating the bdf argument,
  ensuring that it actually maps to an lpar, but no longer remove anything
  from the XTS_PID table. If/when we start supporting virtualized GPUs, we
  might consider actually removing these wildcard entries by keeping a
  refcount, but keep things simple for now.

CAPI/OpenCAPI
-------------

Since :ref:`skiboot-5.11-rc1`:

- capi: Poll Err/Status register during CAPP recovery

  This patch updates do_capp_recovery_scoms() to poll the CAPP
  Err/Status control register, check for CAPP-Recovery to complete/fail
  based on indications of BITS-1,5,9 and then proceed with the
  CAPP-Recovery scoms iif recovery completed successfully. This would
  prevent cases where we bring-up the PCIe link while recovery sequencer
  on CAPP is still busy with casting out cache lines.

  In case CAPP-Recovery didn't complete successfully an error is returned
  from do_capp_recovery_scoms() asking phb4_creset() to keep the phb4
  fenced and mark it as broken.

  The loop that implements polling of Err/Status register will also log
  an error on the PHB when it continues for more than 168ms which is the
  max time to failure for CAPP-Recovery.

Since :ref:`skiboot-5.10`:

- npu2-opencapi: Add OpenCAPI OPAL API calls

  Add three OPAL API calls that are required by the ocxl driver.

  - OPAL_NPU_SPA_SETUP

    The Shared Process Area (SPA) is a table containing one entry (a
    "Process Element") per memory context which can be accessed by the
    OpenCAPI device.

  - OPAL_NPU_SPA_CLEAR_CACHE

    The NPU keeps a cache of recently accessed memory contexts. When a
    Process Element is removed from the SPA, the cache for the link must be
    cleared.

  - OPAL_NPU_TL_SET

    The Transaction Layer specification defines several templates for
    messages to be exchanged on the link. During link setup, the host and
    device must negotiate what templates are supported on both sides and at
    what rates those messages can be sent.
- npu2-opencapi: Train OpenCAPI links and setup devices

  Scan the OpenCAPI links under the NPU, and for each link, reset the card,
  set up a device, train the link and register a PHB.

  Implement the necessary operations for the OpenCAPI PHB type.

  For bringup, test and debug purposes, we allow an NVRAM setting,
  "opencapi-link-training" that can be set to either disable link training
  completely or to use the prbs31 test pattern.

  To disable link training: ::

    nvram -p ibm,skiboot --update-config opencapi-link-training=none

  To use prbs31: ::

    nvram -p ibm,skiboot --update-config opencapi-link-training=prbs31
- npu2-hw-procedures: Add support for OpenCAPI PHY link training

  Unlike NVLink, which uses the pci-virt framework to fake a PCI
  configuration space for NVLink devices, the OpenCAPI device model presents
  us with a real configuration space handled by the device over the OpenCAPI
  link.

  As a result, we have to train the OpenCAPI link in skiboot before we do PCI
  probing, so that config space can be accessed, rather than having link
  training being triggered by the Linux driver.
- npu2-opencapi: Configure NPU for OpenCAPI

  Scan the device tree for NPUs with OpenCAPI links and configure the NPU per
  the initialisation sequence in the NPU OpenCAPI workbook.
- capp: Make error in capp timebase sync a non-fatal error

  Presently when we encounter an error while synchronizing capp timebase
  with chip-tod at the end of enable_capi_mode() we return an
  error. This has an to unintended consequences. First this will prevent
  disabling of fast-reboot even though CAPP is already enabled by this
  point. Secondly, failure during timebase sync is a non fatal error or
  capp initialization as CAPP/PSL can continue working after this and an
  AFU will only see an error when it tries to read the timebase value
  from PSL.

  So this patch updates enable_capi_mode() to not return an error in
  case call to chiptod_capp_timebase_sync() fails. The function will now
  just log an error and continue further with capp init sequence. This
  make the current implementation align with the one in kernel 'cxl'
  driver which also assumes the PSL timebase sync errors as non-fatal
  init error.
- npu2-opencapi: Fix assert on link reset during init

  We don't support resetting an opencapi link yet.

  Commit fe6d86b9 ("pci: Make fast reboot creset PHBs in parallel")
  tries resetting any PHB whose slot defines a 'run_sm' callback. It
  raises an assert when applied to an opencapi PHB, as 'run_sm' calls
  the 'freset' callback, which is not yet defined for opencapi.

  Fix it for now by removing the currently useless definition of
  'run_sm' on the opencapi slot. It will print a message in the skiboot
  log because the PHB cannot be reset, which is correct. It will all go
  away when we add support for resetting an opencapi link.
- capp: Add lid definition for P9 DD-2.2

  Update fsp_lid_map to include CAPP ucode lid for phb4-chipid ==
  0x202d1 that corresponds to P9 DD-2.2 chip.
- capp: Disable fast-reboot when capp is enabled


PCI
---

Since :ref:`skiboot-5.11-rc1`:

- phb4: Reset FIR/NFIR registers before PHB4 probe

  The function phb4_probe_stack() resets "ETU Reset Register" to
  unfreeze the PHB before it performs mmio access on the PHB. However in
  case the FIR/NFIR registers are set while entering this function,
  the reset of "ETU Reset Register" wont unfreeze the PHB and it will
  remain fenced. This leads to failure during initial CRESET of the PHB
  as mmio access is still not enabled and an error message of the form
  below is logged: ::

     PHB#0000[0:0]: Initializing PHB4...
     PHB#0000[0:0]: Default system config: 0xffffffffffffffff
     PHB#0000[0:0]: New system config    : 0xffffffffffffffff
     PHB#0000[0:0]: Initial PHB CRESET is 0xffffffffffffffff
     PHB#0000[0:0]: Waiting for DLP PG reset to complete...
     <snip>
     PHB#0000[0:0]: Timeout waiting for DLP PG reset !
     PHB#0000[0:0]: Initialization failed

  This is especially seen happening during the MPIPL flow where SBE
  would quiesces and fence the PHB so that it doesn't stomp on the main
  memory. However when skiboot enters phb4_probe_stack() after MPIPL,
  the FIR/NFIR registers are set forcing PHB to re-enter fence after ETU
  reset is done.

  So to fix this issue the patch introduces new xscom writes to
  phb4_probe_stack() to reset the FIR/NFIR registers before performing
  ETU reset to enable mmio access to the PHB.

Since :ref:`skiboot-5.10`:

- pci: Reduce log level of error message

  If a link doesn't train, we can end up with error messages like this: ::

    [   63.027261959,3] PHB#0032[8:2]: LINK: Timeout waiting for electrical link
    [   63.027265573,3] PHB#0032:00:00.0 Error -6 resetting

  The first message is useful but the second message is just debug from
  the core PCI code and is confusing to print to the console.

  This reduces the second print to debug level so it's not seen by the
  console by default.
- Revert "platforms/astbmc/slots.c: Allow comparison of bus numbers when matching slots"

  This reverts commit bda7cc4d0354eb3f66629d410b2afc08c79f795f.

  Ben says:
  It's on purpose that we do NOT compare the bus numbers,
  they are always 0 in the slot table
  we do a hierarchical walk of the tree, matching only the
  devfn's along the way bcs the bus numbering isn't fixed
  this breaks all slot naming etc... stuff on anything using
  the "skiboot" slot tables (P8 opp typically)
- core/pci-dt-slot: Fix booting with no slot map

  Currently if you don't have a slot map in the device tree in
  /ibm,pcie-slots, you can crash with a back trace like this: ::

    CPU 0034 Backtrace:
     S: 0000000031cd3370 R: 000000003001362c   .backtrace+0x48
     S: 0000000031cd3410 R: 0000000030019e38   ._abort+0x4c
     S: 0000000031cd3490 R: 000000003002760c   .exception_entry+0x180
     S: 0000000031cd3670 R: 0000000000001f10 *
     S: 0000000031cd3850 R: 00000000300b4f3e * cpu_features_table+0x1d9e
     S: 0000000031cd38e0 R: 000000003002682c   .dt_node_is_compatible+0x20
     S: 0000000031cd3960 R: 0000000030030e08   .map_pci_dev_to_slot+0x16c
     S: 0000000031cd3a30 R: 0000000030091054   .dt_slot_get_slot_info+0x28
     S: 0000000031cd3ac0 R: 000000003001e27c   .pci_scan_one+0x2ac
     S: 0000000031cd3ba0 R: 000000003001e588   .pci_scan_bus+0x70
     S: 0000000031cd3cb0 R: 000000003001ee74   .pci_scan_phb+0x100
     S: 0000000031cd3d40 R: 0000000030017ff0   .cpu_process_jobs+0xdc
     S: 0000000031cd3e00 R: 0000000030014cb0   .__secondary_cpu_entry+0x44
     S: 0000000031cd3e80 R: 0000000030014d04   .secondary_cpu_entry+0x34
     S: 0000000031cd3f00 R: 0000000030002770   secondary_wait+0x8c
    [   73.016947149,3] Fatal MCE at 0000000030026054   .dt_find_property+0x30
    [   73.017073254,3] CFAR : 0000000030026040
    [   73.017138048,3] SRR0 : 0000000030026054 SRR1 : 9000000000201000
    [   73.017198375,3] HSRR0: 0000000000000000 HSRR1: 0000000000000000
    [   73.017263210,3] DSISR: 00000008         DAR  : 7c7b1b7848002524
    [   73.017352517,3] LR   : 000000003002602c CTR  : 000000003009102c
    [   73.017419778,3] CR   : 20004204         XER  : 20040000
    [   73.017502425,3] GPR00: 000000003002682c GPR16: 0000000000000000
    [   73.017586924,3] GPR01: 0000000031c23670 GPR17: 0000000000000000
    [   73.017643873,3] GPR02: 00000000300fd500 GPR18: 0000000000000000
    [   73.017767091,3] GPR03: fffffffffffffff8 GPR19: 0000000000000000
    [   73.017855707,3] GPR04: 00000000300b3dc6 GPR20: 0000000000000000
    [   73.017943944,3] GPR05: 0000000000000000 GPR21: 00000000300bb6d2
    [   73.018024709,3] GPR06: 0000000031c23910 GPR22: 0000000000000000
    [   73.018117716,3] GPR07: 0000000031c23930 GPR23: 0000000000000000
    [   73.018195974,3] GPR08: 0000000000000000 GPR24: 0000000000000000
    [   73.018278350,3] GPR09: 0000000000000000 GPR25: 0000000000000000
    [   73.018353795,3] GPR10: 0000000000000028 GPR26: 00000000300be6fb
    [   73.018424362,3] GPR11: 0000000000000000 GPR27: 0000000000000000
    [   73.018533159,3] GPR12: 0000000020004208 GPR28: 0000000030767d38
    [   73.018642725,3] GPR13: 0000000031c20000 GPR29: 00000000300b3dc6
    [   73.018737925,3] GPR14: 0000000000000000 GPR30: 0000000000000010
    [   73.018794428,3] GPR15: 0000000000000000 GPR31: 7c7b1b7848002514

  This has been seen in the lab on a witherspoon using the device tree
  entry point (ie. no HDAT).

  This fixes the null pointer deref.

Bugs Fixed
----------
Since :ref:`skiboot-5.11-rc1`:

- cpufeatures: Fix setting DARN and SCV HWCAP feature bits

  DARN and SCV has been assigned AT_HWCAP2 (32-63) bits: ::

    #define PPC_FEATURE2_DARN               0x00200000 /* darn random number insn */
    #define PPC_FEATURE2_SCV                0x00100000 /* scv syscall */

  A cpufeatures-aware OS will not advertise these to userspace without
  this patch.
- xive: disable store EOI support

  Hardware has limitations which would require to put a sync after each
  store EOI to make sure the MMIO operations that change the ESB state
  are ordered. This is a killer for performance and the PHBs do not
  support the sync. So remove the store EOI for the moment, until
  hardware is improved.

  Also, while we are at changing the XIVE source flags, let's fix the
  settings for the PHB4s which should follow these rules :

  - SHIFT_BUG    for DD10
  - STORE_EOI    for DD20 and if enabled
  - TRIGGER_PAGE for DDx0 and if not STORE_EOI

Since :ref:`skiboot-5.10`:

- xive: fix opal_xive_set_vp_info() error path

  In case of error, opal_xive_set_vp_info() will return without
  unlocking the xive object. This is most certainly a typo.
- hw/imc: don't access homer memory if it was not initialised

  This can happen under mambo, at least.
- nvram: run nvram_validate() after nvram_reformat()

  nvram_reformat() sets nvram_valid = true, but it does not set
  skiboot_part_hdr. Call nvram_validate() instead, which sets
  everything up properly.
- dts: Zero struct to avoid using uninitialised value
- hw/imc: Don't dereference possible NULL
- libstb/create-container: munmap() signature file address
- npu2-opencapi: Fix memory leak
- npu2: Fix possible NULL dereference
- occ-sensors: Remove NULL checks after dereference
- core/ipmi-opal: Add interrupt-parent property for ipmi node on P9 and above.

  dtc complains below warning with newer 4.2+ kernels. ::

    dts: Warning (interrupts_property): Missing interrupt-parent for /ibm,opal/ipmi

  This fix adds interrupt-parent property under /ibm,opal/ipmi DT node on P9
  and above, which allows ipmi-opal to properly use the OPAL irqchip.

Other fixes and improvements
----------------------------

- core/cpu: discover stack region size before initialising memory regions

  Stack allocation first allocates a memory region sized to hold stacks
  for all possible CPUs up to the maximum PIR of the architecture, zeros
  the region, then initialises all stacks. Max PIR is 32768 on POWER9,
  which is 512MB for stacks.

  The stack region is then shrunk after CPUs are discovered, but this is
  a bit of a hack, and it leaves a hole in the memory allocation regions
  as it's done after mem regions are initialised. ::

      0x000000000000..00002fffffff : ibm,os-reserve - OS
      0x000030000000..0000303fffff : ibm,firmware-code - OPAL
      0x000030400000..000030ffffff : ibm,firmware-heap - OPAL
      0x000031000000..000031bfffff : ibm,firmware-data - OPAL
      0x000031c00000..000031c0ffff : ibm,firmware-stacks - OPAL
      *** gap ***
      0x000051c00000..000051d01fff : ibm,firmware-allocs-memory@0 - OPAL
      0x000051d02000..00007fffffff : ibm,firmware-allocs-memory@0 - OS
      0x000080000000..000080b3cdff : initramfs - OPAL
      0x000080b3ce00..000080b7cdff : ibm,fake-nvram - OPAL
      0x000080b7ce00..0000ffffffff : ibm,firmware-allocs-memory@0 - OS

  This change moves zeroing into the per-cpu stack setup. The boot CPU
  stack is set up based on the current PIR. Then the size of the stack
  region is set, by discovering the maximum PIR of the system from the
  device tree, before mem regions are intialised.

  This results in all memory being accounted within memory regions,
  and less memory fragmentation of OPAL allocations.
- Make gard display show that a record is cleared

  When clearing gard records, Hostboot only modifies the record_id
  portion to be 0xFFFFFFFF.  The remainder of the entry remains.
  Without this change it can be confusing to users to know that
  the record they are looking at is no longer valid.
- Reserve OPAL API number for opal_handle_hmi2 function.
- dts: spl_wakeup: Remove all workarounds in the spl wakeup logic

  We coded few workarounds in special wakeup logic to handle the
  buggy firmware. Now that is fixed remove them as they break the
  special wakeup protocol. As per the spec we should not de-assert
  beofre assert is complete. So follow this protocol.
- build: use thin archives rather than incremental linking

  This changes to build system to use thin archives rather than
  incremental linking for built-in.o, similar to recent change to Linux.
  built-in.o is renamed to built-in.a, and is created as a thin archive
  with no index, for speed and size. All built-in.a are aggregated into
  a skiboot.tmp.a which is a thin archive built with an index, making it
  suitable or linking. This is input into the final link.

  The advantags of build size and linker code placement flexibility are
  not as great with skiboot as a bigger project like Linux, but it's a
  conceptually better way to build, and is more compatible with link
  time optimisation in toolchains which might be interesting for skiboot
  particularly for size reductions.

  Size of build tree before this patch is 34.4MB, afterwards 23.1MB.
- core/init: Assert when kernel not found

  If the kernel doesn't load out of flash or there is nothing at
  KERNEL_LOAD_BASE, we end up with an esoteric message as we try to
  branch to out of skiboot into nothing ::

      [    0.007197688,3] INIT: ELF header not found. Assuming raw binary.
      [    0.014035267,5] INIT: Starting kernel at 0x0, fdt at 0x3044ad90 13029
      [    0.014042254,3] ***********************************************
      [    0.014069947,3] Fatal Exception 0xe40 at 0000000000000000
      [    0.014085574,3] CFAR : 00000000300051c4
      [    0.014090118,3] SRR0 : 0000000000000000 SRR1 : 0000000000000000
      [    0.014096243,3] HSRR0: 0000000000000000 HSRR1: 9000000000001000
      [    0.014102546,3] DSISR: 00000000         DAR  : 0000000000000000
      [    0.014108538,3] LR   : 00000000300144c8 CTR  : 0000000000000000
      [    0.014114756,3] CR   : 40002202         XER  : 00000000
      [    0.014120301,3] GPR00: 000000003001447c GPR16: 0000000000000000

  This improves the message and asserts in this case: ::

    [    0.014042685,5] INIT: Starting kernel at 0x0, fdt at 0x3044ad90 13049 bytes)
    [    0.014049556,0] FATAL: Kernel is zeros, can't execute!
    [    0.014054237,0] Assert fail: core/init.c:566:0
    [    0.014060472,0] Aborting!
- core: Fix 'opal-runtime-size' property

  We are populating 'opal-runtime-size' before calculating actual stack size.
  Hence we endup having wrong runtime size (ex: on P9 it shows ~540MB while
  actual size is around ~40MB). Note that only device tree property is shows
  wrong value, but reserved-memory reflects correct size.

  init_all_cpus() calculates and updates actual stack size. Hence move this
  function call before add_opal_node().

- mambo: Add fw-feature flags for security related settings

  Newer firmwares report some feature flags related to security
  settings via HDAT. On real hardware skiboot translates these into
  device tree properties. For testing purposes just create the
  properties manually in the tcl.

  These values don't exactly match any actual chip revision, but the
  code should not rely on any exact set of values anyway. We just define
  the most interesting flags, that if toggled to "disable" will change
  Linux behaviour. You can see the actual values in the hostboot source
  in src/usr/hdat/hdatiplparms.H.

  Also add an environment variable for easily toggling the top-level
  "security on" setting.
- direct-controls: mambo fix for multiple chips
- libflash/blocklevel: Correct miscalculation in blocklevel_smart_erase()

  If blocklevel_smart_erase() detects that the smart erase fits entire in
  one erase block, it has an early bail path. In this path it miscaculates
  where in the buffer the backend needs to read from to perform the final
  write.
- libstb/secureboot: Fix logging of secure verify messages.

  Currently we are logging secure verify/enforce messages in PR_EMERG
  level even when there is no secureboot mode enabled. So reduce the
  log level to PR_ERR when secureboot mode is OFF.

Testing / Code coverage improvements
------------------------------------

Improvements in gcov support include support for newer GCCs as well
as easily exporting the area of memory you need to dump to feed to
`extract-gcov`.

- cpu_idle_job: relax a bit

  This *dramatically* improves kernel boot time with GCOV builds

  from ~3minutes between loading kernel and switching the HILE
  bit down to around 10 seconds.
- gcov: Another GCC, another gcov tweak
- Keep constructors with priorities

  Fixes GCOV builds with gcc7, which uses this.
- gcov: Add gcov data struct to sysfs

  Extracting the skiboot gcov data is currently a tedious process which
  involves taking a mem dump of skiboot and searching for the gcov_info
  struct.
  This patch adds the gcov struct to sysfs under /opal/exports. Allowing the
  data to be copied directly into userspace and processed.

