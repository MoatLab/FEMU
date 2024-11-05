.. _skiboot-5.9:

skiboot-5.9
===========

skiboot v5.9 was released on Tuesday October 31st 2017. It is the first
release of skiboot 5.9 and becomes the new stable release
of skiboot following the 5.8 release, first released August 31st 2017.
In this cyle we have had five release candidate releases, mostly centered
around bug fixing for POWER9 platforms.

This release should be considered suitable for early-access POWER9 systems.

skiboot v5.9 contains all bug fixes as of :ref:`skiboot-5.4.8`
and :ref:`skiboot-5.1.21` (the currently maintained stable releases).
There may be some 5.9.x stable releases, depending on what issues are found.

For how the skiboot stable releases work, see :ref:`stable-rules` for details.

Over :ref:`skiboot-5.8`, we have the following changes:

New Features
------------

POWER8
^^^^^^
- fast-reset by default (if possible)

  Currently, this is limited to POWER8 systems.

  A normal reboot will, rather than doing a full IPL, go through a
  fast reboot procedure. This reduces the "reboot to petitboot" time
  from minutes to a handful of seconds.

POWER9
^^^^^^

Since :ref:`skiboot-5.9-rc3`:

- occ-sensors : Add OCC inband sensor region to exports
  (useful for debugging)

Two SRESET fixes (see below for feature description):

- core: direct-controls: Fix clearing of special wakeup

  'special_wakeup_count' is incremented on successfully asserting
  special wakeup. So we will never clear the special wakeup if we
  check 'special_wakeup_count' to be zero. Fix this issue by checking
  the 'special_wakeup_count' to 1 in dctl_clear_special_wakeup().
- core/direct-controls: increase special wakeup timeout on POWER9

  Some instances have been observed where the special wakeup assert
  times out. The current timeout is too short for deeper sleep states.
  Hostboot uses 100ms, so match that.


Since :ref:`skiboot-5.9-rc2`:
- cpu: Add OPAL_REINIT_CPUS_TM_SUSPEND_DISABLED

  Add a new CPU reinit flag, "TM Suspend Disabled", which requests that
  CPUs be configured so that TM (Transactional Memory) suspend mode is
  disabled.

  Currently this always fails, because skiboot has no way to query the
  state. A future hostboot change will add a mechanism for skiboot to
  determine the status and return an appropriate error code.

Since :ref:`skiboot-5.8`:

- POWER9 power management during boot

  Less power should be consumed during boot.
- OPAL_SIGNAL_SYSTEM_RESET for POWER9

  This implements OPAL_SIGNAL_SYSTEM_RESET, using scom registers to
  quiesce the target thread and raise a system reset exception on it.
  It has been tested on DD2 with stop0 ESL=0 and ESL=1 shallow power
  saving modes.

  DD1 is not implemented because it is sufficiently different as to
  make support difficult.
- Enable deep idle states for POWER9

  - SLW: Add support for p9_stop_api

    p9_stop_api's are used to set SPR state on a core wakeup form a  deeper
    low power state. p9_stop_api uses  low level platform formware and
    self-restore microcode to restore the sprs to requested values.

    Code is taken from :
    https://github.com/open-power/hostboot/tree/master/src/import/chips/p9/procedures/utils/stopreg
  - SLW: Removing timebase related flags for stop4

    When a core enters stop4, it does not loose decrementer and time base.
    Hence removing flags OPAL_PM_DEC_STOP and OPAL_PM_TIMEBASE_STOP.
  - SLW: Allow deep states if homer address is known

    Use a common variable has_wakeup_engine instead of has_slw to tell if
    the:
    - SLW image is populated in case of power8
    - CME image is populated in case of power9

    Currently we expect CME to be loaded if homer address is known ( except
    for simulators)
  - SLW: Configure self-restore for HRMOR

    Make a stop api call using libpore to restore HRMOR register. HRMOR needs
    to be cleared so that when thread exits stop, they arrives at linux
    system_reset vector (0x100).
  - SLW: Add opal_slw_set_reg support for power9

    This OPAL call is made from Linux to OPAL to configure values in
    various SPRs after wakeup from a deep idle state.
- PHB4: CAPP recovery

  CAPP recovery is initiated when a CAPP Machine Check is detected.
  The capp recovery procedure is initiated via a Hypervisor Maintenance
  interrupt (HMI).

  CAPP Machine Check may arise from either an error that results in a PHB
  freeze or from an internal CAPP error with CAPP checkstop FIR action.
  An error that causes a PHB freeze will result in the link down signal
  being asserted. The system continues running and the CAPP and PSL will
  be re-initialized.

  This implements CAPP recovery for POWER9 systems
- Add ``wafer-location`` property for POWER9

  Extract wafer-location from ECID and add property under xscom node.
  - bits  64:71 are the chip x location (7:0)
  - bits  72:79 are the chip y location (7:0)

  Sample output: ::

    [root@wsp xscom@623fc00000000]# lsprop ecid
    ecid             019a00d4 03100718 852c0000 00fd7911
    [root@wsp xscom@623fc00000000]# lsprop wafer-location
    wafer-location   00000085 0000002c
- Add ``wafer-id`` property for POWER9

  Wafer id is derived from ECID data.
  - bits   4:63 are the wafer id ( ten 6 bit fields each containing a code)

  Sample output: ::

    [root@wsp xscom@623fc00000000]# lsprop ecid
    ecid             019a00d4 03100718 852c0000 00fd7911
    [root@wsp xscom@623fc00000000]# lsprop wafer-id
    wafer-id         "6Q0DG340SO"
- Add ``ecid`` property under ``xscom`` node for POWER9.
  Sample output: ::

    [root@wsp xscom@623fc00000000]# lsprop ecid
    ecid             019a00d4 03100718 852c0000 00fd7911
- Add ibm,firmware-versions device tree node

  In P8, hostboot provides mini device tree. It contains ``/ibm,firmware-versions``
  node which has various firmware component version details.

  In P9, OPAL is building device tree. This patch adds support to parse VERSION
  section of PNOR and create ``/ibm,firmware-versions`` device tree node.

  Sample output: ::

            /sys/firmware/devicetree/base/ibm,firmware-versions # lsprop .
            occ              "6a00709"
            skiboot          "v5.7-rc1-p344fb62"
            buildroot        "2017.02.2-7-g23118ce"
            capp-ucode       "9c73e9f"
            petitboot        "v1.4.3-p98b6d83"
            sbe              "02021c6"
            open-power       "witherspoon-v1.17-128-gf1b53c7-dirty"
            ....
            ....

POWER9
------
Since :ref:`skiboot-5.9-rc5`:

- Suppress XSCOM chiplet-offline errors on P9

  Workaround on P9: PRD does operations it *knows* will fail with this
  error to work around a hardware issue where accesses via the PIB
  (FSI or OCC) work as expected, accesses via the ADU (what xscom goes
  through) do not. The chip logic will always return all FFs if there
  is any error on the scom.
- asm/head: initialize preferred DSCR value

  POWER7/8 use DSCR=0. POWER9 preferred value has "stride-N" enabled.

Since :ref:`skiboot-5.9-rc4`:
- opal/hmi: Workaround Power9 hw logic bug for couple of TFMR TB errors.
- opal/hmi: Fix TB reside and HDEC parity error recovery for power9

Since :ref:`skiboot-5.9-rc2`:
- hw/imc: Fix IMC Catalog load for DD2.X processors

Since :ref:`skiboot-5.9-rc1`:
- xive: Fix VP free block group mode false-positive parameter check

  The check to ensure the buddy allocation idx is aligned to its
  allocation order was not taking into account the allocation split.
  This would result in opal_xive_free_vp_block failures despite
  giving the same value as returned by opal_xive_alloc_vp_block.

  E.g., starting then stopping 4 KVM guests gives the following pattern
  in the host: ::

      opal_xive_alloc_vp_block(5)=0x45000020
      opal_xive_alloc_vp_block(5)=0x45000040
      opal_xive_alloc_vp_block(5)=0x45000060
      opal_xive_alloc_vp_block(5)=0x45000080
      opal_xive_free_vp_block(0x45000020)=-1
      opal_xive_free_vp_block(0x45000040)=0
      opal_xive_free_vp_block(0x45000060)=-1
      opal_xive_free_vp_block(0x45000080)=0

- hw/imc: pause microcode at boot

  IMC nest counters has both in-band (ucode access) and out of
  band access to it. Since not all nest counter configurations
  are supported by ucode, out of band tools are used to characterize
  other configuration.

  So it is prefer to pause the nest microcode at boot to aid the
  nest out of band tools. If the ucode not paused and OS does not
  have IMC driver support, then out to band tools will race with
  ucode and end up getting undesirable values. Patch to check and
  pause the ucode at boot.

  OPAL provides APIs to control IMC counters. OPAL_IMC_COUNTERS_INIT
  is used to initialize these counters at boot. OPAL_IMC_COUNTERS_START
  and OPAL_IMC_COUNTERS_STOP API calls should be used to start and pause
  these IMC engines. `doc/opal-api/opal-imc-counters.rst` details the
  OPAL APIs and their usage.
- hdata/i2c: update the list of known i2c devs

  This updates the list of known i2c devices - as of HDAT spec v10.5e - so
  that they can be properly identified during the hdat parsing.
- hdata/i2c: log unknown i2c devices

  An i2c device is unknown if either the i2c device list is outdated or
  the device is marked as unknown (0xFF) in the hdat.

Since :ref:`skiboot-5.8`:

- Disable Transactional Memory on Power9 DD 2.1

  Update pa_features_p9[] to disable TM (Transactional Memory). On DD 2.1
  TM is not usable by Linux without other workarounds, so skiboot must
  disable it.
- xscom: Do not print error message for 'chiplet offline' return values

  xscom_read/write operations returns CHIPLET_OFFLINE when chiplet is offline.
  Some multicast xscom_read/write requests from HBRT results in xscom operation
  on offline chiplet(s) and printing below warnings in OPAL console: ::

    [ 135.036327572,3] XSCOM: Read failed, ret = -14
    [ 135.092689829,3] XSCOM: Read failed, ret = -14

  Some SCOM users can deal correctly with this error code (notably opal-prd),
  so the error message is (in practice) erroneous.
- IMC: Fix the core_imc_event_mask

  CORE_IMC_EVENT_MASK is a scom that contains bits to control event sampling for
  different machine state for core imc. The current event-mask setting sample
  events only on host kernel (hypervisor) and host userspace.

  Patch to enable the sampling of events in other machine states (like guest
  kernel and guest userspace).
- IMC: Update the nest_pmus array with occ/gpe microcode uav updates

  OOC/gpe nest microcode maintains the list of individual nest units
  supported. Sync the recent updates to the UAV with nest_pmus array.

  For reference occ/gpr microcode link for the UAV:
  https://github.com/open-power/occ/blob/master/src/occ_gpe1/gpe1_24x7.h
- Parse IOSLOT information from HDAT

  Add structure definitions that describe the physical PCIe topology of
  a system and parse them into the device-tree based PCIe slot
  description.
- idle: user context state loss flags fix for stop states

  The "lite" stop variants with PSSCR[ESL]=PSSCR[EC]=1 do not lose user
  context, while the non-lite variants do (ESL: enable state loss).

  Some of the POWER9 idle states had these wrong.

CAPI
^^^^
- POWER9 DD2 update

  The CAPI initialization sequence has been updated in DD2.
  This patch adapts to the changes, retaining compatibility with DD1.
  The patch includes some changes to DD1 fix-ups as well.
- Load CAPP microcode for POWER9 DD2.0 and DD2.1
- capi: Mask Psl Credit timeout error for POWER9

  Mask the PSL credit timeout error in CAPP FIR Mask register
  bit(46). As per the h/w team this error is now deprecated and shouldn't
  cause any fir-action for P9.

NVLINK2
^^^^^^^

A notabale change is that we now generate the device tree description of
NVLINK based on the HDAT we get from hostboot. Since Hostboot will generate
HDAT based on VPD, you now *MUST* have correct VPD programmed or we will
*default* to a Sequoia layout, which will lead to random problems if you
are not booting a Sequoia Witherspoon planar. In the case of booting with
old VPD and/or Hostboot, we print a **giant scary warning** in order to scare you.

Since :ref:`skiboot-5.9-rc2`:
- Revert "npu2: Add vendor cap for IRQ testing"

  This reverts commit 9817c9e29b6fe00daa3a0e4420e69a97c90eb373 which seems to
  break setting the PCI dev flag and the link number in the PCIe vendor
  specific config space. This leads to the device driver attempting to
  re-init the DL when it shouldn't which can cause HMI's.

Since :ref:`skiboot-5.8`:

- npu2: Read slot label from the HDAT link node

  Binding GPU to emulated NPU PCI devices is done using the slot labels
  since the NPU devices do not have a patching slot node we need to
  copy the label in here.

- npu2: Copy link speed from the npu HDAT node

  This needs to be in the PCI device node so the speed of the NVLink
  can be passed to the GPU driver.
- npu2: hw-procedures: Add settings to PHY_RESET

  Set a few new values in the PHY_RESET procedure, as specified by our
  updated programming guide documentation.
- Parse NVLink information from HDAT

  Add the per-chip structures that descibe how the A-Bus/NVLink/OpenCAPI
  phy is configured. This generates the npu@xyz nodes for each chip on
  systems that support it.
- npu2: Add vendor cap for IRQ testing

  Provide a way to test recoverable data link interrupts via a new
  vendor capability byte.
- npu2: Enable recoverable data link (no-stall) interrupts

  Allow the NPU2 to trigger "recoverable data link" interrupts.

- npu2: Implement basic FLR (Function Level Reset)
- npu2: hw-procedures: Update PHY DC calibration procedure
- npu2: hw-procedures: Change rx_pr_phase_step value

XIVE
^^^^
- xive: Fix opal_xive_dump_tm() to access W2 properly.
  The HW only supported limited access sizes.
- xive: Make opal_xive_allocate_irq() properly try all chips

  When requested via OPAL_XIVE_ANY_CHIP, we need to try all
  chips. We first try the current one (on which the caller
  sits) and if that fails, we iterate all chips until the
  allocation succeeds.
- xive: Fix initialization & cleanup of HW thread contexts

  Instead of trying to "pull" everything and clear VT (which didn't
  work and caused some FIRs to be set), instead just clear and then
  set the PTER thread enable bit. This has the side effect of
  completely resetting the corresponding thread context.

  This fixes the spurrious XIVE FIRs reported by PRD and fircheck
- xive: Add debug option for detecting misrouted IPI in emulation

  This is high overhead so we don't enable it by default even
  in debug builds, it's also a bit messy, but it allowed me to
  detect and debug a locking issue earlier so it can be useful.
- xive: Increase the interrupt "gap" on debug builds

  We normally allocate IPIs from 0x10. Make that 0x1000 on debug
  builds to limit the chances of overlapping with Linux interrupt
  numbers which makes debugging code that confuses them easier.

  Also add a warning in emulation if we get an interrupt in the
  queue whose number is below the gap.
- xive: Fix locking around cache scrub & watch

  Thankfully the missing locking only affects debug code and
  init code that doesn't run concurrently. Also adds a DEBUG
  option that checks the lock is properly held.
- xive: Workaround HW issue with scrub facility

  Without this, we sometimes don't observe from a CPU the
  values written to the ENDs or NVTs via the cache watch.
- xive: Add exerciser for cache watch/scrub facility in DEBUG builds
- xive: Make assertion in xive_eq_for_target() more informative
- xive: Add debug code to check initial cache updates
- xive: Ensure pressure relief interrupts are disabled

  We don't use them and we hijack the VP field with their
  configuration to store the EQ reference, so make sure the
  kernel or guest can't turn them back on by doing MMIO
  writes to ACK#
- xive: Don't try setting the reserved ACK# field in VPs

  That doesn't work, the HW doesn't implement it in the cache
  watch facility anyway.
- xive: Remove useless memory barriers in VP/EQ inits

  We no longer update "live" memory structures, we use a temporary
  copy on the stack and update the actual memory structure using
  the cache watch, so those barriers are pointless.

PHB4
^^^^
Since :ref:`skiboot-5.9-rc4`:

- phb4: Escalate freeze to fence to avoid checkstop

  Freeze events such as MMIO loads can cause the PHB to lose it's
  limited powerbus credits. If all credits are used and a further MMIO
  will cause a checkstop.

  To work around this, we escalate the troublesome freeze events to a
  fence. The fence will cause a full PHB reset which resets the powerbus
  credits and avoids the checkstop.
- phb4: Update some init registers

  New inits based on next PHB4 workbook. Increases some timeouts to
  avoid some spurious error conditions.
- phb4: Enable PHB MMIO in phb4_root_port_init()

  Linux EEH flow is somewhat broken. It saves the PCIe config space of
  the PHB on boot, which it then uses to restore on EEH recovery. It
  does this to restore MMIO bars and some other pieces.

  Unfortunately this save is done before any drivers are bound to
  devices under the PHB. A number of other things are configured in the
  PHB after drivers start, hence some configuration space settings
  aren't saved correctly. These include bus master and MMIO bits in the
  command register.

  Linux tried to hack around this in this linux commit
  ``bf898ec5cb`` powerpc/eeh: Enable PCI_COMMAND_MASTER for PCI bridges
  This sets the bus master bit but ignores the MMIO bit.

  Hence we lose MMIO after a full PHB reset. This causes the next MMIO
  access to the device to fail and for us to perform a PE freeze
  recovery, which still doesn't set the MMIO bit and hence we still
  fail.

  This works around this by forcing MMIO on during
  phb4_root_port_init().

  With this we can recovery from a PHB fence event on POWER9.
- phb4: Reduce link degraded message log level to debug

  If we hit this message we'll retry and fix the problem. If we run out
  of retries and can't fix the problem, we'll still print a log message
  at error level indicating a problem.
- phb4: Fix GEN3 for DD2.00

  In this fix: ``62ac7631ae phb4: Fix PCIe GEN4 on DD2.1 and above``
  We fixed DD2.1 GEN4 but broke DD2.00 as GEN3.

  This fixes DD2.00 back to GEN3. This time for sure!

Since :ref:`skiboot-5.9-rc3`:
- phb4: Fix PCIe GEN4 on DD2.1 and above

  In this change:
      eef0e197ab PHB4: Default to PCIe GEN3 on POWER9 DD2.00

  We clamped DD2.00 parts to GEN3 but unfortunately this change also
  applies to DD2.1 and above.

  This fixes this to only apply to DD2.00.

Since :ref:`skiboot-5.8`:

- phb4: Mask RXE_ARB: DEC Stage Valid Error

  Change the inits to mask out the RXE ARB: DEC Stage Valid Error (bit
  370. This has been a fatal error but should be informational only.

  This update will be in the next version of the phb4 workbook.
- phb4: Add additional adapter to retrain whitelist

  The single port version of the ConnectX-5 has a different device ID 0x1017.
  Updated descriptions to match pciutils database.
- PHB4: Default to PCIe GEN3 on POWER9 DD2.00

  You can use the NVRAM override for DD2.00 screened parts.
- phb4: Retrain link if degraded

  On P9 Scale Out (Nimbus) DD2.0 and Scale in (Cumulus) DD1.0 (and
  below) the PCIe PHY can lockup causing training issues. This can cause
  a degradation in speed or width in ~5% of training cases (depending on
  the card). This is fixed in later chip revisions. This issue can also
  cause PCIe links to not train at all, but this case is already
  handled.

  This patch checks if the PCIe link has trained optimally and if not,
  does a full PHB reset (to fix the PHY lockup) and retrain.

  One complication is some devices are known to train degraded unless
  device specific configuration is performed. Because of this, we only
  retrain when the device is in a whitelist. All devices in the current
  whitelist have been testing on a P9DSU/Boston, ZZ and Witherspoon.

  We always gather information on the link and print it in the logs even
  if the card is not in the whitelist.

  For testing purposes, there's an nvram to retry all PCIe cards and all
  P9 chips when a degraded link is detected. The new option is
  'pci-retry-all=true' which can be set using:
  `nvram -p ibm,skiboot --update-config pci-retry-all=true`.
  This option may increase the boot time if used on a badly behaving
  card.


IBM FSP platforms
-----------------

Since :ref:`skiboot-5.9-rc5`:
- FSP/CONSOLE: Disable notification on unresponsive consoles

  Commit fd6b71fc fixed the situation where ipmi console was open (hvc0) but got
  data on different console (hvc1).

  During FSP Reset/Reload OPAL closes all consoles. After Reset/Reload
  complete FSP requests to open hvc1 and sends data on this. If hvc1 registration failed or not opened in host kernel then it will not read data and results in RCU stalls.

  Note that this is workaround for older kernel where we don't have separate irq
  for each console. Latest kernel works fine without this patch.

Since :ref:`skiboot-5.9-rc1`:

- FSP/CONSOLE: Limit number of error logging

  Commit c8a7535f (FSP/CONSOLE: Workaround for unresponsive ipmi daemon) added
  error logging when buffer is full. In some corner cases kernel may call this
  function multiple time and we may endup logging error again and again.

  This patch fixes it by generating error log only once.

- FSP/CONSOLE: Fix fsp_console_write_buffer_space() call

  Kernel calls fsp_console_write_buffer_space() to check console buffer space
  availability. If there is enough buffer space to write data, then kernel will
  call fsp_console_write() to write actual data.

  In some extreme corner cases (like one explained in commit c8a7535f)
  console becomes full and this function returns 0 to kernel (or space available
  in console buffer < next incoming data size). Kernel will continue retrying
  until it gets enough space. So we will start seeing RCU stalls.

  This patch keeps track of previous available space. If previous space is same
  as current means not enough space in console buffer to write incoming data.
  It may be due to very high console write operation and slow response from FSP
  -OR- FSP has stopped processing data (ex: because of ipmi daemon died). At this
  point we will start timer with timeout of SER_BUFFER_OUT_TIMEOUT (10 secs).
  If situation is not improved within 10 seconds means something went bad. Lets
  return OPAL_RESOURCE so that kernel can drop console write and continue.
- FSP/CONSOLE: Close SOL session during R/R

  Presently we are not closing SOL and FW console sessions during R/R. Host will
  continue to write to SOL buffer during FSP R/R. If there is heavy console write
  operation happening during FSP R/R (like running `top` command inside console),
  then at some point console buffer becomes full. fsp_console_write_buffer_space()
  returns 0 (or less than required space to write data) to host. While one thread
  is busy writing to console, if some other threads tries to write data to console
  we may see RCU stalls (like below) in kernel. ::

    [ 2082.828363] INFO: rcu_sched detected stalls on CPUs/tasks: { 32} (detected by 16, t=6002 jiffies, g=23154, c=23153, q=254769)
    [ 2082.828365] Task dump for CPU 32:
    [ 2082.828368] kworker/32:3    R  running task        0  4637      2 0x00000884
    [ 2082.828375] Workqueue: events dump_work_fn
    [ 2082.828376] Call Trace:
    [ 2082.828382] [c000000f1633fa00] [c00000000013b6b0] console_unlock+0x570/0x600 (unreliable)
    [ 2082.828384] [c000000f1633fae0] [c00000000013ba34] vprintk_emit+0x2f4/0x5c0
    [ 2082.828389] [c000000f1633fb60] [c00000000099e644] printk+0x84/0x98
    [ 2082.828391] [c000000f1633fb90] [c0000000000851a8] dump_work_fn+0x238/0x250
    [ 2082.828394] [c000000f1633fc60] [c0000000000ecb98] process_one_work+0x198/0x4b0
    [ 2082.828396] [c000000f1633fcf0] [c0000000000ed3dc] worker_thread+0x18c/0x5a0
    [ 2082.828399] [c000000f1633fd80] [c0000000000f4650] kthread+0x110/0x130
    [ 2082.828403] [c000000f1633fe30] [c000000000009674] ret_from_kernel_thread+0x5c/0x68

  Hence lets close SOL (and FW console) during FSP R/R.
- FSP/CONSOLE: Do not associate unavailable console

  Presently OPAL sends associate/unassociate MBOX command for all
  FSP serial console (like below OPAL message). We have to check
  console is available or not before sending this message. ::

    [ 5013.227994012,7] FSP: Reassociating HVSI console 1
    [ 5013.227997540,7] FSP: Reassociating HVSI console 2
- FSP: Disable PSI link whenever FSP tells OPAL about impending R/R

  Commit 42d5d047 fixed scenario where DPO has been initiated, but FSP went
  into reset before the CEC power down came in. But this is generic issue
  that can happen in normal shutdown path as well.

  Hence disable PSI link as soon as we detect FSP impending R/R.

- fsp: return OPAL_BUSY_EVENT on failure sending FSP_CMD_POWERDOWN_NORM
  Also, return OPAL_BUSY_EVENT on failure sending FSP_CMD_REBOOT / DEEP_REBOOT.

  We had a race condition between FSP Reset/Reload and powering down
  the system from the host:

  Roughly:

  == ======================== ==========================================================
  #  FSP                      Host
  == ======================== ==========================================================
  1  Power on
  2                           Power on
  3  (inject EPOW)
  4  (trigger FSP R/R)
  5                           Processes EPOW event, starts shutting down
  6                           calls OPAL_CEC_POWER_DOWN
  7  (is still in R/R)
  8                           gets OPAL_INTERNAL_ERROR, spins in opal_poll_events
  9  (FSP comes back)
  10                          spinning in opal_poll_events
  11 (thinks host is running)
  == ======================== ==========================================================

  The call to OPAL_CEC_POWER_DOWN is only made once as the reset/reload
  error path for fsp_sync_msg() is to return -1, which means we give
  the OS OPAL_INTERNAL_ERROR, which is fine, except that our own API
  docs give us the opportunity to return OPAL_BUSY when trying again
  later may be successful, and we're ambiguous as to if you should retry
  on OPAL_INTERNAL_ERROR.

  For reference, the linux code looks like this: ::

    static void __noreturn pnv_power_off(void)
    {
            long rc = OPAL_BUSY;
    
            pnv_prepare_going_down();
    
            while (rc == OPAL_BUSY || rc == OPAL_BUSY_EVENT) {
                    rc = opal_cec_power_down(0);
                    if (rc == OPAL_BUSY_EVENT)
                            opal_poll_events(NULL);
                    else
                            mdelay(10);
            }
            for (;;)
                    opal_poll_events(NULL);
    }

  Which means that *practically* our only option is to return OPAL_BUSY
  or OPAL_BUSY_EVENT.

  We choose OPAL_BUSY_EVENT for FSP systems as we do want to ensure we're
  running pollers to communicate with the FSP and do the final bits of
  Reset/Reload handling before we power off the system.


Since :ref:`skiboot-5.8`:

- FSP/NVRAM: Handle "get vNVRAM statistics" command

  FSP sends MBOX command (cmd : 0xEB, subcmd : 0x05, mod : 0x00) to get vNVRAM
  statistics. OPAL doesn't maintain any such statistics. Hence return
  FSP_STATUS_INVALID_SUBCMD.

  Fixes these messages appearing in the OPAL log: ::

      [16944.384670488,3] FSP: Unhandled message eb0500
      [16944.474110465,3] FSP: Unhandled message eb0500
      [16945.111280784,3] FSP: Unhandled message eb0500
      [16945.293393485,3] FSP: Unhandled message eb0500
- fsp: Move common prints to trace

  These two prints just end up filling the skiboot logs on any machine
  that's been booted for more than a few hours.

  They have never been useful, so make them trace level. They were: ::
    SURV: Received heartbeat acknowledge from FSP
    SURV: Sending the heartbeat command to FSP

BMC based systems
-----------------
- hw/lpc-uart: read from RBR to clear character timeout interrupts

  When using the aspeed SUART, we see a condition where the UART sends
  continuous character timeout interrupts. This change adds a (heavily
  commented) dummy read from the RBR to clear the interrupt condition on
  init.

  This was observed on p9dsu systems, but likely applies to other systems
  using the SUART.
- astbmc: Add methods for handing Device Tree based slots
  e.g. ones from HDAT on POWER9.

General
-------

Since :ref:`skiboot-5.9-rc5`:

- p8-i2c: Further timeout reworks

  This patch reworks the way timeouts are set so that rather than imposing
  a hard deadline based on the transaction length it uses a
  kick-the-can-down-the-road approach where the timeout will be reset each
  time data is written to or received from the master. This fits better
  with the actual failure modes that timeouts are designed to handle, such
  as unusually slow or broken devices.

  Additionally this patch moves all the special case detection out of the
  timeout handler. This is help to improve the robustness of the driver and
  prepare for a more substantial rework of the driver as a whole later on.
- npu: Fix broken fast reset

  0679f61244b "fast-reset: by default (if possible)" broke NPU - now
  the NV links does not get enabled after reboot.

  This disables fast reboot for NPU machines till a better solution is found.

Since :ref:`skiboot-5.9-rc2`:

- Improvements to vpd device tree entries

  Previously we would miss some properties

Since :ref:`skiboot-5.9-rc1`:

- hw/p8-i2c: Fix deadlock in p9_i2c_bus_owner_change

  When debugging a system where Linux was taking soft lockup errors with
  two CPUs stuck in OPAL:

  ======================= ==============
  CPU0                    CPU1
  ======================= ==============
  lock
  p8_i2c_recover
  opal_handle_interrupt
                          sync_timer
			  cancel_timer
			  p9_i2c_bus_owner_change
			  occ_p9_interrupt
			  xive_source_interrupt
			  opal_handle_interrupt
  ======================= ==============

  p8_i2c_recover() is a timer, and is stuck trying to take master->lock.
  p9_i2c_bus_owner_change() has taken master->lock, but then is stuck waiting
  for all timers to complete. We deadlock.

  Fix this by using cancel_timer_async().
- opal/cpu: Mark the core as bad while disabling threads of the core.

  If any of the core fails to sync its TB during chipTOD initialization,
  all the threads of that core are disabled. But this does not make
  linux kernel to ignore the core/cpus. It crashes while bringing them up
  with below backtrace: ::

    [   38.883898] kexec_core: Starting new kernel
    cpu 0x0: Vector: 300 (Data Access) at [c0000003f277b730]
        pc: c0000000001b9890: internal_create_group+0x30/0x304
        lr: c0000000001b9880: internal_create_group+0x20/0x304
        sp: c0000003f277b9b0
       msr: 900000000280b033
       dar: 40
     dsisr: 40000000
      current = 0xc0000003f9f41000
      paca    = 0xc00000000fe00000   softe: 0        irq_happened: 0x01
        pid   = 2572, comm = kexec
    Linux version 4.13.2-openpower1 (jenkins@p89) (gcc version 6.4.0 (Buildroot 2017.08-00006-g319c6e1)) #1 SMP Wed Sep 20 05:42:11 UTC 2017
    enter ? for help
    [c0000003f277b9b0] c0000000008a8780 (unreliable)
    [c0000003f277ba50] c00000000041c3ac topology_add_dev+0x2c/0x40
    [c0000003f277ba70] c00000000006b078 cpuhp_invoke_callback+0x88/0x170
    [c0000003f277bac0] c00000000006b22c cpuhp_up_callbacks+0x54/0xb8
    [c0000003f277bb10] c00000000006bc68 cpu_up+0x11c/0x168
    [c0000003f277bbc0] c00000000002f0e0 default_machine_kexec+0x1fc/0x274
    [c0000003f277bc50] c00000000002e2d8 machine_kexec+0x50/0x58
    [c0000003f277bc70] c0000000000de4e8 kernel_kexec+0x98/0xb4
    [c0000003f277bce0] c00000000008b0f0 SyS_reboot+0x1c8/0x1f4
    [c0000003f277be30] c00000000000b118 system_call+0x58/0x6c

Since :ref:`skiboot-5.8`:

- ipmi: Convert common debug prints to trace

  OPAL logs messages for every IPMI request from host. Sometime OPAL console
  is filled with only these messages. This path is pretty stable now and
  we have enough logs to cover bad path. Hence lets convert these debug
  message to trace/info message. Examples are: ::

    [ 1356.423958816,7] opal_ipmi_recv(cmd: 0xf0 netfn: 0x3b resp_size: 0x02)
    [ 1356.430774496,7] opal_ipmi_send(cmd: 0xf0 netfn: 0x3a len: 0x3b)
    [ 1356.430797392,7] BT: seq 0x20 netfn 0x3a cmd 0xf0: Message sent to host
    [ 1356.431668496,7] BT: seq 0x20 netfn 0x3a cmd 0xf0: IPMI MSG done
- libflash/file: Handle short read()s and write()s correctly

  Currently we don't move the buffer along for a short read() or write()
  and nor do we request only the remaining amount.

- hw/p8-i2c: Rework timeout handling

  Currently we treat a timeout as a hard failure and will automatically
  fail any transations that hit their timeout. This results in
  unnecessarily failing I2C requests if interrupts are dropped, etc.
  Although these are bad things that we should log we can handle them
  better by checking the actual hardware status and completing the
  transation if there are no real errors. This patch reworks the timeout
  handling to check the status and continue the transaction if it can.
  if it can while logging an error if it detects a timeout due to a
  dropped interrupt.
- core/flash: Only expect ELF header for BOOTKERNEL partition flash resource

  When loading a flash resource which isn't signed (secure and trusted
  boot) and which doesn't have a subpartition, we assume it's the
  BOOTKERNEL since previously this was the only such resource. Thus we
  also assumed it had an ELF header which we parsed to get the size of the
  partition rather than trusting the actual_size field in the FFS header.
  A previous commit (9727fe3 DT: Add ibm,firmware-versions node) added the
  version resource which isn't signed and also doesn't have a subpartition,
  thus we expect it to have an ELF header. It doesn't so we print the
  error message "FLASH: Invalid ELF header part VERSION".

  It is a fluke that this works currently since we load the secure boot
  header unconditionally and this happen to be the same size as the
  version partition. We also don't update the return code on error so
  happen to return OPAL_SUCCESS.

  To make this explicitly correct; only check for an ELF header if we are
  loading the BOOTKERNEL resource, otherwise use the partition size from
  the FFS header. Also set the return code on error so we don't
  erroneously return OPAL_SUCCESS. Add a check that the resource will fit
  in the supplied buffer to prevent buffer overrun.
- flash: Support adding the no-erase property to flash

  The mbox protocol explicitly states that an erase is not required
  before a write. This means that issuing an erase from userspace,
  through the mtd device, and back returns a successful operation
  that does nothing. Unfortunately, this makes userspace tools unhappy.
  Linux MTD devices support the MTD_NO_ERASE flag which conveys that
  writes do not require erases on the underlying flash devices. We
  should set this property on all of our
  devices which do not require erases to be performed.

  NOTE: This still requires a linux kernel component to set the
  MTD_NO_ERASE flag from the device tree property.

Utilities
---------

Since :ref:`skiboot-5.9-rc1`:
- opal-prd: Fix memory leak

Since :ref:`skiboot-5.8`:

- external/gard: Clear entire guard partition instead of entry by entry

  When using the current implementation of the gard tool to ecc clear the
  entire GUARD partition it is done one gard record at a time. While this
  may be ok when accessing the actual flash this is very slow when done
  from the host over the mbox protocol (on the order of 4 minutes) because
  the bmc side is required to do many read, erase, writes under the hood.

  Fix this by rewriting the gard tool reset_partition() function. Now we
  allocate all the erased guard entries and (if required) apply ecc to the
  entire buffer. Then we can do one big erase and write of the entire
  partition. This reduces the time to clear the guard partition to on the
  order of 4 seconds.
- opal-prd: Fix opal-prd command line options

  HBRT OCC reset interface depends on service processor type.

  - FSP: reset_pm_complex()
  - BMC: process_occ_reset()

  We have both `occ` and `pm-complex` command line interfaces.
  This patch adds support to dispaly appropriate message depending
  on system type.

  === ==================== ============================
  SP  Command              Action
  === ==================== ============================
  FSP opal-prd occ         display error message
  FSP opal-prd pm-complex  Call pm_complex_reset()
  BMC opal-prd occ         Call process_occ_reset()
  BMC opal-prd pm-complex  display error message
  === ==================== ============================

- opal-prd: detect service processor type and
  then make appropriate occ reset call.
- pflash: Fix erase command for unaligned start address

  The erase_range() function handles erasing the flash for a given start
  address and length, and can handle an unaligned start address and
  length. However in the unaligned start address case we are incorrectly
  calculating the remaining size which can lead to incomplete erases.

  If we're going to update the remaining size based on what the start
  address was then we probably want to do that before we overide the
  origin start address. So rearrange the code so that this is indeed the
  case.
- external/gard: Print an error if run on an FSP system

Simulators
----------

- mambo: Add mambo socket program

  This adds a program that can be run inside a mambo simulator in linux
  userspace which enables TCP sockets to be proxied in and out of the
  simulator to the host.

  Unlike mambo bogusnet, it's requires no linux or skiboot specific
  drivers/infrastructure to run.

  Run inside the simulator:

  - to forward host ssh connections to sim ssh server:
    ``./mambo-socket-proxy -h 10022 -s 22``, then connect to port 10022
    on your host with ``ssh -p 10022 localhost``
  - to allow http proxy access from inside the sim to local http proxy:
    ``./mambo-socket-proxy -b proxy.mynetwork -h 3128 -s 3128``

  Multiple connections are supported.
- idle: disable stop*_lite POWER9 idle states for Mambo platform

  Mambo prior to Mambo.7.8.21 had a bug where the stop idle instruction
  with PSSCR[ESL]=PSSCR[EC]=0 would resume with MSR set as though it had
  taken a system reset interrupt.

  Linux currently executes this instruction with MSR already set that
  way, so the problem went unnoticed. A proposed patch to Linux changes
  that, and causes the idle code to crash. Work around this by disabling
  lite stop states for the mambo platform for now.

Contributors
------------

- 209 csets from 32 developers
- 2 employers found
- A total of 9619 lines added, 1612 removed (delta 8007)

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
======= ====== ======== ========= ========= ===========

The review count here is largely bogus, there was a series of 25 whitespace
patches that got "Reviewed-by" and if we exclude them, we're back to 14%,
which is more like what I'd expect.


Developers with the most changesets
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

========================== === =======
Developer                    # %
========================== === =======
Stewart Smith               28 (13.4%)
Vasant Hegde                25 (12.0%)
Joel Stanley                25 (12.0%)
Michael Neuling             24 (11.5%)
Oliver O'Halloran           20 (9.6%)
Benjamin Herrenschmidt      16 (7.7%)
Nicholas Piggin             12 (5.7%)
Akshay Adiga                 8 (3.8%)
Madhavan Srinivasan          7 (3.3%)
Reza Arbab                   6 (2.9%)
Mahesh Salgaonkar            3 (1.4%)
Claudio Carvalho             3 (1.4%)
Suraj Jitindar Singh         3 (1.4%)
Sam Bobroff                  3 (1.4%)
Shilpasri G Bhat             2 (1.0%)
Michael Ellerman             2 (1.0%)
Andrew Donnellan             2 (1.0%)
Vaibhav Jain                 2 (1.0%)
Jeremy Kerr                  2 (1.0%)
Cyril Bur                    2 (1.0%)
Christophe Lombard           2 (1.0%)
Daniel Black                 2 (1.0%)
Alexey Kardashevskiy         1 (0.5%)
Alistair Popple              1 (0.5%)
Anton Blanchard              1 (0.5%)
Guilherme G. Piccoli         1 (0.5%)
John W Walthour              1 (0.5%)
Anju T Sudhakar              1 (0.5%)
Balbir Singh                 1 (0.5%)
Russell Currey               1 (0.5%)
William A. Kennington III    1 (0.5%)
Sukadev Bhattiprolu          1 (0.5%)
========================== === =======

Developers with the most changed lines
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

========================== ==== =======
Developer                     # %
========================== ==== =======
Akshay Adiga               2731 (27.9%)
Oliver O'Halloran          1512 (15.5%)
Stewart Smith              1355 (13.9%)
Nicholas Piggin             929 (9.5%)
Vasant Hegde                827 (8.5%)
Michael Neuling             719 (7.4%)
Benjamin Herrenschmidt      522 (5.3%)
Madhavan Srinivasan         180 (1.8%)
Sam Bobroff                 172 (1.8%)
Christophe Lombard          170 (1.7%)
Mahesh Salgaonkar           166 (1.7%)
Andrew Donnellan            125 (1.3%)
Joel Stanley                 70 (0.7%)
Reza Arbab                   64 (0.7%)
Claudio Carvalho             51 (0.5%)
Suraj Jitindar Singh         42 (0.4%)
Alistair Popple              28 (0.3%)
Jeremy Kerr                  25 (0.3%)
Michael Ellerman             21 (0.2%)
Cyril Bur                    18 (0.2%)
Shilpasri G Bhat             17 (0.2%)
Vaibhav Jain                  8 (0.1%)
Daniel Black                  6 (0.1%)
William A. Kennington III     4 (0.0%)
Sukadev Bhattiprolu           4 (0.0%)
Alexey Kardashevskiy          3 (0.0%)
John W Walthour               3 (0.0%)
Balbir Singh                  3 (0.0%)
Guilherme G. Piccoli          2 (0.0%)
Anton Blanchard               1 (0.0%)
Anju T Sudhakar               1 (0.0%)
Russell Currey                1 (0.0%)
========================== ==== =======

Developers with the most lines removed
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

========================== ==== =======
Developer                     # %
========================== ==== =======
Alistair Popple              28 (1.7%)
========================== ==== =======

Developers with the most signoffs
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

========================== === =======
Developer                    # %
========================== === =======
Stewart Smith              180 (97.8%)
Shilpasri G Bhat             2 (1.1%)
Mukesh Ojha                  1 (0.5%)
Michael Neuling              1 (0.5%)
Total                      184 (100%)
========================== === =======

Developers with the most reviews
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

=========================== == =======
Developer                    # %
=========================== == =======
Michael Neuling             25 (32.5%)
Russell Currey              25 (32.5%)
Vaidyanathan Srinivasan      9 (11.7%)
Oliver O'Halloran            4 (5.2%)
Andrew Donnellan             3 (3.9%)
Frederic Barrat              2 (2.6%)
Suraj Jitindar Singh         2 (2.6%)
Vasant Hegde                 2 (2.6%)
Andrew Jeffery               1 (1.3%)
Samuel Mendoza-Jonas         1 (1.3%)
Alexey Kardashevskiy         1 (1.3%)
Cyril Bur                    1 (1.3%)
Akshay Adiga                 1 (1.3%)
Total                       77 (100%)
=========================== == =======


Developers with the most test credits
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

=========================== == =======
Developer                    # %
=========================== == =======
Pridhiviraj Paidipeddi       3 (100.0%)
=========================== == =======

Developers who gave the most tested-by credits
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

=========================== == =======
Developer                    # %
=========================== == =======
Vasant Hegde                 2 (66.7%)
Michael Neuling              1 (33.3%)
=========================== == =======


Developers with the most report credits
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

=========================== == =======
Developer                    # %
=========================== == =======
Pridhiviraj Paidipeddi       6 (60.0%)
Andrew Donnellan             1 (10.0%)
Stewart Smith                1 (10.0%)
Shriya                       1 (10.0%)
Robert Lippert               1 (10.0%)
Total                       10 (100%)
=========================== == =======

Developers who gave the most report credits
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

=========================== == =======
Developer                    # %
=========================== == =======
Stewart Smith                3 (30.0%)
Suraj Jitindar Singh         3 (30.0%)
Vasant Hegde                 2 (20.0%)
Michael Neuling              1 (10.0%)
Madhavan Srinivasan          1 (10.0%)
Total                       10 (100%)
=========================== == =======

Changesets and Employers
^^^^^^^^^^^^^^^^^^^^^^^^

Top changeset contributors by employer:

=========================== === =======
Employer                      # %
=========================== === =======
IBM                         208 (99.5%)
Google                        1 (0.5%)
=========================== === =======

Top lines changed by employer:

=========================== ==== =======
Employer                       # %
=========================== ==== =======
IBM                         9776 (100.0%)
Google                         4 (0.0%)
=========================== ==== =======

Employers with the most signoffs (total 184):

=========================== === =======
Employer                      # %
=========================== === =======
IBM                         184 (100.0%)
=========================== === =======

Employers with the most hackers (total 32):

=========================== === =======
Employer                      # %
=========================== === =======
IBM                          31 (96.9%)
Google                        1 (3.1%)
=========================== === =======
