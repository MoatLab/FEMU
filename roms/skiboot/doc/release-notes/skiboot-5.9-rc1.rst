.. _skiboot-5.9-rc1:

skiboot-5.9-rc1
===============

skiboot v5.9-rc1 was released on Wednesday October 11th 2017. It is the first
release candidate of skiboot 5.9, which will become the new stable release
of skiboot following the 5.8 release, first released August 31st 2017.

skiboot v5.9-rc1 contains all bug fixes as of :ref:`skiboot-5.4.7`
and :ref:`skiboot-5.1.21` (the currently maintained stable releases). We
do not currently expect to do any 5.8.x stable releases.

For how the skiboot stable releases work, see :ref:`stable-rules` for details.

The current plan is to cut the final 5.9 by October 17th, with skiboot 5.9
being for all POWER8 and POWER9 platforms in op-build v1.20 (Due October 18th).
This release will be targetted to early POWER9 systems.

Over skiboot-5.8, we have the following changes:

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
