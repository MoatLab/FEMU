.. _skiboot-5.5.0-rc1:

skiboot-5.5.0-rc1
=================

skiboot-5.5.0-rc1 was released on Tuesday March 28th 2017. It is the first
release candidate of skiboot 5.5, which will become the new stable release
of skiboot following the 5.4 release, first released November 11th 2016.

skiboot-5.5.0-rc1 contains all bug fixes as of :ref:`skiboot-5.4.3`
and :ref:`skiboot-5.1.19` (the currently maintained stable releases).

For how the skiboot stable releases work, see :ref:`stable-rules` for details.

The current plan is to cut the final 5.5.0 by April 8th, with skiboot 5.5.0
being for all POWER8 and POWER9 platforms in op-build v1.16 (Due April 12th).
This is a short cycle as this release is mainly targetted towards POWER9
bringup efforts.

Following skiboot-5.5.0, we will move to a regular six week release cycle,
similar to op-build, but slightly offset to allow for a short stabilisation
period. Expected release dates and contents are tracked using GitHub milestone
and issues: https://github.com/open-power/skiboot/milestones

Over skiboot-5.4, we have the following changes:

New Platforms
-------------
- SuperMicro's (SMC) P8DNU: An astbmc based POWER8 platform
- Add a generic platform to help with bringup of new systems.
- Four POWER9 based systems (NOTE: All POWER9 systems should be considered
  for bringup use only at this point):

  - Romulus
  - Witherspoon (a POWER9 system with NVLink2 attached GPUs)
  - Zaius (OpenCompute platform, also known as "Barreleye 2")
  - ZZ (FSP based system)

New features
------------

- System reset IPI facility and Mambo implementation
  Add an opal call :ref:`OPAL_SIGNAL_SYSTEM_RESET` which allows system reset
  exceptions to be raised on other CPUs and act as an NMI IPI. There
  is an initial simple Mambo implementation, but allowances are made
  for a more complex hardware implementation.

  The Mambo implementation is based on the RFC implementation for POWER8
  hardware (see https://patchwork.ozlabs.org/patch/694794/) which we hope
  makes it into a future release.

  This implements an in-band NMI equivalent.
- add CONTRIBUTING.md, ensuring that people new to the project have a one-stop
  place to find out how to get started.
- interrupts: Add optional name for OPAL interrupts

  This adds the infrastructure for an interrupt source to provide
  a name for an interrupt directed toward OPAL. Those names will
  be put into an "opal-interrupts-names" property which is a
  standard DT string list corresponding 1:1 with the "opal-interrupts"
  property. PSI interrupts get names, and this is visible in Linux
  through /proc/interrupts
- platform: add OPAL_REBOOT_FULL_IPL reboot type

  There may be circumstances in which a user wants to force a full IPL reboot
  rather than using fast reboot. Add a new reboot type, OPAL_REBOOT_FULL_IPL,
  that disables fast reboot. On platforms which don't support fast reboot,
  this will be equivalent to a normal reboot.
- phb3: Trick to allow control of the PCIe link width and speed

  This implements a hook inside OPAL that catches 16 and 32 bit writes
  to the link status register of the PHB.

  It allows you to write a new speed or a new width, and OPAL will then
  cause the PHB to renegociate.

  Example:

    First read the link status on PHB4: ::

      setpci -s 0004:00:00.0 0x5a.w
      a103

    It's at x16 Gen3 speed (8GT/s)

    bits 0x0ff0 are the width and 0x000f the speed. The width can be
    1 to 16 and the speed 1 to 3 (2.5, 5 and 8GT/s)

    Then try to bring it down to 1x Gen1 : ::

      setpci -s 0004:00:00.0 0x5a.w=0xa011

    Observe the result in the PHB: ::

      / # lspci -s 0004:00:00.0 -vv
      0004:00:00.0 PCI bridge: IBM Device 03dc (prog-if 00 [Normal decode])
      .../...
      LnkSta: Speed 2.5GT/s, Width x1, TrErr- Train- SlotClk- DLActive+ BWMgmt- ABWMgmt+

    And in the device: ::

      / # lspci -s 0004:01:00.0 -vv
      .../...
      LnkSta: Speed 2.5GT/s, Width x1, TrErr- Train- SlotClk+ DLActive- BWMgmt- ABWMgmt-

- core/init: Add hdat-map property to OPAL node.

  Exports the HDAT heap to the OS. This allows the OS to view the HDAT heap
  directly.  This allows us to view the HDAT area without having to use
  getmemproc.

- Add a generic platform: If /bmc in device tree, attempt to init one
  For the most part, this gets us somewhere on some OpenPOWER systems
  before there's a platform file for that machine.

  Useful in bringup only, and marked as such with scary looking log
  messages.


Core
----

- asm: Don't try to set LPCR:LPES1 on P8 and P9, the bit doesn't exist.

- pci: Add a framework for quirks

  In future we may want to be able to do fixups for specific PCI devices in
  skiboot, so add a small framework for doing this.

  This is not intended for the same purposes as quirks in the Linux kernel,
  as the PCI devices that quirks can match for in skiboot are not properly
  configured.  This is intended to enable having a custom path to make
  changes that don't directly interact with the PCI device, for example
  adding device tree entries.

- hw/slw: fix possible NULL dereference
- slw: Print enabled stop states on boot
- uart: Fix Linux pass-through policy, provide NVRAM override option
- libc/stdio/vsnprintf.c: add explicit fallthrough, this silences a recent
  (GCC 7.x) warning
- init: print the FDT blob size in decimal
- init: Print some more info before booting linux

  The kernel command line from nvram and the stdout-path are
  useful to know when debugging console related problems.

- Makefile: Disable stack protector due to gcc problems

  Depending on how it was built, gcc will use the canary from a global
  (works for us) or from the TLS (doesn't work for us and accesses
  random stuff instead).

  Fixing that would be tricky. There are talks of adding a gcc option
  to force use of globals, but in the meantime, disable the stack
  protector.
- Stop using 3-operand cmp[l][i] for latest binutils
  Since a5721ba270, binutils does not support 3-operand cmp[l][i].
  This adds (previously optional) parameter L.
- buddy: Add a simple generic buddy allocator
- stack: Don't recurse into __stack_chk_fail
- Makefile: Use -ffixed-r13
  We use r13 for our own stuff, make sure it's properly fixed
- Always set ibm,occ-functional-state correctly
- psi: fix the xive registers initialization on P8, which seems to be fine
  for real HW but causes a lof of pain under qemu
- slw: Set PSSCR value for idle states
- Limit number of "Poller recursion detected" errors to display

  In some error conditions, we could spiral out of control on this
  and spend all of our time printing the exact same backtrace.

  Limit it to 16 times, because 16 is a nice number.
- slw: do SLW timer testing while holding xscom lock

  We add some routines that let a caller get the xscom lock once and
  then do a bunch of xscoms while holding it.
  In some situations without this, it could take long enough to get
  the xscom lock that the 1ms timeout would expire and we'd falsely
  think the SLW timer didn't work when in fact it did.
- wait_for_resource_loaded: don't needlessly sleep for 5ms
- run pollers in cpu_process_local_jobs() if running job synchonously
- fsp: Don't recurse pollers in ibm_fsp_terminate
- chiptod: More hardening against -1 chip ID
- interrupts: Rewrite/correct doc for opal_set/get_xive
- cpu: Don't enable nap mode/PM mode on non-P8
- platform: Call generic platform probe and init UART there
- psi: Don't register more interrupts than the HW supports
- psi: Add DT option to disable LPC interrupts

I2C and TPM
-----------
- p8i2c: Use calculated poll_interval when booting OPAL
  Otherwise we'd default to 2seconds (TIMER_POLL) during boot on
  chips with a functional i2c interrupt, leading to slow i2c
  during boot (or hitting timeouts instead).
- i2c: Add i2c_run_req() to crank the state machine for a request
- tpm_i2c_nuvoton: work out the polling time using mftb()
- tpm_i2c_nuvoton: handle errors after reading the tpm fifo
- tpm_i2c_nuvoton: cleanup variables in tpm_read_fifo()
- tpm_i2c_nuvoton: handle errors after writting the tpm fifo
- tpm_i2c_nuvoton: cleanup variables in tpm_write_fifo()
- tpm_i2c_nuvoton: handle errors after writing sts.commandReady in step 5
- tpm_i2c_nuvoton: handle errors after writing sts.go
- tpm_i2c_nuvoton: handle errors after checking the tpm fifo status
- tpm_i2c_nuvoton: return burst_count in tpm_read_burst_count()
- tpm_i2c_nuvoton: isolate the code that handles the TPM_TIMEOUT_D timeout
- tpm_i2c_nuvoton: handle errors after reading sts.commandReady
- tpm_i2c_nuvoton: add tpm_status_read_byte()
- tpm_i2c_nuvoton: add tpm_check_status()
- tpm_i2c_nuvoton: rename defines to shorter names
- tpm_i2c_interface: decouple rc from being done with i2c request
- tpm_i2c_interface: set timeout before each request
- i2c: Add nuvoton quirk, disallowing i2cdetect as it locks TPM

  p8-i2c reset things manually in some error conditions
- stb: create-container and wrap skiboot in Secure/Trusted Boot container

  We produce **UNSIGNED** skiboot.lid.stb and skiboot.lid.xz.stb as build
  artifacts.

  These are suitable blobs for flashing onto Trusted Boot enabled op-build
  builds *WITH* the secure boot jumpers *ON* (i.e. *NOT* in secure mode).
  It's just enough of the Secure and Trusted Boot container format to
  make Hostboot behave.


PCI
---
- core/pci: Support SRIOV VFs

  Currently, skiboot can't see SRIOV VFs. It introduces some troubles
  as I can see: The device initialization logic (phb->ops->device_init())
  isn't applied to VFs, meaning we have to maintain same and duplicated
  mechanism in kernel for VFs only. It introduces difficulty to code
  maintaining and prone to lose sychronization.

  This was motivated by bug reported by Carol: The VF's Max Payload
  Size (MPS) isn't matched with PF's on Mellanox's adapter even kernel
  tried to make them same. It's caused by readonly PCIECAP_EXP_DEVCTL
  register on VFs. The skiboot would be best place to emulate this bits
  to eliminate the gap as I can see.

  This supports SRIOV VFs. When the PF's SRIOV capability is populated,
  the number of maximal VFs (struct pci_device) are instanciated, but
  but not usable yet. In the mean while, PCI config register filter is
  registered against PCIECAP_SRIOV_CTRL_VFE to capture the event of
  enabling or disabling VFs. The VFs are initialized, put into the PF's
  children list (pd->children), populate its PCI capabilities, and
  register PCI config register filter against PCICAP_EXP_DEVCTL. The
  filter's handler caches what is written to MPS field and returns
  the cached value on read, to eliminate the gap mentioned as above.

- core/pci: Avoid hreset after freset

  Commit 5ac71c9 ("pci: Avoid hot resets at boot time") missed to
  avoid hot reset after fundamental reset for PCIe common slots.

  This fixes it.
- core/pci: Enforce polling PCIe link in hot-add path

  In surprise hot-add path, the power state isn't changed on hardware.
  Instead, we set the cached power state (@slot->power_state) and
  return OPAL_SUCCESS. The upper layer starts the PCI probing immediately
  when receiving OPAL_SUCCESS. However, the PCIe link behind the PCI
  slot is likely down. Nothing will be probed from the PCI slot even
  we do have PCI adpater connected to the slot.

  This fixes the issue by returning OPAL_ASYNC_COMPLETION to force
  upper layer to poll the PCIe link before probing the PCI devices
  behind the slot in surprise and managed hot-add paths.
- hw/phb3: fix error handling in complete reset
    During a complete reset, when we get a timeout waiting for pending
    transaction in state PHB3_STATE_CRESET_WAIT_CQ, we mark the PHB as
    permanently broken.

    Set the state to PHB3_STATE_FENCED so that the kernel can retry the
    complete reset.
- phb3: Lock the PHB on set_xive callbacks

p8dnu platform
--------------
- astbmc/p8dnu: Enable PCI slot's power supply on PEX9733 in hot-add path
- astbmc/p8dnu: Enable PCI slot's power supply on PEX8718 in hot-add path
- core/pci: Mark broken PDC on slots without surprise hotplug capability

  We has to support surprise hotplug on PCI slots that don't support
  it on hardware. So we're fully utilizing the PCIe link state change
  event to detect the events (hot-remove and hot-add). The PDC (Presence
  Detection Change) event isn't reliable for the purpose. For example,
  PEX8718 on superMicro's machines.

  This adds another PCI slot property "ibm,slot-broken-pdc" in the
  device-tree, to indicate the PDC isn't reliable on those (software
  claimed) surprise pluggable slots.
- core/pci: Fix PCIe slot's presence

  According to PCIe spec, the presence bit is hardcoded to 1 if PCIe
  switch downstream port doesn't support slot capability. The register
  used for the check in pcie_slot_get_presence_state() is wrong. It
  should be PCIe capability register instead of PCIe slot capability
  register. Otherwise, we always have present bit on the PCI topology.
  The issue is found on Supermicro's p8dtu2u machine: ::

     # lspci -t
     -+-[0022:00]---00.0-[01-08]----00.0-[02-08]--+-01.0-[03]----00.0
      |                                           \-02.0-[04-08]--
     # cat /sys/bus/pci/slots/S002204/adapter
     1
     # lspci -vvs 0022:02:02.0
     # lspci -vvs 0022:02:02.0
     0022:02:02.0 PCI bridge: PLX Technology, Inc. PEX 8718 16-Lane, \
     5-Port PCI Express Gen 3 (8.0 GT/s) Switch (rev ab) (prog-if 00 [Normal decode])
        :
     Capabilities: [68] Express (v2) Downstream Port (Slot+), MSI 00
        :
        SltSta:    Status: AttnBtn- PowerFlt- MRL- CmdCplt- PresDet- Interlock-
                   Changed: MRL- PresDet- LinkState-

    This fixes the issue by checking the correct register (PCIe capability).
    Also, the register's value is cached in advance as we did for slot and
    link capability.
- core/pci: More reliable way to update PCI slot power state

  The power control bit (SLOT_CTL, offset: PCIe cap + 0x18) isn't
  reliable enough to reflect the PCI slot's power state. Instead,
  the power indication bits are more reliable comparatively. This
  leads to mismatch between the cached power state and PCI slot's
  presence state, resulting in the hotplug driver in kernel refuses
  to unplug the devices properly on the request. The issue was
  found on below NVMe card on "supermicro,p8dtu2u" machine. We don't
  have this issue on the integrated PLX 8718 switch. ::

     # lspci
     0022:01:00.0 PCI bridge: PLX Technology, Inc. PEX 9733 33-lane, \
                  9-port PCI Express Gen 3 (8.0 GT/s) Switch (rev aa)
     0022:02:01.0 PCI bridge: PLX Technology, Inc. PEX 9733 33-lane, \
                  9-port PCI Express Gen 3 (8.0 GT/s) Switch (rev aa)
     0022:02:04.0 PCI bridge: PLX Technology, Inc. PEX 9733 33-lane, \
                  9-port PCI Express Gen 3 (8.0 GT/s) Switch (rev aa)
     0022:02:05.0 PCI bridge: PLX Technology, Inc. PEX 9733 33-lane, \
                  9-port PCI Express Gen 3 (8.0 GT/s) Switch (rev aa)
     0022:02:06.0 PCI bridge: PLX Technology, Inc. PEX 9733 33-lane, \
                  9-port PCI Express Gen 3 (8.0 GT/s) Switch (rev aa)
     0022:02:07.0 PCI bridge: PLX Technology, Inc. PEX 9733 33-lane, \
                  9-port PCI Express Gen 3 (8.0 GT/s) Switch (rev aa)
     0022:17:00.0 Non-Volatile memory controller: Device 19e5:0123 (rev 45)

    This updates the cached PCI slot's power state using the power
    indication bits instead of power control bit, to fix above issue.

Utilities
---------

- opal-prd: Direct systemd to always restart opal-prd
  Always restart the opal-prd daemon, irrespective of why it stopped.
- external/ffspart: Simple C program to be able to make an FFS partition
- getscom: Add chip info for P9.
- gard: Fix make dist target
- pflash/libflash: arch_flash_arm: Don't assume mtd labels are short

libffs
------
- libffs: Understand how to create FFS partition TOCs and entries.

BMC Based systems
-----------------
- platforms/astbmc: Support PCI slots for palmetto
- habanero/slottable: Remove Network Mezz(2, 0) from PHB1.
- BMC/PCI: Check slot tables against detected devices
  On BMC machines, we have slot tables of built in PHBs, slots and devices
  that are physically present in the system (such as the BMC itself). We
  can use these tables to check what we *detected* against what *should*
  be in the system and throw an error if they differ.

  We have seen this occur a couple of times while still booting, giving the
  user just an empty petitboot screen and not much else to go on. This
  patch helps in that we get a skiboot error message, and at some point
  in the future when we pump them up to the OS we could get a big friendly
  error message telling you you're having a bad day.
- pci/quirk: Populate device tree for AST2400 VGA

  Adding these properties enables the kernel to function in the same way
  that it would if it could no longer access BMC configuration registers
  through a backdoor, which may become the default in future.

  The comments describe how isolating the host from the BMC could be
  achieved in skiboot, assuming all kernels that the system boots
  support this.  Isolating the BMC and the host from each other is
  important if they are owned by different parties; for example, a cloud
  provider renting machines "bare metal".

- astbmc/pnor: Use mbox-flash for flash accesses

  If the BMC is MBOX protocol aware, request flash reads/writes over the
  MBOX regs. This inits the blocklevel for pnor access with mbox-flash.
- ast: Account for differences between 2400 vs 2500
- platform: set default bmc_platform
  The bmc_platform pointer is set to NULL by default and on non-AMI BMC
  platforms. As a result a few places in hw/ipmi/ipmi-sel.c will blindly
  dereference a NULL pointer.

POWER9
------

- external: Update xscom utils for type 1 indirect accesses
- xscom: Harden indirect writes
- xscom: Add POWER9 scom reset
- homer : Enable HOMER region reservation for POWER9
- slw: Define stop idle states for P9 DD1
- slw: Fix parsing of supported STOP states
- slw: only enable supported STOP states
- dts: add support for p9 cores

- asm: Add POWER9 case to init_shared_sprs

  For now, setup the HID and HMEER. We'll add more as we get
  good default values from HW.
- xive/psi/lpc: Handle proper clearing of LPC SerIRQ latch on POWER9 DD1
- lpc: Mark the power9 LPC bus as compatible with power8
- Fix typo in PIR mask for POWER9. Fixes booting multi-chip.
- vpd: add vpd_valid() to check keyword VPD blobs

  Adds a function to check whether a blob is a valid IBM ASCII keyword
  VPD blob. This allows us to recognise when we do and do not have a VPD
  blob and act accordingly.
- core/cpu.c: Use a device-tree node to detect nest mmu presence
  The nest mmu address scom was hardcoded which could lead to boot
  failure on POWER9 systems without a nest mmu. For example Mambo
  doesn't model the nest mmu which results in  failure when
  calling opal_nmmu_set_ptcr() during kernel load.
- psi: Fix P9 BAR setup on multi-chips

PHB4:

  - phb4: Fix TVE encoding for start address
  - phb4: Always assign powerbus BARs

    HostBoot configure them with weird values that confuse us, instead
    let's just own the assignment. This is temporary, I will centralize
    memory map management next but this gets us going.
  - phb4: Fix endian issue with link control2/status2 registers
    Fixes training at larger than PCIe Gen1 speeds.
  - phb4: Add ability to log config space access
    Useful for debugging
  - phb4: Change debug prints
    Currently we print "PHB4" and mean either "PHB version 4" or "PHB
    number 4" which can be quite confusing.
  - phb4: Fix config space enable bits on DD1
  - phb4: Fix location of EEH enable bits
  - phb4: Fix setting of max link speed
  - phb4: Updated inits as of PHB4 spec 0.52

HDAT fixes:

  - hdat: Parse BMC nodes much earlier

    This moves the parsing of the BMC and LPC details to the start of the
    HDAT parsing. This allows us to enable the Skiboot log console earlier
    so we can get debug output while parsing the rest of the HDAT.
  - astbmc: Don't do P8 PSI or DT fixups on P9

    Previously the HDAT format was only ever used with IBM hardware so it
    would store vital product data (VPD) blobs in the IBM ASCII Keyword VPD
    format. With P9 HDAT is used on OpenPower machines which use Industry
    Standard DIMMs that provide their product data through a "Serial Present
    Detect" EEPROM mounted on the DIMM.

    The SPD blob has a different format and is exported in the device-tree
    under the "spd" property rather than the "ibm,vpd" property. This patch
    adds support for recognising these blobs and placing them in the
    appropriate DT property.
  - hdat: Add __packed to all HDAT structures and workaround HB reserve

    Some HDAT structures aren't properly aligned. We were using __packed
    on some but not others and got at least one wrong (HB reserve). This
    adds it everywhere to avoid such problems.

    However this then triggers another problem where HB gives us a
    crazy range (0.256M) to reserve with no label, which triggers an
    assertion failure later on in mem_regions.c.

    So also add a test to skip any region starting at 0 until we can
    undertand that better and have it fixed one way or another.
  - hdat: Ignore broken memory reserves

    Ignore HDAT memory reserves > 512MB.  These are considered bogus and
    workaround known HDAT bugs.
  - hdat: Add BMC device-tree node for P9 OpenPOWER systems
  - hdat: Fix interrupt & device_type of UART node

    The interrupt should use a standard "interrupts" property. The UART
    node also need a device_type="serial" property for historical reasons
    otherwise Linux won't pick it up.
  - parse and export STOP levels
  - add new sppcrd_chip_info fields
  - add radix-AP-encodings
  - stop using proc_int_line in favor of pir
  - rename add_icp() to add_xics_icp()
  - Add support for PHB4
  - create XIVE nodes under each xscom node
  - Add P9 compatible property
  - Parse hostboot memory reservations from HDAT
  - Add new fields to IPL params structure and update sys family for p9.
  - Fix ibm,pa-features for all CPU types
  - Fix XSCOM nodes for P9
  - Remove deprecated 'ibm, mem-interleave-scope' from DT on POWER9
  - Grab system model name from HDAT when available
  - Grab vendor information from HDAT when available
  - SPIRA-H/S changes for P9
  - Add BMC and LPC IOPATH support
  - handle ISDIMM SPD blobs
  - make HDIF_child() print more useful errors
  - Add PSI HB xscom details
  - Add new fields to proc_init_data structure
  - Add processor version check for hs service ntuple
  - add_iplparams_serial - Validate HDIF_get_iarray_size() return value


XIVE:

The list of XIVE fixes and updates is extensive. Below is only a portion of
the changes that have gone into skiboot 5.5.0-rc1 for the new XIVE hardware
that is present in POWER9:

  - xive: Enable backlog on queues
  - xive: Use for_each_present_cpu() for setting up XIVE
  - xive: Fix logic in opal_xive_get_xirr()
  - xive: Properly initialize new VP and EQ structures
  - xive: Improve/fix EOI of LSIs
  - xive: Add FIXME comments about mask/umask races
  - xive: Fix memory barrier in opal_xive_get_xirr()
  - xive: Don't try to find a target EQ for prio 0xff
  - xive: Bump table sizes in direct mode
  - xive: Properly register escalation interrupts
  - xive: Split the OPAL irq flags from the internal ones
  - xive: Don't touch ESB masks unless masking/unmasking
  - xive: Fix xive_get_ir_targetting()
  - xive: Cleanup escalation PQ on queue change
  - xive: Add *any chip* for allocating interrupts
  - xive: Add chip_id to get_vp_info
  - xive: Add opal_xive_get/set_vp_info
  - xive: Add VP alloc/free OPAL functions
  - xive: Workaround for bad DD1 checker
  - xive: Add more checks for exploitation mode
  - xive: Add support for EOIs via OPAL
  - xive/phb4: Work around broken LSI control on P9 DD1
  - xive: Forward interrupt names callback
  - xive: Export opal_xive_reset() arguments in OPAL API
  - xive: Add interrupt allocator
  - xive: Implement xive_reset
  - xive: Don't assert if xive_get_vp() fails
  - xive: Expose exploitation mode DT properties
  - xive: Use a constant for max# of chips
  - xive: Keep track of which interrupts were ever enabled
    In order to speed up xive reset
  - xive: Implement internal VP allocator
  - xive: Add xive_get/set_queue_info
  - xive: Add helpers to encode and decode VP numbers
  - xive: Add API to donate pages in indirect mode
  - xive: Add asynchronous cache updates and update irq targetting
  - xive: Split xive_provision_cpu() and use cache watch for VP
  - xive: Add cache scrub to push watch updates to memory
  - xive: Mark XIVE owned EQs with a specific flag
  - xive: Use an allocator for EQDs
  - xive: Break assumption that block ID == chip ID
  - xive/phb4: Handle bad ESB offsets in PHB4 DD1
  - xive: Implement get/set_irq_config APIs
  - xive: Rework xive_set_eq_info() to store all info even when masking
  - xive: Implement cache watch and use it for EQs
  - xive: Add locking to some API calls
  - xive: Add opal_xive_get_irq_info()
  - xive: Add CPU node "interrupts" properties representing the IPIs
  - xive: Add basic opal_xive_reset() call and exploitation mode
  - xive: Add support for escalation interrupts
  - xive: OPAL API update
  - xive: Add some dump facility for debugging
  - xive: Document exploitation mode
    (Pretty much work in progress)
  - xive: Indirect table entries must have top bits "type" set
  - xive: Remove unused field and clarify comment
  - xive: Provide a way to override some IPI sources
  - xive: Add helper to retrieve an IPI trigger port
  - xive: Fix IPI EOI logic in opal_xive_eoi()
  - xive: Don't try to EOI a masked source
  - xive: Fix comments in xive_source_set_xive()
  - xive: Fix comments in xive_get_ive()
  - xive: Configure forwarding ports
  - xive: Fix mangling of interrupt server# in opal_get/set_xive()
  - xive: Fix interrupt number mangling


Fast-reboot
-----------
- fast-reboot: creset PHBs on fast reboot
  On fast reboot, perform a creset of all PHBs. This ensures that any PHBs
  that are fenced will be working after the reboot.
- fast-reboot: Enable fast reboot with CAPI adapters in CAPI mode
  CAPI mode is disabled as part of OPAL_SYNC_HOST_REBOOT.
- opal/fast-reboot: set fw_progress sensor status with IPMI_FW_PCI_INIT.

CAPI
----

- hmi: Print CAPP FIR information when handling CAPP malfunction alerts

FSP based systems
-----------------

- hw/fsp: Do not queue SP and SPCN class messages during reset/reload
  This could cause soft lockups if FSP reset reload was done while in OPAL
  During FSP R/R, the FSP is inaccessible and will lose state. Messages to the
  FSP are generally queued for sending later.

Tests
-----
- core/test/run-trace: Reduce number of samples when running under valgrind
    This reduces 'make check' run time by ~10 seconds on my laptop,
    and just the run-trace test itself takes 15 seconds less (under valgrind).
- test/sreset_world: Kind of like Hello World, but from the SRESET vector.
  A regression test for the mambo implementation of OPAL_SIGNAL_SYSTEM_RESET.
- nvram-format: Fix endian issues
    NVRAM formats are always BE, so let's use the sparse annotation to catch
    any issues (and correct said issues).

    On LE platforms, the test was erroneously passing as with building the
    nvram-format code on LE we were produces an incorrect NVRAM image.

- test/hello_world: use P9MAMBO to differentiate from P8
- hdata_to_dt: Specify PVR on command line
- hdata/test: Add DTS output for the test cases
- hdata/test: strip blobs from the DT output
- mambo: add mprintf()

    mprintf() is printf(), but it goes straight to the mambo console. This
    allows it to be independent of Skiboot's actual console infrastructure
    so it can be used for debugging the console drivers and for debugging
    code that runs before the console is setup.
- generate-fwts-olog: add support for parsing prerror()
- Add bitmap test
    The worst test suite ever
- mambo_utils: add ascii output to hexdump
- mambo_utils: add p_str <addr> [limit]
- mambo_utils: make p return a value
- hello_world: print out full path of missing MAMBO_BINARY
- print-stb-container: Fix build on centos7

- Travis-ci improvements:
  - install expect on ubuntu 12.04, disable qemu on 16.04/latest
  - build and test more on centos7
  - hello_world: run p9 mambo tests
  - install systemsim-p8 on centos7
  - install systemsim-p8 on centos6
  - install systemsim-p9
  - enable fedora25
  - always pull new docker image
  - add fedora rawhide

- Add fwts annotation for duplicate DT node entries.

    Reference bug: https://github.com/open-power/op-build/issues/751
- external/fwts: Add 'last-tag' to FWTS olog output
  This isn't so useful at the moment, but this will make cleaning out
  crufty old error definitions much easier.
- external/fwts: Add FWTS olog merge script
  A script to merge olog error definitions from multiple skiboot versions
  into a single olog JSON file. Will prompt when conflicting patterns are
  found to update the pattern, or add both.
- mambo: fake NVRAM support
- mambo: Add Fake NVRAM driver
- external/mambo: add shortcut to print all GPRs



Contributors
------------

Processed 363 csets from 28 developers.
A total of 18105 lines added, 16499 removed (delta 1606)

Developers with the most changesets
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

========================== === =======
Developer                    # %
========================== === =======
Benjamin Herrenschmidt     138 (38.0%)
Stewart Smith               56 (15.4%)
Oliver O'Halloran           47 (12.9%)
Michael Neuling             18 (5.0%)
Gavin Shan                  15 (4.1%)
Claudio Carvalho            14 (3.9%)
Vasant Hegde                11 (3.0%)
Cyril Bur                   11 (3.0%)
Andrew Donnellan            11 (3.0%)
Ananth N Mavinakayanahalli   5 (1.4%)
Cédric Le Goater             5 (1.4%)
Pridhiviraj Paidipeddi       5 (1.4%)
Shilpasri G Bhat             4 (1.1%)
Nicholas Piggin              4 (1.1%)
Russell Currey               3 (0.8%)
Alistair Popple              2 (0.6%)
Jack Miller                  2 (0.6%)
Chris Smart                  2 (0.6%)
Matt Brown                   1 (0.3%)
Michael Ellerman             1 (0.3%)
Frederic Barrat              1 (0.3%)
Hank Chang                   1 (0.3%)
Willie Liauw                 1 (0.3%)
Werner Fischer               1 (0.3%)
Jeremy Kerr                  1 (0.3%)
Patrick Williams             1 (0.3%)
Joel Stanley                 1 (0.3%)
Alexey Kardashevskiy         1 (0.3%)
========================== === =======

Developers with the most changed lines
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

=========================== ===== =======
Developer                    #    %
=========================== ===== =======
Oliver O'Halloran           17961 (56.7%)
Benjamin Herrenschmidt       5509 (17.4%)
Cyril Bur                    2801 (8.8%)
Stewart Smith                1649 (5.2%)
Gavin Shan                    653 (2.1%)
Claudio Carvalho              489 (1.5%)
Willie Liauw                  361 (1.1%)
Ananth N Mavinakayanahalli    340 (1.1%)
Andrew Donnellan              315 (1.0%)
Michael Neuling               240 (0.8%)
Shilpasri G Bhat              228 (0.7%)
Nicholas Piggin               219 (0.7%)
Vasant Hegde                  207 (0.7%)
Russell Currey                158 (0.5%)
Jack Miller                   127 (0.4%)
Cédric Le Goater              126 (0.4%)
Chris Smart                    95 (0.3%)
Hank Chang                     56 (0.2%)
Pridhiviraj Paidipeddi         47 (0.1%)
Alistair Popple                39 (0.1%)
Matt Brown                     29 (0.1%)
Michael Ellerman                3 (0.0%)
Alexey Kardashevskiy            2 (0.0%)
Frederic Barrat                 1 (0.0%)
Werner Fischer                  1 (0.0%)
Jeremy Kerr                     1 (0.0%)
Patrick Williams                1 (0.0%)
Joel Stanley                    1 (0.0%)
=========================== ===== =======

Developers with the most lines removed
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

=========================== ===== =======
Developer                       # %
=========================== ===== =======
Oliver O'Halloran            8810 (53.4%)
Ananth N Mavinakayanahalli     98 (0.6%)
Alistair Popple                 9 (0.1%)
Michael Ellerman                3 (0.0%)
Werner Fischer                  1 (0.0%)
=========================== ===== =======

Developers with the most signoffs
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Total 322

======================== ===== =======
Developer                    # %
======================== ===== =======
Stewart Smith              307 (95.3%)
Michael Neuling              6 (1.9%)
Oliver O'Halloran            3 (0.9%)
Benjamin Herrenschmidt       2 (0.6%)
Vaidyanathan Srinivasan      1 (0.3%)
Hank Chang                   1 (0.3%)
Jack Miller                  1 (0.3%)
Gavin Shan                   1 (0.3%)
======================== ===== =======

Developers with the most reviews
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Total: 45

======================== ===== =======
Developer                    # %
======================== ===== =======
Vasant Hegde                10 (22.2%)
Andrew Donnellan             9 (20.0%)
Russell Currey               6 (13.3%)
Cédric Le Goater             5 (11.1%)
Oliver O'Halloran            4 (8.9%)
Gavin Shan                   3 (6.7%)
Vaidyanathan Srinivasan      2 (4.4%)
Alistair Popple              2 (4.4%)
Frederic Barrat              2 (4.4%)
Mahesh Salgaonkar            1 (2.2%)
Cyril Bur                    1 (2.2%)
======================== ===== =======

Developers with the most test credits
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Total 11

======================== ===== =======
Developer                    # %
======================== ===== =======
Willie Liauw                 4 (36.4%)
Claudio Carvalho             3 (27.3%)
Gavin Shan                   1 (9.1%)
Michael Neuling              1 (9.1%)
Pridhiviraj Paidipeddi       1 (9.1%)
Chris Smart                  1 (9.1%)
======================== ===== =======

Developers who gave the most tested-by credits
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Total 11

========================== ===== =======
Developer                    #   %
========================== ===== =======
Gavin Shan                     4 (36.4%)
Stewart Smith                  4 (36.4%)
Chris Smart                    1 (9.1%)
Oliver O'Halloran              1 (9.1%)
Ananth N Mavinakayanahalli     1 (9.1%)
========================== ===== =======

Developers with the most report credits
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Total 7

========================== === =======
Developer                    #   %
========================== === =======
Hank Chang                   4 (57.1%)
Guilherme G. Piccoli         1 (14.3%)
Colin Ian King               1 (14.3%)
Pradipta Ghosh               1 (14.3%)
========================== === =======


Developers who gave the most report credits
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Total 7

========================== === =======
Developer                    #  %
========================== === =======
Gavin Shan                   5 (71.4%)
Andrew Donnellan             1 (14.3%)
Jeremy Kerr                  1 (14.3%)
========================== === =======
