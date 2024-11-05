.. _skiboot-6.3-rc3:

skiboot-6.3-rc3
===============

skiboot v6.3-rc3 was released on Thursday May 2nd 2019. It is the third
release candidate of skiboot 6.3, which will become the new stable release
of skiboot following the 6.2 release, first released December 14th 2018.

Skiboot 6.3 will mark the basis for op-build v2.3. I expect to tag the final
skiboot 6.3 in the next week (I also predicted this last time, so take my
predictions with a large amount of sodium).

skiboot v6.3-rc3 contains all bug fixes as of :ref:`skiboot-6.0.19`,
and :ref:`skiboot-6.2.3` (the currently maintained
stable releases).

For how the skiboot stable releases work, see :ref:`stable-rules` for details.

Over :ref:`skiboot-6.3-rc2`, we have the following changes:


- Expose PNOR Flash partitions to host MTD driver via devicetree

  This makes it possible for the host to directly address each
  partition without requiring each application to directly parse
  the FFS headers.  This has been in use for some time already to
  allow BOOTKERNFW partition updates from the host.

  All partitions except BOOTKERNFW are marked readonly.

  The BOOTKERNFW partition is currently exclusively used by the TalosII platform

- Write boot progress to LPC port 80h

  This is an adaptation of what we currently do for op_display() on FSP
  machines, inventing an encoding for what we can write into the single
  byte at LPC port 80h.

  Port 80h is often used on x86 systems to indicate boot progress/status
  and dates back a decent amount of time. Since a byte isn't exactly very
  expressive for everything that can go on (and wrong) during boot, it's
  all about compromise.

  Some systems (such as Zaius/Barreleye G2) have a physical dual 7 segment
  display that display these codes. So far, this has only been driven by
  hostboot (see hostboot commit 90ec2e65314c).

- Write boot progress to LPC ports 81 and 82

  There's a thought to write more extensive boot progress codes to LPC
  ports 81 and 82 to supplement/replace any reliance on port 80.

  We want to still emit port 80 for platforms like Zaius and Barreleye
  that have the physical display. Ports 81 and 82 can be monitored by a
  BMC though.

- Copy and convert Romulus descriptors to Talos

  Talos II has some hardware differences from Romulus, therefore
  we cannot guarantee Talos II == Romulus in skiboot.  Copy and
  slightly modify the Romulus files for Talos II.

- npu2: Disable Probe-to-Invalid-Return-Modified-or-Owned snarfing by default

  V100 GPUs are known to violate NVLink2 protocol in some cases (one is when
  memory was accessed by the CPU and they by GPU using so called block
  linear mapping) and issue double probes to NPU which can cope with this
  problem only if CONFIG_ENABLE_SNARF_CPM ("disable/enable Probe.I.MO
  snarfing a cp_m") is not set in the CQ_SM Misc Config register #0.
  If the bit is set (which is the case today), NPU issues the machine
  check stop.

  The snarfing feature is designed to detect 2 probes in flight and combine
  them into one.

  This adds a new "opal-npu2-snarf-cpm" nvram variable which controls
  CONFIG_ENABLE_SNARF_CPM for all NVLinks to prevent the machine check
  stop from happening.

  This disables snarfing by default as otherwise a broken GPU driver can
  crash the entire box even when a GPU is passed through to a guest.
  This provides a dial to allow regression tests (might be useful for
  a bare metal). To enable snarfing, the user needs to run: ::

    sudo nvram -p ibm,skiboot --update-config opal-npu2-snarf-cpm=enable

  and reboot the host system.

- hw/npu2: Show name of opencapi error interrupts
- core/pci: Use PHB io-base-location by default for PHB slots

  On witherspoon only the GPU slots and the three pluggable PCI slots
  (SLOT0, 1, 2) have platform defined slot names. For builtin devices such
  as the SATA controller or the PLX switch that fans out to the GPU slots
  we have no location codes which some people consider an issue.

  This patch address the problem by making the ibm,slot-location-code for
  the root port device default to the ibm,io-base-location-code which is
  typically the location code for the system itself.

  e.g. ::

    pciex@600c3c0100000/ibm,loc-code
                     "UOPWR.0000000-Node0-Proc0"

    pciex@600c3c0100000/pci@0/ibm,loc-code
                     "UOPWR.0000000-Node0-Proc0"

    pciex@600c3c0100000/pci@0/usb-xhci@0/ibm,loc-code
                     "UOPWR.0000000-Node0"

  The PHB node, and the root complex nodes have a loc code of the
  processor they are attached to, while the usb-xhci device under the
  root port has a location code of the system itself.

- hw/phb4: Read ibm,loc-code from PBCQ node

  On P9 the PBCQs are subdivided by stacks which implement the PCI Express
  logic. When phb4 was forked from phb3 most of the properties that were
  in the pbcq node moved into the stack node, but ibm,loc-code was not one
  of them. This patch fixes the phb4 init sequence to read the base
  location code from the PBCQ node (parent of the stack node) rather than
  the stack node itself.
- hw/xscom: add missing P9P chip name
- asm/head: balance branches to avoid link stack predictor mispredicts

  The Linux wrapper for OPAL call and return is arranged like this: ::

      __opal_call:
          mflr   r0
          std    r0,PPC_STK_LROFF(r1)
          LOAD_REG_ADDR(r11, opal_return)
          mtlr   r11
          hrfid  -> OPAL

      opal_return:
          ld     r0,PPC_STK_LROFF(r1)
          mtlr   r0
          blr

  When skiboot returns to Linux, it branches to LR (i.e., opal_return)
  with a blr. This unbalances the link stack predictor and will cause
  mispredicts back up the return stack.
- external/mambo: also invoke readline for the non-autorun case
- asm/head.S: set POWER9 radix HID bit at entry

  When running in virtual memory mode, the radix MMU hid bit should not
  be changed, so set this in the initial boot SPR setup.

  As a side effect, fast reboot also has HID0:RADIX bit set by the
  shared spr init, so no need for an explicit call.
- opal-prd: Fix memory leak in is-fsp-system check
- opal-prd: Check malloc return value
- hw/phb4: Squash the IO bridge window

  The PCI-PCI bridge spec says that bridges that implement an IO window
  should hardcode the IO base and limit registers to zero.
  Unfortunately, these registers only define the upper bits of the IO
  window and the low bits are assumed to be 0 for the base and 1 for the
  limit address. As a result, setting both to zero can be mis-interpreted
  as a 4K IO window.

  This patch fixes the problem the same way PHB3 does. It sets the IO base
  and limit values to 0xf000 and 0x1000 respectively which most software
  interprets as a disabled window.

  lspci before patch: ::

    0000:00:00.0 PCI bridge: IBM Device 04c1 (prog-if 00 [Normal decode])
            I/O behind bridge: 00000000-00000fff

  lspci after patch: ::

    0000:00:00.0 PCI bridge: IBM Device 04c1 (prog-if 00 [Normal decode])
            I/O behind bridge: None

- build: link with --orphan-handling=warn

  The linker can warn when the linker script does not explicitly place
  all sections. These orphan sections are placed according to
  heuristics, which may not always be desirable. Enable this warning.
- build: -fno-asynchronous-unwind-tables

  skiboot does not use unwind tables, this option saves about 100kB,
  mostly from .text.
- hw/xscom: Enable sw xstop by default on p9

  This was disabled at some point during bringup to make life easier for
  the lab folks trying to debug NVLink issues. This hack really should
  have never made it out into the wild though, so we now have the
  following situation occuring in the field:

  1) A bad happens
  2) The host kernel recieves an unrecoverable HMI and calls into OPAL to
     request a platform reboot.
  3) OPAL rejects the reboot attempt and returns to the kernel with
     OPAL_PARAMETER.
  4) Kernel panics and attempts to kexec into a kdump kernel.

  A side effect of the HMI seems to be CPUs becoming stuck which results
  in the initialisation of the kdump kernel taking a extremely long time
  (6+ hours). It's also been observed that after performing a dump the
  kdump kernel then crashes itself because OPAL has ended up in a bad
  state as a side effect of the HMI.

  All up, it's not very good so re-enable the software checkstop by
  default. If people still want to turn it off they can using the nvram
  override.
- opal/hmi: Initialize the hmi event with old value of TFMR.

  Do this before we fix TFAC errors. Otherwise the event at host console
  shows no thread error reported in TFMR register.

  Without this patch the console event show TFMR with no thread error:
  (DEC parity error TFMR[59] injection) ::

    [   53.737572] Severe Hypervisor Maintenance interrupt [Recovered]
    [   53.737596]  Error detail: Timer facility experienced an error
    [   53.737611]  HMER: 0840000000000000
    [   53.737621]  TFMR: 3212000870e04000

  After this patch it shows old TFMR value on host console: ::

    [ 2302.267271] Severe Hypervisor Maintenance interrupt [Recovered]
    [ 2302.267305]  Error detail: Timer facility experienced an error
    [ 2302.267320]  HMER: 0840000000000000
    [ 2302.267330]  TFMR: 3212000870e14010
