.. _skiboot-6.3.2:

==============
skiboot-6.3.2
==============

skiboot 6.3.2 was released on Monday July 1st, 2019. It replaces
:ref:`skiboot-6.3.1` as the current stable release in the 6.3.x series.

It is recommended that 6.3.2 be used instead of 6.3.1 version due to the
bug fixes it contains.

Bug fixes included in this release are:

- npu2: Purge cache when resetting a GPU

  After putting all a GPU's links in reset, do a cache purge in case we
  have CPU cache lines belonging to the now-unaccessible GPU memory.

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

- opal-prd: Fix prd message size issue

  If prd messages size is insufficient then read_prd_msg() call fails with
  below error. And caller is not reallocating sufficient buffer. Also its
  hard to guess the size.

  sample log::

    Mar 28 03:31:43 zz24p1 opal-prd: FW: error reading from firmware: alloc 32 rc -1: Invalid argument
    Mar 28 03:31:43 zz24p1 opal-prd: FW: error reading from firmware: alloc 32 rc -1: Invalid argument
    Mar 28 03:31:43 zz24p1 opal-prd: FW: error reading from firmware: alloc 32 rc -1: Invalid argument

  Lets use opal-msg-size device tree property to allocate memory
  for prd message.

- npu2: Fix clearing the FIR bits

  FIR registers are SCOM-only so they cannot be accesses with the indirect
  write, and yet we use SCOM-based addresses for these; fix this.

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

- nvram: Flag dangerous NVRAM options

  Most nvram options used by skiboot are just for debug or testing for
  regressions. They should never be used long term.

  We've hit a number of issues in testing and the field where nvram
  options have been set "temporarily" but haven't been properly cleared
  after, resulting in crashes or real bugs being masked.

  This patch marks most nvram options used by skiboot as dangerous and
  prints a chicken to remind users of the problem.

- devicetree: Don't set path to dtc in makefile

  By setting the path we fail to build under buildroot which has it's own
  set of host tools in PATH, but not at /usr/bin.

  Keep the variable so it can be set if need be but default to whatever
  'dtc' is in the users path.
