.. _skiboot-5.5.0-rc2:

skiboot-5.5.0-rc2
=================

skiboot-5.5.0-rc2 was released on Monday April 3rd 2017. It is the second
release candidate of skiboot 5.5, which will become the new stable release
of skiboot following the 5.4 release, first released November 11th 2016.

skiboot-5.5.0-rc2 contains all bug fixes as of :ref:`skiboot-5.4.3`
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

Over :ref:`skiboot-5.5.0-rc1`, we have the following changes:

NVLINK2
-------

- Introduce NPU2 support

  NVLink2 is a new feature introduced on POWER9 systems. It is an
  evolution of of the NVLink1 feature included in POWER8+ systems but
  adds several new features including support for GPU address
  translation using the Nest MMU and cache coherence.

  Similar to NVLink1 the functionality is exposed to the OS as a series
  of virtual PCIe devices. However the actual hardware interfaces are
  significantly different which limits the amount of common code that
  can be shared between implementations in the firmware.

  This patch adds basic hardware initialisation and exposure of the
  virtual NVLink2 PCIe devices to the running OS.

- npu2: Add OPAL calls for nvlink2 address translation services (see :ref:`OPAL_NPU2`)

  Adds three OPAL calls for interacting with NPU2 devices:
  :ref:`OPAL_NPU_INIT_CONTEXT`, :ref:`OPAL_NPU_DESTROY_CONTEXT` and
  :ref:`OPAL_NPU_MAP_LPAR`.

  These are used to setup and configure address translation services
  (ATS) for a process/partition on a given NVLink2 device.


POWER9
------
- hdata/memory: ignore homer and occ reserved ranges

  We populate these from the HOMER BARs in the PBA directly. There's no
  need to take the hostboot supplied values so just ignore the
  corresponding reserved ranges.

- hdata/vpd: Parse the OpenPOWER OPFR record

  Parse the OpenPOWER FRU VPD (OPFR) record on OpenPOWER instead
  of the VINI records.

- hdata/vpd: Parse additional VINI records

  These records provide hardware version details, CCIN extension information,
  card type details and hardware characteristics of the FRU

- hdata/cpu: account for p9 shared caches

  On P9 the L2 and L3 caches are shared between pairs of SMT=4 cores.
  Currently this is not accounted for when creating caches nodes in
  the device tree. This patch adds additional checking so that a
  cache node is only created for the first core in the pair and
  the second core will reference the cache correctly.

- hdata: print backtraces on HDAT errors
- hdat: ignore zero length reserves

  Hostboot can export reserved regions with a length of zero and these
  should be ignored rather than being turned into reserved range. While
  we're here fix a memory leak by moving the "too large" region check
  to before we allocate space for the label.

- SLW: Add init for power9 power management

  This patch adds new function to init core for power9 power management.
  SPECIAL_WKUP_* SCOM registers, if set, can hold the cores from going into
  idle states. Hence, clear PPM_SPECIAL_WKUP_HYP_REG scom register for each
  core during init. (This init are not required for MAMBO)


PCI
---

- hw/phb3: Adjust ECRC on root port dynamically

  The Samsung NVMe adapter is lost when it's connected to PMC 8546 PCIe
  switch, until ECRC is disabled on the root port. We found similar issue
  prevously when Broadcom adapter is connected to same part of PCIe switch
  and it was fixed by commit 60ce59ccd0e9 ("hw/phb3: Disable ECRC on Broadcom
  adapter behind PMC switch"). Unfortunately, the commit doesn't fix
  the Samsung NVMe adapter lost issue.

  This fixes the issues by disable ECRC generation/check on root port
  when PMC 8546 PCIe switch ports are found. This can be extended for
  other PCIe switches or endpoints in future: Each PHB maintains the
  count of PCI devices (PMC 8546 PCIe switch ports currently) which
  require to disable ECRC on root port. The ECRC functionality is
  enabled when first PMC 8546 switch port is probed and disabled when
  last PMC 8546 switch port is destroyed (in PCI hot remove scenario).
  Except PHB's reinitialization after complete reset, the ECRC on
  root port is untouched.

- core/pci: Fix lost NVMe adapter behind PMC 8546 switch

  The NVMe adapter in below PCI topology is lost. The root cause is
  the presence bit on its PCI slot is missed, but the PCIe link has
  been up. The PCI core doesn't probe the adapter behind the slot,
  leading to lost NVMe adapter in the particular case.

  - PHB3 root port
  - PLX switch 8748 (10b5:8748)
  - PLX swich 9733 (10b5:9733)
  - PMC 8546 swtich (11f8:8546)
  - NVMe adapter (1c58:0023)

  This fixes the issue by overriding the PCI slot presence bit with
  PCIe link state bit.
- hw/phb4: Locate AER capability position if necessary
- core/pci: Disable surprise hotplug on root port
- core/pci: Ignore PCI slot capability on root port

  We are creating PCI slot on root port, where the PCI slot isn't
  supported from hardware. For this case, we shouldn't read the PCI
  slot capability from hardware. When bogus data returned from the
  hardware, we will attempt to the PCI slot's power state or enable
  surprise hotplug functionality. All of them can't be accomplished
  without hardware support.

  This leaves the PCI slot's capability list 0 if PCICAP_EXP_CAP_SLOT
  isn't set in hardware (pcie_cap + 0x2). Otherwise, the PCI slot's
  capability list is retrieved from hardware (pcie_cap + 0x14).


- phb4: Default to PCIe GEN2 on DD1

  Default to PCIe GEN2 link speeds on DD1 for stability.

  Can be overridden using nvram pcie-max-link-speed=4 parameter.

- phb3/4: Set max link speed via nvram

  This adds an nvram parameter pcie-max-link-speed to configure the max
  speed of the pcie link.  This can be set from the petitboot prompt
  using: ::

    nvram -p ibm,skiboot --update-config pcie-max-link-speed=4

  This takes preference over anything set in the device tree and is
  global to all PHBs.

Tests
-----

- Mambo/Qemu boot tests: expect (and fail) on checkstop

  This allows us to fail a lot faster if we checkstop
