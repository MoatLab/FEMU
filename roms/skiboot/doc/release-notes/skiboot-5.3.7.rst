.. _skiboot-5.3.7:

skiboot-5.3.7
-------------

skiboot-5.3.7 was released on Wednesday October 12th, 2016.

This is the 8th stable release of skiboot 5.3, the new stable release of
skiboot (first released with 5.3.0 on August 2nd, 2016).

Skiboot 5.3.7 replaces skiboot-5.3.6 as the current stable version. It contains
a few bugfixes, including an important PCI bug fix that could cause some
adapters to not be detected.

Over skiboot-5.3.6, the following fixes are included:

PCI:

- pci: Avoid hot resets at boot time
    In the PCI post-fundamental reset code, a hot reset is performed at the
    end.  This is causing issues at boot time as a reset signal is being sent
    downstream before the links are up, which is causing issues on adapters
    behind switches.  No errors result in skiboot, but the adapters are not
    usable in Linux as a result.

    This patch fixes some adapters not being configurable in Linux on some
    systems.  The issue was not present in skiboot 5.2.x.

- core/pci: Fix the power-off timeout in pci_slot_power_off()
    The timeout should be 1000ms instead of 1000 ticks while powering
    off PCI slot in pci_slot_power_off(). Otherwise, it's likely to
    hit timeout powering off the PCI slot as below skiboot logs reveal:

    [47912590456,5] SkiBoot skiboot-5.3.6 starting...
    (snip)
    [5399532365,7] PHB#0005:02:11.0 Bus 0f..ff  scanning...
    [5399540804,7] PHB#0005:02:11.0 No card in slot
    [5399576870,5] PHB#0005:02:11.0 Timeout powering off slot
    [5401431782,3] FIRENZE-PCI: Wrong state 00000000 on slot 8000000002880005

PRD:

- occ/prd/opal-prd: Queue OCC_RESET event message to host in OpenPOWER
    During an OCC reset cycle the system is forced to Psafe pstate.
    When OCC becomes active, the system has to be restored to its
    last pstate as requested by host. So host needs to be notified
    of OCC_RESET event or else system will continue to remian in
    Psafe state until host requests a new pstate after the OCC
    reset cycle.
- opal-prd: Fix error code from scom_read & scom_write
    Currently, we always return a zero value from scom_read & scom_write,
    so the HBRT implementation has no way of detecting errors during scom
    operations.
    This change uses the actual return value from the scom operation from
    the kernel instead.

- opal-prd: Add get_interface_capabilities to host interfaces
    We need a way to indicate behaviour changes & fixes in the prd
    interface, without requiring a major version bump.

    This change introduces the get_interface_capabilities callback,
    returning a bitmask of capability flags, pertaining to 'sets' of
    capabilities. We currently return 0 for all.

IBM FSP Platforms:

- platforms/firenze: Fix clock frequency dt property
- platforms/firence: HDAT: Fix typo in nest-frequency property

NVLink:

- hw/npu.c: Fix reserved PE#
    Currently the reserved PE is set to NPU_NUM_OF_PES, which is one
    greater than the maximum PE resulting in the following kernel errors
    at boot:

    [    0.000000] pnv_ioda_reserve_pe: Invalid PE 4 on PHB#4
    [    0.000000] pnv_ioda_reserve_pe: Invalid PE 4 on PHB#5

    Due to a HW errata PE#0 is already reserved in the kernel, so update
    the opal-reserved-pe device-tree property to match this.
