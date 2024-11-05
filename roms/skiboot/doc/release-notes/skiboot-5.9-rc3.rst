.. _skiboot-5.9-rc3:

skiboot-5.9-rc3
===============

skiboot v5.9-rc3 was released on Wednesday October 18th 2017. It is the third
release candidate of skiboot 5.9, which will become the new stable release
of skiboot following the 5.8 release, first released August 31st 2017.

skiboot v5.9-rc3 contains all bug fixes as of :ref:`skiboot-5.4.8`
and :ref:`skiboot-5.1.21` (the currently maintained stable releases). We
do not currently expect to do any 5.8.x stable releases.

For how the skiboot stable releases work, see :ref:`stable-rules` for details.

The current plan is to cut the final 5.9 by October 20th, with skiboot 5.9
being for all POWER8 and POWER9 platforms in op-build v1.20 (Due October 18th).
This release will be targetted to early POWER9 systems.

Over :ref:`skiboot-5.9-rc2`, we have the following changes:


- Improvements to vpd device tree entries

  Previously we would miss some properties
- Revert "npu2: Add vendor cap for IRQ testing"

  This reverts commit 9817c9e29b6fe00daa3a0e4420e69a97c90eb373 which seems to
  break setting the PCI dev flag and the link number in the PCIe vendor
  specific config space. This leads to the device driver attempting to
  re-init the DL when it shouldn't which can cause HMI's.

- hw/imc: Fix IMC Catalog load for DD2.X processors
- cpu: Add OPAL_REINIT_CPUS_TM_SUSPEND_DISABLED

  Add a new CPU reinit flag, "TM Suspend Disabled", which requests that
  CPUs be configured so that TM (Transactional Memory) suspend mode is
  disabled.

  Currently this always fails, because skiboot has no way to query the
  state. A future hostboot change will add a mechanism for skiboot to
  determine the status and return an appropriate error code.
