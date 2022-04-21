.. _skiboot-5.10-rc3:

skiboot-5.10-rc3
================

skiboot v5.10-rc3 was released on Thursday February 15th 2018. It is the third
release candidate of skiboot 5.10, which will become the new stable release
of skiboot following the 5.9 release, first released October 31st 2017.

skiboot v5.10-rc3 contains all bug fixes as of :ref:`skiboot-5.9.8`
and :ref:`skiboot-5.4.9` (the currently maintained stable releases). There
may be more 5.9.x stable releases, it will depend on demand.

For how the skiboot stable releases work, see :ref:`stable-rules` for details.

The current plan is to cut the final 5.10 in February, with skiboot 5.10
being for all POWER8 and POWER9 platforms in op-build v1.21.
This release will be targeted to early POWER9 systems.

Over skiboot-5.10-rc2, we have the following changes:

- vas: Disable VAS/NX-842 on some P9 revisions

  VAS/NX-842 are not functional on some P9 revisions, so disable them
  in hardware and skip creating their device tree nodes.

  Since the intent is to prevent OS from configuring VAS/NX, we remove
  only the platform device nodes but leave the VAS/NX DT nodes under
  xscom (i.e we don't skip add_vas_node() in hdata/spira.c)
- phb4: Only escalate freezes on MMIO load where necessary

  In order to work around a hardware issue, MMIO load freezes were
  escalated to fences on every chip.  Now that hardware no longer requires
  this, restrict escalation to the chips that actually need it.
- pflash: Fix makefile dependency issue
- DT: Add "version" property under ibm, firmware-versions node

  First line of VERSION section in PNOR contains firmware version.
  Use that to add "version" property under firmware versions dt node.

  Sample output:

  .. code-block:: console

     root@xxx2:/proc/device-tree/ibm,firmware-versions# lsprop
     version          "witherspoon-ibm-OP9_v1.19_1.94"

- npu2: Disable TVT range check when in bypass mode

  On POWER9 the GPUs need to be able to access the MMIO memory space. Therefore
  the TVT range check needs to include the MMIO address space. As any possible
  range check would cover all of memory anyway this patch just disables the TVT
  range check all together when bypassing the TCE tables.
- hw/npu2: support creset of npu2 devices

  creset calls in the hw procedure that resets the PHY, we don't
  take them out of reset, just put them in reset.

  this fixes a kexec issue.
- ATTN: Enable flush instruction cache bit in HID register

  In P9, we have to enable "flush the instruction cache" bit along with
  "attn instruction support" bit to trigger attention.
- capi: Enable channel tag streaming for PHB in CAPP mode

  We re-enable channel tag streaming for PHB in CAPP mode as without it
  PEC was waiting for cresp for each DMA write command before sending a
  new DMA write command on the Powerbus. This resulted in much lower DMA
  write performance than expected.

  The patch updates enable_capi_mode() to remove the masking of
  channel_streaming_en bit in PBCQ Hardware Configuration Register. Also
  does some re-factoring of the code that updates this register to use
  xscom_write_mask instead of xscom_read followed by a xscom_write.
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
