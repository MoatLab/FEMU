PCI
===

Debugging
---------

There exist a couple of NVRAM options for enabling extra debug functionality
to help debug PCI issues. These are not ABI and may be changed or removed at
**any** time.

Verbose EEH
^^^^^^^^^^^

::

   nvram -p ibm,skiboot --update-config pci-eeh-verbose=true

Disable EEH MMIO
^^^^^^^^^^^^^^^^
::
   nvram -p ibm,skiboot --update-config pci-eeh-mmio=disabled


Check for RX errors after link training
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Some PHB4 PHYs can get stuck in a bad state where they are constantly
retraining the link. This happens transparently to skiboot and Linux
but will causes PCIe to be slow. Resetting the PHB4 clears the
problem.

We can detect this case by looking at the RX errors count where we
check for link stability. This patch does this by modifying the link
optimal code to check for RX errors. If errors are occurring we
retrain the link irrespective of the chip rev or card.

Normally when this problem occurs, the RX error count is maxed out at
255. When there is no problem, the count is 0. We chose 8 as the max
rx errors value to give us some margin for a few errors. There is also
a knob that can be used to set the error threshold for when we should
retrain the link. i.e. ::

      nvram -p ibm,skiboot --update-config phb-rx-err-max=8

Retrain link if degraded
^^^^^^^^^^^^^^^^^^^^^^^^

On P9 Scale Out (Nimbus) DD2.0 and Scale in (Cumulus) DD1.0 (and
below) the PCIe PHY can lockup causing training issues. This can cause
a degradation in speed or width in ~5% of training cases (depending on
the card). This is fixed in later chip revisions. This issue can also
cause PCIe links to not train at all, but this case is already
handled.

There is code in skiboot that checks if the PCIe link has trained optimally
and if not, does a full PHB reset (to fix the PHY lockup) and retrain.

One complication is some devices are known to train degraded unless
device specific configuration is performed. Because of this, we only
retrain when the device is in a whitelist. All devices in the current
whitelist have been testing on a P9DSU/Boston, ZZ and Witherspoon.

We always gather information on the link and print it in the logs even
if the card is not in the whitelist.

For testing purposes, there's an nvram to retry all PCIe cards and all
P9 chips when a degraded link is detected. The new option is
'pci-retry-all=true' which can be set using: ::

  nvram -p ibm,skiboot --update-config pci-retry-all=true

This option may increase the boot time if used on a badly behaving
card.

Maximum link speed
^^^^^^^^^^^^^^^^^^

Was useful during bringup on P9 DD1.

::
   nvram -p ibm,skiboot --update-config pcie-max-link-speed=4


Ric Mata Mode
^^^^^^^^^^^^^

This mode (for PHB4) will trace the training process closely. This activates
as soon as PERST is deasserted and produces human readable output of
the process.

It will also add the PCIe Link Training and Status State Machine (LTSSM) tracing
and details on speed and link width.

Output looks a bit like this ::

  [    1.096995141,3] PHB#0000[0:0]: TRACE:0x0000001101000000  0ms          GEN1:x16:detect
  [    1.102849137,3] PHB#0000[0:0]: TRACE:0x0000102101000000 11ms presence GEN1:x16:polling
  [    1.104341838,3] PHB#0000[0:0]: TRACE:0x0000182101000000 14ms training GEN1:x16:polling
  [    1.104357444,3] PHB#0000[0:0]: TRACE:0x00001c5101000000 14ms training GEN1:x16:recovery
  [    1.104580394,3] PHB#0000[0:0]: TRACE:0x00001c5103000000 14ms training GEN3:x16:recovery
  [    1.123259359,3] PHB#0000[0:0]: TRACE:0x00001c5104000000 51ms training GEN4:x16:recovery
  [    1.141737656,3] PHB#0000[0:0]: TRACE:0x0000144104000000 87ms presence GEN4:x16:L0
  [    1.141752318,3] PHB#0000[0:0]: TRACE:0x0000154904000000 87ms trained  GEN4:x16:L0
  [    1.141757964,3] PHB#0000[0:0]: TRACE: Link trained.
  [    1.096834019,3] PHB#0001[0:1]: TRACE:0x0000001101000000  0ms          GEN1:x16:detect
  [    1.105578525,3] PHB#0001[0:1]: TRACE:0x0000102101000000 17ms presence GEN1:x16:polling
  [    1.112763075,3] PHB#0001[0:1]: TRACE:0x0000183101000000 31ms training GEN1:x16:config
  [    1.112778956,3] PHB#0001[0:1]: TRACE:0x00001c5081000000 31ms training GEN1:x08:recovery
  [    1.113002083,3] PHB#0001[0:1]: TRACE:0x00001c5083000000 31ms training GEN3:x08:recovery
  [    1.114833873,3] PHB#0001[0:1]: TRACE:0x0000144083000000 35ms presence GEN3:x08:L0
  [    1.114848832,3] PHB#0001[0:1]: TRACE:0x0000154883000000 35ms trained  GEN3:x08:L0
  [    1.114854650,3] PHB#0001[0:1]: TRACE: Link trained.

Enabled via NVRAM: ::

  nvram -p ibm,skiboot --update-config pci-tracing=true

Named after the person the output of this mode is typically sent to.


**WARNING**: The documentation below **urgently needs updating** and is *woefully* incomplete.

IODA PE Setup Sequences
-----------------------

(**WARNING**: this was rescued from old internal documentation. Needs verification)

To setup basic PE mappings, the host performs this basic sequence:

For ibm,opal-ioda2, prior to allocating PHB resources to PEs, the host must
allocate memory for PE structures and then calls
``opal_pci_set_phb_table_memory( phb_id, rtt_addr, ivt_addr, ivt_len, rrba_addr, peltv_addr)`` to define them to the PHB. OPAL returns ``OPAL_UNSUPPORTED`` status for ``ibm,opal-ioda`` PHBs.

The host calls ``opal_pci_set_pe( phb_id, pe_number, bus, dev, func, validate_mask, bus_mask, dev_mask, func mask)`` to map a PE to a PCI RID or range of RIDs in the same PE domain.

The host calls ``opal_pci_set_peltv(phb_id, parent_pe, child_pe, state)`` to
set a parent PELT vector bit for the child PE argument to 1 (a child of the
parent) or 0 (not in the parent PE domain).

IODA MMIO Setup Sequences
-------------------------

(**WARNING**: this was rescued from old internal documentation. Needs verification)


The host calls ``opal_pci_phb_mmio_enable( phb_id, window_type, window_num, 0x0)`` to disable the MMIO window.

The host calls ``opal_pci_set_phb_mmio_window( phb_id, mmio_window, starting_real_address, starting_pci_address, segment_size)`` to change the MMIO window location in PCI and/or processor real address space, or to change the size -- and corresponding window size -- of a particular MMIO window.

The host calls ``opal_pci_map_pe_mmio_window( pe_number, mmio_window, segment_number)`` to map PEs to window segments, for each segment mapped to each PE.

The host calls ``opal_pci_phb_mmio_enable( phb_id, window_type, window_num, 0x1)`` to enable the MMIO window.

IODA MSI Setup Sequences
------------------------

(**WARNING**: this was rescued from old internal documentation. Needs verification)

To setup MSIs:

1. For ibm,opal-ioda PHBs, the host chooses an MVE for a PE to use and calls ``opal_pci_set_mve( phb_id, mve_number, pe_number,)`` to setup the MVE for the PE number. HAL treats this call as a NOP and returns hal_success status for ibm,opal-ioda2 PHBs.
2. The host chooses an XIVE to use with a PE and calls
   a. ``opal_pci_set_xive_pe( phb_id, xive_number, pe_number)`` to authorize that PE to signal that XIVE as an interrupt. The host must call this function for each XIVE assigned to a particular PE, but may use this call for all XIVEs prior to calling ``opel_pci_set_mve()`` to bind the PE XIVEs to an MVE. For MSI conventional, the host must bind a unique MVE for each sequential set of 32 XIVEs.
   b. The host forms the interrupt_source_number from the combination of the device tree MSI property base BUID and XIVE number, as an input to ``opal_set_xive(interrupt_source_number, server_number, priority)`` and ``opal_get_xive(interrupt_source_number, server_number, priority)`` to set or return the server and priority numbers within an XIVE.
   c. ``opal_get_msi_64[32](phb_id, mve_number, xive_num, msi_range, msi_address, message_data)`` to determine the MSI DMA address (32 or 64 bit) and message data value for that xive.

      For MSI conventional, the host uses this for each sequential power of 2 set of 1 to 32 MSIs, to determine the MSI DMA address and starting message data value for that MSI range. For MSI-X, the host calls this uniquely for each MSI interrupt with an msi_range input value of 1.
3. For ``ibm,opal-ioda`` PHBs, once the MVE and XIVRs are setup for a PE, the host calls ``opal_pci_set_mve_enable( phb_id, mve_number, state)`` to enable that MVE to be a valid target of MSI DMAs. The host may also call this function to disable an MVE when changing PE domains or states.

IODA DMA Setup Sequences
------------------------

(**WARNING**: this was rescued from old internal documentation. Needs verification)

To Manage DMA Windows :

1. The host calls ``opal_pci_map_pe_dma_window( phb_id, dma_window_number, pe_number, tce_levels, tce_table_addr, tce_table_size, tce_page_size, utin64_t* pci_start_addr )`` to setup a DMA window for a PE to translate through a TCE table structure in KVM memory.
2. The host calls ``opal_pci_map_pe_dma_window_real( phb_id, dma_window_number, pe_number, mem_low_addr, mem_high_addr)`` to setup a DMA window for a PE that is translated (but validated by the PHB as an untranlsated address space authorized to this PE).

Device Tree Bindings
--------------------

See :doc:`device-tree/pci` for device tree information.
