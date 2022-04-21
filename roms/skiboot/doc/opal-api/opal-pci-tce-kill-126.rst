.. _OPAL_PCI_TCE_KILL:

OPAL_PCI_TCE_KILL
=================

.. code-block:: c

   int64_t opal_pci_tce_kill(uint64_t phb_id,
			  uint32_t kill_type,
			  uint64_t pe_number,
			  uint32_t tce_size,
			  uint64_t dma_addr,
			  uint32_t npages);

An abstraction around TCE kill. This allows host OS kernels to use an OPAL
call if they don't know the model specific invalidation method.

Where kill_type is one of:

.. code-block:: c

  enum {
     OPAL_PCI_TCE_KILL_PAGES,
     OPAL_PCI_TCE_KILL_PE,
     OPAL_PCI_TCE_KILL_ALL,
  };

Not all PHB types currently support this abstraction. It is supported in
PHB4, which means from POWER9 onwards it will be present.

Returns
-------
:ref:`OPAL_PARAMETER`
  if ``phb_id`` is invalid (or similar)
:ref:`OPAL_UNSUPPORTED`
  if PHB model doesn't support this call. This is likely
  true for systems before POWER9/PHB4.
  Do *NOT* rely on this call existing for systems prior to
  POWER9 (i.e. PHB4).

Example code (from linux/arch/powerpc/platforms/powernv/pci-ioda.c)

.. code-block:: c

  static inline void pnv_pci_ioda2_tce_invalidate_pe(struct pnv_ioda_pe *pe)
  {
	struct pnv_phb *phb = pe->phb;

	if (phb->model == PNV_PHB_MODEL_PHB3 && phb->regs)
	   pnv_pci_phb3_tce_invalidate_pe(pe);
	else
	   opal_pci_tce_kill(phb->opal_id, OPAL_PCI_TCE_KILL_PE,
			     pe->pe_number, 0, 0, 0);
  }

and

.. code-block:: c

  struct pnv_phb *phb = pe->phb;
  unsigned int shift = tbl->it_page_shift;

  if (phb->model == PNV_PHB_MODEL_PHB3 && phb->regs)
	pnv_pci_phb3_tce_invalidate(pe, rm, shift,
				    index, npages);
  else
	opal_pci_tce_kill(phb->opal_id,
			  OPAL_PCI_TCE_KILL_PAGES,
			  pe->pe_number, 1u << shift,
			  index << shift, npages);
