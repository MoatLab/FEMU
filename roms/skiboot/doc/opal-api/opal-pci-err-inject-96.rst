.. _OPAL_PCI_ERR_INJECT:

OPAL_PCI_ERR_INJECT
===================

.. code-block:: c

   #define OPAL_PCI_ERR_INJECT			96

   enum OpalErrinjectType {
	OPAL_ERR_INJECT_TYPE_IOA_BUS_ERR	= 0,
	OPAL_ERR_INJECT_TYPE_IOA_BUS_ERR64	= 1,
   };

   enum OpalErrinjectFunc {
	/* IOA bus specific errors */
	OPAL_ERR_INJECT_FUNC_IOA_LD_MEM_ADDR	= 0,
	OPAL_ERR_INJECT_FUNC_IOA_LD_MEM_DATA	= 1,
	OPAL_ERR_INJECT_FUNC_IOA_LD_IO_ADDR	= 2,
	OPAL_ERR_INJECT_FUNC_IOA_LD_IO_DATA	= 3,
	OPAL_ERR_INJECT_FUNC_IOA_LD_CFG_ADDR	= 4,
	OPAL_ERR_INJECT_FUNC_IOA_LD_CFG_DATA	= 5,
	OPAL_ERR_INJECT_FUNC_IOA_ST_MEM_ADDR	= 6,
	OPAL_ERR_INJECT_FUNC_IOA_ST_MEM_DATA	= 7,
	OPAL_ERR_INJECT_FUNC_IOA_ST_IO_ADDR	= 8,
	OPAL_ERR_INJECT_FUNC_IOA_ST_IO_DATA	= 9,
	OPAL_ERR_INJECT_FUNC_IOA_ST_CFG_ADDR	= 10,
	OPAL_ERR_INJECT_FUNC_IOA_ST_CFG_DATA	= 11,
	OPAL_ERR_INJECT_FUNC_IOA_DMA_RD_ADDR	= 12,
	OPAL_ERR_INJECT_FUNC_IOA_DMA_RD_DATA	= 13,
	OPAL_ERR_INJECT_FUNC_IOA_DMA_RD_MASTER	= 14,
	OPAL_ERR_INJECT_FUNC_IOA_DMA_RD_TARGET	= 15,
	OPAL_ERR_INJECT_FUNC_IOA_DMA_WR_ADDR	= 16,
	OPAL_ERR_INJECT_FUNC_IOA_DMA_WR_DATA	= 17,
	OPAL_ERR_INJECT_FUNC_IOA_DMA_WR_MASTER	= 18,
	OPAL_ERR_INJECT_FUNC_IOA_DMA_WR_TARGET	= 19,
   };

   int64_t opal_pci_err_inject(uint64_t phb_id, uint64_t pe_number,
                               uint32_t type, uint32_t func,
                               uint64_t addr, uint64_t mask);

Inject an error, used to test OS and OPAL EEH handling.

Returns
-------

:ref:`OPAL_SUCCESS`
     Error injected successfully.
:ref:`OPAL_PARAMETER`
     Invalid argument.
:ref:`OPAL_UNSUPPORTED`
     PHB doesn't support error injection or the specific error attempting to
     be injected.
