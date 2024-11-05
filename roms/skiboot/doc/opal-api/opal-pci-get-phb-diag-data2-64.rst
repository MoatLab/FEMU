.. _OPAL_PCI_GET_PHB_DIAG_DATA2:

OPAL_PCI_GET_PHB_DIAG_DATA2
===========================

.. code-block:: c

   #define OPAL_PCI_GET_PHB_DIAG_DATA2		64

   /**
    * This structure defines the overlay which will be used to store PHB error
    * data upon request.
    */
    enum {
	OPAL_PHB_ERROR_DATA_VERSION_1 = 1,
    };

   enum {
	OPAL_PHB_ERROR_DATA_TYPE_P7IOC = 1,
	OPAL_PHB_ERROR_DATA_TYPE_PHB3 = 2,
	OPAL_PHB_ERROR_DATA_TYPE_PHB4 = 3
   };

   enum {
	OPAL_P7IOC_NUM_PEST_REGS = 128,
	OPAL_PHB3_NUM_PEST_REGS = 256,
	OPAL_PHB4_NUM_PEST_REGS = 512
   };

   struct OpalIoPhbErrorCommon {
	__be32 version;
	__be32 ioType;
	__be32 len;
   };

   struct OpalIoP7IOCPhbErrorData {
	struct OpalIoPhbErrorCommon common;

	__be32 brdgCtl;

	// P7IOC utl regs
	__be32 portStatusReg;
	__be32 rootCmplxStatus;
	__be32 busAgentStatus;

	// P7IOC cfg regs
	__be32 deviceStatus;
	__be32 slotStatus;
	__be32 linkStatus;
	__be32 devCmdStatus;
	__be32 devSecStatus;

	// cfg AER regs
	__be32 rootErrorStatus;
	__be32 uncorrErrorStatus;
	__be32 corrErrorStatus;
	__be32 tlpHdr1;
	__be32 tlpHdr2;
	__be32 tlpHdr3;
	__be32 tlpHdr4;
	__be32 sourceId;

	__be32 rsv3;

	// Record data about the call to allocate a buffer.
	__be64 errorClass;
	__be64 correlator;

	//P7IOC MMIO Error Regs
	__be64 p7iocPlssr;                // n120
	__be64 p7iocCsr;                  // n110
	__be64 lemFir;                    // nC00
	__be64 lemErrorMask;              // nC18
	__be64 lemWOF;                    // nC40
	__be64 phbErrorStatus;            // nC80
	__be64 phbFirstErrorStatus;       // nC88
	__be64 phbErrorLog0;              // nCC0
	__be64 phbErrorLog1;              // nCC8
	__be64 mmioErrorStatus;           // nD00
	__be64 mmioFirstErrorStatus;      // nD08
	__be64 mmioErrorLog0;             // nD40
	__be64 mmioErrorLog1;             // nD48
	__be64 dma0ErrorStatus;           // nD80
	__be64 dma0FirstErrorStatus;      // nD88
	__be64 dma0ErrorLog0;             // nDC0
	__be64 dma0ErrorLog1;             // nDC8
	__be64 dma1ErrorStatus;           // nE00
	__be64 dma1FirstErrorStatus;      // nE08
	__be64 dma1ErrorLog0;             // nE40
	__be64 dma1ErrorLog1;             // nE48
	__be64 pestA[OPAL_P7IOC_NUM_PEST_REGS];
	__be64 pestB[OPAL_P7IOC_NUM_PEST_REGS];
   };

   struct OpalIoPhb3ErrorData {
	struct OpalIoPhbErrorCommon common;

	__be32 brdgCtl;

	/* PHB3 UTL regs */
	__be32 portStatusReg;
	__be32 rootCmplxStatus;
	__be32 busAgentStatus;

	/* PHB3 cfg regs */
	__be32 deviceStatus;
	__be32 slotStatus;
	__be32 linkStatus;
	__be32 devCmdStatus;
	__be32 devSecStatus;

	/* cfg AER regs */
	__be32 rootErrorStatus;
	__be32 uncorrErrorStatus;
	__be32 corrErrorStatus;
	__be32 tlpHdr1;
	__be32 tlpHdr2;
	__be32 tlpHdr3;
	__be32 tlpHdr4;
	__be32 sourceId;

	__be32 rsv3;

	/* Record data about the call to allocate a buffer */
	__be64 errorClass;
	__be64 correlator;

	/* PHB3 MMIO Error Regs */
	__be64 nFir;			/* 000 */
	__be64 nFirMask;		/* 003 */
	__be64 nFirWOF;		/* 008 */
	__be64 phbPlssr;		/* 120 */
	__be64 phbCsr;		/* 110 */
	__be64 lemFir;		/* C00 */
	__be64 lemErrorMask;		/* C18 */
	__be64 lemWOF;		/* C40 */
	__be64 phbErrorStatus;	/* C80 */
	__be64 phbFirstErrorStatus;	/* C88 */
	__be64 phbErrorLog0;		/* CC0 */
	__be64 phbErrorLog1;		/* CC8 */
	__be64 mmioErrorStatus;	/* D00 */
	__be64 mmioFirstErrorStatus;	/* D08 */
	__be64 mmioErrorLog0;		/* D40 */
	__be64 mmioErrorLog1;		/* D48 */
	__be64 dma0ErrorStatus;	/* D80 */
	__be64 dma0FirstErrorStatus;	/* D88 */
	__be64 dma0ErrorLog0;		/* DC0 */
	__be64 dma0ErrorLog1;		/* DC8 */
	__be64 dma1ErrorStatus;	/* E00 */
	__be64 dma1FirstErrorStatus;	/* E08 */
	__be64 dma1ErrorLog0;		/* E40 */
	__be64 dma1ErrorLog1;		/* E48 */
	__be64 pestA[OPAL_PHB3_NUM_PEST_REGS];
	__be64 pestB[OPAL_PHB3_NUM_PEST_REGS];
   };

   struct OpalIoPhb4ErrorData {
	struct OpalIoPhbErrorCommon common;

	__be32 brdgCtl;

	/* XXX missing UTL registers? */

	/* PHB4 cfg regs */
	__be32 deviceStatus;
	__be32 slotStatus;
	__be32 linkStatus;
	__be32 devCmdStatus;
	__be32 devSecStatus;

	/* cfg AER regs */
	__be32 rootErrorStatus;
	__be32 uncorrErrorStatus;
	__be32 corrErrorStatus;
	__be32 tlpHdr1;
	__be32 tlpHdr2;
	__be32 tlpHdr3;
	__be32 tlpHdr4;
	__be32 sourceId;

	/* PHB4 ETU Error Regs */
	__be64 nFir;				/* 000 */
	__be64 nFirMask;			/* 003 */
	__be64 nFirWOF;				/* 008 */
	__be64 phbPlssr;			/* 120 */
	__be64 phbCsr;				/* 110 */
	__be64 lemFir;				/* C00 */
	__be64 lemErrorMask;			/* C18 */
	__be64 lemWOF;				/* C40 */
	__be64 phbErrorStatus;			/* C80 */
	__be64 phbFirstErrorStatus;		/* C88 */
	__be64 phbErrorLog0;			/* CC0 */
	__be64 phbErrorLog1;			/* CC8 */
	__be64 phbTxeErrorStatus;		/* D00 */
	__be64 phbTxeFirstErrorStatus;		/* D08 */
	__be64 phbTxeErrorLog0;			/* D40 */
	__be64 phbTxeErrorLog1;			/* D48 */
	__be64 phbRxeArbErrorStatus;		/* D80 */
	__be64 phbRxeArbFirstErrorStatus;	/* D88 */
	__be64 phbRxeArbErrorLog0;		/* DC0 */
	__be64 phbRxeArbErrorLog1;		/* DC8 */
	__be64 phbRxeMrgErrorStatus;		/* E00 */
	__be64 phbRxeMrgFirstErrorStatus;	/* E08 */
	__be64 phbRxeMrgErrorLog0;		/* E40 */
	__be64 phbRxeMrgErrorLog1;		/* E48 */
	__be64 phbRxeTceErrorStatus;		/* E80 */
	__be64 phbRxeTceFirstErrorStatus;	/* E88 */
	__be64 phbRxeTceErrorLog0;		/* EC0 */
	__be64 phbRxeTceErrorLog1;		/* EC8 */

	/* PHB4 REGB Error Regs */
	__be64 phbPblErrorStatus;		/* 1900 */
	__be64 phbPblFirstErrorStatus;		/* 1908 */
	__be64 phbPblErrorLog0;			/* 1940 */
	__be64 phbPblErrorLog1;			/* 1948 */
	__be64 phbPcieDlpErrorLog1;		/* 1AA0 */
	__be64 phbPcieDlpErrorLog2;		/* 1AA8 */
	__be64 phbPcieDlpErrorStatus;		/* 1AB0 */
	__be64 phbRegbErrorStatus;		/* 1C00 */
	__be64 phbRegbFirstErrorStatus;		/* 1C08 */
	__be64 phbRegbErrorLog0;		/* 1C40 */
	__be64 phbRegbErrorLog1;		/* 1C48 */

	__be64 pestA[OPAL_PHB4_NUM_PEST_REGS];
	__be64 pestB[OPAL_PHB4_NUM_PEST_REGS];
   };

   int64_t opal_pci_get_phb_diag_data2(uint64_t phb_id, void *diag_buffer, uint64_t diag_buffer_len);

Get PCI diagnostic data from a given PHB. Each PHB present in the device tree
has a ``ibm,phb-diag-data-size`` property which is the size of the diagnostic
data structure that can be returned.

Each PHB generation has a different structure for diagnostic data, and the
small common structure will allow the OS to work out what format the data
is coming in.

In future, it's possible that the format will change to be more flexible, and
require less OS support.

Parameters
----------
``uint64_t phb_id``
  the ID of the PHB you want to retrieve data from

``void *diag_buffer``
  an allocated buffer to store diag data in

``uint64_t diag_buffer_len``
  size in bytes of the diag buffer

Calling
-------

Retrieve the PHB's diagnostic data.  The diagnostic data is stored in the
buffer pointed by @diag_buffer.  Different PHB versions will store different
diagnostics, defined in include/opal-api.h as ``struct OpalIo<PHBVer>ErrorData``.

:ref:`OPAL_PCI_GET_PHB_DIAG_DATA` is deprecated and
:ref:`OPAL_PCI_GET_PHB_DIAG_DATA2` should be used instead.

Return Codes
------------
:ref:`OPAL_SUCCESS`
  Diagnostic data has been retrieved and stored successfully
:ref:`OPAL_PARAMETER`
  The given buffer is too small to store the diagnostic data
:ref:`OPAL_HARDWARE`
  The PHB is in a broken state and its data cannot be retreived
:ref:`OPAL_UNSUPPORTED`
  Diagnostic data is not implemented for this PHB type
