.. _OPAL_PCI_RESET:

OPAL_PCI_RESET
==============

.. code-block:: c

   #define OPAL_PCI_RESET				49

   enum OpalPciResetScope {
	OPAL_RESET_PHB_COMPLETE		= 1,
	OPAL_RESET_PCI_LINK		= 2,
	OPAL_RESET_PHB_ERROR		= 3,
	OPAL_RESET_PCI_HOT		= 4,
	OPAL_RESET_PCI_FUNDAMENTAL	= 5,
	OPAL_RESET_PCI_IODA_TABLE	= 6
   };

   enum OpalPciResetState {
	OPAL_DEASSERT_RESET = 0,
	OPAL_ASSERT_RESET   = 1
   };

   int64_t opal_pci_reset(uint64_t id, uint8_t reset_scope, uint8_t assert_state);

Kick off the requested PCI reset operation. This starts a state machine off to
perform the requested operation. This call will return how many milliseconds to
wait before calling back into :ref:`OPAL_PCI_POLL`. An OS can
call :ref:`OPAL_PCI_POLL` earlier, but it is unlikely any progress will have
been made.


Returns
-------

:ref:`OPAL_PARAMETER`
     Invalid ``id``, ``reset_scope``, or ``assert_state``.
:ref:`OPAL_UNSUPPORTED`
     Operation is unsupported on ``id``.
value > 0
     How many ms to wait for the state machine to crank.
     Call :ref:`OPAL_PCI_POLL` to crank the state machine further.
