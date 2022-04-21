.. _OPAL_PCI_SET_PE:

OPAL_PCI_SET_PE
===============

.. code-block:: c

   #define OPAL_PCI_SET_PE				31

   int64_t opal_pci_set_pe(uint64_t phb_id, uint64_t pe_number,
                           uint64_t bus_dev_func, uint8_t bus_compare,
                           uint8_t dev_compare, uint8_t func_compare,
                           uint8_t pe_action);

**NOTE:** The following two paragraphs come from some old documentation and
have not been checked for accuracy. Same goes for bus_compare, dev_compare
and func_compare documentation. Do *NOT* assume this documentation is correct
without checking the source.

A host OS calls this function to map a PCIE function (RID), or range of
function bus/dev/funcs (RIDs), to a PHB PE. The bus, device, func, and
compare parameters define a range of bus, device, or function numbers to
define a range of RIDs within this domain. A value of "7" for the bus_compare,
and non-zero for the dev_compare and func_compare, define exactly one function
RID to be a PE (within a PE number domain).

This must be called prior to ALL other OPAL calls that take a PE number
argument, for OPAL to correlate the RID (bus/dev/func) domain of the PE. If a
PE domain is changed, the host must call this to reset the PE bus/dev/func
domain and then call all other OPAL calls that map PHB IODA resources to
update those domains within PHB facilities.

``phb_id``
  is the value from the PHB node ibm,opal-phbid property.

``pe_number``
  is the index of a PE, from 0 to ibm,opal-num-pes minus 1.

``bus_compare``
  is a value from 0 to 7 indicating which bus number
  bits define the range of buses in a PE domain:

  0 = do not validate against RID bus number (PE = all bus numbers)

  2 = compare high order 3 bits of RID bus number to high order 3 bits of
      PE bus number

  3 = compare high order 4 bits of RID bus number to high order 4 bits of
      PE bus number

  6 = compare high order 7 bits of RID bus number to high order 7 bits of
      PE bus number

  7 = compare all bits of RID bus number to all bits of PE bus number

``dev_compare``
  indicates to compare the RID device number to the PE
  device number or not. '0' signifies that the RID device number is not compared
  -- essentially all device numbers within the bus and function number range of
  this PE are also within this PE. Non-zero signifies to compare the RID device
  number to the PE device number, such that only that device number is in the PE
  domain, for all buses and function numbers in the PE domain.

``func_compare``
  indicates to compare the RID function number to the
  PE function number or not. '0' signifies that the RID function number is not
  compared -- essentially all function numbers within the bus and device number
  range of this PE are also within this PE. Non-zero signifies to compare the
  RID function number to the PE function number, such that only that function
  number is in the PE domain, for all buses and device numbers in the PE domain.

``pe_action``
  is one of: ::

    enum OpalPeAction {
	OPAL_UNMAP_PE = 0,
	OPAL_MAP_PE = 1
    };

Returns
-------

:ref:`OPAL_PARAMETER`
  If one of the following:

   - invalid phb
   - invalid pe_action
   - invalid bus_dev_func
   - invalid bus_compare
:ref:`OPAL_UNSUPPORTED`
  PHB does not support set_pe operation
:ref:`OPAL_SUCCESS`
  if operation was successful
