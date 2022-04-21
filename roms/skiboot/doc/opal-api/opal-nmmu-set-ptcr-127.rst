.. _OPAL_NMMU_SET_PTCR:

OPAL_NMMU_SET_PTCR
------------------

.. code-block:: c

   #define OPAL_NMMU_SET_PTCR			127

   int64 opal_nmmu_set_ptcr(uint64 chip_id, uint64_t ptcr);


``uint64 chip_id``
    either the chip id containing the nest mmu who's ptcr should be set
    or alternatively -1ULL to indicate all nest mmu ptcr's should be set to
    the same value.
``uint64 ptcr``
    ptcr value pointing to either the radix tables or hash tables.

This OPAL call sets up the Nest MMU by pointing it at the radix page
table base or the hash page table base (HTABORG).

Return Values
^^^^^^^^^^^^^

:ref:`OPAL_SUCCESS`
   the PTCR was updated successful
:ref:`OPAL_PARAMETER`
   a parameter was incorrect
