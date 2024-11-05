.. _OPAL_NPU_SET_RELAXED_ORDER:

OPAL_NPU_SET_RELAXED_ORDER
==========================

Request that relaxed memory ordering be enabled or disabled for a device.

Parameters
----------
::

	uint64_t phb_id
	uint16_t bdfn
	bool request_enabled

``phb_id``
	OPAL ID of the PHB

``bdfn``
	Bus-Device-Function number of the device

``request_enabled``
	Requested state of relaxed memory ordering enablement

Return values
-------------

``OPAL_SUCCESS``
	Requested state set

``OPAL_PARAMETER``
	The given phb_id or bdfn is invalid or out of range

``OPAL_CONSTRAINED``
	Relaxed ordering can not be enabled until an enable request is made
	for every device on this PHB.

``OPAL_RESOURCE``
	No more relaxed ordering sources are available

.. _OPAL_NPU_GET_RELAXED_ORDER:

OPAL_NPU_GET_RELAXED_ORDER
==========================

Query the relaxed memory ordering state of a device.

Parameters
----------
::

	uint64_t phb_id
	uint64_t bdfn

``phb_id``
	OPAL ID of the PHB

``bdfn``
	Bus-Device-Function number of the device

Return values
-------------

On success, the current relaxed ordering state is returned.

``OPAL_PARAMETER``
	The given phb_id or bdfn is invalid.
