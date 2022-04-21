.. _OPAL_GET_EPOW_STATUS:

OPAL_GET_EPOW_STATUS
====================

.. code-block:: c

   #define OPAL_GET_EPOW_STATUS			56

   enum OpalEpowStatus {
	OPAL_EPOW_NONE = 0,
	OPAL_EPOW_UPS = 1,
	OPAL_EPOW_OVER_AMBIENT_TEMP = 2,
	OPAL_EPOW_OVER_INTERNAL_TEMP = 3
   };

   /* System EPOW type */
   enum OpalSysEpow {
	OPAL_SYSEPOW_POWER	= 0,	/* Power EPOW */
	OPAL_SYSEPOW_TEMP	= 1,	/* Temperature EPOW */
	OPAL_SYSEPOW_COOLING	= 2,	/* Cooling EPOW */
	OPAL_SYSEPOW_MAX	= 3,	/* Max EPOW categories */
   };

   /* Power EPOW */
   enum OpalSysPower {
	OPAL_SYSPOWER_UPS	= 0x0001, /* System on UPS power */
	OPAL_SYSPOWER_CHNG	= 0x0002, /* System power configuration change */
	OPAL_SYSPOWER_FAIL	= 0x0004, /* System impending power failure */
	OPAL_SYSPOWER_INCL	= 0x0008, /* System incomplete power */
	};

   /* Temperature EPOW */
   enum OpalSysTemp {
	OPAL_SYSTEMP_AMB	= 0x0001, /* System over ambient temperature */
	OPAL_SYSTEMP_INT	= 0x0002, /* System over internal temperature */
	OPAL_SYSTEMP_HMD	= 0x0004, /* System over ambient humidity */
   };

   /* Cooling EPOW */
   enum OpalSysCooling {
	OPAL_SYSCOOL_INSF	= 0x0001, /* System insufficient cooling */
   };

   int64_t opal_get_epow_status(int16_t *out_epow, int16_t *length);

The :ref:`OPAL_GET_EPOW_STATUS` call gets the Environmental and Power Warnings
state from OPAL. This can allow an OS to take action based on information from
firmware / sensors.

On receipt of an :ref:`OPAL_MSG_EPOW` message, the OS can query the status
using the :ref:`OPAL_GET_EPOW_STATUS` call. The OS allocates an array for the
status bits, and passes in the length of this array. OPAL will return the
maximum length it filled out. Thus, new classes can be added and backwards
compatibility is maintained.

At time of writing, this call is only implemented on FSP based systems.

Returns
-------

:ref:`OPAL_SUCCESS`
     Successfully retreived status. Note, success is returned even if only
     able to retreive a subset of the EPOW classes.

Other return codes may be returned in the future.
