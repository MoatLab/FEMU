.. _opal-api-cec-reboot:

OPAL_CEC_REBOOT and OPAL_CEC_REBOOT2
====================================

.. code-block:: c

   #define OPAL_CEC_REBOOT		6
   #define OPAL_CEC_REBOOT2	116

There are two opal calls to invoke system reboot.

:ref:`OPAL_CEC_REBOOT`
  Original reboot call for a normal reboot.
  It is recommended to first try :ref:`OPAL_CEC_REBOOT2`
  (use :ref:`OPAL_CHECK_TOKEN` first), and then, if not available,
  fall back to :ref:`OPAL_CEC_REBOOT`.
  All POWER9 systems shipped with support for :ref:`OPAL_CEC_REBOOT2`,
  so it is safe to exclusively call the new call if an OS only targets POWER9
  and above.

:ref:`OPAL_CEC_REBOOT2`
  Newer call for rebooting a system, supporting different types of reboots.
  For example, the OS may request a reboot due to a platform or OS error,
  which may trigger host or BMC firmware to save debugging information.

.. _OPAL_CEC_REBOOT:

OPAL_CEC_REBOOT
---------------
Syntax: ::

  int64_t opal_cec_reboot(void)

System reboots normally, equivalent to :ref:`OPAL_CEC_REBOOT2`. See
:ref:`OPAL_CEC_REBOOT2` for details, as both OPAL calls should be called
in the same way.

.. _OPAL_CEC_REBOOT2:

OPAL_CEC_REBOOT2
----------------
Syntax:

.. code-block:: c

  int64_t opal_cec_reboot2(uint32_t reboot_type, char *diag)

A reboot call is likely going to involve talking to a service processor to
request a reboot, which can be quite a slow operation. Thus, the correct
way for an OS to make an OPAL reboot call is to spin on :ref:`OPAL_POLL_EVENTS`
to crank any state machine needed for the reboot until the machine reboots
from underneath the OS.

For example, the below code could be part of an OS calling to do any type
of reboot, and falling back to a normal reboot if that type is not supported.

.. code-block:: c

	int rc;
	int reboot_type = OPAL_REBOOT_NORMAL;

	do {
	  if (opal_check_token(OPAL_CEC_REBOOT2) == 0) {
	    rc = opal_cec_reboot2(reboot_type, NULL);
	  } else {
	    rc = opal_cec_reboot();
	  }
	  if (rc == OPAL_UNSUPPORTED) {
	    printf("Falling back to normal reboot\n");
	    reboot_type = OPAL_REBOOT_NORMAL;
	    rc = OPAL_BUSY;
	  }
	  opal_poll_events(NULL);
	} while (rc == OPAL_BUSY || rc == OPAL_BUSY_EVENT);

	for (;;)
	  opal_poll_events(NULL);


Input parameters
^^^^^^^^^^^^^^^^
``reboot_type``
  Type of reboot. (see below)

``diag``
  Null-terminated string.

Depending on reboot type, this call will carry out additional steps
before triggering a reboot.

Return Codes
^^^^^^^^^^^^

:ref:`OPAL_SUCCESS`
     The system will soon reboot. The OS should loop on :ref:`OPAL_POLL_EVENTS`
     in case there's any work for OPAL to do.

:ref:`OPAL_BUSY` or :ref:`OPAL_BUSY_EVENT`
     OPAL is currently busy and can't issue a reboot, call
     :ref:`OPAL_POLL_EVENTS` and retry reboot call.

:ref:`OPAL_UNSUPPORTED`
     Unsupported reboot type (applicable to :ref:`OPAL_CEC_REBOOT2` only), retry
     with other reboot type.

Other error codes
     Keep calling reboot and hope for the best? In theory this should never happen.


Supported reboot types:
-----------------------

OPAL_REBOOT_NORMAL = 0
	Behavior is as similar to that of opal_cec_reboot()

OPAL_REBOOT_PLATFORM_ERROR = 1
	Log an error to the BMC and then trigger a system checkstop, using
	the information provided by 'ibm,sw-checkstop-fir' property in the
	device-tree. Post the checkstop trigger, OCC/BMC will collect
	relevant data for error analysis and trigger a reboot.

	In absence of 'ibm,sw-checkstop-fir' device property, this function
	will return with OPAL_UNSUPPORTED and no reboot will be triggered.

OPAL_REBOOT_FULL_IPL = 2
	Force a full IPL reboot rather than using fast reboot.

	On platforms that don't support fast reboot, this is equivalent to a
	normal reboot.

OPAL_REBOOT_MPIPL = 3
	Request for MPIPL reboot. Firmware will reboot the system and collect
	dump.

	On platforms that don't support MPIPL, this is equivalent to a
	normal assert.

Unsupported Reboot type
	For unsupported reboot type, this function will return with
	OPAL_UNSUPPORTED and no reboot will be triggered.

Debugging
^^^^^^^^^

This is **not** ABI and may change or be removed at any time.

You can change if the software checkstop trigger is used or not by an NVRAM
variable: ::

  nvram -p ibm,skiboot --update-config opal-sw-xstop=enable
  nvram -p ibm,skiboot --update-config opal-sw-xstop=disable
