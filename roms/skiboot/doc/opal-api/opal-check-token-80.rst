.. _OPAL_CHECK_TOKEN:

OPAL_CHECK_TOKEN
================

.. code-block:: c

   #define OPAL_CHECK_TOKEN			80

   int64_t opal_check_token(uint64_t token);

This OPAL call allows the host OS to determine if a particular OPAL call is present
on a system. This allows for simple compatibility between OPAL versions and different
OPAL implementations/platforms.

One parameter is accepted: the OPAL token number.

``OPAL_CHECK_TOKEN`` will return: ::

  enum OpalCheckTokenStatus {
    OPAL_TOKEN_ABSENT = 0,
    OPAL_TOKEN_PRESENT = 1
  };

indicating the presence/absence of the particular OPAL_CALL.

``OPAL_CHECK_TOKEN`` is REQUIRED to be implemented by a conformant OPAL implementation.

For skiboot, only positively ancient internal-to-IBM versions were missing
OPAL_CHECK_TOKEN. In this case, OPAL_PARAMETER would be returned. There is no
reason for a host OS to support this behaviour.
