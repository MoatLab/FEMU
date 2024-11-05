OPAL Secure Variable API
========================

Overview
--------

In order to support host OS secure boot on POWER systems, the platform needs
some form of tamper-resistant persistant storage for authorized public keys.
Furthermore, these keys must be retrieveable by the host kernel, and new
keys must be able to be submitted.

OPAL exposes an abstracted "variable" API, in which these keys can be stored
and retrieved. At a high level, ``opal_secvar_get`` retrieves a specific
variable corresponding to a particular key. ``opal_secvar_get_next`` can be
used to iterate through the keys of the stored variables.
``opal_secvar_enqueue_update`` can be used to submit a new variable for
processing on next boot.

OPAL_SECVAR_GET
===============
::

   #define OPAL_SECVAR_GET                         176

``OPAL_SECVAR_GET`` call retrieves a data blob associated with the supplied
key.


Parameters
----------
::

   char     *key
   uint64_t  key_len
   void     *data
   uint64_t *data_size

``key``
   a buffer used to associate with the variable data. May
   be any encoding, but must not be all zeroes

``key_len``
   size of the key buffer in bytes

``data``
   return buffer to store the data blob of the requested variable if
   a match was found. May be set to NULL to only query the size into
   ``data_size``

``data_size``
   reference to the size of the ``data`` buffer. OPAL sets this to
   the size of the requested variable if found.


Return Values
-------------

``OPAL_SUCCESS``
   the requested data blob was copied successfully. ``data`` was NULL,
   and the ``data_size`` value was set successfully

``OPAL_PARAMETER``
   ``key`` is NULL.
   ``key_len`` is zero.
   ``data_size`` is NULL.

``OPAL_EMPTY``
   no variable with the supplied ``key`` was found

``OPAL_PARTIAL``
   the buffer size provided in ``data_size`` was insufficient.
   ``data_size`` is set to the minimum required size.

``OPAL_UNSUPPORTED``
   secure variables are not supported by the platform

``OPAL_RESOURCE``
   secure variables are supported, but did not initialize properly

OPAL_SECVAR_GET_NEXT
====================
::

   #define OPAL_SECVAR_GET_NEXT                        177

``OPAL_SECVAR_GET_NEXT`` returns the key of the next variable in the secure
variable bank in sequence.

Parameters
----------
::

   char     *key
   uint64_t *key_len
   uint64_t  key_buf_size


``key``
   name of the previous variable or empty. The key of the next
   variable in sequence will be copied to ``key``. If passed as empty,
   returns the first variable in the bank

``key_len``
   length in bytes of the key in the  ``key`` buffer. OPAL sets
   this to the length in bytes of the next variable in sequence

``key_buf_size``
   maximum size of the ``key`` buffer. The next key will not be
   copied if this value is less than the length of the next key


Return Values
-------------

``OPAL_SUCCESS``
   the key and length of the next variable in sequence was copied
   successfully

``OPAL_PARAMETER``
   ``key`` or ``key_length`` is NULL.
   ``key_size`` is zero.
   ``key_length`` is impossibly large. No variable with the associated
   ``key`` was found

``OPAL_EMPTY``
   end of list reached

``OPAL_PARTIAL``
   the size specified in ``key_size`` is insufficient for the next
   variable's key length. ``key_length`` is set to the next variable's
   length, but ``key`` is untouched

``OPAL_UNSUPPORTED``
   secure variables are not supported by the platform

``OPAL_RESOURCE``
   secure variables are supported, but did not initialize properly

OPAL_SECVAR_ENQUEUE_UPDATE
==========================
::

   #define OPAL_SECVAR_ENQUEUE_UPDATE                    178

``OPAL_SECVAR_ENQUEUE`` call appends the supplied variable data to the
queue for processing on next boot.

Parameters
----------
::

   char     *key
   uint64_t  key_len
   void     *data
   uint64_t  data_size

``key``
   a buffer used to associate with the variable data. May
   be any encoding, but must not be all zeroes

``key_len``
   size of the key buffer in bytes

``data``
   buffer containing the blob of data to enqueue

``data_size``
   size of the ``data`` buffer

Return Values
-------------

``OPAL_SUCCESS``
   the variable was appended to the update queue bank successfully

``OPAL_PARAMETER``
   ``key`` or ``data`` was NULL.
   ``key`` was empty.
   ``key_len`` or ``data_size`` was zero.
   ``key_len``, ``data_size`` is larger than the maximum size

``OPAL_NO_MEM``
   OPAL was unable to allocate memory for the variable update

``OPAL_HARDWARE``
   OPAL was unable to write the update to persistant storage

``OPAL_UNSUPPORTED``
   secure variables are not supported by the platform

``OPAL_RESOURCE``
   secure variables are supported, but did not initialize properly
