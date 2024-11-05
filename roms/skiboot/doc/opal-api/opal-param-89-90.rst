.. _opal-sysparams:

=========================
Get/Set System Parameters
=========================

The usual way for setting system parameters is via IPMI for things controlled
by the service processor, or through NVRAM for things controlled by host
firmware. However, some platforms may have other options not easily (or
possible to be) exposed over IPMI. These OPAL calls will read (and write)
these parameters.

The list of parameters is set at boot time, and is represented in the device
tree (see :ref:`device-tree/ibm,opal/sysparams` for details).

Currently only implemented on FSP based systems.

.. _OPAL_GET_PARAM:

OPAL_GET_PARAM
==============

.. code-block:: c

   #define OPAL_GET_PARAM				89

   int64_t fsp_opal_get_param(uint64_t async_token, uint32_t param_id,
                              uint64_t buffer, uint64_t length);

Get the current setting of `param_id`. This is an asynchronous call as OPAL may
need to communicate with a service processor. The `param_id` and `length` are
described in the device tree for each parameter (see
:ref:`device-tree/ibm,opal/sysparams` for details).

Returns
-------
:ref:`OPAL_HARDWARE`
     Hardware issue prevents retreiving parameter. e.g. FSP is offline or
     absent.
:ref:`OPAL_PARAMETER`
     Invalid `param_id`
:ref:`OPAL_PERMISSION`
     Not allowed to read parameter.
:ref:`OPAL_NO_MEM`
     Not enough free memory in OPAL to process request.
:ref:`OPAL_INTERNAL_ERROR`
     Other internal OPAL error
:ref:`OPAL_ASYNC_COMPLETION`
     Request is submitted.

.. _OPAL_SET_PARAM:

OPAL_SET_PARAM
==============

.. code-block:: c

   #define OPAL_SET_PARAM				90

   int64_t fsp_opal_set_param(uint64_t async_token, uint32_t param_id,
                              uint64_t buffer, uint64_t length);


Write a new setting for `param_id`. This is an asynchronous call as OPAL may
need to communicate with a service processor. The `param_id` and `length` are
described in the device tree for each parameter (see
:ref:`device-tree/ibm,opal/sysparams` for details).


Returns
-------
:ref:`OPAL_HARDWARE`
     Hardware issue prevents retreiving parameter. e.g. FSP is offline or
     absent.
:ref:`OPAL_PARAMETER`
     Invalid `param_id`
:ref:`OPAL_PERMISSION`
     Not allowed to write parameter.
:ref:`OPAL_NO_MEM`
     Not enough free memory in OPAL to process request.
:ref:`OPAL_INTERNAL_ERROR`
     Other internal OPAL error
:ref:`OPAL_ASYNC_COMPLETION`
     Request is submitted.
