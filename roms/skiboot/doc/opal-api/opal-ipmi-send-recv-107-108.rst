.. _OPAL_IPMI_SEND:

OPAL_IPMI_SEND
==============

.. code-block:: c

   #define OPAL_IPMI_SEND                          107

   enum {
		OPAL_IPMI_MSG_FORMAT_VERSION_1 = 1,
   };

   struct opal_ipmi_msg {
		uint8_t version;
		uint8_t netfn;
		uint8_t cmd;
		uint8_t data[];
   };

   int64_t opal_ipmi_send(uint64_t interface,
                          struct opal_ipmi_msg *opal_ipmi_msg, uint64_t msg_len);

:ref:`OPAL_IPMI_SEND` call will send an IPMI message to the service processor.

Parameters
----------

``interface``
  ``interface`` parameter is the value from the ipmi interface node ``ibm,ipmi-interface-id``
``opal_ipmi_msg``
  ``opal_ipmi_msg`` is the pointer to a ``struct opal_ipmi_msg`` (see above)
``msg_len``
  ipmi message request size

Return Values
-------------

:ref:`OPAL_SUCCESS`
  ``msg`` queued successfully
:ref:`OPAL_PARAMETER`
  invalid ipmi message request length ``msg_len``
:ref:`OPAL_HARDWARE`
  backend support is not present as block transfer/service processor ipmi routines are not
  initialized which are used for communication
:ref:`OPAL_UNSUPPORTED`
  in-correct opal ipmi message format version ``opal_ipmi_msg->version``
:ref:`OPAL_RESOURCE`
  insufficient resources to create ``ipmi_msg`` structure

.. _OPAL_IPMI_RECV:

OPAL_IPMI_RECV
==============

.. code-block:: c

   #define OPAL_IPMI_RECV                          108

   enum {
		OPAL_IPMI_MSG_FORMAT_VERSION_1 = 1,
   };

   struct opal_ipmi_msg {
		uint8_t version;
		uint8_t netfn;
		uint8_t cmd;
		uint8_t data[];
   };

   int64_t opal_ipmi_recv(uint64_t interface,
                          struct opal_ipmi_msg *opal_ipmi_msg, uint64_t *msg_len)

``OPAL_IPMI_RECV`` call reads an ipmi message of type ``ipmi_msg`` from ipmi message
queue ``msgq`` into host OS structure ``opal_ipmi_msg``.

Parameters
----------

``interface``
  ``interface`` parameter is the value from the ipmi interface node ``ibm,ipmi-interface-id``
``opal_ipmi_msg``
  ``opal_ipmi_msg`` is the pointer to a ``struct opal_ipmi_msg`` (see above)
``msg_len``
  ``msg_len`` is the pointer to ipmi message response size

Return Values
-------------

:ref:`OPAL_SUCCESS`
  ipmi message dequeued from ``msgq`` queue and memory taken by it got released successfully
:ref:`OPAL_EMPTY`
  ``msgq`` list is empty
ref:`OPAL_PARAMETER`
  invalid ipmi ``interface`` value
:ref:`OPAL_UNSUPPORTED`
  incorrect opal ipmi message format version ``opal_ipmi_msg->version``
