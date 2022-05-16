.. _OPAL_PRD_MSG:

OPAL_PRD_MSG
============

.. code-block:: c

   #define OPAL_PRD_MSG				113

   int64_t opal_prd_msg(struct opal_prd_msg *msg);

The OPAL_PRD_MSG call is used to pass a struct opal_prd_msg from the HBRT
code into opal, and is paired with the :ref:`OPAL_PRD_MSG` message type.

Parameters
----------

``struct opal_msg *msg``
  Passes an opal_msg, of type OPAL_PRD_MSG, from the OS to OPAL.
