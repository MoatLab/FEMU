.. _OPAL_I2C_REQUEST:

OPAL_I2C_REQUEST
================

.. code-block:: c

   #define OPAL_I2C_REQUEST			109

   /* OPAL I2C request */
   struct opal_i2c_request {
		uint8_t	type;
   #define OPAL_I2C_RAW_READ	0
   #define OPAL_I2C_RAW_WRITE	1
   #define OPAL_I2C_SM_READ	2
   #define OPAL_I2C_SM_WRITE	3
		uint8_t flags;
   #define OPAL_I2C_ADDR_10	0x01	/* Not supported yet */
		uint8_t	subaddr_sz;		/* Max 4 */
		uint8_t reserved;
		__be16 addr;			/* 7 or 10 bit address */
		__be16 reserved2;
		__be32 subaddr;		/* Sub-address if any */
		__be32 size;			/* Data size */
		__be64 buffer_ra;		/* Buffer real address */
   };

   int opal_i2c_request(uint64_t async_token, uint32_t bus_id,
                        struct opal_i2c_request *oreq);

Initiate I2C request using i2c master that OPAL controls.

Return Codes
------------

Most return codes will come through as part of async completion.

:ref:`OPAL_PARAMETER`
     Invalid request pointer, or bus ID.
:ref:`OPAL_UNSUPPORTED`
     Unsupported operation. e.g. 10 bit addresses not yet supported.
:ref:`OPAL_NO_MEM`
     Not enough free memory in OPAL to initiate request.
:ref:`OPAL_ASYNC_COMPLETION`
     Operation will complete asynchronously.
:ref:`OPAL_I2C_TIMEOUT`
     I2C operation initiated successfully, but timed out.
:ref:`OPAL_I2C_INVALID_CMD`
     Invalid i2c Command.
:ref:`OPAL_I2C_LBUS_PARITY`
     I2C LBUS Parity error
:ref:`OPAL_I2C_BKEND_OVERRUN`
     I2C Backend overrun.
:ref:`OPAL_I2C_BKEND_ACCESS`
     I2C Backend Access error.
:ref:`OPAL_I2C_ARBT_LOST`
     I2C Bus Arbitration lost.
:ref:`OPAL_I2C_NACK_RCVD`
     I2C NACK received.
:ref:`OPAL_I2C_STOP_ERR`
     I2C STOP error.
:ref:`OPAL_SUCCESS`
     I2C operation completed successfully. Typically only as part of
     async completion.
