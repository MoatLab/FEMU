.. _opal-messages:

OPAL_MESSAGE
============

The host OS can use OPAL_GET_MSG to retrive messages queued by OPAL. The
messages are defined by enum opal_msg_type. The host is notified of there
being messages to be consumed by the OPAL_EVENT_MSG_PENDING bit being set.

An opal_msg is: ::

  struct opal_msg {
	__be32 msg_type;
	__be32 size;
	__be64 params[8];
  };

The data structure is ALWAYS at least this size (4+4+8*8 = 72 bytes). Some
messages define fewer than eight parameters. For messages that do not
define all eight parameters, the value in the undefined parameters is
undefined, although can safely be memcpy()d or otherwise moved.

In the device tree, there's an opal-msg-size property of the OPAL node that
says the size of a struct opal-msg. Kernel will use this property to allocate
memory for opal_msg structure. See ``OPAL_GET_MESSAGE`` documentation for
details.
::

  ibm,opal {
            opal-msg-size = <0x48>;
  }


OPAL_MSG_ASYNC_COMP
-------------------
::

   params[0] = token
   params[1] = rc

Additional parameters are function-specific.

OPAL_MSG_MEM_ERR
----------------

.. _OPAL_MSG_EPOW:

OPAL_MSG_EPOW
-------------

Used by OPAL to issue environmental and power warnings to host OS for
conditions requiring an earlier poweroff. A few examples of these are high
ambient temperature or system running on UPS power with low UPS battery.
Host OS can query OPAL via :ref:`OPAL_GET_EPOW_STATUS` API to obtain information about
EPOW conditions present. Refer include/opal-api.h for description of
all supported EPOW events. OPAL_SYSPOWER_CHNG, OPAL_SYSPOWER_FAIL and
OPAL_SYSPOWER_INC events don't require system poweroff.

Host OS should look for 'ibm,opal-v3-epow' string as compatible property
for 'epow' node under OPAL device-tree to determine epow support.

OPAL_MSG_SHUTDOWN
-----------------

Used by OPAL to inform the host OS it must imitate a graceful shutdown. Uses
the first parameter to indicate weather the system is going down for shutdown
or a reboot. ::

  params[0] = 0x01 reboot, 0x00 shutdown

.. _OPAL_MSG_HMI_EVT:

OPAL_MSG_HMI_EVT
----------------

Used by OPAL to sends the OPAL HMI Event to the host OS that reports a
summary of HMI error and whether it was successfully recovered or not.

HMI is a Hypervisor Maintenance Interrupt usually reports error related
to processor recovery/checkstop, NX checkstop and Timer facility. Hypervisor
then takes this opportunity to analyze and recover from some of these errors.
Hypervisor takes assistance from OPAL layer to handle and recover from
HMI. After handling HMI, OPAL layer sends the summary of error report and
status of recovery action using HMI event structure shown below.

The HMI event structure uses version numbering to allow future enhancement
to accommodate additional members. The version start from V1 onward.
Version 0 is invalid version and unsupported.

The current version of HMI event structure V2 and is backward compatible
to V1 version.

Notes:

- When adding new structure to the union in future, the version number
  must be bumped.
- All future versions must be backward compatible to all its older versions.
- Size of this structure should not exceed that of struct opal_msg.

::

   struct OpalHMIEvent {
        uint8_t         version;        /* 0x00 */
        uint8_t         severity;       /* 0x01 */
        uint8_t         type;           /* 0x02 */
        uint8_t         disposition;    /* 0x03 */
        uint8_t         reserved_1[4];  /* 0x04 */

	__be64		hmer;
	/* TFMR register. Valid only for TFAC and TFMR_PARITY error type. */
	__be64		tfmr;

	/* version 2 and later */
	union {
		/*
		 * checkstop info (Core/NX).
		 * Valid for OpalHMI_ERROR_MALFUNC_ALERT.
		 */
		struct {
			uint8_t	xstop_type;	/* enum OpalHMI_XstopType */
			uint8_t reserved_1[3];
			__be32 xstop_reason;
			union {
				__be32 pir;	  /* for CHECKSTOP_TYPE_CORE */
				__be32 chip_id; /* for CHECKSTOP_TYPE_NX */
			} u;
		} xstop_error;
	} u;
   };

.. _OPAL_MSG_DPO:

OPAL_MSG_DPO
------------

Delayed poweroff where OPAL informs host OS that a poweroff has been
requested and a forced shutdown will happen in future. Host OS can use
OPAL_GET_DPO_STATUS API to query OPAL the number of seconds remaining
before a forced poweroff will occur.

.. _OPAL_MSG_PRD:

OPAL_MSG_PRD
------------

This message is a OPAL-to-HBRT notification, and contains a
struct opal_prd_msg: ::

	enum opal_prd_msg_type {
		OPAL_PRD_MSG_TYPE_INIT = 0,	/* HBRT --> OPAL */
		OPAL_PRD_MSG_TYPE_FINI,		/* HBRT --> OPAL */
		OPAL_PRD_MSG_TYPE_ATTN,		/* HBRT <-- OPAL */
		OPAL_PRD_MSG_TYPE_ATTN_ACK,	/* HBRT --> OPAL */
		OPAL_PRD_MSG_TYPE_OCC_ERROR,	/* HBRT <-- OPAL */
		OPAL_PRD_MSG_TYPE_OCC_RESET,	/* HBRT <-- OPAL */
	};

	struct opal_prd_msg {
		uint8_t		type;
		uint8_t		pad[3];
		__be32		token;
		union {
			struct {
				__be64	version;
				__be64	ipoll;
			} init;
			struct {
				__be64	proc;
				__be64	ipoll_status;
				__be64	ipoll_mask;
			} attn;
			struct {
				__be64	proc;
				__be64	ipoll_ack;
			} attn_ack;
			struct {
				__be64	chip;
			} occ_error;
			struct {
				__be64	chip;
			} occ_reset;
		};
	};

Responses from the kernel use the same message format, but are passed
through the :ref:`OPAL_PRD_MSG` call.

OPAL_MSG_OCC
------------

This is used by OPAL to inform host about OCC events like OCC reset,
OCC load and throttle status change by OCC which can indicate the
host the reason for frequency throttling/unthrottling. ::

  #define OCC_RESET			0
  #define OCC_LOAD 			1
  #define OCC_THROTTLE 			2
  #define OCC_MAX_THROTTLE_STATUS		5
  /*
   * struct opal_occ_msg:
   * type: OCC_RESET, OCC_LOAD, OCC_THROTTLE
   * chip: chip id
   * throttle status: Indicates the reason why OCC may have limited
   * the max Pstate of the chip.
   * 0x00 = No throttle
   * 0x01 = Power Cap
   * 0x02 = Processor Over Temperature
   * 0x03 = Power Supply Failure (currently not used)
   * 0x04 = Over current (currently not used)
   * 0x05 = OCC Reset (not reliable as some failures will not allow for
   * OCC to update throttle status)
   */
  struct opal_occ_msg {
	__be64 type;
	__be64 chip;
	__be64 throttle_status;
  };

Host should read opal_occ_msg.chip and opal_occ_msg.throttle_status
only when ``opal_occ_msg.type = OCC_THROTTLE``.
If host receives ``OCC_THROTTLE`` after an ``OCC_RESET`` then this throttle
message will have a special meaning which indicates that all the OCCs
have become active after a reset. In such cases ``opal_occ_msg.chip`` and
``opal_occ_msg.throttle_status`` will be set to 0 and host should not use
these values.

If ``opal_occ_msg.type > 2`` then host should ignore the message for now,
new events can be defined for ``opal_occ_msg.type`` in the future versions
of OPAL.

OPAL_MSG_PRD2
-------------

This message is a OPAL-to-HBRT notification. Its same as OPAL_MSG_PRD except
this one supports passing more than 64bytes (8*8) of data.
