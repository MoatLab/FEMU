.. _opal-api-LEDs:

Service Indicators (LEDS)
=========================

The service indicator is one element of an overall hardware service strategy
where end user simplicity is a high priority. The goal is system firmware or
operating system code to isolate hardware failures to the failing FRU and
automatically activate the fault indicator associated with the failing FRU.
The end user then needs only to look for the FRU with the active fault
indicator to know which part to replace.

Different types of indicators handled by LED code:

  - System attention indicator (Check log indicator)
      Indicates there is a problem with the system that needs attention.
  - Identify
      Helps the user locate/identify a particular FRU or resource in the
      system.
  - Fault
      Indicates there is a problem with the FRU or resource at the
      location with which the indicator is associated.

All LEDs are defined in the device tree (see :ref:`device-tree/ibm,opal/leds`).

LED Design
----------
  When it comes to implementation we can classify LEDs into two
  categories:

1. Hypervisor (OPAL) controlled LEDs (All identify & fault indicators)
   During boot, we read/cache these LED details in OPAL (location code,
   state, etc). We use cached data to serve read request from FSP/Host.
   And we use SPCN passthrough MBOX command to update these LED state.

2. Service processor (FSP) controlled LEDs (System Attention Indicator)
   During boot, we read/cache this LED info using MBOX command. Later
   anytime FSP updates this LED, it sends update system parameter
   notification MBOX command. We use that data to update cached data.
   LED update request is sent via set/reset attn MBOX command.

LED update request:
  Both FSP and Host will send LED update requests. We have to serialize
  SPCN passthrough command. Hence we maintain local queue.

Note:

  - For more information regarding service indicator refer to PAPR spec
    (Service Indicators chapter).

There are two OPAL calls relating to LED operations.

.. _OPAL_LEDS_GET_INDICATOR:

OPAL_LEDS_GET_INDICATOR
-----------------------

.. code-block:: c

   #define OPAL_LEDS_GET_INDICATOR			114

   int64_t opal_leds_get_indicator(char *loc_code, u64 *led_mask,
		                   u64 *led_value, u64 *max_led_type);

Returns LED state for the given location code.

``loc_code``
  Location code of the LEDs.
``led_mask``
  LED types whose status is available (return by OPAL)
``led_value``
  Status of the available LED types (return by OPAL)
``max_led_type``
  Maximum number of supported LED types (Host/OPAL)

The host will pass the location code of the LED types (loc_code) and
maximum number of LED types it understands (max_led_type). OPAL will
update the 'led_mask' with set bits pointing to LED types whose status
is available and updates the 'led_value' with actual status. OPAL checks
the 'max_led_type' to understand whether the host is newer or older
compared to itself. In the case where the OPAL is newer compared
to host (OPAL's max_led_type > host's max_led_type), it will update
led_mask and led_value according to max_led_type requested by the host.
When the host is newer compared to the OPAL (host's max_led_type >
OPAL's max_led_type), OPAL updates 'max_led_type' to the maximum
number of LED type it understands and updates 'led_mask', 'led_value'
based on that maximum value of LED types.

Currently this is only implemented on FSP basde machines, see
hw/fsp/fsp-leds.c for more deatails.

.. _OPAL_LEDS_SET_INDICATOR:

OPAL_LEDS_SET_INDICATOR
-----------------------

.. code-block:: c

   #define OPAL_LEDS_SET_INDICATOR			115

   int64_t opal_leds_set_indicator(uint64_t async_token,
				   char *loc_code, const u64 led_mask,
				   const u64 led_value, u64 *max_led_type);

Sets LED state for the given location code.

``loc_code``
  Location code of the LEDs to be set.
``led_mask``
  LED types whose status will be updated
``led_value``
  Requested status of various LED types.
``max_led_type``
  Maximum number of supported LED types. If OPAL supports fewer LED types
  than requested, it will set ``max_led_type`` to the maximum it does support.

The host will pass the location code of the LED types, mask, value
and maximum number of LED types it understands. OPAL will update
LED status for all the LED types mentioned in the mask with their
value mentioned. OPAL checks the 'max_led_type' to understand
whether the host is newer or older compared to itself. In case where
the OPAL is newer compared to the host (OPAL's max_led_type >
host's max_led_type), it updates LED status based on max_led_type
requested from the host. When the host is newer compared to the OPAL
(host's max_led_type > OPAL's max_led_type), OPAL updates
'max_led_type' to the maximum number of LED type it understands and
then it updates LED status based on that updated  maximum value of LED
types. Host needs to check the returned updated value of max_led_type
to figure out which part of it's request got served and which ones got
ignored.

Currently this is only implemented on FSP basde machines, see
hw/fsp/fsp-leds.c for more deatails.
