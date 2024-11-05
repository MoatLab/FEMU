.. _device-tree/ibm,opal/leds:

Service Indicators (LEDS)
=========================

The 'leds' node under 'ibm,opal' lists service indicators available in the
system and their capabilities.

.. code-block:: dts

  leds {
	compatible = "ibm,opal-v3-led";
	phandle = <0x1000006b>;
	linux,phandle = <0x1000006b>;
	led-mode = "lightpath";

	U78C9.001.RST0027-P1-C1 {
		led-types = "identify", "fault";
		phandle = <0x1000006f>;
		linux,phandle = <0x1000006f>;
	};
	/* Other LED nodes like the above one */
  };

compatible
  property describes LEDs compatibility.

led-mode
  property describes service indicator mode (lightpath/guidinglight).

Each node under 'leds' node describes location code of FRU/Enclosure.

The properties under each node:

led-types
  Supported indicators (attention/identify/fault).

These LEDs can be accessed through OPAL_LEDS_{GET/SET}_INDICATOR interfaces.
Refer to :ref:`opal-api-LEDs` for interface details.
