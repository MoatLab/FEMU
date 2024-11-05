ibm,opal/sensors/ device tree nodes
-----------------------------------

All sensors of a POWER8 system are made available to the OS in the
ibm,opal/sensors/ directory. Each sensor is identified with a node
which name follows this pattern : ::

	<resource class name>@<resource identifier>/

For example : ::

	core-temp@20/

Each node has a minimum set of properties describing the sensor :

- a "compatible" property which should be "ibm,opal-sensor"

- a "sensor-type" property, which can be "temp", "fan", "power".
  More will be added when new resources are supported. This type
  is used "as is" by the Linux driver to map sensors in the sysfs
  interface of the hwmon framework of Linux.

- a "sensor-data" property giving a unique handler for the
  OPAL_SENSOR_READ call to be used by Linux to get the value of
  a sensor attribute. This value is opaque to the OS but is *currently*
  constructed using the following encoding : ::

		|  Attr. |Fam|Res. |   Resource     |
		| Number |ily|Class|      Id        |
		|--------|---|-----|----------------|

  The sensor family (FSP, DTS, etc) is used to dispatch the call to
  the appriopriate skiboot component.

- a "sensor-status" property giving the state of the sensor. The
  status bits have the slightly meanings depending on the resource
  type but testing against 0x6 should raise an alarm.

- an optional "label" property

Each node can have some extra properties depending on the resource
they represent. See the tree below for more information.

.. code-block:: dts

  ibm,opal {
    sensors {

	/*
	 * Core temperatures (DTS) nodes.
	 *
	 * We use the PIR of the core as a resource identifier.
	 */
	core-temp@20 {
		compatible = "ibm,opal-sensor";
		name = "core-temp";
		sensor-type = "temp";

		/* Status bits :
		 *
		 * 0x0003	FATAL
		 * 0x0002	CRITICAL
		 * 0x0001	WARNING
		 */
		sensor-data = <0x00800020>;

		/*
		 * These are extra properties to help Linux output.
		 */
		ibm,pir = <0x20>;
		label = "Core";
	};

	/*
	 * Centaur temperatures (DTS) nodes. Open Power only.
	 *
	 * We use the PIR of the core as a resource identifier.
	 */
	mem-temp@1 {
		compatible = "ibm,opal-sensor";
		name = "mem-temp";
		sensor-type = "temp";

		/* Status bits :
		 *
		 * 0x0003	FATAL
		 * 0x0002	CRITICAL
		 * 0x0001	WARNING
		 */
		sensor-data = <0x00810001>;

		/*
		 * These are extra properties to help Linux output.
		 */
		ibm,chip-id = <0x80000001>;
		label = "Centaur";
	};
    };
  };
