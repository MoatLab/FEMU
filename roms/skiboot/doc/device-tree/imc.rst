.. _device-tree/imc:

===========================
IMC Device Tree Bindings
===========================

See :ref:`imc` for general In-Memory Collection (IMC) counter information.

imc-counters top-level node
----------------------------
.. code-block:: dts

      imc-counters {
        compatible = "ibm,opal-in-memory-counters";
        #address-cells = <0x1>;
        #size-cells = <0x1>;
        phandle = <0x1000023a>;
        version-id = <0xd>;
	/* Denote IMC Events Catalog version used to build this DTS file. */

      };

IMC device/units bindings
-------------------------

.. code-block:: dts

        mcs3 {
                compatible = "ibm,imc-counters";
                events-prefix = "PM_MCS3_"; /* denotes event name to be prefixed to get complete event name supported by this device */

                phandle = <0x10000241>;
                events = <0x10000242>; /* phandle of the events node supported by this device */

                unit = "MiB";
                scale = "4"; /* unit and scale for all the events for this device */

                reg = <0x118 0x8>; /* denotes base address for device event updates */
                type = <0x10>;
                size = 0x40000;
                offset = 0x180000;
                base_addr = <Base address of the counter in reserve memory>
                /* This is per-chip memory field and OPAL files it based on the no of chip in the system */
                /* base_addr property also indicates (or hints) kernel whether to memory */
                /* should be mmapped or allocated at system start for the counters */
                chipids = <chip-id for the base_addr >
        };

        trace@0 {
                 compatible = "ibm,imc-counters";
                 events-prefix = "trace_";
                 reg = <0x0 0x8>;
                 events = < &TRACE_IMC >;
                 type = <0x2>;
                 size = <0x40000>;
         };

IMC device event bindings
-------------------------

.. code-block:: dts

        nest-mcs-events {
                #address-cells = <0x1>;
                #size-cells = <0x1>;
                phandle = <0x10000242>;

                event@98 {
                      desc = "Total Write Bandwidth seen on both MCS"; /* event description */

                      phandle = <0x1000023d>;
                      reg = <0x98 0x8>; /* event offset,when added with (nest-offset-address + device reg) will point to actual counter memory */

                      event-name = "DOWN_128B_DATA_XFER"; /* denotes the actual event name */

                };

		/* List of events supported */

        };

        TRACE_IMC: trace-events {
              #address-cells = <0x1>;
              #size-cells = <0x1>;

              event@10200000 {
                    event-name = "cycles" ; /* For trace node, we only have cycles event now */
                    reg = <0x10200000 0x8>;
                    desc = "Reference cycles" ;
              };
         };

Trace-mode SCOM
----------------

Trace scom is a 64 bit value which contains the event information for
IMC-trace mode. Following is the trace-scom layout.

**TRACE_IMC_SCOM bit representation**

:0-1:   SAMPSEL

:2-33:  CPMC_LOAD

:34-40: CPMC1SEL

:41-47: CPMC2SEL

:48-50: BUFFERSIZE

:51-63: RESERVED

*CPMC_LOAD* contains the sampling duration. *SAMPSEL* and *CPMC*SEL*
determines the event to count. *BUFFRSIZE* indicates the memory range.

*BUFFERSIZE* can be

.. code-block:: text

   b’000’ - 4K entries * 64 per entry = 256K
   b’001’ - 8K entries * 64 per entry = 512K
   b’010’ - 16K entries * 64 per entry = 1M
   b’011’ - 32K entries * 64 per entry = 2M
   b’100’ - 64K entries * 64 per entry = 4M
