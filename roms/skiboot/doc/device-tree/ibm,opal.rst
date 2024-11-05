.. _device-tree/ibm,opal:

ibm,opal
========

.. toctree::
   :maxdepth: 1
   :glob:

   ibm,opal/*


Top level ibm,opal node
-----------------------

.. code-block:: dts

   ibm,opal {
		#address-cells = <0x0>;
		#size-cells = <0x0>;
		compatible = "ibm,opal-v2", "ibm,opal-v3";

   /* v2 is maintained for possible compatibility with very, very old kernels
    * it will go away at some point in the future. Detect and rely on ibm,opal-v3
    * ibm,opal-v2 is *NOT* present on POWER9 and above.
    */

		ibm,associativity-reference-points = <0x4 0x3, 0x2>;
		ibm,heartbeat-ms = <0x7d0>;

   /* how often any OPAL call needs to be made to avoid a watchdog timer on BMC
    * from kicking in
    */

		ibm,opal-memcons = <0x0 0x3007a000>;

   /* location of in memory OPAL console buffer. */

		ibm,opal-trace-mask = <0x0 0x3008c3f0>;
		ibm,opal-traces = <0x0 0x3007b010 0x0 0x10077 0x0 0x3b001010 0x0 0x1000a7 0x0 0x3b103010 0x0 0x1000a7 0x0 0x3b205010 0x0 0x1000a7 0x0 0x3b307010 0x0 0x1000a7 0x0 0x3b409010 0x0 0x1000a7 0x10 0x1801010 0x0 0x1000a7 0x10 0x1903010 0x0 0x1000a7 0x10 0x1a05010 0x0 0x1000a7 0x10 0x1b07010 0x0 0x1000a7 0x10 0x1c09010 0x0 0x1000a7 0x10 0x1d0b010 0x0 0x1000a7 0x10 0x1e0d010 0x0 0x1000a7 0x10 0x1f0f010 0x0 0x1000a7 0x10 0x2011010 0x0 0x1000a7 0x10 0x2113010 0x0 0x1000a7 0x10 0x2215010 0x0 0x1000a7 0x10 0x2317010 0x0 0x1000a7 0x10 0x2419010 0x0 0x1000a7 0x10 0x251b010 0x0 0x1000a7 0x10 0x261d010 0x0 0x1000a7>;

   /* see docs on tracing */

		linux,phandle = <0x10000003>;
		opal-base-address = <0x0 0x30000000>;
		opal-entry-address = <0x0 0x300050c0>;
		opal-interrupts = <0x10 0x11 0x12 0x13 0x14 0x20010 0x20011 0x20012 0x20013 0x20014 0xffe 0xfff 0x17fe 0x17ff 0x2ffe 0x2fff 0x37fe 0x37ff 0x20ffe 0x20fff 0x22ffe 0x22fff 0x237fe 0x237ff>;
		opal-msg-async-num = <0x8>;
		opal-msg-size = <0x48>;
		opal-runtime-size = <0x0 0x9a00000>;
		phandle = <0x10000003>;
    };

.. ibm-heartbeat-ms:

ibm,heartbeat-ms
^^^^^^^^^^^^^^^^

.. code-block:: dts

   ibm,opal {
		ibm,heartbeat-ms = <0x7d0>;
   }


Any OS targetting POWER9 processors *must* respect `ibm,heartbeat-ms`.

Linux kernels prior to v4.1-rc1 would ignore `ibm,heartbeat-ms`. These only
supported POWER8 systems.

On the earliest POWER8 OPAL systems, there was `ibm,heartbeat-freq` instead.
However, no OS at the time ever looked at that value, so it can be ignored
by any new operating systems.

fast-reboot property
^^^^^^^^^^^^^^^^^^^^

This property of the `ibm,opal` node is an option property that will either be
the string `okay` or the reason the fast reboot feature was disabled on boot.

The motivation behind adding this property is to help the OPAL test suite work
out if it should even try the fast reboot test on a particular platform
(without it having to resort to grepping firmware logs).
