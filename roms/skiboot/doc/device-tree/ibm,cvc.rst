.. _device-tree/ibm,cvc:

ibm,cvc
=======

This describes the code (a.k.a container verification code) that skiboot uses
to verify signed firmware blobs. Each ibm,cvc child node describes CVC service,
which has a version and offset (reg).

Added in the device tree from ``ibm,secureboot-v2``.

Required properties
-------------------

.. code-block:: none

   compatible:      should be "ibm,container-verification-code"

   memory-region:   this points to the reserved memory where the
                    container-verification-code is stored.

Example
-------

.. code-block:: dts

	ibm,cvc {
		phandle = <0x10f>;
		#address-cells = <0x1>;
		#size-cells = <0x0>;
		compatible = "ibm,container-verification-code";
		memory-region = <0xaa>;

		ibm,cvc-service@40 {
			phandle = <0x110>;
			compatible = "ibm,cvc-sha512";
			reg = <0x40>;
			version = <0x1>;
		};

		ibm,cvc-service@50 {
			phandle = <0x111>;
			compatible = "ibm,cvc-verify";
			reg = <0x50>;
			version = <0x1>;
		};
	};
