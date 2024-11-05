.. _device-tree/opencapi:

=============================
OpenCAPI Device Tree Bindings
=============================

NPU bindings
------------

The NPU nodes are similar to those in :doc:`nvlink`.

We distinguish between OpenCAPI and NVLink links using the
`ibm.npu-link-type` property. NPUs with a mixture of OpenCAPI and
NVLink links are currently unsupported.

.. code-block:: dts

  xscom@603fc00000000 {
    npu@5011000 {
      compatible = "ibm,power9-npu";
      phandle = <0xe6>;
      reg = <0x5011000 0x2c>;
      ibm,npu-index = <0x0>;
      ibm,npu-links = <0x2>; /* Number of links wired up to this npu. */

      link@2 {
	compatible = "ibm,npu-link";
	ibm,npu-link-type = "opencapi";
        ibm,npu-group-id = <0x1>;
	ibm,npu-lane-mask = <0xf1e000>; /* Mask specifying which IBM PHY lanes
	                                 * are used for this link. 24-bit,
	                                 * lane 0 is most significant bit */
        ibm,npu-phy = <0x80000000 0x9010c3f>; /* SCOM address of the IBM PHY
	                                       * controlling this link. */
	ibm,npu-link-index = <0x2>; /* Hardware link index.
                                     * Used to calculate various address offsets. */
	phandle = <0xe7>;
      };

      link@3 {
	compatible = "ibm,npu-link";
	ibm,npu-link-type = "opencapi";
	ibm,npu-group-id = <0x2>;
	ibm,npu-lane-mask = <0x78f>;
	ibm,npu-phy = <0x80000000 0x9010c3f>;
	ibm,npu-link-index = <0x3>;
	phandle = <0xe8>;
      };
    };
  };

PCI device bindings
-------------------

The PCI devices mostly look like regular PCI devices (see :doc:`pci`),
but have a few additional fields to allow the devices to be associated
with the relevant NPU. These fields are presently not consumed by
anything but may be used in future.

.. code-block:: dts

  pciex@600e800000000 {
    /* OpenCAPI specific properties */
    compatible = "ibm,power9-npu-opencapi-pciex", "ibm,ioda2-npu2-opencapi-phb";
    ibm,npcq = <0xe6>; /* phandle to the NPU node */
    ibm,npu-index = <0x0>;
    ibm,links = <0x1>;
    /* Generic PCI fields here */
  }

