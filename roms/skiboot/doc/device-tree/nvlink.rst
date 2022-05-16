.. _device-tree/nvlink:

===========================
Nvlink Device Tree Bindings
===========================

See :ref:`nvlink` for general Nvlink information.

NPU bindings:

.. code-block:: dts

  xscom@3fc0000000000 {
    npu@8013c00 {
      reg = <0x8013c00 0x2c>;
      compatible = "ibm,power8-npu";
      ibm,npu-index = <0x0>;
      ibm,npu-links = <0x4>; /* Number of links wired up to this npu. */

      phandle = <0x100002bc>;
      linux,phandle = <0x100002bc>;

      link@0 {
        ibm,npu-pbcq = <0x1000000b>; /* phandle to the pbcq which connects to the GPU. */
	ibm,npu-phy = <0x80000000 0x8010c3f>; /* SCOM address of the IBM PHY controlling this link. */
	compatible = "ibm,npu-link";
        ibm,npu-lane-mask = <0xff>; /* Mask specifying which IBM PHY lanes are used for this link. */

	phandle = <0x100002bd>;
        ibm,npu-link-index = <0x0>; /* Hardware link index. Naples systems
		                     * contain links at index 0,1,4 & 5.
                                     * Used to calculate various address offsets. */

	linux,phandle = <0x100002bd>;
      };

      link@1 {
        ibm,npu-pbcq = <0x1000000b>;
        ibm,npu-phy = <0x80000000 0x8010c3f>;
        compatible = "ibm,npu-link";
        ibm,npu-lane-mask = <0xff00>;
        phandle = <0x100002be>;
        ibm,npu-link-index = <0x1>;
        linux,phandle = <0x100002be>;
      };

      link@4 {
        ibm,npu-pbcq = <0x1000000a>;
        ibm,npu-phy = <0x80000000 0x8010c7f>;
        compatible = "ibm,npu-link";
        ibm,npu-lane-mask = <0xff00>;
        phandle = <0x100002bf>;
	ibm,npu-link-index = <0x4>;
        linux,phandle = <0x100002bf>;
      };

      link@5 {
        ibm,npu-pbcq = <0x1000000a>;
        ibm,npu-phy = <0x80000000 0x8010c7f>;
        compatible = "ibm,npu-link";
        ibm,npu-lane-mask = <0xff>;
        phandle = <0x100002c0>;
        ibm,npu-link-index = <0x5>;
        linux,phandle = <0x100002c0>;
      };
    };
  };

GPU memory bindings
-------------------

.. code-block:: dts

        memory@100000000 {
                device_type = "memory"
                compatible = "ibm,coherent-device-memory";
                linux,usable-memory = <0x0 0x100000000 0x0 0x0>;

        ; denotes a region of unplugged system memory

                reg = <0x0 0x100000000 0x0 0x80000000>;
                ibm,associativity = <0x4 0x0 0x0 0x0 0x64>;

        ; numa associativity for the memory once it is hotplugged

                phandle = <0x10000abc>;
                linux,phandle = <0x10000abc>;
        };

Emulated PCI device bindings
----------------------------

.. code-block:: dts

       pciex@3fff000400000 {
                ibm,npcq = <0x100002bc>; /* phandle to the NPU node. Used to find associated PCI GPU devices. */
                compatible = "ibm,power8-npu-pciex", "ibm,ioda2-npu-phb";

		pci@0 {
                        reg = <0x0 0x0 0x0 0x0 0x0>;
                        revision-id = <0x0>;
                        interrupts = <0x1>;
                        device-id = <0x4ea>;
                        ibm,pci-config-space-type = <0x1>;
                        vendor-id = <0x1014>;
                        ibm,gpu = <0x100002f7>; /* phandle pointing the associated GPU PCI device node */
			memory-region = <0x10000abc>; /* phandle pointing to the GPU memory */
                        ibm,nvlink-speed = <0x1>;

                ; Denotes the speed the link is running at:
                ; 0x3 == 20 Gbps, 0x8 = 25.78125 Gbps, 0x9 == 25.00000 Gbps

                        phandle = <0x100002fc>;
                };

                pci@1 {
                        reg = <0x800 0x0 0x0 0x0 0x0>;
                        revision-id = <0x0>;
                        interrupts = <0x1>;
                        device-id = <0x4ea>;
                        ibm,pci-config-space-type = <0x1>;
                        vendor-id = <0x1014>;
                        ibm,gpu = <0x100002f5>;
                        memory-region = <0x10000def>;
                        phandle = <0x100002fe>;
                        class-code = <0x60400>;
                        linux,phandle = <0x100002fe>;
                };

                pci@0,1 {
                        reg = <0x100 0x0 0x0 0x0 0x0>;
                        revision-id = <0x0>;
                        interrupts = <0x2>;
                        device-id = <0x4ea>;
                        ibm,pci-config-space-type = <0x1>;
                        vendor-id = <0x1014>;
                        ibm,gpu = <0x100002f7>;
                        memory-region = <0x10000abc>;
                        phandle = <0x100002fd>;
                        class-code = <0x60400>;
                        linux,phandle = <0x100002fd>;
                };

                pci@1,1 {
                       reg = <0x900 0x0 0x0 0x0 0x0>;
                        revision-id = <0x0>;
                        interrupts = <0x2>;
                        device-id = <0x4ea>;
                        ibm,pci-config-space-type = <0x1>;
                        vendor-id = <0x1014>;
                        ibm,gpu = <0x100002f5>;
                        memory-region = <0x10000def>;
                        phandle = <0x100002ff>;
                        class-code = <0x60400>;
                        linux,phandle = <0x100002ff>;
                };
        };
