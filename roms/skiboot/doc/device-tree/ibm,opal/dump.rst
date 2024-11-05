.. _device-tree/ibm,opal/dump:

Dump (MPIPL) Device Tree Binding
=================================

See :ref:`mpipl` for general MPIPL information.

dump node
---------
.. code-block:: dts

	dump {
                /*
                 * Memory used by OPAL to load kernel/initrd from PNOR
                 * (KERNEL_LOAD_BASE & INITRAMFS_LOAD_BASE). This is the
                 * temporary memory used by OPAL during boot. Later Linux
                 * kernel is free to use this memory. During MPIPL boot
                 * also OPAL will overwrite this memory.
                 *
                 * OPAL will advertise these memory details to kernel.
                 * If kernel is using these memory and needs these memory
                 * content for proper dump creation, then it has to reserve
                 * destination memory to preserve these memory ranges.
                 * Also kernel should pass this detail during registration.
                 * During MPIPL firmware will take care of preserving memory
                 * and post MPIPL kernel can create proper dump.
                 */
		fw-load-area = <0x0 0x20000000 0x0 0x8000000 0x0 0x28000000 0x0 0x8000000>;
                /* Compatible property */
		compatible = "ibm,opal-dump";
		phandle = <0x98>;
                /*
                 * This property indicates that its MPIPL boot. Kernel will use OPAL API
                 * to retrieve metadata tags and use metadata to create dump.
                 */
                mpipl-boot
	};
