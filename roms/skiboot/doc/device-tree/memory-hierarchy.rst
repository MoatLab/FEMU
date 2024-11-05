P9 memory hierarchy
-------------------
P9 Nimbus supports direct attached DDR memory through 4 DDR ports per side
of the processor. Device tree contains memory hierarchy so that one can
traverse from chip to DIMM like below:

  xscom@<addr>/mcbist@<mcbist_id>/mcs@<mcs_id>/mca@<mca_id>/dimm@<resource_id>

Example of dimm node:

.. code-block:: dts

    dimm@d00e {
            memory-id = <0xc>; /* DRAM Device Type. 0xc = DDR4 */
            product-version = <0x32>; /* Module Revision Code */
            device_type = "memory-dimm-ddr4";
            serial-number = <0x15d9ad1c>;
            status = "okay";
            size = <0x4000>;
            phandle = <0xd2>;
            ibm,loc-code = "UOPWR.0000000-Node0-DIMM14";
            part-number = "36ASF2G72PZ-2G6B2   ";
            reg = <0xd00e>;
            manufacturer-id = <0x802c>; /* Vendor ID, we can get vendor name from this ID */
    };

