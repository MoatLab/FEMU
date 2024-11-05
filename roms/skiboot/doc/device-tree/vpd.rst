VPD (Vital Product Data)
========================

VPD provides the information about the FRUs (Field Replaceable Unit) present in
the system and each vpd node in the device tree represents a FRU. These
properties are passed to skiboot in the form of HDAT structure. Skiboot parses
these structures and adds respective nodes in the device tree. These properties
are available in all system except POWER8 BMC based system.

.. code-block:: dts

 vpd {			   /* VPD root node */
   fru-name@rsrc-id {	   /* Node name formatted as such */
   ibm,vpd = <             /* VPD data binary blob */ >;
     ccin = "524D";        /* Customer Card Identification Number */
     fru-type = [ 41 56 ]; /* FRU type label (2 bytes ASCII character) */
     fru-number    =       "FRU stocking part number";
     ibm,loc-code  =       "Location code";
     part-number   =       "ABC123456";
     serial-number =       "ABC123456";
     ibm,chip-id   = <0x0>; /* If part is a chip, Processor Id */
     size = "0032768";      /* DIMM size (applicable for DIMM VPD only) */
     ibm,memory-bus-frequency = <0x0 0x0>; /* DIMM frequency (applicable for DIMM VPD only) */
     vendor = <vendor name> /* Vendor name */
     build-date = <build date> /* Manufacturing build date (applicate for P9 BMC systems only) */
   };
 };

The VPD tree in the device tree depicts the hierarchial structure of the
FRUs having parent-child relationship. ::

 root-node-vpd@a000
    |-- enclosure@1e00
    |   |-- air-mover@3a00
    |   |-- air-mover@3a01
    |   |-- backplane@800
    |   |   |-- anchor-card@500
    |   |   |-- backplane-extender@900
    |   |   |   |-- serial-connector@2a00
    |   |   |   |-- usb-connector@2900
    |   |   |   `-- usb-connector@2901
    |   |   |-- ethernet-connector@2800
    |   |   |-- ethernet-connector@2801
    |   |   |-- ms-dimm@d002
    |   |   |-- ms-dimm@d003
    |   |   |-- processor@1000
    |   |   |-- processor@1001
    |   |   |-- usb-connector@2902
    |   |   |-- usb-connector@2903
    |   |   |-- usb-connector@2904
    |   |   `-- usb-connector@2905
    |   |-- dasd-backplane@2400
    |   |-- dasd-backplane@2401
    |   |-- power-supply@3103
    |   `-- service-processor@200
    |-- enclosure-fault-led@a300
    |-- enclosure-led@a200
    |-- root-node-vpd@a001
    `-- system-vpd@1c00

Example vpd node:

.. code-block:: dts

 anchor-card@500 {
	ccin = "52FE";
	fru-number = "00E2147";
	description = "System Anchor Card - IBM Power 824";
	ibm,loc-code = "U78C9.001.WZS007X-P1-C13";
	serial-number = "YL10113BJ001";
	ibm,vpd = <0x84cc0052 0x54045649 0x4e494452 0x10414e43 0x484f5220 0x20202020 0x20202020 0x20434501 0x31565a02 0x3031464e 0x7303045 0x32313437 0x504e0730 0x30453231 0x3438534e 0xc594c31 0x30313133 0x424a3030 0x31434304 0x35324645 0x50520881 0x300000 0x48 0x45043030 0x31304354 0x440b400 0x485702 0x14233 0x6000000 0x142 0x34010042 0x370c0000 0x0 0x0 0x4239 0x3c435333 0x22071917 0xd1569c53 0x50973c87 0x71f9c40 0x1d4d3142 0x985e80f1 0x5cb3614d 0x32a902cb 0xd9d714ab 0x164d3322 0xdda4f986 0x5a618f4d 0x340b157c 0x2cac0a94 0x6504603 0x78 0x0>;
	fru-type = [41 56];
	part-number = "00E2148";
	phandle = <0x8d>;
	linux,phandle = <0x8d>;
 };
