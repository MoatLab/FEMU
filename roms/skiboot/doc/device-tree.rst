.. _device-tree:

Device Tree
===========

General notes on the Device Tree produced by skiboot. This chapter
**needs updating**.


General comments
----------------

* skiboot does not require nodes to have phandle properties, but
  if you have them then *all* nodes must have them including the
  root of the device-tree (currently a HB bug !). It is recommended
  to have them since they are needed to represent the cache levels.
* **NOTE**: The example tree below only has phandle properties for
  nodes that are referenced by other nodes. This is *not* correct
  and is purely done for keeping this document smaller, make sure
  to follow the rule above.
* Only the "phandle" property is required. Sapphire also generates
  a "linux,phandle" for backward compatibility but doesn't require
  it as an input
* Any property not specifically documented must be put in "as is"
* All ibm,chip-id properties contain a HW chip ID which correspond
  on P8 to the PIR value shifted right by 7 bits, ie. it's a 6-bit
  value made of a 3-bit node number and a 3-bit chip number.
* Unit addresses (@xxxx part of node names) should if possible use
  lower case hexadecimal to be consistent with what skiboot does
  and to help some stupid parsers out there...


Reserve Map
-----------

Here are the reserve map entries. They should exactly match the
reserved-ranges property of the root node (see documentation
of that property)

.. code-block:: dts

  /dts-v1/;
  /memreserve/	0x00000007fe600000 0x0000000000100000;
  /memreserve/	0x00000007fe200000 0x0000000000100000;
  /memreserve/	0x0000000031e00000 0x00000000003e0000;
  /memreserve/	0x0000000031000000 0x0000000000e00000;
  /memreserve/	0x0000000030400000 0x0000000000c00000;
  /memreserve/	0x0000000030000000 0x0000000000400000;
  /memreserve/	0x0000000400000000 0x0000000000600450;

Root Node
---------

Root node of device tree. There are a few required and a few optional properties
that sit in the root node. They're described here.

compatible
^^^^^^^^^^

The "compatible" properties are string lists indicating the overall
compatibility from the more specific to the least specific.

The root node compatible property *must* contain "ibm,powernv" for
Linux to have the powernv platform match the machine.

Each distinct platform *MUST* also add a more precise property (first
in order) indicating the board type.

The standard naming is "vendor,name". For example: `compatible = "goog,rhesus","ibm,powernv";`
would work. Or even better: `compatible = "goog,rhesus-v1","goog,rhesus","ibm,powernv";`.

The bare `ibm,powernv` should be reserved for bringup/testing:

.. code-block:: dts

 /dts-v1/;
 / {
	compatible = "ibm,powernv";
   };

Example
^^^^^^^

.. code-block:: dts

 /dts-v1/;
 / {
	compatible = "ibm,powernv";

	/* mandatory */
	#address-cells = <0x2>;
	#size-cells = <0x2>;

	/* User visible board name (will be shown in /proc/cpuinfo) */
	model = "Machine Name";

	/*
	 * The reserved-names and reserve-names properties work hand in hand. The first one
	 * is a list of strings providing a "name" for each entry in the second one using
	 * the traditional "vendor,name" format.
	 *
	 * The reserved-ranges property contains a list of ranges, each in the form of 2 cells
	 * of address and 2 cells of size (64-bit x2 so each entry is 4 cells) indicating
	 * regions of memory that are reserved and must not be overwritten by skiboot or
	 * subsequently by the Linux Kernel.
	 *
	 * Corresponding entries must also be created in the "reserved map" part of the flat
	 * device-tree (which is a binary list in the header of the fdt).
	 *
	 * Unless a component (skiboot or Linux) specifically knows about a region (usually
	 * based on its name) and decides to change or remove it, all these regions are
	 * passed as-is to Linux and to subsequent kernels across kexec and are kept
	 * preserved.
	 *
	 * NOTE: Do *NOT* copy the entries below, they are just an example and are actually
	 * created by skiboot itself. They represent the SLW image as "detected" by reading
	 * the PBA BARs and skiboot own memory allocations.
	 *
	 * I would recommend that you put in there the SLW and OCC (or HOMER as one block
	 * if that's how you use it) and any additional memory you want to preserve such
	 * as FW log buffers etc...
	 */
	 
	reserved-names = "ibm,slw-image", "ibm,slw-image", "ibm,firmware-stacks", "ibm,firmware-data", "ibm,firmware-heap", "ibm,firmware-code", "memory@400000000";
	reserved-ranges = <0x7 0xfe600000 0x0 0x100000 0x7 0xfe200000 0x0 0x100000 0x0 0x31e00000 0x0 0x3e0000 0x0 0x31000000 0x0 0xe00000 0x0 0x30400000 0x0 0xc00000 0x0 0x30000000 0x0 0x400000 0x4 0x0 0x0 0x600450>;

	/* Mandatory */
	cpus {
		#address-cells = <0x1>;
		#size-cells = <0x0>;

		/*
		 * The following node must exist for each *core* in the system. The unit
		 * address (number after the @) is the hexadecimal HW CPU number (PIR value)
		 * of thread 0 of that core.
		 */
		PowerPC,POWER8@20 {
			/* mandatory/standard properties */
			device_type = "cpu";
			64-bit;
			32-64-bridge;
			graphics;
			general-purpose;

			/*
			 * The "status" property indicate whether the core is functional. It's
			 * a string containing "okay" for a good core or "bad" for a non-functional
			 * one. You can also just ommit the non-functional ones from the DT
			 */
			status = "okay";

			/*
			 * This is the same value as the PIR of thread 0 of that core
			 * (ie same as the @xx part of the node name)
			 */
			reg = <0x20>;

			/* same as above */
			ibm,pir = <0x20>;

			/* chip ID of this core */
			ibm,chip-id = <0x0>;

			/*
			 * interrupt server numbers (aka HW processor numbers) of all threads
			 * on that core. This should have 8 numbers and the first one should
			 * have the same value as the above ibm,pir and reg properties
			 */
			ibm,ppc-interrupt-server#s = <0x20 0x21 0x22 0x23 0x24 0x25 0x26 0x27>;

			/*
			 * This is the "architected processor version" as defined in PAPR. Just
			 * stick to 0x0f000004 for P8 and things will be fine
			 */
			cpu-version = <0x0f000004>;

			/*
			 * These are various definitions of the page sizes and segment sizes
			 * supported by the MMU, those values are fine for P8 for now
			 */
			ibm,processor-segment-sizes = <0x1c 0x28 0xffffffff 0xffffffff>;
			ibm,processor-page-sizes = <0xc 0x10 0x18 0x22>;
			ibm,segment-page-sizes = <0xc 0x0 0x3 0xc 0x0 0x10 0x7 0x18 0x38 0x10 0x110 0x2 0x10 0x1 0x18 0x8 0x18 0x100 0x1 0x18 0x0 0x22 0x120 0x1 0x22 0x3>;

			/*
			 * Similarly that might need to be reviewed later but will do for now...
			 */			
			ibm,pa-features = [0x6 0x0 0xf6 0x3f 0xc7 0x0 0x80 0xc0];

			/* SLB size, use as-is */
			ibm,slb-size = <0x20>;

			/* VSX support, use as-is */
			ibm,vmx = <0x2>;

			/* DFP support, use as-is */
			ibm,dfp = <0x2>;

			/* PURR/SPURR support, use as-is */
			ibm,purr = <0x1>;
			ibm,spurr = <0x1>;

			/*
			 * Old-style core clock frequency. Only create this property if the frequency fits
			 * in a 32-bit number. Do not create it if it doesn't
			 */
			clock-frequency = <0xf5552d00>;

			/*
			 * mandatory: 64-bit version of the core clock frequency, always create this
			 * property.
			 */
			ibm,extended-clock-frequency = <0x0 0xf5552d00>;

			/* Timebase freq has a fixed value, always use that */
			timebase-frequency = <0x1e848000>;

			/* Same */
			ibm,extended-timebase-frequency = <0x0 0x1e848000>;

			/* Use as-is, values might need to be adjusted but that will do for now */
			reservation-granule-size = <0x80>;
			d-tlb-size = <0x800>;
			i-tlb-size = <0x0>;
			tlb-size = <0x800>;
			d-tlb-sets = <0x4>;
			i-tlb-sets = <0x0>;
			tlb-sets = <0x4>;
			d-cache-block-size = <0x80>;
			i-cache-block-size = <0x80>;
			d-cache-size = <0x10000>;
			i-cache-size = <0x8000>;
			i-cache-sets = <0x4>;
			d-cache-sets = <0x8>;
			performance-monitor = <0x0 0x1>;

			/*
			 * optional: phandle of the node representing the L2 cache for this core,
			 * note: it can also be named "next-level-cache", Linux will support both
			 * and Sapphire doesn't currently use those properties, just passes them
			 * along to Linux
			 */
			l2-cache = < 0x4 >;
		};

		/*
		 * Cache nodes. Those are siblings of the processor nodes under /cpus and
		 * represent the various level of caches.
		 *
		 * The unit address (and reg property) is mostly free-for-all as long as
		 * there is no collisions. On HDAT machines we use the following encoding
		 * which I encourage you to also follow to limit surprises:
		 *
		 * L2   :  (0x20 << 24) | PIR (PIR is PIR value of thread 0 of core)
		 * L3   :  (0x30 << 24) | PIR
		 * L3.5 :  (0x35 << 24) | PIR
		 *
		 * In addition, each cache points to the next level cache via its
		 * own "l2-cache" (or "next-level-cache") property, so the core node
		 * points to the L2, the L2 points to the L3 etc...
		 */
 
		l2-cache@20000020 {
			phandle = <0x4>;
			device_type = "cache";
			reg = <0x20000020>;
			status = "okay";
			cache-unified;
			d-cache-sets = <0x8>;
			i-cache-sets = <0x8>;
			d-cache-size = <0x80000>;
			i-cache-size = <0x80000>;
			l2-cache = <0x5>;
		};

		l3-cache@30000020 {
			phandle = <0x5>;
			device_type = "cache";
			reg = <0x30000020>;
			status = "bad";
			cache-unified;
			d-cache-sets = <0x8>;
			i-cache-sets = <0x8>;
			d-cache-size = <0x800000>;
			i-cache-size = <0x800000>;
		};

	};

	/*
	 * Interrupt presentation controller (ICP) nodes
	 *
	 * There is some flexibility as to how many of these are presents since
	 * a given node can represent multiple ICPs. When generating from HDAT we
	 * chose to create one per core
	 */
	interrupt-controller@3ffff80020000 {
		/* Mandatory */
		compatible = "IBM,ppc-xicp", "IBM,power8-icp";
		interrupt-controller;
		#address-cells = <0x0>;
		device_type = "PowerPC-External-Interrupt-Presentation";

		/*
		 * Range of HW CPU IDs represented by that node. In this example
		 * the core starting at PIR 0x20 and 8 threads, which corresponds
		 * to the CPU node of the example above. The property in theory
		 * supports multiple ranges but Linux doesn't.
		 */
		ibm,interrupt-server-ranges = <0x20 0x8>;

		/*
		 * For each server in the above range, the physical address of the
		 * ICP register block and its size. Since the root node #address-cells
		 * and #size-cells properties are both "2", each entry is thus
		 * 2 cells address and 2 cells size (64-bit each).
		 */
		reg = <0x3ffff 0x80020000 0x0 0x1000 0x3ffff 0x80021000 0x0 0x1000 0x3ffff 0x80022000 0x0 0x1000 0x3ffff 0x80023000 0x0 0x1000 0x3ffff 0x80024000 0x0 0x1000 0x3ffff 0x80025000 0x0 0x1000 0x3ffff 0x80026000 0x0 0x1000 0x3ffff 0x80027000 0x0 0x1000>;
	};

	/*
	 * The "memory" nodes represent physical memory in the system. They
	 * do not represent DIMMs, memory controllers or Centaurs, thus will
	 * be expressed separately.
	 *
	 * In order to be able to handle affinity properly, we require that
	 * a memory node is created for each range of memory that has a different
	 * "affinity", which in practice means for each chip since we don't
	 * support memory interleaved across multiple chips on P8.
	 *
	 * Additionally, it is *not* required that one chip = one memory node,
	 * it is perfectly acceptable to break down the memory of one chip into
	 * multiple memory nodes (typically skiboot does that if the two MCs
	 * are not interlaved).
	 */
	memory@0 {
		device_type = "memory";

		/*
		 * We support multiple entries in the ibm,chip-id property for
		 * memory nodes in case the memory is interleaved across multiple
		 * chips but that shouldn't happen on P8
		 */
		ibm,chip-id = <0x0>;

		/* The "reg" property is 4 cells, as usual for a child of
		 * the root node, 2 cells of address and 2 cells of size
		 */
		reg = <0x0 0x0 0x4 0x0>;
	};

	/*
	 * The XSCOM node. This is the closest thing to a "chip" node we have.
	 * there must be one per chip in the system (thus a DCM has two) and
	 * while it represents the "parent" of various devices on the PIB/PCB
	 * that we want to expose, it is also used to store all sort of
	 * miscellaneous per-chip information on HDAT based systems (such
	 * as VPDs).
	 */
	xscom@3fc0000000000 {
		/* standard & mandatory */
		#address-cells = <0x1>;
		#size-cells = <0x1>;
		scom-controller;
		compatible = "ibm,xscom", "ibm,power8-xscom";

		/* The chip ID as usual ... */
		ibm,chip-id = <0x0>;

		/* The base address of xscom for that chip */
		reg = <0x3fc00 0x0 0x8 0x0>;

		/*
		 * This comes from HDAT and I *think* is the raw content of the 
		 * module VPD eeprom (and thus doesn't have a standard ASCII keyword
		 * VPD format). We don't currently use it though ...
		 */
		ibm,module-vpd = < /* ... big pile of binary data ... */ >;

		/* PSI host bridge XSCOM register set */
		psihb@2010900 {
			reg = <0x2010900 0x20>;
			compatible = "ibm,power8-psihb-x", "ibm,psihb-x";
		};

		/* Chip TOD XSCOM register set */
		chiptod@40000 {
			reg = <0x40000 0x34>;
			compatible = "ibm,power-chiptod", "ibm,power8-chiptod";

			/*
			 * Create that property with no value if this chip has
			 * the Primary TOD in the topology. If it has the secondary
			 * one (backup master ?) use "secondary".
			 */
			primary;
		};

		/* NX XSCOM register set */
		nx@2010000 {
			reg = <0x2010000 0x4000>;
			compatible = "ibm,power-nx", "ibm,power8-nx";
		};

		/*
		 * PCI "PE Master" XSCOM register set for each active PHB
		 *
		 * For now, do *not* create these if the PHB isn't connected,
		 * clocked, or the PHY/HSS not configured.
		 */
		pbcq@2012000 {
			reg = <0x2012000 0x20 0x9012000 0x5 0x9013c00 0x15>;
			compatible = "ibm,power8-pbcq";

			/* Indicate the PHB index on the chip, ie, 0,1 or 2 */
			ibm,phb-index = <0x0>;

			/* Create that property to use the IBM-style "A/B" dual input
			 * slot presence detect mechanism.
			 */
			ibm,use-ab-detect;

			/*
			 * TBD: Lane equalization values. Not currently used by
			 * skiboot but will have to be sorted out
			 */
			ibm,lane_eq = <0x0>;
		};

		pbcq@2012400 {
			reg = <0x2012400 0x20 0x9012400 0x5 0x9013c40 0x15>;
			compatible = "ibm,power8-pbcq";
			ibm,phb-index = <0x1>;
			ibm,use-ab-detect;
			ibm,lane_eq = <0x0>;
		};

		/*
		 * Here's the LPC bus. Ideally each chip has one but in
		 * practice it's ok to only populate the ones actually
		 * used for something. This is not an exact representation
		 * of HW, in that case we would have eccb -> opb -> lpc,
		 * but instead we just have an lpc node and the address is
		 * the base of the ECCB register set for it
		 *
		 * Devices on the LPC are represented as children nodes,
		 * see example below for a standard UART.
		 */
                lpc@b0020 {
			/*
			 * Empty property indicating this is the primary
			 * LPC bus. It will be used for the default UART
			 * if any and this is the bus that will be used
			 * by Linux as the virtual 64k of IO ports
			 */
                        primary;

			/*
			 * 2 cells of address, the first one indicates the
			 * address type, see below
			 */
                        #address-cells = <0x2>;
                        #size-cells = <0x1>;
                        reg = <0xb0020 0x4>;
                        compatible = "ibm,power8-lpc";

			/*
			 * Example device: a UART on IO ports.
		 	 *
			 * LPC address have 2 cells. The first cell is the
			 * address type as follow:
	 		 *
			 *   0 : LPC memory space
			 *   1 : LPC IO space
			 *   2:  LPC FW space
			 *
			 * (This corresponds to the OPAL_LPC_* arguments
			 * passed to the opal_lpc_read/write functions)
			 *
			 * The unit address follows the old ISA convention
			 * for open firmware which prefixes IO ports with "i".
			 *
			 * (This is not critical and can be 1,3f8 if that's
			 * problematic to generate)
			 */
			serial@i3f8 {
				reg = <0x1 0x3f8 8>;
				compatible = "ns16550", "pnpPNP,501";

				/* Baud rate generator base frequency */
				clock-frequency = < 1843200 >;

				/* Default speed to use */
				current-speed = < 115200 >;

				/* Historical, helps Linux */
				device_type = "serial";

				/*
				 * Indicate which chip ID the interrupt
				 * is routed to (we assume it will always
				 * be the "host error interrupt" (aka
				 * "TPM interrupt" of that chip).
				 */
				 ibm,irq-chip-id = <0x0>;
			};
                };
	};
 };
