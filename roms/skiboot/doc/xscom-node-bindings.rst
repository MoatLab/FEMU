XSCOM Bindings
==============

XSCOM regions
-------------

The top-level xscom nodes specify the mapping range from the 64-bit address
space into the PCB address space.

There's one mapping range per chip xscom, therefore one node per mapping range.
::

 /
 /xscom@<chip-base-address-0>/
 /xscom@<chip-base-address-1>/
 …
 /xscom@<chip-base-address-n>/

* where <chip-base-address-n> is the xscom base address with the gcid-specific
  bits (for chip n) OR-ed in.

Each xscom node has the following properties:

 * #address-cells = 1
 * #size-cells = 1
 * reg = <base-address[#parent-address-cells] size[#parent-size-cells]>
 * ibm,chip-id = gcid
 * compatible = "ibm,xscom", "ibm,power8-scom" / "ibm,power7-xscom" 
 * ecid = <Electronic Chip ID, applicable for POWER9 onwards>
 * wafer-id = <wafer ID, applicable for POWER9 onwards>
 * wafer-location = <wafer location, applicable for POWER9 onwards>

ECID
----
Electronic Chip ID (ECID) is a process by which the wafer number, chip location
(i.e. X,Y) and other optional data items are electrically encoded directly on
the chip. wafer-id property represents wafer number and wafer-location property
represents chip location (both X and Y location).


Chiplet endpoints
-----------------

One sub-node per endpoint. Endpoints are defined by their (port,
endpoint-address) data on the PCB, and are named according to their endpoint
types:
::

 /xscom@<chip-base-address>/
 /xscom@<chip-base-address>/chiptod@<endpoint-addr>
 /xscom@<chip-base-address>/lpc@<endpoint-addr>

* where the <endpoint-addr> is a single address (as distinct from the current
  (gcid,base) format), consisting of the SCOM port and SCOM endpoint bits in
  their 31-bit address format.

Each endpoint node has the following properties:

 * reg = <endpoint-address[#parent-address-cells] size[#parent-size-cells]>
 * compatible - depends on endpoint type, eg "ibm,power8-chiptod" 

The endpoint address specifies the address on the PCB. So, to calculate the
MMIO address for a PCB register:
::

	mmio_addr  = <xscom-base-addr> | (pcb_addr[1:27] << 4)
				       | (pcb_addr[28:31] << 3)

Where:

  * xscom-base-addr is the address from the first two cells of the parent
    node's reg property
  * pcb_addr is the first cell of the endpoint's reg property 
