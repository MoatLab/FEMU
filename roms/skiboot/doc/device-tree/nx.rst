Nest (NX) Accelerator Coprocessor
=================================

The NX coprocessor is present in P7+ or later processors.  Each NX node
represents a unique NX coprocessor.  The nodes are located under an
xscom node, as: ::

  /xscom@<xscom_addr>/nx@<nx_addr>

With unique xscom and nx addresses.  Their compatible node contains
"ibm,power-nx".


NX Compression Coprocessor
--------------------------

This is the memory compression coprocessor. which uses the IBM proprietary
842 compression algorithm and format. Each NX node contains an 842 engine.  ::

   ibm,842-coprocessor-type	: CT value common to all 842 coprocessors
   ibm,842-coprocessor-instance	: CI value unique to all 842 coprocessors

Access to the coprocessor requires using the ICSWX instruction, which uses
a specific format including a Coprocessor Type (CT) and Coprocessor Instance
(CI) value to address each request to the right coprocessor.  The driver should
use the CT and CI values for a particular node to communicate with it.  For
all 842 coprocessors in the system, the CT value will (should) be the same,
while each will have a different CI value.  The driver can use CI 0 to allow
the hardware to automatically select which coprocessor instance to use.

On P9, this compression coprocessor also supports standard GZIP/ZLIB
compression algorithm and format. Virtual Accelerator Swirchboard (VAS) is used
to access this coprocessor. VAS writes each request to receive FIFOs (RXFIFO)
which are either high or normal priority  and these FIFOs are bound to
coprocessor types (842 and gzip).

VAS distinguishes NX requests for the target engines based on logical
partition ID (lpid), process ID (pid) and Thread ID (tid). So (lpid, pid, tid)
combination has to be unique in the system. Each NX node contains high and
normal FIFOs for each  842 and GZIP engines.  ::

  /ibm,842-high-fifo		: High priority 842 RxFIFO
  /ibm,842-normal-fifo		: Normal priority 842 RxFIFO
  /ibm,gzip-high-fifo		: High priority gzip RxFIFO
  /ibm,gzip-normal-fifo		: Normal priority gzip RxFIFO

Each RxFIFO node contains: ::

	compatible		: ibm,p9-nx-842 or ibm,p9-nx-gzip
	priority		: High or Normal
	rx-fifo-address		: RxFIFO buffer address
	rx-fifo-size		: RxFIFO size
	lpid			: 0xfff (1's for 12 bits in UMAC notify match
				  register)
	pid			: Coprocessor type (either 842 or gzip)
	tid			: counter in each coprocessor type

During initialization, the driver invokes VAS interface for each coprocessor
type (842 and gzip) to configure the RxFIFO with rx_fifo_address, lpid, pid
and tid for high and nornmal priority FIFOs.

NX RNG Coprocessor
------------------

This is the Random Number Generator (RNG) coprocessor, which is a part
of each NX coprocessor.  Each node represents a unique RNG coprocessor.
Its nodes are not under the main nx node, they are located at: ::

  /hwrng@<addr>		: RNG at address <addr>
  ibm,chip-id		: chip id where the RNG is
  reg			: address of the register to read from

Each read from the RNG register will provide a new random number.


