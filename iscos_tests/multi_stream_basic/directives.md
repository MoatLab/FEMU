Directives used for computational storage:

We use identify directive "send command" to set the reads/writes done from a particular fd to undergo a specific computation.

identifier type - 00
`doper` - send
`dw12` - 15:08 are the bits that can be used for setting or resetting a particular directive on an fd.
we leave the first two bits 08 (0x101) and 09 (0x201) as they represent `NVME_DIR_IDF_IDENTIFY` and `NVME_DIR_IDF_STREAMS`.
We use 15:10 bits in dw12 to set a stream/directive to perform computation.

Directives Primer

There are 3 fields in a directive - `dtype`, `dspec`, `doper`

Directive Types:
1.	00 - identify directive. 
	`dspec` is ignored here. `doper` is either send or recieve.
	for `directive_recieve_command` `doper=01h`, controller returns the directive types supported and enabled by the controller and the namespace.
	for `directive_send_command` `doper=01h`, dw12 - 15:08 DTYPE to enable or disable. 00 ENDIR enable directive or disable directive.

2.	01 - stream directive.
	- `directive_recieve_command` 
		`doper=01h` `return_parameters` operation - host knows parameters associated with stream resources. `dspec` is ignored. return parameters contain
		1. NVMe Subsystem Fields
		MSL (Maximum Streams Limit), NVM Subsystem Streams Available (NSSA), Streams Open (NSSO), Stream Capability (NSSC).
		2. Namespace Specific Fields
		SWS (Stream Write Size), SGS (Stream Grannularity Size)
		Few others	

		`doper=02h` `get_status` operation - list of open stream identifiers are returned.
		`dspec` not used. returns info about status of currently opened streams.
		128KB return structure. returns
		1. open stream count
		2. Stream ID 1.
		3. Stream ID 2. and so on.

		`doper=03h` `allocate_resources` operation - 
		number of streams host requests for its exclusive use for a specified namespace.
		dw12 - (NSR) number of stream resources requested by host.
		dw0 - (NSA) number of stream resources allocated by host.

	- `directive_send_command`
		`doper=01h` - release identifyer 
		`doper=02h` - release resources

