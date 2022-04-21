How to log errors on OPAL
=========================

Currently the errors reported by OPAL interfaces are in free form, where as
errors reported by service processor is in standard Platform Error Log (PEL)
format. For out-of band management via IPMI interfaces, it is necessary to
push down the errors to service processor via mailbox (reported by OPAL)
in PEL format.

PEL size can vary from 2K-16K bytes, fields of which needs to populated based
on the kind of event and error that needs to be reported. All the information
needed to be reported as part of the error, is passed by user using the
error-logging interfaces outlined below. Following which, PEL structure is
generated based on the input and then passed on to service processor.

We do create eSEL error log format for some service processors but it's just
a wrapper around PEL format. Actual data still stays in PEL format.

Error logging interfaces in OPAL
--------------------------------

Interfaces are provided for the user to log/report an error in OPAL. Using
these interfaces relevant error information is collected and later converted
to PEL format and then pushed to service processor.

Step 1: To report an error, invoke ``opal_elog_create()`` with required argument.

	``struct errorlog *opal_elog_create(struct opal_err_info *e_info, uint32_t tag);``

Parameters:

	* ``struct opal_err_info *e_info``
	  Struct to hold information identifying error/event source.
        * ``uint32_t tag:`` Unique value to identify the data.
                       Ideal to have ASCII value for 4-byte string.

	The opal_err_info struct holds several pieces of information to help
	identify the error/event. The struct can be obtained via the
	``DEFINE_LOG_ENTRY`` macro as below - it only needs to be called once.

        ::

	 DEFINE_LOG_ENTRY(OPAL_RC_ATTN, OPAL_PLATFORM_ERR_EVT, OPAL_CHIP,
			OPAL_PLATFORM_FIRMWARE, OPAL_PREDICTIVE_ERR_GENERAL,
			OPAL_NA);

	The various attributes set by this macro are described below.

	``uint8_t opal_error_event_type``: Classification of error/events
	type reported on OPAL. ::

		/* Platform Events/Errors: Report Machine Check Interrupt */
		#define OPAL_PLATFORM_ERR_EVT           0x01
		/* INPUT_OUTPUT: Report all I/O related events/errors */
		#define OPAL_INPUT_OUTPUT_ERR_EVT       0x02
		/* RESOURCE_DEALLOC: Hotplug events and errors */
		#define OPAL_RESOURCE_DEALLOC_ERR_EVT   0x03
		/* MISC: Miscellaneous error */
		#define OPAL_MISC_ERR_EVT               0x04

	``uint16_t component_id``: Component ID of OPAL component as
	listed in ``include/errorlog.h``.

	``uint8_t subsystem_id``: ID of the sub-system reporting error. ::

		/* OPAL Subsystem IDs listed for reporting events/errors */
		#define OPAL_PROCESSOR_SUBSYSTEM        0x10
		#define OPAL_MEMORY_SUBSYSTEM           0x20
		#define OPAL_IO_SUBSYSTEM               0x30
		#define OPAL_IO_DEVICES                 0x40
		#define OPAL_CEC_HARDWARE               0x50
		#define OPAL_POWER_COOLING              0x60
		#define OPAL_MISC                       0x70
		#define OPAL_SURVEILLANCE_ERR           0x7A
		#define OPAL_PLATFORM_FIRMWARE          0x80
		#define OPAL_SOFTWARE                   0x90
		#define OPAL_EXTERNAL_ENV               0xA0

	``uint8_t event_severity``: Severity of the event/error to be reported. ::

		#define OPAL_INFO                                   0x00
		#define OPAL_RECOVERED_ERR_GENERAL                  0x10

		/* 0x2X series is to denote set of Predictive Error */
		/* 0x20 Generic predictive error */
		#define OPAL_PREDICTIVE_ERR_GENERAL                         0x20
		/* 0x21 Predictive error, degraded performance */
		#define OPAL_PREDICTIVE_ERR_DEGRADED_PERF                   0x21
		/* 0x22 Predictive error, fault may be corrected after reboot */
		#define OPAL_PREDICTIVE_ERR_FAULT_RECTIFY_REBOOT            0x22
		/*
		 * 0x23 Predictive error, fault may be corrected after reboot,
		 * degraded performance
		 */
		#define OPAL_PREDICTIVE_ERR_FAULT_RECTIFY_BOOT_DEGRADE_PERF 0x23
		/* 0x24 Predictive error, loss of redundancy */
		#define OPAL_PREDICTIVE_ERR_LOSS_OF_REDUNDANCY              0x24

		/* 0x4X series for Unrecoverable Error */
		/* 0x40 Generic Unrecoverable error */
		#define OPAL_UNRECOVERABLE_ERR_GENERAL                      0x40
		/* 0x41 Unrecoverable error bypassed with degraded performance */
		#define OPAL_UNRECOVERABLE_ERR_DEGRADE_PERF                 0x41
		/* 0x44 Unrecoverable error bypassed with loss of redundancy */
		#define OPAL_UNRECOVERABLE_ERR_LOSS_REDUNDANCY              0x44
		/* 0x45 Unrecoverable error bypassed with loss of redundancy
		 * and performance
		 */
		#define OPAL_UNRECOVERABLE_ERR_LOSS_REDUNDANCY_PERF         0x45
		/* 0x48 Unrecoverable error bypassed with loss of function */
		#define OPAL_UNRECOVERABLE_ERR_LOSS_OF_FUNCTION             0x48

		#define OPAL_ERROR_PANIC				    0x50

	``uint8_t  event_subtype``: Event Sub-type ::

		  #define OPAL_NA                                         0x00
		  #define OPAL_MISCELLANEOUS_INFO_ONLY                    0x01
		  #define OPAL_PREV_REPORTED_ERR_RECTIFIED                0x10
		  #define OPAL_SYS_RESOURCES_DECONFIG_BY_USER             0x20
		  #define OPAL_SYS_RESOURCE_DECONFIG_PRIOR_ERR            0x21
		  #define OPAL_RESOURCE_DEALLOC_EVENT_NOTIFY              0x22
		  #define OPAL_CONCURRENT_MAINTENANCE_EVENT               0x40
		  #define OPAL_CAPACITY_UPGRADE_EVENT                     0x60
		  #define OPAL_RESOURCE_SPARING_EVENT                     0x70
		  #define OPAL_DYNAMIC_RECONFIG_EVENT                     0x80
		  #define OPAL_NORMAL_SYS_PLATFORM_SHUTDOWN               0xD0
		  #define OPAL_ABNORMAL_POWER_OFF                         0xE0


	``uint8_t opal_srctype``: SRC type, value should be OPAL_SRC_TYPE_ERROR.
			SRC refers to System Reference Code.
			It is 4 byte hexa-decimal number that reflects the
			current system state.
			Eg: BB821010,

			* 1st byte -> BB -> SRC Type
			* 2nd byte -> 82 -> Subsystem
			* 3rd, 4th byte -> Component ID and Reason Code

			SRC needs to be generated on the fly depending on the state
			of the system. All the parameters needed to generate a SRC
			should be provided during reporting of an event/error.


	``uint32_t reason_code``: Reason for failure as stated in ``include/errorlog.h`` for OPAL.
			Eg: Reason code for code-update failures can be

			* ``OPAL_RC_CU_INIT``  -> Initialisation failure
			* ``OPAL_RC_CU_FLASH`` -> Flash failure


Step 2: Data can be appended to the user data section using the either of
        the below two interfaces: ::

	  void log_append_data(struct errorlog *buf, unsigned char *data,
				uint16_t size);

Parameters:

	``struct opal_errorlog *buf``: ``struct opal_errorlog`` pointer
	returned by ``opal_elog_create()`` call.

	``unsigned char *data``: Pointer to the dump data

	``uint16_t size``: Size of the dump data.

	``void log_append_msg(struct errorlog *buf, const char *fmt, ...);``

Parameters:

	``struct opal_errorlog *buf``: pointer returned by ``opal_elog_create()``
	call.

	``const char *fmt``: Formatted error log string.

	Additional user data sections can be added to the error log to
	separate data (eg. readable text vs binary data) by calling
	``log_add_section()``. The interfaces in Step 2 operate on the 'last'
	user data section of the error log.

	``void log_add_section(struct errorlog *buf, uint32_t tag);``

Parameters:

	  ``struct opal_errorlog *buf``: pointer returned by ``opal_elog_create()`` call.

	  ``uint32_t tag``: Unique value to identify the data.
	    Ideal to have ASCII value for 4-byte string.

Step 3: There is a platform hook for the OPAL error log to be committed on any
	service processor(Currently used for FSP and BMC based machines).

	Below is snippet of the code of how this hook is called.
	::

		void log_commit(struct errorlog *elog)
		{
			....
			....
			if (platform.elog_commit) {
				rc = platform.elog_commit(elog);
				if (rc)
					prerror("ELOG: Platform commit error %d"
						"\n", rc);
				return;
			}
			....
			....
		}

Step 3.1 FSP:
	::

		.elog_commit            = elog_fsp_commit

	Once all the data for an error is logged in, the error needs to
	be committed in FSP.

	In the process of committing an error to FSP, log info is first
	internally converted to PEL format and then pushed to the FSP.
	FSP then take cares of sending all logs including its own and
	OPAL's one to the POWERNV.

	OPAL maintains timeout field for all error logs it is sending to
	FSP. If it is not logged within allotted time period (e.g if FSP
	is down), in that case OPAL sends those logs to POWERNV.

Step 3.2 BMC:
	::

		  .elog_commit            = ipmi_elog_commit

	In case of BMC machines, error logs are first converted to eSEL format.
	i.e:
	::

		  eSEL = SEL header + PEL data

	SEL header contains below fields.
	::

		struct sel_header {
			uint16_t id;
			uint8_t record_type;
			uint32_t timestamp;
			uint16_t genid;
			uint8_t evmrev;
			uint8_t sensor_type;
			uint8_t sensor_num;
			uint8_t dir_type;
			uint8_t signature;
			uint8_t reserved[2];
		}

	After filling up the SEL header fields, OPAL copies the error log
	PEL data after the header section in the error log buffer. Then using
	IPMI interface, eSEL gets logged in BMC.


If the user does not intend to dump various user data sections, but just
log the error with some amount of description around that error, they can do
so using just the simple error logging interface. ::

	log_simple_error(uint32_t reason_code, char *fmt, ...);

For example: ::

	log_simple_error(OPAL_RC_SURVE_STATUS,
			"SURV: Error retrieving surveillance status: %d\n",
                       						err_len);

Using the reason code, an error log is generated with the information derived
from the look-up table, populated and committed to service processor. All of it
is done with just one call.


Error logging retrieval from FSP:
=================================

FSP sends error log notification to OPAL via mailbox protocol.

OPAL maintains below lists:

* Free list      : List of free nodes.
* Pending list   : List of nodes which is yet to be read by the POWERNV.
* Processed list : List of nodes which has been read but still waiting for
  acknowledgement.

Below is the structure of the node: ::

	struct fsp_log_entry {
		uint32_t log_id;
		size_t log_size;
		struct list_node link;
	};

OPAL maintains a state machine which has following states. ::

	enum elog_head_state {
		ELOG_STATE_FETCHING,    /*In the process of reading log from FSP. */
		ELOG_STATE_FETCHED_INFO,/* Indicates reading log info is completed */
		ELOG_STATE_FETCHED_DATA,/* Indicates reading log is completed */
		ELOG_STATE_HOST_INFO,   /* Host read log info */
		ELOG_STATE_NONE,        /* Indicates to fetch next log */
		ELOG_STATE_REJECTED,    /* resend all pending logs to linux */
	};

Initially, state of the state machine is ``ELOG_STATE_NONE``. When OPAL gets
the notification about the error log, it takes out the node from free list
and put it into pending list and update the state machine to fetching state
(``ELOG_STATE_FETCHING``). It also gives response back to FSP about the
received error log notification.

It then queue mailbox message to get the error log data in OPAL error log
buffer, once it is done state machine gets into fetched state
(``ELOG_STATE_FETCHED_DATA``). After that, OPAL notifies POWERNV host to
fetch new error log.

POWERNV uses the OPAL interface to get the error log info(elogid, elog_size,
elog_type) first then it reads the error log data in its buffer that moves
the pending error log to processed list. After reading, the state machine
moves to ``ELOG_STATE_NONE`` state.

It acknowledges the error log id after reading error log data by sending the
call to OPAL, which in turn sends the acknowledgement mbox message to FSP and
moves error log id from processed list to again back to free node list and this
process goes on every FSP error log.

Design constraints:
-------------------
::

#define ELOG_READ_MAX_RECORD            128

Currently, the number of error logs from FSP, OPAL can hold is limited to
128. If OPAL run out of free node in the list for the new error log, it sends
'Discarded by OPAL' message to the FSP. At some point in the future, it is
upto FSP when it notifies again to OPAL about the discarded error log.

::

#define ELOG_WRITE_MAX_RECORD		64

There is also limitation on the number of OPAL error logs OPAL can hold is 64.
If it is run out of the buffers in the pool, it will log the message saying
'Failed to get the buffer'.

Note
----

* For more information regarding error logging and PEL format
  refer to PAPR doc and P7 PEL and SRC PLDD document.

* Refer to ``include/errorlog.h`` for all the error logging
  interface parameters and ``include/pel.h`` for PEL
  structures.

Sample error logging
--------------------

::

  DEFINE_LOG_ENTRY(OPAL_RC_ATTN, OPAL_PLATFORM_ERR_EVT, OPAL_ATTN,
		 OPAL_PLATFORM_FIRMWARE, OPAL_PREDICTIVE_ERR_GENERAL,
		 OPAL_NA);

  void report_error(int index)
  {
	struct errorlog *buf;
	char data1[] = "This is a sample user defined data section1";
	char data2[] = "Error logging sample. These are dummy errors. Section 2";
	char data3[] = "Sample error Sample error Sample error Sample error \
			 Sample error abcdefghijklmnopqrstuvwxyz";
	int tag;

	printf("ELOG: In machine check report error index: %d\n", index);

	/* To report an error, create an error log with relevant information
	 * opal_elog_create(). Call returns a pre-allocated buffer of type
	 * 'struct errorlog' buffer with relevant fields updated.
	 */

	/* tag -> unique ascii tag to identify a particular data dump section */
	tag = 0x4b4b4b4b;
	buf = opal_elog_create(&e_info(OPAL_RC_ATTN), tag);
	if (buf == NULL) {
		printf("ELOG: Error getting buffer.\n");
		return;
	}

	/* Append data or text with log_append_data() or log_append_msg() */
	log_append_data(buf, data1, sizeof(data1));

	/* In case of user wanting to add multiple sections of various dump data
	 * for better debug, data sections can be added using this interface
	 * void log_add_section(struct errorlog *buf, uint32_t tag);
	 */
	tag = 0x4c4c4c4c;
	log_add_section(buf, tag);
	log_append_data(buf, data2, sizeof(data2));
	log_append_data(buf, data3, sizeof(data3));

	/* Once all info is updated, ready to be sent to FSP */
	printf("ELOG:commit to FSP\n");
	log_commit(buf);
 }

Sample output PEL dump got from FSP
-----------------------------------

::
   
 $ errl -d -x 0x533C9B37
 |   00000000     50480030  01004154  20150728  02000500     PH.0..AT ..(....   |
 |   00000010     20150728  02000566  4B000107  00000000      ..(...fK.......   |
 |   00000020     00000000  00000000  B0000002  533C9B37     ............S..7   |
 |   00000030     55480018  01004154  80002000  00000000     UH....AT.. .....   |
 |   00000040     00002000  01005300  50530050  01004154     .. ...S.PS.P..AT   |
 |   00000050     02000008  00000048  00000080  00000000     .......H........   |
 |   00000060     00000000  00000000  00000000  00000000     ................   |
 |   00000070     00000000  00000000  42423832  31343130     ........BB821410   |
 |   00000080     20202020  20202020  20202020  20202020                        |
 |   00000090     20202020  20202020  4548004C  01004154             EH.L..AT   |
 |   000000A0     38323836  2D343241  31303738  34415400     8286-42A10784AT.   |
 |   000000B0     00000000  00000000  00000000  00000000     ................   |
 |   000000C0     00000000  00000000  00000000  00000000     ................   |
 |   000000D0     00000000  00000000  20150728  02000500     ........ ..(....   |
 |   000000E0     00000000  4D54001C  01004154  38323836     ....MT....AT8286   |
 |   000000F0     2D343241  31303738  34415400  00000000     -42A10784AT.....   |
 |   00000100     5544003C  01004154  4B4B4B4B  00340000     UD....ATKKKK.4..   |
 |   00000110     54686973  20697320  61207361  6D706C65     This is a sample   |
 |   00000120     20757365  72206465  66696E65  64206461      user defined da   |
 |   00000130     74612073  65637469  6F6E3100  554400A7     ta section1.UD..   |
 |   00000140     01004154  4C4C4C4C  009F0000  4572726F     ..ATLLLL....Erro   |
 |   00000150     72206C6F  6767696E  67207361  6D706C65     r logging sample   |
 |   00000160     2E205468  65736520  61726520  64756D6D     . These are dumm   |
 |   00000170     79206572  726F7273  2E205365  6374696F     y errors. Sectio   |
 |   00000180     6E203200  53616D70  6C652065  72726F72     n 2.Sample error   |
 |   00000190     2053616D  706C6520  6572726F  72205361      Sample error Sa   |
 |   000001A0     6D706C65  20657272  6F722053  616D706C     mple error Sampl   |
 |   000001B0     65206572  726F7220  09090953  616D706C     e error ...Sampl   |
 |   000001C0     65206572  726F7220  61626364  65666768     e error abcdefgh   |
 |   000001D0     696A6B6C  6D6E6F70  71727374  75767778     ijklmnopqrstuvwx   |
 |   000001E0     797A00                                     yz.                |
 |------------------------------------------------------------------------------|
 |                       Platform Event Log - 0x533C9B37                        |
 |------------------------------------------------------------------------------|
 |                                Private Header                                |
 |------------------------------------------------------------------------------|
 | Section Version          : 1                                                 |
 | Sub-section type         : 0                                                 |
 | Created by               : 4154                                              |
 | Created at               : 07/28/2015 02:00:05                               |
 | Committed at             : 07/28/2015 02:00:05                               |
 | Creator Subsystem        : OPAL                                              |
 | CSSVER                   :                                                   |
 | Platform Log Id          : 0xB0000002                                        |
 | Entry Id                 : 0x533C9B37                                        |
 | Total Log Size           : 483                                               |
 |------------------------------------------------------------------------------|
 |                                 User Header                                  |
 |------------------------------------------------------------------------------|
 | Section Version          : 1                                                 |
 | Sub-section type         : 0                                                 |
 | Log Committed by         : 4154                                              |
 | Subsystem                : Platform Firmware                                 |
 | Event Scope              : Unknown - 0x00000000                              |
 | Event Severity           : Predictive Error                                  |
 | Event Type               : Not Applicable                                    |
 | Return Code              : 0x00000000                                        |
 | Action Flags             : Report Externally                                 |
 | Action Status            : Sent to Hypervisor                                |
 |------------------------------------------------------------------------------|
 |                        Primary System Reference Code                         |
 |------------------------------------------------------------------------------|
 | Section Version          : 1                                                 |
 | Sub-section type         : 0                                                 |
 | Created by               : 4154                                              |
 | SRC Format               : 0x80                                              |
 | SRC Version              : 0x02                                              |
 | Virtual Progress SRC     : False                                             |
 | I5/OS Service Event Bit  : False                                             |
 | Hypervisor Dump Initiated: False                                             |
 | Power Control Net Fault  : False                                             |
 |                                                                              |
 | Valid Word Count         : 0x08                                              |
 | Reference Code           : BB821410                                          |
 | Hex Words 2 - 5          : 00000080 00000000 00000000 00000000               |
 | Hex Words 6 - 9          : 00000000 00000000 00000000 00000000               |
 |                                                                              |
 |------------------------------------------------------------------------------|
 |                             Extended User Header                             |
 |------------------------------------------------------------------------------|
 | Section Version          : 1                                                 |
 | Sub-section type         : 0                                                 |
 | Created by               : 4154                                              |
 | Reporting Machine Type   : 8286-42A                                          |
 | Reporting Serial Number  : 10784AT                                           |
 | FW Released Ver          :                                                   |
 | FW SubSys Version        :                                                   |
 | Common Ref Time          : 07/28/2015 02:00:05                               |
 | Symptom Id Len           : 0                                                 |
 | Symptom Id               :                                                   |
 |------------------------------------------------------------------------------|
 |                      Machine Type/Model & Serial Number                      |
 |------------------------------------------------------------------------------|
 | Section Version          : 1                                                 |
 | Sub-section type         : 0                                                 |
 | Created by               : 4154                                              |
 | Machine Type Model       : 8286-42A                                          |
 | Serial Number            : 10784AT                                           |
 |------------------------------------------------------------------------------|
 |                              User Defined Data                               |
 |------------------------------------------------------------------------------|
 | Section Version          : 1                                                 |
 | Sub-section type         : 0                                                 |
 | Created by               : 4154                                              |
 |                                                                              |
 |   00000000     4B4B4B4B  00340000  54686973  20697320     KKKK.4..This is    |
 |   00000010     61207361  6D706C65  20757365  72206465     a sample user de   |
 |   00000020     66696E65  64206461  74612073  65637469     fined data secti   |
 |   00000030     6F6E3100                                   on1.               |
 |                                                                              |
 |------------------------------------------------------------------------------|
 |                              User Defined Data                               |
 |------------------------------------------------------------------------------|
 | Section Version          : 1                                                 |
 | Sub-section type         : 0                                                 |
 | Created by               : 4154                                              |
 |                                                                              |
 |   00000000     4C4C4C4C  009F0000  4572726F  72206C6F     LLLL....Error lo   |
 |   00000010     6767696E  67207361  6D706C65  2E205468     gging sample. Th   |
 |   00000020     65736520  61726520  64756D6D  79206572     ese are dummy er   |
 |   00000030     726F7273  2E205365  6374696F  6E203200     rors. Section 2.   |
 |   00000040     53616D70  6C652065  72726F72  2053616D     Sample error Sam   |
 |   00000050     706C6520  6572726F  72205361  6D706C65     ple error Sample   |
 |   00000060     20657272  6F722053  616D706C  65206572      error Sample er   |
 |   00000070     726F7220  09090953  616D706C  65206572     ror ...Sample er   |
 |   00000080     726F7220  61626364  65666768  696A6B6C     ror abcdefghijkl   |
 |   00000090     6D6E6F70  71727374  75767778  797A00       mnopqrstuvwxyz.    |
 |                                                                              |
 |------------------------------------------------------------------------------|

