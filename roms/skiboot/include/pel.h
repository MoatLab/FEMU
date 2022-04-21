// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2014 IBM Corp. */

#ifndef __PEL_H
#define __PEL_H

#include <compiler.h>
#include <errorlog.h>

/* Data Structures for PEL data. */

#define PRIVATE_HEADER_SECTION_SIZE		48
#define USER_HEADER_SECTION_SIZE		24
#define SRC_SECTION_SIZE			80
#define SRC_SUBSECTION_SIZE			 4
#define SRC_LENGTH				72
#define OPAL_MAX_SRC_BYTES			32
#define EXTENDED_HEADER_SECTION_SIZE		76
#define MTMS_SECTION_SIZE			28
#define IO_EVENT_SECTION_SIZE			16

#define OPAL_ELOG_VERSION		1
#define OPAL_ELOG_SST			0
#define OPAL_SRC_MAX_WORD_COUNT		8

#define OPAL_SRC_FORMAT         0x80
#define OPAL_FAILING_SUBSYSTEM  0x82

#define OPAL_SYS_MODEL_LEN      8
#define OPAL_SYS_SERIAL_LEN     12
#define OPAL_VER_LEN            16
#define OPAL_SYMPID_LEN         80
#define OPAL_RC_NONE		0

#define OPAL_IO_MAX_RPC_DATA	216
#define OPAL_SRC_SEC_VER	0x02
#define OPAL_EXT_HRD_VER	0x01

/* Error log reporting action */
#define ERRL_ACTION_REPORT     0x2000
#define ERRL_ACTION_NONE       0x0000

enum elogSectionId {
	ELOG_SID_PRIVATE_HEADER                 = 0x5048, /* PH */
	ELOG_SID_USER_HEADER                    = 0x5548, /* UH */
	ELOG_SID_EXTENDED_HEADER                = 0x4548, /* EH */
	ELOG_SID_PRIMARY_SRC                    = 0x5053, /* PS */
	ELOG_SID_MACHINE_TYPE                   = 0x4D54, /* MT */
	ELOG_SID_SECONDARY_SRC                  = 0x5353, /* SS */
	ELOG_SID_CALL_HOME                      = 0x4348, /* CH */
	ELOG_SID_DUMP_LOCATOR                   = 0x4448, /* DH */
	ELOG_SID_SOFTWARE_ERROR			= 0x5357, /* SW */
	ELOG_SID_PARTITION                      = 0x4C50, /* LP */
	ELOG_SID_LOGICAL_RESOURCE               = 0x4C52, /* LR */
	ELOG_SID_HMC_ID                         = 0x484D, /* HM */
	ELOG_SID_EPOW                           = 0x4550, /* EP */
	ELOG_SID_IO_EVENT                       = 0x4945, /* IE */
	ELOG_SID_MFG_INFORMATION                = 0x4D49, /* MI */
	ELOG_SID_USER_DEFINED                   = 0x5544  /* UD */
};


struct opal_v6_header {
	__be16	id;	/* section id */
	__be16	length;		/* section length */
	uint8_t	version;		/* section version */
	uint8_t	subtype;		/* section sub-type id */
	__be16	component_id;	/* component id of section creator */
} __packed;

/* opal_srctype */
#define OPAL_SRC_TYPE_ERROR 0xBB

#define OPAL_CID_SAPPHIRE	'K'	/* creator ID for sapphire log */
#define OPAL_CID_POWERNV	'P'	/* creator ID for powernv log */

/* Origin of error, elog_origin */
#define ORG_SAPPHIRE	1
#define ORG_POWERNV	2

/* MAX time for error log commit */
#define ERRORLOG_TIMEOUT_INTERVAL	180

/*struct opal_private head section_ */
struct opal_private_header_section {

	struct opal_v6_header v6header;
	__be32 create_date;
	__be32 create_time;
	__be32 commit_date;
	__be32 commit_time;

	uint8_t creator_id;		/* subsystem component id */
	__be16 reserved_0;
	uint8_t section_count;		/* number of sections in log */
	__be32 reserved_1;
	__be32 creator_subid_hi;
	__be32 creator_subid_lo;
	__be32 plid;			/* platform log id */
	__be32 log_entry_id;		/* Unique log entry id */
} __packed;

/* opal user header section */
struct opal_user_header_section {

	struct opal_v6_header v6header;

	uint8_t subsystem_id;	/* subsystem id */
	uint8_t event_scope;
	uint8_t event_severity;
	uint8_t event_type;	/* error/event severity */

	__be32 reserved_0;
	__be16 reserved_1;
	__be16 action_flags;	/* error action code */
	__be32 reserved_2;
} __packed;

struct opal_src_section {
	struct opal_v6_header v6header;
	uint8_t		version;
	uint8_t		flags;
	uint8_t		reserved_0;
	uint8_t		wordcount;
	__be16		reserved_1;
	__be16		srclength;
	__be32		hexwords[OPAL_SRC_MAX_WORD_COUNT];
	char		srcstring[OPAL_MAX_SRC_BYTES];
} __packed;

struct opal_extended_header_section {
	struct	opal_v6_header v6header;
	char	model[OPAL_SYS_MODEL_LEN];
	char	serial_no[OPAL_SYS_SERIAL_LEN];
	char	opal_release_version[OPAL_VER_LEN];
	char	opal_subsys_version[OPAL_VER_LEN];
	__be16	reserved_0;
	__be32	extended_header_date;
	__be32	extended_header_time;
	__be16	reserved_1;
	uint8_t	reserved_2;
	uint8_t	opal_symid_len;
	char	opalsymid[OPAL_SYMPID_LEN];
} __packed;

/* opal MTMS section */
struct opal_mtms_section {
	struct opal_v6_header v6header;
	char        model[OPAL_SYS_MODEL_LEN];
	char        serial_no[OPAL_SYS_SERIAL_LEN];
} __packed;

/* User defined section */
struct opal_user_section {
	struct opal_v6_header v6header;
	char dump[1];
} __packed;

/* The minimum size of a PEL record */
#define PEL_MIN_SIZE (PRIVATE_HEADER_SECTION_SIZE + USER_HEADER_SECTION_SIZE \
		      + SRC_SECTION_SIZE + EXTENDED_HEADER_SECTION_SIZE \
		      + MTMS_SECTION_SIZE)

size_t pel_size(struct errorlog *elog_data);
int create_pel_log(struct errorlog *elog_data, char *pel_buffer,
		   size_t pel_buffer_size) __warn_unused_result;

#endif
