// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * SPCN based LED location code and other information
 *
 * Copyright 2013-2016 IBM Corp.
 */

#ifndef __FSP_LEDS_H
#define __FSP_LEDS_H

/* Supported FSP response codes */
#define FSP_IND_NOT_IMPLMNTD		0x00 /* Indicator not implemented */
#define FSP_IND_IMPLMNTD		0x04 /* Indicator implemented */
#define FSP_IND_IMPL_UNKNOWN		0x08 /* Implementation unknown */
#define FSP_IND_INACTIVE		0x00 /* Indicator not active */
#define FSP_IND_IDENTIFY_ACTV		0x01 /* Identify state active */
#define FSP_IND_FAULT_ACTV		0x02 /* Fault state active */
#define FSP_IND_STATE_UNKNOWN		0xff /* Indicator state unknown */
#define FSP_RSRC_NOT_PRESENT		0x00 /* Resource not present */
#define FSP_RSRC_PRESENT		0x40 /* Resource present */
#define FSP_RSRC_PRSNC_UNKNOWN		0x80 /* Resource presence unknown */

/* LED exclusive bits */
#define FSP_LED_EXCL_FAULT	(1UL << 0)
#define FSP_LED_EXCL_IDENTIFY	(1UL << 1)

/* LED update message source */
enum spcn_cmd_src {
	SPCN_SRC_FSP	= 0,
	SPCN_SRC_OPAL	= 1,
	SPCN_SRC_MAX	= 2
};

/* SPCN set LED */
struct spcn_led_data {
	u8	lc_len;
	__be16	state;
	char	lc_code[LOC_CODE_SIZE];
} __packed;

/* LED data */
struct fsp_led_data {
	u16			rid;			/* Resource ID */
	u8			lc_len;			/* Location code len */
        char			loc_code[LOC_CODE_SIZE];
	u16			parms;			/* Parameters */
	u16			status;			/* Status */
	u16			excl_bit;		/* Exclusive LED bit */
	struct list_node	link;
};

/* FSP location code request */
struct fsp_loc_code_req {
	__be16	len;
	__be16	req_type;
	u8	raw_len;
	u8	lc_sz;
	char	loc_code[LOC_CODE_SIZE];
} __packed;

/* FSP location code data */
struct fsp_loc_code_data {
	__be16	size;
	__be32	ccin;
	u8	status;
	u8	ind_state;
	u8	raw_len;
	u8	fld_sz;

	/* The size below must include the padding to
	 * make the whole structure aligned to a
	 * multiple of 4 bytes
	 */
	char	loc_code[LOC_CODE_SIZE + 2]; /* 82 */

	/* We need to pack the structure otherwise the
	 * compiler adds additional alignment to make
	 * it 8 bytes aligned
	 */
} __packed;

/* Get indicator state request */
struct fsp_get_ind_state_req {
	__be16	size;
	u8	lc_len;
	u8	fld_sz;
	char	loc_code[LOC_CODE_SIZE];
} __packed;

/* Set indicator state request */
struct fsp_set_ind_state_req {
	__be16	size;
	__be16	req_type;
	u8	reserved[3];
	u8	ind_state;
	u8	lc_len;
	u8	fld_sz;
	char	loc_code[LOC_CODE_SIZE];
} __packed;

/* LED set SPCN command */
struct led_set_cmd {
	char	loc_code[LOC_CODE_SIZE];
	u8	command;
	u8	state;
	u16	ckpt_status;		/* Checkpointed status */
	u16	ckpt_excl_bit;		/* Checkpointed exclusive status */
	u64	async_token;		/* OPAL async token */
	enum	spcn_cmd_src cmd_src;	/* OPAL or FSP based */
	struct	list_node link;
};

/* System Attention Indicator */
struct sai_data {
	uint8_t	state;
	char	loc_code[LOC_CODE_SIZE];
};

/* LED commands and state */
#define LED_COMMAND_FAULT		1
#define LED_COMMAND_IDENTIFY		0
#define LED_STATE_ON			1
#define LED_STATE_OFF			0

/* FSP get loc-code list command request type */
#define	GET_LC_CMPLT_SYS		0x8000
#define	GET_LC_ENCLOSURES		0x4000
#define	GET_LC_ENCL_DESCENDANTS		0x2000
#define	GET_LC_SINGLE_LOC_CODE		0x0100

/* FSP set indicator command request type */
#define	SET_IND_ENCLOSURE		0x4000
#define	SET_IND_SINGLE_LOC_CODE		0x0001

/* Response buffer */
#define OUTBUF_HEADER_SIZE		8

/* LED miscellaneous */
#define LOC_CODE_LEN			1
#define LED_CONTROL_LEN			2
#define FSP_LC_STRUCT_FIXED_SZ		0x0a

/* LED Device tree property names */
#define DT_PROPERTY_LED_COMPATIBLE	"ibm,opal-v3-led"
#define DT_PROPERTY_LED_NODE		"leds"
#define DT_PROPERTY_LED_MODE		"led-mode"
#define DT_PROPERTY_LED_TYPES		"led-types"

/* LED Mode */
#define LED_MODE_LIGHT_PATH		"lightpath"
#define LED_MODE_GUIDING_LIGHT		"guidinglight"

/* LED type */
#define LED_TYPE_IDENTIFY		"identify"
#define LED_TYPE_FAULT			"fault"
#define LED_TYPE_ATTENTION		"attention"

#endif
