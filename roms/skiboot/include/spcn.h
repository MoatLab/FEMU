// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2016 IBM Corp. */

#ifndef __SPCN_H
#define __SPCN_H


/* SPCN commands */
#define SPCN_CMD_PRS			0x42 /* Power Resource Status */
#define SPCN_CMD_SET			0x66 /* Set Environmental Thresholds */

/* SPCN command address modes */
#define SPCN_ADDR_MODE_CEC_NODE		0x0000d000 /* CEC node single destination */
#define SPCN_ADDR_MODE_ALL_SLAVES	0x0000f000 /* Address all slaves in all racks */
#define SPCN_ADDR_MODE_RACK_NODES	0x00000000 /* Address rack node in all racks */

/* SPCN PRS command modifiers */
#define SPCN_MOD_PRS_STATUS_FIRST	0x01 /* Power Resource Status (First 1KB) */
#define SPCN_MOD_PRS_STATUS_SUBS	0x02 /* Subsequent set of 1KB PRS entries */
#define SPCN_MOD_PRS_LED_DATA_FIRST	0x51 /* LED data entry (First 1KB) */
#define SPCN_MOD_PRS_LED_DATA_SUB	0x52 /* Subsequent LED data entries */

/* SPCN SET command modifiers */
#define SPCN_MOD_SET_LED_CTL_LOC_CODE	0x07 /* Control LED with location code */
#define SPCN_MOD_SET_IDENTIFY_OFF_ENC	0x08 /* Turn off identify LEDs in CEC */
#define SPCN_MOD_SET_IDENTIFY_OFF_NODE	0x0B /* Turn off identify LEDs in Node */

/* SPCN SENSOR command modifiers */
#define SPCN_MOD_SENSOR_PARAM_FIRST	0x10 /* First 1K sensor parameters */
#define SPCN_MOD_SENSOR_PARAM_SUBS	0x11 /* Subsequent sensor parameters */
#define SPCN_MOD_SENSOR_DATA_FIRST	0x12 /* First 1K sensor data */
#define SPCN_MOD_SENSOR_DATA_SUBS	0x13 /* Subsequent sensor data blocks */
#define SPCN_MOD_PROC_JUNC_TEMP		0x14 /* Process junction temperatures */
#define SPCN_MOD_SENSOR_POWER		0x1c /* System power consumption */
#define SPCN_MOD_LAST			0xff

/*
 * Modifiers 0x53 and 0x54 are used by LEDS at standby. So HV does not come into
 * the picture here. Do we need those?
 */

/* Supported SPCN response codes */
#define LOGICAL_IND_STATE_MASK		0x10 /* If set, control fault state */
#define ACTIVE_LED_STATE_MASK		0x01 /* If set, switch on the LED */
#define SPCN_LED_IDENTIFY_MASK		0x80 /* Set identify indicator */
#define SPCN_LED_FAULT_MASK		0x40 /* Set fault indicator */
#define SPCN_LED_TRANS_MASK		0x20 /* LED is in transition */
#define SPCN_CLR_LED_STATE		0x00 /* Reset identify indicator */

/* SPCN command response status codes */
enum spcn_rsp_status {
	SPCN_RSP_STATUS_SUCCESS		= 0x01, /* Command successful */
	SPCN_RSP_STATUS_COND_SUCCESS	= 0x02, /* Command successful, but additional entries exist */
	SPCN_RSP_STATUS_INVALID_RACK	= 0x15, /* Invalid rack command */
	SPCN_RSP_STATUS_INVALID_SLAVE	= 0x16, /* Invalid slave command */
	SPCN_RSP_STATUS_INVALID_MOD	= 0x18, /* Invalid modifier */
	SPCN_RSP_STATUS_STATE_PROHIBIT	= 0x21, /* Present state prohibits */
	SPCN_RSP_STATUS_UNKNOWN		= 0xff, /* Default state */
};

/* Sensor FRCs (Frame resource class) */
enum {
	SENSOR_FRC_POWER_CTRL = 0x02,
	SENSOR_FRC_POWER_SUPPLY,
	SENSOR_FRC_REGULATOR,
	SENSOR_FRC_COOLING_FAN,
	SENSOR_FRC_COOLING_CTRL,
	SENSOR_FRC_BATTERY_CHRG,
	SENSOR_FRC_BATTERY_PACK,
	SENSOR_FRC_AMB_TEMP,
	SENSOR_FRC_TEMP,
	SENSOR_FRC_VRM,
	SENSOR_FRC_RISER_CARD,
	SENSOR_FRC_IO_BP,
};

/*
 * Common to all PRS modifiers (subcommands)
 */
struct sensor_header {
	__be16 frc;	/* Frame resource class */
	__be16 rid;	/* Resource ID */
} __packed;

/*
 * Data layout for PRS modifier PRS_STATUS 0x01, 0x02
 */
struct sensor_prs {
	struct sensor_header header;
	__be16 src;	/* unused */
	__be16 status;
} __packed;

#define PRS_STATUS_ON_SUPPORTED	0x0010
#define PRS_STATUS_ON		0x0008
#define PRS_STATUS_AC_FAULTED	0x0004
#define PRS_STATUS_FAULTED	0x0002
#define PRS_STATUS_PRESENT	0x0001

/*
 * Data layout for PRS modifier SENSOR_PARAM 0x10, 0x11
 */
struct sensor_param {
	struct sensor_header header;
	char location[4];
	char __reserved[4];
	__be16 threshold;
	__be16 status;
} __packed;

/*
 * Data layout for PRS modifier SENSOR_DATA 0x12, 0x13
 */
struct sensor_data {
	struct sensor_header header;
	__be16 data;
	__be16 status;
} __packed;

#define SENSOR_STATUS_EM_ALERT	0x0004
#define SENSOR_STATUS_FAULTED	0x0002
#define SENSOR_STATUS_PRESENT	0x0001

/* Power sensor is retrieved through a new PRS modifier 0x1C, data
 * response is as follows:
 *
 * Byte 0:
 *
 *	Bit 7: Data valid
 *	Bit 4-6: reserved
 *	Bit 0-3: Number of power supply or data records
 *
 * Each data record is 5 Bytes following above byte 0:
 *
 * Data Record: Byte 0: Power supply ID {00, 01, 02, 03, ...}
 *	     Byte 1-4: Power sensor value in milli-watts
 *
 * Example Power Sensor data: (Tuleta)
 * 84 00 00 00 00 00
 *    01 00 00 00 00
 *    02 00 02 5d 78
 *    03 00 02 0f 58
 *    00 00 00 00 00
 *
 * 0x84: Bit 7 is valid bit and there are 4 power supplies
 * 0x00 00 00 00 00
 *   |  ^^^^^^^^^^^ Power in milli-watts
 *   \-- Power supply ID
 *
 * Ox03 00 02 0f 58
 *   |  ^^^^^^^^^^^ Power in milli-watts (135000 mW)
 *   \-- Power supply ID
 */

#define POWER_SUPPLY_MAX 8

struct sensor_power_supply {
	uint8_t	rid;		/* Power supply ID */
	__be32 milliwatts;
} __packed;

struct sensor_power {
	uint8_t status;
	struct sensor_power_supply supplies[POWER_SUPPLY_MAX];
} __packed;

#define sensor_power_is_valid(s)	((s)->status & 0x80)
#define sensor_power_count(s)		((s)->status & 0x0f)


#endif /* __SPCN_H */
