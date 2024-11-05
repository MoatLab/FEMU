// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2018 IBM Corp. */

#define pr_fmt(fmt) "IPMI: " fmt
#include <ccan/list/list.h>
#include <ccan/str/str.h>
#include <compiler.h>
#include <errno.h>
#include <skiboot.h>
#include <stdlib.h>
#include <string.h>
#include <ipmi.h>
#include <device.h>
#include <opal.h>
#include <lock.h>
#include <errorlog.h>
#include <pel.h>
#include <opal-msg.h>
#include <debug_descriptor.h>
#include <occ.h>
#include <timebase.h>

/* OEM SEL fields */
#define SEL_OEM_ID_0		0x55
#define SEL_OEM_ID_1		0x55
#define SEL_RECORD_TYPE_OEM	0xC0
#define SEL_RECORD_TYPE_EVENT	0x02

#define SEL_NETFN_IBM		0x3a

/* OEM SEL Commands */
/* TODO: Move these to their respective source files */
#define CMD_AMI_POWER		0x04
#define CMD_AMI_PNOR_ACCESS	0x07
#define CMD_AMI_OCC_RESET	0x0e
#define CMD_HEARTBEAT		0xff

/* XXX: Listed here for completeness, registered in libflash/ipmi-flash.c */
#define CMD_OP_HIOMAP_EVENT	0x0f

#define SOFT_OFF	        0x00
#define SOFT_REBOOT	        0x01

#define RELEASE_PNOR		0x00
#define REQUEST_PNOR		0x01

/* 32.1 SEL Event Records type */
#define SEL_REC_TYPE_SYS_EVENT	0x02
#define SEL_REC_TYPE_AMI_ESEL	0xDF

/* OEM SEL generator ID for AMI */
#define SEL_GENERATOR_ID_AMI	0x0020

/* IPMI SEL version */
#define SEL_EVM_VER_1		0x03
#define SEL_EVM_VER_2		0x04

/*
 * Sensor type for System events
 *
 * Sensor information (type, number, etc) is passed to us via
 * device tree. Currently we are using System Event type to
 * log OPAL events.
 */
#define SENSOR_TYPE_SYS_EVENT	0x12

/*
 * 42.1 Event/Reading Type Codes
 *
 * Note that device hotplug and availability related events
 * are not defined as we are not using those events type.
 */
#define SEL_EVENT_DIR_TYPE_UNSPECIFIED	0x00
#define SEL_EVENT_DIR_TYPE_THRESHOLD	0x01
#define SEL_EVENT_DIR_TYPE_STATE	0x03
#define SEL_EVENT_DIR_TYPE_PREDICTIVE	0x04
#define SEL_EVENT_DIR_TYPE_LIMIT	0x05
#define SEL_EVENT_DIR_TYPE_PERFORMANCE	0x06
#define SEL_EVENT_DIR_TYPE_TRANSITION	0x07
#define SEL_EVENT_DIR_TYPE_OEM		0x70

/*
 * 42.1 Event/Reading Type Codes
 */
#define SEL_DATA1_AMI			0xAA
#define SEL_DATA1_DEASSERTED		0x00
#define SEL_DATA1_ASSERTED		0x01
#define SEL_DATA1_OK			0x00
#define SEL_DATA1_NON_CRIT_FROM_OK	0x01
#define SEL_DATA1_CRIT_FROM_LESS_SEV	0x02
#define SEL_DATA1_NON_REC_FROM_LESS_SEV	0x03
#define SEL_DATA1_NON_CRIT		0x04
#define SEL_DATA1_CRITICAL		0x05
#define SEL_DATA1_NON_RECOVERABLE	0X06
#define SEL_DATA1_MONITOR		0x07
#define SEL_DATA1_INFORMATIONAL		0x08

/* SEL Record Entry */
struct sel_record {
	le16		record_id;
	uint8_t		record_type;
	le32		timestamp;
	le16		generator_id;
	uint8_t		evm_ver;
	uint8_t		sensor_type;
	uint8_t		sensor_number;
	uint8_t		event_dir_type;
	uint8_t		event_data1;
	uint8_t		event_data2;
	uint8_t		event_data3;
} __packed;

static struct sel_record sel_record;

struct oem_sel {
	/* SEL header */
	uint8_t id[2];
	uint8_t type;
	uint8_t timestamp[4];
	uint8_t manuf_id[3];
	/* OEM SEL data (6 bytes) follows */
	uint8_t netfun;
	uint8_t cmd;
	uint8_t data[4];
};

#define ESEL_HDR_SIZE 7

/* Used for sending PANIC events like abort() path */
struct ipmi_sel_panic_msg {
	bool		busy;
	struct ipmi_msg	*msg;
	struct lock	lock;
};
static struct ipmi_sel_panic_msg ipmi_sel_panic_msg;

static LIST_HEAD(sel_handlers);

/* Forward declaration */
static void ipmi_elog_poll(struct ipmi_msg *msg);

/*
 * Allocate IPMI message:
 * For normal event, allocate memory using ipmi_mkmsg and for PANIC
 * event, use pre-allocated buffer.
 */
static struct ipmi_msg *ipmi_sel_alloc_msg(struct errorlog *elog_buf)
{
	struct ipmi_msg *msg = NULL;

	if (elog_buf->event_severity == OPAL_ERROR_PANIC) {
		/* Called before initialization completes */
		if (ipmi_sel_panic_msg.msg == NULL) {
			ipmi_sel_init();	/* Try to allocate IPMI message */
			if (ipmi_sel_panic_msg.msg == NULL)
				return NULL;
		}

		if (ipmi_sel_panic_msg.busy == true)
			return NULL;

		lock(&ipmi_sel_panic_msg.lock);
		msg = ipmi_sel_panic_msg.msg;
		ipmi_sel_panic_msg.busy = true;
		unlock(&ipmi_sel_panic_msg.lock);

		ipmi_init_msg(msg, IPMI_DEFAULT_INTERFACE, IPMI_RESERVE_SEL,
				ipmi_elog_poll, elog_buf, IPMI_MAX_REQ_SIZE, 2);
	} else {
		msg = ipmi_mkmsg(IPMI_DEFAULT_INTERFACE, IPMI_RESERVE_SEL,
				ipmi_elog_poll, elog_buf, NULL,
				IPMI_MAX_REQ_SIZE, 2);
	}

	return msg;
}

static void ipmi_sel_free_msg(struct ipmi_msg *msg)
{
	if (msg == ipmi_sel_panic_msg.msg) {
		lock(&ipmi_sel_panic_msg.lock);
		ipmi_sel_panic_msg.busy = false;
		unlock(&ipmi_sel_panic_msg.lock);
	} else {
		ipmi_free_msg(msg);
	}

	msg = NULL;
}

/* Initialize eSEL record */
static void ipmi_init_esel_record(void)
{
	memset(&sel_record, 0, sizeof(struct sel_record));
	sel_record.record_type = SEL_REC_TYPE_AMI_ESEL;
	sel_record.generator_id = cpu_to_le16(SEL_GENERATOR_ID_AMI);
	sel_record.evm_ver = SEL_EVM_VER_2;
	sel_record.sensor_type	= SENSOR_TYPE_SYS_EVENT;
	sel_record.sensor_number =
		ipmi_get_sensor_number(SENSOR_TYPE_SYS_EVENT);
	sel_record.event_dir_type = SEL_EVENT_DIR_TYPE_OEM;
	sel_record.event_data1 = SEL_DATA1_AMI;
}

/* Update required fields in SEL record */
static void ipmi_update_sel_record(uint8_t event_severity, uint16_t esel_record_id)
{
	sel_record.record_type = SEL_REC_TYPE_SYS_EVENT;
	sel_record.event_data2 = (esel_record_id >> 8) & 0xff;
	sel_record.event_data3 = esel_record_id & 0xff;

	switch (event_severity) {
	case OPAL_ERROR_PANIC:
		sel_record.event_dir_type = SEL_EVENT_DIR_TYPE_TRANSITION;
		sel_record.event_data1 = SEL_DATA1_CRITICAL;
		break;
	case OPAL_UNRECOVERABLE_ERR_GENERAL:	/* Fall through */
	case OPAL_UNRECOVERABLE_ERR_DEGRADE_PERF:
	case OPAL_UNRECOVERABLE_ERR_LOSS_REDUNDANCY:
	case OPAL_UNRECOVERABLE_ERR_LOSS_REDUNDANCY_PERF:
	case OPAL_UNRECOVERABLE_ERR_LOSS_OF_FUNCTION:
		sel_record.event_dir_type = SEL_EVENT_DIR_TYPE_TRANSITION;
		sel_record.event_data1 = SEL_DATA1_NON_RECOVERABLE;
		break;
	case OPAL_PREDICTIVE_ERR_GENERAL:	/* Fall through */
	case OPAL_PREDICTIVE_ERR_DEGRADED_PERF:
	case OPAL_PREDICTIVE_ERR_FAULT_RECTIFY_REBOOT:
	case OPAL_PREDICTIVE_ERR_FAULT_RECTIFY_BOOT_DEGRADE_PERF:
	case OPAL_PREDICTIVE_ERR_LOSS_OF_REDUNDANCY:
		sel_record.event_dir_type = SEL_EVENT_DIR_TYPE_PREDICTIVE;
		sel_record.event_data1 = SEL_DATA1_NON_CRIT_FROM_OK;
		break;
	case OPAL_RECOVERED_ERR_GENERAL:
		sel_record.event_dir_type = SEL_EVENT_DIR_TYPE_TRANSITION;
		sel_record.event_data1 = SEL_DATA1_OK;
		break;
	case OPAL_INFO:
		sel_record.event_dir_type = SEL_EVENT_DIR_TYPE_TRANSITION;
		sel_record.event_data1 = SEL_DATA1_INFORMATIONAL;
		break;
	default:
		sel_record.event_dir_type = SEL_EVENT_DIR_TYPE_STATE;
		sel_record.event_data1 = SEL_DATA1_ASSERTED;
		break;
	}
}

static void ipmi_elog_error(struct ipmi_msg *msg)
{
	if (msg->cc == IPMI_LOST_ARBITRATION_ERR)
		/* Retry due to SEL erase */
		ipmi_queue_msg(msg);
	else {
		opal_elog_complete(msg->user_data, false);
		ipmi_sel_free_msg(msg);
	}
}

static void ipmi_log_sel_event_error(struct ipmi_msg *msg)
{
	if (msg->cc != IPMI_CC_NO_ERROR)
		prlog(PR_INFO, "SEL: Failed to log SEL event\n");

	ipmi_sel_free_msg(msg);
}

static void ipmi_log_sel_event_complete(struct ipmi_msg *msg)
{
	prlog(PR_INFO, "SEL: New event logged [ID : %x%x]\n", msg->data[1],
		msg->data[0]);

	ipmi_sel_free_msg(msg);
}

/* Log SEL event with eSEL record ID */
static void ipmi_log_sel_event(struct ipmi_msg *msg, uint8_t event_severity,
				uint16_t esel_record_id)
{
	/* Fill required SEL event fields */
	ipmi_update_sel_record(event_severity, esel_record_id);

	/* Fill IPMI message */
	ipmi_init_msg(msg, IPMI_DEFAULT_INTERFACE, IPMI_ADD_SEL_EVENT,
		      ipmi_log_sel_event_complete, NULL,
		      sizeof(struct sel_record), 2);

	/* Copy SEL data */
	memcpy(msg->data, &sel_record, sizeof(struct sel_record));

	msg->error = ipmi_log_sel_event_error;
	ipmi_queue_msg_head(msg);
}

/* Goes through the required steps to add a complete eSEL:
 *
 *  1. Get a reservation
 *  2. Add eSEL header
 *  3. Partially add data to the SEL
 *
 * Because a reservation is needed we need to ensure eSEL's are added
 * as a single transaction as concurrent/interleaved adds would cancel
 * the reservation. We guarantee this by always adding our messages to
 * the head of the transmission queue, blocking any other messages
 * being sent until we have completed sending this message.
 *
 * There is still a very small chance that we will accidentally
 * interleave a message if there is another one waiting at the head of
 * the ipmi queue and another cpu calls the ipmi poller before we
 * complete. However this should just cause a resevation cancelled
 * error which we have to deal with anyway (eg. because there may be a
 * SEL erase in progress) so it shouldn't cause any problems.
 */
static void ipmi_elog_poll(struct ipmi_msg *msg)
{
	static bool first = false;
	static char pel_buf[IPMI_MAX_PEL_SIZE];
	static size_t pel_size;
	static size_t esel_size;
	static int esel_index = 0;
	int pel_index;
	static unsigned int reservation_id = 0;
	static unsigned int record_id = 0;
	struct errorlog *elog_buf = (struct errorlog *) msg->user_data;
	size_t req_size;

	if (bmc_platform->sw->ipmi_oem_partial_add_esel == 0) {
		prlog(PR_WARNING, "Dropped eSEL: BMC code is buggy/missing\n");
		ipmi_sel_free_msg(msg);
		return;
	}

	ipmi_init_esel_record();
	if (msg->cmd == IPMI_CMD(IPMI_RESERVE_SEL)) {
		first = true;
		reservation_id = msg->data[0];
		reservation_id |= msg->data[1] << 8;
		if (!reservation_id) {
			/*
			 * According to specification we should never
			 * get here, but just in case we do we cancel
			 * sending the message.
			 */
			prerror("Invalid reservation id");
			opal_elog_complete(elog_buf, false);
			ipmi_sel_free_msg(msg);
			return;
		}

		pel_size = create_pel_log(elog_buf, pel_buf, IPMI_MAX_PEL_SIZE);
		esel_size = pel_size + sizeof(struct sel_record);
		esel_index = 0;
		record_id = 0;
	} else {
		record_id = msg->data[0];
		record_id |= msg->data[1] << 8;
	}

	/* Start or continue the IPMI_PARTIAL_ADD_SEL */
	if (esel_index >= esel_size) {
		/*
		 * We're all done. Invalidate the resevation id to
		 * ensure we get an error if we cut in on another eSEL
		 * message.
		 */
		reservation_id = 0;
		esel_index = 0;

		/* Log SEL event and free ipmi message */
		ipmi_log_sel_event(msg, elog_buf->event_severity, record_id);

		opal_elog_complete(elog_buf, true);
		return;
	}

	if ((esel_size - esel_index) <= (IPMI_MAX_REQ_SIZE - ESEL_HDR_SIZE)) {
		/* Last data to send */
		msg->data[6] = 1;
		req_size = esel_size - esel_index + ESEL_HDR_SIZE;
	} else {
		msg->data[6] = 0;
		req_size = IPMI_MAX_REQ_SIZE;
	}

	ipmi_init_msg(msg, IPMI_DEFAULT_INTERFACE,
		      bmc_platform->sw->ipmi_oem_partial_add_esel,
		      ipmi_elog_poll, elog_buf, req_size, 2);

	msg->data[0] = reservation_id & 0xff;
	msg->data[1] = (reservation_id >> 8) & 0xff;
	msg->data[2] = record_id & 0xff;
	msg->data[3] = (record_id >> 8) & 0xff;
	msg->data[4] = esel_index & 0xff;
	msg->data[5] = (esel_index >> 8) & 0xff;

	if (first) {
		first = false;
		memcpy(&msg->data[ESEL_HDR_SIZE], &sel_record,
			sizeof(struct sel_record));
		esel_index = sizeof(struct sel_record);
		msg->req_size = esel_index + ESEL_HDR_SIZE;
	} else {
		pel_index = esel_index - sizeof(struct sel_record);
		memcpy(&msg->data[ESEL_HDR_SIZE], &pel_buf[pel_index],
			msg->req_size - ESEL_HDR_SIZE);
		esel_index += msg->req_size - ESEL_HDR_SIZE;
	}

	ipmi_queue_msg_head(msg);
	return;
}

int ipmi_elog_commit(struct errorlog *elog_buf)
{
	struct ipmi_msg *msg;

	/* Only log events that needs attention */
	if (elog_buf->event_severity <
			OPAL_PREDICTIVE_ERR_FAULT_RECTIFY_REBOOT ||
			elog_buf->elog_origin != ORG_SAPPHIRE) {
		prlog(PR_INFO, "dropping non severe PEL event\n");
		opal_elog_complete(elog_buf, true);
		return 0;
	}

	/*
	 * We pass a large request size in to mkmsg so that we have a
	 * large enough allocation to reuse the message to pass the
	 * PEL data via a series of partial add commands.
	 */
	msg = ipmi_sel_alloc_msg(elog_buf);
	if (!msg) {
		opal_elog_complete(elog_buf, false);
		return OPAL_RESOURCE;
	}

	msg->error = ipmi_elog_error;
	msg->req_size = 0;
	if (elog_buf->event_severity == OPAL_ERROR_PANIC) {
		ipmi_queue_msg_sync(msg);

		/*
		 * eSEL logs are split into multiple smaller chunks and sent
		 * to BMC. Lets wait until we finish sending all the chunks
		 * to BMC.
		 */
		while (ipmi_sel_panic_msg.busy != false) {
			if (msg->backend->poll)
				msg->backend->poll();
			time_wait_ms(10);
		}
	} else {
		ipmi_queue_msg(msg);
	}

	return 0;
}

#define ACCESS_DENIED	0x00
#define ACCESS_GRANTED	0x01

static void sel_pnor(uint8_t access, void *context __unused)
{
	struct ipmi_msg *msg;
	uint8_t granted = ACCESS_GRANTED;

	switch (access) {
	case REQUEST_PNOR:
		prlog(PR_NOTICE, "PNOR access requested\n");
		if (bmc_platform->sw->ipmi_oem_pnor_access_status == 0) {
			/**
			 * @fwts-label PNORAccessYeahButNoBut
			 * @fwts-advice OPAL doesn't know that the BMC supports
			 * PNOR access commands. This will be a bug in the OPAL
			 * support for this BMC.
			 */
			prlog(PR_ERR, "PNOR BUG: access requested but BMC doesn't support request\n");
			break;
		}

		granted = flash_reserve();
		if (granted)
			occ_pnor_set_owner(PNOR_OWNER_EXTERNAL);
		/* Ack the request */
		msg = ipmi_mkmsg_simple(bmc_platform->sw->ipmi_oem_pnor_access_status, &granted, 1);
		ipmi_queue_msg(msg);
		break;
	case RELEASE_PNOR:
		prlog(PR_NOTICE, "PNOR access released\n");
		flash_release();
		occ_pnor_set_owner(PNOR_OWNER_HOST);
		break;
	default:
		/**
		 * @fwts-label InvalidPNORAccessRequest
		 * @fwts-advice In negotiating PNOR access with BMC, we
		 * got an odd/invalid request from the BMC. Likely a bug
		 * in OPAL/BMC interaction.
		 */
		prlog(PR_ERR, "invalid PNOR access requested: %02x\n",
		      access);
	}
}

static void sel_power(uint8_t power, void *context __unused)
{
	switch (power) {
	case SOFT_OFF:
		prlog(PR_NOTICE, "Soft shutdown requested\n");
		if (opal_booting() && platform.cec_power_down) {
			prlog(PR_NOTICE, "Host not up, shutting down now\n");
			platform.cec_power_down(IPMI_CHASSIS_PWR_DOWN);
		} else {
			opal_queue_msg(OPAL_MSG_SHUTDOWN, NULL, NULL,
					cpu_to_be64(SOFT_OFF));
		}

		break;
	case SOFT_REBOOT:
		prlog(PR_NOTICE, "Soft reboot requested\n");
		if (opal_booting() && platform.cec_reboot) {
			prlog(PR_NOTICE, "Host not up, rebooting now\n");
			platform.cec_reboot();
		} else {
			opal_queue_msg(OPAL_MSG_SHUTDOWN, NULL, NULL,
					cpu_to_be64(SOFT_REBOOT));
		}

		break;
	default:
		prlog(PR_WARNING, "requested bad power state: %02x\n",
		      power);
	}
}

static void sel_heartbeat(uint8_t heartbeat, void *context __unused)
{
	/* There is only one sub-command so no processing needed */
	prlog(PR_DEBUG, "BMC issued heartbeat command: %02x\n",
	      heartbeat);
}

static uint32_t occ_sensor_id_to_chip(uint8_t sensor, uint32_t *chip)
{
	struct dt_node *node, *bmc_node, *sensors_node;

	/* Default chip id */
	*chip = 0;

	bmc_node = dt_find_by_name(dt_root, "bmc");
	if (!bmc_node)
		return 0;

	sensors_node = dt_find_by_name(bmc_node, "sensors");
	if (!sensors_node)
		return 0;

	node = dt_find_by_name_addr(sensors_node, "sensor", sensor);
	if (!node) {
		prlog(PR_DEBUG, "Could not find OCC sensor node. Id : %d\n",
		      (u32)sensor);
		return 0;
	}

	if (!dt_has_node_property(node, "ibm,chip-id", NULL)) {
		prlog(PR_DEBUG, "Could not find chip-id for OCC sensor : %d\n",
		      (u32)sensor);
		return 0;
	}

	*chip = dt_get_chip_id(node);
	return 0;
}

static void sel_occ_reset(uint8_t sensor, void *context __unused)
{
	uint32_t chip;
	int rc;

	rc = occ_sensor_id_to_chip(sensor, &chip);
	if (rc) {
		/**
		 * @fwts-label: SELUnknownOCCReset
		 * @fwts-advice: Likely bug in what sent us the OCC reset.
		 */
		prlog(PR_ERR, "SEL message to reset an unknown OCC "
				"(sensor ID 0x%02x)\n", sensor);
		return;
	}

	prd_occ_reset(chip);
}

struct ipmi_sel_handler {
	uint8_t oem_cmd;
	void (*fn)(uint8_t data, void *context);
	void *context;
	struct list_node node;
};

int ipmi_sel_register(uint8_t oem_cmd,
		      void (*fn)(uint8_t data, void *context),
		      void *context)
{
	struct ipmi_sel_handler *handler;

	list_for_each(&sel_handlers, handler, node) {
		if (handler->oem_cmd == oem_cmd) {
			prerror("Handler for SEL command 0x%02x already registered\n",
				oem_cmd);
			return -EINVAL;
		}
	}

	handler = malloc(sizeof(*handler));
	if (!handler)
		return -ENOMEM;

	handler->oem_cmd = oem_cmd;
	handler->fn = fn;
	handler->context = context;

	list_add(&sel_handlers, &handler->node);

	return 0;
}

void ipmi_sel_init(void)
{
	int rc;

	/* Already done */
	if (ipmi_sel_panic_msg.msg != NULL)
		return;

	memset(&ipmi_sel_panic_msg, 0, sizeof(struct ipmi_sel_panic_msg));
	ipmi_sel_panic_msg.msg = ipmi_mkmsg(IPMI_DEFAULT_INTERFACE,
					IPMI_RESERVE_SEL, ipmi_elog_poll,
					NULL, NULL, IPMI_MAX_REQ_SIZE, 2);

	/* Hackishly register these old-style handlers here for now */
	/* TODO: Move them to their appropriate source files */
	rc = ipmi_sel_register(CMD_AMI_POWER, sel_power, NULL);
	if (rc < 0) {
		prerror("Failed to register SEL handler for %s",
			stringify(CMD_AMI_POWER));
	}

	rc = ipmi_sel_register(CMD_AMI_OCC_RESET, sel_occ_reset, NULL);
	if (rc < 0) {
		prerror("Failed to register SEL handler for %s",
			stringify(CMD_AMI_OCC_RESET));
	}

	rc = ipmi_sel_register(CMD_AMI_PNOR_ACCESS, sel_pnor, NULL);
	if (rc < 0) {
		prerror("Failed to register SEL handler for %s",
			stringify(CMD_AMI_PNOR_ACCESS));
	}

	rc = ipmi_sel_register(CMD_HEARTBEAT, sel_heartbeat, NULL);
	if (rc < 0) {
		prerror("Failed to register SEL handler for %s",
			stringify(CMD_HEARTBEAT));
	}
}

void ipmi_parse_sel(struct ipmi_msg *msg)
{
	struct ipmi_sel_handler *handler;
	struct oem_sel sel;

	assert(msg->resp_size <= 16);

	memcpy(&sel, msg->data, msg->resp_size);

	/* We do not process system event records */
	if (sel.type == SEL_RECORD_TYPE_EVENT) {
		prlog(PR_INFO, "dropping System Event Record SEL\n");
		return;
	}

	prlog(PR_DEBUG, "SEL received (%d bytes, netfn %d, cmd %d)\n",
			msg->resp_size, sel.netfun, sel.cmd);

	/* Only accept OEM SEL messages */
	if (sel.id[0] != SEL_OEM_ID_0 || sel.id[1] != SEL_OEM_ID_1 ||
		sel.type != SEL_RECORD_TYPE_OEM) {
		prlog(PR_WARNING, "unknown SEL %02x%02x (type %02x)\n",
		      sel.id[0], sel.id[1], sel.type);
		return;
	}

	list_for_each(&sel_handlers, handler, node) {
		if (handler->oem_cmd == sel.cmd) {
			handler->fn(sel.data[0], handler->context);
			return;
		}
	}

	prlog(PR_WARNING, "unknown OEM SEL command %02x received\n", sel.cmd);
}
