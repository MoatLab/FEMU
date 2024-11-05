// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * This code will enable the 'powernv' to retrieve sensor related data from FSP
 * using SPCN passthru mailbox commands.
 *
 * The OPAL read sensor API in Sapphire is implemented as an 'asynchronous' read
 * call that returns after queuing the read request. A unique sensor-id is
 * expected as an argument for OPAL read call which has already been exported
 * to the device tree during fsp init. The sapphire code decodes this Id to
 * determine requested attribute and sensor.
 *
 * Copyright 2013-2017 IBM Corp.
 */

#include <skiboot.h>
#include <fsp.h>
#include <lock.h>
#include <device.h>
#include <spcn.h>
#include <opal-api.h>
#include <opal-msg.h>
#include <errorlog.h>
#include <sensor.h>

#define INVALID_DATA	((uint32_t)-1)

/* Entry size of PRS command modifiers */
#define PRS_STATUS_ENTRY_SZ	0x08
#define SENSOR_PARAM_ENTRY_SZ	0x10
#define SENSOR_DATA_ENTRY_SZ	0x08
#define PROC_JUNC_ENTRY_SZ	0x04

DEFINE_LOG_ENTRY(OPAL_RC_SENSOR_INIT, OPAL_PLATFORM_ERR_EVT, OPAL_SENSOR,
			OPAL_MISC_SUBSYSTEM,
			OPAL_PREDICTIVE_ERR_FAULT_RECTIFY_REBOOT,
			OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_SENSOR_READ, OPAL_PLATFORM_ERR_EVT, OPAL_SENSOR,
			OPAL_MISC_SUBSYSTEM, OPAL_INFO,
			OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_SENSOR_ASYNC_COMPLETE, OPAL_PLATFORM_ERR_EVT,
			OPAL_SENSOR, OPAL_MISC_SUBSYSTEM, OPAL_INFO,
			OPAL_NA);

/* FSP response status codes */
enum {
	SP_RSP_STATUS_VALID_DATA = 0x00,
	SP_RSP_STATUS_INVALID_DATA = 0x22,
	SP_RSP_STATUS_SPCN_ERR = 0xA8,
	SP_RSP_STATUS_DMA_ERR = 0x24,
};

enum sensor_state {
	SENSOR_VALID_DATA,
	SENSOR_INVALID_DATA,
	SENSOR_SPCN_ERROR,
	SENSOR_DMA_ERROR,
	SENSOR_PERMANENT_ERROR,
	SENSOR_OPAL_ERROR,
};

enum spcn_attr {
	SENSOR_STATUS,
	SENSOR_THRS,
	SENSOR_DATA,
	SENSOR_MAX,
};

/* Parsed sensor attributes, passed through OPAL */
struct opal_sensor_data {
	uint64_t	async_token;	/* Asynchronous token */
	__be64		*sensor_data;	/* Kernel pointer to copy data */
	enum spcn_attr	spcn_attr;	/* Modifier attribute */
	uint16_t	rid;		/* Sensor RID */
	uint8_t		frc;		/* Sensor resource class */
	uint32_t	mod_index;	/* Modifier index*/
	uint32_t	offset;		/* Offset in sensor buffer */
};

struct spcn_mod {
	uint8_t mod;		/* Modifier code */
	uint8_t entry_size;	/* Size of each entry in response buffer */
	uint16_t entry_count;	/* Number of entries */
};

static struct spcn_mod spcn_mod_data[] = {
		{SPCN_MOD_PRS_STATUS_FIRST, PRS_STATUS_ENTRY_SZ, 0 },
		{SPCN_MOD_PRS_STATUS_SUBS, PRS_STATUS_ENTRY_SZ, 0 },
		{SPCN_MOD_SENSOR_PARAM_FIRST, SENSOR_PARAM_ENTRY_SZ, 0 },
		{SPCN_MOD_SENSOR_PARAM_SUBS, SENSOR_PARAM_ENTRY_SZ, 0 },
		{SPCN_MOD_SENSOR_DATA_FIRST, SENSOR_DATA_ENTRY_SZ, 0 },
		{SPCN_MOD_SENSOR_DATA_SUBS, SENSOR_DATA_ENTRY_SZ, 0 },
		/* TODO Support this modifier '0x14', if required */
		/* {SPCN_MOD_PROC_JUNC_TEMP, PROC_JUNC_ENTRY_SZ, 0, NULL}, */
		{SPCN_MOD_SENSOR_POWER, SENSOR_DATA_ENTRY_SZ, 0 },
		{SPCN_MOD_LAST, 0xff, 0xffff}
};

/* Frame resource class (FRC) names */
static const char *frc_names[] = {
		/* 0x00 and 0x01 are reserved */
		NULL,
		NULL,
		"power-controller",
		"power",
		"regulator",
		"cooling-fan",
		"cooling-controller",
		"battery-charger",
		"battery-pack",
		"amb-temp",
		"temp",
		"vrm",
		"riser-card",
		"io-backplane"
};

#define SENSOR_MAX_SIZE		0x00100000
static void *sensor_buffer = NULL;
static enum sensor_state sensor_state;
static bool prev_msg_consumed = true;
static struct lock sensor_lock;

/* Function prototypes */
static int64_t fsp_sensor_send_read_request(struct opal_sensor_data *attr);
static void queue_msg_for_delivery(int rc, struct opal_sensor_data *attr);


/*
 * Power Resource Status (PRS)
 * Command: 0x42
 *
 * Modifier: 0x01
 * --------------------------------------------------------------------------
 * |    0        1         2      3         4        5         6        7   |
 * --------------------------------------------------------------------------
 * |Frame resrc class|      PRID       |      SRC        |       Status     |
 * --------------------------------------------------------------------------
 *
 *
 * Modifier: 0x10
 * --------------------------------------------------------------------------
 * |    0        1         2      3         4        5         6        7   |
 * --------------------------------------------------------------------------
 * |Frame resrc class|      PRID       |            Sensor location         |
 * --------------------------------------------------------------------------
 * --------------------------------------------------------------------------
 * |    8        9         10      11         12   13          14    15     |
 * --------------------------------------------------------------------------
 * |    Reserved     |   Reserved      |   Threshold     |       Status     |
 * --------------------------------------------------------------------------
 *
 *
 * Modifier: 0x12
 * --------------------------------------------------------------------------
 * |    0        1         2      3         4        5         6        7   |
 * --------------------------------------------------------------------------
 * |Frame resrc class|      PRID      |   Sensor data    |       Status     |
 * --------------------------------------------------------------------------
 *
 *
 * Modifier: 0x14
 * --------------------------------------------------------------------------
 * |       0                 1                2                   3         |
 * --------------------------------------------------------------------------
 * |Enclosure Tj Avg | Chip Tj Avg    |    Reserved      |     Reserved     |
 * --------------------------------------------------------------------------
 */


/*
 * When coming from a SENSOR_POWER modifier command, the resource id
 * of a power supply is on one byte and misses a "subclass" byte
 * (0x10). This routine adds it to be consistent with the PRS_STATUS
 * modifier command.
 */
#define normalize_power_rid(rid) (0x1000|(rid))

static uint32_t sensor_power_process_data(uint16_t rid,
					struct sensor_power *power)
{
	int i;

	if (!sensor_power_is_valid(power)) {
		prlog(PR_TRACE, "Power Sensor data not valid\n");
		return INVALID_DATA;
	}

	for (i = 0; i < sensor_power_count(power); i++) {
		prlog(PR_TRACE, "Power[%d]: %d mW\n", i,
		      power->supplies[i].milliwatts);
		if (rid == normalize_power_rid(power->supplies[i].rid))
			return be32_to_cpu(power->supplies[i].milliwatts) / 1000;
	}

	return 0;
}

static inline uint16_t convert_status_to_fault(uint16_t status)
{
	return status & 0x06;
}

static void fsp_sensor_process_data(struct opal_sensor_data *attr)
{
	uint8_t *sensor_buf_ptr = (uint8_t *)sensor_buffer;
	uint32_t sensor_data = INVALID_DATA;
	__be16 sensor_mod_data[8];
	int count;

	for (count = 0; count < spcn_mod_data[attr->mod_index].entry_count;
			count++) {
		memcpy((void *)sensor_mod_data, sensor_buf_ptr,
				spcn_mod_data[attr->mod_index].entry_size);
		if (spcn_mod_data[attr->mod_index].mod == SPCN_MOD_PROC_JUNC_TEMP) {
			/* TODO Support this modifier '0x14', if required */

		} else if (spcn_mod_data[attr->mod_index].mod == SPCN_MOD_SENSOR_POWER) {
			sensor_data = sensor_power_process_data(attr->rid,
					(struct sensor_power *) sensor_buf_ptr);
			break;
		} else if (be16_to_cpu(sensor_mod_data[0]) == attr->frc &&
				be16_to_cpu(sensor_mod_data[1]) == attr->rid) {
			switch (attr->spcn_attr) {
			case SENSOR_STATUS:
				sensor_data =
					convert_status_to_fault(be16_to_cpu(sensor_mod_data[3]));
				break;
			case SENSOR_THRS:
				sensor_data = be16_to_cpu(sensor_mod_data[6]);
				break;
			case SENSOR_DATA:
				sensor_data = be16_to_cpu(sensor_mod_data[2]);
				break;
			default:
				break;
			}

			break;
		}

		sensor_buf_ptr += spcn_mod_data[attr->mod_index].entry_size;
	}

	*attr->sensor_data = cpu_to_be64(sensor_data);
	if (sensor_data == INVALID_DATA)
		queue_msg_for_delivery(OPAL_PARTIAL, attr);
	else
		queue_msg_for_delivery(OPAL_SUCCESS, attr);
}

static int fsp_sensor_process_read(struct fsp_msg *resp_msg)
{
	uint8_t mbx_rsp_status;
	uint32_t size = 0;

	mbx_rsp_status = (resp_msg->word1 >> 8) & 0xff;
	switch (mbx_rsp_status) {
	case SP_RSP_STATUS_VALID_DATA:
		sensor_state = SENSOR_VALID_DATA;
		size = fsp_msg_get_data_word(resp_msg, 1) & 0xffff;
		break;
	case SP_RSP_STATUS_INVALID_DATA:
		log_simple_error(&e_info(OPAL_RC_SENSOR_READ),
			"SENSOR: %s: Received invalid data\n", __func__);
		sensor_state = SENSOR_INVALID_DATA;
		break;
	case SP_RSP_STATUS_SPCN_ERR:
		log_simple_error(&e_info(OPAL_RC_SENSOR_READ),
			"SENSOR: %s: Failure due to SPCN error\n", __func__);
		sensor_state = SENSOR_SPCN_ERROR;
		break;
	case SP_RSP_STATUS_DMA_ERR:
		log_simple_error(&e_info(OPAL_RC_SENSOR_READ),
			"SENSOR: %s: Failure due to DMA error\n", __func__);
		sensor_state = SENSOR_DMA_ERROR;
		break;
	default:
		log_simple_error(&e_info(OPAL_RC_SENSOR_READ),
			"SENSOR %s: Read failed, status:0x%02X\n",
					__func__, mbx_rsp_status);
		sensor_state = SENSOR_INVALID_DATA;
		break;
	}

	return size;
}

static void queue_msg_for_delivery(int rc, struct opal_sensor_data *attr)
{
	prlog(PR_INSANE, "%s: rc:%d, data:%lld\n",
	      __func__, rc, *(attr->sensor_data));
	check_sensor_read(attr->async_token);
	opal_queue_msg(OPAL_MSG_ASYNC_COMP, NULL, NULL,
			cpu_to_be64(attr->async_token),
			cpu_to_be64(rc));
	spcn_mod_data[attr->mod_index].entry_count = 0;
	free(attr);
	prev_msg_consumed = true;
}

static void fsp_sensor_read_complete(struct fsp_msg *msg)
{
	struct opal_sensor_data *attr = msg->user_data;
	enum spcn_rsp_status status;
	int rc, size;

	prlog(PR_INSANE, "%s()\n", __func__);

	status = (fsp_msg_get_data_word(msg->resp, 1) >> 24) & 0xff;
	size = fsp_sensor_process_read(msg->resp);
	fsp_freemsg(msg);

	lock(&sensor_lock);
	if (sensor_state == SENSOR_VALID_DATA) {
		spcn_mod_data[attr->mod_index].entry_count += (size /
				spcn_mod_data[attr->mod_index].entry_size);
		attr->offset += size;
		/* Fetch the subsequent entries of the same modifier type */
		if (status == SPCN_RSP_STATUS_COND_SUCCESS) {
			switch (spcn_mod_data[attr->mod_index].mod) {
			case SPCN_MOD_PRS_STATUS_FIRST:
			case SPCN_MOD_SENSOR_PARAM_FIRST:
			case SPCN_MOD_SENSOR_DATA_FIRST:
				attr->mod_index++;
				spcn_mod_data[attr->mod_index].entry_count =
						spcn_mod_data[attr->mod_index - 1].
						entry_count;
				spcn_mod_data[attr->mod_index - 1].entry_count = 0;
				break;
			default:
				break;
			}

			rc = fsp_sensor_send_read_request(attr);
			if (rc != OPAL_ASYNC_COMPLETION)
				goto err;
		} else { /* Notify 'powernv' of read completion */
			fsp_sensor_process_data(attr);
		}
	} else {
		rc = OPAL_INTERNAL_ERROR;
		goto err;
	}
	unlock(&sensor_lock);
	return;
err:
	*attr->sensor_data = cpu_to_be64(INVALID_DATA);
	queue_msg_for_delivery(rc, attr);
	unlock(&sensor_lock);
	log_simple_error(&e_info(OPAL_RC_SENSOR_ASYNC_COMPLETE),
		"SENSOR: %s: Failed to queue the "
		"read request to fsp\n", __func__);
}

static int64_t fsp_sensor_send_read_request(struct opal_sensor_data *attr)
{
	int rc;
	struct fsp_msg *msg;
	uint32_t align;
	uint32_t cmd_header;

	if (fsp_in_rr())
		return OPAL_BUSY;

	prlog(PR_INSANE, "Get the data for modifier [%x]\n",
	      spcn_mod_data[attr->mod_index].mod);

	if (spcn_mod_data[attr->mod_index].mod == SPCN_MOD_PROC_JUNC_TEMP) {
		/* TODO Support this modifier '0x14', if required */
		align = attr->offset % sizeof(uint32_t);
		if (align)
			attr->offset += (sizeof(uint32_t) - align);

		/* TODO Add 8 byte command data required for mod 0x14 */

		attr->offset += 8;

		cmd_header = spcn_mod_data[attr->mod_index].mod << 24 |
				SPCN_CMD_PRS << 16 | 0x0008;
	} else {
		cmd_header = spcn_mod_data[attr->mod_index].mod << 24 |
				SPCN_CMD_PRS << 16;
	}

	msg = fsp_mkmsg(FSP_CMD_SPCN_PASSTHRU, 4,
			SPCN_ADDR_MODE_CEC_NODE, cmd_header, 0,
			PSI_DMA_SENSOR_BUF + attr->offset);

	if (!msg) {
		log_simple_error(&e_info(OPAL_RC_SENSOR_READ), "SENSOR: Failed "
				 "to allocate read message\n");
		return OPAL_INTERNAL_ERROR;
	}

	msg->user_data = attr;
	rc = fsp_queue_msg(msg, fsp_sensor_read_complete);
	if (rc) {
		fsp_freemsg(msg);
		msg = NULL;
		log_simple_error(&e_info(OPAL_RC_SENSOR_READ), "SENSOR: Failed "
				 "to queue read message (%d)\n", rc);
		return OPAL_INTERNAL_ERROR;
	}

	return OPAL_ASYNC_COMPLETION;
}

/*
 * These are the resources we know about and for which we provide a
 * mapping in the device tree to capture data from the OS. Just
 * discard the other ones for the moment.
 */
static inline bool sensor_frc_is_valid(uint16_t frc)
{
	switch (frc) {
	case SENSOR_FRC_POWER_SUPPLY:
	case SENSOR_FRC_COOLING_FAN:
	case SENSOR_FRC_AMB_TEMP:
		return true;
	default:
		return false;
	}
}

/*
 * Each attribute of a resource needs a request to the FSP to capture
 * its data. The routine below provides the mapping between the
 * attribute and the PRS command modifier to use.
 *
 *	resource        | data   |  thrs  | status    |
 *	----------------+--------+--------+-----------+
 *	power_supply    | POWER  |        |           |
 *	                |        |        | PRS       |
 *	----------------+--------+--------+-----------+
 *	amb-temp        | DATA   |        | DATA      |
 *	                |        | PARAM  | PARAM (*) |
 *	----------------+--------+--------+-----------+
 *	fan             | DATA   |        | DATA  (*) |
 *	                |        | PARAM  | PARAM (*) |
 *	                |        |        | PRS       |
 *
 * (*) don't use the attribute given by this command modifier
 */
static int64_t parse_sensor_id(uint32_t handler, struct opal_sensor_data *attr)
{
	uint32_t mod, index;

	attr->frc = sensor_get_frc(handler);
	attr->rid = sensor_get_rid(handler);
	attr->spcn_attr = sensor_get_attr(handler);

	if (!sensor_frc_is_valid(attr->frc))
		return OPAL_PARAMETER;

	/* now compute the PRS command modifier which will be used to
	 * request a resource attribute from the FSP */
	switch (attr->spcn_attr) {
	case SENSOR_DATA:
		if (attr->frc == SENSOR_FRC_POWER_SUPPLY)
			mod = SPCN_MOD_SENSOR_POWER;
		else
			mod = SPCN_MOD_SENSOR_DATA_FIRST;
		break;

	case SENSOR_THRS:
		mod = SPCN_MOD_SENSOR_PARAM_FIRST;
		break;

	case SENSOR_STATUS:
		switch (attr->frc) {
		case SENSOR_FRC_AMB_TEMP:
			mod = SPCN_MOD_SENSOR_DATA_FIRST;
			break;
		case SENSOR_FRC_POWER_SUPPLY:
		case SENSOR_FRC_COOLING_FAN:
			mod = SPCN_MOD_PRS_STATUS_FIRST;
			break;
		default:
			return OPAL_PARAMETER;
		}
		break;

	default:
		return OPAL_PARAMETER;
	}

	for (index = 0; spcn_mod_data[index].mod != SPCN_MOD_LAST; index++) {
		if (spcn_mod_data[index].mod == mod)
			break;
	}

	attr->mod_index = index;
	return 0;
}


int64_t fsp_opal_read_sensor(uint32_t sensor_hndl, int token,
				__be64 *sensor_data)
{
	struct opal_sensor_data *attr;
	int64_t rc;

	prlog(PR_INSANE, "fsp_opal_read_sensor [%08x]\n", sensor_hndl);

	if (fsp_in_rr())
		return OPAL_BUSY;

	if (sensor_state == SENSOR_PERMANENT_ERROR) {
		rc = OPAL_HARDWARE;
		goto out;
	}

	if (!sensor_hndl) {
		rc = OPAL_PARAMETER;
		goto out;
	}

	lock(&sensor_lock);
	if (prev_msg_consumed) {
		attr = zalloc(sizeof(*attr));
		if (!attr) {
			log_simple_error(&e_info(OPAL_RC_SENSOR_READ),
				"SENSOR: Failed to allocate memory\n");
			rc = OPAL_NO_MEM;
			goto out_lock;
		}

		/* Parse the sensor id and store them to the local structure */
		rc = parse_sensor_id(sensor_hndl, attr);
		if (rc) {
			log_simple_error(&e_info(OPAL_RC_SENSOR_READ),
				"SENSOR: %s: Failed to parse the sensor "
				"handle[0x%08x]\n", __func__, sensor_hndl);
			goto out_free;
		}
		/* Kernel buffer pointer to copy the data later when ready */
		attr->sensor_data = sensor_data;
		attr->async_token = token;

		rc = fsp_sensor_send_read_request(attr);
		if (rc != OPAL_ASYNC_COMPLETION) {
			log_simple_error(&e_info(OPAL_RC_SENSOR_READ),
				"SENSOR: %s: Failed to queue the read "
					"request to fsp\n", __func__);
			goto out_free;
		}

		prev_msg_consumed = false;
	} else {
		rc = OPAL_BUSY_EVENT;
	}

	unlock(&sensor_lock);
	return rc;

out_free:
	free(attr);
out_lock:
	unlock(&sensor_lock);
out:
	return rc;
}


#define MAX_NAME	64

static struct dt_node *sensor_get_node(struct dt_node *sensors,
		       struct sensor_header *header, const char* attrname)
{
	char name[MAX_NAME];
	struct dt_node *node;

	/*
	 * Just use the resource class name and resource id. This
	 * should be obvious enough for a node name.
	 */
	snprintf(name, sizeof(name), "%s#%d-%s", frc_names[be16_to_cpu(header->frc)], be16_to_cpu(header->rid), attrname);

	/*
	 * The same resources are reported by the different PRS
	 * subcommands (PRS_STATUS, SENSOR_PARAM, SENSOR_DATA). So we
	 * need to check that we did not already create the device
	 * node.
	 */
	node = dt_find_by_path(sensors, name);
	if (!node) {
		prlog(PR_INFO, "SENSOR: creating node %s\n", name);

		node = dt_new(sensors, name);

		snprintf(name, sizeof(name), "ibm,opal-sensor-%s",
			 frc_names[be16_to_cpu(header->frc)]);
		dt_add_property_string(node, "compatible", name);
	} else {
		/**
		 * @fwts-label OPALSensorNodeExists
		 * @fwts-advice OPAL had trouble creating the sensor
		 * nodes in the device tree as there was already one there.
		 * This indicates either the device tree from Hostboot
		 * already filled in sensors or an OPAL bug.
		 */
		prlog(PR_ERR, "SENSOR: node %s exists\n", name);
	}
	return node;
}

#define sensor_handler(header, attr_num) \
	sensor_make_handler(SENSOR_FSP, be16_to_cpu((header).frc), be16_to_cpu((header).rid), attr_num)

static int add_sensor_prs(struct dt_node *sensors, struct sensor_prs *prs)
{
	struct dt_node *node;

	node = sensor_get_node(sensors, &prs->header, "faulted");
	if (!node)
		return -1;

	dt_add_property_cells(node, "sensor-id",
			      sensor_handler(prs->header, SENSOR_STATUS));
	return 0;
}

static int add_sensor_param(struct dt_node *sensors, struct sensor_param *param)
{
	struct dt_node *node;

	node = sensor_get_node(sensors, &param->header, "thrs");
	if (!node)
		return -1;

	dt_add_property_string(node, "ibm,loc-code", param->location);
	dt_add_property_cells(node, "sensor-id",
			      sensor_handler(param->header, SENSOR_THRS));
	/* don't use the status coming from the response of the
	 * SENSOR_PARAM subcommand */
	return 0;
}

static int add_sensor_data(struct dt_node *sensors,
				struct sensor_data *data)
{
	struct dt_node *node;

	node = sensor_get_node(sensors, &data->header, "data");
	if (!node)
		return -1;

	dt_add_property_cells(node, "sensor-id",
			      sensor_handler(data->header, SENSOR_DATA));

	/* Let's make sure we are not adding a duplicate device node.
	 * Some resource, like fans, get their status attribute from
	 * three different commands ...
	 */
	if (be16_to_cpu(data->header.frc) == SENSOR_FRC_AMB_TEMP) {
		node = sensor_get_node(sensors, &data->header, "faulted");
		if (!node)
			return -1;

		dt_add_property_cells(node, "sensor-id",
				      sensor_handler(data->header, SENSOR_STATUS));
	}

	return 0;
}

static int add_sensor_power(struct dt_node *sensors, struct sensor_power *power)
{
	int i;
	struct dt_node *node;

	if (!sensor_power_is_valid(power))
		return -1;

	for (i = 0; i < sensor_power_count(power); i++) {
		struct sensor_header header = {
			cpu_to_be16(SENSOR_FRC_POWER_SUPPLY),
			cpu_to_be16(normalize_power_rid(power->supplies[i].rid))
		};

		node = sensor_get_node(sensors, &header, "data");

		prlog(PR_TRACE, "SENSOR: Power[%d] : %d mW\n",
		      power->supplies[i].rid,
		      be32_to_cpu(power->supplies[i].milliwatts));

		dt_add_property_cells(node, "sensor-id",
				      sensor_handler(header, SENSOR_DATA));
	}
	return 0;
}

static void add_sensor_ids(struct dt_node *sensors)
{
	uint8_t *sensor_buf_ptr = (uint8_t *)sensor_buffer;
	struct spcn_mod *smod;
	int i;

	for (smod = spcn_mod_data; smod->mod != SPCN_MOD_LAST; smod++) {
		/*
		 * SPCN_MOD_SENSOR_POWER (0x1C) has a different layout.
		 */
		if (smod->mod == SPCN_MOD_SENSOR_POWER) {
			add_sensor_power(sensors,
				      (struct sensor_power *) sensor_buf_ptr);

			sensor_buf_ptr += smod->entry_size * smod->entry_count;
			continue;
		}

		for (i = 0; i < smod->entry_count; i++) {
			struct sensor_header *header =
				(struct sensor_header *) sensor_buf_ptr;

			if (!sensor_frc_is_valid(be16_to_cpu(header->frc)))
				goto out_sensor;

			switch (smod->mod) {
			case SPCN_MOD_PROC_JUNC_TEMP:
				/* TODO Support this modifier '0x14',
				   if required */
				break;

			case SPCN_MOD_PRS_STATUS_FIRST:
			case SPCN_MOD_PRS_STATUS_SUBS:
				add_sensor_prs(sensors,
					(struct sensor_prs *) header);
				break;

			case SPCN_MOD_SENSOR_PARAM_FIRST:
			case SPCN_MOD_SENSOR_PARAM_SUBS:
				add_sensor_param(sensors,
					(struct sensor_param *) header);
				break;

			case SPCN_MOD_SENSOR_DATA_FIRST:
			case SPCN_MOD_SENSOR_DATA_SUBS:
				add_sensor_data(sensors,
					(struct sensor_data *) header);

				break;

			default:
				prerror("SENSOR: unknown modifier : %x\n",
					smod->mod);
			}

out_sensor:
			sensor_buf_ptr += smod->entry_size;
		}
	}
}

static void add_opal_sensor_node(void)
{
	int index;

	if (!fsp_present())
		return;

	add_sensor_ids(sensor_node);

	/* Reset the entry count of each modifier */
	for (index = 0; spcn_mod_data[index].mod != SPCN_MOD_LAST;
			index++)
		spcn_mod_data[index].entry_count = 0;
}

void fsp_init_sensor(void)
{
	uint32_t cmd_header, align, size, psi_dma_offset = 0;
	enum spcn_rsp_status status;
	struct fsp_msg msg, resp;
	int index, rc;

	if (!fsp_present()) {
		sensor_state = SENSOR_PERMANENT_ERROR;
		return;
	}

	sensor_buffer = memalign(TCE_PSIZE, SENSOR_MAX_SIZE);
	if (!sensor_buffer) {
		log_simple_error(&e_info(OPAL_RC_SENSOR_INIT), "SENSOR: could "
				 "not allocate sensor_buffer!\n");
		return;
	}

	/* Map TCE */
	fsp_tce_map(PSI_DMA_SENSOR_BUF, sensor_buffer, PSI_DMA_SENSOR_BUF_SZ);

	msg.resp = &resp;

	/* Traverse using all the modifiers to know all the sensors available
	 * in the system */
	for (index = 0; spcn_mod_data[index].mod != SPCN_MOD_LAST &&
			sensor_state == SENSOR_VALID_DATA;) {
		prlog(PR_TRACE, "Get the data for modifier [%d]\n",
		      spcn_mod_data[index].mod);
		if (spcn_mod_data[index].mod == SPCN_MOD_PROC_JUNC_TEMP) {
			/* TODO Support this modifier 0x14, if required */
			align = psi_dma_offset % sizeof(uint32_t);
			if (align)
				psi_dma_offset += (sizeof(uint32_t) - align);

			/* TODO Add 8 byte command data required for mod 0x14 */
			psi_dma_offset += 8;

			cmd_header = spcn_mod_data[index].mod << 24 |
					SPCN_CMD_PRS << 16 | 0x0008;
		} else {
			cmd_header = spcn_mod_data[index].mod << 24 |
					SPCN_CMD_PRS << 16;
		}

		fsp_fillmsg(&msg, FSP_CMD_SPCN_PASSTHRU, 4,
				SPCN_ADDR_MODE_CEC_NODE, cmd_header, 0,
				PSI_DMA_SENSOR_BUF + psi_dma_offset);

		rc = fsp_sync_msg(&msg, false);
		if (rc >= 0) {
			status = (fsp_msg_get_data_word(&resp, 1) >> 24) & 0xff;
			size = fsp_sensor_process_read(&resp);
			psi_dma_offset += size;
			spcn_mod_data[index].entry_count += (size /
					spcn_mod_data[index].entry_size);
		} else {
			sensor_state = SENSOR_PERMANENT_ERROR;
			break;
		}

		switch (spcn_mod_data[index].mod) {
		case SPCN_MOD_PRS_STATUS_FIRST:
		case SPCN_MOD_SENSOR_PARAM_FIRST:
		case SPCN_MOD_SENSOR_DATA_FIRST:
			if (status == SPCN_RSP_STATUS_COND_SUCCESS)
				index++;
			else
				index += 2;

			break;
		case SPCN_MOD_PRS_STATUS_SUBS:
		case SPCN_MOD_SENSOR_PARAM_SUBS:
		case SPCN_MOD_SENSOR_DATA_SUBS:
			if (status != SPCN_RSP_STATUS_COND_SUCCESS)
				index++;
			break;
		case SPCN_MOD_SENSOR_POWER:
			index++;
		default:
			break;
		}
	}

	if (sensor_state != SENSOR_VALID_DATA)
		sensor_state = SENSOR_PERMANENT_ERROR;
	else
		add_opal_sensor_node();
}
