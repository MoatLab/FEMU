// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2017 IBM Corp. */

#include <device.h>
#include <ipmi.h>
#include <opal.h>
#include <skiboot.h>
#include <string.h>
#include <stdbool.h>

#define IPMI_WRITE_SENSOR		(1 << 0)

#define FW_PROGRESS_SENSOR_TYPE	0x0F
#define BOOT_COUNT_SENSOR_TYPE	0xC3

static int16_t sensors[MAX_IPMI_SENSORS];

static bool sensors_present = false;

struct set_sensor_req {
	u8 sensor_number;
	u8 operation;
	u8 sensor_reading;
	u8 assertion_mask[2];
	u8 deassertion_mask[2];
	u8 event_data[3];
};

static bool ipmi_sensor_type_present(uint8_t sensor_type)
{
        const struct dt_property *type_prop;
        uint8_t type;
        struct dt_node *node;

        dt_for_each_compatible(dt_root, node, "ibm,ipmi-sensor") {
                type_prop = dt_find_property(node, "ipmi-sensor-type");
                if (!type_prop) {
                        prlog(PR_ERR, "IPMI: sensor doesn't have ipmi-sensor-type\n");
                        continue;
                }

                type = (uint8_t)dt_property_get_cell(type_prop, 0);
                if (type == sensor_type)
                        return true;
        }
        return false;
}

uint8_t ipmi_get_sensor_number(uint8_t sensor_type)
{
	assert(sensor_type < MAX_IPMI_SENSORS);
	return sensors[sensor_type];
}

int ipmi_set_boot_count(void)
{
	struct set_sensor_req req;
	struct ipmi_msg *msg;
	int boot_count_sensor;

	if (!sensors_present)
		return OPAL_UNSUPPORTED;

	if (!ipmi_present())
		return OPAL_CLOSED;

        if (!ipmi_sensor_type_present(BOOT_COUNT_SENSOR_TYPE))
                return OPAL_HARDWARE;

	boot_count_sensor = sensors[BOOT_COUNT_SENSOR_TYPE];

	if (boot_count_sensor < 0) {
		prlog(PR_DEBUG, "IPMI: boot count set but not present\n");
		return OPAL_HARDWARE;
	}

	memset(&req, 0, sizeof(req));

	req.sensor_number = boot_count_sensor;
	req.operation = IPMI_WRITE_SENSOR;
	req.sensor_reading = 0x00;
	req.assertion_mask[0] = 0x02;

	msg = ipmi_mkmsg_simple(IPMI_SET_SENSOR_READING, &req, sizeof(req));
	if (!msg)
		return OPAL_HARDWARE;

	printf("IPMI: Resetting boot count on successful boot\n");

	return ipmi_queue_msg(msg);
}

int ipmi_set_fw_progress_sensor(uint8_t state)
{
	struct ipmi_msg *msg;
	struct set_sensor_req request;
	int fw_sensor_num;

	if (!sensors_present)
		return OPAL_UNSUPPORTED;

	if (!ipmi_present())
		return OPAL_CLOSED;

        if (!ipmi_sensor_type_present(FW_PROGRESS_SENSOR_TYPE))
                return OPAL_HARDWARE;

	fw_sensor_num = sensors[FW_PROGRESS_SENSOR_TYPE];

	if (fw_sensor_num < 0) {
		prlog(PR_DEBUG, "IPMI: fw progress set but not present\n");
		return OPAL_HARDWARE;
	}

	memset(&request, 0, sizeof(request));

	request.sensor_number = fw_sensor_num;
	request.operation = 0xa0; /* Set event data bytes, assertion bits */
	request.assertion_mask[0] = 0x04; /* Firmware progress offset */
	request.event_data[0] = 0xc2;
	request.event_data[1] = state;

	prlog(PR_INFO, "IPMI: setting fw progress sensor %02x to %02x\n",
			request.sensor_number, request.event_data[1]);

	msg = ipmi_mkmsg_simple(IPMI_SET_SENSOR_READING, &request,
			sizeof(request));
	if (!msg)
		return OPAL_HARDWARE;

	return ipmi_queue_msg(msg);
}

void ipmi_sensor_init(void)
{
	const struct dt_property *type_prop, *num_prop;
	uint8_t num, type;
	struct dt_node *n;

	memset(sensors, -1, sizeof(sensors));

	dt_for_each_compatible(dt_root, n, "ibm,ipmi-sensor") {
		type_prop = dt_find_property(n, "ipmi-sensor-type");
		if (!type_prop) {
			prerror("IPMI: sensor doesn't have ipmi-sensor-type\n");
			continue;
		}

		num_prop = dt_find_property(n, "reg");
		if (!num_prop) {
			prerror("IPMI: sensor doesn't have reg property\n");
			continue;
		}
		num = (uint8_t)dt_property_get_cell(num_prop, 0);
		type = (uint8_t)dt_property_get_cell(type_prop, 0);
		assert(type < MAX_IPMI_SENSORS);
		sensors[type] = num;
	}
	sensors_present = true;
}
