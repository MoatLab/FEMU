// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * OPAL Sensor APIs
 *
 * Copyright 2013-2018 IBM Corp.
 */

#include <sensor.h>
#include <skiboot.h>
#include <device.h>
#include <opal.h>
#include <dts.h>
#include <lock.h>
#include <occ.h>

struct dt_node *sensor_node;

static struct lock async_read_list_lock = LOCK_UNLOCKED;
static LIST_HEAD(async_read_list);

struct sensor_async_read {
	struct list_node link;
	__be64 *val;
	__be32 *opal_data;
	int token;
};

static int add_to_async_read_list(int token, __be32 *opal_data, __be64 *val)
{
	struct sensor_async_read *req;

	req = zalloc(sizeof(*req));
	if (!req)
		return OPAL_NO_MEM;

	req->token = token;
	req->val = val;
	req->opal_data = opal_data;

	lock(&async_read_list_lock);
	list_add_tail(&async_read_list, &req->link);
	unlock(&async_read_list_lock);

	return OPAL_ASYNC_COMPLETION;
}

void check_sensor_read(int token)
{
	struct sensor_async_read *req = NULL;

	lock(&async_read_list_lock);
	if (list_empty(&async_read_list))
		goto out;

	list_for_each(&async_read_list, req, link) {
		if (req->token == token)
			break;
	}
	if (!req)
		goto out;

	*req->opal_data = cpu_to_be32(be64_to_cpu(*req->val));
	free(req->val);
	list_del(&req->link);
	free(req);
out:
	unlock(&async_read_list_lock);
}

static s64 opal_sensor_read_64(u32 sensor_hndl, int token, __be64 *data)
{
	s64 rc;

	switch (sensor_get_family(sensor_hndl)) {
	case SENSOR_DTS:
		rc = dts_sensor_read(sensor_hndl, token, data);
		return rc;

	case SENSOR_OCC:
		rc = occ_sensor_read(sensor_hndl, data);
		return rc;

	default:
		break;
	}

	if (platform.sensor_read) {
		rc = platform.sensor_read(sensor_hndl, token, data);
		return rc;
	}

	return OPAL_UNSUPPORTED;
}

static int64_t opal_sensor_read(uint32_t sensor_hndl, int token,
				__be32 *data)
{
	__be64 *val;
	s64 rc;

	val = zalloc(sizeof(*val));
	if (!val)
		return OPAL_NO_MEM;

	rc = opal_sensor_read_64(sensor_hndl, token, val);
	if (rc == OPAL_SUCCESS) {
		*data = cpu_to_be32(be64_to_cpu(*val));
		free(val);
	} else if (rc == OPAL_ASYNC_COMPLETION) {
		rc = add_to_async_read_list(token, data, val);
	}

	return rc;
}

static int opal_sensor_group_clear(u32 group_hndl, int token)
{
	switch (sensor_get_family(group_hndl)) {
	case SENSOR_OCC:
		return occ_sensor_group_clear(group_hndl, token);
	default:
		break;
	}

	return OPAL_UNSUPPORTED;
}

static int opal_sensor_group_enable(u32 group_hndl, int token, bool enable)
{
	switch (sensor_get_family(group_hndl)) {
	case SENSOR_OCC:
		return occ_sensor_group_enable(group_hndl, token, enable);
	default:
		break;
	}

	return OPAL_UNSUPPORTED;
}
void sensor_init(void)
{
	sensor_node = dt_new(opal_node, "sensors");

	dt_add_property_string(sensor_node, "compatible", "ibm,opal-sensor");
	dt_add_property_cells(sensor_node, "#address-cells", 1);
	dt_add_property_cells(sensor_node, "#size-cells", 0);

	/* Register OPAL interface */
	opal_register(OPAL_SENSOR_READ, opal_sensor_read, 3);
	opal_register(OPAL_SENSOR_GROUP_CLEAR, opal_sensor_group_clear, 2);
	opal_register(OPAL_SENSOR_READ_U64, opal_sensor_read_64, 3);
	opal_register(OPAL_SENSOR_GROUP_ENABLE, opal_sensor_group_enable, 3);
}
