// SPDX-License-Identifier: Apache-2.0
/* Copyright 2013-2019 IBM Corp. */

#include <xscom.h>
#include <chip.h>
#include <sensor.h>
#include <dts.h>
#include <skiboot.h>
#include <opal-api.h>
#include <opal-msg.h>
#include <timer.h>
#include <timebase.h>

struct dts {
	uint8_t		valid;
	uint8_t		trip;
	int16_t		temp;
};

/*
 * Attributes for the core temperature sensor
 */
enum {
	SENSOR_DTS_ATTR_TEMP_MAX,
	SENSOR_DTS_ATTR_TEMP_TRIP
};


/* Therm mac result masking for DTS (result(0:15)
 *  0:3   - 0x0
 *  4:11  - Temperature in degrees C
 *  12:13 - trip bits: 00 - no trip; 01 - warning; 10 - critical; 11 - fatal
 *  14    - spare
 *  15    - valid
 */
static void dts_decode_one_dts(uint16_t raw, struct dts *dts)
{
	/*
	 * The value is both signed and unsigned :-) 0xff could be
	 * either 255C or -1C, so for now we treat this as unsigned
	 * which is sufficient for our purpose. We could try to be
	 * a bit smarter and treat it as signed for values between
	 * -10 and 0 and unsigned to 239 or something like that...
	 */
	dts->valid = raw & 1;
	if (dts->valid) {
		dts->temp = (raw >> 4) & 0xff;
		dts->trip = (raw >> 2) & 0x3;
	} else {
		dts->temp = 0;
		dts->trip = 0;
	}
}

static void dts_keep_max(struct dts *temps, int n, struct dts *dts)
{
	int i;

	for (i = 0; i < n; i++) {
		int16_t t = temps[i].temp;

		if (!temps[i].valid)
			continue;

		if (t > dts->temp)
			dts->temp = t;

		dts->valid++;
		dts->trip |= temps[i].trip;
	}
}

/* Per core Digital Thermal Sensors */
#define EX_THERM_DTS_RESULT0	0x10050000
#define EX_THERM_DTS_RESULT1	0x10050001

/* Different sensor locations */
#define P8_CT_ZONE_LSU	0
#define P8_CT_ZONE_ISU	1
#define P8_CT_ZONE_FXU	2
#define P8_CT_ZONE_L3C	3
#define P8_CT_ZONES	4

/*
 * Returns the temperature as the max of all 4 zones and a global trip
 * attribute.
 */
static int dts_read_core_temp_p8(uint32_t pir, struct dts *dts)
{
	int32_t chip_id = pir_to_chip_id(pir);
	int32_t core = pir_to_core_id(pir);
	uint64_t dts0, dts1;
	struct dts temps[P8_CT_ZONES];
	int rc;

	rc = xscom_read(chip_id, XSCOM_ADDR_P8_EX(core, EX_THERM_DTS_RESULT0),
			&dts0);
	if (rc)
		return rc;

	rc = xscom_read(chip_id, XSCOM_ADDR_P8_EX(core, EX_THERM_DTS_RESULT1),
			&dts1);
	if (rc)
		return rc;

	dts_decode_one_dts(dts0 >> 48, &temps[P8_CT_ZONE_LSU]);
	dts_decode_one_dts(dts0 >> 32, &temps[P8_CT_ZONE_ISU]);
	dts_decode_one_dts(dts0 >> 16, &temps[P8_CT_ZONE_FXU]);
	dts_decode_one_dts(dts1 >> 48, &temps[P8_CT_ZONE_L3C]);

	dts_keep_max(temps, P8_CT_ZONES, dts);

	prlog(PR_TRACE, "DTS: Chip %x Core %x temp:%dC trip:%x\n",
	      chip_id, core, dts->temp, dts->trip);

	/*
	 * FIXME: The trip bits are always set ?! Just discard
	 * them for the moment until we understand why.
	 */
	dts->trip = 0;
	return 0;
}

/* Per core Digital Thermal Sensors */
#define EC_THERM_P9_DTS_RESULT0	0x050000

/* Different sensor locations */
#define P9_CORE_DTS0	0
#define P9_CORE_DTS1	1
#define P9_CORE_ZONES	2

/*
 * Returns the temperature as the max of all zones and a global trip
 * attribute.
 */
static int dts_read_core_temp_p9(uint32_t pir, struct dts *dts)
{
	int32_t chip_id = pir_to_chip_id(pir);
	int32_t core = pir_to_core_id(pir);
	uint64_t dts0;
	struct dts temps[P9_CORE_ZONES];
	int rc;

	rc = xscom_read(chip_id, XSCOM_ADDR_P9_EC(core, EC_THERM_P9_DTS_RESULT0),
			&dts0);
	if (rc)
		return rc;

	dts_decode_one_dts(dts0 >> 48, &temps[P9_CORE_DTS0]);
	dts_decode_one_dts(dts0 >> 32, &temps[P9_CORE_DTS1]);

	dts_keep_max(temps, P9_CORE_ZONES, dts);

	prlog(PR_TRACE, "DTS: Chip %x Core %x temp:%dC trip:%x\n",
	      chip_id, core, dts->temp, dts->trip);

	/*
	 * FIXME: The trip bits are always set ?! Just discard
	 * them for the moment until we understand why.
	 */
	dts->trip = 0;
	return 0;
}

static void dts_async_read_temp(struct timer *t __unused, void *data,
				u64 now __unused)
{
	struct dts dts = {0};
	int rc, swkup_rc;
	struct cpu_thread *cpu = data;

	swkup_rc = dctl_set_special_wakeup(cpu);

	if (proc_gen == proc_gen_p9)
		rc = dts_read_core_temp_p9(cpu->pir, &dts);
	else /* (proc_gen == proc_gen_p10) */
		rc = OPAL_UNSUPPORTED; /* XXX P10 */

	if (!rc) {
		if (cpu->sensor_attr == SENSOR_DTS_ATTR_TEMP_MAX)
			*cpu->sensor_data = cpu_to_be64(dts.temp);
		else if (cpu->sensor_attr == SENSOR_DTS_ATTR_TEMP_TRIP)
			*cpu->sensor_data = cpu_to_be64(dts.trip);
	}

	if (!swkup_rc)
		dctl_clear_special_wakeup(cpu);

	check_sensor_read(cpu->token);
	rc = opal_queue_msg(OPAL_MSG_ASYNC_COMP, NULL, NULL,
			cpu_to_be64(cpu->token),
			cpu_to_be64(rc));
	if (rc)
		prerror("Failed to queue async message\n");

	cpu->dts_read_in_progress = false;
}

static int dts_read_core_temp(u32 pir, struct dts *dts, u8 attr,
			      int token, __be64 *sensor_data)
{
	struct cpu_thread *cpu;
	int rc;

	switch (proc_gen) {
	case proc_gen_p8:
		rc = dts_read_core_temp_p8(pir, dts);
		break;
	case proc_gen_p9: /* Asynchronus read */
		cpu = find_cpu_by_pir(pir);
		if (!cpu)
			return OPAL_PARAMETER;
		lock(&cpu->dts_lock);
		if (cpu->dts_read_in_progress) {
			unlock(&cpu->dts_lock);
			return OPAL_BUSY;
		}
		cpu->dts_read_in_progress = true;
		cpu->sensor_attr = attr;
		cpu->sensor_data = sensor_data;
		cpu->token = token;
		schedule_timer(&cpu->dts_timer, 0);
		rc = OPAL_ASYNC_COMPLETION;
		unlock(&cpu->dts_lock);
		break;
	case proc_gen_p10: /* XXX P10 */
	default:
		rc = OPAL_UNSUPPORTED;
	}
	return rc;
}

/* Per memory controller Digital Thermal Sensors */
#define THERM_MEM_DTS_RESULT0	0x2050000

/* Different sensor locations */
#define P8_MEM_DTS0	0
#define P8_MEM_DTS1	1
#define P8_MEM_ZONES	2

static int dts_read_mem_temp(uint32_t chip_id, struct dts *dts)
{
	uint64_t dts0;
	struct dts temps[P8_MEM_ZONES];
	int i;
	int rc;

	rc = xscom_read(chip_id, THERM_MEM_DTS_RESULT0, &dts0);
	if (rc)
		return rc;

	dts_decode_one_dts(dts0 >> 48, &temps[P8_MEM_DTS0]);
	dts_decode_one_dts(dts0 >> 32, &temps[P8_MEM_DTS1]);

	for (i = 0; i < P8_MEM_ZONES; i++) {
		int16_t t = temps[i].temp;

		if (!temps[i].valid)
			continue;

		/* keep the max temperature of all 4 sensors */
		if (t > dts->temp)
			dts->temp = t;

		dts->valid++;
		dts->trip |= temps[i].trip;
	}

	prlog(PR_TRACE, "DTS: Chip %x temp:%dC trip:%x\n",
	      chip_id, dts->temp, dts->trip);

	/*
	 * FIXME: The trip bits are always set ?! Just discard
	 * them for the moment until we understand why.
	 */
	dts->trip = 0;
	return 0;
}

/*
 * DTS sensor class ids. Only one for the moment: the core
 * temperature.
 */
enum sensor_dts_class {
	SENSOR_DTS_CORE_TEMP,
	SENSOR_DTS_MEM_TEMP,
	/* To be continued */
};

/*
 * Extract the centaur chip id which was truncated to fit in the
 * resource identifier field of the sensor handler
 */
#define centaur_get_id(rid) (0x80000000 | ((rid) & 0x3ff))

int64_t dts_sensor_read(u32 sensor_hndl, int token, __be64 *sensor_data)
{
	uint8_t	attr = sensor_get_attr(sensor_hndl);
	uint32_t rid = sensor_get_rid(sensor_hndl);
	struct dts dts = {0};
	int64_t rc;

	if (attr > SENSOR_DTS_ATTR_TEMP_TRIP)
		return OPAL_PARAMETER;

	memset(&dts, 0, sizeof(struct dts));

	switch (sensor_get_frc(sensor_hndl)) {
	case SENSOR_DTS_CORE_TEMP:
		rc = dts_read_core_temp(rid, &dts, attr, token, sensor_data);
		break;
	case SENSOR_DTS_MEM_TEMP:
		rc = dts_read_mem_temp(centaur_get_id(rid), &dts);
		break;
	default:
		rc = OPAL_PARAMETER;
		break;
	}
	if (rc)
		return rc;

	if (attr == SENSOR_DTS_ATTR_TEMP_MAX)
		*sensor_data = cpu_to_be64(dts.temp);
	else if (attr == SENSOR_DTS_ATTR_TEMP_TRIP)
		*sensor_data = cpu_to_be64(dts.trip);

	return 0;
}

/*
 * We only have two bytes for the resource identifier in the sensor
 * handler. Let's trunctate the centaur chip id to squeeze it in.
 *
 * Centaur chip IDs are using the XSCOM "partID" encoding described in
 * xscom.h. recap:
 *
 *     0b1000.0000.0000.0000.0000.00NN.NCCC.MMMM
 *     N=Node, C=Chip, M=Memory Channel
 */
#define centaur_make_id(cen_id, dimm_id)	\
	(((chip_id) & 0x3ff) | ((dimm_id) << 10))

#define core_handler(core_id, attr_id)					\
	sensor_make_handler(SENSOR_DTS, SENSOR_DTS_CORE_TEMP,		\
			    core_id, attr_id)

#define cen_handler(cen_id, attr_id)					\
	sensor_make_handler(SENSOR_DTS, SENSOR_DTS_MEM_TEMP,		\
			    centaur_make_id(chip_id, 0), attr_id)

bool dts_sensor_create_nodes(struct dt_node *sensors)
{
	struct proc_chip *chip;
	struct dt_node *cn;
	char name[64];

	/* build the device tree nodes :
	 *
	 *     sensors/core-temp@pir
	 *
	 * The core is identified by its PIR, is stored in the resource
	 * number of the sensor handler.
	 */
	for_each_chip(chip) {
		struct cpu_thread *c;

		for_each_available_core_in_chip(c, chip->id) {
			struct dt_node *node;
			uint32_t handler;

			snprintf(name, sizeof(name), "core-temp@%x", c->pir);

			handler = core_handler(c->pir, SENSOR_DTS_ATTR_TEMP_MAX);
			node = dt_new(sensors, name);
			dt_add_property_string(node, "compatible",
					       "ibm,opal-sensor");
			dt_add_property_cells(node, "sensor-data", handler);
			handler = core_handler(c->pir, SENSOR_DTS_ATTR_TEMP_TRIP);
			dt_add_property_cells(node, "sensor-status", handler);
			dt_add_property_string(node, "sensor-type", "temp");
			dt_add_property_cells(node, "ibm,pir", c->pir);
			dt_add_property_cells(node, "reg", handler);
			dt_add_property_string(node, "label", "Core");
			init_timer(&c->dts_timer, dts_async_read_temp, c);
			c->dts_read_in_progress = false;
		}
	}

	/*
	 * sensors/mem-temp@chip for Centaurs
	 */
	dt_for_each_compatible(dt_root, cn, "ibm,centaur") {
		uint32_t chip_id;
		struct dt_node *node;
		uint32_t handler;

		chip_id = dt_prop_get_u32(cn, "ibm,chip-id");

		snprintf(name, sizeof(name), "mem-temp@%x", chip_id);

		handler = cen_handler(chip_id, SENSOR_DTS_ATTR_TEMP_MAX);
		node = dt_new(sensors, name);
		dt_add_property_string(node, "compatible",
				       "ibm,opal-sensor");
		dt_add_property_cells(node, "sensor-data", handler);

		handler = cen_handler(chip_id, SENSOR_DTS_ATTR_TEMP_TRIP);
		dt_add_property_cells(node, "sensor-status", handler);
		dt_add_property_string(node, "sensor-type", "temp");
		dt_add_property_cells(node, "ibm,chip-id", chip_id);
		dt_add_property_cells(node, "reg", handler);
		dt_add_property_string(node, "label", "Centaur");
	}

	return true;
}
