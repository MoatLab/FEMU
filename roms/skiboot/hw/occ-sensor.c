// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * OCC (On Chip Controller) exports a bunch of sensors
 *
 * Copyright 2017-2019 IBM Corp.
 */

#include <skiboot.h>
#include <opal.h>
#include <chip.h>
#include <sensor.h>
#include <device.h>
#include <cpu.h>
#include <occ.h>

enum sensor_attr {
	SENSOR_SAMPLE,
	SENSOR_SAMPLE_MIN,	/* OCC's min/max */
	SENSOR_SAMPLE_MAX,
	SENSOR_CSM_MIN,		/* CSM's min/max */
	SENSOR_CSM_MAX,
	SENSOR_ACCUMULATOR,
	MAX_SENSOR_ATTR,
};

#define HWMON_SENSORS_MASK	(OCC_SENSOR_TYPE_CURRENT | \
				 OCC_SENSOR_TYPE_VOLTAGE | \
				 OCC_SENSOR_TYPE_TEMPERATURE | \
				 OCC_SENSOR_TYPE_POWER)

/*
 * Standard HWMON linux interface expects the below units for the
 * environment sensors:
 * - Current		: milliampere
 * - Voltage		: millivolt
 * - Temperature	: millidegree Celsius (scaled in kernel)
 * - Power		: microWatt	      (scaled in kernel)
 * - Energy		: microJoule
 */

/*
 * OCC sensor units are obtained after scaling the sensor values.
 * https://github.com/open-power/occ/blob/master/src/occ_405/sensor/sensor_info.c
 */

static struct str_map {
	const char *occ_str;
	const char *opal_str;
} str_maps[] = {
	{"PWRSYS", "System"},
	/* Bulk power of the system: Watt */
	{"PWRFAN", "Fan"},
	/* Power consumption of the system fans: Watt */
	{"PWRIO", "IO"},
	/* Power consumption of the IO subsystem: Watt */
	{"PWRSTORE", "Storage"},
	/* Power comsumption of the storage subsystem: Watt */
	{"PWRGPU", "GPU"},
	/* Power consumption for GPUs per socket read from APSS: Watt */
	{"PWRAPSSCH", "APSS"},
	/* Power Provided by APSS channel x (where x=0…15): Watt */
	{"PWRPROC", ""},
	/* Power consumption for this Processor: Watt */
	{"PWRVDD", "Vdd"},
	/* Power consumption for this Processor's Vdd(AVSBus readings): Watt */
	{"PWRVDN", "Vdn"},
	/* Power consumption for  this Processor's Vdn (nest)
	 * Calculated from AVSBus readings: Watt */
	{"PWRMEM", "Memory"},
	/* Power consumption for Memory  for this Processor read from APSS:
	 * Watt */
	{"CURVDD", "Vdd"},
	/* Processor Vdd Current (read from AVSBus): Ampere */
	{"CURVDN", "Vdn"},
	/* Processor Vdn Current (read from AVSBus): Ampere */
	{"VOLTVDDSENSE", "Vdd Remote Sense"},
	/* Vdd Voltage at the remote sense.
	 * AVS reading adjusted for loadline: millivolt */
	{"VOLTVDNSENSE", "Vdn Remote Sense"},
	/* Vdn Voltage at the remote sense.
	 * AVS reading adjusted for loadline: millivolt */
	{"VOLTVDD", "Vdd"},
	/* Processor Vdd Voltage (read from AVSBus): millivolt */
	{"VOLTVDN", "Vdn"},
	/* Processor Vdn Voltage (read from AVSBus): millivolt */
	{"TEMPC", "Core"},
	/* Average temperature of core DTS sensors for Processor's Core y:
	 * Celsius */
	{"TEMPQ", "Quad"},
	/* Average temperature of quad (in cache) DTS sensors for
	 * Processor’s Quad y: Celsius */
	{"TEMPNEST", "Nest"},
	/* Average temperature of nest DTS sensors: Celsius */
	{"TEMPPROCTHRMC", "Core"},
	/* The combined weighted core/quad temperature for processor core y:
	 * Celsius */
	{"TEMPDIMM", "DIMM"},
	/* DIMM temperature for DIMM x: Celsius */
	{"TEMPGPU", "GPU"},
	/* GPU x (0..2) board temperature: Celsius */
	/* TEMPGPUxMEM: GPU x hottest HBM temperature (individual memory
	 * temperatures are not available): Celsius */
	{"TEMPVDD", "VRM VDD"},
	/* VRM Vdd temperature: Celsius */
};

static u64 occ_sensor_base;

static inline
struct occ_sensor_data_header *get_sensor_header_block(int occ_num)
{
	return (struct occ_sensor_data_header *)
		(occ_sensor_base + occ_num * OCC_SENSOR_DATA_BLOCK_SIZE);
}

static inline
struct occ_sensor_name *get_names_block(struct occ_sensor_data_header *hb)
{
	return ((struct occ_sensor_name *)((u64)hb + be32_to_cpu(hb->names_offset)));
}

static inline u32 sensor_handler(int occ_num, int sensor_id, int attr)
{
	return sensor_make_handler(SENSOR_OCC, occ_num, sensor_id, attr);
}

/*
 * The scaling factor for the sensors is encoded in the below format:
 * (((UINT32)mantissa << 8) | (UINT32)((UINT8) 256 + (UINT8)exp))
 * https://github.com/open-power/occ/blob/master/src/occ_405/sensor/sensor.h
 */
static void scale_sensor(struct occ_sensor_name *md, u64 *sensor)
{
	u32 factor = be32_to_cpu(md->scale_factor);
	int i;
	s8 exp;

	if (be16_to_cpu(md->type) == OCC_SENSOR_TYPE_CURRENT)
		*sensor *= 1000; //convert to mA

	*sensor *= factor >> 8;
	exp = factor & 0xFF;

	if (exp > 0) {
		for (i = labs(exp); i > 0; i--)
			*sensor *= 10;
	} else {
		for (i = labs(exp); i > 0; i--)
			*sensor /= 10;
	}
}

static void scale_energy(struct occ_sensor_name *md, u64 *sensor)
{
	u32 factor = be32_to_cpu(md->freq);
	int i;
	s8 exp;

	*sensor *= 1000000; //convert to uJ

	*sensor /= factor >> 8;
	exp = factor & 0xFF;

	if (exp > 0) {
		for (i = labs(exp); i > 0; i--)
			*sensor /= 10;
	} else {
		for (i = labs(exp); i > 0; i--)
			*sensor *= 10;
	}
}

static u64 read_sensor(struct occ_sensor_record *sensor, int attr)
{
	switch (attr) {
	case SENSOR_SAMPLE:
		return be16_to_cpu(sensor->sample);
	case SENSOR_SAMPLE_MIN:
		return be16_to_cpu(sensor->sample_min);
	case SENSOR_SAMPLE_MAX:
		return be16_to_cpu(sensor->sample_max);
	case SENSOR_CSM_MIN:
		return be16_to_cpu(sensor->csm_min);
	case SENSOR_CSM_MAX:
		return be16_to_cpu(sensor->csm_max);
	case SENSOR_ACCUMULATOR:
		return be64_to_cpu(sensor->accumulator);
	default:
		break;
	}

	return 0;
}

static void *select_sensor_buffer(struct occ_sensor_data_header *hb, int id)
{
	struct occ_sensor_name *md;
	u8 *ping, *pong;
	void *buffer = NULL;
	u32 reading_offset;

	if (!hb)
		return NULL;

	md = get_names_block(hb);

	ping = (u8 *)((u64)hb + be32_to_cpu(hb->reading_ping_offset));
	pong = (u8 *)((u64)hb + be32_to_cpu(hb->reading_pong_offset));
	reading_offset = be32_to_cpu(md[id].reading_offset);

	/* Check which buffer is valid  and read the data from that.
	 * Ping Pong	Action
	 *  0	0	Return with error
	 *  0	1	Read Pong
	 *  1	0	Read Ping
	 *  1	1	Read the buffer with latest timestamp
	 */

	if (*ping && *pong) {
		u64 tping, tpong;
		u64 ping_buf = (u64)ping + reading_offset;
		u64 pong_buf = (u64)pong + reading_offset;

		tping = be64_to_cpu(((struct occ_sensor_record *)ping_buf)->timestamp);
		tpong = be64_to_cpu(((struct occ_sensor_record *)pong_buf)->timestamp);

		if (tping > tpong)
			buffer = ping;
		else
			buffer = pong;
	} else if (*ping && !*pong) {
		buffer = ping;
	} else if (!*ping && *pong) {
		buffer = pong;
	} else if (!*ping && !*pong) {
		prlog(PR_DEBUG, "OCC: Both ping and pong sensor buffers are invalid\n");
		return NULL;
	}

	assert(buffer);
	buffer = (void *)((u64)buffer + reading_offset);

	return buffer;
}

int occ_sensor_read(u32 handle, __be64 *data)
{
	struct occ_sensor_data_header *hb;
	struct occ_sensor_name *md;
	u16 id = sensor_get_rid(handle);
	u8 occ_num = sensor_get_frc(handle);
	u8 attr = sensor_get_attr(handle);
	u64 d;
	void *buff;

	if (occ_num > MAX_OCCS)
		return OPAL_PARAMETER;

	if (attr > MAX_SENSOR_ATTR)
		return OPAL_PARAMETER;

	if (is_occ_reset())
		return OPAL_HARDWARE;

	hb = get_sensor_header_block(occ_num);

	if (hb->valid != 1)
		return OPAL_HARDWARE;

	if (id > be16_to_cpu(hb->nr_sensors))
		return OPAL_PARAMETER;

	buff = select_sensor_buffer(hb, id);
	if (!buff)
		return OPAL_HARDWARE;

	d = read_sensor(buff, attr);
	if (!d)
		goto out_success;

	md = get_names_block(hb);
	if (be16_to_cpu(md[id].type) == OCC_SENSOR_TYPE_POWER && attr == SENSOR_ACCUMULATOR)
		scale_energy(&md[id], &d);
	else
		scale_sensor(&md[id], &d);

out_success:
	*data = cpu_to_be64(d);

	return OPAL_SUCCESS;
}

static bool occ_sensor_sanity(struct occ_sensor_data_header *hb, int chipid)
{
	if (hb->valid != 0x01) {
		prerror("OCC: Chip %d sensor data invalid\n", chipid);
		return false;
	}

	if (hb->version != 0x01) {
		prerror("OCC: Chip %d unsupported sensor header block version %d\n",
			chipid, hb->version);
		return false;
	}

	if (hb->reading_version != 0x01) {
		prerror("OCC: Chip %d unsupported sensor record format %d\n",
			chipid, hb->reading_version);
		return false;
	}

	if (hb->names_version != 0x01) {
		prerror("OCC: Chip %d unsupported sensor names format %d\n",
			chipid, hb->names_version);
		return false;
	}

	if (hb->name_length != sizeof(struct occ_sensor_name)) {
		prerror("OCC: Chip %d unsupported sensor names length %d\n",
			chipid, hb->name_length);
		return false;
	}

	if (!hb->nr_sensors) {
		prerror("OCC: Chip %d has no sensors\n", chipid);
		return false;
	}

	if (!hb->names_offset ||
	    !hb->reading_ping_offset ||
	    !hb->reading_pong_offset) {
		prerror("OCC: Chip %d Invalid sensor buffer pointers\n",
			chipid);
		return false;
	}

	return true;
}

/*
 * parse_entity: Parses OCC sensor name to return the entity number like
 *		 chipid, core-id, dimm-no, gpu-no. 'end' is used to
 *		 get the subentity strings. Returns -1 if no number is found.
 *		 TEMPC4 --> returns 4, end will be NULL
 *		 TEMPGPU2DRAM1 --> returns 2, end = "DRAM1"
 *		 PWRSYS --> returns -1, end = NULL
 */
static int parse_entity(const char *name, char **end)
{
	while (*name != '\0') {
		if (isdigit(*name))
			break;
		name++;
	}

	if (*name)
		return strtol(name, end, 10);
	else
		return -1;
}

static void add_sensor_label(struct dt_node *node, struct occ_sensor_name *md,
			     int chipid)
{
	char sname[30] = "";
	char prefix[30] = "";
	uint16_t location = be16_to_cpu(md->location);
	int i;

	if (location != OCC_SENSOR_LOC_SYSTEM)
		snprintf(prefix, sizeof(prefix), "%s %d ", "Chip", chipid);

	for (i = 0; i < ARRAY_SIZE(str_maps); i++)
		if (!strncmp(str_maps[i].occ_str, md->name,
			     strlen(str_maps[i].occ_str))) {
			char *end;
			int num = -1;

			if (location != OCC_SENSOR_LOC_CORE)
				num = parse_entity(md->name, &end);

			if (num != -1) {
				snprintf(sname, sizeof(sname), "%s%s %d %s",
					 prefix, str_maps[i].opal_str, num,
					 end);
			} else {
				snprintf(sname, sizeof(sname), "%s%s", prefix,
					 str_maps[i].opal_str);
			}
			dt_add_property_string(node, "label", sname);
			return;
		}

	/* Fallback to OCC literal if mapping is not found */
	if (location == OCC_SENSOR_LOC_SYSTEM) {
		dt_add_property_string(node, "label", md->name);
	} else {
		snprintf(sname, sizeof(sname), "%s%s", prefix, md->name);
		dt_add_property_string(node, "label", sname);
	}
}

static const char *get_sensor_type_string(enum occ_sensor_type type)
{
	switch (type) {
	case OCC_SENSOR_TYPE_POWER:
		return "power";
	case OCC_SENSOR_TYPE_TEMPERATURE:
		return "temp";
	case OCC_SENSOR_TYPE_CURRENT:
		return "curr";
	case OCC_SENSOR_TYPE_VOLTAGE:
		return "in";
	default:
		break;
	}

	return "unknown";
}

static const char *get_sensor_loc_string(enum occ_sensor_location loc)
{
	switch (loc) {
	case OCC_SENSOR_LOC_SYSTEM:
		return "sys";
	case OCC_SENSOR_LOC_PROCESSOR:
		return "proc";
	case OCC_SENSOR_LOC_MEMORY:
		return "mem";
	case OCC_SENSOR_LOC_VRM:
		return "vrm";
	case OCC_SENSOR_LOC_CORE:
		return "core";
	case OCC_SENSOR_LOC_QUAD:
		return "quad";
	case OCC_SENSOR_LOC_GPU:
		return "gpu";
	default:
		break;
	}

	return "unknown";
}

/*
 * Power sensors can be 0 valued in few platforms like Zaius, Romulus
 * which do not have APSS. At the moment there is no HDAT/DT property
 * to indicate if APSS is present. So for now skip zero valued power
 * sensors.
 */
static bool check_sensor_sample(struct occ_sensor_data_header *hb, u32 offset)
{
	struct occ_sensor_record *ping, *pong;

	ping = (struct occ_sensor_record *)((u64)hb
			+ be32_to_cpu(hb->reading_ping_offset) + offset);
	pong = (struct occ_sensor_record *)((u64)hb
			+ be32_to_cpu(hb->reading_pong_offset) + offset);
	return ping->sample || pong->sample;
}

static void add_sensor_node(const char *loc, const char *type, int i, int attr,
			    struct occ_sensor_name *md, __be32 *phandle, u32 *ptype,
			    u32 pir, u32 occ_num, u32 chipid)
{
	char name[30];
	struct dt_node *node;
	u32 handler;

	snprintf(name, sizeof(name), "%s-%s", loc, type);
	handler = sensor_handler(occ_num, i, attr);
	node = dt_new_addr(sensor_node, name, handler);
	dt_add_property_string(node, "sensor-type", type);
	dt_add_property_cells(node, "sensor-data", handler);
	dt_add_property_cells(node, "reg", handler);
	dt_add_property_string(node, "occ_label", md->name);
	add_sensor_label(node, md, chipid);

	if (be16_to_cpu(md->location) == OCC_SENSOR_LOC_CORE)
		dt_add_property_cells(node, "ibm,pir", pir);

	*ptype = be16_to_cpu(md->type);

	if (attr == SENSOR_SAMPLE) {
		handler = sensor_handler(occ_num, i, SENSOR_CSM_MAX);
		dt_add_property_cells(node, "sensor-data-max", handler);

		handler = sensor_handler(occ_num, i, SENSOR_CSM_MIN);
		dt_add_property_cells(node, "sensor-data-min", handler);
	}

	dt_add_property_string(node, "compatible", "ibm,opal-sensor");
	*phandle = cpu_to_be32(node->phandle);
}

bool occ_sensors_init(void)
{
	struct proc_chip *chip;
	struct dt_node *sg, *exports;
	int occ_num = 0, i;
	bool has_gpu = false;

	/* OCC inband sensors is only supported in P9/10 */
	if (proc_gen < proc_gen_p9)
		return false;

	/* Sensors are copied to BAR2 OCC Common Area */
	chip = next_chip(NULL);
	if (!chip->occ_common_base) {
		prerror("OCC: Unassigned OCC Common Area. No sensors found\n");
		return false;
	}

	occ_sensor_base = chip->occ_common_base + OCC_SENSOR_DATA_BLOCK_OFFSET;

	sg = dt_new(opal_node, "sensor-groups");
	if (!sg) {
		prerror("OCC: Failed to create sensor groups node\n");
		return false;
	}
	dt_add_property_string(sg, "compatible", "ibm,opal-sensor-group");
	dt_add_property_cells(sg, "#address-cells", 1);
	dt_add_property_cells(sg, "#size-cells", 0);

	/*
	 * On POWER9, ibm,ioda2-npu2-phb indicates the presence of a
	 * GPU NVlink.
	 */
	if (dt_find_compatible_node(dt_root, NULL, "ibm,ioda2-npu2-phb")) {

		for_each_chip(chip) {
			int max_gpus_per_chip = 3, i;

			for(i = 0; i < max_gpus_per_chip; i++) {
				has_gpu = occ_get_gpu_presence(chip, i);

				if (has_gpu)
					break;
			}

			if (has_gpu)
				break;
		}
	}

	for_each_chip(chip) {
		struct occ_sensor_data_header *hb;
		struct occ_sensor_name *md;
		__be32 *phandles;
		u32 *ptype, phcount = 0;
		unsigned int nr_sensors;

		hb = get_sensor_header_block(occ_num);
		md = get_names_block(hb);

		/* Sanity check of the Sensor Data Header Block */
		if (!occ_sensor_sanity(hb, chip->id))
			continue;

		nr_sensors = be16_to_cpu(hb->nr_sensors);

		phandles = malloc(nr_sensors * sizeof(__be32));
		assert(phandles);
		ptype = malloc(nr_sensors * sizeof(u32));
		assert(ptype);

		for (i = 0; i < nr_sensors; i++) {
			const char *type_name, *loc;
			struct cpu_thread *c = NULL;
			uint32_t pir = 0;
			uint16_t type = be16_to_cpu(md[i].type);
			uint16_t location = be16_to_cpu(md[i].location);

			if (md[i].structure_type != OCC_SENSOR_READING_FULL)
				continue;

			if (!(type & HWMON_SENSORS_MASK))
				continue;

			if (location == OCC_SENSOR_LOC_GPU && !has_gpu)
				continue;

			if (type == OCC_SENSOR_TYPE_POWER &&
			    !check_sensor_sample(hb, be32_to_cpu(md[i].reading_offset)))
				continue;

			if (location == OCC_SENSOR_LOC_CORE) {
				int num = parse_entity(md[i].name, NULL);

				for_each_available_core_in_chip(c, chip->id)
					if (pir_to_core_id(c->pir) == num)
						break;
				if (!c)
					continue;
				pir = c->pir;
			}

			type_name = get_sensor_type_string(type);
			loc = get_sensor_loc_string(location);

			add_sensor_node(loc, type_name, i, SENSOR_SAMPLE, &md[i],
					&phandles[phcount], &ptype[phcount],
					pir, occ_num, chip->id);
			phcount++;

			/* Add energy sensors */
			if (type == OCC_SENSOR_TYPE_POWER &&
			    md[i].structure_type == OCC_SENSOR_READING_FULL) {
				add_sensor_node(loc, "energy", i,
						SENSOR_ACCUMULATOR, &md[i],
						&phandles[phcount], &ptype[phcount],
						pir, occ_num, chip->id);
				phcount++;
			}

		}
		occ_num++;
		occ_add_sensor_groups(sg, phandles, ptype, phcount, chip->id);
		free(phandles);
		free(ptype);
	}
	/* clear the device tree property if no sensors */
	if (list_empty(&sg->children)) {
               dt_free(sg);
	}

	if (!occ_num)
		return false;

	exports = dt_find_by_path(dt_root, "/ibm,opal/firmware/exports");
	if (!exports) {
		prerror("OCC: dt node /ibm,opal/firmware/exports not found\n");
		return false;
	}

	dt_add_property_u64s(exports, "occ_inband_sensors", occ_sensor_base,
			     OCC_SENSOR_DATA_BLOCK_SIZE * occ_num);

	return true;
}
