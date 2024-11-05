// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2017-2019 IBM Corp. */

#include <chip.h>

/* OCC Functions */

extern void occ_pstates_init(void);
extern void occ_fsp_init(void);
int find_master_and_slave_occ(uint64_t **master, uint64_t **slave,
			      int *nr_masters, int *nr_slaves);

/* OCC interrupt for P8 */
extern void occ_p8_interrupt(uint32_t chip_id);
extern void occ_send_dummy_interrupt(void);

/* OCC interrupt for P9 */
extern void occ_p9_interrupt(uint32_t chip_id);

/* OCC load support */
extern void occ_poke_load_queue(void);

/* OCC/Host PNOR ownership */
enum pnor_owner {
	PNOR_OWNER_HOST,
	PNOR_OWNER_EXTERNAL,
};
extern void occ_pnor_set_owner(enum pnor_owner owner);

/* GPU presence detection */
bool occ_get_gpu_presence(struct proc_chip *chip, int gpu_num);

/* OCC Inband Sensors */
extern bool occ_sensors_init(void);
extern int occ_sensor_read(u32 handle, __be64 *data);
extern int occ_sensor_group_clear(u32 group_hndl, int token);
extern void occ_add_sensor_groups(struct dt_node *sg, __be32 *phandles,
				  u32 *ptype, int nr_phandles, int chipid);

extern int occ_sensor_group_enable(u32 group_hndl, int token, bool enable);

extern bool is_occ_reset(void);

/*
 * OCC Sensor Data
 *
 * OCC sensor data will use BAR2 (OCC Common is per physical drawer).
 * Starting address is at offset 0x00580000 from BAR2 base address.
 * Maximum size is 1.5MB.
 *
 * -------------------------------------------------------------------------
 * | Start (Offset from |	End	| Size	   |Description		   |
 * | BAR2 base address) |		|	   |			   |
 * -------------------------------------------------------------------------
 * |	0x00580000      |  0x005A57FF   |150kB     |OCC 0 Sensor Data Block|
 * |	0x005A5800      |  0x005CAFFF   |150kB	   |OCC 1 Sensor Data Block|
 * |	    :		|	:	|  :	   |		:          |
 * |	0x00686800	|  0x006ABFFF   |150kB	   |OCC 7 Sensor Data Block|
 * |	0x006AC000	|  0x006FFFFF   |336kB     |Reserved		   |
 * -------------------------------------------------------------------------
 *
 *
 * OCC N Sensor Data Block Layout (150kB)
 *
 * The sensor data block layout is the same for each OCC N. It contains
 * sensor-header-block, sensor-names buffer, sensor-readings-ping buffer and
 * sensor-readings-pong buffer.
 *
 * ----------------------------------------------------------------------------
 * | Start (Offset from OCC |   End	   | Size |Description		      |
 * | N Sensor Data Block)   |		   |	  |			      |
 * ----------------------------------------------------------------------------
 * |	0x00000000	    |  0x000003FF  |1kB   |Sensor Data Header Block   |
 * |	0x00000400	    |  0x0000CBFF  |50kB  |Sensor Names		      |
 * |	0x0000CC00	    |  0x0000DBFF  |4kB   |Reserved		      |
 * |	0x0000DC00	    |  0x00017BFF  |40kB  |Sensor Readings ping buffer|
 * |	0x00017C00	    |  0x00018BFF  |4kB   |Reserved		      |
 * |	0x00018C00	    |  0x00022BFF  |40kB  |Sensor Readings pong buffer|
 * |	0x00022C00	    |  0x000257FF  |11kB  |Reserved		      |
 * ----------------------------------------------------------------------------
 *
 * Sensor Data Header Block : This is written once by the OCC during
 * initialization after a load or reset. Layout is defined in 'struct
 * occ_sensor_data_header'
 *
 * Sensor Names : This is written once by the OCC during initialization after a
 * load or reset. It contains static information for each sensor. The number of
 * sensors, format version and length of each sensor is defined in
 * 'Sensor Data Header Block'. Format of each sensor name is defined in
 * 'struct occ_sensor_name'. The first sensor starts at offset 0 followed
 * immediately by the next sensor.
 *
 * Sensor Readings Ping/Pong Buffer:
 * There are two 40kB buffers to store the sensor readings. One buffer that
 * is currently being updated by the OCC and one that is available to be read.
 * Each of these buffers will be of the same format. The number of sensors and
 * the format version of the ping and pong buffers is defined in the
 * 'Sensor Data Header Block'.
 *
 * Each sensor within the ping and pong buffers may be of a different format
 * and length. For each sensor the length and format is determined by its
 * 'struct occ_sensor_name.structure_type' in the Sensor Names buffer.
 *
 * --------------------------------------------------------------------------
 * | Offset | Byte0 | Byte1 | Byte2 | Byte3 | Byte4 | Byte5 | Byte6 | Byte7 |
 * --------------------------------------------------------------------------
 * | 0x0000 |Valid  |		   Reserved				    |
 * |        |(0x01) |							    |
 * --------------------------------------------------------------------------
 * | 0x0008 |			Sensor Readings				    |
 * --------------------------------------------------------------------------
 * |	:   |				:				    |
 * --------------------------------------------------------------------------
 * | 0xA000 |                     End of Data				    |
 * --------------------------------------------------------------------------
 *
 */

#define MAX_OCCS			8
#define MAX_CHARS_SENSOR_NAME		16
#define MAX_CHARS_SENSOR_UNIT		4

#define OCC_SENSOR_DATA_BLOCK_OFFSET		0x00580000
#define OCC_SENSOR_DATA_BLOCK_SIZE		0x00025800

/*
 * These should match the definitions inside the OCC source:
 * occ/src/occ_405/sensor/sensor_info.c
 */

enum occ_sensor_type {
	OCC_SENSOR_TYPE_GENERIC		= 0x0001,
	OCC_SENSOR_TYPE_CURRENT		= 0x0002,
	OCC_SENSOR_TYPE_VOLTAGE		= 0x0004,
	OCC_SENSOR_TYPE_TEMPERATURE	= 0x0008,
	OCC_SENSOR_TYPE_UTILIZATION	= 0x0010,
	OCC_SENSOR_TYPE_TIME		= 0x0020,
	OCC_SENSOR_TYPE_FREQUENCY	= 0x0040,
	OCC_SENSOR_TYPE_POWER		= 0x0080,
	OCC_SENSOR_TYPE_PERFORMANCE	= 0x0200,
};

#define OCC_ENABLED_SENSOR_MASK	(OCC_SENSOR_TYPE_GENERIC |	\
				 OCC_SENSOR_TYPE_CURRENT |	\
				 OCC_SENSOR_TYPE_VOLTAGE |	\
				 OCC_SENSOR_TYPE_TIME    |	\
				 OCC_SENSOR_TYPE_TEMPERATURE |	\
				 OCC_SENSOR_TYPE_POWER |	\
				 OCC_SENSOR_TYPE_UTILIZATION |	\
				 OCC_SENSOR_TYPE_FREQUENCY   |	\
				 OCC_SENSOR_TYPE_PERFORMANCE);

enum occ_sensor_location {
	OCC_SENSOR_LOC_SYSTEM		= 0x0001,
	OCC_SENSOR_LOC_PROCESSOR	= 0x0002,
	OCC_SENSOR_LOC_PARTITION	= 0x0004,
	OCC_SENSOR_LOC_MEMORY		= 0x0008,
	OCC_SENSOR_LOC_VRM		= 0x0010,
	OCC_SENSOR_LOC_OCC		= 0x0020,
	OCC_SENSOR_LOC_CORE		= 0x0040,
	OCC_SENSOR_LOC_GPU		= 0x0080,
	OCC_SENSOR_LOC_QUAD		= 0x0100,
};

enum sensor_struct_type {
	OCC_SENSOR_READING_FULL		= 0x01,
	OCC_SENSOR_READING_COUNTER	= 0x02,
};

/**
 * struct occ_sensor_data_header -	Sensor Data Header Block
 * @valid:				When the value is 0x01 it indicates
 *					that this header block and the sensor
 *					names buffer are ready
 * @version:				Format version of this block
 * @nr_sensors:				Number of sensors in names, ping and
 *					pong buffer
 * @reading_version:			Format version of the Ping/Pong buffer
 * @names_offset:			Offset to the location of names buffer
 * @names_version:			Format version of names buffer
 * @names_length:			Length of each sensor in names buffer
 * @reading_ping_offset:		Offset to the location of Ping buffer
 * @reading_pong_offset:		Offset to the location of Pong buffer
 * @pad/reserved:			Unused data
 */
struct occ_sensor_data_header {
	u8 valid;
	u8 version;
	__be16 nr_sensors;
	u8 reading_version;
	u8 pad[3];
	__be32 names_offset;
	u8 names_version;
	u8 name_length;
	u16 reserved;
	__be32 reading_ping_offset;
	__be32 reading_pong_offset;
} __attribute__((__packed__));

/**
 * struct occ_sensor_name -		Format of Sensor Name
 * @name:				Sensor name
 * @units:				Sensor units of measurement
 * @gsid:				Global sensor id (OCC)
 * @freq:				Update frequency
 * @scale_factor:			Scaling factor
 * @type:				Sensor type as defined in
 *					'enum occ_sensor_type'
 * @location:				Sensor location as defined in
 *					'enum occ_sensor_location'
 * @structure_type:			Indicates type of data structure used
 *					for the sensor readings in the ping and
 *					pong buffers for this sensor as defined
 *					in 'enum sensor_struct_type'
 * @reading_offset:			Offset from the start of the ping/pong
 *					reading buffers for this sensor
 * @sensor_data:			Sensor specific info
 * @pad:				Padding to fit the size of 48 bytes.
 */
struct occ_sensor_name {
	char name[MAX_CHARS_SENSOR_NAME];
	char units[MAX_CHARS_SENSOR_UNIT];
	__be16 gsid;
	__be32 freq;
	__be32 scale_factor;
	__be16 type;
	__be16 location;
	u8 structure_type;
	__be32 reading_offset;
	u8 sensor_data;
	u8 pad[8];
} __attribute__((__packed__));

/**
 * struct occ_sensor_record -		Sensor Reading Full
 * @gsid:				Global sensor id (OCC)
 * @timestamp:				Time base counter value while updating
 *					the sensor
 * @sample:				Latest sample of this sensor
 * @sample_min:				Minimum value since last OCC reset
 * @sample_max:				Maximum value since last OCC reset
 * @csm_min:				Minimum value since last reset request
 *					by CSM (CORAL)
 * @csm_max:				Maximum value since last reset request
 *					by CSM (CORAL)
 * @profiler_min:			Minimum value since last reset request
 *					by profiler (CORAL)
 * @profiler_max:			Maximum value since last reset request
 *					by profiler (CORAL)
 * @job_scheduler_min:			Minimum value since last reset request
 *					by job scheduler(CORAL)
 * @job_scheduler_max:			Maximum value since last reset request
 *					by job scheduler (CORAL)
 * @accumulator:			Accumulator for this sensor
 * @update_tag:				Count of the number of ticks that have
 *					passed between updates
 * @pad:				Padding to fit the size of 48 bytes
 */
struct occ_sensor_record {
	u16 gsid;
	__be64 timestamp;
	__be16 sample;
	__be16 sample_min;
	__be16 sample_max;
	__be16 csm_min;
	__be16 csm_max;
	__be16 profiler_min;
	__be16 profiler_max;
	__be16 job_scheduler_min;
	__be16 job_scheduler_max;
	__be64 accumulator;
	__be32 update_tag;
	u8 pad[8];
} __attribute__((__packed__));

/**
 * struct occ_sensor_counter -		Sensor Reading Counter
 * @gsid:				Global sensor id (OCC)
 * @timestamp:				Time base counter value while updating
 *					the sensor
 * @accumulator:			Accumulator/Counter
 * @sample:				Latest sample of this sensor (0/1)
 * @pad:				Padding to fit the size of 24 bytes
 */
struct occ_sensor_counter {
	u16 gsid;
	__be64 timestamp;
	__be64 accumulator;
	u8 sample;
	u8 pad[5];
} __attribute__((__packed__));
