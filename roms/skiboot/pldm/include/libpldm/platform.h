#ifndef PLATFORM_H
#define PLATFORM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "base.h"
#include "pdr.h"
#include "pldm_types.h"

/* Maximum size for request */
#define PLDM_SET_STATE_EFFECTER_STATES_REQ_BYTES  19
#define PLDM_GET_STATE_SENSOR_READINGS_REQ_BYTES  4
#define PLDM_GET_NUMERIC_EFFECTER_VALUE_REQ_BYTES 2
#define PLDM_GET_SENSOR_READING_REQ_BYTES	  3
#define PLDM_SET_EVENT_RECEIVER_REQ_BYTES	  5
/* Response lengths are inclusive of completion code */
#define PLDM_SET_STATE_EFFECTER_STATES_RESP_BYTES 1

#define PLDM_SET_NUMERIC_EFFECTER_VALUE_RESP_BYTES    1
#define PLDM_SET_NUMERIC_EFFECTER_VALUE_MIN_REQ_BYTES 4

#define PLDM_GET_PDR_REQ_BYTES 13

#define PLDM_SET_EVENT_RECEIVER_RESP_BYTES 1

/* Platform event supported request */
#define PLDM_EVENT_MESSAGE_BUFFER_SIZE_REQ_BYTES  2
#define PLDM_EVENT_MESSAGE_BUFFER_SIZE_RESP_BYTES 3

#define PLDM_EVENT_MESSAGE_SUPPORTED_REQ_BYTES	    1
#define PLDM_EVENT_MESSAGE_SUPPORTED_MIN_RESP_BYTES 4

#define PLDM_POLL_FOR_PLATFORM_EVENT_MESSAGE_REQ_BYTES	    8
#define PLDM_POLL_FOR_PLATFORM_EVENT_MESSAGE_MIN_RESP_BYTES 4
#define PLDM_POLL_FOR_PLATFORM_EVENT_MESSAGE_RESP_BYTES	    14
#define PLDM_POLL_FOR_PLATFORM_EVENT_MESSAGE_CHECKSUM_BYTES 4

/* Minimum response length */
#define PLDM_GET_PDR_MIN_RESP_BYTES		       12
#define PLDM_GET_NUMERIC_EFFECTER_VALUE_MIN_RESP_BYTES 5
#define PLDM_GET_SENSOR_READING_MIN_RESP_BYTES	       8
#define PLDM_GET_STATE_SENSOR_READINGS_MIN_RESP_BYTES  2
#define PLDM_GET_PDR_REPOSITORY_INFO_RESP_BYTES	       41

/* Minimum length for PLDM PlatformEventMessage request */
#define PLDM_PLATFORM_EVENT_MESSAGE_MIN_REQ_BYTES		 3
#define PLDM_PLATFORM_EVENT_MESSAGE_STATE_SENSOR_STATE_REQ_BYTES 6
#define PLDM_PLATFORM_EVENT_MESSAGE_RESP_BYTES			 2
#define PLDM_PLATFORM_EVENT_MESSAGE_FORMAT_VERSION		 1
#define PLDM_PLATFORM_EVENT_MESSAGE_EVENT_ID			 2
#define PLDM_PLATFORM_EVENT_MESSAGE_TRANFER_HANDLE		 4

/* Minumum length of senson event data */
#define PLDM_MSG_POLL_EVENT_LENGTH 7

/* Minumum length of senson event data */
#define PLDM_SENSOR_EVENT_DATA_MIN_LENGTH			 5
#define PLDM_SENSOR_EVENT_SENSOR_OP_STATE_DATA_LENGTH		 2
#define PLDM_SENSOR_EVENT_STATE_SENSOR_STATE_DATA_LENGTH	 3
#define PLDM_SENSOR_EVENT_NUMERIC_SENSOR_STATE_MIN_DATA_LENGTH	 4
#define PLDM_SENSOR_EVENT_NUMERIC_SENSOR_STATE_MAX_DATA_LENGTH	 7
#define PLDM_SENSOR_EVENT_NUMERIC_SENSOR_STATE_8BIT_DATA_LENGTH	 4
#define PLDM_SENSOR_EVENT_NUMERIC_SENSOR_STATE_16BIT_DATA_LENGTH 5
#define PLDM_SENSOR_EVENT_NUMERIC_SENSOR_STATE_32BIT_DATA_LENGTH 7

/* Minimum length of data for pldmPDRRepositoryChgEvent */
#define PLDM_PDR_REPOSITORY_CHG_EVENT_MIN_LENGTH     2
#define PLDM_PDR_REPOSITORY_CHANGE_RECORD_MIN_LENGTH 2

/* Minimum length of numeric sensor PDR */
#define PLDM_PDR_NUMERIC_SENSOR_PDR_FIXED_LENGTH		       57
#define PLDM_PDR_NUMERIC_SENSOR_PDR_VARIED_SENSOR_DATA_SIZE_MIN_LENGTH 3
#define PLDM_PDR_NUMERIC_SENSOR_PDR_VARIED_RANGE_FIELD_MIN_LENGTH      9
#define PLDM_PDR_NUMERIC_SENSOR_PDR_MIN_LENGTH                                 \
	(PLDM_PDR_NUMERIC_SENSOR_PDR_FIXED_LENGTH +                            \
	 PLDM_PDR_NUMERIC_SENSOR_PDR_VARIED_SENSOR_DATA_SIZE_MIN_LENGTH +      \
	 PLDM_PDR_NUMERIC_SENSOR_PDR_VARIED_RANGE_FIELD_MIN_LENGTH)

#define PLDM_INVALID_EFFECTER_ID 0xFFFF
#define PLDM_TID_RESERVED	 0xFF

/* DSP0248 Table1 PLDM monitoring and control data types */
#define PLDM_STR_UTF_8_MAX_LEN	256
#define PLDM_STR_UTF_16_MAX_LEN 256

enum pldm_effecter_data_size {
	PLDM_EFFECTER_DATA_SIZE_UINT8,
	PLDM_EFFECTER_DATA_SIZE_SINT8,
	PLDM_EFFECTER_DATA_SIZE_UINT16,
	PLDM_EFFECTER_DATA_SIZE_SINT16,
	PLDM_EFFECTER_DATA_SIZE_UINT32,
	PLDM_EFFECTER_DATA_SIZE_SINT32
};

enum pldm_range_field_format {
	PLDM_RANGE_FIELD_FORMAT_UINT8,
	PLDM_RANGE_FIELD_FORMAT_SINT8,
	PLDM_RANGE_FIELD_FORMAT_UINT16,
	PLDM_RANGE_FIELD_FORMAT_SINT16,
	PLDM_RANGE_FIELD_FORMAT_UINT32,
	PLDM_RANGE_FIELD_FORMAT_SINT32,
	PLDM_RANGE_FIELD_FORMAT_REAL32
};
#define PLDM_RANGE_FIELD_FORMAT_MAX PLDM_RANGE_FIELD_FORMAT_REAL32

enum set_request { PLDM_NO_CHANGE = 0x00, PLDM_REQUEST_SET = 0x01 };

enum effecter_state { PLDM_INVALID_VALUE = 0xFF };

enum pldm_sensor_present_state {
	PLDM_SENSOR_UNKNOWN = 0x0,
	PLDM_SENSOR_NORMAL = 0x01,
	PLDM_SENSOR_WARNING = 0x02,
	PLDM_SENSOR_CRITICAL = 0x03,
	PLDM_SENSOR_FATAL = 0x04,
	PLDM_SENSOR_LOWERWARNING = 0x05,
	PLDM_SENSOR_LOWERCRITICAL = 0x06,
	PLDM_SENSOR_LOWERFATAL = 0x07,
	PLDM_SENSOR_UPPERWARNING = 0x08,
	PLDM_SENSOR_UPPERCRITICAL = 0x09,
	PLDM_SENSOR_UPPERFATAL = 0x0a
};

enum pldm_sensor_event_message_enable {
	PLDM_NO_EVENT_GENERATION,
	PLDM_EVENTS_DISABLED,
	PLDM_EVENTS_ENABLED,
	PLDM_OP_EVENTS_ONLY_ENABLED,
	PLDM_STATE_EVENTS_ONLY_ENABLED
};

enum pldm_effecter_oper_state {
	EFFECTER_OPER_STATE_ENABLED_UPDATEPENDING,
	EFFECTER_OPER_STATE_ENABLED_NOUPDATEPENDING,
	EFFECTER_OPER_STATE_DISABLED,
	EFFECTER_OPER_STATE_UNAVAILABLE,
	EFFECTER_OPER_STATE_STATUSUNKNOWN,
	EFFECTER_OPER_STATE_FAILED,
	EFFECTER_OPER_STATE_INITIALIZING,
	EFFECTER_OPER_STATE_SHUTTINGDOWN,
	EFFECTER_OPER_STATE_INTEST
};

enum pldm_platform_commands {
	PLDM_SET_EVENT_RECEIVER = 0x04,
	PLDM_PLATFORM_EVENT_MESSAGE = 0x0A,
	PLDM_POLL_FOR_PLATFORM_EVENT_MESSAGE = 0x0B,
	PLDM_EVENT_MESSAGE_SUPPORTED = 0x0C,
	PLDM_EVENT_MESSAGE_BUFFER_SIZE = 0x0D,
	PLDM_GET_SENSOR_READING = 0x11,
	PLDM_GET_STATE_SENSOR_READINGS = 0x21,
	PLDM_SET_NUMERIC_EFFECTER_VALUE = 0x31,
	PLDM_GET_NUMERIC_EFFECTER_VALUE = 0x32,
	PLDM_SET_STATE_EFFECTER_STATES = 0x39,
	PLDM_GET_PDR_REPOSITORY_INFO = 0x50,
	PLDM_GET_PDR = 0x51,
};

/** @brief PLDM PDR types
 */
enum pldm_pdr_types {
	PLDM_TERMINUS_LOCATOR_PDR = 1,
	PLDM_NUMERIC_SENSOR_PDR = 2,
	PLDM_NUMERIC_SENSOR_INITIALIZATION_PDR = 3,
	PLDM_STATE_SENSOR_PDR = 4,
	PLDM_STATE_SENSOR_INITIALIZATION_PDR = 5,
	PLDM_SENSOR_AUXILIARY_NAMES_PDR = 6,
	PLDM_OEM_UNIT_PDR = 7,
	PLDM_OEM_STATE_SET_PDR = 8,
	PLDM_NUMERIC_EFFECTER_PDR = 9,
	PLDM_NUMERIC_EFFECTER_INITIALIZATION_PDR = 10,
	PLDM_STATE_EFFECTER_PDR = 11,
	PLDM_STATE_EFFECTER_INITIALIZATION_PDR = 12,
	PLDM_EFFECTER_AUXILIARY_NAMES_PDR = 13,
	PLDM_EFFECTER_OEM_SEMANTIC_PDR = 14,
	PLDM_PDR_ENTITY_ASSOCIATION = 15,
	PLDM_ENTITY_AUXILIARY_NAMES_PDR = 16,
	PLDM_OEM_ENTITY_ID_PDR = 17,
	PLDM_INTERRUPT_ASSOCIATION_PDR = 18,
	PLDM_EVENT_LOG_PDR = 19,
	PLDM_PDR_FRU_RECORD_SET = 20,
	PLDM_COMPACT_NUMERIC_SENSOR_PDR = 21,
	PLDM_OEM_DEVICE_PDR = 126,
	PLDM_OEM_PDR = 127,
};

/** @brief PLDM effecter initialization schemes
 */
enum pldm_effecter_init {
	PLDM_NO_INIT,
	PLDM_USE_INIT_PDR,
	PLDM_ENABLE_EFFECTER,
	PLDM_DISABLE_EFECTER
};

/** @brief PLDM Platform M&C completion codes
 */
enum pldm_platform_completion_codes {
	PLDM_PLATFORM_INVALID_SENSOR_ID = 0x80,
	PLDM_PLATFORM_REARM_UNAVAILABLE_IN_PRESENT_STATE = 0x81,

	PLDM_PLATFORM_INVALID_EFFECTER_ID = 0x80,
	PLDM_PLATFORM_INVALID_STATE_VALUE = 0x81,

	PLDM_PLATFORM_INVALID_DATA_TRANSFER_HANDLE = 0x80,
	PLDM_PLATFORM_INVALID_TRANSFER_OPERATION_FLAG = 0x81,
	PLDM_PLATFORM_INVALID_RECORD_HANDLE = 0x82,
	PLDM_PLATFORM_INVALID_RECORD_CHANGE_NUMBER = 0x83,
	PLDM_PLATFORM_TRANSFER_TIMEOUT = 0x84,

	PLDM_PLATFORM_SET_EFFECTER_UNSUPPORTED_SENSORSTATE = 0x82,

	PLDM_PLATFORM_INVALID_PROTOCOL_TYPE = 0x80,
	PLDM_PLATFORM_ENABLE_METHOD_NOT_SUPPORTED = 0x81,
	PLDM_PLATFORM_HEARTBEAT_FREQUENCY_TOO_HIGH = 0x82,
};

/** @brief PLDM Event types
 */
enum pldm_event_types {
	PLDM_SENSOR_EVENT = 0x00,
	PLDM_EFFECTER_EVENT = 0x01,
	PLDM_REDFISH_TASK_EXECUTED_EVENT = 0x02,
	PLDM_REDFISH_MESSAGE_EVENT = 0x03,
	PLDM_PDR_REPOSITORY_CHG_EVENT = 0x04,
	PLDM_MESSAGE_POLL_EVENT = 0x05,
	PLDM_HEARTBEAT_TIMER_ELAPSED_EVENT = 0x06
};

/** @brief PLDM sensorEventClass states
 */
enum sensor_event_class_states {
	PLDM_SENSOR_OP_STATE,
	PLDM_STATE_SENSOR_STATE,
	PLDM_NUMERIC_SENSOR_STATE
};

/** @brief PLDM sensor supported states
 */
enum pldm_sensor_operational_state {
	PLDM_SENSOR_ENABLED,
	PLDM_SENSOR_DISABLED,
	PLDM_SENSOR_UNAVAILABLE,
	PLDM_SENSOR_STATUSUNKOWN,
	PLDM_SENSOR_FAILED,
	PLDM_SENSOR_INITIALIZING,
	PLDM_SENSOR_SHUTTINGDOWN,
	PLDM_SENSOR_INTEST
};

/** @brief PLDM pldmPDRRepositoryChgEvent class eventData format
 */
enum pldm_pdr_repository_chg_event_data_format {
	REFRESH_ENTIRE_REPOSITORY,
	FORMAT_IS_PDR_TYPES,
	FORMAT_IS_PDR_HANDLES
};

/** @brief PLDM pldmPDRRepositoryChgEvent class changeRecord format
 * eventDataOperation
 */
enum pldm_pdr_repository_chg_event_change_record_event_data_operation {
	PLDM_REFRESH_ALL_RECORDS,
	PLDM_RECORDS_DELETED,
	PLDM_RECORDS_ADDED,
	PLDM_RECORDS_MODIFIED
};

/** @brief PLDM NumericSensorStatePresentReading data type
 */
enum pldm_sensor_readings_data_type {
	PLDM_SENSOR_DATA_SIZE_UINT8,
	PLDM_SENSOR_DATA_SIZE_SINT8,
	PLDM_SENSOR_DATA_SIZE_UINT16,
	PLDM_SENSOR_DATA_SIZE_SINT16,
	PLDM_SENSOR_DATA_SIZE_UINT32,
	PLDM_SENSOR_DATA_SIZE_SINT32
};
#define PLDM_SENSOR_DATA_SIZE_MAX PLDM_SENSOR_DATA_SIZE_SINT32

/** @brief PLDM PlatformEventMessage response status
 */
enum pldm_platform_event_status {
	PLDM_EVENT_NO_LOGGING = 0x00,
	PLDM_EVENT_LOGGING_DISABLED = 0x01,
	PLDM_EVENT_LOG_FULL = 0x02,
	PLDM_EVENT_ACCEPTED_FOR_LOGGING = 0x03,
	PLDM_EVENT_LOGGED = 0x04,
	PLDM_EVENT_LOGGING_REJECTED = 0x05
};

/** @brief PLDM Terminus Locator PDR validity
 */
enum pldm_terminus_locator_pdr_validity {
	PLDM_TL_PDR_NOT_VALID,
	PLDM_TL_PDR_VALID
};

/** @brief PLDM Terminus Locator type
 */
enum pldm_terminus_locator_type {
	PLDM_TERMINUS_LOCATOR_TYPE_UID,
	PLDM_TERMINUS_LOCATOR_TYPE_MCTP_EID,
	PLDM_TERMINUS_LOCATOR_TYPE_SMBUS_RELATIVE,
	PLDM_TERMINUS_LOCATOR_TYPE_SYS_SW
};

/** @brief PLDM event message global enable for
 *  SetEventReceiver command
 */
enum pldm_event_message_global_enable {
	PLDM_EVENT_MESSAGE_GLOBAL_DISABLE,
	PLDM_EVENT_MESSAGE_GLOBAL_ENABLE_ASYNC,
	PLDM_EVENT_MESSAGE_GLOBAL_ENABLE_POLLING,
	PLDM_EVENT_MESSAGE_GLOBAL_ENABLE_ASYNC_KEEP_ALIVE
};

/** @brief PLDM DSP0248 1.2.1 table 74 sensorUnits enumeration
 */
enum pldm_sensor_units {
	PLDM_SENSOR_UNIT_NONE = 0x00,
	PLDM_SENSOR_UNIT_UNSPECIFIED,
	PLDM_SENSOR_UNIT_DEGRESS_C,
	PLDM_SENSOR_UNIT_DEGRESS_F,
	PLDM_SENSOR_UNIT_KELVINS,
	PLDM_SENSOR_UNIT_VOLTS,
	PLDM_SENSOR_UNIT_AMPS,
	PLDM_SENSOR_UNIT_WATTS,
	PLDM_SENSOR_UNIT_JOULES,
	PLDM_SENSOR_UNIT_COULOMBS,
	PLDM_SENSOR_UNIT_VA,
	PLDM_SENSOR_UNIT_NITS,
	PLDM_SENSOR_UNIT_LUMENS,
	PLDM_SENSOR_UNIT_LUX,
	PLDM_SENSOR_UNIT_CANDELAS,
	PLDM_SENSOR_UNIT_KPA,
	PLDM_SENSOR_UNIT_PSI,
	PLDM_SENSOR_UNIT_NEWTONS,
	PLDM_SENSOR_UNIT_CFM,
	PLDM_SENSOR_UNIT_RPM,
	PLDM_SENSOR_UNIT_HERTZ,
	PLDM_SENSOR_UNIT_SECONDS,
	PLDM_SENSOR_UNIT_MINUTES,
	PLDM_SENSOR_UNIT_HOURS,
	PLDM_SENSOR_UNIT_DAYS,
	PLDM_SENSOR_UNIT_WEEKS,
	PLDM_SENSOR_UNIT_MILS,
	PLDM_SENSOR_UNIT_INCHES,
	PLDM_SENSOR_UNIT_FEET,
	PLDM_SENSOR_UNIT_CUBIC_INCHES,
	PLDM_SENSOR_UNIT_CUBIC_FEET,
	PLDM_SENSOR_UNIT_METERS,
	PLDM_SENSOR_UNIT_CUBIC_CENTERMETERS,
	PLDM_SENSOR_UNIT_CUBIC_METERS,
	PLDM_SENSOR_UNIT_LITERS,
	PLDM_SENSOR_UNIT_FLUID_OUNCES,
	PLDM_SENSOR_UNIT_RADIANS,
	PLDM_SENSOR_UNIT_STERADIANS,
	PLDM_SENSOR_UNIT_REVOLUTIONS,
	PLDM_SENSOR_UNIT_CYCLES,
	PLDM_SENSOR_UNIT_GRAVITIES,
	PLDM_SENSOR_UNIT_OUNCES,
	PLDM_SENSOR_UNIT_POUNDS,
	PLDM_SENSOR_UNIT_FOOT_POUNDS,
	PLDM_SENSOR_UNIT_OUNCE_INCHES,
	PLDM_SENSOR_UNIT_GUESS,
	PLDM_SENSOR_UNIT_GILBERTS,
	PLDM_SENSOR_UNIT_HENRIES,
	PLDM_SENSOR_UNIT_FARADS,
	PLDM_SENSOR_UNIT_OHMS,
	PLDM_SENSOR_UNIT_SIEMENS,
	PLDM_SENSOR_UNIT_MOLES,
	PLDM_SENSOR_UNIT_BECQUERELS,
	PLDM_SENSOR_UNIT_PPM,
	PLDM_SENSOR_UNIT_DECIBELS,
	PLDM_SENSOR_UNIT_DBA,
	PLDM_SENSOR_UNIT_DBC,
	PLDM_SENSOR_UNIT_GRAYS,
	PLDM_SENSOR_UNIT_SIEVERTS,
	PLDM_SENSOR_UNIT_COLOR_TEMPERATURE_DEGRESS_K,
	PLDM_SENSOR_UNIT_BITS,
	PLDM_SENSOR_UNIT_BYTES,
	PLDM_SENSOR_UNIT_WORDS,
	PLDM_SENSOR_UNIT_DOUBLE_WORDS,
	PLDM_SENSOR_UNIT_QUAD_WORDS,
	PLDM_SENSOR_UNIT_PERCENTAGE,
	PLDM_SENSOR_UNIT_PASCALS,
	PLDM_SENSOR_UNIT_COUNTS,
	PLDM_SENSOR_UNIT_GRAMS,
	PLDM_SENSOR_UNIT_NEWTON_METERS,
	PLDM_SENSOR_UNIT_HITS,
	PLDM_SENSOR_UNIT_MISSES,
	PLDM_SENSOR_UNIT_RETRIES,
	PLDM_SENSOR_UNIT_OVERRUNS_OVERFLOWS,
	PLDM_SENSOR_UNIT_UNDERRUNS,
	PLDM_SENSOR_UNIT_COLLISIONS,
	PLDM_SENSOR_UNIT_PACKETS,
	PLDM_SENSOR_UNIT_MESSAGES,
	PLDM_SENSOR_UNIT_CHARATERS,
	PLDM_SENSOR_UNIT_ERRORS,
	PLDM_SENSOR_UNIT_CORRECTED_ERRORS,
	PLDM_SENSOR_UNIT_UNCORRECTABLE_ERRORS,
	PLDM_SENSOR_UNIT_SQUARE_MILS,
	PLDM_SENSOR_UNIT_SQUARE_INCHES,
	PLDM_SENSOR_UNIT_SQUARE_FEET,
	PLDM_SENSOR_UNIT_SQUARE_CENTIMETERS,
	PLDM_SENSOR_UNIT_SQUARE_METERS,
	PLDM_SENSOR_UNIT_OEMUNIT = 255
};

enum pldm_occurrence_rate {
	PLDM_RATE_UNIT_NONE = 0x0,
	PLDM_RATE_UNIT_PER_MICRO_SECOND,
	PLDM_RATE_UNIT_PER_MILLI_SECOND,
	PLDM_RATE_UNIT_PER_SECOND,
	PLDM_RATE_UNIT_PER_MINUTE,
	PLDM_RATE_UNIT_PER_HOUR,
	PLDM_RATE_UNIT_PER_DAY,
	PLDM_RATE_UNIT_PER_WEEK,
	PLDM_RATE_UNIT_PER_MONTH,
	PLDM_RATE_UNIT_PER_YEAR
};

/** @brief PLDM respository state */
enum pldm_repository_state {
	PLDM_AVAILABLE,
	PLDM_UPDATE_IN_PROGRESS,
	PLDM_FAILED
};

/** @brief PLDM respository data transfer handler timeout */
enum pldm_repository_data_transfer_handler_timeout {
	PLDM_NO_TIMEOUT,
	PLDM_DEFALUT_MINIMUM_TIMEOUT
};

/** @brief PLDM event message type */
enum pldm_event_message_type {
	PLDM_MESSAGE_TYPE_NOT_CONFIGURED = 0x00,
	PLDM_MESSAGE_TYPE_ASYNCHRONOUS = 0x01,
	PLDM_MESSAGE_TYPE_SYNCHRONOUS = 0x02,
	PLDM_MESSAGE_TYPE_ASYNCHRONOUS_WITH_HEARTBEAT = 0x03
};

/** @struct pldm_pdr_hdr
 *
 *  Structure representing PLDM common PDR header
 */
struct pldm_pdr_hdr {
	uint32_t record_handle;
	uint8_t version;
	uint8_t type;
	uint16_t record_change_num;
	uint16_t length;
} __attribute__((packed));

/** @struct pldm_terminus_locator_pdr
 *
 *  Structure representing PLDM terminus locator PDR
 */
struct pldm_terminus_locator_pdr {
	struct pldm_pdr_hdr hdr;
	uint16_t terminus_handle;
	uint8_t validity;
	uint8_t tid;
	uint16_t container_id;
	uint8_t terminus_locator_type;
	uint8_t terminus_locator_value_size;
	uint8_t terminus_locator_value[1];
} __attribute__((packed));

/** @struct pldm_sensor_auxiliary_names_pdr
 *
 *  Structure representing PLDM Sensor Auxiliary Names PDR
 */
struct pldm_sensor_auxiliary_names_pdr {
	struct pldm_pdr_hdr hdr;
	uint16_t terminus_handle;
	uint16_t sensor_id;
	uint8_t sensor_count;
	uint8_t names[1];
} __attribute__((packed));

/** @struct pldm_terminus_locator_type_mctp_eid
 *
 *  Structure representing terminus locator value for
 *  terminus locator type MCTP_EID
 */
struct pldm_terminus_locator_type_mctp_eid {
	uint8_t eid;
} __attribute__((packed));

/** @struct pldm_pdr_entity_association
 *
 *  Structure representing PLDM Entity Association PDR
 */
struct pldm_pdr_entity_association {
	uint16_t container_id;
	uint8_t association_type;
	pldm_entity container;
	uint8_t num_children;
	pldm_entity children[1];
} __attribute__((packed));

/** @struct pldm_pdr_fru_record_set
 *
 *  Structure representing PLDM FRU record set PDR
 */
struct pldm_pdr_fru_record_set {
	uint16_t terminus_handle;
	uint16_t fru_rsi;
	uint16_t entity_type;
	uint16_t entity_instance_num;
	uint16_t container_id;
} __attribute__((packed));

/** @struct pldm_state_sensor_pdr
 *
 *  Structure representing PLDM state sensor PDR
 */
struct pldm_state_sensor_pdr {
	struct pldm_pdr_hdr hdr;
	uint16_t terminus_handle;
	uint16_t sensor_id;
	uint16_t entity_type;
	uint16_t entity_instance;
	uint16_t container_id;
	uint8_t sensor_init;
	bool8_t sensor_auxiliary_names_pdr;
	uint8_t composite_sensor_count;
	uint8_t possible_states[1];
} __attribute__((packed));

/** @struct state_sensor_possible_states
 *
 *  Structure representing state enums for state sensor
 */
struct state_sensor_possible_states {
	uint16_t state_set_id;
	uint8_t possible_states_size;
	bitfield8_t states[1];
} __attribute__((packed));

/** @struct pldm_state_effecter_pdr
 *
 *  Structure representing PLDM state effecter PDR
 */
struct pldm_state_effecter_pdr {
	struct pldm_pdr_hdr hdr;
	uint16_t terminus_handle;
	uint16_t effecter_id;
	uint16_t entity_type;
	uint16_t entity_instance;
	uint16_t container_id;
	uint16_t effecter_semantic_id;
	uint8_t effecter_init;
	bool8_t has_description_pdr;
	uint8_t composite_effecter_count;
	uint8_t possible_states[1];
} __attribute__((packed));

/** @struct pldm_compact_numeric_sensor_pdr
 *
 *  Structure representing PLDM compact numeric sensor PDR
 */
struct pldm_compact_numeric_sensor_pdr {
	struct pldm_pdr_hdr hdr;
	uint16_t terminus_handle;
	uint16_t sensor_id;
	uint16_t entity_type;
	uint16_t entity_instance;
	uint16_t container_id;
	uint8_t sensor_name_length;
	uint8_t base_unit;
	int8_t unit_modifier;
	uint8_t occurrence_rate;
	bitfield8_t range_field_support;
	int32_t warning_high;
	int32_t warning_low;
	int32_t critical_high;
	int32_t critical_low;
	int32_t fatal_high;
	int32_t fatal_low;
	uint8_t sensor_name[1];
} __attribute__((packed));

/** @brief Encode PLDM state sensor PDR
 *
 * @param[in/out] sensor                 Structure to encode. All members of
 * sensor, except those mentioned in the @note below, should be initialized by
 * the caller.
 * @param[in]     allocation_size        Size of sensor allocation in bytes
 * @param[in]     possible_states        Possible sensor states
 * @param[in]     possible_states_size   Size of possible sensor states in bytes
 * @param[out]    actual_size            Size of sensor PDR. Set to 0 on error.
 * @return int    pldm_completion_codes
 *                PLDM_SUCCESS/PLDM_ERROR/PLDM_ERROR_INVALID_LENGTH
 *
 * @note The sensor parameter will be encoded in place.
 * @note Caller is responsible for allocation of the sensor parameter. Caller
 *       must allocate enough space for the base structure and the
 *       sensor->possible_states array, otherwise the function will fail.
 * @note sensor->hdr.length, .type, and .version will be set appropriately.
 */
int encode_state_sensor_pdr(
	struct pldm_state_sensor_pdr *sensor, size_t allocation_size,
	const struct state_sensor_possible_states *possible_states,
	size_t possible_states_size, size_t *actual_size);

/** @union union_effecter_data_size
 *
 *  The bit width and format of reading and threshold values that the effecter
 *  returns.
 *  Refer to: DSP0248_1.2.0: 28.11 Table 87
 */
typedef union {
	uint8_t value_u8;
	int8_t value_s8;
	uint16_t value_u16;
	int16_t value_s16;
	uint32_t value_u32;
	int32_t value_s32;
} union_effecter_data_size;

/** @union union_range_field_format
 *
 *  Indicates the format used for the nominalValue, normalMax, and normalMin
 *  fields.
 *  Refer to: DSP0248_1.2.0: 28.11 Table 87
 */
typedef union {
	uint8_t value_u8;
	int8_t value_s8;
	uint16_t value_u16;
	int16_t value_s16;
	uint32_t value_u32;
	int32_t value_s32;
	real32_t value_f32;
} union_range_field_format;

/** @struct pldm_numeric_effecter_value_pdr
 *
 *  Structure representing PLDM numeric effecter value PDR
 */
struct pldm_numeric_effecter_value_pdr {
	struct pldm_pdr_hdr hdr;
	uint16_t terminus_handle;
	uint16_t effecter_id;
	uint16_t entity_type;
	uint16_t entity_instance;
	uint16_t container_id;
	uint16_t effecter_semantic_id;
	uint8_t effecter_init;
	bool8_t effecter_auxiliary_names;
	uint8_t base_unit;
	int8_t unit_modifier;
	uint8_t rate_unit;
	uint8_t base_oem_unit_handle;
	uint8_t aux_unit;
	int8_t aux_unit_modifier;
	uint8_t aux_rate_unit;
	uint8_t aux_oem_unit_handle;
	bool8_t is_linear;
	uint8_t effecter_data_size;
	real32_t resolution;
	real32_t offset;
	uint16_t accuracy;
	uint8_t plus_tolerance;
	uint8_t minus_tolerance;
	real32_t state_transition_interval;
	real32_t transition_interval;
	union_effecter_data_size max_settable;
	union_effecter_data_size min_settable;
	uint8_t range_field_format;
	bitfield8_t range_field_support;
	union_range_field_format nominal_value;
	union_range_field_format normal_max;
	union_range_field_format normal_min;
	union_range_field_format rated_max;
	union_range_field_format rated_min;
} __attribute__((packed));

/** @union union_sensor_data_size
 *
 *  The bit width and format of reading and threshold values that the sensor
 *  returns.
 *  Refer to: DSP0248_1.2.0: 28.4 Table 78
 */
typedef union {
	uint8_t value_u8;
	int8_t value_s8;
	uint16_t value_u16;
	int16_t value_s16;
	uint32_t value_u32;
	int32_t value_s32;
} union_sensor_data_size;

/** @struct pldm_value_pdr_hdr
 *
 *  Structure representing PLDM PDR header for unpacked value
 *  Refer to: DSP0248_1.2.0: 28.1 Table 75
 */
struct pldm_value_pdr_hdr {
	uint32_t record_handle;
	uint8_t version;
	uint8_t type;
	uint16_t record_change_num;
	uint16_t length;
};

/** @struct pldm_numeric_sensor_value_pdr
 *
 *  Structure representing PLDM Numeric Sensor PDR for unpacked value
 *  Refer to: DSP0248_1.2.0: 28.4 Table 78
 */
struct pldm_numeric_sensor_value_pdr {
	struct pldm_value_pdr_hdr hdr;
	uint16_t terminus_handle;
	uint16_t sensor_id;
	uint16_t entity_type;
	uint16_t entity_instance_num;
	uint16_t container_id;
	uint8_t sensor_init;
	bool8_t sensor_auxiliary_names_pdr;
	uint8_t base_unit;
	int8_t unit_modifier;
	uint8_t rate_unit;
	uint8_t base_oem_unit_handle;
	uint8_t aux_unit;
	int8_t aux_unit_modifier;
	uint8_t aux_rate_unit;
	uint8_t rel;
	uint8_t aux_oem_unit_handle;
	bool8_t is_linear;
	uint8_t sensor_data_size;
	real32_t resolution;
	real32_t offset;
	uint16_t accuracy;
	uint8_t plus_tolerance;
	uint8_t minus_tolerance;
	union_sensor_data_size hysteresis;
	bitfield8_t supported_thresholds;
	bitfield8_t threshold_and_hysteresis_volatility;
	real32_t state_transition_interval;
	real32_t update_interval;
	union_sensor_data_size max_readable;
	union_sensor_data_size min_readable;
	uint8_t range_field_format;
	bitfield8_t range_field_support;
	union_range_field_format nominal_value;
	union_range_field_format normal_max;
	union_range_field_format normal_min;
	union_range_field_format warning_high;
	union_range_field_format warning_low;
	union_range_field_format critical_high;
	union_range_field_format critical_low;
	union_range_field_format fatal_high;
	union_range_field_format fatal_low;
};

/** @struct state_effecter_possible_states
 *
 *  Structure representing state enums for state effecter
 */
struct state_effecter_possible_states {
	uint16_t state_set_id;
	uint8_t possible_states_size;
	bitfield8_t states[1];
} __attribute__((packed));

/** @struct pldm_effecter_aux_name_pdr
 *
 *  Structure representing PLDM aux name numeric effecter value PDR
 */
struct pldm_effecter_aux_name_pdr {
	struct pldm_pdr_hdr hdr;
	uint16_t terminus_handle;
	uint16_t effecter_id;
	uint8_t effecter_count;
	uint8_t effecter_names[1];
} __attribute__((packed));

/** @brief Encode PLDM state effecter PDR
 *
 * @param[in/out] effecter               Structure to encode. All members of
 *                                       effecter, except those mentioned in
 *                                       the @note below, should be initialized
 *                                       by the caller.
 * @param[in]     allocation_size        Size of effecter allocation in bytes
 * @param[in]     possible_states        Possible effecter states
 * @param[in]     possible_states_size   Size of possible effecter states in
 *                                       bytes
 * @param[out]    actual_size            Size of effecter PDR. Set to 0 on
 *                                       error.
 * @return int    pldm_completion_codes
 *                PLDM_SUCCESS/PLDM_ERROR/PLDM_ERROR_INVALID_LENGTH
 *
 * @note The effecter parameter will be encoded in place.
 * @note Caller is responsible for allocation of the effecter parameter. Caller
 *       must allocate enough space for the base structure and the
 *       effecter->possible_states array, otherwise the function will fail.
 * @note effecter->hdr.length, .type, and .version will be set appropriately.
 */
int encode_state_effecter_pdr(
	struct pldm_state_effecter_pdr *effecter, size_t allocation_size,
	const struct state_effecter_possible_states *possible_states,
	size_t possible_states_size, size_t *actual_size);

/** @struct set_effecter_state_field
 *
 *  Structure representing a stateField in SetStateEffecterStates command */

typedef struct state_field_for_state_effecter_set {
	uint8_t set_request;	//!< Whether to change the state
	uint8_t effecter_state; //!< Expected state of the effecter
} __attribute__((packed)) set_effecter_state_field;

/** @struct get_sensor_readings_field
 *
 *  Structure representing a stateField in GetStateSensorReadings command */

typedef struct state_field_for_get_state_sensor_readings {
	uint8_t sensor_op_state; //!< The state of the sensor itself
	uint8_t present_state;	 //!< Return a state value
	uint8_t previous_state; //!< The state that the presentState was entered
				//! from. This must be different from the
				//! present state
	uint8_t event_state;	//!< Return a state value from a PLDM State Set
				//! that is associated with the sensor
} __attribute__((packed)) get_sensor_state_field;

/** @struct PLDM_SetStateEffecterStates_Request
 *
 *  Structure representing PLDM set state effecter states request.
 */
struct pldm_set_state_effecter_states_req {
	uint16_t effecter_id;
	uint8_t comp_effecter_count;
	set_effecter_state_field field[8];
} __attribute__((packed));

/** @struct pldm_get_pdr_repository_info_resp
 *
 *  Structure representing GetPDRRepositoryInfo response packet
 */
struct pldm_pdr_repository_info_resp {
	uint8_t completion_code;
	uint8_t repository_state;
	uint8_t update_time[PLDM_TIMESTAMP104_SIZE];
	uint8_t oem_update_time[PLDM_TIMESTAMP104_SIZE];
	uint32_t record_count;
	uint32_t repository_size;
	uint32_t largest_record_size;
	uint8_t data_transfer_handle_timeout;
} __attribute__((packed));

/** @struct pldm_get_pdr_resp
 *
 *  structure representing GetPDR response packet
 *  transfer CRC is not part of the structure and will be
 *  added at the end of last packet in multipart transfer
 */
struct pldm_get_pdr_resp {
	uint8_t completion_code;
	uint32_t next_record_handle;
	uint32_t next_data_transfer_handle;
	uint8_t transfer_flag;
	uint16_t response_count;
	uint8_t record_data[1];
} __attribute__((packed));

/** @struct pldm_get_pdr_req
 *
 *  structure representing GetPDR request packet
 */
struct pldm_get_pdr_req {
	uint32_t record_handle;
	uint32_t data_transfer_handle;
	uint8_t transfer_op_flag;
	uint16_t request_count;
	uint16_t record_change_number;
} __attribute__((packed));

/** @struct pldm_set_event_receiver_req
 *
 * Structure representing SetEventReceiver command.
 * This structure applies only for MCTP as a transport type.
 */
struct pldm_set_event_receiver_req {
	uint8_t event_message_global_enable;
	uint8_t transport_protocol_type;
	uint8_t event_receiver_address_info;
	uint16_t heartbeat_timer;
} __attribute__((packed));

/** @struct pldm_event_message_buffer_size_req
 *
 *  Structure representing EventMessageBufferSizes command request data
 */
struct pldm_event_message_buffer_size_req {
	uint16_t event_receiver_max_buffer_size;
} __attribute__((packed));

/** @struct pldm_event_message_buffer_size_resp
 *
 *  Structure representing EventMessageBufferSizes command response data
 */
struct pldm_event_message_buffer_size_resp {
	uint8_t completion_code;
	uint16_t terminus_max_buffer_size;
} __attribute__((packed));

/** @struct pldm_platform_event_message_supported_req
 *
 *  structure representing PlatformEventMessageSupported command request data
 */
struct pldm_event_message_supported_req {
	uint8_t format_version;
} __attribute__((packed));

/** @struct pldm_event_message_supported_response
 *
 *  structure representing EventMessageSupported command response data
 */
struct pldm_event_message_supported_resp {
	uint8_t completion_code;
	uint8_t synchrony_configuration;
	bitfield8_t synchrony_configuration_supported;
	uint8_t number_event_class_returned;
	uint8_t event_class[1];
} __attribute__((packed));

/** @struct pldm_set_numeric_effecter_value_req
 *
 *  structure representing SetNumericEffecterValue request packet
 */
struct pldm_set_numeric_effecter_value_req {
	uint16_t effecter_id;
	uint8_t effecter_data_size;
	uint8_t effecter_value[1];
} __attribute__((packed));

/** @struct pldm_get_state_sensor_readings_req
 *
 *  Structure representing PLDM get state sensor readings request.
 */
struct pldm_get_state_sensor_readings_req {
	uint16_t sensor_id;
	bitfield8_t sensor_rearm;
	uint8_t reserved;
} __attribute__((packed));

/** @struct pldm_get_state_sensor_readings_resp
 *
 *  Structure representing PLDM get state sensor readings response.
 */
struct pldm_get_state_sensor_readings_resp {
	uint8_t completion_code;
	uint8_t comp_sensor_count;
	get_sensor_state_field field[1];
} __attribute__((packed));

/** @struct pldm_sensor_event
 *
 *  structure representing sensorEventClass
 */
struct pldm_sensor_event_data {
	uint16_t sensor_id;
	uint8_t sensor_event_class_type;
	uint8_t event_class[1];
} __attribute__((packed));

/** @struct pldm_state_sensor_state
 *
 *  structure representing sensorEventClass for stateSensorState
 */
struct pldm_sensor_event_state_sensor_state {
	uint8_t sensor_offset;
	uint8_t event_state;
	uint8_t previous_event_state;
} __attribute__((packed));

/** @struct pldm_sensor_event_numeric_sensor_state
 *
 *  structure representing sensorEventClass for stateSensorState
 */
struct pldm_sensor_event_numeric_sensor_state {
	uint8_t event_state;
	uint8_t previous_event_state;
	uint8_t sensor_data_size;
	uint8_t present_reading[1];
} __attribute__((packed));

/** @struct pldm_sensor_event_sensor_op_state
 *
 *  structure representing sensorEventClass for SensorOpState
 */
struct pldm_sensor_event_sensor_op_state {
	uint8_t present_op_state;
	uint8_t previous_op_state;
} __attribute__((packed));

/** @struct pldm_platform_event_message_req
 *
 *  structure representing PlatformEventMessage command request data
 */
struct pldm_platform_event_message_req {
	uint8_t format_version;
	uint8_t tid;
	uint8_t event_class;
	uint8_t event_data[1];
} __attribute__((packed));

/** @struct pldm_poll_for_platform_event_message_req
 *
 *  structure representing PollForPlatformEventMessage command request data
 */
struct pldm_poll_for_platform_event_message_req {
	uint8_t format_version;
	uint8_t transfer_operation_flag;
	uint32_t data_transfer_handle;
	uint16_t event_id_to_acknowledge;
};

/** @struct pldm_poll_for_platform_event_message_min_resp
 *
 *  structure representing PollForPlatformEventMessage command response data
 */
struct pldm_poll_for_platform_event_message_min_resp {
	uint8_t completion_code;
	uint8_t tid;
	uint16_t event_id;
};

/** @struct pldm_platform_event_message_response
 *
 *  structure representing PlatformEventMessage command response data
 */
struct pldm_platform_event_message_resp {
	uint8_t completion_code;
	uint8_t platform_event_status;
} __attribute__((packed));

/** @struct pldm_pdr_repository_chg_event_data
 *
 *  structure representing pldmPDRRepositoryChgEvent class eventData
 */
struct pldm_pdr_repository_chg_event_data {
	uint8_t event_data_format;
	uint8_t number_of_change_records;
	uint8_t change_records[1];
} __attribute__((packed));

/** @struct pldm_pdr_repository_chg_event_change_record_data
 *
 *  structure representing pldmPDRRepositoryChgEvent class eventData's change
 *  record data
 */
struct pldm_pdr_repository_change_record_data {
	uint8_t event_data_operation;
	uint8_t number_of_change_entries;
	uint32_t change_entry[1];
} __attribute__((packed));

/** @struct pldm_get_numeric_effecter_value_req
 *
 *  structure representing GetNumericEffecterValue request packet
 */
struct pldm_get_numeric_effecter_value_req {
	uint16_t effecter_id;
} __attribute__((packed));

/** @struct pldm_get_numeric_effecter_value_resp
 *
 *  structure representing GetNumericEffecterValue response packet
 */
struct pldm_get_numeric_effecter_value_resp {
	uint8_t completion_code;
	uint8_t effecter_data_size;
	uint8_t effecter_oper_state;
	uint8_t pending_and_present_values[1];
} __attribute__((packed));

/** @struct pldm_get_sensor_reading_req
 *
 *  Structure representing PLDM get sensor reading request
 */
struct pldm_get_sensor_reading_req {
	uint16_t sensor_id;
	bool8_t rearm_event_state;
} __attribute__((packed));

/** @struct pldm_get_sensor_reading_resp
 *
 *  Structure representing PLDM get sensor reading response
 */
struct pldm_get_sensor_reading_resp {
	uint8_t completion_code;
	uint8_t sensor_data_size;
	uint8_t sensor_operational_state;
	uint8_t sensor_event_message_enable;
	uint8_t present_state;
	uint8_t previous_state;
	uint8_t event_state;
	uint8_t present_reading[1];
} __attribute__((packed));

/* Responder */

/* SetNumericEffecterValue */

/** @brief Decode SetNumericEffecterValue request data
 *
 *  @param[in] msg - Request message
 *  @param[in] payload_length - Length of request message payload
 *  @param[out] effecter_id - used to identify and access the effecter
 *  @param[out] effecter_data_size - The bit width and format of the setting
 * 				value for the effecter.
 * 				value:{uint8,sint8,uint16,sint16,uint32,sint32}
 *  @param[out] effecter_value - The setting value of numeric effecter being
 * 				requested.
 *  @return pldm_completion_codes
 */
int decode_set_numeric_effecter_value_req(const struct pldm_msg *msg,
					  size_t payload_length,
					  uint16_t *effecter_id,
					  uint8_t *effecter_data_size,
					  uint8_t effecter_value[4]);

/** @brief Create a PLDM response message for SetNumericEffecterValue
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] completion_code - PLDM completion code
 *  @param[out] msg - Message will be written to this
 *  @param[in] payload_length - Length of request message payload
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.body.payload'
 */
int encode_set_numeric_effecter_value_resp(uint8_t instance_id,
					   uint8_t completion_code,
					   struct pldm_msg *msg,
					   size_t payload_length);

/* SetStateEffecterStates */

/** @brief Create a PLDM response message for SetStateEffecterStates
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] completion_code - PLDM completion code
 *  @param[out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.body.payload'
 */

int encode_set_state_effecter_states_resp(uint8_t instance_id,
					  uint8_t completion_code,
					  struct pldm_msg *msg);

/** @brief Decode SetStateEffecterStates request data
 *
 *  @param[in] msg - Request message
 *  @param[in] payload_length - Length of request message payload
 *  @param[out] effecter_id - used to identify and access the effecter
 *  @param[out] comp_effecter_count - number of individual sets of effecter
 *         information. Upto eight sets of state effecter info can be accessed
 *         for a given effecter.
 *  @param[out] field - each unit is an instance of the stateFileld structure
 *         that is used to set the requested state for a particular effecter
 *         within the state effecter. This field holds the starting address of
 *         the stateField values. The user is responsible to allocate the
 *         memory prior to calling this command. Since the state field count is
 *         not known in advance, the user should allocate the maximum size
 *         always, which is 8 in number.
 *  @return pldm_completion_codes
 */

int decode_set_state_effecter_states_req(const struct pldm_msg *msg,
					 size_t payload_length,
					 uint16_t *effecter_id,
					 uint8_t *comp_effecter_count,
					 set_effecter_state_field *field);

/* GetPDR */

/** @brief Create a PLDM response message for GetPDR
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] completion_code - PLDM completion code
 *  @param[in] next_record_hndl - The recordHandle for the PDR that is next in
 *        the PDR Repository
 *  @param[in] next_data_transfer_hndl - A handle that identifies the next
 *        portion of the PDR data to be transferred, if any
 *  @param[in] transfer_flag - Indicates the portion of PDR data being
 *        transferred
 *  @param[in] resp_cnt - The number of recordData bytes returned in this
 *        response
 *  @param[in] record_data - PDR data bytes of length resp_cnt
 *  @param[in] transfer_crc - A CRC-8 for the overall PDR. This is present only
 *        in the last part of a PDR being transferred
 *  @param[out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.payload'
 */
int encode_get_pdr_resp(uint8_t instance_id, uint8_t completion_code,
			uint32_t next_record_hndl,
			uint32_t next_data_transfer_hndl, uint8_t transfer_flag,
			uint16_t resp_cnt, const uint8_t *record_data,
			uint8_t transfer_crc, struct pldm_msg *msg);

/** @brief Decode GetPDR request data
 *
 *  @param[in] msg - Request message
 *  @param[in] payload_length - Length of request message payload
 *  @param[out] record_hndl - The recordHandle value for the PDR to be retrieved
 *  @param[out] data_transfer_hndl - Handle used to identify a particular
 *         multipart PDR data transfer operation
 *  @param[out] transfer_op_flag - Flag to indicate the first or subsequent
 *         portion of transfer
 *  @param[out] request_cnt - The maximum number of record bytes requested
 *  @param[out] record_chg_num - Used to determine whether the PDR has changed
 *        while PDR transfer is going on
 *  @return pldm_completion_codes
 */

int decode_get_pdr_req(const struct pldm_msg *msg, size_t payload_length,
		       uint32_t *record_hndl, uint32_t *data_transfer_hndl,
		       uint8_t *transfer_op_flag, uint16_t *request_cnt,
		       uint16_t *record_chg_num);

/* GetStateSensorReadings */

/** @brief Decode GetStateSensorReadings request data
 *
 *  @param[in] msg - Request message
 *  @param[in] payload_length - Length of request message payload
 *  @param[out] sensor_id - used to identify and access the simple or composite
 *         sensor
 *  @param[out] sensor_rearm - Each bit location in this field corresponds to a
 *         particular sensor within the state sensor, where bit [0] corresponds
 *         to the first state sensor (sensor offset 0) and bit [7] corresponds
 *         to the eighth sensor (sensor offset 7), sequentially.
 *  @param[out] reserved - value: 0x00
 *  @return pldm_completion_codes
 */

int decode_get_state_sensor_readings_req(const struct pldm_msg *msg,
					 size_t payload_length,
					 uint16_t *sensor_id,
					 bitfield8_t *sensor_rearm,
					 uint8_t *reserved);

/** @brief Encode GetStateSensorReadings response data
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] completion_code - PLDM completion code
 *  @param[out] comp_sensor_count - The number of individual sets of sensor
 *         information that this command accesses
 *  @param[out] field - Each stateField is an instance of a stateField structure
 *         that is used to return the present operational state setting and the
 *         present state and event state for a particular set of sensor
 *         information contained within the state sensor
 *  @param[out] msg - Message will be written to this
 *  @return pldm_completion_codes
 */

int encode_get_state_sensor_readings_resp(uint8_t instance_id,
					  uint8_t completion_code,
					  uint8_t comp_sensor_count,
					  get_sensor_state_field *field,
					  struct pldm_msg *msg);

/* GetNumericEffecterValue */

/** @brief Decode GetNumericEffecterValue request data
 *
 *  @param[in] msg - Request message
 *  @param[in] payload_length - Length of request message payload
 *  @param[out] effecter_id - used to identify and access the effecter
 *  @return pldm_completion_codes
 */
int decode_get_numeric_effecter_value_req(const struct pldm_msg *msg,
					  size_t payload_length,
					  uint16_t *effecter_id);

/** @brief Create a PLDM response message for GetNumericEffecterValue
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] completion_code - PLDM completion code
 *  @param[in] effecter_data_size - The bit width and format of the setting
 *             value for the effecter.
 * 	       value:{uint8,sint8,uint16,sint16,uint32,sint32}
 *  @param[in] effecter_oper_state - The state of the effecter itself
 *  @param[in] pending_value - The pending numeric value setting of the
 *             effecter. The effecterDataSize field indicates the number of
 *             bits used for this field
 *  @param[in] present_value - The present numeric value setting of the
 *             effecter. The effecterDataSize indicates the number of bits
 *             used for this field
 *  @param[out] msg - Message will be written to this
 *  @param[in] payload_length - Length of request message payload
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.payload'
 */
int encode_get_numeric_effecter_value_resp(
	uint8_t instance_id, uint8_t completion_code,
	uint8_t effecter_data_size, uint8_t effecter_oper_state,
	const uint8_t *pending_value, const uint8_t *present_value,
	struct pldm_msg *msg, size_t payload_length);

/* GetSensorReading */

/** @brief Decode GetSensorReading request data
 *
 *  @param[in] msg - Request message
 *  @param[in] payload_length - Length of request message payload
 *  @param[out] sensor_id - A handle that is used to identify and access
 *         the sensor
 *  @param[out] rearm_event_state - true =  manually re-arm EventState after
 *         responding to this request, false = no manual re-arm
 *  @return pldm_completion_codes
 */

int decode_get_sensor_reading_req(const struct pldm_msg *msg,
				  size_t payload_length, uint16_t *sensor_id,
				  bool8_t *rearm_event_state);

/** @brief Encode GetSensorReading response data
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] completion_code - PLDM completion code
 *  @param[out] sensor_data_size - The bit width and format of reading and
 *         threshold values
 *  @param[out] sensor_operational_state - The state of the sensor itself
 *  @param[out] sensor_event_message_enable - value: { noEventGeneration,
 *         eventsDisabled, eventsEnabled, opEventsOnlyEnabled,
 *         stateEventsOnlyEnabled }
 *  @param[out] present_state - The most recently assessed state value monitored
 *         by the sensor
 *  @param[out] previous_state - The state that the presentState was entered
 *         from
 *  @param[out] event_state - Indicates which threshold crossing assertion
 *         events have been detected
 *  @param[out] present_reading - The present value indicated by the sensor
 *  @param[out] msg - Message will be written to this
 *  @param[in] payload_length - Length of request message payload
 *  @return pldm_completion_codes
 */

int encode_get_sensor_reading_resp(uint8_t instance_id, uint8_t completion_code,
				   uint8_t sensor_data_size,
				   uint8_t sensor_operational_state,
				   uint8_t sensor_event_message_enable,
				   uint8_t present_state,
				   uint8_t previous_state, uint8_t event_state,
				   const uint8_t *present_reading,
				   struct pldm_msg *msg, size_t payload_length);

/* Requester */

/*GetPDRRepositoryInfo*/

/** @brief Encode GetPDRRepositoryInfo response data
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] completion_code - PLDM completion code
 *  @param[in] repository_state - PLDM repository state
 *  @param[in] update_time - When the standard PDR repository data was
 *                           originally created
 *  @param[in] oem_update_time - when OEM PDRs in the PDR Repository were
 *                               originally created
 *  @param[in] record_count - Total number of PDRs in this repository
 *  @param[in] repository_size - Size of the PDR Repository in bytes
 *  @param[in] largest_record_size - Size of the largest record in the PDR
 * Repository in bytes
 *  @param[in] data_transfer_handle_timeout - Data transmission timeout
 *  @param[out] msg - Message will be written to this
 *  @return pldm_completion_codes
 */
int encode_get_pdr_repository_info_resp(
	uint8_t instance_id, uint8_t completion_code, uint8_t repository_state,
	const uint8_t *update_time, const uint8_t *oem_update_time,
	uint32_t record_count, uint32_t repository_size,
	uint32_t largest_record_size, uint8_t data_transfer_handle_timeout,
	struct pldm_msg *msg);

/** @brief Decode GetPDRRepositoryInfo response data
 *
 *  @param[in] msg - Response message
 *  @param[in] payload_length - Length of response message payload
 *  @param[out] completion_code - PLDM completion code
 *  @param[out] repository_state - PLDM repository state
 *  @param[out] update_time - When the standard PDR repository data was
 *                           originally created
 *  @param[out] oem_update_time - when OEM PDRs in the PDR Repository were
 *                               originally created
 *  @param[out] record_count - Total number of PDRs in this repository
 *  @param[out] repository_size - Size of the PDR Repository in bytes
 *  @param[out] largest_record_size - Size of the largest record in the PDR
 * Repository in bytes
 *  @param[out] data_transfer_handle_timeout - Data transmission timeout
 *  @return pldm_completion_codes
 */
int decode_get_pdr_repository_info_resp(
	const struct pldm_msg *msg, size_t payload_length,
	uint8_t *completion_code, uint8_t *repository_state,
	uint8_t *update_time, uint8_t *oem_update_time, uint32_t *record_count,
	uint32_t *repository_size, uint32_t *largest_record_size,
	uint8_t *data_transfer_handle_timeout);

/* GetPDR */

/** @brief Create a PLDM request message for GetPDR
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] record_hndl - The recordHandle value for the PDR to be retrieved
 *  @param[in] data_transfer_hndl - Handle used to identify a particular
 *         multipart PDR data transfer operation
 *  @param[in] transfer_op_flag - Flag to indicate the first or subsequent
 *         portion of transfer
 *  @param[in] request_cnt - The maximum number of record bytes requested
 *  @param[in] record_chg_num - Used to determine whether the PDR has changed
 *        while PDR transfer is going on
 *  @param[out] msg - Message will be written to this
 *  @param[in] payload_length - Length of request message payload
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.payload'
 */
int encode_get_pdr_req(uint8_t instance_id, uint32_t record_hndl,
		       uint32_t data_transfer_hndl, uint8_t transfer_op_flag,
		       uint16_t request_cnt, uint16_t record_chg_num,
		       struct pldm_msg *msg, size_t payload_length);

/** @brief Decode GetPDR response data
 *
 *  Note:
 *  * If the return value is not PLDM_SUCCESS, it represents a
 * transport layer error.
 *  * If the completion_code value is not PLDM_SUCCESS, it represents a
 * protocol layer error and all the out-parameters are invalid.
 *
 *  @param[in] msg - Request message
 *  @param[in] payload_length - Length of request message payload
 *  @param[out] completion_code - PLDM completion code
 *  @param[out] next_record_hndl - The recordHandle for the PDR that is next in
 *        the PDR Repository
 *  @param[out] next_data_transfer_hndl - A handle that identifies the next
 *        portion of the PDR data to be transferred, if any
 *  @param[out] transfer_flag - Indicates the portion of PDR data being
 *        transferred
 *  @param[out] resp_cnt - The number of recordData bytes returned in this
 *        response
 *  @param[out] record_data - PDR data bytes of length resp_cnt, or NULL to
 *        skip the copy and place the actual length in resp_cnt.
 *  @param[in] record_data_length - Length of record_data
 *  @param[out] transfer_crc - A CRC-8 for the overall PDR. This is present only
 *        in the last part of a PDR being transferred
 *  @return pldm_completion_codes
 */
int decode_get_pdr_resp(const struct pldm_msg *msg, size_t payload_length,
			uint8_t *completion_code, uint32_t *next_record_hndl,
			uint32_t *next_data_transfer_hndl,
			uint8_t *transfer_flag, uint16_t *resp_cnt,
			uint8_t *record_data, size_t record_data_length,
			uint8_t *transfer_crc);

/* SetStateEffecterStates */

/** @brief Create a PLDM request message for SetStateEffecterStates
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] effecter_id - used to identify and access the effecter
 *  @param[in] comp_effecter_count - number of individual sets of effecter
 *         information. Upto eight sets of state effecter info can be accessed
 *         for a given effecter.
 *  @param[in] field - each unit is an instance of the stateField structure
 *         that is used to set the requested state for a particular effecter
 *         within the state effecter. This field holds the starting address of
 *         the stateField values. The user is responsible to allocate the
 *         memory prior to calling this command. The user has to allocate the
 *         field parameter as sizeof(set_effecter_state_field) *
 *         comp_effecter_count
 *  @param[out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.payload'
 */

int encode_set_state_effecter_states_req(uint8_t instance_id,
					 uint16_t effecter_id,
					 uint8_t comp_effecter_count,
					 set_effecter_state_field *field,
					 struct pldm_msg *msg);

/** @brief Decode SetStateEffecterStates response data
 *
 *  Note:
 *  * If the return value is not PLDM_SUCCESS, it represents a
 * transport layer error.
 *  * If the completion_code value is not PLDM_SUCCESS, it represents a
 * protocol layer error and all the out-parameters are invalid.
 *
 *  @param[in] msg - Request message
 *  @param[in] payload_length - Length of response message payload
 *  @param[out] completion_code - PLDM completion code
 *  @return pldm_completion_codes
 */
int decode_set_state_effecter_states_resp(const struct pldm_msg *msg,
					  size_t payload_length,
					  uint8_t *completion_code);

/* SetNumericEffecterValue */

/** @brief Create a PLDM request message for SetNumericEffecterValue
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] effecter_id - used to identify and access the effecter
 *  @param[in] effecter_data_size - The bit width and format of the setting
 * 				value for the effecter.
 * 				value:{uint8,sint8,uint16,sint16,uint32,sint32}
 *  @param[in] effecter_value - The setting value of numeric effecter being
 * 				requested.
 *  @param[in] payload_length - Length of request message payload
 *  @param[out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.payload'
 */
int encode_set_numeric_effecter_value_req(uint8_t instance_id,
					  uint16_t effecter_id,
					  uint8_t effecter_data_size,
					  const uint8_t *effecter_value,
					  struct pldm_msg *msg,
					  size_t payload_length);

/** @brief Decode SetNumericEffecterValue response data
 *  @param[in] msg - Request message
 *  @param[in] payload_length - Length of response message payload
 *  @param[out] completion_code - PLDM completion code
 *  @return pldm_completion_codes
 */
int decode_set_numeric_effecter_value_resp(const struct pldm_msg *msg,
					   size_t payload_length,
					   uint8_t *completion_code);

/** @brief Create a PLDM request message for GetStateSensorReadings
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] sensor_id - used to identify and access the simple or composite
 *         sensor
 *  @param[in] sensorRearm - Each bit location in this field corresponds to a
 *         particular sensor within the state sensor, where bit [0] corresponds
 *         to the first state sensor (sensor offset 0) and bit [7] corresponds
 *         to the eighth sensor (sensor offset 7), sequentially
 *  @param[in] reserved - value: 0x00
 *  @param[out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.payload'
 */
int encode_get_state_sensor_readings_req(uint8_t instance_id,
					 uint16_t sensor_id,
					 bitfield8_t sensor_rearm,
					 uint8_t reserved,
					 struct pldm_msg *msg);

/** @brief Decode GetStateSensorReadings response data
 *
 *  @param[in] msg - Request message
 *  @param[in] payload_length - Length of response message payload
 *  @param[out] completion_code - PLDM completion code
 *  @param[in,out] comp_sensor_count - The number of individual sets of sensor
 *         information that this command accesses
 *  @param[out] field - Each stateField is an instance of a stateField structure
 *         that is used to return the present operational state setting and the
 *         present state and event state for a particular set of sensor
 *         information contained within the state sensor
 *  @return pldm_completion_codes
 */

int decode_get_state_sensor_readings_resp(const struct pldm_msg *msg,
					  size_t payload_length,
					  uint8_t *completion_code,
					  uint8_t *comp_sensor_count,
					  get_sensor_state_field *field);

/* PlatformEventMessage */

/** @brief Decode PlatformEventMessage request data
 *  @param[in] msg - Request message
 *  @param[in] payload_length - Length of response message payload
 *  @param[out] format_version - Version of the event format
 *  @param[out] tid - Terminus ID for the terminus that originated the event
 * message
 *  @param[out] event_class - The class of event being sent
 *  @param[out] event_data_offset - Offset where the event data should be read
 * from pldm msg
 *  @return pldm_completion_codes
 */
int decode_platform_event_message_req(const struct pldm_msg *msg,
				      size_t payload_length,
				      uint8_t *format_version, uint8_t *tid,
				      uint8_t *event_class,
				      size_t *event_data_offset);

/** @brief Decode PollForEventMessage request data
 *  @param[in] msg - Request message
 *  @param[in] payload_length - Length of response message payload
 *  @param[out] format_version - Version of the event format
 *  @param[out] transfer_operation_flag - The transfer operation flag
 *  @param[out] data_transfer_handle - The data transfer handle
 *  @param[out] event_id_to_acknowledge - The class of event being sent
 *  from pldm msg
 *  @return pldm_completion_codes
 */
int decode_poll_for_platform_event_message_req(
	const struct pldm_msg *msg, size_t payload_length,
	uint8_t *format_version, uint8_t *transfer_operation_flag,
	uint32_t *data_transfer_handle, uint16_t *event_id_to_acknowledge);

/** @brief Encode PlatformEventMessage response data
 *  @param[in] instance_id - Message's instance id
 *  @param[in] completion_code - PLDM completion code
 *  @param[in] platform_event_status - Response status of the event message
 * command
 *  @param[out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.payload'
 */
int encode_platform_event_message_resp(uint8_t instance_id,
				       uint8_t completion_code,
				       uint8_t platform_event_status,
				       struct pldm_msg *msg);

/** @brief Encode PollForPlatformEventMessage response data
 *  @param[in] instance_id - Message's instance id
 *  @param[in] completion_code - PLDM completion code
 *  @param[in] tid - Terminus ID
 *  @param[in] event_id - The event id
 *  @param[in] next_data_transfer_handle - The next data transfer handle
 *  @param[in] transfer_flag - The transfer flag
 *  @param[in] event_class - The event class
 *  @param[in] event_data_size - The event data size
 *  @param[in] event_data - The event data
 *  @param[in] checksum - The checksum
 *  @param[out] msg - Message will be written to this
 *  @param[in] payload_length - Length of Response message payload
 *  @return pldm_completion_codes
 *  @note Caller is responsible for memory alloc and dealloc of param
 *  'msg.payload'
 */
int encode_poll_for_platform_event_message_resp(
	uint8_t instance_id, uint8_t completion_code, uint8_t tid,
	uint16_t event_id, uint32_t next_data_transfer_handle,
	uint8_t transfer_flag, uint8_t event_class, uint32_t event_data_size,
	uint8_t *event_data, uint32_t checksum, struct pldm_msg *msg,
	size_t payload_length);

/** @brief Encode PlatformEventMessage request data
 * @param[in] instance_id - Message's instance id
 * @param[in] format_version - Version of the event format
 * @param[in] tid - Terminus ID for the terminus that originated the event
 * message
 * @param[in] event_class - The class of event being sent
 * @param[in] event_data - the event data should be read from pldm msg
 * @param[in] event_data_length - Length of the event data
 * @param[out] msg - Request message
 * @return pldm_completion_codes
 * @note Caller is responsible for memory alloc and dealloc of param
 * 'msg.payload'
 */
int encode_platform_event_message_req(
	uint8_t instance_id, uint8_t format_version, uint8_t tid,
	uint8_t event_class, const uint8_t *event_data,
	size_t event_data_length, struct pldm_msg *msg, size_t payload_length);

/** @brief Encode PollForPlatformEventMessage request data
 *  @param[in] instance_id - Message's instance id
 *  @param[in] format_version - Version of the event format
 *  @param[in] transfer_operation_flag - Tranfer operation
 *  @param[in] data_transfer_handle - The data transfer handle
 *  @param[in] event_id_to_acknowledge - the event data to acknowleadge
 *  @param[out] msg - Request message
 *  @return pldm_completion_codes
 *  @note Caller is responsible for memory alloc and dealloc of param
 *  'msg.payload'
 */
int encode_poll_for_platform_event_message_req(uint8_t instance_id,
					       uint8_t format_version,
					       uint8_t transfer_operation_flag,
					       uint32_t data_transfer_handle,
					       uint16_t event_id_to_acknowledge,
					       struct pldm_msg *msg,
					       size_t payload_length);

/** @brief Decode PollForPlatformEventMessage response data
 *  @param[in] msg - Request message
 *  @param[in] payload_length - Length of Response message payload
 *  @param[out] completion_code - the completion code
 *  @param[out] tid - the tid
 *  @param[out] event_id - The event id
 *  @param[out] next_data_transfer_handle - The next data transfer handle
 *  @param[out] transfer_flag - The transfer flag
 *  @param[out] event_class - The event class
 *  @param[out] event_data_size - The event data size
 *  @param[out] event_data - The event data. The event_data pointer points into
 *  msg.payload and therefore has the same lifetime as msg.payload.
 *  @param[out] event_data_integrity_checksum - The checksum
 *  command
 *  @return pldm_completion_codes
 *  @note Caller is responsible for memory alloc and dealloc of param
 *  'msg.payload'
 */
int decode_poll_for_platform_event_message_resp(
	const struct pldm_msg *msg, size_t payload_length,
	uint8_t *completion_code, uint8_t *tid, uint16_t *event_id,
	uint32_t *next_data_transfer_handle, uint8_t *transfer_flag,
	uint8_t *event_class, uint32_t *event_data_size, void **event_data,
	uint32_t *event_data_integrity_checksum);

/** @brief Decode PlatformEventMessage response data
 * @param[in] msg - Request message
 * @param[in] payload_length - Length of Response message payload
 * @param[out] completion_code - PLDM completion code
 * @param[out] platform_event_status - Response status of the event message
 * command
 * @return pldm_completion_codes
 */
int decode_platform_event_message_resp(const struct pldm_msg *msg,
				       size_t payload_length,
				       uint8_t *completion_code,
				       uint8_t *platform_event_status);

/** @brief Decode EventMessageBufferSize response data
 *  @param[in] msg - Request message
 *  @param[in] payload_length - Length of Response message payload
 *  @param[out] completion_code - PLDM completion code
 *  @return pldm_completion_codes
 */
int decode_event_message_buffer_size_resp(const struct pldm_msg *msg,
					  size_t payload_length,
					  uint8_t *completion_code,
					  uint16_t *terminus_max_buffer_size);

/** @brief Encode EventMessageBufferSize request data
 *  @param[in] instance_id - Message's instance id
 *  @param[in] event_receiver_max_buffer_size - Max buffer size
 *  @param[out] msg - Request message
 *  @return pldm_completion_codes
 *  @note Caller is responsible for memory alloc and dealloc of param
 *  'msg.payload'
 */
int encode_event_message_buffer_size_req(uint8_t instance_id,
					 uint16_t event_receiver_max_buffer_size,
					 struct pldm_msg *msg);

/** @brief Encode EventMessageSupported request data
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] format_version - Version of the event format
 *  @param[out] msg - Request message
 *
 *  @return pldm_completion_codes
 *  @note Caller is responsible for memory alloc and dealloc of param
 *  'msg.payload'
 */
int encode_event_message_supported_req(uint8_t instance_id,
				       uint8_t format_version,
				       struct pldm_msg *msg);

/** @brief Decode EventMessageSupported response data
 *
 *  @param[in] msg - Request message
 *  @param[in] payload_length - Length of Response message payload
 *  @param[out] completion_code - PLDM completion code
 *  @param[out] synchrony_config - the synchrony configuration
 *  @param[out] synchrony_config_support - the synchrony configuration support
 *  @param[out] number_event_class_returned - PLDM completion code
 *  @param[out] event_class - the event classes
 *  @param[in] event_class_count - the event class count
 *
 *  @return pldm_completion_codes
 */
int decode_event_message_supported_resp(const struct pldm_msg *msg,
					size_t payload_length,
					uint8_t *completion_code,
					uint8_t *synchrony_config,
					bitfield8_t *synchrony_config_support,
					uint8_t *number_event_class_returned,
					uint8_t *event_class,
					uint8_t event_class_count);

/** @brief Decode sensorEventData response data
 *
 *  @param[in] event_data - event data from the response message
 *  @param[in] event_data_length - length of the event data
 *  @param[out] sensor_id -  sensorID value of the sensor
 *  @param[out] sensor_event_class_type - Type of sensor event class
 *  @param[out] event_class_data_offset - Offset where the event class data
 * should be read from event data
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'event_data'
 */
int decode_sensor_event_data(const uint8_t *event_data,
			     size_t event_data_length, uint16_t *sensor_id,
			     uint8_t *sensor_event_class_type,
			     size_t *event_class_data_offset);

/** @brief Decode sensorOpState response data
 *
 *  @param[in] sensor_data - sensor_data for sensorEventClass = sensorOpState
 *  @param[in] sensor_data_length - Length of sensor_data
 *  @param[out] present_op_state - The sensorOperationalState value from the
 * state change that triggered the event message
 *  @param[out] previous_op_state - The sensorOperationalState value for the
 * state from which the present state was entered
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'sensor_data'
 */
int decode_sensor_op_data(const uint8_t *sensor_data, size_t sensor_data_length,
			  uint8_t *present_op_state,
			  uint8_t *previous_op_state);

/** @brief Decode stateSensorState response data
 *
 *  @param[in] sensor_data - sensor_data for sensorEventClass = stateSensorState
 *  @param[in] sensor_data_length - Length of sensor_data
 *  @param[out] sensor_offset - Identifies which state sensor within a composite
 * state sensor the event is being returned for
 *  @param[out] event_state - The event state value from the state change that
 * triggered the event message
 *  @param[out] previous_event_state - The event state value for the state from
 * which the present event state was entered
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'sensor_data'
 */
int decode_state_sensor_data(const uint8_t *sensor_data,
			     size_t sensor_data_length, uint8_t *sensor_offset,
			     uint8_t *event_state,
			     uint8_t *previous_event_state);

/** @brief Decode numericSensorState response data
 *
 *  @param[in] sensor_data - sensor_data for sensorEventClass =
 * numericSensorState
 *  @param[in] sensor_data_length - Length of sensor_data
 *  @param[out] event_state - The eventState value from the state change that
 * triggered the event message
 *  @param[out] previous_event_state - The eventState value for the state from
 * which the present state was entered
 *  @param[out] sensor_data_size - The bit width and format of reading and
 * threshold values that the sensor returns
 *  @param[out] present_reading - The present value indicated by the sensor
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'sensor_data'
 */
int decode_numeric_sensor_data(const uint8_t *sensor_data,
			       size_t sensor_data_length, uint8_t *event_state,
			       uint8_t *previous_event_state,
			       uint8_t *sensor_data_size,
			       uint32_t *present_reading);

/** @brief Decode Numeric Sensor Pdr data
 *
 *  @param[in] pdr_data - pdr data for numeric sensor
 *  @param[in] pdr_data_length - Length of pdr data
 *  @param[out] pdr_value - unpacked numeric sensor PDR struct
 */
int decode_numeric_sensor_pdr_data(
	const void *pdr_data, size_t pdr_data_length,
	struct pldm_numeric_sensor_value_pdr *pdr_value);

/* GetNumericEffecterValue */

/** @brief Create a PLDM request message for GetNumericEffecterValue
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] effecter_id - used to identify and access the effecter
 *  @param[out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.payload'
 */
int encode_get_numeric_effecter_value_req(uint8_t instance_id,
					  uint16_t effecter_id,
					  struct pldm_msg *msg);

/** @brief Create a PLDM response message for GetNumericEffecterValue
 *
 *  @param[in] msg - Request message
 *  @param[in] payload_length - Length of request message payload
 *  @param[out] completion_code - PLDM completion code
 *  @param[out] effecter_data_size - The bit width and format of the setting
 *		value for the effecter.
 *		value:{uint8,sint8,uint16,sint16,uint32,sint32}
 *  @param[out] effecter_oper_state - The state of the effecter itself
 *  @param[out] pending_value - The pending numeric value setting of the
 *              effecter. The effecterDataSize field indicates the number of
 *              bits used for this field
 *  @param[out] present_value - The present numeric value setting of the
 *              effecter. The effecterDataSize indicates the number of bits
 *              used for this field
 *  @return pldm_completion_codes
 */
int decode_get_numeric_effecter_value_resp(const struct pldm_msg *msg,
					   size_t payload_length,
					   uint8_t *completion_code,
					   uint8_t *effecter_data_size,
					   uint8_t *effecter_oper_state,
					   uint8_t *pending_value,
					   uint8_t *present_value);

/** @brief Decode pldmPDRRepositoryChgEvent response data
 *
 *  @param[in] event_data - eventData for pldmPDRRepositoryChgEvent
 *  @param[in] event_data_size - Length of event_data
 *  @param[out] event_data_format - This field indicates if the changedRecords
 * are of PDR Types or PDR Record Handles
 *  @param[out] number_of_change_records - The number of changeRecords following
 * this field
 *  @param[out] change_record_data_offset - Identifies where changeRecord data
 * is located within event_data
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'event_data'
 */
int decode_pldm_pdr_repository_chg_event_data(
	const uint8_t *event_data, size_t event_data_size,
	uint8_t *event_data_format, uint8_t *number_of_change_records,
	size_t *change_record_data_offset);

/** @brief Decode pldmMessagePollEvent event data type
 *
 *  @param[in] event_data - event data from the response message
 *  @param[in] event_data_length - length of the event data
 *  @param[out] format_version - Version of the event format
 *  @param[out] event_id - The event id
 *  @param[out] data_transfer_handle - The data transfer handle
 *  should be read from event data
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'event_data'
 */
int decode_pldm_message_poll_event_data(const uint8_t *event_data,
					size_t event_data_length,
					uint8_t *format_version,
					uint16_t *event_id,
					uint32_t *data_transfer_handle);

/** @brief Encode pldmMessagePollEvent event data type
 *
 *  @param[in] format_version - Version of the event format
 *  @param[in] event_id - The event id
 *  @param[in] data_transfer_handle - The data transfer handle
 *  @param[out] event_data - event data to the response message
 *  @param[in] event_data_length - length of the event data
 *  @return pldm_completion_codes
 *  @note The caller is responsible for allocating and deallocating the
 *        event_data
 */
int encode_pldm_message_poll_event_data(uint8_t format_version,
					uint16_t event_id,
					uint32_t data_transfer_handle,
					uint8_t *event_data,
					size_t event_data_length);

/** @brief Encode PLDM PDR Repository Change eventData
 *  @param[in] event_data_format - Format of this event data (e.g.
 * FORMAT_IS_PDR_HANDLES)
 *  @param[in] number_of_change_records - Number of changeRecords in this
 * eventData
 *  @param[in] event_data_operations - Array of eventDataOperations
 *      (e.g. RECORDS_ADDED) for each changeRecord in this eventData. This array
 * should contain number_of_change_records elements.
 *  @param[in] numbers_of_change_entries - Array of numbers of changeEntrys
 *      for each changeRecord in this eventData. This array should contain
 *      number_of_change_records elements.
 *  @param[in] change_entries - 2-dimensional array of arrays of changeEntrys,
 *      one array per changeRecord in this eventData. The toplevel array should
 *      contain number_of_change_records elements. Each subarray [i] should
 *      contain numbers_of_change_entries[i] elements.
 *  @param[in] event_data - The eventData will be encoded into this. This entire
 *      structure must be max_change_records_size long. It must be large enough
 *      to accomodate the data to be encoded. The caller is responsible for
 *      allocating and deallocating it, including the variable-size
 *      'event_data.change_records' field. If this parameter is NULL,
 *      PLDM_SUCCESS will be returned and actual_change_records_size will be set
 *      to reflect the required size of the structure.
 *  @param[out] actual_change_records_size - The actual number of meaningful
 *      encoded bytes in event_data. The caller can over-allocate memory and use
 *      this output to determine the real size of the structure.
 *  @param[in] max_change_records_size - The size of event_data in bytes. If the
 *      encoded message would be larger than this value, an error is returned.
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 * 'event_data.change_records'
 */
int encode_pldm_pdr_repository_chg_event_data(
	uint8_t event_data_format, uint8_t number_of_change_records,
	const uint8_t *event_data_operations,
	const uint8_t *numbers_of_change_entries,
	const uint32_t *const *change_entries,
	struct pldm_pdr_repository_chg_event_data *event_data,
	size_t *actual_change_records_size, size_t max_change_records_size);

/** @brief Encode event data for a PLDM Sensor Event
 *
 *  @param[out] event_data              The object to store the encoded event in
 *  @param[in] event_data_size          Size of the allocation for event_data
 *  @param[in] sensor_id                Sensor ID
 *  @param[in] sensor_event_class       Sensor event class
 *  @param[in] sensor_offset            Offset
 *  @param[in] event_state              Event state
 *  @param[in] previous_event_state     Previous event state
 *  @param[out] actual_event_data_size  The real size in bytes of the event_data
 *  @return int pldm_completion_codes   PLDM_SUCCESS/PLDM_ERROR_INVALID_LENGTH
 *  @note If event_data is NULL, then *actual_event_data_size will be set to
 *        reflect the size of the event data, and PLDM_SUCCESS will be returned.
 *  @note The caller is responsible for allocating and deallocating the
 *        event_data
 */
int encode_sensor_event_data(struct pldm_sensor_event_data *event_data,
			     size_t event_data_size, uint16_t sensor_id,
			     enum sensor_event_class_states sensor_event_class,
			     uint8_t sensor_offset, uint8_t event_state,
			     uint8_t previous_event_state,
			     size_t *actual_event_data_size);

/** @brief Decode PldmPDRRepositoryChangeRecord response data
 *
 *  @param[in] change_record_data - changeRecordData for
 * pldmPDRRepositoryChgEvent
 *  @param[in] change_record_data_size - Length of change_record_data
 *  @param[out] event_data_operation - This field indicates the changeEntries
 * operation types
 *  @param[out] number_of_change_entries - The number of changeEntries following
 * this field
 *  @param[out] change_entry_data_offset - Identifies where changeEntries data
 * is located within change_record_data
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'change_record_data'
 */
int decode_pldm_pdr_repository_change_record_data(
	const uint8_t *change_record_data, size_t change_record_data_size,
	uint8_t *event_data_operation, uint8_t *number_of_change_entries,
	size_t *change_entry_data_offset);

/* GetSensorReading */

/** @brief Encode GetSensorReading request data
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] sensor_id - A handle that is used to identify and access the
 *         sensor
 *  @param[in] rearm_event_state - true =  manually re-arm EventState after
 *         responding to this request, false = no manual re-arm
 *  @param[out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note	Caller is responsible for memory alloc and dealloc of param
 * 		'msg.payload'
 */
int encode_get_sensor_reading_req(uint8_t instance_id, uint16_t sensor_id,
				  bool8_t rearm_event_state,
				  struct pldm_msg *msg);

/** @brief Decode GetSensorReading response data
 *
 *  @param[in] msg - Request message
 *  @param[in] payload_length - Length of response message payload
 *  @param[out] completion_code - PLDM completion code
 *  @param[out] sensor_data_size - The bit width and format of reading and
 *         threshold values
 *  @param[out] sensor_operational_state - The state of the sensor itself
 *  @param[out] sensor_event_message_enable - value: { noEventGeneration,
 *         eventsDisabled, eventsEnabled, opEventsOnlyEnabled,
 *         stateEventsOnlyEnabled }
 *  @param[out] present_state - The most recently assessed state value monitored
 *         by the sensor
 *  @param[out] previous_state - The state that the presentState was entered
 *         from
 *  @param[out] event_state - Indicates which threshold crossing assertion
 *         events have been detected
 *  @param[out] present_reading - The present value indicated by the sensor
 *  @return pldm_completion_codes
 */

int decode_get_sensor_reading_resp(
	const struct pldm_msg *msg, size_t payload_length,
	uint8_t *completion_code, uint8_t *sensor_data_size,
	uint8_t *sensor_operational_state, uint8_t *sensor_event_message_enable,
	uint8_t *present_state, uint8_t *previous_state, uint8_t *event_state,
	uint8_t *present_reading);

/** @brief Encode the SetEventReceiver request message
 *
 * @param[in] instance_id - Message's instance id
 * @param[in] event_message_global_enable - This value is used to enable or
 *        disable event message generation from the terminus value: {
 *        disable, enableAsync, enablePolling, enableAsyncKeepAlive }
 * @param[in] transport_protocol_type - This value is provided in the request
 *        to help the responder verify that the content of the
 *        eventReceiverAddressInfo field used in this request is correct for
 *        the messaging protocol supported by the terminus.
 * @param[in] event_receiver_address_info - this value is a medium and
 *        protocol-specific address that the responder should use when
 *        transmitting event messages using the indicated protocol
 * @param[in] heartbeat_timer - Amount of time in seconds after each elapsing
 *        of which the terminus shall emit a heartbeat event to the receiver
 * @param[out] msg - Argument to capture the Message
 * @return pldm_completion_codes
 */
int encode_set_event_receiver_req(uint8_t instance_id,
				  uint8_t event_message_global_enable,
				  uint8_t transport_protocol_type,
				  uint8_t event_receiver_address_info,
				  uint16_t heartbeat_timer,
				  struct pldm_msg *msg);

/** @brief Decode the SetEventReceiver response message
 *
 * @param[in] msg - Request message
 * @param[in] payload_length - Length of response message payload
 * @param[out] completion_code - PLDM completion code
 * @return pldm_completion_codes
 */
int decode_set_event_receiver_resp(const struct pldm_msg *msg,
				   size_t payload_length,
				   uint8_t *completion_code);

/** @brief Decode the SetEventReceiver request message
 *
 * @param[in] msg - Request message
 * @param[in] payload_length - Length of request message payload
 * @param[out] event_message_global_enable - This value is used to enable or
 *        disable event message generation from the terminus value: {
 *        disable, enableAsync, enablePolling, enableAsyncKeepAlive }
 * @param[out] transport_protocol_type - This value is provided in the request
 *        to help the responder verify that the content of the
 *        eventReceiverAddressInfo field used in this request is correct for
 *        the messaging protocol supported by the terminus.
 * @param[out] event_receiver_address_info - This value is a medium and
 *        protocol-specific address that the responder should use when
 *        transmitting event messages using the indicated protocol
 * @param[out] heartbeat_timer - Amount of time in seconds after each elapsing
 *        of which the terminus shall emit a heartbeat event to the receiver
 * @return pldm_completion_codes
 */
int decode_set_event_receiver_req(const struct pldm_msg *msg,
				  size_t payload_length,
				  uint8_t *event_message_global_enable,
				  uint8_t *transport_protocol_type,
				  uint8_t *event_receiver_address_info,
				  uint16_t *heartbeat_timer);

/** @brief Encode the SetEventReceiver response message
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] completion_code - PLDM completion code
 *  @param[out] msg - Argument to capture the Message
 *  @return pldm_completion_codes
 */
int encode_set_event_receiver_resp(uint8_t instance_id, uint8_t completion_code,
				   struct pldm_msg *msg);

#ifdef __cplusplus
}
#endif

#endif /* PLATFORM_H */
