// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef __IPMI_H
#define __IPMI_H

#include <stdint.h>
#include <ccan/list/list.h>
#include <stdbool.h>
#include <types.h>

#define MAX_IPMI_SENSORS 255

/*
 * IPMI codes as defined by the standard.
 */
#define IPMI_GET_DEVICE_ID_CMD		0x01
#define IPMI_COLD_RESET_CMD		0x02
#define IPMI_WARM_RESET_CMD		0x03
#define IPMI_CLEAR_MSG_FLAGS_CMD	0x30
#define IPMI_GET_DEVICE_GUID_CMD	0x08
#define IPMI_GET_MSG_FLAGS_CMD		0x31
#define IPMI_SEND_MSG_CMD		0x34
#define IPMI_GET_MSG_CMD		0x33
#define IPMI_SET_BMC_GLOBAL_ENABLES_CMD	0x2e
#define IPMI_GET_BMC_GLOBAL_ENABLES_CMD	0x2f
#define IPMI_READ_EVENT_MSG_BUFFER_CMD	0x35
#define IPMI_GET_CHANNEL_INFO_CMD	0x42

/*
 * 28. Chassis Commands
 */
#define IPMI_CHASSIS_GET_CAP_CMD		0x00
#define IPMI_CHASSIS_GET_STATUS_CMD		0x01
#define IPMI_CHASSIS_CONTROL_CMD		0x02
#define IPMI_CHASSIS_RESET_CMD			0x03
#define IPMI_CHASSIS_IDENTIFY_CMD		0x04
#define IPMI_CHASSIS_SET_PANEL_BUTTON_EN_CMD	0x0a
#define IPMI_CHASSIS_SET_CAP_CMD		0x05
#define IPMI_CHASSIS_SET_PWR_RESTORE_CMD	0x06
#define IPMI_CHASSIS_SET_PWR_CYCLE_CMD		0x0b
#define IPMI_CHASSIS_GET_SYS_RESTART_CAUSE_CMD	0x07
#define IPMI_CHASSIS_SET_SYS_BOOT_OPT_CMD	0x08
#define IPMI_CHASSIS_GET_SYS_BOOT_OPT_CMD	0x09
#define IPMI_CHASSIS_GET_POH_COUNTER_CMD	0x0f


/* 28.3. Chassis Control Command */
#define   IPMI_CHASSIS_PWR_DOWN 		0x00
#define   IPMI_CHASSIS_PWR_UP			0x01
#define   IPMI_CHASSIS_PWR_CYCLE		0x02
#define   IPMI_CHASSIS_HARD_RESET		0x03
#define   IPMI_CHASSIS_PULSE_DIAG		0x04
#define   IPMI_CHASSIS_SOFT_SHUTDOWN		0x05

/* 20.7. ACPI Power State Command */
#define   IPMI_PWR_SYS_S0_WORKING		0x00
#define   IPMI_PWR_SYS_S1			0x01
#define   IPMI_PWR_SYS_S2			0x02
#define   IPMI_PWR_SYS_S3_SUSPEND_TO_RAM	0x03
#define   IPMI_PWR_SYS_S4_SUSPEND_TO_DISK	0x04
#define   IPMI_PWR_SYS_S5_SOFT_OFF		0x05
#define   IPMI_PWR_SYS_SUSPEND			0x06
#define   IPMI_PWR_SYS_LEGACY_ON		0x20
#define   IPMI_PWR_SYS_LEGACY_OFF		0x21
#define   IPMI_PWR_SYS_UNKNOWN			0x2a
#define   IPMI_PWR_NOCHANGE                     0x7f

/* 22.{3,4} Clear / Get message flags */
#define	IPMI_MESSAGE_FLAGS_RX_MESSAGE_QUEUE	(1<<0)
#define IPMI_MESSAGE_FLAGS_EVENT_BUFFER		(1<<1)
#define IPMI_MESSAGE_FLAGS_WATCHDOG_PRE_TIMEOUT	(1<<3)
#define IPMI_MESSAGE_FLAGS_OEM0			(1<<5)
#define IPMI_MESSAGE_FLAGS_OEM1			(1<<6)
#define IPMI_MESSAGE_FLAGS_OEM2			(1<<7)

/* Firmware Progress Sensor states */
#define IPMI_FW_PCI_INIT		0x07
#define IPMI_FW_OS_BOOT			0x13
#define IPMI_FW_MOTHERBOARD_INIT	0x14

#define IPMI_CODE(netfn, cmd)		((netfn) << 8 | (cmd))
#define IPMI_CMD(code)			((code) & 0xff)
#define IPMI_NETFN(code)		((code) >> 8 & 0xff)

#define IPMI_NETFN_RETURN_CODE(netfn)	((netfn) | 0x4)

#define IPMI_NETFN_CHASSIS		0x00
#define IPMI_NETFN_SE			0x04
#define IPMI_NETFN_STORAGE		0x0a
#define IPMI_NETFN_APP			0x06

#define IPMI_WRITE_FRU			IPMI_CODE(IPMI_NETFN_STORAGE, 0x12)
#define IPMI_GET_SEL_INFO		IPMI_CODE(IPMI_NETFN_STORAGE, 0x40)
#define IPMI_RESERVE_SEL		IPMI_CODE(IPMI_NETFN_STORAGE, 0x42)
#define IPMI_ADD_SEL_EVENT		IPMI_CODE(IPMI_NETFN_STORAGE, 0x44)
#define IPMI_GET_SEL_TIME		IPMI_CODE(IPMI_NETFN_STORAGE, 0x48)
#define IPMI_SET_SEL_TIME		IPMI_CODE(IPMI_NETFN_STORAGE, 0x49)
#define IPMI_CHASSIS_CONTROL		IPMI_CODE(IPMI_NETFN_CHASSIS, 0x02)
#define IPMI_CHASSIS_GET_BOOT_OPT	IPMI_CODE(IPMI_NETFN_CHASSIS, 0x09)
#define IPMI_BMC_GET_DEVICE_ID		IPMI_CODE(IPMI_NETFN_APP, 0x01)
#define IPMI_SET_POWER_STATE		IPMI_CODE(IPMI_NETFN_APP, 0x06)
#define IPMI_GET_POWER_STATE		IPMI_CODE(IPMI_NETFN_APP, 0x07)
#define IPMI_RESET_WDT			IPMI_CODE(IPMI_NETFN_APP, 0x22)
#define IPMI_SET_WDT			IPMI_CODE(IPMI_NETFN_APP, 0x24)
#define IPMI_SET_ENABLES		IPMI_CODE(IPMI_NETFN_APP, 0x2E)
#define IPMI_GET_ENABLES		IPMI_CODE(IPMI_NETFN_APP, 0x2F)
#define IPMI_CLEAR_MESSAGE_FLAGS	IPMI_CODE(IPMI_NETFN_APP, 0x30)
#define IPMI_GET_MESSAGE_FLAGS		IPMI_CODE(IPMI_NETFN_APP, 0x31)
#define IPMI_GET_MESSAGE		IPMI_CODE(IPMI_NETFN_APP, 0x33)
#define IPMI_READ_EVENT			IPMI_CODE(IPMI_NETFN_APP, 0x35)
#define IPMI_GET_BT_CAPS		IPMI_CODE(IPMI_NETFN_APP, 0x36)
#define IPMI_SET_SENSOR_READING		IPMI_CODE(IPMI_NETFN_SE, 0x30)

/*
 * IPMI response codes.
 */
#define IPMI_CC_NO_ERROR		0x00
#define IPMI_NODE_BUSY_ERR		0xc0
#define IPMI_INVALID_COMMAND_ERR	0xc1
#define IPMI_TIMEOUT_ERR		0xc3
#define IPMI_ERR_MSG_TRUNCATED		0xc6
#define IPMI_REQ_LEN_INVALID_ERR	0xc7
#define IPMI_REQ_LEN_EXCEEDED_ERR	0xc8
#define IPMI_NOT_IN_MY_STATE_ERR	0xd5	/* IPMI 2.0 */
#define IPMI_LOST_ARBITRATION_ERR	0x81
#define IPMI_BUS_ERR			0x82
#define IPMI_NAK_ON_WRITE_ERR		0x83
#define IPMI_ERR_UNSPECIFIED		0xff

#define IPMI_DEFAULT_INTERFACE		0

#define IPMI_MAX_REQ_SIZE		60
#define IPMI_MAX_RESP_SIZE		60

/*
 * As far as I can tell the size of PEL record is unbounded (due to
 * the possible presence of the user defined section). We chose this
 * size because it's what hostboot also uses and most of the OPAL logs
 * are few hundred bytes.
 */
#define IPMI_MAX_PEL_SIZE		0x800

struct ipmi_backend;
struct ipmi_msg {
	/* Can be used by command implementations to track requests */
	struct list_node link;

	struct ipmi_backend *backend;
	uint8_t netfn;
	uint8_t cmd;
	uint8_t cc;

	/* Called when a response is received to the ipmi message */
	void (*complete)(struct ipmi_msg *);

	/* Called if non-NULL when the ipmi layer detects an error */
	void (*error)(struct ipmi_msg *);
	void *user_data;

	uint8_t req_size;
	uint8_t resp_size;
	uint8_t *data;
};

struct ipmi_backend {
	uint64_t opal_event_ipmi_recv;
	struct ipmi_msg *(*alloc_msg)(size_t, size_t);
	void (*free_msg)(struct ipmi_msg *);
	int (*queue_msg)(struct ipmi_msg *);
	int (*queue_msg_head)(struct ipmi_msg *);
	int (*dequeue_msg)(struct ipmi_msg *);
	void (*disable_retry)(struct ipmi_msg *);
	/*
	 * When processing a synchronous IPMI message, pollers may not run, and
	 * neither may timers (as the synchronous IPMI message may be being
	 * done with locks held, which a timer may then try to also take).
	 *
	 * So, ensure we have a way to drive any state machines that an IPMI
	 * backend may neeed to crank to ensure forward progress.
	 */
	void (*poll)(void);
};

extern struct ipmi_backend *ipmi_backend;

/* Initialise the IPMI interface */
void ipmi_init(void);

bool ipmi_present(void);

void ipmi_free_msg(struct ipmi_msg *msg);

struct ipmi_msg *ipmi_mkmsg_simple(uint32_t code, void *req_data, size_t req_size);
struct ipmi_msg *ipmi_mkmsg(int interface, uint32_t code,
			    void (*complete)(struct ipmi_msg *),
			    void *user_data, void *req_data, size_t req_size,
			    size_t resp_size);

/* Initialise a previously allocated message with the required
fields. The caller must ensure the message is large enough to hold the
request and response data. */
void ipmi_init_msg(struct ipmi_msg *msg, int interface,
		   uint32_t code, void (*complete)(struct ipmi_msg *),
		   void *user_data, size_t req_size, size_t resp_size);

/* called by backend code to indicate a SMS_ATN event */
void ipmi_sms_attention(void);

/* Add an ipmi message to the queue */
int ipmi_queue_msg(struct ipmi_msg *msg);

/* Add an ipmi message to the start of the queue */
int ipmi_queue_msg_head(struct ipmi_msg *msg);

/* Synchronously send an ipmi message. This won't return until the
 * messages callback has been called. */
void ipmi_queue_msg_sync(struct ipmi_msg *msg);

/* Removes the message from the list, queued previously */
int ipmi_dequeue_msg(struct ipmi_msg *msg);

/* Process a completed message */
void ipmi_cmd_done(uint8_t cmd, uint8_t netfn, uint8_t cc, struct ipmi_msg *msg);

/* 28.3 Chassis Control Command. Changes the power state of the P8. */
int ipmi_chassis_control(uint8_t request);

/* 20.7 ACPI Power State Command (without the ACPI part). Informative only,
 * use chassis control to perform power off and reboot. */
int ipmi_set_power_state(uint8_t system, uint8_t device);

/* 35.17 Set Sensor Reading Command */
int ipmi_set_sensor(uint8_t sensor, uint8_t *reading, size_t len);
int ipmi_set_fw_progress_sensor(uint8_t state);

/* Register a backend with the ipmi core. Currently we only support one. */
void ipmi_register_backend(struct ipmi_backend *backend);

/* Allocate IPMI SEL panic message */
void ipmi_sel_init(void);

/* Register SEL handler with IPMI core */
int ipmi_sel_register(uint8_t oem_cmd,
		      void (*handler)(uint8_t data, void *context),
		      void *context);

/* Register rtc ipmi commands with as opal callbacks. */
void ipmi_rtc_init(void);

/* Register ipmi host interface access callbacks */
void ipmi_opal_init(void);

/* Populate fru data */
void ipmi_fru_init(uint8_t fru_dev_id);

/* Commit an error log to the bmc using the OEM add eSEL commands */
struct errorlog;
int ipmi_elog_commit(struct errorlog *elog_buf);

/* Callback to parse an OEM SEL message */
void ipmi_parse_sel(struct ipmi_msg *msg);

/* Starts the watchdog timer */
void ipmi_wdt_init(void);

/* Stop the wdt */
void ipmi_wdt_stop(void);

/* Reset the watchdog timer. Does not return until the timer has been
 * reset and does not schedule future resets. */
void ipmi_wdt_final_reset(void);

/* Discover id of settable ipmi sensors */
void ipmi_sensor_init(void);

/* Get sensor number for given sensor type */
uint8_t ipmi_get_sensor_number(uint8_t sensor_type);

/* Set the boot count once the OS is up and running */
int ipmi_set_boot_count(void);

/* Terminate immediate */
void __attribute__((noreturn)) ipmi_terminate(const char *msg);

/* Get BMC firmware info */
extern int ipmi_get_bmc_info_request(void);

/* Add BMC firmware info to device tree */
extern void ipmi_dt_add_bmc_info(void);

/* Get BMC Boot Options info (specifically OEM param 0x62) */
int ipmi_get_chassis_boot_opt_request(void);

/* Get OEM Boot Option 0x62 for SBE validation flag */
int ipmi_chassis_check_sbe_validation(void);

#endif
