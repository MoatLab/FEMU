// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2018 IBM Corp. */

#ifndef __ERRORLOG_H
#define __ERRORLOG_H

#include <compiler.h>
#include <opal.h>
#include <stdint.h>
#include <ccan/list/list.h>

/* Classification of error/events type reported on OPAL */
/* Platform Events/Errors: Report Machine Check Interrupt */
#define OPAL_PLATFORM_ERR_EVT		0x01
/* INPUT_OUTPUT: Report all I/O related events/errors */
#define OPAL_INPUT_OUTPUT_ERR_EVT	0x02
/* RESOURCE_DEALLOC: Hotplug events and errors */
#define OPAL_RESOURCE_DEALLOC_ERR_EVT	0x03
/* MISC: Miscellaneous error */
#define OPAL_MISC_ERR_EVT		0x04

/* OPAL Subsystem IDs listed for reporting events/errors */
#define OPAL_PROCESSOR_SUBSYSTEM	0x10
#define OPAL_MEMORY_SUBSYSTEM		0x20
#define OPAL_IO_SUBSYSTEM		0x30
#define OPAL_IO_DEVICES			0x40
#define OPAL_CEC_HARDWARE		0x50
#define OPAL_POWER_COOLING		0x60
#define OPAL_MISC_SUBSYSTEM		0x70
#define OPAL_SURVEILLANCE_ERR		0x7A
#define OPAL_PLATFORM_FIRMWARE		0x80
#define OPAL_SOFTWARE			0x90
#define OPAL_EXTERNAL_ENV		0xA0

/*
 * During reporting an event/error the following represents
 * how serious the logged event/error is. (Severity)
 */
#define OPAL_INFO						0x00
#define OPAL_RECOVERED_ERR_GENERAL				0x10

/* 0x2X series is to denote set of Predictive Error */
/* 0x20 Generic predictive error */
#define OPAL_PREDICTIVE_ERR_GENERAL				0x20
/* 0x21 Predictive error, degraded performance */
#define OPAL_PREDICTIVE_ERR_DEGRADED_PERF			0x21
/* 0x22 Predictive error, fault may be corrected after reboot */
#define OPAL_PREDICTIVE_ERR_FAULT_RECTIFY_REBOOT		0x22
/*
 * 0x23 Predictive error, fault may be corrected after reboot,
 * degraded performance
 */
#define OPAL_PREDICTIVE_ERR_FAULT_RECTIFY_BOOT_DEGRADE_PERF	0x23
/* 0x24 Predictive error, loss of redundancy */
#define OPAL_PREDICTIVE_ERR_LOSS_OF_REDUNDANCY			0x24

/* 0x4X series for Unrecoverable Error */
/* 0x40 Generic Unrecoverable error */
#define OPAL_UNRECOVERABLE_ERR_GENERAL				0x40
/* 0x41 Unrecoverable error bypassed with degraded performance */
#define OPAL_UNRECOVERABLE_ERR_DEGRADE_PERF			0x41
/* 0x44 Unrecoverable error bypassed with loss of redundancy */
#define OPAL_UNRECOVERABLE_ERR_LOSS_REDUNDANCY			0x44
/* 0x45 Unrecoverable error bypassed with loss of redundancy and performance */
#define OPAL_UNRECOVERABLE_ERR_LOSS_REDUNDANCY_PERF		0x45
/* 0x48 Unrecoverable error bypassed with loss of function */
#define OPAL_UNRECOVERABLE_ERR_LOSS_OF_FUNCTION			0x48
/* 0x50 In case of PANIC	*/
#define OPAL_ERROR_PANIC					0x50

/*
 * OPAL Event Sub-type
 * This field provides additional information on the non-error
 * event type
 */
#define OPAL_NA						0x00
#define OPAL_MISCELLANEOUS_INFO_ONLY			0x01
#define OPAL_PREV_REPORTED_ERR_RECTIFIED		0x10
#define OPAL_SYS_RESOURCES_DECONFIG_BY_USER		0x20
#define OPAL_SYS_RESOURCE_DECONFIG_PRIOR_ERR		0x21
#define OPAL_RESOURCE_DEALLOC_EVENT_NOTIFY		0x22
#define OPAL_CONCURRENT_MAINTENANCE_EVENT		0x40
#define OPAL_CAPACITY_UPGRADE_EVENT			0x60
#define OPAL_RESOURCE_SPARING_EVENT			0x70
#define OPAL_DYNAMIC_RECONFIG_EVENT			0x80
#define OPAL_NORMAL_SYS_PLATFORM_SHUTDOWN		0xD0
#define OPAL_ABNORMAL_POWER_OFF				0xE0

/* Max user dump size is 14K	*/
#define OPAL_LOG_MAX_DUMP	14336

/* Origin of error, elog_origin */
#define ORG_SAPPHIRE	1
#define ORG_POWERNV	2

/* Multiple user data sections */
struct elog_user_data_section {
	__be32 tag;
	__be16 size;
	__be16 component_id;
	char data_dump[1];
} __packed;

/*
 * All the information regarding an error/event to be reported
 * needs to populate this structure using pre-defined interfaces
 * only
 */
struct errorlog {

	uint16_t component_id;
	uint8_t error_event_type;
	uint8_t subsystem_id;

	uint8_t event_severity;
	uint8_t event_subtype;
	uint8_t user_section_count;
	uint8_t elog_origin;

	uint32_t user_section_size;
	uint32_t reason_code;
	uint32_t additional_info[4];

	uint32_t plid;
	uint32_t log_size;
	uint64_t elog_timeout;

	char user_data_dump[OPAL_LOG_MAX_DUMP];
	struct list_node link;
};

struct opal_err_info {
	uint32_t reason_code;
	uint8_t err_type;
	uint16_t cmp_id;
	uint8_t subsystem;
	uint8_t sev;
	uint8_t event_subtype;
};

/* Component IDs */
/* In PEL error log format, Creator ID is hypervisor
 * But we can have various component ID to distinguish
 * which component in hypervisor is reporting the error
 * This is 2 bytes long,
 *	first byte corresponds to Component IDs
 *	Second byte is reserved for the Reason code.
 * Component ID is mapped to readable 4-digit ascii
 * character name in FSP and displayed.
 */
/* SAPPHIRE components */
#define OPAL_CODEUPDATE				0x4355  /* CU */
#define OPAL_CONSOLE				0x434E  /* CN */
#define OPAL_CEC				0x4345  /* CE */
#define OPAL_CHIP				0x4348  /* CH */
#define OPAL_ELOG				0x454C  /* EL */
#define OPAL_NVRAM				0x4E56  /* NV */
#define OPAL_RTC				0x5254  /* RT */
#define OPAL_SURVEILLANCE			0x5355  /* SU */
#define OPAL_SYSPARAM				0x5350  /* SP */
#define OPAL_LPC				0x4C50  /* LP */
#define OPAL_UART				0x5541  /* UA */
#define OPAL_OCC				0x4F43  /* OC */
#define OPAL_OP_PANEL				0x4F50  /* OP */
#define OPAL_PHB				0x5048  /* PH */
#define OPAL_PSI				0x5053  /* PS */
#define OPAL_VPD				0x5650  /* VP */
#define OPAL_XSCOM				0x5853  /* XS */
#define OPAL_PCI				0x5043  /* PC */
#define OPAL_MISC				0x4D49  /* MI */
#define OPAL_ATTN				0x4154  /* AT */
#define OPAL_MEM_ERR				0x4D45  /* ME */
#define OPAL_CENTAUR				0x4354  /* CT */
#define OPAL_MFSI				0x4D46  /* MF */
#define OPAL_DUMP				0x4455  /* DU */
#define OPAL_LED				0x4C45  /* LE */
#define OPAL_SENSOR				0x5345  /* SE */
#define OPAL_SLW				0x534C  /* SL */
#define OPAL_FSP				0x4650  /* FP */
#define OPAL_I2C				0x4943  /* IC */
#define OPAL_IPMI				0x4950  /* IP */

/* SAPPHIRE SRC component ID*/
#define OPAL_SRC_COMPONENT_CODE_UPDATE		0x1000
#define OPAL_SRC_COMPONENT_XSCOM		0x1100
#define OPAL_SRC_COMPONENT_PCI			0x1200
#define OPAL_SRC_COMPONENT_MISC			0x1300
#define OPAL_SRC_COMPONENT_ATTN			0x1400
#define OPAL_SRC_COMPONENT_MEM_ERR		0x1500
#define OPAL_SRC_COMPONENT_CENTAUR		0x1600
#define OPAL_SRC_COMPONENT_MFSI			0x1700
#define OPAL_SRC_COMPONENT_DUMP			0x1800
#define OPAL_SRC_COMPONENT_LED			0x1900
#define OPAL_SRC_COMPONENT_VPD			0x1a00
#define OPAL_SRC_COMPONENT_CONSOLE		0x1b00
#define OPAL_SRC_COMPONENT_SENSOR		0x2000
#define OPAL_SRC_COMPONENT_SLW			0x2100
#define OPAL_SRC_COMPONENT_FSP			0x2200
#define OPAL_SRC_COMPONENT_I2C			0x2300
#define OPAL_SRC_COMPONENT_IPMI			0x2400
#define OPAL_SRC_COMPONENT_CEC			0x3000
#define OPAL_SRC_COMPONENT_CHIP			0x4000
#define OPAL_SRC_COMPONENT_ELOG			0x5000
#define OPAL_SRC_COMPONENT_NVRAM		0x6000
#define OPAL_SRC_COMPONENT_RTC			0x7000
#define OPAL_SRC_COMPONENT_SURVEILLANCE		0x8000
#define OPAL_SRC_COMPONENT_SYSPARAM		0x9000
#define OPAL_SRC_COMPONENT_LPC			0xa000
#define OPAL_SRC_COMPONENT_UART			0xb000
#define OPAL_SRC_COMPONENT_OCC			0xc000
#define OPAL_SRC_COMPONENT_OP_PANEL		0xd000
#define OPAL_SRC_COMPONENT_PHB			0xe000
#define OPAL_SRC_COMPONENT_PSI			0xf000

enum opal_reasoncode {
/* code update */
	OPAL_RC_CU_FLASH	    = OPAL_SRC_COMPONENT_CODE_UPDATE | 0x10,
	OPAL_RC_CU_INIT		    = OPAL_SRC_COMPONENT_CODE_UPDATE | 0x11,
	OPAL_RC_CU_SG_LIST	    = OPAL_SRC_COMPONENT_CODE_UPDATE | 0x12,
	OPAL_RC_CU_COMMIT	    = OPAL_SRC_COMPONENT_CODE_UPDATE | 0x13,
	OPAL_RC_CU_MSG		    = OPAL_SRC_COMPONENT_CODE_UPDATE | 0x14,
	OPAL_RC_CU_NOTIFY	    = OPAL_SRC_COMPONENT_CODE_UPDATE | 0x15,
	OPAL_RC_CU_MARKER_LID	    = OPAL_SRC_COMPONENT_CODE_UPDATE | 0x16,
/* NVRAM */
	OPAL_RC_NVRAM_INIT	    = OPAL_SRC_COMPONENT_NVRAM | 0x10,
	OPAL_RC_NVRAM_OPEN	    = OPAL_SRC_COMPONENT_NVRAM | 0x11,
	OPAL_RC_NVRAM_SIZE	    = OPAL_SRC_COMPONENT_NVRAM | 0x12,
	OPAL_RC_NVRAM_WRITE	    = OPAL_SRC_COMPONENT_NVRAM | 0x13,
	OPAL_RC_NVRAM_READ	    = OPAL_SRC_COMPONENT_NVRAM | 0x14,
/* CENTAUR */
	OPAL_RC_CENTAUR_INIT	    = OPAL_SRC_COMPONENT_CENTAUR | 0x10,
	OPAL_RC_CENTAUR_RW_ERR	    = OPAL_SRC_COMPONENT_CENTAUR | 0x11,
/* MFSI */
	OPAL_RC_MFSI_RW_ERR	    = OPAL_SRC_COMPONENT_MFSI | 0x10,
/* UART */
	OPAL_RC_UART_INIT	    = OPAL_SRC_COMPONENT_UART | 0x10,
/* OCC */
	OPAL_RC_OCC_RESET	    = OPAL_SRC_COMPONENT_OCC | 0x10,
	OPAL_RC_OCC_LOAD	    = OPAL_SRC_COMPONENT_OCC | 0x11,
	OPAL_RC_OCC_PSTATE_INIT	    = OPAL_SRC_COMPONENT_OCC | 0x12,
	OPAL_RC_OCC_TIMEOUT	    = OPAL_SRC_COMPONENT_OCC | 0x13,
/* RTC	*/
	OPAL_RC_RTC_READ	    = OPAL_SRC_COMPONENT_RTC | 0x10,
	OPAL_RC_RTC_TOD		    = OPAL_SRC_COMPONENT_RTC | 0x11,
/* SURVEILLANCE */
	OPAL_RC_SURVE_INIT	    = OPAL_SRC_COMPONENT_SURVEILLANCE | 0x10,
	OPAL_RC_SURVE_STATUS	    = OPAL_SRC_COMPONENT_SURVEILLANCE | 0x11,
	OPAL_RC_SURVE_ACK	    = OPAL_SRC_COMPONENT_SURVEILLANCE | 0x12,
	OPAL_INJECTED_HIR	    = OPAL_SRC_COMPONENT_SURVEILLANCE | 0x13,
/* SYSPARAM */
	OPAL_RC_SYSPARM_INIT	    = OPAL_SRC_COMPONENT_SYSPARAM | 0x10,
	OPAL_RC_SYSPARM_MSG	    = OPAL_SRC_COMPONENT_SYSPARAM | 0x11,
/* LPC */
	OPAL_RC_LPC_READ	    = OPAL_SRC_COMPONENT_LPC | 0x10,
	OPAL_RC_LPC_WRITE	    = OPAL_SRC_COMPONENT_LPC | 0x11,
	OPAL_RC_LPC_SYNC	    = OPAL_SRC_COMPONENT_LPC | 0x12,
	OPAL_RC_LPC_SYNC_PERF	    = OPAL_SRC_COMPONENT_LPC | 0x13,
/* OP_PANEL */
	OPAL_RC_PANEL_WRITE	    = OPAL_SRC_COMPONENT_OP_PANEL | 0x10,
/* PSI */
	OPAL_RC_PSI_INIT	    = OPAL_SRC_COMPONENT_PSI | 0x10,
	OPAL_RC_PSI_IRQ_RESET	    = OPAL_SRC_COMPONENT_PSI | 0x11,
	OPAL_RC_PSI_TIMEOUT	    = OPAL_SRC_COMPONENT_PSI | 0X12,
/* XSCOM */
	OPAL_RC_XSCOM_RW	    = OPAL_SRC_COMPONENT_XSCOM | 0x10,
	OPAL_RC_XSCOM_INDIRECT_RW   = OPAL_SRC_COMPONENT_XSCOM | 0x11,
	OPAL_RC_XSCOM_RESET	    = OPAL_SRC_COMPONENT_XSCOM | 0x12,
	OPAL_RC_XSCOM_BUSY	    = OPAL_SRC_COMPONENT_XSCOM | 0x13,
/* PCI */
	OPAL_RC_PCI_INIT_SLOT	    = OPAL_SRC_COMPONENT_PCI | 0x10,
	OPAL_RC_PCI_ADD_SLOT	    = OPAL_SRC_COMPONENT_PCI | 0x11,
	OPAL_RC_PCI_SCAN	    = OPAL_SRC_COMPONENT_PCI | 0x12,
	OPAL_RC_PCI_RESET_PHB	    = OPAL_SRC_COMPONENT_PCI | 0x10,
/* ATTN */
	OPAL_RC_ATTN		    = OPAL_SRC_COMPONENT_ATTN | 0x10,
/* MEM_ERR */
	OPAL_RC_MEM_ERR_RES	    = OPAL_SRC_COMPONENT_MEM_ERR | 0x10,
	OPAL_RC_MEM_ERR_DEALLOC	    = OPAL_SRC_COMPONENT_MEM_ERR | 0x11,
/* DUMP */
	OPAL_RC_DUMP_INIT	    = OPAL_SRC_COMPONENT_DUMP | 0x10,
	OPAL_RC_DUMP_LIST	    = OPAL_SRC_COMPONENT_DUMP | 0x11,
	OPAL_RC_DUMP_ACK	    = OPAL_SRC_COMPONENT_DUMP | 0x12,
	OPAL_RC_DUMP_MDST_INIT	    = OPAL_SRC_COMPONENT_DUMP | 0x13,
	OPAL_RC_DUMP_MDST_UPDATE    = OPAL_SRC_COMPONENT_DUMP | 0x14,
	OPAL_RC_DUMP_MDST_ADD	    = OPAL_SRC_COMPONENT_DUMP | 0x15,
	OPAL_RC_DUMP_MDST_REMOVE    = OPAL_SRC_COMPONENT_DUMP | 0x16,
/* LED	*/
	OPAL_RC_LED_SPCN	    = OPAL_SRC_COMPONENT_LED | 0x10,
	OPAL_RC_LED_BUFF	    = OPAL_SRC_COMPONENT_LED | 0x11,
	OPAL_RC_LED_LC		    = OPAL_SRC_COMPONENT_LED | 0x12,
	OPAL_RC_LED_STATE	    = OPAL_SRC_COMPONENT_LED | 0x13,
	OPAL_RC_LED_SUPPORT	    = OPAL_SRC_COMPONENT_LED | 0x14,
/* SENSOR */
	OPAL_RC_SENSOR_INIT	    = OPAL_SRC_COMPONENT_SENSOR | 0x10,
	OPAL_RC_SENSOR_READ	    = OPAL_SRC_COMPONENT_SENSOR | 0x11,
	OPAL_RC_SENSOR_ASYNC_COMPLETE
				    = OPAL_SRC_COMPONENT_SENSOR | 0x12,
/* SLW */
	OPAL_RC_SLW_INIT	    = OPAL_SRC_COMPONENT_SLW | 0x10,
	OPAL_RC_SLW_SET		    = OPAL_SRC_COMPONENT_SLW | 0x11,
	OPAL_RC_SLW_GET		    = OPAL_SRC_COMPONENT_SLW | 0x12,
	OPAL_RC_SLW_REG		    = OPAL_SRC_COMPONENT_SLW | 0x13,
/* FSP	*/
	OPAL_RC_FSP_POLL_TIMEOUT    = OPAL_SRC_COMPONENT_FSP | 0x10,
	OPAL_RC_FSP_MBOX_ERR	    = OPAL_SRC_COMPONENT_FSP | 0x11,
	OPAL_RC_FSP_DISR_HIR_MASK   = OPAL_SRC_COMPONENT_FSP | 0x12,
/* I2C */
	OPAL_RC_I2C_INIT	    = OPAL_SRC_COMPONENT_I2C | 0X10,
	OPAL_RC_I2C_START_REQ	    = OPAL_SRC_COMPONENT_I2C | 0X11,
	OPAL_RC_I2C_TIMEOUT	    = OPAL_SRC_COMPONENT_I2C | 0x12,
	OPAL_RC_I2C_TRANSFER	    = OPAL_SRC_COMPONENT_I2C | 0x13,
	OPAL_RC_I2C_RESET	    = OPAL_SRC_COMPONENT_I2C | 0x14,

/* IPMI */
	OPAL_RC_IPMI_REQ	    = OPAL_SRC_COMPONENT_IPMI | 0x10,
	OPAL_RC_IPMI_RESP	    = OPAL_SRC_COMPONENT_IPMI | 0x11,
	OPAL_RC_IPMI_DMA_ERROR_RESP
				    = OPAL_SRC_COMPONENT_IPMI | 0x12,

/* Platform error */
	OPAL_RC_ABNORMAL_REBOOT	    = OPAL_SRC_COMPONENT_CEC | 0x10,

/* FSP console */
	OPAL_RC_CONSOLE_HANG	    = OPAL_SRC_COMPONENT_CONSOLE | 0x10,
};

#define OPAL_ELOG_SEC_DESC	0x44455343

#define DEFINE_LOG_ENTRY(reason, type, id, subsys,			\
severity, subtype) static struct opal_err_info err_##reason =		\
{ .reason_code = reason, .err_type = type, .cmp_id = id,		\
.subsystem = subsys, .sev = severity, .event_subtype = subtype }

/* This is wrapper around the error log function, which creates
 * and commits the error to FSP.
 * Used for simple error logging.
 * Returns a Log ID, if an error involves a service processor needing
 * to be kicked, this logid can be sent to the service processor explaining
 * *why* we kicked it. Log Id = -1 on error.
 */
uint32_t log_simple_error(struct opal_err_info *e_info,
		const char *fmt, ...) __attribute__ ((format (printf, 2, 3)));

#define e_info(reason_code) err_##reason_code

struct errorlog *opal_elog_create(struct opal_err_info *e_info,
				  uint32_t tag) __warn_unused_result;
void log_add_section(struct errorlog *buf, uint32_t tag);
void log_append_data(struct errorlog *buf, unsigned char *data, uint16_t size);
void log_append_msg(struct errorlog *buf,
		const char *fmt, ...) __attribute__ ((format (printf, 2, 3)));
void log_commit(struct errorlog *elog);

/* Called by the backend after an error has been logged by the
 * backend. If the error could not be logged successfully success is
 * set to false. */
void opal_elog_complete(struct errorlog *elog, bool success);

int elog_init(void);

#endif /* __ERRORLOG_H */
