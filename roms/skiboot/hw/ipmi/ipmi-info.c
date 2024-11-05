// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Various bits of info retreived over IPMI
 *
 * Copyright 2018-2019 IBM Corp.
 */

#include <device.h>
#include <skiboot.h>
#include <stdlib.h>
#include <ipmi.h>
#include <mem_region-malloc.h>
#include <opal.h>
#include <timebase.h>

/*
 * Response data from IPMI Get device ID command (As defined in
 * Section 20.1 Get Device ID Command - IPMI standard spec).
 */
struct ipmi_dev_id {
	uint8_t	dev_id;
	uint8_t	dev_revision;
	uint8_t	fw_rev1;
	uint8_t	fw_rev2;
	uint8_t	ipmi_ver;
	uint8_t	add_dev_support;
	uint8_t	manufactur_id[3];
	uint8_t	product_id[2];
	uint8_t	aux_fw_rev[4];
};
static struct ipmi_dev_id *ipmi_dev_id;

/*
 * Response data from IPMI Chassis Get System Boot Option (As defined in
 * Section 28.13 Get System Boot Options Command - IPMI standard spec).
 */
struct ipmi_sys_boot_opt {
	uint8_t param_version;
	uint8_t param_valid;
	/*
	 * Fields for OEM parameter 0x62. This parameter does not follow
	 * the normal layout and just has a single byte to signal if it
	 * is active or not.
	 */
	uint8_t flag_set;
};
static struct ipmi_sys_boot_opt *ipmi_sys_boot_opt;

/* Got response from BMC? */
static bool bmc_info_waiting = false;
static bool bmc_info_valid = false;
static bool bmc_boot_opt_waiting = false;
static bool bmc_boot_opt_valid = false;

/* This will free ipmi_dev_id structure */
void ipmi_dt_add_bmc_info(void)
{
	char buf[8];
	struct dt_node *dt_fw_version;

	while (bmc_info_waiting)
		time_wait_ms(5);

	if (!bmc_info_valid)
		return;

	dt_fw_version = dt_find_by_name(dt_root, "ibm,firmware-versions");
	if (!dt_fw_version) {
		free(ipmi_dev_id);
		return;
	}

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf), "%x.%02x",
		 ipmi_dev_id->fw_rev1, ipmi_dev_id->fw_rev2);
	dt_add_property_string(dt_fw_version, "bmc-firmware-version", buf);

	free(ipmi_dev_id);
}

static void ipmi_get_bmc_info_resp(struct ipmi_msg *msg)
{
	bmc_info_waiting = false;

	if (msg->cc != IPMI_CC_NO_ERROR) {
		prlog(PR_ERR, "IPMI: IPMI_BMC_GET_DEVICE_ID cmd returned error"
		      " [rc : 0x%x]\n", msg->data[0]);
		return;
	}

	/* ipmi_dev_id has optional fields */
	if (msg->resp_size <= sizeof(struct ipmi_dev_id)) {
		bmc_info_valid = true;
		memcpy(ipmi_dev_id, msg->data, msg->resp_size);
	} else {
		prlog(PR_WARNING, "IPMI: IPMI_BMC_GET_DEVICE_ID unexpected response size\n");
	}

	ipmi_free_msg(msg);
}

int ipmi_get_bmc_info_request(void)
{
	int rc;
	struct ipmi_msg *msg;

	ipmi_dev_id = zalloc(sizeof(struct ipmi_dev_id));
	assert(ipmi_dev_id);

	msg = ipmi_mkmsg(IPMI_DEFAULT_INTERFACE, IPMI_BMC_GET_DEVICE_ID,
			 ipmi_get_bmc_info_resp, NULL, NULL,
			 0, sizeof(struct ipmi_dev_id));
	if (!msg)
		return OPAL_NO_MEM;

	msg->error = ipmi_get_bmc_info_resp;
	prlog(PR_INFO, "IPMI: Requesting IPMI_BMC_GET_DEVICE_ID\n");
	rc = ipmi_queue_msg(msg);
	if (rc) {
		prlog(PR_ERR, "IPMI: Failed to queue IPMI_BMC_GET_DEVICE_ID\n");
		ipmi_free_msg(msg);
		return rc;
	}

	bmc_info_waiting = true;
	return rc;
}

/* This will free ipmi_sys_boot_opt structure */
int ipmi_chassis_check_sbe_validation(void)
{
	int rc = -1;

	while (bmc_boot_opt_waiting)
		time_wait_ms(10);

	if (!bmc_boot_opt_valid)
		goto out;

	if ((ipmi_sys_boot_opt->param_valid & 0x8) != 0)
		goto out;
	if (ipmi_sys_boot_opt->param_valid != 0x62)
		goto out;

	rc = ipmi_sys_boot_opt->flag_set;

out:
	free(ipmi_sys_boot_opt);
	return rc;
}

static void ipmi_get_chassis_boot_opt_resp(struct ipmi_msg *msg)
{
	bmc_boot_opt_waiting = false;

	if (msg->cc != IPMI_CC_NO_ERROR) {
		prlog(PR_INFO, "IPMI: IPMI_CHASSIS_GET_BOOT_OPT cmd returned error"
		      " [rc : 0x%x]\n", msg->data[0]);
		ipmi_free_msg(msg);
		return;
	}

	if (msg->resp_size == sizeof(struct ipmi_sys_boot_opt)) {
		bmc_boot_opt_valid = true;
		memcpy(ipmi_sys_boot_opt, msg->data, msg->resp_size);
	} else {
		prlog(PR_WARNING, "IPMI: IPMI_CHASSIS_GET_BOOT_OPT unexpected response size\n");
	}

	ipmi_free_msg(msg);
}

int ipmi_get_chassis_boot_opt_request(void)
{
	int rc;
	struct ipmi_msg *msg;
	uint8_t req[] = {
		0x62, /* OEM parameter (SBE Validation on astbmc) */
		0x00, /* no set selector */
		0x00, /* no block selector */
	};

	ipmi_sys_boot_opt = zalloc(sizeof(struct ipmi_sys_boot_opt));
	assert(ipmi_sys_boot_opt);

	msg = ipmi_mkmsg(IPMI_DEFAULT_INTERFACE, IPMI_CHASSIS_GET_BOOT_OPT,
			 ipmi_get_chassis_boot_opt_resp, NULL, req,
			 sizeof(req), sizeof(struct ipmi_sys_boot_opt));
	if (!msg) {
		free(ipmi_sys_boot_opt);
		return OPAL_NO_MEM;
	}

	msg->error = ipmi_get_chassis_boot_opt_resp;
	prlog(PR_INFO, "IPMI: Requesting IPMI_CHASSIS_GET_BOOT_OPT\n");
	rc = ipmi_queue_msg(msg);
	if (rc) {
		prlog(PR_ERR, "IPMI: Failed to queue IPMI_CHASSIS_GET_BOOT_OPT\n");
		free(ipmi_sys_boot_opt);
		ipmi_free_msg(msg);
		return rc;
	}

	bmc_boot_opt_waiting = true;
	return rc;
}
