// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// Copyright 2022 IBM Corp.

#define pr_fmt(fmt) "PLDM: " fmt

#include <stdlib.h>
#include <string.h>
#include <device.h>
#include <ipmi.h>
#include <opal.h>
#include <lock.h>
#include <timebase.h>
#include <ccan/list/list.h>
#include "pldm.h"

#define BMC_VERSION_LENGTH 100

/*
 * Response data from IPMI Get device ID command (As defined in
 * Section 20.1 Get Device ID Command - IPMI standard spec).
 */
struct ipmi_dev_id {
	uint8_t dev_id;
	uint8_t dev_revision;
	uint8_t fw_rev1;
	uint8_t fw_rev2;
	uint8_t ipmi_ver;
	uint8_t add_dev_support;
	uint8_t manufactur_id[3];
	uint8_t product_id[2];
	uint8_t aux_fw_rev[4];
};

static struct lock msgq_lock = LOCK_UNLOCKED;
static struct list_head msgq = LIST_HEAD_INIT(msgq);
uint64_t opal_event_ipmi_recv;

static void opal_send_complete(struct ipmi_msg *msg)
{
	lock(&msgq_lock);
	list_add_tail(&msgq, &msg->link);
	opal_update_pending_evt(opal_event_ipmi_recv,
			opal_event_ipmi_recv);
	unlock(&msgq_lock);
}

#define GUID_SIZE 16

static int opal_get_tid_req(struct opal_ipmi_msg *opal_ipmi_msg,
			    uint64_t msg_len __unused)
{
	struct ipmi_msg *opal_ipmi_response = NULL;
	uint8_t guid[GUID_SIZE];
	int bmc_tid;

	opal_ipmi_response = zalloc(sizeof(struct ipmi_msg) + GUID_SIZE);
	opal_ipmi_response->netfn = IPMI_NETFN_RETURN_CODE(opal_ipmi_msg->netfn);
	opal_ipmi_response->cmd = opal_ipmi_msg->cmd;

	memset(&guid, 0, GUID_SIZE);

	/* First byte of guid contains bmc tid */
	bmc_tid = pldm_base_get_bmc_tid();
	if (bmc_tid == -1) {
		opal_ipmi_response->resp_size = 0;
		opal_ipmi_response->cc = IPMI_ERR_UNSPECIFIED;
		goto out;
	}

	guid[0] = (uint8_t)bmc_tid;
	memcpy(opal_ipmi_response->data, guid, GUID_SIZE);

	opal_ipmi_response->resp_size = GUID_SIZE;
	opal_ipmi_response->cc = IPMI_CC_NO_ERROR;

out:
	opal_send_complete(opal_ipmi_response);
	return OPAL_SUCCESS;
}

static int parse_bmc_version(uint8_t *bmc_version,
			     struct ipmi_dev_id *devid)
{
	uint8_t *ptr;
	uint8_t temp;

	prlog(PR_TRACE, "%s - bmc version: %s len=%d\n", __func__,
			bmc_version, (int)strlen(bmc_version));

	/*
	 * parse bmc version string to find fw_rev1 and fw_rev2
	 * Firmware Name is in format :
	 * fw1030.00-2.8-1030.2233.20220819a (NL1030_007)
	 * so fw_rev1 = 10
	 * fw_rev2 = 20
	 * aux_fw_rev = "007"
	 */
	ptr = strstr(bmc_version, "NL");
	if (ptr == NULL || strlen(ptr) < 8)
		return OPAL_PARAMETER;

	ptr += 2;
	/*
	 * Convert first two byte to
	 * fw_rev1 and net 2byte to fw_rev2
	 */
	temp = ptr[2];
	ptr[2] = '\0';
	devid->fw_rev1 = (uint8_t)atoi(ptr);
	ptr += 2;
	ptr[0] = temp;

	temp = ptr[2];
	ptr[2] = '\0';
	devid->fw_rev2 = (uint8_t)atoi(ptr);
	ptr += 2;
	ptr[0] = temp;

	/* Aux version is truncated to 4 char only */
	if (*ptr == '_')
		strncpy(devid->aux_fw_rev, ptr + 1, 3);

	prlog(PR_TRACE, "BMC Version major->%d minor->%d aux->%.4s\n",
			devid->fw_rev1, devid->fw_rev2, devid->aux_fw_rev);

	return OPAL_SUCCESS;
}

static int opal_get_bmc_info(struct opal_ipmi_msg *opal_ipmi_msg,
			     uint64_t msg_len __unused)
{
	struct ipmi_msg *opal_ipmi_response = NULL;
	char bmc_version[BMC_VERSION_LENGTH];
	struct ipmi_dev_id devid;
	int rc;

	opal_ipmi_response = zalloc(sizeof(struct ipmi_msg) +
				    sizeof(struct ipmi_dev_id));
	opal_ipmi_response->resp_size = sizeof(struct ipmi_dev_id);
	opal_ipmi_response->netfn = IPMI_NETFN_RETURN_CODE(opal_ipmi_msg->netfn);
	opal_ipmi_response->cmd = opal_ipmi_msg->cmd;
	opal_ipmi_response->cc = IPMI_CC_NO_ERROR;

	memset(&devid, 0, sizeof(devid));
	devid.ipmi_ver = OPAL_IPMI_MSG_FORMAT_VERSION_1;

	/* retrieve bmc version */
	rc = pldm_fru_get_bmc_version(bmc_version, BMC_VERSION_LENGTH);
	if (rc) {
		opal_ipmi_response->resp_size = 0;
		opal_ipmi_response->cc = IPMI_ERR_UNSPECIFIED;
		goto out;
	}

	/* parse the bmc version */
	rc = parse_bmc_version(bmc_version, &devid);
	if (rc) {
		prlog(PR_ERR, "%s: Failed to parse BMC version, bmc version: %s\n",
				__func__, bmc_version);
		opal_ipmi_response->resp_size = 0;
		opal_ipmi_response->cc = IPMI_ERR_UNSPECIFIED;
		goto out;
	}

	memcpy(opal_ipmi_response->data, &devid, sizeof(devid));

out:
	opal_send_complete(opal_ipmi_response);
	return OPAL_SUCCESS;
}

static int64_t opal_ipmi_send(uint64_t interface __unused,
			      struct opal_ipmi_msg *opal_ipmi_msg,
			      uint64_t msg_len)
{
	int16_t ipmi_code;

	if (opal_ipmi_msg->version != OPAL_IPMI_MSG_FORMAT_VERSION_1) {
		prerror("OPAL IPMI: Incorrect version\n");
		return OPAL_UNSUPPORTED;
	}

	msg_len -= sizeof(struct opal_ipmi_msg);
	if (msg_len > IPMI_MAX_REQ_SIZE) {
		prerror("OPAL IPMI: Invalid request length\n");
		return OPAL_PARAMETER;
	}

	ipmi_code = IPMI_CODE(opal_ipmi_msg->netfn >> 2, opal_ipmi_msg->cmd);
	if ((ipmi_code == IPMI_CHASSIS_GET_SYS_BOOT_OPT_CMD) ||
	    (opal_ipmi_msg->cmd == IPMI_CODE(opal_ipmi_msg->netfn >> 2, 0x1a)) ||
	    (opal_ipmi_msg->cmd == IPMI_CODE(opal_ipmi_msg->netfn >> 2, 0x42))) {
		prerror("OPAL IPMI: Command not supported, code: %d, "
			"cmd: 0x%x netfn: 0x%x\n",
			ipmi_code, opal_ipmi_msg->cmd, opal_ipmi_msg->netfn >> 2);
		return OPAL_UNSUPPORTED;
	}

	prlog(PR_TRACE, "%s - cmd: 0x%02x netfn: 0x%02x len: 0x%02llx\n",
			__func__, opal_ipmi_msg->cmd, opal_ipmi_msg->netfn >> 2,
			msg_len);

	switch (opal_ipmi_msg->cmd) {
	case IPMI_GET_DEVICE_ID_CMD:
		return opal_get_bmc_info(opal_ipmi_msg, msg_len);

	case IPMI_GET_DEVICE_GUID_CMD:
		return opal_get_tid_req(opal_ipmi_msg, msg_len);
	}

	prerror("OPAL IPMI: Command not supported, cmd: 0x%x netfn: 0x%x\n",
		 opal_ipmi_msg->cmd, opal_ipmi_msg->netfn >> 2);

	return OPAL_UNSUPPORTED;
}

static int64_t opal_ipmi_recv(uint64_t interface,
			      struct opal_ipmi_msg *opal_ipmi_msg,
			      __be64 *msg_len)
{
	struct ipmi_msg *msg;
	int64_t rc;

	lock(&msgq_lock);
	msg = list_top(&msgq, struct ipmi_msg, link);

	if (!msg) {
		rc = OPAL_EMPTY;
		goto out_unlock;
	}

	if (opal_ipmi_msg->version != OPAL_IPMI_MSG_FORMAT_VERSION_1) {
		prerror("OPAL IPMI: Incorrect version\n");
		rc = OPAL_UNSUPPORTED;
		goto out_del_msg;
	}

	if (interface != IPMI_DEFAULT_INTERFACE) {
		prerror("IPMI: Invalid interface 0x%llx in %s\n", interface, __func__);
		rc = OPAL_PARAMETER;
		goto out_del_msg;
	}

	if (be64_to_cpu(*msg_len) - sizeof(struct opal_ipmi_msg) < msg->resp_size + 1) {
		rc = OPAL_RESOURCE;
		goto out_del_msg;
	}

	list_del(&msg->link);
	if (list_empty(&msgq))
		opal_update_pending_evt(opal_event_ipmi_recv, 0);
	unlock(&msgq_lock);

	opal_ipmi_msg->cmd = msg->cmd;
	opal_ipmi_msg->netfn = msg->netfn;
	opal_ipmi_msg->data[0] = msg->cc;
	memcpy(&opal_ipmi_msg->data[1], msg->data, msg->resp_size);

	prlog(PR_TRACE, "%s - cmd: 0x%02x netfn: 0x%02x resp_size: 0x%02x\n",
			__func__, msg->cmd, msg->netfn >> 2, msg->resp_size);

	/* Add one as the completion code is returned in the message data */
	*msg_len = cpu_to_be64(msg->resp_size + sizeof(struct opal_ipmi_msg) + 1);
	free(msg);

	return OPAL_SUCCESS;

out_del_msg:
	list_del(&msg->link);
	if (list_empty(&msgq))
		opal_update_pending_evt(opal_event_ipmi_recv, 0);
	free(msg);

out_unlock:
	unlock(&msgq_lock);
	return rc;
}

void pldm_opal_init(void)
{
	struct dt_node *opal_ipmi, *opal_event = NULL;

	opal_ipmi = dt_new(opal_node, "ipmi");
	dt_add_property_strings(opal_ipmi, "compatible", "ibm,opal-ipmi");
	dt_add_property_cells(opal_ipmi, "ibm,ipmi-interface-id",
			      IPMI_DEFAULT_INTERFACE);
	opal_event_ipmi_recv = opal_dynamic_event_alloc();
	dt_add_property_cells(opal_ipmi, "interrupts",
			      ilog2(opal_event_ipmi_recv));

	opal_event = dt_find_by_name(opal_node, "event");
	if (opal_event)
		dt_add_property_cells(opal_ipmi, "interrupt-parent",
				      opal_event->phandle);

	opal_register(OPAL_IPMI_SEND, opal_ipmi_send, 3);
	opal_register(OPAL_IPMI_RECV, opal_ipmi_recv, 3);
}
