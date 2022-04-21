// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * FSP Environmental and Power Warnings (EPOW) support
 *
 * Copyright 2013-2016 IBM Corp.
 */

#define pr_fmt(fmt) "FSP-EPOW: " fmt

#include <fsp.h>
#include <device.h>
#include <lock.h>
#include <opal-msg.h>
#include <opal-api.h>

#include "fsp-epow.h"

/*
 * System EPOW status
 *
 * This value is exported to the host. Each individual element in this
 * array [0...(OPAL_SYSEPOW_MAX-1)] contains bitwise EPOW event info
 * corresponding to particular defined EPOW sub class. For example.
 * opal_epow_status[OPAL_SYSEPOW_POWER] will reflect power related EPOW events.
 */
static int16_t epow_status[OPAL_SYSEPOW_MAX];

/* EPOW lock */
static struct lock epow_lock = LOCK_UNLOCKED;

/* Process FSP sent EPOW based information */
static void epow_process_ex1_event(u8 *epow)
{
	memset(epow_status, 0, sizeof(epow_status));

	if (epow[4] == EPOW_TMP_INT) {
		prlog(PR_INFO, "Internal temp above normal\n");
		epow_status[OPAL_SYSEPOW_TEMP] = OPAL_SYSTEMP_INT;

	} else if (epow[4] == EPOW_TMP_AMB) {
		prlog(PR_INFO, "Ambient temp above normal\n");
		epow_status[OPAL_SYSEPOW_TEMP] = OPAL_SYSTEMP_AMB;

	} else if (epow[4] == EPOW_ON_UPS) {
		prlog(PR_INFO, "System running on UPS power\n");
		epow_status[OPAL_SYSEPOW_POWER] = OPAL_SYSPOWER_UPS;

	}
}

/* Process EPOW event */
static void fsp_process_epow(struct fsp_msg *msg, int epow_type)
{
	int rc;
	u8 epow[8];
	bool epow_changed = false;
	int16_t old_epow_status[OPAL_SYSEPOW_MAX];

	/* Basic EPOW signature */
	if (msg->data.bytes[0] != 0xF2) {
		/**
		 * @fwts-label EPOWSignatureMismatch
		 * @fwts-advice Bug in skiboot/FSP code for EPOW event handling
		 */
		prlog(PR_ERR, "Signature mismatch\n");
		return;
	}

	lock(&epow_lock);

	/* Copy over and clear system EPOW status */
	memcpy(old_epow_status, epow_status, sizeof(old_epow_status));

	switch(epow_type) {
	case EPOW_NORMAL:
	case EPOW_EX2:
		break;
	case EPOW_EX1:
		epow[0] = msg->data.bytes[0];
		epow[1] = msg->data.bytes[1];
		epow[2] = msg->data.bytes[2];
		epow[3] = msg->data.bytes[3];
		epow[4] = msg->data.bytes[4];

		epow_process_ex1_event(epow);
		break;
	default:
		prlog(PR_WARNING, "Unknown EPOW event notification\n");
		break;
	}

	if (memcmp(epow_status, old_epow_status, sizeof(epow_status)))
		epow_changed = true;

	unlock(&epow_lock);

	/* Send OPAL message notification */
	if (epow_changed) {
		rc = opal_queue_msg(OPAL_MSG_EPOW, NULL, NULL);
		if (rc) {
			/**
			 * @fwts-label EPOWMessageQueueFailed
			 * @fwts-advice Queueing a message from OPAL to FSP
			 * failed. This is likely due to either an OPAL bug
			 * or the FSP going away.
			 */
			prlog(PR_ERR, "OPAL EPOW message queuing failed\n");
			return;
		}
		prlog(PR_INFO, "Notified host about EPOW event\n");
	}
}

/*
 * EPOW OPAL interface
 *
 * The host requests for the system EPOW status through this
 * OPAl call, where it passes a buffer with a give length.
 * Sapphire fills the buffer with updated system EPOW status
 * and then updates the length variable back to reflect the
 * number of EPOW sub classes it has updated the buffer with.
 */
static int64_t fsp_opal_get_epow_status(__be16 *out_epow, __be16 *length)
{
	int i;
	int n_epow_class;
	int l = be16_to_cpu(*length);

	/*
	 * There can be situations where the host and the Sapphire versions
	 * don't match with eact other and hence the expected system EPOW status
	 * details. Newer hosts might be expecting status for more number of EPOW
	 * sub classes which Sapphire may not know about and older hosts might be
	 * expecting status for EPOW sub classes which is a subset of what
	 * Sapphire really knows about. Both these situations are handled here.
	 *
	 * (A) Host version >= Sapphire version
	 *
	 * Sapphire sends out EPOW status for sub classes it knows about
	 * and keeps the status. Updates the length variable for the host.
	 *
	 * (B) Host version < Sapphire version
	 *
	 * Sapphire sends out EPOW status for sub classes host knows about
	 * and can interpret correctly.
	 */
	if (l >= OPAL_SYSEPOW_MAX) {
		n_epow_class = OPAL_SYSEPOW_MAX;
		*length = cpu_to_be16(OPAL_SYSEPOW_MAX);
	} else {
		n_epow_class = l;
	}

	/* Transfer EPOW Status */
	for (i = 0; i < n_epow_class; i++)
		out_epow[i] = cpu_to_be16(epow_status[i]);

	return OPAL_SUCCESS;
}

/* Handle EPOW sub-commands from FSP */
static bool fsp_epow_message(u32 cmd_sub_mod, struct fsp_msg *msg)
{
	switch(cmd_sub_mod) {
	case FSP_CMD_PANELSTATUS:
		fsp_process_epow(msg, EPOW_NORMAL);
		return true;
	case FSP_CMD_PANELSTATUS_EX1:
		fsp_process_epow(msg, EPOW_EX1);
		return true;
	case FSP_CMD_PANELSTATUS_EX2:
		fsp_process_epow(msg, EPOW_EX2);
		return true;
	}
	return false;
}

static struct fsp_client fsp_epow_client = {
	.message = fsp_epow_message,
};

void fsp_epow_init(void)
{
	struct dt_node *np;

	fsp_register_client(&fsp_epow_client, FSP_MCLASS_SERVICE);
	opal_register(OPAL_GET_EPOW_STATUS, fsp_opal_get_epow_status, 2);
	np = dt_new(opal_node, "epow");
	dt_add_property_strings(np, "compatible", "ibm,opal-v3-epow");
	dt_add_property_strings(np, "epow-classes", "power", "temperature", "cooling");
	prlog(PR_INFO, "FSP EPOW support initialized\n");
}
