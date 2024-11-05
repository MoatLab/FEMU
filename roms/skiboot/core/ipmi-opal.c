// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * IPMI OPAL calls
 *
 * Copyright 2013-2018 IBM Corp.
 */

#include <stdlib.h>
#include <string.h>
#include <ipmi.h>
#include <lock.h>
#include <opal.h>
#include <device.h>
#include <ccan/list/list.h>

static struct lock msgq_lock = LOCK_UNLOCKED;
static struct list_head msgq = LIST_HEAD_INIT(msgq);

static void opal_send_complete(struct ipmi_msg *msg)
{
	lock(&msgq_lock);
	list_add_tail(&msgq, &msg->link);
	opal_update_pending_evt(ipmi_backend->opal_event_ipmi_recv,
				ipmi_backend->opal_event_ipmi_recv);
	unlock(&msgq_lock);
}

static int64_t opal_ipmi_send(uint64_t interface,
			      struct opal_ipmi_msg *opal_ipmi_msg, uint64_t msg_len)
{
	struct ipmi_msg *msg;

	if (opal_ipmi_msg->version != OPAL_IPMI_MSG_FORMAT_VERSION_1) {
		prerror("OPAL IPMI: Incorrect version\n");
		return OPAL_UNSUPPORTED;
	}

	msg_len -= sizeof(struct opal_ipmi_msg);
	if (msg_len > IPMI_MAX_REQ_SIZE) {
		prerror("OPAL IPMI: Invalid request length\n");
		return OPAL_PARAMETER;
	}

	prlog(PR_TRACE, "opal_ipmi_send(cmd: 0x%02x netfn: 0x%02x len: 0x%02llx)\n",
	       opal_ipmi_msg->cmd, opal_ipmi_msg->netfn >> 2, msg_len);

	msg = ipmi_mkmsg(interface,
			 IPMI_CODE(opal_ipmi_msg->netfn >> 2, opal_ipmi_msg->cmd),
			 opal_send_complete, NULL, opal_ipmi_msg->data,
			 msg_len, IPMI_MAX_RESP_SIZE);
	if (!msg)
		return OPAL_RESOURCE;

	msg->complete = opal_send_complete;
	msg->error = opal_send_complete;
	return ipmi_queue_msg(msg);
}

static int64_t opal_ipmi_recv(uint64_t interface,
			      struct opal_ipmi_msg *opal_ipmi_msg, __be64 *msg_len)
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
		prerror("IPMI: Invalid interface 0x%llx in opal_ipmi_recv\n", interface);
		rc = OPAL_PARAMETER;
		goto out_del_msg;
	}

	if (be64_to_cpu(*msg_len) - sizeof(struct opal_ipmi_msg) < msg->resp_size + 1) {
		rc = OPAL_RESOURCE;
		goto out_del_msg;
	}

	list_del(&msg->link);
	if (list_empty(&msgq))
		opal_update_pending_evt(ipmi_backend->opal_event_ipmi_recv, 0);
	unlock(&msgq_lock);

	opal_ipmi_msg->cmd = msg->cmd;
	opal_ipmi_msg->netfn = msg->netfn;
	opal_ipmi_msg->data[0] = msg->cc;
	memcpy(&opal_ipmi_msg->data[1], msg->data, msg->resp_size);

	prlog(PR_TRACE, "opal_ipmi_recv(cmd: 0x%02x netfn: 0x%02x resp_size: 0x%02x)\n",
	      msg->cmd, msg->netfn >> 2, msg->resp_size);

	/* Add one as the completion code is returned in the message data */
	*msg_len = cpu_to_be64(msg->resp_size + sizeof(struct opal_ipmi_msg) + 1);
	ipmi_free_msg(msg);

	return OPAL_SUCCESS;

out_del_msg:
	list_del(&msg->link);
	if (list_empty(&msgq))
		opal_update_pending_evt(ipmi_backend->opal_event_ipmi_recv, 0);
	ipmi_free_msg(msg);
out_unlock:
	unlock(&msgq_lock);
	return rc;
}

void ipmi_opal_init(void)
{
	struct dt_node *opal_ipmi, *opal_event = NULL;

	opal_ipmi = dt_new(opal_node, "ipmi");
	dt_add_property_strings(opal_ipmi, "compatible", "ibm,opal-ipmi");
	dt_add_property_cells(opal_ipmi, "ibm,ipmi-interface-id",
			      IPMI_DEFAULT_INTERFACE);
	dt_add_property_cells(opal_ipmi, "interrupts",
			      ilog2(ipmi_backend->opal_event_ipmi_recv));

        if (proc_gen >= proc_gen_p9)
		opal_event = dt_find_by_name(opal_node, "event");
	if (opal_event)
		dt_add_property_cells(opal_ipmi, "interrupt-parent",
				      opal_event->phandle);

	opal_register(OPAL_IPMI_SEND, opal_ipmi_send, 3);
	opal_register(OPAL_IPMI_RECV, opal_ipmi_recv, 3);
}
