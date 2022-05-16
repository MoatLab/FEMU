// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Conduit for IPMI messages to/from FSP
 *
 * Copyright 2014-2019 IBM Corp.
 */

#include <errorlog.h>
#include <fsp.h>
#include <ipmi.h>
#include <lock.h>
#include <opal-api.h>

/*
 * Under the hood, FSP IPMI component implements the KCS (Keyboard Controller
 * Style) interface
 *
 * KCS interface request message format
 *
 *    BYTE 1	 BYTE 2	       BYTE 3:N
 *  -------------------------------------
 * | NetFn/LUN |    Cmd    |    Data     |
 *  -------------------------------------
 *
 * KCS interface response message format
 *
 *    BYTE 1	 BYTE 2		BYTE 3	  BYTE 4:N
 *  ------------------------------------------------
 * | NetFn/LUN |    Cmd    |  CompCode  |   Data    |
 *  ------------------------------------------------

 */

#define FSP_IPMI_REQ_MIN_LEN	2 /* NetFn + Cmd */
#define FSP_IPMI_RESP_MIN_LEN	3 /* NetFn + Cmd + Completion code */

DEFINE_LOG_ENTRY(OPAL_RC_IPMI_REQ, OPAL_PLATFORM_ERR_EVT, OPAL_IPMI,
		 OPAL_PLATFORM_FIRMWARE, OPAL_PREDICTIVE_ERR_GENERAL,
		 OPAL_NA);
DEFINE_LOG_ENTRY(OPAL_RC_IPMI_RESP, OPAL_PLATFORM_ERR_EVT, OPAL_IPMI,
		 OPAL_PLATFORM_FIRMWARE, OPAL_PREDICTIVE_ERR_GENERAL,
		 OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_IPMI_DMA_ERROR_RESP, OPAL_PLATFORM_ERR_EVT, OPAL_IPMI,
		 OPAL_PLATFORM_FIRMWARE, OPAL_INFO,
		 OPAL_NA);

struct fsp_ipmi_msg {
	struct list_node	link;
	struct ipmi_msg		ipmi_msg;
};

static struct fsp_ipmi {
	struct list_head	msg_queue;
	void			*ipmi_req_buf;
	void			*ipmi_resp_buf;
	/* There can only be one outstanding request whose reference is stored
	 * in 'cur_msg' and the 'lock' protects against the concurrent updates
	 * of it through request and response. The same 'lock' also protects
	 * the list manipulation.
	 */
	struct fsp_ipmi_msg	*cur_msg;
	struct lock		lock;
} fsp_ipmi;

static int fsp_ipmi_send_request(void);

static void fsp_ipmi_cmd_done(uint8_t cmd, uint8_t netfn, uint8_t cc)
{
	struct fsp_ipmi_msg *fsp_ipmi_msg = fsp_ipmi.cur_msg;

	lock(&fsp_ipmi.lock);
	if (fsp_ipmi.cur_msg == NULL) {
		unlock(&fsp_ipmi.lock);
		return;
	}
	list_del(&fsp_ipmi_msg->link);
	fsp_ipmi.cur_msg = NULL;
	unlock(&fsp_ipmi.lock);

	ipmi_cmd_done(cmd, netfn, cc, &fsp_ipmi_msg->ipmi_msg);
}


static void fsp_ipmi_req_complete(struct fsp_msg *msg)
{
	uint8_t status = (msg->resp->word1 >> 8) & 0xff;
	uint32_t length = fsp_msg_get_data_word(msg->resp, 0);
	struct fsp_ipmi_msg *fsp_ipmi_msg = msg->user_data;
	struct ipmi_msg *ipmi_msg;

	fsp_freemsg(msg);

	if (status != FSP_STATUS_SUCCESS) {
		assert(fsp_ipmi_msg == fsp_ipmi.cur_msg);

		ipmi_msg = &fsp_ipmi_msg->ipmi_msg;

		if (length != (ipmi_msg->req_size + FSP_IPMI_REQ_MIN_LEN))
			prlog(PR_DEBUG, "IPMI: Length mismatch in req completion "
			      "(%d, %d)\n", ipmi_msg->req_size, length);

		log_simple_error(&e_info(OPAL_RC_IPMI_REQ), "IPMI: Request "
				 "failed with status:0x%02x\n", status);
		/* FSP will not send the response now, so clear the current
		 * outstanding request
		 */
		fsp_ipmi_cmd_done(ipmi_msg->cmd,
				  IPMI_NETFN_RETURN_CODE(ipmi_msg->netfn),
				  IPMI_ERR_UNSPECIFIED);

		/* Send the next request in the queue */
		fsp_ipmi_send_request();
	}
}

static int fsp_ipmi_send_request(void)
{
	uint8_t *req_buf = fsp_ipmi.ipmi_req_buf;
	struct ipmi_msg *ipmi_msg;
	struct fsp_msg *msg;
	int rc;

	if (fsp_in_rr())
		return OPAL_BUSY;

	lock(&fsp_ipmi.lock);
	/* An outstanding request is still pending */
	if (fsp_ipmi.cur_msg) {
		unlock(&fsp_ipmi.lock);
		return OPAL_SUCCESS;
	}

	fsp_ipmi.cur_msg = list_top(&fsp_ipmi.msg_queue, struct fsp_ipmi_msg,
				    link);
	unlock(&fsp_ipmi.lock);

	if (!fsp_ipmi.cur_msg)
		return OPAL_SUCCESS;

	ipmi_msg = &fsp_ipmi.cur_msg->ipmi_msg;
	prlog(PR_TRACE, "IPMI: Send request, netfn:0x%02x, cmd:0x%02x, "
	      "req_len:%d\n", ipmi_msg->netfn, ipmi_msg->cmd, ipmi_msg->req_size);

	/* KCS request message format */
	*req_buf++ = ipmi_msg->netfn;	/* BYTE 1 */
	*req_buf++ = ipmi_msg->cmd;	/* BYTE 2 */
	if (ipmi_msg->req_size)
		memcpy(req_buf, ipmi_msg->data, ipmi_msg->req_size);

	msg = fsp_mkmsg(FSP_CMD_FETCH_PLAT_DATA, 5, 0, PSI_DMA_PLAT_REQ_BUF,
			0, PSI_DMA_PLAT_RESP_BUF,
			ipmi_msg->req_size + FSP_IPMI_REQ_MIN_LEN);
	if (!msg) {
		log_simple_error(&e_info(OPAL_RC_IPMI_REQ), "IPMI: Failed to "
				 "allocate request message\n");
		fsp_ipmi_cmd_done(ipmi_msg->cmd,
				  IPMI_NETFN_RETURN_CODE(ipmi_msg->netfn),
				  IPMI_ERR_UNSPECIFIED);
		return OPAL_NO_MEM;
	}

	msg->user_data = fsp_ipmi.cur_msg;
	rc = fsp_queue_msg(msg, fsp_ipmi_req_complete);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_IPMI_REQ), "IPMI: Failed to "
				 "queue request message (%d)\n", rc);
		fsp_freemsg(msg);
		fsp_ipmi_cmd_done(ipmi_msg->cmd,
				  IPMI_NETFN_RETURN_CODE(ipmi_msg->netfn),
				  IPMI_ERR_UNSPECIFIED);
		return OPAL_INTERNAL_ERROR;
	}

	return OPAL_SUCCESS;
}

static struct ipmi_msg *fsp_ipmi_alloc_msg(size_t req_size, size_t resp_size)
{
	struct fsp_ipmi_msg *fsp_ipmi_msg;
	struct ipmi_msg *ipmi_msg;

	fsp_ipmi_msg = zalloc(sizeof(*fsp_ipmi_msg) + MAX(req_size, resp_size));
	if (!fsp_ipmi_msg)
		return NULL;

	ipmi_msg = &fsp_ipmi_msg->ipmi_msg;

	ipmi_msg->req_size = req_size;
	ipmi_msg->resp_size = resp_size;
	ipmi_msg->data = (uint8_t *)(fsp_ipmi_msg + 1);

	return ipmi_msg;
}

static void fsp_ipmi_free_msg(struct ipmi_msg *ipmi_msg)
{
	struct fsp_ipmi_msg *fsp_ipmi_msg = container_of(ipmi_msg,
			struct fsp_ipmi_msg, ipmi_msg);

	free(fsp_ipmi_msg);
}

static int fsp_ipmi_queue_msg(struct ipmi_msg *ipmi_msg)
{
	struct fsp_ipmi_msg *fsp_ipmi_msg = container_of(ipmi_msg,
			struct fsp_ipmi_msg, ipmi_msg);

	if (fsp_in_rr())
		return OPAL_BUSY;

	lock(&fsp_ipmi.lock);
	list_add_tail(&fsp_ipmi.msg_queue, &fsp_ipmi_msg->link);
	unlock(&fsp_ipmi.lock);

	return fsp_ipmi_send_request();
}

static int fsp_ipmi_queue_msg_head(struct ipmi_msg *ipmi_msg)
{
	struct fsp_ipmi_msg *fsp_ipmi_msg = container_of(ipmi_msg,
			struct fsp_ipmi_msg, ipmi_msg);

	if (fsp_in_rr())
		return OPAL_BUSY;

	lock(&fsp_ipmi.lock);
	list_add(&fsp_ipmi.msg_queue, &fsp_ipmi_msg->link);
	unlock(&fsp_ipmi.lock);

	return fsp_ipmi_send_request();
}

static int fsp_ipmi_dequeue_msg(struct ipmi_msg *ipmi_msg)
{
	struct fsp_ipmi_msg *fsp_ipmi_msg = container_of(ipmi_msg,
			struct fsp_ipmi_msg, ipmi_msg);

	lock(&fsp_ipmi.lock);
	list_del_from(&fsp_ipmi.msg_queue, &fsp_ipmi_msg->link);
	unlock(&fsp_ipmi.lock);

	return 0;
}

static struct ipmi_backend fsp_ipmi_backend = {
	.alloc_msg	= fsp_ipmi_alloc_msg,
	.free_msg	= fsp_ipmi_free_msg,
	.queue_msg	= fsp_ipmi_queue_msg,
	.queue_msg_head	= fsp_ipmi_queue_msg_head,
	.dequeue_msg	= fsp_ipmi_dequeue_msg,
	/* FIXME if ever use ipmi_queue_msg_sync on FSP */
	.poll           = NULL,
};

static bool fsp_ipmi_rr_notify(uint32_t cmd_sub_mod,
			       struct fsp_msg *msg __unused)
{
	struct ipmi_msg *ipmi_msg;

	switch (cmd_sub_mod) {
	case FSP_RESET_START:
		return true;
	case FSP_RELOAD_COMPLETE:
		/*
		 * We will not get response for outstanding request. Send error
		 * message to caller and start sending new ipmi messages.
		 */
		if (fsp_ipmi.cur_msg) {
			ipmi_msg = &fsp_ipmi.cur_msg->ipmi_msg;
			fsp_ipmi_cmd_done(ipmi_msg->cmd,
					  IPMI_NETFN_RETURN_CODE(ipmi_msg->netfn),
					  IPMI_ERR_UNSPECIFIED);
		}
		fsp_ipmi_send_request();
		return true;
	}
	return false;
}

static struct fsp_client fsp_ipmi_client_rr = {
	.message = fsp_ipmi_rr_notify,
};

static bool fsp_ipmi_send_response(uint32_t cmd)
{
	struct fsp_msg *resp;
	int rc;

	resp = fsp_mkmsg(cmd, 0);
	if (!resp) {
		log_simple_error(&e_info(OPAL_RC_IPMI_RESP), "IPMI: Failed to "
				 "allocate response message\n");
		return false;
	}

	rc = fsp_queue_msg(resp, fsp_freemsg);
	if (rc) {
		fsp_freemsg(resp);
		log_simple_error(&e_info(OPAL_RC_IPMI_RESP), "IPMI: Failed to "
				 "queue response message\n");
		return false;
	}

	return true;
}

static bool fsp_ipmi_read_response(struct fsp_msg *msg)
{
	uint8_t *resp_buf = fsp_ipmi.ipmi_resp_buf;
	uint32_t status = fsp_msg_get_data_word(msg, 3);
	uint32_t length = fsp_msg_get_data_word(msg, 2);
	struct ipmi_msg *ipmi_msg;
	uint8_t netfn, cmd, cc;

	assert(fsp_ipmi.cur_msg);
	ipmi_msg = &fsp_ipmi.cur_msg->ipmi_msg;

	/* Response TCE token */
	assert(fsp_msg_get_data_word(msg, 1) == PSI_DMA_PLAT_RESP_BUF);

	if (status != FSP_STATUS_SUCCESS) {
		if(status == FSP_STATUS_DMA_ERROR)
			log_simple_error(&e_info(OPAL_RC_IPMI_DMA_ERROR_RESP), "IPMI: Received "
				"DMA ERROR response from FSP, this may be due to FSP "
				"is in termination state:0x%02x\n", status);
		else
			log_simple_error(&e_info(OPAL_RC_IPMI_RESP), "IPMI: FSP response "
				 "received with bad status:0x%02x\n", status);

		fsp_ipmi_cmd_done(ipmi_msg->cmd,
				  IPMI_NETFN_RETURN_CODE(ipmi_msg->netfn),
				  IPMI_ERR_UNSPECIFIED);
		return fsp_ipmi_send_response(FSP_RSP_PLAT_DATA |
					      FSP_STATUS_SUCCESS);
	}

	/* KCS response message format */
	netfn = *resp_buf++;
	cmd = *resp_buf++;
	cc = *resp_buf++;
	length -= FSP_IPMI_RESP_MIN_LEN;

	prlog(PR_TRACE, "IPMI: fsp response received, netfn:0x%02x, cmd:0x%02x,"
	      " cc:0x%02x, length:%d\n", netfn, cmd, cc, length);

	if (length > ipmi_msg->resp_size) {
		prlog(PR_DEBUG, "IPMI: Length mismatch in response (%d, %d)\n",
		      length, ipmi_msg->resp_size);
		length = ipmi_msg->resp_size; /* Truncate */
		cc = IPMI_ERR_MSG_TRUNCATED;
	}

	ipmi_msg->resp_size = length;
	if (length)
		memcpy(ipmi_msg->data, resp_buf, length);

	fsp_ipmi_cmd_done(cmd, netfn, cc);

	return fsp_ipmi_send_response(FSP_RSP_PLAT_DATA);
}

static bool fsp_ipmi_response(uint32_t cmd_sub_mod, struct fsp_msg *msg)
{
	bool rc;

	switch (cmd_sub_mod) {
	case FSP_CMD_SEND_PLAT_DATA:
		prlog(PR_TRACE, "FSP_CMD_SEND_PLAT_DATA command received\n");
		rc = fsp_ipmi_read_response(msg);
		break;
	default:
		return false;
	};

	/* If response sent successfully, pick the next request */
	if (rc == true)
		fsp_ipmi_send_request();

	return rc;
}

static struct fsp_client fsp_ipmi_client = {
	.message = fsp_ipmi_response,
};

void fsp_ipmi_init(void)
{
	fsp_tce_map(PSI_DMA_PLAT_REQ_BUF, fsp_ipmi.ipmi_req_buf,
		    PSI_DMA_PLAT_REQ_BUF_SIZE);
	fsp_tce_map(PSI_DMA_PLAT_RESP_BUF, fsp_ipmi.ipmi_resp_buf,
		    PSI_DMA_PLAT_RESP_BUF_SIZE);

	list_head_init(&fsp_ipmi.msg_queue);
	init_lock(&fsp_ipmi.lock);

	fsp_register_client(&fsp_ipmi_client, FSP_MCLASS_FETCH_SPDATA);
	fsp_register_client(&fsp_ipmi_client_rr, FSP_MCLASS_RR_EVENT);
	ipmi_register_backend(&fsp_ipmi_backend);
}
