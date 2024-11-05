// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * LED location code and indicator handling
 *
 * Copyright 2013-2019 IBM Corp.
 */

#define pr_fmt(fmt) "FSPLED: " fmt
#include <skiboot.h>
#include <fsp.h>
#include <device.h>
#include <spcn.h>
#include <lock.h>
#include <errorlog.h>
#include <opal.h>
#include <opal-msg.h>
#include <fsp-leds.h>
#include <fsp-sysparam.h>

#define buf_write(p, type, val)  do { *(type *)(p) = val;\
					p += sizeof(type); } while(0)
#define buf_read(p, type, addr)  do { *addr = *(type *)(p);\
					p += sizeof(type); } while(0)

/* SPCN replay threshold */
#define SPCN_REPLAY_THRESHOLD 2

/* LED support status */
enum led_support_state {
	LED_STATE_ABSENT,
	LED_STATE_READING,
	LED_STATE_PRESENT,
};

static enum led_support_state led_support = LED_STATE_ABSENT;

/*
 *  PSI mapped buffer for LED data
 *
 * Mapped once and never unmapped. Used for fetching all
 * available LED information and creating the list. Also
 * used for setting individual LED state.
 *
 */
static void *led_buffer;
static u8 *loc_code_list_buffer = NULL;

/* Maintain list of all LEDs
 *
 * The contents here will be used to cater requests from FSP
 * async commands and HV initiated OPAL calls.
 */
static struct list_head  cec_ledq;		/* CEC LED list */
static struct list_head	 encl_ledq;	/* Enclosure LED list */
static struct list_head  spcn_cmdq;	/* SPCN command queue */

/* LED lock */
static struct lock led_lock = LOCK_UNLOCKED;
static struct lock spcn_cmd_lock = LOCK_UNLOCKED;
static struct lock sai_lock = LOCK_UNLOCKED;

static bool spcn_cmd_complete = true;	/* SPCN command complete */

/* Last SPCN command */
static u32 last_spcn_cmd;
static int replay = 0;

/*
 * FSP controls System Attention Indicator. But it expects hypervisor
 * keep track of the status and serve get LED state request (both from
 * Linux and FSP itself)!
 */
static struct sai_data sai_data;

/* Forward declaration */
static void fsp_read_leds_data_complete(struct fsp_msg *msg);
static int process_led_state_change(void);


DEFINE_LOG_ENTRY(OPAL_RC_LED_SPCN, OPAL_PLATFORM_ERR_EVT, OPAL_LED,
		OPAL_PLATFORM_FIRMWARE, OPAL_PREDICTIVE_ERR_GENERAL,
		OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_LED_BUFF, OPAL_PLATFORM_ERR_EVT, OPAL_LED,
		OPAL_PLATFORM_FIRMWARE, OPAL_PREDICTIVE_ERR_GENERAL,
		OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_LED_LC, OPAL_PLATFORM_ERR_EVT, OPAL_LED,
		OPAL_PLATFORM_FIRMWARE, OPAL_INFO, OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_LED_STATE, OPAL_PLATFORM_ERR_EVT, OPAL_LED,
		OPAL_PLATFORM_FIRMWARE, OPAL_PREDICTIVE_ERR_GENERAL,
		OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_LED_SUPPORT, OPAL_PLATFORM_ERR_EVT, OPAL_LED,
		OPAL_PLATFORM_FIRMWARE, OPAL_INFO, OPAL_NA);


/* Find descendent LED record with CEC location code in CEC list */
static struct fsp_led_data *fsp_find_cec_led(char *loc_code)
{
	struct fsp_led_data *led, *next;

	list_for_each_safe(&cec_ledq, led, next, link) {
		if (strcmp(led->loc_code, loc_code))
			continue;
		return led;
	}
	return NULL;
}

/* Find encl LED record with ENCL location code in ENCL list */
static struct fsp_led_data *fsp_find_encl_led(char *loc_code)
{
	struct fsp_led_data *led, *next;

	list_for_each_safe(&encl_ledq, led, next, link) {
		if (strcmp(led->loc_code, loc_code))
			continue;
		return led;
	}
	return NULL;
}

/* Find encl LED record with CEC location code in CEC list */
static struct fsp_led_data *fsp_find_encl_cec_led(char *loc_code)
{
	struct fsp_led_data *led, *next;

	list_for_each_safe(&cec_ledq, led, next, link) {
		if (strstr(led->loc_code, "-"))
			continue;
		if (!strstr(loc_code, led->loc_code))
			continue;
		return led;
	}
	return NULL;
}

/* Find encl LED record with CEC location code in ENCL list */
static struct fsp_led_data *fsp_find_encl_encl_led(char *loc_code)
{
	struct fsp_led_data *led, *next;

	list_for_each_safe(&encl_ledq, led, next, link) {
		if (!strstr(loc_code, led->loc_code))
			continue;
		return led;
	}
	return NULL;
}

/* Compute the ENCL LED status in CEC list */
static void compute_encl_status_cec(struct fsp_led_data *encl_led)
{
	struct fsp_led_data *led, *next;

	encl_led->status &= ~SPCN_LED_IDENTIFY_MASK;
	encl_led->status &= ~SPCN_LED_FAULT_MASK;

	list_for_each_safe(&cec_ledq, led, next, link) {
		if (!strstr(led->loc_code, encl_led->loc_code))
			continue;

		/* Don't count the enclsure LED itself */
		if (!strcmp(led->loc_code, encl_led->loc_code))
			continue;

		if (led->status & SPCN_LED_IDENTIFY_MASK)
			encl_led->status |= SPCN_LED_IDENTIFY_MASK;

		if (led->status & SPCN_LED_FAULT_MASK)
			encl_led->status |= SPCN_LED_FAULT_MASK;
	}
}

/* Is a enclosure LED */
static bool is_enclosure_led(char *loc_code)
{
	if (strstr(loc_code, "-"))
		return false;
	if (!fsp_find_cec_led(loc_code) || !fsp_find_encl_led(loc_code))
		return false;
	return true;
}

static inline void opal_led_update_complete(u64 async_token, u64 result)
{
	opal_queue_msg(OPAL_MSG_ASYNC_COMP, NULL, NULL,
			cpu_to_be64(async_token),
			cpu_to_be64(result));
}

static inline bool is_sai_loc_code(const char *loc_code)
{
	if (!loc_code)
		return false;

	if (!strncmp(sai_data.loc_code, loc_code, strlen(sai_data.loc_code)))
		return true;

	return false;
}

/* Set/Reset System attention indicator */
static void fsp_set_sai_complete(struct fsp_msg *msg)
{
	int ret = OPAL_SUCCESS;
	int rc = msg->resp->word1 & 0xff00;
	struct led_set_cmd *spcn_cmd = (struct led_set_cmd *)msg->user_data;

	if (rc) {
		/**
		 * @fwts-label FSPSAIFailed
		 * @fwts-advice Failed to update System Attention Indicator.
		 * Likely means some bug with OPAL interacting with FSP.
		 */
		prlog(PR_ERR, "Update SAI cmd failed [rc=%d].\n", rc);
		ret = OPAL_INTERNAL_ERROR;

		/* Roll back */
		lock(&sai_lock);
		sai_data.state = spcn_cmd->ckpt_status;
		unlock(&sai_lock);
	}

	if (spcn_cmd->cmd_src == SPCN_SRC_OPAL)
		opal_led_update_complete(spcn_cmd->async_token, ret);

	/* free msg and spcn command */
	free(spcn_cmd);
	fsp_freemsg(msg);

	/* Process pending LED update request */
	process_led_state_change();
}

static int fsp_set_sai(struct led_set_cmd *spcn_cmd)
{
	int rc = -ENOMEM;
	uint32_t cmd = FSP_CMD_SA_INDICATOR;
	struct fsp_msg *msg;

	/*
	 * FSP does not allow hypervisor to set real SAI, but we can
	 * reset real SAI. Also in our case only host can control
	 * LEDs, not guests. Hence we will set platform virtual SAI
	 * and reset real SAI.
	 */
	if (spcn_cmd->state == LED_STATE_ON)
		cmd |= FSP_LED_SET_PLAT_SAI;
	else
		cmd |= FSP_LED_RESET_REAL_SAI;

	prlog(PR_TRACE, "Update SAI Indicator [cur : 0x%x, new : 0x%x].\n",
	      sai_data.state, spcn_cmd->state);

	msg = fsp_mkmsg(cmd, 0);
	if (!msg) {
		/**
		 * @fwts-label SAIMallocFail
		 * @fwts-advice OPAL ran out of memory while trying to
		 * allocate an FSP message in SAI code path. This indicates
		 * an OPAL bug that caused OPAL to run out of memory.
		 */
		prlog(PR_ERR, "%s: Memory allocation failed.\n", __func__);
		goto sai_fail;
	}

	spcn_cmd->ckpt_status = sai_data.state;
	msg->user_data = spcn_cmd;
	rc = fsp_queue_msg(msg, fsp_set_sai_complete);
	if (rc) {
		fsp_freemsg(msg);
		/**
		 * @fwts-label SAIQueueFail
		 * @fwts-advice Error in queueing message to FSP in SAI code
		 * path. Likely an OPAL bug.
		 */
		prlog(PR_ERR, "%s: Failed to queue the message\n", __func__);
		goto sai_fail;
	}

	lock(&sai_lock);
	sai_data.state = spcn_cmd->state;
	unlock(&sai_lock);

	return OPAL_SUCCESS;

sai_fail:
	if (spcn_cmd->cmd_src == SPCN_SRC_OPAL)
		opal_led_update_complete(spcn_cmd->async_token,
					 OPAL_INTERNAL_ERROR);

	return OPAL_INTERNAL_ERROR;
}

static void fsp_get_sai_complete(struct fsp_msg *msg)
{
	int rc = msg->resp->word1 & 0xff00;

	if (rc) {
		/**
		 * @fwts-label FSPSAIGetFailed
		 * @fwts-advice Possibly an error on FSP side, OPAL failed
		 * to read state from FSP.
		 */
		prlog(PR_ERR, "Read real SAI cmd failed [rc = 0x%x].\n", rc);
	} else { /* Update SAI state */
		lock(&sai_lock);
		sai_data.state = fsp_msg_get_data_word(msg->resp, 0) & 0xff;
		unlock(&sai_lock);

		prlog(PR_TRACE, "SAI initial state = 0x%x\n", sai_data.state);
	}

	fsp_freemsg(msg);
}

/* Read initial SAI state. */
static void fsp_get_sai(void)
{
	int rc;
	uint32_t cmd = FSP_CMD_SA_INDICATOR | FSP_LED_READ_REAL_SAI;
	struct fsp_msg *msg;

	msg = fsp_mkmsg(cmd, 0);
	if (!msg) {
		/**
		 * @fwts-label FSPGetSAIMallocFail
		 * @fwts-advice OPAL ran out of memory: OPAL bug.
		 */
		prlog(PR_ERR, "%s: Memory allocation failed.\n", __func__);
		return;
	}
	rc = fsp_queue_msg(msg, fsp_get_sai_complete);
	if (rc) {
		fsp_freemsg(msg);
		/**
		 * @fwts-label FSPGetSAIQueueFail
		 * @fwts-advice Failed to queue message to FSP: OPAL bug
		 */
		prlog(PR_ERR, "%s: Failed to queue the message\n", __func__);
	}
}

static bool sai_update_notification(struct fsp_msg *msg)
{
	uint32_t state = fsp_msg_get_data_word(msg, 2);
	uint32_t param_id = fsp_msg_get_data_word(msg, 0);
	int len = fsp_msg_get_data_word(msg, 1) & 0xffff;

	if (param_id != SYS_PARAM_REAL_SAI && param_id != SYS_PARAM_PLAT_SAI)
		return false;

	if (len != 4)
		return false;

	if (state != LED_STATE_ON && state != LED_STATE_OFF)
		return false;

	/* Update SAI state */
	lock(&sai_lock);
	sai_data.state = state;
	unlock(&sai_lock);

	prlog(PR_TRACE, "SAI updated. New SAI state = 0x%x\n", state);
	return true;
}


/*
 * Update both the local LED lists to reflect upon led state changes
 * occurred with the recent SPCN command. Subsequent LED requests will
 * be served with these updates changed to the list.
 */
static void update_led_list(char *loc_code, u32 led_state, u32 excl_bit)
{
	struct fsp_led_data *led = NULL, *encl_led = NULL, *encl_cec_led = NULL;
	bool is_encl_led = is_enclosure_led(loc_code);

	/* Enclosure LED in CEC list */
	encl_cec_led = fsp_find_encl_cec_led(loc_code);
	if (!encl_cec_led) {
		log_simple_error(&e_info(OPAL_RC_LED_LC),
			"Could not find enclosure LED in CEC LC=%s\n",
			loc_code);
		return;
	}

	/* Update state */
	if (is_encl_led) {
		/* Enclosure exclusive bit */
		encl_cec_led->excl_bit = excl_bit;
	} else {	/* Descendant LED in CEC list */
		led = fsp_find_cec_led(loc_code);
		if (!led) {
			log_simple_error(&e_info(OPAL_RC_LED_LC),
					 "Could not find descendent LED in \
					 CEC LC=%s\n", loc_code);
			return;
		}
		led->status = led_state;
	}

	/* Enclosure LED in ENCL list */
	encl_led = fsp_find_encl_encl_led(loc_code);
	if (!encl_led) {
		log_simple_error(&e_info(OPAL_RC_LED_LC),
			"Could not find enclosure LED in ENCL LC=%s\n",
			loc_code);
		return;
	}

	/* Compute descendent rolled up status */
	compute_encl_status_cec(encl_cec_led);

	/* Check whether exclussive bits set */
	if (encl_cec_led->excl_bit & FSP_LED_EXCL_FAULT)
		encl_cec_led->status |= SPCN_LED_FAULT_MASK;

	if (encl_cec_led->excl_bit & FSP_LED_EXCL_IDENTIFY)
		encl_cec_led->status |= SPCN_LED_IDENTIFY_MASK;

	/* Copy over */
	encl_led->status = encl_cec_led->status;
	encl_led->excl_bit = encl_cec_led->excl_bit;
}

static int fsp_set_led_response(uint32_t cmd)
{
	struct fsp_msg *msg;
	int rc = -1;

	msg = fsp_mkmsg(cmd, 0);
	if (!msg) {
		prerror("Failed to allocate FSP_RSP_SET_LED_STATE [cmd=%x])\n",
			cmd);
	} else {
		rc = fsp_queue_msg(msg, fsp_freemsg);
		if (rc != OPAL_SUCCESS) {
			fsp_freemsg(msg);
			prerror("Failed to queue FSP_RSP_SET_LED_STATE"
				" [cmd=%x]\n", cmd);
		}
	}
	return rc;
}

static void fsp_spcn_set_led_completion(struct fsp_msg *msg)
{
	struct fsp_msg *resp = msg->resp;
	u32 cmd = FSP_RSP_SET_LED_STATE;
	u8 status = resp->word1 & 0xff00;
	struct led_set_cmd *spcn_cmd = (struct led_set_cmd *)msg->user_data;

	lock(&led_lock);

	/*
	 * LED state update request came as part of FSP async message
	 * FSP_CMD_SET_LED_STATE, we need to send response message.
	 *
	 * Also if SPCN command failed, then roll back changes.
	 */
	if (status != FSP_STATUS_SUCCESS) {
		log_simple_error(&e_info(OPAL_RC_LED_SPCN),
			"Last SPCN command failed, status=%02x\n",
			status);
		cmd |= FSP_STATUS_GENERIC_ERROR;

		/* Rollback the changes */
		update_led_list(spcn_cmd->loc_code,
				spcn_cmd->ckpt_status, spcn_cmd->ckpt_excl_bit);
	}

	/* FSP initiated SPCN command */
	if (spcn_cmd->cmd_src == SPCN_SRC_FSP)
		fsp_set_led_response(cmd);

	/* OPAL initiated SPCN command */
	if (spcn_cmd->cmd_src == SPCN_SRC_OPAL) {
		if (status != FSP_STATUS_SUCCESS)
			opal_led_update_complete(spcn_cmd->async_token,
						 OPAL_INTERNAL_ERROR);
		else
			opal_led_update_complete(spcn_cmd->async_token,
						 OPAL_SUCCESS);
	}

	unlock(&led_lock);

	/* free msg and spcn command */
	free(spcn_cmd);
	fsp_freemsg(msg);

	/* Process pending LED update request */
	process_led_state_change();
}

/*
 * Set the state of the LED pointed by the location code
 *
 * LED command:		FAULT state or IDENTIFY state
 * LED state  :		OFF (reset) or ON (set)
 *
 * SPCN TCE mapped buffer entries for setting LED state
 *
 * struct spcn_led_data {
 *	u8	lc_len;
 *	u16	state;
 *	char	lc_code[LOC_CODE_SIZE];
 *};
 */
static int fsp_msg_set_led_state(struct led_set_cmd *spcn_cmd)
{
	struct spcn_led_data sled;
	struct fsp_msg *msg = NULL;
	struct fsp_led_data *led = NULL;
	void *buf = led_buffer;
	u16 data_len = 0;
	u32 cmd_hdr = 0;
	u32 cmd = FSP_RSP_SET_LED_STATE;
	int rc = -1;

	memset(sled.lc_code, 0, LOC_CODE_SIZE);
	sled.lc_len = strlen(spcn_cmd->loc_code);
	if (sled.lc_len >= LOC_CODE_SIZE)
		sled.lc_len = LOC_CODE_SIZE - 1;
	strncpy(sled.lc_code, spcn_cmd->loc_code, LOC_CODE_SIZE - 1);

	lock(&led_lock);

	/* Location code length + Location code + LED control */
	data_len = LOC_CODE_LEN + sled.lc_len + LED_CONTROL_LEN;
	cmd_hdr =  SPCN_MOD_SET_LED_CTL_LOC_CODE << 24 | SPCN_CMD_SET << 16 |
		data_len;

	/* Fetch the current state of LED */
	led = fsp_find_cec_led(spcn_cmd->loc_code);

	/* LED not present */
	if (led == NULL) {
		if (spcn_cmd->cmd_src == SPCN_SRC_FSP) {
			cmd |= FSP_STATUS_INVALID_LC;
			fsp_set_led_response(cmd);
		}

		if (spcn_cmd->cmd_src == SPCN_SRC_OPAL)
			opal_led_update_complete(spcn_cmd->async_token,
						 OPAL_INTERNAL_ERROR);

		unlock(&led_lock);
		return rc;
	}

	/*
	 * Checkpoint the status here, will use it if the SPCN
	 * command eventually fails.
	 */
	spcn_cmd->ckpt_status = led->status;
	spcn_cmd->ckpt_excl_bit = led->excl_bit;
	sled.state = cpu_to_be16(led->status);

	/* Update the exclussive LED bits  */
	if (is_enclosure_led(spcn_cmd->loc_code)) {
		if (spcn_cmd->command == LED_COMMAND_FAULT) {
			if (spcn_cmd->state == LED_STATE_ON)
				led->excl_bit |= FSP_LED_EXCL_FAULT;
			if (spcn_cmd->state == LED_STATE_OFF)
				led->excl_bit &= ~FSP_LED_EXCL_FAULT;
		}

		if (spcn_cmd->command == LED_COMMAND_IDENTIFY) {
			if (spcn_cmd->state == LED_STATE_ON)
				led->excl_bit |= FSP_LED_EXCL_IDENTIFY;
			if (spcn_cmd->state == LED_STATE_OFF)
				led->excl_bit &= ~FSP_LED_EXCL_IDENTIFY;
		}
	}

	/* LED FAULT commad */
	if (spcn_cmd->command == LED_COMMAND_FAULT) {
		if (spcn_cmd->state == LED_STATE_ON)
			sled.state |= cpu_to_be16(SPCN_LED_FAULT_MASK);
		if (spcn_cmd->state == LED_STATE_OFF)
			sled.state &= cpu_to_be16(~SPCN_LED_FAULT_MASK);
	}

	/* LED IDENTIFY command */
	if (spcn_cmd->command == LED_COMMAND_IDENTIFY) {
		if (spcn_cmd->state == LED_STATE_ON)
			sled.state |= cpu_to_be16(SPCN_LED_IDENTIFY_MASK);
		if (spcn_cmd->state == LED_STATE_OFF)
			sled.state &= cpu_to_be16(~SPCN_LED_IDENTIFY_MASK);
	}

	/* Write into SPCN TCE buffer */
	buf_write(buf, u8, sled.lc_len);	/* Location code length */
	memcpy(buf, sled.lc_code, sled.lc_len);	/* Location code */
	buf += sled.lc_len;
	buf_write(buf, __be16, sled.state);	/* LED state */

	msg = fsp_mkmsg(FSP_CMD_SPCN_PASSTHRU, 4,
			SPCN_ADDR_MODE_CEC_NODE, cmd_hdr, 0, PSI_DMA_LED_BUF);
	if (!msg) {
		cmd |= FSP_STATUS_GENERIC_ERROR;
		rc = -1;
		goto update_fail;
	}

	/*
	 * Update the local lists based on the attempted SPCN command to
	 * set/reset an individual led (CEC or ENCL).
	 */
	update_led_list(spcn_cmd->loc_code, be16_to_cpu(sled.state), led->excl_bit);
	msg->user_data = spcn_cmd;

	rc = fsp_queue_msg(msg, fsp_spcn_set_led_completion);
	if (rc != OPAL_SUCCESS) {
		cmd |= FSP_STATUS_GENERIC_ERROR;
		fsp_freemsg(msg);
		/* Revert LED state update */
		update_led_list(spcn_cmd->loc_code, spcn_cmd->ckpt_status,
				spcn_cmd->ckpt_excl_bit);
	}

update_fail:
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_LED_STATE),
				 "Set led state failed at LC=%s\n",
				 spcn_cmd->loc_code);

		if (spcn_cmd->cmd_src == SPCN_SRC_FSP)
			fsp_set_led_response(cmd);

		if (spcn_cmd->cmd_src == SPCN_SRC_OPAL)
			opal_led_update_complete(spcn_cmd->async_token,
						 OPAL_INTERNAL_ERROR);
	}

	unlock(&led_lock);
	return rc;
}

/*
 * process_led_state_change
 *
 * If the command queue is empty, it sets the 'spcn_cmd_complete' as true
 * and just returns. Else it pops one element from the command queue
 * and processes the command for the requested LED state change.
 */
static int process_led_state_change(void)
{
	struct led_set_cmd *spcn_cmd;
	int rc = 0;

	/*
	 * The command queue is empty. This will only
	 * happen during the SPCN command callback path
	 * in which case we set 'spcn_cmd_complete' as true.
	 */
	lock(&spcn_cmd_lock);
	if (list_empty(&spcn_cmdq)) {
		spcn_cmd_complete = true;
		unlock(&spcn_cmd_lock);
		return rc;
	}

	spcn_cmd = list_pop(&spcn_cmdq, struct led_set_cmd, link);
	unlock(&spcn_cmd_lock);

	if (is_sai_loc_code(spcn_cmd->loc_code))
		rc = fsp_set_sai(spcn_cmd);
	else
		rc = fsp_msg_set_led_state(spcn_cmd);

	if (rc) {
		free(spcn_cmd);
		process_led_state_change();
	}

	return rc;
}

/*
 * queue_led_state_change
 *
 * FSP async command or OPAL based request for LED state change gets queued
 * up in the command queue. If no previous SPCN command is pending, then it
 * immediately pops up one element from the list and processes it. If previous
 * SPCN commands are still pending then it just queues up and return. When the
 * SPCN command callback gets to execute, it processes one element from the
 * list and keeps the chain execution going. At last when there are no elements
 * in the command queue it sets 'spcn_cmd_complete' as true again.
 */
static int queue_led_state_change(char *loc_code, u8 command,
				  u8 state, int cmd_src, uint64_t async_token)
{
	struct led_set_cmd *cmd;
	int rc = 0;

	/* New request node */
	cmd = zalloc(sizeof(struct led_set_cmd));
	if (!cmd) {
		/**
		 * @fwts-label FSPLEDRequestMallocFail
		 * @fwts-advice OPAL failed to allocate memory for FSP LED
		 * command. Likely an OPAL bug led to out of memory.
		 */
		prlog(PR_ERR, "SPCN set command node allocation failed\n");
		return -1;
	}

	/* Save the request */
	strncpy(cmd->loc_code, loc_code, LOC_CODE_SIZE - 1);
	cmd->command = command;
	cmd->state = state;
	cmd->cmd_src = cmd_src;
	cmd->async_token = async_token;

	/* Add to the queue */
	lock(&spcn_cmd_lock);
	list_add_tail(&spcn_cmdq,  &cmd->link);

	/* No previous SPCN command pending */
	if (spcn_cmd_complete) {
		spcn_cmd_complete = false;
		unlock(&spcn_cmd_lock);
		rc = process_led_state_change();
		return rc;
	}

	unlock(&spcn_cmd_lock);
	return rc;
}

/*
 * Write single location code information into the TCE outbound buffer
 *
 * Data layout
 *
 * 2 bytes - Length of location code structure
 * 4 bytes - CCIN in ASCII
 * 1 byte  - Resource status flag
 * 1 byte  - Indicator state
 * 1 byte  - Raw loc code length
 * 1 byte  - Loc code field size
 * Field size byte - Null terminated ASCII string padded to 4 byte boundary
 *
 */
static u32 fsp_push_data_to_tce(struct fsp_led_data *led, u8 *out_data,
				u32 total_size)
{
	struct fsp_loc_code_data lcode;

	/* CCIN value is irrelevant */
	lcode.ccin = 0x0;

	lcode.status = FSP_IND_NOT_IMPLMNTD;

	if (led->parms & SPCN_LED_IDENTIFY_MASK)
		lcode.status = FSP_IND_IMPLMNTD;

	/* LED indicator status */
	lcode.ind_state = FSP_IND_INACTIVE;
	if (led->status & SPCN_LED_IDENTIFY_MASK)
		lcode.ind_state |= FSP_IND_IDENTIFY_ACTV;
	if (led->status & SPCN_LED_FAULT_MASK)
		lcode.ind_state |= FSP_IND_FAULT_ACTV;

	/* Location code */
	memset(lcode.loc_code, 0, LOC_CODE_SIZE);
	lcode.raw_len = strlen(led->loc_code);
	strncpy(lcode.loc_code, led->loc_code, LOC_CODE_SIZE - 1);
	lcode.fld_sz = sizeof(lcode.loc_code);

	/* Rest of the structure */
	lcode.size = cpu_to_be16(sizeof(lcode));
	lcode.status &= 0x0f;

	/*
	 * Check for outbound buffer overflow. If there are still
	 * more LEDs to be sent across to FSP, don't send, ignore.
	 */
	if ((total_size + be16_to_cpu(lcode.size)) > PSI_DMA_LOC_COD_BUF_SZ)
		return 0;

	/* Copy over to the buffer */
	memcpy(out_data, &lcode, sizeof(lcode));

	return be16_to_cpu(lcode.size);
}

/*
 * Send out LED information structure pointed by "loc_code"
 * to FSP through the PSI DMA mapping. Buffer layout structure
 * must be followed.
 */
static void fsp_ret_loc_code_list(u16 req_type, char *loc_code)
{
	struct fsp_led_data *led, *next;
	struct fsp_msg *msg;

	u8 *data;			/* Start of TCE mapped buffer */
	u8 *out_data;			/* Start of location code data */
	u32 bytes_sent = 0, total_size = 0;
	u16 header_size = 0, flags = 0;

	if (loc_code_list_buffer == NULL) {
		prerror("No loc_code_list_buffer\n");
		return;
	}

	/* Init the addresses */
	data = loc_code_list_buffer;
	out_data = NULL;

	/* Unmapping through FSP_CMD_RET_LOC_BUFFER command */
	fsp_tce_map(PSI_DMA_LOC_COD_BUF, (void *)data, PSI_DMA_LOC_COD_BUF_SZ);
	out_data = data + 8;

	/* CEC LED list */
	list_for_each_safe(&cec_ledq, led, next, link) {
		/*
		 * When the request type is system wide led list
		 * i.e GET_LC_CMPLT_SYS, send the entire contents
		 * of the CEC list including both all descendents
		 * and all of their enclosures.
		 */

		if (req_type == GET_LC_ENCLOSURES)
			break;

		if (req_type == GET_LC_ENCL_DESCENDANTS) {
			if (strstr(led->loc_code, loc_code) == NULL)
				continue;
		}

		if (req_type == GET_LC_SINGLE_LOC_CODE) {
			if (strcmp(led->loc_code, loc_code))
				continue;
		}

		/* Push the data into TCE buffer */
		bytes_sent = fsp_push_data_to_tce(led, out_data, total_size);

		/* Advance the TCE pointer */
		out_data += bytes_sent;
		total_size += bytes_sent;
	}

	/* Enclosure LED list */
	if (req_type == GET_LC_ENCLOSURES) {
		list_for_each_safe(&encl_ledq, led, next, link) {

			/* Push the data into TCE buffer */
			bytes_sent = fsp_push_data_to_tce(led,
							  out_data, total_size);

			/* Advance the TCE pointer */
			out_data += bytes_sent;
			total_size += bytes_sent;
		}
	}

	/* Count from 'data' instead of 'data_out' */
	total_size += 8;
	memcpy(data, &total_size, sizeof(total_size));

	header_size = OUTBUF_HEADER_SIZE;
	memcpy(data + sizeof(total_size), &header_size, sizeof(header_size));

	if (req_type == GET_LC_ENCL_DESCENDANTS)
		flags = 0x8000;

	memcpy(data +  sizeof(total_size) + sizeof(header_size), &flags,
	       sizeof(flags));
	msg = fsp_mkmsg(FSP_RSP_GET_LED_LIST, 3, 0,
			PSI_DMA_LOC_COD_BUF, total_size);
	if (!msg) {
		prerror("Failed to allocate FSP_RSP_GET_LED_LIST.\n");
	} else {
		if (fsp_queue_msg(msg, fsp_freemsg)) {
			fsp_freemsg(msg);
			prerror("Failed to queue FSP_RSP_GET_LED_LIST\n");
		}
	}
}

/*
 * FSP async command: FSP_CMD_GET_LED_LIST
 *
 * (1) FSP sends the list of location codes through inbound buffer
 * (2) HV sends the status of those location codes through outbound buffer
 *
 * Inbound buffer data layout (loc code request structure)
 *
 * 2 bytes - Length of entire structure
 * 2 bytes - Request type
 * 1 byte - Raw length of location code
 * 1 byte - Location code field size
 * `Field size` bytes - NULL terminated ASCII location code string
 */
static void fsp_get_led_list(struct fsp_msg *msg)
{
	struct fsp_loc_code_req req;
	u32 tce_token = fsp_msg_get_data_word(msg, 1);
	void *buf;

	/* Parse inbound buffer */
	buf = fsp_inbound_buf_from_tce(tce_token);
	if (!buf) {
		struct fsp_msg *msg;
		msg = fsp_mkmsg(FSP_RSP_GET_LED_LIST | FSP_STATUS_INVALID_DATA,
				0);
		if (!msg) {
			prerror("Failed to allocate FSP_RSP_GET_LED_LIST"
				" | FSP_STATUS_INVALID_DATA\n");
		} else {
			if (fsp_queue_msg(msg, fsp_freemsg)) {
				fsp_freemsg(msg);
				prerror("Failed to queue "
					"FSP_RSP_GET_LED_LIST |"
					" FSP_STATUS_INVALID_DATA\n");
			}
		}
		return;
	}
	memcpy(&req, buf, sizeof(req));

	prlog(PR_TRACE, "Request for loc code list type 0x%04x LC=%s\n",
	       be16_to_cpu(req.req_type), req.loc_code);

	fsp_ret_loc_code_list(be16_to_cpu(req.req_type), req.loc_code);
}

/*
 * FSP async command: FSP_CMD_RET_LOC_BUFFER
 *
 * With this command FSP returns ownership of the outbound buffer
 * used by Sapphire to pass the indicator list previous time. That
 * way FSP tells Sapphire that it has consumed all the data present
 * on the outbound buffer and Sapphire can reuse it for next request.
 */
static void fsp_free_led_list_buf(struct fsp_msg *msg)
{
	u32 tce_token = fsp_msg_get_data_word(msg, 1);
	u32 cmd = FSP_RSP_RET_LED_BUFFER;
	struct fsp_msg *resp;

	/* Token does not point to outbound buffer */
	if (tce_token != PSI_DMA_LOC_COD_BUF) {
		log_simple_error(&e_info(OPAL_RC_LED_BUFF),
			"Invalid tce token from FSP\n");
		cmd |=  FSP_STATUS_GENERIC_ERROR;
		resp = fsp_mkmsg(cmd, 0);
		if (!resp) {
			prerror("Failed to allocate FSP_RSP_RET_LED_BUFFER"
				"| FSP_STATUS_GENERIC_ERROR\n");
			return;
		}

		if (fsp_queue_msg(resp, fsp_freemsg)) {
			fsp_freemsg(resp);
			prerror("Failed to queue "
				"RET_LED_BUFFER|ERROR\n");
		}
		return;
	}

	/* Unmap the location code DMA buffer */
	fsp_tce_unmap(PSI_DMA_LOC_COD_BUF, PSI_DMA_LOC_COD_BUF_SZ);

	resp = fsp_mkmsg(cmd, 0);
	if (!resp) {
		prerror("Failed to allocate FSP_RSP_RET_LED_BUFFER\n");
		return;
	}
	if (fsp_queue_msg(resp, fsp_freemsg)) {
		fsp_freemsg(resp);
		prerror("Failed to queue FSP_RSP_RET_LED_BUFFER\n");
	}
}

static void fsp_ret_led_state(char *loc_code)
{
	bool found = false;
	u8 ind_state = 0;
	u32 cmd = FSP_RSP_GET_LED_STATE;
	struct fsp_led_data *led, *next;
	struct fsp_msg *msg;

	if (is_sai_loc_code(loc_code)) {
		if (sai_data.state & OPAL_SLOT_LED_STATE_ON)
			ind_state = FSP_IND_FAULT_ACTV;
		found = true;
	} else {
		list_for_each_safe(&cec_ledq, led, next, link) {
			if (strcmp(loc_code, led->loc_code))
				continue;

			/* Found the location code */
			if (led->status & SPCN_LED_IDENTIFY_MASK)
				ind_state |= FSP_IND_IDENTIFY_ACTV;
			if (led->status & SPCN_LED_FAULT_MASK)
				ind_state |= FSP_IND_FAULT_ACTV;

			found = true;
			break;
		}
	}

	/* Location code not found */
	if (!found) {
		log_simple_error(&e_info(OPAL_RC_LED_LC),
				 "Could not find the location code LC=%s\n",
				 loc_code);
		cmd |= FSP_STATUS_INVALID_LC;
		ind_state = 0xff;
	}

	msg = fsp_mkmsg(cmd, 1, ind_state);
	if (!msg) {
		prerror("Couldn't alloc FSP_RSP_GET_LED_STATE\n");
		return;
	}

	if (fsp_queue_msg(msg, fsp_freemsg)) {
		fsp_freemsg(msg);
		prerror("Couldn't queue FSP_RSP_GET_LED_STATE\n");
	}
}

/*
 * FSP async command: FSP_CMD_GET_LED_STATE
 *
 * With this command FSP query the state for any given LED
 */
static void fsp_get_led_state(struct fsp_msg *msg)
{
	struct fsp_get_ind_state_req req;
	u32 tce_token = fsp_msg_get_data_word(msg, 1);
	void *buf;

	/* Parse the inbound buffer */
	buf = fsp_inbound_buf_from_tce(tce_token);
	if (!buf) {
		struct fsp_msg *msg;
		msg = fsp_mkmsg(FSP_RSP_GET_LED_STATE |
				FSP_STATUS_INVALID_DATA, 0);
		if (!msg) {
			prerror("Failed to allocate FSP_RSP_GET_LED_STATE"
				" | FSP_STATUS_INVALID_DATA\n");
			return;
		}
		if (fsp_queue_msg(msg, fsp_freemsg)) {
			fsp_freemsg(msg);
			prerror("Failed to queue FSP_RSP_GET_LED_STATE"
				" | FSP_STATUS_INVALID_DATA\n");
		}
		return;
	}
	memcpy(&req, buf, sizeof(req));

	prlog(PR_TRACE, "%s: tce=0x%08x buf=%p rq.sz=%d rq.lc_len=%d"
	      " rq.fld_sz=%d LC: %02x %02x %02x %02x....\n", __func__,
	      tce_token, buf, req.size, req.lc_len, req.fld_sz,
	      req.loc_code[0], req.loc_code[1],
	      req.loc_code[2], req.loc_code[3]);

	/* Bound check */
	if (req.lc_len >= LOC_CODE_SIZE) {
		log_simple_error(&e_info(OPAL_RC_LED_LC),
				 "Loc code too large in %s: %d bytes\n",
				 __func__, req.lc_len);
		req.lc_len = LOC_CODE_SIZE - 1;
	}
	/* Ensure NULL termination */
	req.loc_code[req.lc_len] = 0;

	/* Do the deed */
	fsp_ret_led_state(req.loc_code);
}

/*
 * FSP async command: FSP_CMD_SET_LED_STATE
 *
 * With this command FSP sets/resets the state for any given LED
 */
static void fsp_set_led_state(struct fsp_msg *msg)
{
	struct fsp_set_ind_state_req req;
	struct fsp_led_data *led, *next;
	u32 tce_token = fsp_msg_get_data_word(msg, 1);
	bool command, state;
	void *buf;
	int rc;

	/* Parse the inbound buffer */
	buf = fsp_inbound_buf_from_tce(tce_token);
	if (!buf) {
		fsp_set_led_response(FSP_RSP_SET_LED_STATE |
				     FSP_STATUS_INVALID_DATA);
		return;
	}
	memcpy(&req, buf, sizeof(req));

	prlog(PR_TRACE, "%s: tce=0x%08x buf=%p rq.sz=%d rq.typ=0x%04x"
	      " rq.lc_len=%d rq.fld_sz=%d LC: %02x %02x %02x %02x....\n",
	      __func__, tce_token, buf, be16_to_cpu(req.size), req.lc_len, req.fld_sz,
	      be16_to_cpu(req.req_type),
	      req.loc_code[0], req.loc_code[1],
	      req.loc_code[2], req.loc_code[3]);

	/* Bound check */
	if (req.lc_len >= LOC_CODE_SIZE) {
		log_simple_error(&e_info(OPAL_RC_LED_LC),
				 "Loc code too large in %s: %d bytes\n",
				 __func__, req.lc_len);
		req.lc_len = LOC_CODE_SIZE - 1;
	}
	/* Ensure NULL termination */
	req.loc_code[req.lc_len] = 0;

	/* Decode command */
	command =  (req.ind_state & LOGICAL_IND_STATE_MASK) ?
		LED_COMMAND_FAULT : LED_COMMAND_IDENTIFY;
	state = (req.ind_state & ACTIVE_LED_STATE_MASK) ?
		LED_STATE_ON : LED_STATE_OFF;

	/* Handle requests */
	switch (be16_to_cpu(req.req_type)) {
	case SET_IND_ENCLOSURE:
		list_for_each_safe(&cec_ledq, led, next, link) {
			/* Only descendants of the same enclosure */
			if (!strstr(led->loc_code, req.loc_code))
				continue;

			/* Skip the enclosure */
			if (!strcmp(led->loc_code, req.loc_code))
				continue;

			rc = queue_led_state_change(led->loc_code, command,
						    state, SPCN_SRC_FSP, 0);
			if (rc != 0)
				fsp_set_led_response(FSP_RSP_SET_LED_STATE |
						     FSP_STATUS_GENERIC_ERROR);
		}
		break;
	case SET_IND_SINGLE_LOC_CODE:
		/* Set led state for single descendent led */
		rc = queue_led_state_change(req.loc_code,
					    command, state, SPCN_SRC_FSP, 0);
		if (rc != 0)
			fsp_set_led_response(FSP_RSP_SET_LED_STATE |
					     FSP_STATUS_GENERIC_ERROR);
		break;
	default:
		fsp_set_led_response(FSP_RSP_SET_LED_STATE |
				     FSP_STATUS_NOT_SUPPORTED);
		break;
	}
}

/* Handle received indicator message from FSP */
static bool fsp_indicator_message(u32 cmd_sub_mod, struct fsp_msg *msg)
{
	u32 cmd;
	struct fsp_msg *resp;

	/* LED support not available yet */
	if (led_support != LED_STATE_PRESENT) {
		log_simple_error(&e_info(OPAL_RC_LED_SUPPORT),
			"Indicator message while LED support not"
			" available yet\n");
		return false;
	}

	switch (cmd_sub_mod) {
	case FSP_CMD_GET_LED_LIST:
		prlog(PR_TRACE, "FSP_CMD_GET_LED_LIST command received\n");
		fsp_get_led_list(msg);
		return true;
	case FSP_CMD_RET_LED_BUFFER:
		prlog(PR_TRACE, "FSP_CMD_RET_LED_BUFFER command received\n");
		fsp_free_led_list_buf(msg);
		return true;
	case FSP_CMD_GET_LED_STATE:
		prlog(PR_TRACE, "FSP_CMD_GET_LED_STATE command received\n");
		fsp_get_led_state(msg);
		return true;
	case FSP_CMD_SET_LED_STATE:
		prlog(PR_TRACE, "FSP_CMD_SET_LED_STATE command received\n");
		fsp_set_led_state(msg);
		return true;
	/*
	 * FSP async sub commands which have not been implemented.
	 * For these async sub commands, print for the log and ack
	 * the field service processor with a generic error.
	 */
	case FSP_CMD_GET_MTMS_LIST:
		prlog(PR_TRACE, "FSP_CMD_GET_MTMS_LIST command received\n");
		cmd = FSP_RSP_GET_MTMS_LIST;
		break;
	case FSP_CMD_RET_MTMS_BUFFER:
		prlog(PR_TRACE, "FSP_CMD_RET_MTMS_BUFFER command received\n");
		cmd = FSP_RSP_RET_MTMS_BUFFER;
		break;
	case FSP_CMD_SET_ENCL_MTMS:
		prlog(PR_TRACE, "FSP_CMD_SET_MTMS command received\n");
		cmd = FSP_RSP_SET_ENCL_MTMS;
		break;
	case FSP_CMD_CLR_INCT_ENCL:
		prlog(PR_TRACE, "FSP_CMD_CLR_INCT_ENCL command received\n");
		cmd = FSP_RSP_CLR_INCT_ENCL;
		break;
	case FSP_CMD_ENCL_MCODE_INIT:
		prlog(PR_TRACE, "FSP_CMD_ENCL_MCODE_INIT command received\n");
		cmd = FSP_RSP_ENCL_MCODE_INIT;
		break;
	case FSP_CMD_ENCL_MCODE_INTR:
		prlog(PR_TRACE, "FSP_CMD_ENCL_MCODE_INTR command received\n");
		cmd = FSP_RSP_ENCL_MCODE_INTR;
		break;
	case FSP_CMD_ENCL_POWR_TRACE:
		prlog(PR_TRACE, "FSP_CMD_ENCL_POWR_TRACE command received\n");
		cmd = FSP_RSP_ENCL_POWR_TRACE;
		break;
	case FSP_CMD_RET_ENCL_TRACE_BUFFER:
		prlog(PR_TRACE, "FSP_CMD_RET_ENCL_TRACE_BUFFER command received\n");
		cmd = FSP_RSP_RET_ENCL_TRACE_BUFFER;
		break;
	case FSP_CMD_GET_SPCN_LOOP_STATUS:
		prlog(PR_TRACE, "FSP_CMD_GET_SPCN_LOOP_STATUS command received\n");
		cmd = FSP_RSP_GET_SPCN_LOOP_STATUS;
		break;
	case FSP_CMD_INITIATE_LAMP_TEST:
		/* XXX: FSP ACK not required for this sub command */
		prlog(PR_TRACE, "FSP_CMD_INITIATE_LAMP_TEST command received\n");
		return true;
	default:
		return false;
	}
	cmd |= FSP_STATUS_GENERIC_ERROR;
	resp = fsp_mkmsg(cmd, 0);
	if (!resp) {
		prerror("Failed to allocate FSP_STATUS_GENERIC_ERROR\n");
		return false;
	}
	if (fsp_queue_msg(resp, fsp_freemsg)) {
		fsp_freemsg(resp);
		prerror("Failed to queue FSP_STATUS_GENERIC_ERROR\n");
		return false;
	}
	return true;
}

/* Indicator class client */
static struct fsp_client fsp_indicator_client = {
	.message = fsp_indicator_message,
};


static int fsp_opal_get_sai(__be64 *led_mask, __be64 *led_value)
{
	*led_mask |= cpu_to_be64(OPAL_SLOT_LED_STATE_ON << OPAL_SLOT_LED_TYPE_ATTN);
	if (sai_data.state & OPAL_SLOT_LED_STATE_ON)
		*led_value |= cpu_to_be64(OPAL_SLOT_LED_STATE_ON << OPAL_SLOT_LED_TYPE_ATTN);

	return OPAL_SUCCESS;
}

static int fsp_opal_set_sai(uint64_t async_token, char *loc_code,
			    const u64 led_mask, const u64 led_value)
{
	int state = LED_STATE_OFF;

	if (!((led_mask >> OPAL_SLOT_LED_TYPE_ATTN) & OPAL_SLOT_LED_STATE_ON))
		return OPAL_PARAMETER;

	if ((led_value >> OPAL_SLOT_LED_TYPE_ATTN) & OPAL_SLOT_LED_STATE_ON)
		state = LED_STATE_ON;

	return queue_led_state_change(loc_code, 0,
				      state, SPCN_SRC_OPAL, async_token);
}

/*
 * fsp_opal_leds_get_ind (OPAL_LEDS_GET_INDICATOR)
 *
 * Argument	 Description				Updated By
 * --------	 -----------				----------
 * loc_code	 Location code of the LEDs		(Host)
 * led_mask	 LED types whose status is available	(OPAL)
 * led_value	 Status of the available LED types	(OPAL)
 * max_led_type  Maximum number of supported LED types	(Host/OPAL)
 *
 * The host will pass the location code of the LED types (loc_code) and
 * maximum number of LED types it understands (max_led_type). OPAL will
 * update the 'led_mask' with set bits pointing to LED types whose status
 * is available and updates the 'led_value' with actual status. OPAL checks
 * the 'max_led_type' to understand whether the host is newer or older
 * compared to itself. In the case where the OPAL is newer compared
 * to host (OPAL's max_led_type > host's max_led_type), it will update
 * led_mask and led_value according to max_led_type requested by the host.
 * When the host is newer compared to the OPAL (host's max_led_type >
 * OPAL's max_led_type), OPAL updates 'max_led_type' to the maximum
 * number of LED type it understands and updates 'led_mask', 'led_value'
 * based on that maximum value of LED types.
 */
static int64_t fsp_opal_leds_get_ind(char *loc_code, __be64 *led_mask,
				     __be64 *led_value, __be64 *max_led_type)
{
	bool supported = true;
	int64_t max;
	int rc;
	struct fsp_led_data *led;

	/* FSP not present */
	if (!fsp_present())
		return OPAL_HARDWARE;

	/* LED support not available */
	if (led_support != LED_STATE_PRESENT)
		return OPAL_HARDWARE;

	max = be64_to_cpu(*max_led_type);

	/* Adjust max LED type */
	if (max > OPAL_SLOT_LED_TYPE_MAX) {
		supported = false;
		max = OPAL_SLOT_LED_TYPE_MAX;
		*max_led_type = cpu_to_be64(max);
	}

	/* Invalid parameter */
	if (max <= 0)
		return OPAL_PARAMETER;

	/* Get System attention indicator state */
	if (is_sai_loc_code(loc_code)) {
		rc = fsp_opal_get_sai(led_mask, led_value);
		return rc;
	}

	/* LED not found */
	led = fsp_find_cec_led(loc_code);
	if (!led)
		return OPAL_PARAMETER;

	*led_mask = 0;
	*led_value = 0;

	/* Identify LED */
	--max;
	*led_mask |= cpu_to_be64(OPAL_SLOT_LED_STATE_ON << OPAL_SLOT_LED_TYPE_ID);
	if (led->status & SPCN_LED_IDENTIFY_MASK)
		*led_value |= cpu_to_be64(OPAL_SLOT_LED_STATE_ON << OPAL_SLOT_LED_TYPE_ID);

	/* Fault LED */
	if (!max)
		return OPAL_SUCCESS;

	--max;
	*led_mask |= cpu_to_be64(OPAL_SLOT_LED_STATE_ON << OPAL_SLOT_LED_TYPE_FAULT);
	if (led->status & SPCN_LED_FAULT_MASK)
		*led_value |= cpu_to_be64(OPAL_SLOT_LED_STATE_ON << OPAL_SLOT_LED_TYPE_FAULT);

	/* OPAL doesn't support all the LED type requested by payload */
	if (!supported)
		return OPAL_PARTIAL;

	return OPAL_SUCCESS;
}

/*
 * fsp_opal_leds_set_ind (OPAL_LEDS_SET_INDICATOR)
 *
 * Argument	 Description				Updated By
 * --------	 -----------				----------
 * loc_code	 Location code of the LEDs		(Host)
 * led_mask	 LED types whose status will be updated	(Host)
 * led_value	 Requested status of various LED types	(Host)
 * max_led_type  Maximum number of supported LED types	(Host/OPAL)
 *
 * The host will pass the location code of the LED types, mask, value
 * and maximum number of LED types it understands. OPAL will update
 * LED status for all the LED types mentioned in the mask with their
 * value mentioned. OPAL checks the 'max_led_type' to understand
 * whether the host is newer or older compared to itself. In case where
 * the OPAL is newer compared to the host (OPAL's max_led_type >
 * host's max_led_type), it updates LED status based on max_led_type
 * requested from the host. When the host is newer compared to the OPAL
 * (host's max_led_type > OPAL's max_led_type), OPAL updates
 * 'max_led_type' to the maximum number of LED type it understands and
 * then it updates LED status based on that updated  maximum value of LED
 * types. Host needs to check the returned updated value of max_led_type
 * to figure out which part of it's request got served and which ones got
 * ignored.
 */
static int64_t fsp_opal_leds_set_ind(uint64_t async_token,
				     char *loc_code, const u64 led_mask,
				     const u64 led_value, __be64 *max_led_type)
{
	bool supported = true;
	int command, state, rc = OPAL_SUCCESS;
	int64_t max;
	struct fsp_led_data *led;

	/* FSP not present */
	if (!fsp_present())
		return OPAL_HARDWARE;

	/* LED support not available */
	if (led_support != LED_STATE_PRESENT)
		return OPAL_HARDWARE;

	max = be64_to_cpu(*max_led_type);

	/* Adjust max LED type */
	if (max > OPAL_SLOT_LED_TYPE_MAX) {
		supported = false;
		max = OPAL_SLOT_LED_TYPE_MAX;
		*max_led_type = cpu_to_be64(max);
	}

	/* Invalid parameter */
	if (max <= 0)
		return OPAL_PARAMETER;

	/* Set System attention indicator state */
	if (is_sai_loc_code(loc_code)) {
		supported = true;
		rc = fsp_opal_set_sai(async_token,
				      loc_code, led_mask, led_value);
		goto success;
	}

	/* LED not found */
	led = fsp_find_cec_led(loc_code);
	if (!led)
		return OPAL_PARAMETER;

	/* Indentify LED mask */
	--max;

	if ((led_mask >> OPAL_SLOT_LED_TYPE_ID) & OPAL_SLOT_LED_STATE_ON) {
		supported = true;

		command = LED_COMMAND_IDENTIFY;
		state = LED_STATE_OFF;
		if ((led_value >> OPAL_SLOT_LED_TYPE_ID)
					& OPAL_SLOT_LED_STATE_ON)
			state = LED_STATE_ON;

		rc = queue_led_state_change(loc_code, command,
					    state, SPCN_SRC_OPAL, async_token);
	}

	if (!max)
		goto success;

	/* Fault LED mask */
	--max;
	if ((led_mask >> OPAL_SLOT_LED_TYPE_FAULT) & OPAL_SLOT_LED_STATE_ON) {
		supported = true;

		command = LED_COMMAND_FAULT;
		state = LED_STATE_OFF;
		if ((led_value >> OPAL_SLOT_LED_TYPE_FAULT)
					& OPAL_SLOT_LED_STATE_ON)
			state = LED_STATE_ON;

		rc = queue_led_state_change(loc_code, command,
					    state, SPCN_SRC_OPAL, async_token);
	}

success:
	/* Unsupported LED type */
	if (!supported)
		return OPAL_UNSUPPORTED;

	if (rc == OPAL_SUCCESS)
		rc = OPAL_ASYNC_COMPLETION;
	else
		rc = OPAL_INTERNAL_ERROR;

	return rc;
}

/* Get LED node from device tree */
static struct dt_node *dt_get_led_node(void)
{
	struct dt_node *pled;

	if (!opal_node) {
		prlog(PR_WARNING, "OPAL parent device node not available\n");
		return NULL;
	}

	pled = dt_find_by_path(opal_node, DT_PROPERTY_LED_NODE);
	if (!pled)
		prlog(PR_WARNING, "Parent device node not available\n");

	return pled;
}

/* Get System attention indicator location code from device tree */
static void dt_get_sai_loc_code(void)
{
	struct dt_node *pled, *child;
	const char *led_type = NULL;

	memset(sai_data.loc_code, 0, LOC_CODE_SIZE);

	pled = dt_get_led_node();
	if (!pled)
		return;

	list_for_each(&pled->children, child, list) {
		led_type = dt_prop_get(child, DT_PROPERTY_LED_TYPES);
		if (!led_type)
			continue;

		if (strcmp(led_type, LED_TYPE_ATTENTION))
			continue;

		memcpy(sai_data.loc_code, child->name, LOC_CODE_SIZE - 1);

		prlog(PR_TRACE, "SAI Location code = %s\n", sai_data.loc_code);
		return;
	}
}

/*
 * create_led_device_node
 *
 * Creates the system parent LED device node and all individual
 * child LED device nodes under it. This is called right before
 * starting the payload (Linux) to ensure that the SPCN command
 * sequence to fetch the LED location code list has been finished
 * and to have a better chance of creating the deviced nodes.
 */
void create_led_device_nodes(void)
{
	const char *led_mode = NULL;
	struct fsp_led_data *led, *next;
	struct dt_node *pled, *cled;

	if (!fsp_present())
		return;

	/* Make sure LED list read is completed */
	while (led_support == LED_STATE_READING)
		opal_run_pollers();

	if (led_support == LED_STATE_ABSENT) {
		prlog(PR_WARNING, "LED support not available, \
		      hence device tree nodes will not be created\n");
		return;
	}

	/* Get LED node */
	pled = dt_get_led_node();
	if (!pled)
		return;

	/* Check if already populated (fast-reboot) */
	if (dt_has_node_property(pled, "compatible", NULL))
		return;
	dt_add_property_strings(pled, "compatible", DT_PROPERTY_LED_COMPATIBLE);

	led_mode = dt_prop_get(pled, DT_PROPERTY_LED_MODE);
	if (!led_mode) {
		prlog(PR_WARNING, "Unknown LED operating mode\n");
		return;
	}

	/* LED child nodes */
	list_for_each_safe(&cec_ledq, led, next, link) {
		/* Duplicate LED location code */
		if (dt_find_by_path(pled, led->loc_code)) {
			prlog(PR_WARNING, "duplicate location code %s\n",
			      led->loc_code);
			continue;
		}

		cled = dt_new(pled, led->loc_code);
		if (!cled) {
			prlog(PR_WARNING, "Child device node creation "
			      "failed\n");
			continue;
		}

		if (!strcmp(led_mode, LED_MODE_LIGHT_PATH))
			dt_add_property_strings(cled, DT_PROPERTY_LED_TYPES,
						LED_TYPE_IDENTIFY,
						LED_TYPE_FAULT);
		else
			dt_add_property_strings(cled, DT_PROPERTY_LED_TYPES,
						LED_TYPE_IDENTIFY);
	}
}

/*
 * Process the received LED data from SPCN
 *
 * Every LED state data is added into the CEC list. If the location
 * code is a enclosure type, its added into the enclosure list as well.
 *
 */
static void fsp_process_leds_data(u16 len)
{
	struct fsp_led_data *led_data = NULL;
	void *buf = NULL;

	/*
	 * Process the entire captured data from the last command
	 *
	 * TCE mapped 'led_buffer' contains the fsp_led_data structure
	 * one after the other till the total length 'len'.
	 *
	 */
	buf = led_buffer;
	while (len) {
		size_t lc_len;
		__be16 tmp;

		/* Prepare */
		led_data = zalloc(sizeof(struct fsp_led_data));
		assert(led_data);

		/* Resource ID */
		buf_read(buf, __be16, &tmp);
		led_data->rid = be16_to_cpu(tmp);
		len -= sizeof(led_data->rid);

		/* Location code length */
		buf_read(buf, u8, &led_data->lc_len);
		len -= sizeof(led_data->lc_len);

		lc_len = led_data->lc_len;
		if (lc_len == 0) {
			free(led_data);
			break;
		}

		if (lc_len >= LOC_CODE_SIZE)
			lc_len = LOC_CODE_SIZE - 1;

		/* Location code */
		strncpy(led_data->loc_code, buf, lc_len);
		led_data->loc_code[lc_len] = '\0';

		buf += led_data->lc_len;
		len -= led_data->lc_len;

		/* Parameters */
		buf_read(buf, __be16, &tmp);
		led_data->parms = be16_to_cpu(tmp);
		len -=  sizeof(led_data->parms);

		/* Status */
		buf_read(buf, __be16, &tmp);
		led_data->status = be16_to_cpu(tmp);
		len -=  sizeof(led_data->status);

		/*
		 * This is Enclosure LED's location code, need to go
		 * inside the enclosure LED list as well.
		 */
		if (!strstr(led_data->loc_code, "-")) {
			struct fsp_led_data *encl_led_data = NULL;
			encl_led_data = zalloc(sizeof(struct fsp_led_data));
			assert(encl_led_data);

			/* copy over the original */
			memcpy(encl_led_data, led_data, sizeof(struct fsp_led_data));

			/* Add to the list of enclosure LEDs */
			list_add_tail(&encl_ledq, &encl_led_data->link);
		}

		/* Push this onto the list */
		list_add_tail(&cec_ledq, &led_data->link);
	}
}

/* Replay the SPCN command */
static void replay_spcn_cmd(u32 last_spcn_cmd)
{
	u32 cmd_hdr = 0;
	int rc = -1;

	/* Reached threshold */
	if (replay == SPCN_REPLAY_THRESHOLD) {
		replay = 0;
		led_support = LED_STATE_ABSENT;
		return;
	}

	replay++;
	if (last_spcn_cmd == SPCN_MOD_PRS_LED_DATA_FIRST) {
		cmd_hdr = SPCN_MOD_PRS_LED_DATA_FIRST << 24 |
			SPCN_CMD_PRS << 16;
		rc = fsp_queue_msg(fsp_mkmsg(FSP_CMD_SPCN_PASSTHRU, 4,
					     SPCN_ADDR_MODE_CEC_NODE,
					     cmd_hdr, 0,
					     PSI_DMA_LED_BUF),
				   fsp_read_leds_data_complete);
		if (rc)
			prlog(PR_ERR, "Replay SPCN_MOD_PRS_LED_DATA_FIRST"
			      " command could not be queued\n");
	}

	if (last_spcn_cmd == SPCN_MOD_PRS_LED_DATA_SUB) {
		cmd_hdr = SPCN_MOD_PRS_LED_DATA_SUB << 24 | SPCN_CMD_PRS << 16;
		rc = fsp_queue_msg(fsp_mkmsg(FSP_CMD_SPCN_PASSTHRU, 4,
					     SPCN_ADDR_MODE_CEC_NODE, cmd_hdr,
					     0, PSI_DMA_LED_BUF),
				   fsp_read_leds_data_complete);
		if (rc)
			prlog(PR_ERR, "Replay SPCN_MOD_PRS_LED_DATA_SUB"
			      " command could not be queued\n");
	}

	/* Failed to queue MBOX message */
	if (rc)
		led_support = LED_STATE_ABSENT;
}

/*
 * FSP message response handler for following SPCN LED commands
 * which are used to fetch all of the LED data from SPCN
 *
 * 1. SPCN_MOD_PRS_LED_DATA_FIRST      --> First 1KB of LED data
 * 2. SPCN_MOD_PRS_LED_DATA_SUB        --> Subsequent 1KB of LED data
 *
 * Once the SPCN_RSP_STATUS_SUCCESS response code has been received
 * indicating the last batch of 1KB LED data is here, the list addition
 * process is now complete and we enable LED support for FSP async commands
 * and for OPAL interface.
 */
static void fsp_read_leds_data_complete(struct fsp_msg *msg)
{
	struct fsp_led_data *led, *next;
	struct fsp_msg *resp = msg->resp;
	u32 cmd_hdr = 0;
	int rc = 0;

	u32 msg_status = resp->word1 & 0xff00;
	u32 led_status = (fsp_msg_get_data_word(resp, 1) >> 24) & 0xff;
	u16 data_len = (u16)(fsp_msg_get_data_word(resp, 1) & 0xffff);

	if (msg_status != FSP_STATUS_SUCCESS) {
		log_simple_error(&e_info(OPAL_RC_LED_SUPPORT),
				 "FSP returned error %x LED not supported\n",
				 msg_status);
		/* LED support not available */
		led_support = LED_STATE_ABSENT;

		fsp_freemsg(msg);
		return;
	}

	/* SPCN command status */
	switch (led_status) {
	/* Last 1KB of LED data */
	case SPCN_RSP_STATUS_SUCCESS:
		prlog(PR_DEBUG, "SPCN_RSP_STATUS_SUCCESS: %d bytes received\n",
		      data_len);

		led_support = LED_STATE_PRESENT;

		/* Copy data to the local list */
		fsp_process_leds_data(data_len);

		/* LEDs captured on the system */
		prlog(PR_DEBUG, "CEC LEDs captured on the system:\n");
		list_for_each_safe(&cec_ledq, led, next, link) {
			prlog(PR_DEBUG,
			       "rid: %x\t"
			       "len: %x      "
			       "lcode: %-30s\t"
			       "parms: %04x\t"
			       "status: %04x\n",
			       led->rid,
			       led->lc_len,
			       led->loc_code,
			       led->parms,
			       led->status);
		}

		prlog(PR_DEBUG, "ENCL LEDs captured on the system:\n");
		list_for_each_safe(&encl_ledq, led, next, link) {
			prlog(PR_DEBUG,
			       "rid: %x\t"
			       "len: %x      "
			       "lcode: %-30s\t"
			       "parms: %04x\t"
			       "status: %04x\n",
			       led->rid,
			       led->lc_len,
			       led->loc_code,
			       led->parms,
			       led->status);
		}

		break;

	/* If more 1KB of LED data present */
	case SPCN_RSP_STATUS_COND_SUCCESS:
		prlog(PR_DEBUG, "SPCN_RSP_STATUS_COND_SUCCESS: %d bytes "
		      " received\n", data_len);

		/* Copy data to the local list */
		fsp_process_leds_data(data_len);

		/* Fetch the remaining data from SPCN */
		last_spcn_cmd = SPCN_MOD_PRS_LED_DATA_SUB;
		cmd_hdr = SPCN_MOD_PRS_LED_DATA_SUB << 24 | SPCN_CMD_PRS << 16;
		rc = fsp_queue_msg(fsp_mkmsg(FSP_CMD_SPCN_PASSTHRU, 4,
					     SPCN_ADDR_MODE_CEC_NODE,
					     cmd_hdr, 0, PSI_DMA_LED_BUF),
				   fsp_read_leds_data_complete);
		if (rc) {
			prlog(PR_ERR, "SPCN_MOD_PRS_LED_DATA_SUB command"
			      " could not be queued\n");

			led_support = LED_STATE_ABSENT;
		}
		break;

	/* Other expected error codes*/
	case SPCN_RSP_STATUS_INVALID_RACK:
	case SPCN_RSP_STATUS_INVALID_SLAVE:
	case SPCN_RSP_STATUS_INVALID_MOD:
	case SPCN_RSP_STATUS_STATE_PROHIBIT:
	case SPCN_RSP_STATUS_UNKNOWN:
	default:
		/* Replay the previous SPCN command */
		replay_spcn_cmd(last_spcn_cmd);
	}
	fsp_freemsg(msg);
}

/*
 * Init the LED state
 *
 * This is called during the host boot process. This is the place where
 * we figure out all the LEDs present on the system, their state and then
 * create structure out of those information and popullate two master lists.
 * One for all the LEDs on the CEC and one for all the LEDs on the enclosure.
 * The LED information contained in the lists will cater either to various
 * FSP initiated async commands or POWERNV initiated OPAL calls. Need to make
 * sure that this initialization process is complete before allowing any requets
 * on LED. Also need to be called to re-fetch data from SPCN after any LED state
 * have been updated.
 */
static void fsp_leds_query_spcn(void)
{
	struct fsp_led_data *led = NULL;
	int rc = 0;

	u32 cmd_hdr = SPCN_MOD_PRS_LED_DATA_FIRST << 24 | SPCN_CMD_PRS << 16;

	/* Till the last batch of LED data */
	last_spcn_cmd = 0;

	/* Empty the lists */
	while (!list_empty(&cec_ledq)) {
		led = list_pop(&cec_ledq, struct fsp_led_data, link);
		free(led);
	}

	while (!list_empty(&encl_ledq)) {
		led = list_pop(&encl_ledq, struct fsp_led_data, link);
		free(led);
	}

	/* Allocate buffer with alignment requirements */
	if (led_buffer == NULL) {
		led_buffer = memalign(TCE_PSIZE, PSI_DMA_LED_BUF_SZ);
		if (!led_buffer)
			return;
	}

	/* TCE mapping - will not unmap */
	fsp_tce_map(PSI_DMA_LED_BUF, led_buffer, PSI_DMA_LED_BUF_SZ);

	/* Request the first 1KB of LED data */
	last_spcn_cmd = SPCN_MOD_PRS_LED_DATA_FIRST;
	rc = fsp_queue_msg(fsp_mkmsg(FSP_CMD_SPCN_PASSTHRU, 4,
			SPCN_ADDR_MODE_CEC_NODE, cmd_hdr, 0,
				PSI_DMA_LED_BUF), fsp_read_leds_data_complete);
	if (rc)
		prlog(PR_ERR,
		      "SPCN_MOD_PRS_LED_DATA_FIRST command could"
		      " not be queued\n");
	else	/* Initiated LED list fetch MBOX command */
		led_support = LED_STATE_READING;
}

/* Init the LED subsystem at boot time */
void fsp_led_init(void)
{
	led_buffer = NULL;

	if (!fsp_present())
		return;

	/* Init the master lists */
	list_head_init(&cec_ledq);
	list_head_init(&encl_ledq);
	list_head_init(&spcn_cmdq);

	fsp_leds_query_spcn();

	loc_code_list_buffer = memalign(TCE_PSIZE, PSI_DMA_LOC_COD_BUF_SZ);
	if (loc_code_list_buffer == NULL)
		prerror("ERROR: Unable to allocate loc_code_list_buffer!\n");

	prlog(PR_TRACE, "Init completed\n");

	/* Get System attention indicator state */
	dt_get_sai_loc_code();
	fsp_get_sai();

	/* Handle FSP initiated async LED commands */
	fsp_register_client(&fsp_indicator_client, FSP_MCLASS_INDICATOR);
	prlog(PR_TRACE, "FSP async command client registered\n");

	/* Register for SAI update notification */
	sysparam_add_update_notifier(sai_update_notification);

	opal_register(OPAL_LEDS_GET_INDICATOR, fsp_opal_leds_get_ind, 4);
	opal_register(OPAL_LEDS_SET_INDICATOR, fsp_opal_leds_set_ind, 5);
	prlog(PR_TRACE, "LED OPAL interface registered\n");
}
