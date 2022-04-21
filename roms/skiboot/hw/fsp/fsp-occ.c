// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * FSP/OCC interactions
 *
 * Unlike OpenPOWER machines, FSP machines are much more tightly coupled
 * between FSP, host, and OCC. On P8 we have to do a dance to start the
 * OCC, but on P9 Hostboot does that, consistent with what we do on
 * OpenPOWER.
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <skiboot.h>
#include <xscom.h>
#include <xscom-p8-regs.h>
#include <io.h>
#include <cpu.h>
#include <chip.h>
#include <mem_region.h>
#include <fsp.h>
#include <timebase.h>
#include <hostservices.h>
#include <errorlog.h>
#include <opal-api.h>
#include <opal-msg.h>
#include <timer.h>
#include <i2c.h>
#include <powercap.h>
#include <psr.h>
#include <sensor.h>
#include <occ.h>

DEFINE_LOG_ENTRY(OPAL_RC_OCC_LOAD, OPAL_PLATFORM_ERR_EVT, OPAL_OCC,
		OPAL_CEC_HARDWARE, OPAL_PREDICTIVE_ERR_GENERAL,
		OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_OCC_RESET, OPAL_PLATFORM_ERR_EVT, OPAL_OCC,
		OPAL_CEC_HARDWARE, OPAL_PREDICTIVE_ERR_GENERAL,
		OPAL_NA);

struct occ_load_req {
	u8 scope;
	u32 dbob_id;
	u32 seq_id;
	struct list_node link;
};
static LIST_HEAD(occ_load_req_list);


static void occ_queue_load(u8 scope, u32 dbob_id, u32 seq_id)
{
	struct occ_load_req *occ_req;

	occ_req = zalloc(sizeof(struct occ_load_req));
	if (!occ_req) {
		/**
		 * @fwts-label OCCload_reqENOMEM
		 * @fwts-advice ENOMEM while allocating OCC load message.
		 * OCCs not started, consequently no power/frequency scaling
		 * will be functional.
		 */
		prlog(PR_ERR, "OCC: Could not allocate occ_load_req\n");
		return;
	}

	occ_req->scope = scope;
	occ_req->dbob_id = dbob_id;
	occ_req->seq_id = seq_id;
	list_add_tail(&occ_load_req_list, &occ_req->link);
}

static void __occ_do_load(u8 scope, u32 dbob_id __unused, u32 seq_id)
{
	struct fsp_msg *stat;
	int rc = -ENOMEM;
	int status_word = 0;
	struct proc_chip *chip = next_chip(NULL);

	/* Call HBRT... */
	rc = host_services_occ_load();

	/* Handle fallback to preload */
	if (rc == -ENOENT && chip->homer_base) {
		prlog(PR_INFO, "OCC: Load: Fallback to preloaded image\n");
		rc = 0;
	} else if (!rc) {
		struct opal_occ_msg occ_msg = { CPU_TO_BE64(OCC_LOAD), 0, 0 };

		rc = _opal_queue_msg(OPAL_MSG_OCC, NULL, NULL,
				     sizeof(struct opal_occ_msg), &occ_msg);
		if (rc)
			prlog(PR_INFO, "OCC: Failed to queue message %d\n",
			      OCC_LOAD);

		/* Success, start OCC */
		rc = host_services_occ_start();
	}
	if (rc) {
		/* If either of hostservices call fail, send fail to FSP */
		/* Find a chip ID to send failure */
		for_each_chip(chip) {
			if (scope == 0x01 && dbob_id != chip->dbob_id)
				continue;
			status_word = 0xB500 | (chip->pcid & 0xff);
			break;
		}
		log_simple_error(&e_info(OPAL_RC_OCC_LOAD),
			"OCC: Error %d in load/start OCC\n", rc);
	}

	/* Send a single response for all chips */
	stat = fsp_mkmsg(FSP_CMD_LOAD_OCC_STAT, 2, status_word, seq_id);
	if (stat)
		rc = fsp_queue_msg(stat, fsp_freemsg);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_OCC_LOAD),
			"OCC: Error %d queueing FSP OCC LOAD STATUS msg", rc);
		fsp_freemsg(stat);
	}
}

void occ_poke_load_queue(void)
{
	struct occ_load_req *occ_req, *next;

	if (list_empty(&occ_load_req_list))
		return;

	list_for_each_safe(&occ_load_req_list, occ_req, next, link) {
		__occ_do_load(occ_req->scope, occ_req->dbob_id,
				occ_req->seq_id);
		list_del(&occ_req->link);
		free(occ_req);
	}
}

static u32 last_seq_id;
static bool in_ipl = true;
static void occ_do_load(u8 scope, u32 dbob_id __unused, u32 seq_id)
{
	struct fsp_msg *rsp;
	int rc = -ENOMEM;
	u8 err = 0;

	if (scope != 0x01 && scope != 0x02) {
		/**
		 * @fwts-label OCCLoadInvalidScope
		 * @fwts-advice Invalid request for loading OCCs. Power and
		 * frequency management not functional
		 */
		prlog(PR_ERR, "OCC: Load message with invalid scope 0x%x\n",
		      scope);
		err = 0x22;
	}

	/* First queue up an OK response to the load message itself */
	rsp = fsp_mkmsg(FSP_RSP_LOAD_OCC | err, 0);
	if (rsp)
		rc = fsp_queue_msg(rsp, fsp_freemsg);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_OCC_LOAD),
			"OCC: Error %d queueing FSP OCC LOAD reply\n", rc);
		fsp_freemsg(rsp);
		return;
	}

	if (err)
		return;

	if (proc_gen >= proc_gen_p9) {
		if (in_ipl) {
			/* OCC is pre-loaded in P9, so send SUCCESS to FSP */
			rsp = fsp_mkmsg(FSP_CMD_LOAD_OCC_STAT, 2, 0, seq_id);
			if (!rsp)
				return;

			rc = fsp_queue_msg(rsp, fsp_freemsg);
			if (rc) {
				log_simple_error(&e_info(OPAL_RC_OCC_LOAD),
				"OCC: Error %d queueing OCC LOAD STATUS msg",
						 rc);
				fsp_freemsg(rsp);
			}
			in_ipl = false;
		} else {
			struct proc_chip *chip = next_chip(NULL);

			last_seq_id = seq_id;
			prd_fsp_occ_load_start(chip->id);
		}
		return;
	}

	/*
	 * Check if hostservices lid caching is complete. If not, queue
	 * the load request.
	 */
	if (!hservices_lid_preload_complete()) {
		occ_queue_load(scope, dbob_id, seq_id);
		return;
	}

	__occ_do_load(scope, dbob_id, seq_id);
}

int fsp_occ_reset_status(u64 chipid, s64 status)
{
	struct fsp_msg *stat;
	int rc = OPAL_NO_MEM;
	int status_word = 0;

	prlog(PR_INFO, "HBRT: OCC stop() completed with %lld\n", status);

	if (status) {
		struct proc_chip *chip = get_chip(chipid);

		if (!chip)
			return OPAL_PARAMETER;

		status_word = 0xfe00 | (chip->pcid & 0xff);
		log_simple_error(&e_info(OPAL_RC_OCC_RESET),
				 "OCC: Error %lld in OCC reset of chip %lld\n",
				 status, chipid);
	} else {
		occ_msg_queue_occ_reset();
	}

	stat = fsp_mkmsg(FSP_CMD_RESET_OCC_STAT, 2, status_word, last_seq_id);
	if (!stat)
		return rc;

	rc = fsp_queue_msg(stat, fsp_freemsg);
	if (rc) {
		fsp_freemsg(stat);
		log_simple_error(&e_info(OPAL_RC_OCC_RESET),
			"OCC: Error %d queueing FSP OCC RESET STATUS message\n",
			rc);
	}
	return rc;
}

int fsp_occ_load_start_status(u64 chipid, s64 status)
{
	struct fsp_msg *stat;
	int rc = OPAL_NO_MEM;
	int status_word = 0;

	if (status) {
		struct proc_chip *chip = get_chip(chipid);

		if (!chip)
			return OPAL_PARAMETER;

		status_word = 0xB500 | (chip->pcid & 0xff);
		log_simple_error(&e_info(OPAL_RC_OCC_LOAD),
				 "OCC: Error %d in load/start OCC %lld\n", rc,
				 chipid);
	}

	stat = fsp_mkmsg(FSP_CMD_LOAD_OCC_STAT, 2, status_word, last_seq_id);
	if (!stat)
		return rc;

	rc = fsp_queue_msg(stat, fsp_freemsg);
	if (rc) {
		fsp_freemsg(stat);
		log_simple_error(&e_info(OPAL_RC_OCC_LOAD),
			"OCC: Error %d queueing FSP OCC LOAD STATUS msg", rc);
	}

	return rc;
}

static void occ_do_reset(u8 scope, u32 dbob_id, u32 seq_id)
{
	struct fsp_msg *rsp, *stat;
	struct proc_chip *chip = next_chip(NULL);
	int rc = -ENOMEM;
	u8 err = 0;

	/* Check arguments */
	if (scope != 0x01 && scope != 0x02) {
		/**
		 * @fwts-label OCCResetInvalidScope
		 * @fwts-advice Invalid request for resetting OCCs. Power and
		 * frequency management not functional
		 */
		prlog(PR_ERR, "OCC: Reset message with invalid scope 0x%x\n",
		      scope);
		err = 0x22;
	}

	/* First queue up an OK response to the reset message itself */
	rsp = fsp_mkmsg(FSP_RSP_RESET_OCC | err, 0);
	if (rsp)
		rc = fsp_queue_msg(rsp, fsp_freemsg);
	if (rc) {
		fsp_freemsg(rsp);
		log_simple_error(&e_info(OPAL_RC_OCC_RESET),
			"OCC: Error %d queueing FSP OCC RESET reply\n", rc);
		return;
	}

	/* If we had an error, return */
	if (err)
		return;

	/*
	 * Call HBRT to stop OCC and leave it stopped.  FSP will send load/start
	 * request subsequently.  Also after few runtime restarts (currently 3),
	 * FSP will request OCC to left in stopped state.
	 */

	switch (proc_gen) {
	case proc_gen_p8:
		rc = host_services_occ_stop();
		break;
	case proc_gen_p9:
	case proc_gen_p10:
		last_seq_id = seq_id;
		chip = next_chip(NULL);
		prd_fsp_occ_reset(chip->id);
		return;
	default:
		return;
	}

	/* Handle fallback to preload */
	if (rc == -ENOENT && chip->homer_base) {
		prlog(PR_INFO, "OCC: Reset: Fallback to preloaded image\n");
		rc = 0;
	}
	if (!rc) {
		/* Send a single success response for all chips */
		stat = fsp_mkmsg(FSP_CMD_RESET_OCC_STAT, 2, 0, seq_id);
		if (stat)
			rc = fsp_queue_msg(stat, fsp_freemsg);
		if (rc) {
			fsp_freemsg(stat);
			log_simple_error(&e_info(OPAL_RC_OCC_RESET),
				"OCC: Error %d queueing FSP OCC RESET"
					" STATUS message\n", rc);
		}
		occ_msg_queue_occ_reset();
	} else {

		/*
		 * Then send a matching OCC Reset Status message with an 0xFE
		 * (fail) response code as well to the first matching chip
		 */
		for_each_chip(chip) {
			if (scope == 0x01 && dbob_id != chip->dbob_id)
				continue;
			rc = -ENOMEM;
			stat = fsp_mkmsg(FSP_CMD_RESET_OCC_STAT, 2,
					 0xfe00 | (chip->pcid & 0xff), seq_id);
			if (stat)
				rc = fsp_queue_msg(stat, fsp_freemsg);
			if (rc) {
				fsp_freemsg(stat);
				log_simple_error(&e_info(OPAL_RC_OCC_RESET),
					"OCC: Error %d queueing FSP OCC RESET"
						" STATUS message\n", rc);
			}
			break;
		}
	}
}

static bool fsp_occ_msg(u32 cmd_sub_mod, struct fsp_msg *msg)
{
	u32 dbob_id, seq_id;
	u8 scope;

	switch (cmd_sub_mod) {
	case FSP_CMD_LOAD_OCC:
		/*
		 * We get the "Load OCC" command at boot. We don't currently
		 * support loading it ourselves (we don't have the procedures,
		 * they will come with Host Services). For now HostBoot will
		 * have loaded a OCC firmware for us, but we still need to
		 * be nice and respond to OCC.
		 */
		scope = msg->data.bytes[3];
		dbob_id = fsp_msg_get_data_word(msg, 1);
		seq_id = fsp_msg_get_data_word(msg, 2);
		prlog(PR_INFO, "OCC: Got OCC Load message, scope=0x%x"
		      " dbob=0x%x seq=0x%x\n", scope, dbob_id, seq_id);
		occ_do_load(scope, dbob_id, seq_id);
		return true;

	case FSP_CMD_RESET_OCC:
		/*
		 * We shouldn't be getting this one, but if we do, we have
		 * to reply something sensible or the FSP will get upset
		 */
		scope = msg->data.bytes[3];
		dbob_id = fsp_msg_get_data_word(msg, 1);
		seq_id = fsp_msg_get_data_word(msg, 2);
		prlog(PR_INFO, "OCC: Got OCC Reset message, scope=0x%x"
		      " dbob=0x%x seq=0x%x\n", scope, dbob_id, seq_id);
		occ_do_reset(scope, dbob_id, seq_id);
		return true;
	}
	return false;
}

static struct fsp_client fsp_occ_client = {
	.message = fsp_occ_msg,
};

void occ_fsp_init(void)
{
	/* If we have an FSP, register for notifications */
	if (fsp_present())
		fsp_register_client(&fsp_occ_client, FSP_MCLASS_OCC);
}
