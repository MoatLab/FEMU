// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2018 IBM Corp. */

#ifndef pr_fmt
#define pr_fmt(fmt) "STB: " fmt
#endif

#include <skiboot.h>
#include <device.h>
#include <string.h>
#include "container.h"
#include "tpm_chip.h"
#include "drivers/tpm_i2c_nuvoton.h"
#include <eventlog.h>

/* For debugging only */
//#define STB_DEBUG

static struct list_head tpm_list = LIST_HEAD_INIT(tpm_list);

static struct tpm_dev *tpm_device = NULL;
static struct tpm_driver *tpm_driver = NULL;

void tss_tpm_register(struct tpm_dev *dev, struct tpm_driver *driver)
{
	tpm_device = dev;
	tpm_driver = driver;
}

void tss_tpm_unregister(void)
{
	tpm_device = NULL;
	tpm_driver = NULL;
}

struct tpm_dev* tpm_get_device(void)
{
	return tpm_device;
}

struct tpm_driver* tpm_get_driver(void)
{
	return tpm_driver;
}

#ifdef STB_DEBUG
static void tpm_print_pcr(TPMI_DH_PCR pcr, TPM_ALG_ID alg,
			  size_t size)
{
	int rc;
	uint8_t digest[TPM_ALG_SHA256_SIZE];

	memset(digest, 0, size);

	rc = tss_pcr_read(pcr, &alg, 1);
	if (rc) {
		/**
		 * @fwts-label STBPCRReadFailed
		 * @fwts-advice STB_DEBUG should not be enabled
		 * in production. PCR read operation failed.
		 * This TSS implementation is part of hostboot,
		 * but the source code is shared with skiboot.
		 * 1) The hostboot TSS may have been updated.
		 * 2) This may be caused by the short I2C
		 * timeout and can be fixed by increasing the
		 * timeout. Otherwise this indicates a bug in
		 * the TSS or the TPM device driver. Each one
		 * has local debug macros that can help.
		 */
		prlog(PR_ERR, "tpmCmdPcrRead() failed: "
		      "tpm%d, alg=%x, pcr%d, rc=%d\n",
		      tpm->id, alg, pcr, rc);
	} else {
		prlog(PR_NOTICE,"print pcr-read: tpm%d alg=0x%x pcr%d\n",
		      tpm->id, alg, pcr);
		stb_print_data(digest, size);
	}
}
#endif

int tpm_register_chip(struct dt_node *node, struct tpm_dev *dev,
		       struct tpm_driver *driver)
{
	int i, rc;
	uint64_t sml_base;
	uint32_t sml_size;
	struct tpm_chip *tpm;

	i = 0;
	list_for_each(&tpm_list, tpm, link) {
		if (tpm->node == node) {
			/**
			 * @fwts-label TPMAlreadyRegistered
			 * @fwts-advice TPM node already registered. The same
			 * node is being registered twice or there is a
			 * tpm node duplicate in the device tree
			 */
			prlog(PR_WARNING, "tpm%d already registered\n", tpm->id);
			return -1;
		}
		i++;
	}

	tpm = (struct tpm_chip*) malloc(sizeof(struct tpm_chip));
	assert(tpm);
	tpm->id = i;

	/*
	 * Read event log info from the tpm device tree node. Both
	 * linux,sml-base and linux,sml-size properties are documented in
	 * 'doc/device-tree/tpm.rst'
	 */

	sml_base = dt_prop_get_u64_def(node, "linux,sml-base", 0);

	/* Check if sml-base is really 0 or it just doesn't exist */
	if (!sml_base &&
	    !dt_find_property(node, "linux,sml-base")) {
		/**
		 * @fwts-label TPMSmlBaseNotFound
		 * @fwts-advice linux,sml-base property not found. This
		 * indicates a Hostboot bug if the property really
		 * doesn't exist in the tpm node.
		 */
		prlog(PR_ERR, "linux,sml-base property not found "
		      "tpm node %p\n", node);
		goto disable;
	}

	sml_size = dt_prop_get_u32_def(node, "linux,sml-size", 0);

	if (!sml_size) {
		/**
		 * @fwts-label TPMSmlSizeNotFound
		 * @fwts-advice linux,sml-size property not found. This
		 * indicates a Hostboot bug if the property really
		 * doesn't exist in the tpm node.
		 */
		prlog(PR_ERR, "linux,sml-size property not found, "
		      "tpm node %p\n", node);
		goto disable;
	}

	/*
	 * Initialize the event log manager by walking through the log to identify
	 * what is the next free position in the log
	 */
	rc = load_eventlog(&tpm->logmgr, (int8_t*) sml_base, sml_size);

	if (rc) {
		/**
		 * @fwts-label TPMInitEventLogFailed
		 * @fwts-advice Hostboot creates and adds entries to the
		 * event log. The failed init function is part of hostboot,
		 * but the source code is shared with skiboot. If the hostboot
		 * TpmLogMgr code (or friends) has been updated, the changes
		 * need to be applied to skiboot as well.
		 */
		prlog(PR_ERR, "eventlog init failed: tpm%d rc=%d\n",
		      tpm->id, rc);
		goto disable;
	}

	tpm->enabled = true;
	tpm->node = node;
	tpm->dev = dev;
	tpm->driver = driver;

	list_add_tail(&tpm_list, &tpm->link);

	prlog(PR_NOTICE, "Found tpm%d,%s evLogLen=%d evLogSize=%d\n",
	      tpm->id, tpm->driver->name, tpm->logmgr.logSize,
	      tpm->logmgr.logMaxSize);

	return 0;

disable:
	dt_add_property_string(node, "status", "disabled");
	prlog(PR_NOTICE, "tpm node %p disabled\n", node);
	free(tpm);
	return -1;
}

int tpm_init(void)
{
	if (!list_empty(&tpm_list))
		return 0;

	list_head_init(&tpm_list);

	/* tpm drivers supported */
	tpm_i2c_nuvoton_probe();

	if (list_empty(&tpm_list)) {
		prlog(PR_INFO, "no compatible tpm device found!\n");
		return -1;
	}
	return 0;
}

void tpm_cleanup(void)
{
	struct tpm_chip *tpm = NULL;

	tpm = list_pop(&tpm_list, struct tpm_chip, link);

	while (tpm) {
		if (tpm->dev)
			free(tpm->dev);
		tpm->driver = NULL;
		free(tpm);
		tpm = list_pop(&tpm_list, struct tpm_chip, link);
	}

	tss_tpm_unregister();
	list_head_init(&tpm_list);
}

static void tpm_disable(struct tpm_chip *tpm)
{
	assert(tpm);
	tpm->enabled = false;
	prlog(PR_NOTICE, "tpm%d disabled\n", tpm->id);
}

int tpm_extendl(TPMI_DH_PCR pcr,
		TPMI_ALG_HASH alg1, uint8_t *digest1,
		TPMI_ALG_HASH alg2, uint8_t *digest2,
		uint32_t event_type, const char *event_msg,
		uint32_t event_msg_len)
{
	int rc, failed;
	TCG_PCR_EVENT2 *event = calloc(1, sizeof(TCG_PCR_EVENT2));
	struct tpm_chip *tpm = NULL;
	uint8_t hashes_len = 2;
	TPMI_ALG_HASH hashes[2] = {alg1, alg2};
	const uint8_t *digests[] = {digest1, digest2};

	failed = 0;

	if (list_empty(&tpm_list)) {
		prlog(PR_ERR, "%s (pcr%d) NOT MEASURED. No TPM "
		      "registered/enabled\n",
		      (event_type==EV_SEPARATOR) ? "EV_SEPARATOR" : event_msg,
		      pcr);
		return -1;
	}

	list_for_each(&tpm_list, tpm, link) {
		if (!tpm->enabled)
			continue;
		/* instantiate eventlog */
		rc = build_event(event, pcr, hashes, hashes_len, digests,
				 event_type, event_msg, event_msg_len);

		if (rc == 0)
			/* eventlog recording */
			rc = add_to_eventlog(&tpm->logmgr, event);
		if (rc) {
			/**
			 * @fwts-label STBAddEventFailed
			 * @fwts-advice TpmLogMgr failed to add a new event
			 * to the event log. TpmLogMgr is part of hostboot,
			 * but the source code is shared with skiboot.
			 * 1) The hostboot TpmLogMgr code may have
			 * been updated.
			 * 2) Check that max event log size was not reached
			 * and log marshall executed with no error. Enabling the
			 * trace routines in trustedbootUtils.H may help.
			 */
			prlog(PR_ERR, "%s -> evLog%d FAILED: pcr%d evType=0x%x rc=%d\n",
			      (event_type==EV_SEPARATOR) ? "EV_SEPARATOR" : event_msg,
			      tpm->id, pcr, event_type, rc);
			tpm_disable(tpm);
			failed++;
			continue;
		}
#ifdef STB_DEBUG
		if (rc == 0)
			prlog(PR_NOTICE, "%s -> evLog%d: pcr%d evType=0x%x "
			      "evLogLen=%d\n",
			      (event_type==EV_SEPARATOR) ? "EV_SEPARATOR" : event_msg,
			      tpm->id, pcr, event_type, tpm->logmgr.logSize);
		tpm_print_pcr(tpm, pcr, alg1, size1);
		tpm_print_pcr(tpm, pcr, alg2, size2);
#endif
		/* extend the pcr number in both sha1 and sha256 banks*/
		rc = tss_pcr_extend(pcr, hashes, hashes_len, digests);
		if (rc) {
			/**
			 * @fwts-label STBPCRExtendFailed
			 * @fwts-advice PCR extend operation failed. This TSS
			 * implementation is part of hostboot, but the source
			 * code is shared with skiboot.
			 * 1) The hostboot TSS may have been updated.
			 * 2) This may be caused by the short I2C timeout and
			 * can be fixed by increasing the timeout. Otherwise,
			 * this indicates a bug in the TSS or the TPM
			 * device driver. Each one has local debug macros that
			 * can help.
			 */
			prlog(PR_ERR, "%s -> tpm%d FAILED: pcr%d rc=%d\n",
			      (event_type==EV_SEPARATOR) ? "EV_SEPARATOR" : event_msg,
			      tpm->id, pcr, rc);
			tpm_disable(tpm);
			failed++;
			continue;
		}
#ifdef STB_DEBUG
		if (rc == 0) {
			prlog(PR_NOTICE, "%s -> tpm%d: pcr%d\n",
			      (event_type==EV_SEPARATOR) ? "EV_SEPARATOR" : event_msg,
			      tpm->id, pcr);
			tpm_print_pcr(tpm, pcr, alg1, size1);
			tpm_print_pcr(tpm, pcr, alg2, size2);
		}
#endif
		prlog(PR_NOTICE, "%s measured on pcr%d (tpm%d, evType 0x%x, "
		      "evLogLen %d)\n",
		      (event_type==EV_SEPARATOR) ? "EV_SEPARATOR" : event_msg,
		      pcr, tpm->id, event_type, tpm->logmgr.logSize);
	}

	if (failed > 0)
		return -2;
	return 0;
}

void tpm_add_status_property(void) {
	struct tpm_chip *tpm;
	list_for_each(&tpm_list, tpm, link) {
		dt_add_property_string(tpm->node, "status",
				       tpm->enabled ? "okay" : "disabled");
	}
}
