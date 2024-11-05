// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef pr_fmt
#define pr_fmt(fmt) "STB: " fmt
#endif

#include <skiboot.h>
#include <device.h>
#include <nvram.h>
#include <opal-api.h>
#include "secureboot.h"
#include "trustedboot.h"
#include "tpm_chip.h"
#include "ibmtss/TPM_Types.h"

/* For debugging only */
//#define STB_DEBUG

static bool trusted_mode = false;
static bool trusted_init = false;
static bool boot_services_exited = false;

/*
 * Partitions retrieved from PNOR must be extended to the proper PCR and
 * recorded in the event log. Later, customers may use: the PCR values to attest
 * the boot security, and the event log to inspect what measurements were
 * extended to the PCRs.
 *
 * The list below should map every skiboot event (or resource) to a PCR
 * following the TCG PC Client Platform Firmware Profile specification,
 * Family 2.0, Level 00, Revision 1.03 v51.
 *
 * Convention for skiboot events:
 *	- Events that represents data should be extended to PCR 4.
 *	- Events that represents config should be extended to PCR 5.
 *	- For the lack of an event type that fits the specific purpose,
 *	  both data and config events should be logged as EV_COMPACT_HASH.
 */
static struct {
	enum resource_id id;
	TPMI_DH_PCR pcr;
} resources[] = {
	{ RESOURCE_ID_IMA_CATALOG,	PCR_4},
	{ RESOURCE_ID_KERNEL,		PCR_4},
	{ RESOURCE_ID_CAPP,		PCR_4},
	{ RESOURCE_ID_VERSION,		PCR_4}, /* Also data for Hostboot */
};

/*
 * Event Separator - digest of 0xFFFFFFFF
 */
static struct {
	const unsigned char *event;
	const unsigned char *sha1;
	const unsigned char *sha256;
} ev_separator = {

	.event = "\xff\xff\xff\xff",

	.sha1   = "\xd9\xbe\x65\x24\xa5\xf5\x04\x7d\xb5\x86"
		  "\x68\x13\xac\xf3\x27\x78\x92\xa7\xa3\x0a",

	.sha256 = "\xad\x95\x13\x1b\xc0\xb7\x99\xc0\xb1\xaf"
		  "\x47\x7f\xb1\x4f\xcf\x26\xa6\xa9\xf7\x60"
		  "\x79\xe4\x8b\xf0\x90\xac\xb7\xe8\x36\x7b"
		  "\xfd\x0e"
};

static TPM_Pcr map_pcr(enum resource_id id)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(resources); i++) {
		if (resources[i].id == id)
			return resources[i].pcr;
	}
	return -1;
}

void trustedboot_init(void)
{
	struct dt_node *node;

	node = dt_find_by_path(dt_root, "/ibm,secureboot");
	if (!node) {
		prlog(PR_NOTICE, "trusted boot not supported\n");
		return;
	}

	if (!secureboot_is_compatible(node, NULL, NULL)) {
		/**
		 * @fwts-label TrustedBootNotCompatible
		 * @fwts-advice Compatible trustedboot driver not found. Probably,
		 * hostboot/mambo/skiboot has updated the
		 * /ibm,secureboot/compatible without adding a driver that
		 * supports it.
		 */
		prlog(PR_ERR, "trustedboot init FAILED, '%s' node not "
		      "compatible.\n", node->name);
		return;
	}

	if (nvram_query_eq_dangerous("force-trusted-mode", "true")) {
		trusted_mode = true;
		prlog(PR_NOTICE, "trusted mode on (FORCED by nvram)\n");
	} else {
		trusted_mode = dt_has_node_property(node, "trusted-enabled", NULL);
		prlog(PR_INFO, "trusted mode %s\n",
		      trusted_mode ? "on" : "off");
	}

	if (!trusted_mode)
		return;

	cvc_init();
	tpm_init();

	trusted_init = true;
	boot_services_exited = false;
}

int trustedboot_exit_boot_services(void)
{
	uint32_t pcr;
	int rc = 0;
	bool failed = false;

	if (!trusted_mode)
		goto out_free;

	if (boot_services_exited) {
		prlog(PR_WARNING, "Trusted boot services exited before.\n");
		goto out_free;
	}

	boot_services_exited = true;
#ifdef STB_DEBUG
	prlog(PR_NOTICE, "ev_separator.event: %s\n", ev_separator.event);
	prlog(PR_NOTICE, "ev_separator.sha1:\n");
	stb_print_data((uint8_t*) ev_separator.sha1, SHA1_DIGEST_SIZE);
	prlog(PR_NOTICE, "ev_separator.sha256:\n");
	stb_print_data((uint8_t*) ev_separator.sha256, SHA256_DIGEST_SIZE);
#endif
	/*
	 * Extend the digest of 0xFFFFFFFF to PCR[0-7] and record it as
	 * EV_SEPARATOR
	 */
	for (pcr = 0; pcr < 8; pcr++) {
		rc = tpm_extendl(pcr,
				TPM_ALG_SHA256, (uint8_t*) ev_separator.sha256,
				TPM_ALG_SHA1, (uint8_t*) ev_separator.sha1,
				EV_SEPARATOR, ev_separator.event,
				strlen(ev_separator.event));
		if (rc)
			failed = true;
	}
	tpm_add_status_property();
	tss_set_platform_auth();

out_free:
	tpm_cleanup();

	return (failed) ? -1 : 0;
}

int trustedboot_measure(enum resource_id id, void *buf, size_t len)
{
	uint8_t digest[SHA512_DIGEST_LENGTH];
	void *buf_aux;
	size_t len_aux;
	const char *name;
	TPMI_DH_PCR pcr;
	int rc = -1;

	if (!trusted_mode)
		return 1;

	name = flash_map_resource_name(id);
	if (!name) {
		/**
		 * @fwts-label ResourceNotMeasuredUnknown
		 * @fwts-advice This is a bug in the trustedboot_measure()
		 * caller, which is passing an unknown resource_id.
		 */
		prlog(PR_ERR, "resource NOT MEASURED, resource_id=%d unknown\n", id);
		return -1;
	}

        if (!trusted_init) {
                prlog(PR_ERR, "resource NOT MEASURED, resource_id=%d "
                      "trustedboot not yet initialized\n", id);
                return -1;
        }

	if (boot_services_exited) {
		prlog(PR_ERR, "%s NOT MEASURED. Already exited from boot "
		      "services\n", name);
		return -1;
	}
	pcr = map_pcr(id);
	if (pcr == -1) {
		/**
		 * @fwts-label ResourceNotMappedToPCR
		 * @fwts-advice This is a bug. The resource cannot be measured
		 * because it is not mapped to a PCR in the resources[] array.
		 */
		prlog(PR_ERR, "%s NOT MEASURED, it's not mapped to a PCR\n", name);
		return -1;
	}
	if (!buf) {
		/**
		 * @fwts-label ResourceNotMeasuredNull
		 * @fwts-advice This is a bug. The trustedboot_measure() caller
		 * provided a NULL container.
		 */
		prlog(PR_ERR, "%s NOT MEASURED, it's null\n", name);
		return -1;
	}
	if (stb_is_container(buf, len)) {
		buf_aux = buf + SECURE_BOOT_HEADERS_SIZE;
		len_aux = len - SECURE_BOOT_HEADERS_SIZE;
	} else {
		buf_aux = buf;
		len_aux = len;
	}

	rc = call_cvc_sha512(buf_aux, len_aux, digest, SHA512_DIGEST_LENGTH);

	if (rc == OPAL_SUCCESS) {
		prlog(PR_NOTICE, "%s hash calculated\n", name);
	} else if (rc == OPAL_PARAMETER) {
		prlog(PR_ERR, "%s NOT MEASURED, invalid param. buf=%p, "
		      "len=%zd, digest=%p\n", name, buf_aux,
		      len_aux, digest);
		return -1;
	} else if (rc == OPAL_UNSUPPORTED) {
		prlog(PR_ERR, "%s NOT MEASURED, CVC-sha512 service not "
		      "supported\n", name);
		return -1;
	} else {
		prlog(PR_ERR, "%s NOT MEASURED, unknown CVC-sha512 error. "
		      "rc=%d\n", name, rc);
		return -1;
	}

#ifdef STB_DEBUG
	stb_print_data(digest, SHA256_DIGEST_SIZE);

#endif
	/*
	 * Extend the given PCR number in both sha256 and sha1 banks with the
	 * sha512 hash calculated. The hash is truncated accordingly to fit the
	 * PCR.
	 */
	return tpm_extendl(pcr,	TPM_ALG_SHA256, (uint8_t*) digest,
			   TPM_ALG_SHA1, (uint8_t*) digest,
			   EV_COMPACT_HASH, name, strlen(name));
}
