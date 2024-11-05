// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef pr_fmt
#define pr_fmt(fmt) "STB: " fmt
#endif

#include <skiboot.h>
#include <device.h>
#include <nvram.h>
#include <opal-api.h>
#include <inttypes.h>
#include "secureboot.h"

static const void* hw_key_hash = NULL;
static size_t hw_key_hash_size;
static bool secure_mode = false;
static bool secure_init = false;
static unsigned int level = PR_ERR;

static struct {
	enum secureboot_version version;
	const char *compat;
} secureboot_map[] = {
	{ IBM_SECUREBOOT_V1, "ibm,secureboot-v1" },
	{ IBM_SECUREBOOT_SOFTROM, "ibm,secureboot-v1-softrom" },
	{ IBM_SECUREBOOT_V2, "ibm,secureboot-v2" },
};

void secureboot_enforce(void)
{
	/* Sanity check */
	if (!secure_mode)
		return;

	/*
	 * TODO: Ideally, the BMC should decide what security policy to apply
	 * (power off, reboot, switch PNOR sides, etc). We may need to provide
	 * extra info to BMC other than just abort.  Terminate Immediate
	 * Attention ? (TI)
	 */
	prlog(PR_EMERG, "secure mode enforced, aborting.\n");
	abort();
}

bool secureboot_is_compatible(struct dt_node *node, int *version, const char **compat)
{
	int i;

	if (!node)
		return false;

	for (i = 0; i < ARRAY_SIZE(secureboot_map); i++) {
		if (dt_node_is_compatible(node, secureboot_map[i].compat)) {
			if (version)
				*version = secureboot_map[i].version;
			if (compat)
				*compat = secureboot_map[i].compat;
			return true;
		}
	}
	return false;
}

bool is_fw_secureboot(void)
{
	return secure_mode;
}

void secureboot_init(void)
{
	struct dt_node *node;
	const char *hash_algo;
	const char *compat = NULL;
	int version;
	size_t size;

	node = dt_find_by_path(dt_root, "/ibm,secureboot");
	if (!node) {
		prlog(PR_NOTICE, "secure boot not supported\n");
		return;
	}

	if (!secureboot_is_compatible(node, &version, &compat)) {
		/**
		 * @fwts-label SecureBootNotCompatible
		 * @fwts-advice Compatible secureboot driver not found. Probably,
		 * hostboot/mambo/skiboot has updated the
		 * /ibm,secureboot/compatible without adding a driver that
		 * supports it.
		 */
		prlog(PR_ERR, "%s FAILED, /ibm,secureboot not compatible.\n",
		      __func__);
		return;
	}

	prlog(PR_DEBUG, "Found %s\n", compat);

	if (nvram_query_eq_dangerous("force-secure-mode", "always")) {
		secure_mode = true;
		prlog(PR_NOTICE, "secure mode on (FORCED by nvram)\n");
	} else {
		secure_mode = dt_has_node_property(node, "secure-enabled", NULL);
		prlog(PR_INFO, "secure mode %s\n",
		      secure_mode ? "on" : "off");
	}

	/* Use emergency log level only when secure mode is ON */
        if (secure_mode)
                level = PR_EMERG;
        else
                level = PR_ERR;

	if (version == IBM_SECUREBOOT_V1 ||
	    version == IBM_SECUREBOOT_SOFTROM) {

		hash_algo = dt_prop_get(node, "hash-algo");
		if (strcmp(hash_algo, "sha512")) {
			/**
			 * @fwts-label HashAlgoInvalid
			 * @fwts-advice Hash algorithm invalid, secureboot
			 * containers version 1 requires sha512. If you're
			 * running the latest POWER firmware, so probably there
			 * is a bug in the device tree received from hostboot.
			 */
			prlog(level, "secureboot init FAILED, hash-algo=%s "
			      "not supported\n", hash_algo);
			secureboot_enforce();
		}
		hw_key_hash_size = SHA512_DIGEST_LENGTH;

	} else if (version == IBM_SECUREBOOT_V2) {

		hw_key_hash_size = dt_prop_get_u32(node, "hw-key-hash-size");
		if (hw_key_hash_size == 0) {
			prlog(level, "hw-key-hash-size=%zd too short\n",
			      hw_key_hash_size);
			secureboot_enforce();
		}
		if (hw_key_hash_size > SHA512_DIGEST_LENGTH) {
			prlog(level, "hw-key-hash-size=%zd too big\n",
			      hw_key_hash_size);
			secureboot_enforce();
		}

	} else {
		prlog(level, "%s FAILED. /ibm,secureboot not supported",
		      __func__);
		secureboot_enforce();
	}

	hw_key_hash = dt_prop_get_def_size(node, "hw-key-hash", NULL, &size);
	if (!hw_key_hash) {
		prlog(level, "hw-key-hash not found\n");
		secureboot_enforce();
	}
	if (size != hw_key_hash_size) {
	       prlog(level, "hw_key-hash wrong size %zd (expected=%zd)\n",
		     size, hw_key_hash_size);
	       secureboot_enforce();
	}
	if (cvc_init())
		secureboot_enforce();

	secure_init = true;
}

int secureboot_verify(enum resource_id id, void *buf, size_t len)
{
	const char *name;
	__be64 log;
	int rc = -1;

	name = flash_map_resource_name(id);
	if (!name) {
		prlog(level, "container NOT VERIFIED, resource_id=%d "
		      "unknown\n", id);
		secureboot_enforce();
		return -1;
	}

        if (!secure_init) {
                prlog(level, "container NOT VERIFIED, resource_id=%d "
                      "secureboot not yet initialized\n", id);
		secureboot_enforce();
		return -1;
        }

	rc = call_cvc_verify(buf, len, hw_key_hash, hw_key_hash_size, &log);

	if (rc == OPAL_SUCCESS) {
		prlog(PR_NOTICE, "%s verified\n", name);
	} else if (rc == OPAL_PARTIAL) {
		/*
		 * The value returned in log indicates what checking has
		 * failed. Return codes defined in
		 * /hostboot/src/include/securerom/status_codes.H
		 */
		prlog(level, "%s verification FAILED. log=0x%" PRIx64 "\n",
			name, be64_to_cpu(log));
		secureboot_enforce();
	} else if (rc == OPAL_PARAMETER) {
		prlog(level, "%s NOT VERIFIED, invalid param. buf=%p, "
		      "len=%zd key-hash=%p hash-size=%zd\n", name, buf, len,
		      hw_key_hash, hw_key_hash_size);
		secureboot_enforce();
	} else if (rc == OPAL_UNSUPPORTED) {
		prlog(level, "%s NOT VERIFIED, CVC-verify service not "
		      "supported\n", name);
		secureboot_enforce();
	} else {
		prlog(level, "%s NOT VERIFIED, unknown CVC-verify error. "
		      "rc=%d\n", name, rc);
		secureboot_enforce();
	}
	return 0;
}
