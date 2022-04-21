// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Parse VERSION partition, add to device tree
 *
 * Copyright 2013-2018 IBM Corp.
 */

#include <skiboot.h>
#include <device.h>
#include <opal.h>
#include <libstb/secureboot.h>
#include <libstb/trustedboot.h>

/* ibm,firmware-versions support */
static char *version_buf;
static size_t version_buf_size = 0x2000;

static void __flash_dt_add_fw_version(struct dt_node *fw_version, char* data)
{
	static bool first = true;
	char *prop;
	int version_len, i;
	int len = strlen(data);
	const char *skiboot_version;
	const char * version_str[] = {"open-power", "buildroot", "skiboot",
				      "hostboot-binaries", "hostboot", "linux",
				      "petitboot", "occ", "capp-ucode", "sbe",
				      "machine-xml", "hcode"};

	if (first) {
		first = false;

		/* Increment past "key-" */
		if (memcmp(data, "open-power", strlen("open-power")) == 0)
			prop = data + strlen("open-power");
		else
			prop = strchr(data, '-');
		if (!prop) {
			prlog(PR_DEBUG,
			      "FLASH: Invalid fw version format (%s)\n", data);
			return;
		}
		prop++;

		dt_add_property_string(fw_version, "version", prop);
		return;
	}

	/*
	 * PNOR version strings are not easily consumable. Split them into
	 * property, value.
	 *
	 * Example input from PNOR :
	 *   "open-power-firestone-v1.8"
	 *   "linux-4.4.6-openpower1-8420e0f"
	 *
	 * Desired output in device tree:
	 *   open-power = "firestone-v1.8";
	 *   linux = "4.4.6-openpower1-8420e0f";
	 */
	for(i = 0; i < ARRAY_SIZE(version_str); i++)
	{
		version_len = strlen(version_str[i]);
		if (len < version_len)
			continue;

		if (memcmp(data, version_str[i], version_len) != 0)
			continue;

		/* Found a match, add property */
		if (dt_find_property(fw_version, version_str[i]))
			continue;

		/* Increment past "key-" */
		prop = data + version_len + 1;
		dt_add_property_string(fw_version, version_str[i], prop);

		/* Sanity check against what Skiboot thinks its version is. */
		if (strncmp(version_str[i], "skiboot",
					strlen("skiboot")) == 0) {
			/*
			 * If Skiboot was built with Buildroot its version may
			 * include a 'skiboot-' prefix; ignore it.
			 */
			if (strncmp(version, "skiboot-",
						strlen("skiboot-")) == 0)
				skiboot_version = version + strlen("skiboot-");
			else
				skiboot_version = version;
			if (strncmp(prop, skiboot_version,
						strlen(skiboot_version)) != 0)
				prlog(PR_WARNING, "WARNING! Skiboot version does not match VERSION partition!\n");
		}
	}
}

void flash_dt_add_fw_version(void)
{
	uint8_t version_data[80];
	int rc;
	int numbytes = 0, i = 0;
	struct dt_node *fw_version;

	if (version_buf == NULL)
		return;

	rc = wait_for_resource_loaded(RESOURCE_ID_VERSION, RESOURCE_SUBID_NONE);
	if (rc != OPAL_SUCCESS) {
		prlog(PR_WARNING, "FLASH: Failed to load VERSION data\n");
		free(version_buf);
		return;
	}

	fw_version = dt_new(dt_root, "ibm,firmware-versions");
	assert(fw_version);

	if (stb_is_container(version_buf, version_buf_size))
		numbytes += SECURE_BOOT_HEADERS_SIZE;
	for ( ; (numbytes < version_buf_size) && version_buf[numbytes]; numbytes++) {
		if (version_buf[numbytes] == '\n') {
			version_data[i] = '\0';
			__flash_dt_add_fw_version(fw_version, version_data);
			memset(version_data, 0, sizeof(version_data));
			i = 0;
			continue;
		} else if (version_buf[numbytes] == '\t') {
			continue; /* skip tabs */
		}

		version_data[i++] = version_buf[numbytes];
		if (i == sizeof(version_data)) {
			prlog(PR_WARNING, "VERSION item >%lu chars, skipping\n",
			      sizeof(version_data));
			break;
		}
	}

	free(version_buf);
}

void flash_fw_version_preload(void)
{
	int rc;

	if (proc_gen < proc_gen_p9)
		return;

	prlog(PR_INFO, "FLASH: Loading VERSION section\n");

	version_buf = malloc(version_buf_size);
	if (!version_buf) {
		prlog(PR_WARNING, "FLASH: Failed to allocate memory\n");
		return;
	}

	rc = start_preload_resource(RESOURCE_ID_VERSION, RESOURCE_SUBID_NONE,
				    version_buf, &version_buf_size);
	if (rc != OPAL_SUCCESS) {
		prlog(PR_WARNING,
		      "FLASH: Failed to start loading VERSION data\n");
		free(version_buf);
		version_buf = NULL;
	}
}
