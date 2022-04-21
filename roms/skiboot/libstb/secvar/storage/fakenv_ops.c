// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2020 IBM Corp. */
#include <skiboot.h>
#include "secboot_tpm.h"

/* Offset into the SECBOOT PNOR partition to write "TPMNV" data */
static size_t fakenv_offset = sizeof(struct secboot);

struct fake_tpmnv {
	struct {
		struct secboot_header header;
		char vars[2048]; // Hardcode the size to 2048 for now
	} vars;
	struct tpmnv_control control;
	int defined[2];
} __attribute__((packed));

static struct fake_tpmnv fakenv;
static int tpm_ready;


static inline void *nv_index_address(int index)
{
	switch (index) {
	case SECBOOT_TPMNV_VARS_INDEX:
		return &fakenv.vars;
	case SECBOOT_TPMNV_CONTROL_INDEX:
		return &fakenv.control;
	default:
		return 0;
	}
}


static int tpm_init(void)
{
	int rc;

	if (tpm_ready)
		return 0;

	rc = flash_secboot_read(&fakenv, fakenv_offset, sizeof(struct fake_tpmnv));
	if (rc)
		return rc;

	tpm_ready = 1;

	return 0;
}

static int fakenv_read(TPMI_RH_NV_INDEX nvIndex, void *buf,
		       size_t bufsize,  uint16_t off)
{
	if (tpm_init())
		return OPAL_INTERNAL_ERROR;

	memcpy(buf, nv_index_address(nvIndex) + off, bufsize);

	return 0;
}

static int fakenv_write(TPMI_RH_NV_INDEX nvIndex, void *buf,
			size_t bufsize, uint16_t off)
{
	if (tpm_init())
		return OPAL_INTERNAL_ERROR;

	memcpy(nv_index_address(nvIndex) + off, buf, bufsize);

	/* Just write the whole NV struct for now */
	return flash_secboot_write(fakenv_offset, &fakenv, sizeof(struct fake_tpmnv));
}

static int fakenv_definespace(TPMI_RH_NV_INDEX nvIndex, uint16_t dataSize)
{
	if (tpm_init())
		return OPAL_INTERNAL_ERROR;

	(void) dataSize;

	switch (nvIndex) {
	case SECBOOT_TPMNV_VARS_INDEX:
		fakenv.defined[0] = 1;
		return 0;
	case SECBOOT_TPMNV_CONTROL_INDEX:
		fakenv.defined[1] = 1;
		return 0;
	}

	return OPAL_INTERNAL_ERROR;
}

static int fakenv_writelock(TPMI_RH_NV_INDEX nvIndex)
{
	if (tpm_init())
		return OPAL_INTERNAL_ERROR;

	(void) nvIndex;

	return 0;
}

static int fakenv_get_defined_indices(TPMI_RH_NV_INDEX **indices, size_t *count)
{
	if (tpm_init())
		return OPAL_INTERNAL_ERROR;

	*indices = zalloc(sizeof(fakenv.defined));
	if (*indices == NULL)
		return OPAL_NO_MEM;

	*count = 0;

	if (fakenv.defined[0]) {
		*indices[0] = SECBOOT_TPMNV_VARS_INDEX;
		(*count)++;
	}
	if (fakenv.defined[1]) {
		*indices[1] = SECBOOT_TPMNV_CONTROL_INDEX;
		(*count)++;
	}

	return 0;
}

static int fakenv_undefinespace(TPMI_RH_NV_INDEX index)
{
	if (tpm_init())
		return OPAL_INTERNAL_ERROR;

	switch (index) {
	case SECBOOT_TPMNV_VARS_INDEX:
		fakenv.defined[0] = 0;
		memset(&fakenv.vars, 0, sizeof(fakenv.vars));
		return 0;
	case SECBOOT_TPMNV_CONTROL_INDEX:
		fakenv.defined[1] = 0;
		memset(&fakenv.control, 0, sizeof(fakenv.control));
		return 0;
	}

	return -1;
}

static int fakenv_readpublic(TPMI_RH_NV_INDEX index, TPMS_NV_PUBLIC *nv_public,
			     TPM2B_NAME *nv_name)
{
	if (tpm_init())
		return OPAL_INTERNAL_ERROR;

	(void) nv_public;

	switch (index) {
	case SECBOOT_TPMNV_VARS_INDEX:
		memcpy(&nv_name->t.name, tpmnv_vars_name, sizeof(TPM2B_NAME));
		break;
	case SECBOOT_TPMNV_CONTROL_INDEX:
		memcpy(&nv_name->t.name, tpmnv_control_name, sizeof(TPM2B_NAME));
		break;
	default:
		return OPAL_INTERNAL_ERROR;
	}

	return 0;
}

struct tpmnv_ops_s tpmnv_ops = {
	.read = fakenv_read,
	.write = fakenv_write,
	.writelock = fakenv_writelock,
	.definespace = fakenv_definespace,
	.getindices = fakenv_get_defined_indices,
	.undefinespace = fakenv_undefinespace,
	.readpublic = fakenv_readpublic,
};
