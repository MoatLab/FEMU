// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2017 IBM Corp. */

#ifndef __SECUREBOOT_H
#define __SECUREBOOT_H

#include <platform.h>
#include <device.h>
#include "container.h"
#include "cvc.h"

enum secureboot_version {
	IBM_SECUREBOOT_V1,
	IBM_SECUREBOOT_SOFTROM,
	IBM_SECUREBOOT_V2,
};

void secureboot_enforce(void);
bool secureboot_is_compatible(struct dt_node *node, int *version, const char **compat);
void secureboot_init(void);
bool is_fw_secureboot(void);

/**
 * secureboot_verify - verify a PNOR partition content
 * @id   : PNOR partition id
 * @buf  : PNOR partition content to be verified
 * @len  : @buf length
 *
 * This verifies the integrity and authenticity of @buf downloaded from PNOR if
 * secure mode is on. The verification is done by the Container Verification
 * Code (CVC) flashed in ROM.
 *
 * For more information refer to 'doc/stb.rst'
 *
 * returns: 0 otherwise the boot process is aborted
 */
int secureboot_verify(enum resource_id id, void *buf, size_t len);

#endif /* __SECUREBOOT_H */
