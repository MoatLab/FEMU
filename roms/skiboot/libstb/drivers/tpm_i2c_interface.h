// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2018 IBM Corp. */

#ifndef __TPM_I2C_H
#define __TPM_I2C_H

#include <i2c.h>
#include <stdlib.h>

#include "../tpm_chip.h"

extern int tpm_i2c_request_send(struct tpm_dev *tpm_device, int read_write,
				uint32_t offset, uint32_t offset_bytes, void* buf,
				size_t buflen);
#endif /* __TPM_I2C_H */
