// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2018 IBM Corp. */

#include <skiboot.h>
#include <opal-api.h>
#include <i2c.h>

#include "tpm_i2c_interface.h"
#include "../status_codes.h"

/* TPMs can clock strech I2C operations for a LOOOOOOONG */
#define I2C_BYTE_TIMEOUT_MS		2000  /* 2000ms/byte timeout */

/**
 * tpm_i2c_request_send - send request to i2c bus
 * @tpm_bus_id: i2c bus id
 * @tpm_dev_addr: address of the tpm device
 * @read_write: SMBUS_READ or SMBUS_WRITE
 * @offset: any of the I2C interface offset defined
 * @offset_bytes: offset size in bytes
 * @buf: data to be read or written
 * @buflen: buf length
 *
 * This interacts with skiboot i2c API to send an I2C request to the tpm
 * device
 *
 * Returns: Zero on success otherwise a negative error code
 */
int tpm_i2c_request_send(struct tpm_dev *tpm_device, int read_write,
			 uint32_t offset, uint32_t offset_bytes, void* buf,
			 size_t buflen)
{
	int rc, timeout;

	/*
	 * Set the request timeout to 30ms per byte. Otherwise, we get
	 * an I2C master timeout for all requests sent to the device
	 * since the I2C master's timeout is too short (1ms per byte).
	 */
	timeout = (buflen + offset_bytes + 2) * I2C_BYTE_TIMEOUT_MS;

	rc = i2c_request_send(tpm_device->bus_id, tpm_device->i2c_addr,
				read_write, offset, offset_bytes, buf, buflen,
				timeout);
	if (rc == OPAL_PARAMETER)
		return STB_ARG_ERROR;
	else if (rc < 0)
		return STB_DRIVER_ERROR;
	return 0;
}
