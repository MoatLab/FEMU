// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2015 IBM Corp */

#ifndef __I2C_H
#define __I2C_H

int i2c_read(uint32_t chip_id, uint8_t engine, uint8_t port,
	     uint16_t device, uint32_t offset_size, uint32_t offset,
	     uint32_t length, void* data);

int i2c_write(uint32_t chip_id, uint8_t engine, uint8_t port,
	      uint16_t device, uint32_t offset_size, uint32_t offset,
	      uint32_t length, void* data);

void i2c_init(void);

#endif /* __I2c_H */
