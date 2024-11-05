// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Test result of our LPC port 80h boot progress code
 *
 * Copyright 2018-2019 IBM Corp.
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <assert.h>

#define __unused __attribute__((unused))

#define __LPC_H

uint8_t port80;
uint16_t port8x;

static int64_t lpc_probe_write(int addr_type __unused, uint32_t addr,
                        uint32_t data, uint32_t sz)
{
	assert((addr - 0x80) <= 2);
	assert(sz == 1);
	if (addr == 0x80)
		port80 = data;
	if (addr == 0x81)
		port8x = data << 8 | (port8x & 0xff);
	if (addr == 0x82)
		port8x = (port8x & 0xff00) | data;
	return 0;
}

#include "op-panel.h"

void op_display_lpc(enum op_severity s, enum op_module m, uint16_t c);

#include "../lpc-port80h.c"
#include "../../core/test/stubs.c"

enum proc_chip_quirks proc_chip_quirks;

int main(void)
{
	op_display_lpc(OP_LOG, OP_MOD_INIT, 0x00);
	assert(port80 == 0x80);
	assert(port8x == 0x8000);
	op_display_lpc(OP_WARN, OP_MOD_INIT, 0x00);
	assert(port80 == 0x82);
	assert(port8x == 0x8002);
	op_display_lpc(OP_ERROR, OP_MOD_INIT, 0x00);
	assert(port80 == 0x81);
	assert(port8x == 0x8001);
	op_display_lpc(OP_FATAL, OP_MOD_INIT, 0x00);
	assert(port80 == 0x83);
	assert(port8x == 0x8003);
	op_display_lpc(OP_FATAL, OP_MOD_INIT, 0x0f);
	assert(port80 == 0xBF);
	assert(port8x == 0x803F);
	op_display_lpc(OP_LOG, OP_MOD_INIT, 0x0f);
	assert(port80 == 0xBC);
	assert(port8x == 0x803C);
	op_display_lpc(OP_FATAL, OP_MOD_CORE, 0x6666);
	assert(port80 == 0xBF);
	assert(port8x == 0x803F);
	op_display_lpc(OP_LOG, OP_MOD_INIT, 0x01);
	assert(port80 == 0x84);
	assert(port8x == 0x8004);
	op_display_lpc(OP_LOG, OP_MOD_CPU, 0x05);
	assert(port80 == 0xC4);
	assert(port8x == 0xC014);
	op_display_lpc(OP_LOG, OP_MOD_LOCK, 0x07);
	assert(port80 == 0xDC);
	assert(port8x == 0xD01C);
	op_display_lpc(OP_FATAL, OP_MOD_LOCK, 0x07);
	assert(port80 == 0xDF);
	assert(port8x == 0xD01F);
	op_display_lpc(OP_FATAL, OP_MOD_MEM, 0x07);
	assert(port80 == 0xEF);
	assert(port8x == 0xE01F);
	op_display_lpc(OP_WARN, OP_MOD_MEM, 0x02);
	assert(port80 == 0xEA);
	assert(port8x == 0xE00A);
	op_display_lpc(OP_WARN, OP_MOD_CHIPTOD, 0x02);
	assert(port80 == 0xFA);
	assert(port8x == 0xF00A);

	/*
	 * We can't assert that OP_MOD_FSP is invalid as we'd end up
	 * trying to set port80 in the assert parth
	 */
	op_display_lpc(OP_LOG, OP_MOD_FSP, 0x00);
	assert(port80 == 0x80);
	assert(port8x == 0x8000);
	op_display_lpc(OP_LOG, OP_MOD_FSPCON, 0x00);
	assert(port80 == 0x80);
	assert(port8x == 0x8000);
	return 0;
}
