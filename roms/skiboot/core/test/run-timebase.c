// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2015-2016 IBM Corp.
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#define __TEST__
#include <timebase.h>

unsigned long tb_hz = 512000000;

int main(void)
{
	/* This is a fairly solid assumption that the math we're doing
	 * is based on tb_hz of exactly 512mhz.
	 * If we do start doing the math on different tb_hz, you probably
	 * want to go and audit every bit of code that touches tb to
	 * count/delay things.
	 */
	assert(tb_hz == 512000000);
	assert(secs_to_tb(1) == tb_hz);
	assert(secs_to_tb(2) == 1024000000);
	assert(secs_to_tb(10) == 5120000000);
	assert(tb_to_secs(512000000) == 1);
	assert(tb_to_secs(5120000000) == 10);
	assert(tb_to_secs(1024000000) == 2);

	assert(msecs_to_tb(1) == 512000);
	assert(msecs_to_tb(100) == 51200000);
	assert(msecs_to_tb(5) == 2560000);
	assert(tb_to_msecs(512000) == 1);

	assert(usecs_to_tb(5) == 2560);
	assert(tb_to_usecs(2560) == 5);
	assert(usecs_to_tb(5)*1000 == msecs_to_tb(5));
	assert(tb_to_usecs(512000) == 1000);

	assert(tb_compare(msecs_to_tb(5), usecs_to_tb(5)) == TB_AAFTERB);
	assert(tb_compare(msecs_to_tb(5), usecs_to_tb(50000)) == TB_ABEFOREB);
	assert(tb_compare(msecs_to_tb(5), usecs_to_tb(5)*1000) == TB_AEQUALB);

	return 0;
}
