// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2017 IBM Corp.
 */

#include "../bitmap.c"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void)
{
	bitmap_t *map = malloc(sizeof(bitmap_elem_t));
	int i;
	memset(map, 0, sizeof(bitmap_elem_t));

	assert(BITMAP_ELEMS(16) == (BITMAP_ELEMS(8)));
	assert(BITMAP_ELEMS(128) == (BITMAP_ELEMS(64)*2));

	assert(BITMAP_BYTES(64) == 8);
	assert(BITMAP_BYTES(128) == 16);

	assert(BITMAP_BIT(1) == 0x1);
	assert(BITMAP_BIT(2) == 0x2);
	assert(BITMAP_BIT(3) == 0x3);
	assert(BITMAP_BIT(8) == 0x8);

	assert(BITMAP_MASK(0) == 0x1);
	assert(BITMAP_MASK(1) == 0x2);
	assert(BITMAP_MASK(8) == 0x100);
	assert(BITMAP_MASK(9) == 0x200);

	assert(BITMAP_ELEM(1) == 0);
	assert(BITMAP_ELEM(128) == BITMAP_ELEMS(128));

	bitmap_set_bit(*map, 0);
	assert(*(unsigned long*)map == 0x1);
	assert(bitmap_tst_bit(*map, 0) == true);
	bitmap_clr_bit(*map, 0);
	assert(*(unsigned long*)map == 0x00);

	bitmap_set_bit(*map, 8);
	assert(*(unsigned long*)map == 0x100);
	assert(bitmap_tst_bit(*map, 0) == false);
	assert(bitmap_tst_bit(*map, 1) == false);
	assert(bitmap_tst_bit(*map, 2) == false);
	assert(bitmap_tst_bit(*map, 3) == false);
	assert(bitmap_tst_bit(*map, 4) == false);
	assert(bitmap_tst_bit(*map, 5) == false);
	assert(bitmap_tst_bit(*map, 6) == false);
	assert(bitmap_tst_bit(*map, 7) == false);
	assert(bitmap_tst_bit(*map, 8) == true);
	assert(bitmap_tst_bit(*map, 9) == false);
	assert(bitmap_tst_bit(*map, 10) == false);
	assert(bitmap_tst_bit(*map, 11) == false);
	assert(bitmap_tst_bit(*map, 12) == false);
	assert(bitmap_tst_bit(*map, 13) == false);
	assert(bitmap_tst_bit(*map, 14) == false);
	assert(bitmap_tst_bit(*map, 15) == false);
	assert(bitmap_find_one_bit(*map, 0, 16) == 8);
	bitmap_clr_bit(*map, 8);
	assert(bitmap_find_one_bit(*map, 0, 16) == -1);
	assert(*(unsigned long*)map == 0x00);
	assert(bitmap_tst_bit(*map, 8) == false);

	bitmap_for_each_zero(*map, 7, i) {
		bitmap_set_bit(*map, i);
	}

	for (i = 0; i < 7; i++)
		assert(bitmap_tst_bit(*map, i) == true);

	assert(bitmap_tst_bit(*map, 8) == false);


	free(map);

	return 0;
}
