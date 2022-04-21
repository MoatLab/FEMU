// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2016 IBM Corp. */

#include "bitmap.h"

static int __bitmap_find_bit(bitmap_t map, unsigned int start, unsigned int count,
			     bool value)
{
	unsigned int el, first_bit;
	unsigned int end = start + count;
	bitmap_elem_t e, ev;
	int b;

	ev = value ? -1ul : 0;
	el = BITMAP_ELEM(start);
	first_bit = BITMAP_BIT(start);

	while (start < end) {
		e = map[el] ^ ev;
		e |= ((1ul << first_bit) - 1);
		if (~e)
			break;
		start = (start + BITMAP_ELSZ) & ~(BITMAP_ELSZ - 1);
		first_bit = 0;
		el++;
	}
	for (b = first_bit; b < BITMAP_ELSZ && start < end; b++,start++) {
		if ((e & (1ull << b)) == 0)
			return start;
	}

	return -1;
}

int bitmap_find_zero_bit(bitmap_t map, unsigned int start, unsigned int count)
{
	return __bitmap_find_bit(map, start, count, false);
}

int bitmap_find_one_bit(bitmap_t map, unsigned int start, unsigned int count)
{
	return __bitmap_find_bit(map, start, count, true);
}

