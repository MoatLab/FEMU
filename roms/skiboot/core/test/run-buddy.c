// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2016-2017 IBM Corp.
 */

#include <buddy.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

static void *zalloc(size_t size)
{
        return calloc(size, 1);
}

#include "../buddy.c"
#include "../bitmap.c"

#define BUDDY_ORDER	8

int main(void)
{
	struct buddy *b;
	int i, a[10];

	b = buddy_create(BUDDY_ORDER);
	assert(b);

	buddy_reserve(b, 127, 0);
	buddy_reserve(b, 0, 4);
	assert(buddy_reserve(b, 0, 4) == false);

	a[0] = buddy_alloc(b, 0);
	assert(a[0] >= 0);
	a[1] = buddy_alloc(b, 0);
	assert(a[1] >= 0);
	a[2] = buddy_alloc(b, 3);
	assert(a[2] >= 0);
	a[3] = buddy_alloc(b, 4);
	assert(a[3] >= 0);
	a[4] = buddy_alloc(b, 5);
	assert(a[4] >= 0);
	a[5] = buddy_alloc(b, 4);
	assert(a[5] >= 0);
	a[6] = buddy_alloc(b, 3);
	assert(a[6] >= 0);
	a[7] = buddy_alloc(b, 2);
	assert(a[7] >= 0);
	a[8] = buddy_alloc(b, 1);
	assert(a[8] >= 0);
	a[9] = buddy_alloc(b, 8);
	assert(a[9] < 0);

	buddy_free(b, a[0], 0);
	buddy_free(b, a[8], 1);
	buddy_free(b, a[1], 0);
	buddy_free(b, a[7], 2);
	buddy_free(b, a[2], 3);
	buddy_free(b, a[6], 3);
	buddy_free(b, a[3], 4);
	buddy_free(b, a[5], 4);
	buddy_free(b, a[4], 5);

	buddy_free(b, 127, 0);
	buddy_free(b, 0, 4);

	for (i = 2; i < buddy_map_size(b); i++)
		assert(bitmap_tst_bit(b->map, i));
	assert(!bitmap_tst_bit(b->map, 1));

	buddy_destroy(b);
	return 0;
}
