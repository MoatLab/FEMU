// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2014 IBM Corp
 */

#include <pool.h>

#include "../pool.c"

#define POOL_OBJ_COUNT 10
#define POOL_RESERVED_COUNT 2
#define POOL_NORMAL_COUNT (POOL_OBJ_COUNT - POOL_RESERVED_COUNT)

struct test_object
{
	int a;
	int b;
	int c;
};

int main(void)
{
	int i, count = 0;
	struct pool pool;
	struct test_object *a[POOL_OBJ_COUNT];

	assert(!pool_init(&pool, sizeof(struct test_object), POOL_OBJ_COUNT,
		      POOL_RESERVED_COUNT));

	a[0] = pool_get(&pool, POOL_NORMAL);
	assert(a[0]);
	pool_free_object(&pool, a[0]);

	for(i = 0; i < POOL_NORMAL_COUNT; i++)
	{
		a[i] = pool_get(&pool, POOL_NORMAL);
		if (a[i])
			count++;
	}
	assert(count == POOL_NORMAL_COUNT);

	/* Normal pool should be exhausted */
	assert(!pool_get(&pool, POOL_NORMAL));

	/* Reserved pool should still be available */
	a[POOL_NORMAL_COUNT] = pool_get(&pool, POOL_HIGH);
	assert(a[POOL_NORMAL_COUNT]);
	a[POOL_NORMAL_COUNT + 1] = pool_get(&pool, POOL_HIGH);
	assert(a[POOL_NORMAL_COUNT + 1]);

	pool_free_object(&pool, a[3]);

	/* Should be a free object to get now */
	a[3] = pool_get(&pool, POOL_HIGH);
	assert(a[3]);

	/* This exits depending on whether all tests passed */
	return 0;
}
