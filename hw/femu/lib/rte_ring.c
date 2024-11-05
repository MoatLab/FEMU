/*
 * FEMU Lockless Ring Buffer: part of the code derived from SPDK wrappers around
 * rte_ring implementation
 */

/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Derived from FreeBSD's bufring.c
 *
 **************************************************************************
 *
 * Copyright (c) 2007,2008 Kip Macy kmacy@freebsd.org
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. The name of Kip Macy nor the names of other
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ***************************************************************************/

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/queue.h>

#include "../inc/rte_ring.h"

/* true if x is a power of 2 */
#define POWEROF2(x) ((((x)-1) & (x)) == 0)

/* return the size of memory occupied by a ring */
ssize_t rte_ring_get_memsize(unsigned count)
{
    ssize_t sz;

    /* count must be a power of 2 */
    if ((!POWEROF2(count)) || (count > RTE_RING_SZ_MASK )) {
        return -EINVAL;
    }
    sz = sizeof(struct rte_ring) + count * sizeof(void *);
    return sz;
}

int rte_ring_init(struct rte_ring *r, const char *name, unsigned count,
        unsigned flags)
{
    int ret;

    /* init the ring structure */
    memset(r, 0, sizeof(*r));
    ret = snprintf(r->name, sizeof(r->name), "%s", name);
    if (ret < 0 || ret >= (int)sizeof(r->name))
        return -ENAMETOOLONG;
    r->flags = flags;
    r->prod.single = (flags & RING_F_SP_ENQ) ? __IS_SP : __IS_MP;
    r->cons.single = (flags & RING_F_SC_DEQ) ? __IS_SC : __IS_MC;

    if (flags & RING_F_EXACT_SZ) {
        r->size = rte_align32pow2(count + 1);
        r->mask = r->size - 1;
        r->capacity = count;
    } else {
        if ((!POWEROF2(count)) || (count > RTE_RING_SZ_MASK)) {
            return -EINVAL;
        }
        r->size = count;
        r->mask = count - 1;
        r->capacity = r->mask;
    }
    r->prod.head = r->cons.head = 0;
    r->prod.tail = r->cons.tail = 0;

    return 0;
}

/* create the ring */
struct rte_ring *rte_ring_create(const char *name, unsigned count,
        unsigned flags)
{
	char mz_name[RTE_NAMESIZE];
	struct rte_ring *r;
	ssize_t ring_size;
	const unsigned int requested_count = count;
	int ret;

	/* for an exact size ring, round up from count to a power of two */
	if (flags & RING_F_EXACT_SZ)
		count = rte_align32pow2(count + 1);

	ring_size = rte_ring_get_memsize(count);
	if (ring_size < 0) {
		return NULL;
	}

	ret = snprintf(mz_name, sizeof(mz_name), "%s%s",
		RTE_RING_MZ_PREFIX, name);
	if (ret < 0 || ret >= (int)sizeof(mz_name)) {
		return NULL;
	}

    r = (struct rte_ring *)valloc(ring_size);

    rte_ring_init(r, name, requested_count, flags);

	return r;
}

/* free the ring */
void rte_ring_free(struct rte_ring *r)
{
	if (r == NULL)
		return;

	free(r);
}

/* dump the status of the ring on the console */
void rte_ring_dump(FILE *f, const struct rte_ring *r)
{
	fprintf(f, "ring <%s>@%p\n", r->name, r);
	fprintf(f, "  flags=%x\n", r->flags);
	fprintf(f, "  size=%"PRIu32"\n", r->size);
	fprintf(f, "  capacity=%"PRIu32"\n", r->capacity);
	fprintf(f, "  ct=%"PRIu32"\n", r->cons.tail);
	fprintf(f, "  ch=%"PRIu32"\n", r->cons.head);
	fprintf(f, "  pt=%"PRIu32"\n", r->prod.tail);
	fprintf(f, "  ph=%"PRIu32"\n", r->prod.head);
	fprintf(f, "  used=%u\n", rte_ring_count(r));
	fprintf(f, "  avail=%u\n", rte_ring_free_count(r));
}

struct rte_ring *femu_ring_create(enum femu_ring_type type, size_t count)
{
	char ring_name[64];
	static uint32_t ring_num = 0;
	unsigned flags = 0;

	switch (type) {
	case FEMU_RING_TYPE_SP_SC:
		flags = RING_F_SP_ENQ | RING_F_SC_DEQ;
		break;
	case FEMU_RING_TYPE_MP_SC:
		flags = RING_F_SC_DEQ;
		break;
	case FEMU_RING_TYPE_MP_MC:
		flags = 0;
		break;
	default:
		return NULL;
	}

	snprintf(ring_name, sizeof(ring_name), "ring_%u_%d",
		 __sync_fetch_and_add(&ring_num, 1), getpid());

	return rte_ring_create(ring_name, count, flags);
}

void femu_ring_free(struct rte_ring *ring)
{
	rte_ring_free((struct rte_ring *)ring);
}

size_t femu_ring_count(struct rte_ring *ring)
{
	return rte_ring_count((struct rte_ring *)ring);
}

size_t femu_ring_enqueue(struct rte_ring *ring, void **objs, size_t count)
{
    return rte_ring_enqueue_bulk((struct rte_ring *)ring, objs, count, NULL);
}

size_t femu_ring_dequeue(struct rte_ring *ring, void **objs, size_t count)
{
	return rte_ring_dequeue_burst((struct rte_ring *)ring, objs, count, NULL);
}

