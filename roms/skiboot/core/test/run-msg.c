// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2013-2019 IBM Corp.
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>

static bool zalloc_should_fail = false;
static int zalloc_should_fail_after = 0;

/* Fake top_of_ram -- needed for API's */
unsigned long top_of_ram = 0xffffffffffffffffULL;

static void *zalloc(size_t size)
{
        if (zalloc_should_fail && zalloc_should_fail_after == 0) {
                errno = ENOMEM;
                return NULL;
        }
	if (zalloc_should_fail_after > 0)
		zalloc_should_fail_after--;

        return calloc(size, 1);
}

#include "../opal-msg.c"
#include <skiboot.h>

void lock_caller(struct lock *l, const char *caller)
{
	(void)caller;
        assert(!l->lock_val);
        l->lock_val = 1;
}

void unlock(struct lock *l)
{
        assert(l->lock_val);
        l->lock_val = 0;
}

void opal_update_pending_evt(uint64_t evt_mask, uint64_t evt_values)
{
        (void)evt_mask;
        (void)evt_values;
}

static long magic = 8097883813087437089UL;
static void callback(void *data, int status)
{
	assert((status == OPAL_SUCCESS || status == OPAL_PARTIAL));
        assert(*(uint64_t *)data == magic);
}

static size_t list_count(struct list_head *list)
{
        size_t count = 0;
        struct opal_msg_entry *dummy;

        list_for_each(list, dummy, link)
                count++;
        return count;
}

int main(void)
{
        struct opal_msg_entry* entry;
        int free_size = OPAL_MAX_MSGS;
        int nfree = free_size;
        int npending = 0;
        int r;
        static struct opal_msg m;
        uint64_t *m_ptr = (uint64_t *)&m;

	zalloc_should_fail = true;
	zalloc_should_fail_after = 3;
	opal_init_msg();

	zalloc_should_fail = false;
	opal_init_msg();

        assert(list_count(&msg_pending_list) == npending);
        assert(list_count(&msg_free_list) == nfree);

        /* Callback. */
        r = opal_queue_msg(0, &magic, callback, (u64)0, (u64)1, (u64)2);
        assert(r == 0);

        assert(list_count(&msg_pending_list) == ++npending);
        assert(list_count(&msg_free_list) == --nfree);

        r = opal_get_msg(m_ptr, sizeof(m));
        assert(r == 0);

        assert(m.params[0] == 0);
        assert(m.params[1] == 1);
        assert(m.params[2] == 2);

        assert(list_count(&msg_pending_list) == --npending);
        assert(list_count(&msg_free_list) == ++nfree);

        /* No params. */
        r = opal_queue_msg(0, NULL, NULL);
        assert(r == 0);

        assert(list_count(&msg_pending_list) == ++npending);
        assert(list_count(&msg_free_list) == --nfree);

        r = opal_get_msg(m_ptr, sizeof(m));
        assert(r == 0);

        assert(list_count(&msg_pending_list) == --npending);
        assert(list_count(&msg_free_list) == ++nfree);

        /* > 8 params (ARRAY_SIZE(entry->msg.params) */
        r = opal_queue_msg(0, NULL, NULL, 0, 1, 2, 3, 4, 5, 6, 7, 0xBADDA7A);
        assert(r == 0);

        assert(list_count(&msg_pending_list) == ++npending);
        assert(list_count(&msg_free_list) == nfree);

        r = opal_get_msg(m_ptr, sizeof(m));
	assert(r == OPAL_PARTIAL);

        assert(list_count(&msg_pending_list) == --npending);
        assert(list_count(&msg_free_list) == nfree);

        /* Return OPAL_PARTIAL to callback */
	r = opal_queue_msg(0, &magic, callback, 0, 1, 2, 3, 4, 5, 6, 7, 0xBADDA7A);
	assert(r == 0);

	assert(list_count(&msg_pending_list) == ++npending);
	assert(list_count(&msg_free_list) == nfree);

	r = opal_get_msg(m_ptr, sizeof(m));
	assert(r == OPAL_PARTIAL);

	assert(list_count(&msg_pending_list) == --npending);
	assert(list_count(&msg_free_list) == nfree);

        /* return OPAL_PARAMETER */
	r = _opal_queue_msg(0, NULL, NULL, OPAL_MSG_SIZE, m_ptr);
	assert(r == OPAL_PARAMETER);

        assert(m.params[0] == 0);
        assert(m.params[1] == 1);
        assert(m.params[2] == 2);
        assert(m.params[3] == 3);
        assert(m.params[4] == 4);
        assert(m.params[5] == 5);
        assert(m.params[6] == 6);
        assert(m.params[7] == 7);

        /* 8 params (ARRAY_SIZE(entry->msg.params) */
        r = opal_queue_msg(0, NULL, NULL, 0, 10, 20, 30, 40, 50, 60, 70);
        assert(r == 0);

        assert(list_count(&msg_pending_list) == ++npending);
        assert(list_count(&msg_free_list) == --nfree);

        r = opal_get_msg(m_ptr, sizeof(m));
        assert(r == 0);

        assert(list_count(&msg_pending_list) == --npending);
        assert(list_count(&msg_free_list) == ++nfree);

        assert(m.params[0] == 0);
        assert(m.params[1] == 10);
        assert(m.params[2] == 20);
        assert(m.params[3] == 30);
        assert(m.params[4] == 40);
        assert(m.params[5] == 50);
        assert(m.params[6] == 60);
        assert(m.params[7] == 70);

        /* Full list (no free nodes in pending). */
        while (nfree > 0) {
                r = opal_queue_msg(OPAL_MSG_ASYNC_COMP, NULL, NULL);
                assert(r == 0);
                assert(list_count(&msg_pending_list) == ++npending);
                assert(list_count(&msg_free_list) == --nfree);
        }
        assert(list_count(&msg_free_list) == 0);
        assert(nfree == 0);
        assert(npending == OPAL_MAX_MSGS);

        r = opal_queue_msg(OPAL_MSG_ASYNC_COMP, NULL, NULL);
        assert(r == 0);

        assert(list_count(&msg_pending_list) == OPAL_MAX_MSGS+1);
        assert(list_count(&msg_pending_list) == ++npending);
        assert(list_count(&msg_free_list) == nfree);

        /* Make zalloc fail to test error handling. */
        zalloc_should_fail = true;
        r = opal_queue_msg(OPAL_MSG_ASYNC_COMP, NULL, NULL);
        assert(r == OPAL_RESOURCE);

        assert(list_count(&msg_pending_list) == OPAL_MAX_MSGS+1);
        assert(list_count(&msg_pending_list) == npending);
        assert(list_count(&msg_free_list) == nfree);

        /* Empty list (no nodes). */
        while(!list_empty(&msg_pending_list)) {
                r = opal_get_msg(m_ptr, sizeof(m));
                assert(r == 0);
                npending--;
                nfree++;
        }
        assert(list_count(&msg_pending_list) == npending);
        assert(list_count(&msg_free_list) == nfree);
        assert(npending == 0);
        assert(nfree == OPAL_MAX_MSGS+1);

        r = opal_queue_msg(OPAL_MSG_ASYNC_COMP, NULL, NULL);
        assert(r == 0);

        assert(list_count(&msg_pending_list) == ++npending);
        assert(list_count(&msg_free_list) == --nfree);

        /* Request invalid size. */
        r = opal_get_msg(m_ptr, sizeof(m) - 1);
        assert(r == OPAL_PARAMETER);

        /* Pass null buffer. */
        r = opal_get_msg(NULL, sizeof(m));
        assert(r == OPAL_PARAMETER);

        /* Get msg when none are pending. */
        r = opal_get_msg(m_ptr, sizeof(m));
        assert(r == 0);

        r = opal_get_msg(m_ptr, sizeof(m));
        assert(r == OPAL_RESOURCE);

#define test_queue_num(type, val) \
        r = opal_queue_msg(0, NULL, NULL, \
                (type)val, (type)val, (type)val, (type)val, \
                (type)val, (type)val, (type)val, (type)val); \
        assert(r == 0); \
        opal_get_msg(m_ptr, sizeof(m)); \
        assert(r == OPAL_SUCCESS); \
        assert(m.params[0] == (type)val); \
        assert(m.params[1] == (type)val); \
        assert(m.params[2] == (type)val); \
        assert(m.params[3] == (type)val); \
        assert(m.params[4] == (type)val); \
        assert(m.params[5] == (type)val); \
        assert(m.params[6] == (type)val); \
        assert(m.params[7] == (type)val)

        /* Test types of various widths */
        test_queue_num(u64, -1);
        test_queue_num(s64, -1);
        test_queue_num(u32, -1);
        test_queue_num(s32, -1);
        test_queue_num(u16, -1);
        test_queue_num(s16, -1);
        test_queue_num(u8, -1);
        test_queue_num(s8, -1);

        /* Clean up the list to keep valgrind happy. */
        while(!list_empty(&msg_free_list)) {
                entry = list_pop(&msg_free_list, struct opal_msg_entry, link);
                assert(entry);
                free(entry);
        }

        while(!list_empty(&msg_pending_list)) {
                entry = list_pop(&msg_pending_list, struct opal_msg_entry, link);
                assert(entry);
                free(entry);
        }

        return 0;
}
