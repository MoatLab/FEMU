// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * OPAL Message queue between host and skiboot
 *
 * Copyright 2013-2019 IBM Corp.
 */

#define pr_fmt(fmt) "opalmsg: " fmt
#include <skiboot.h>
#include <opal-msg.h>
#include <opal-api.h>
#include <lock.h>

#define OPAL_MAX_MSGS		(OPAL_MSG_TYPE_MAX + OPAL_MAX_ASYNC_COMP - 1)

struct opal_msg_entry {
	struct list_node link;
	void (*consumed)(void *data, int status);
	bool extended;
	void *data;
	struct opal_msg msg;
};

static LIST_HEAD(msg_free_list);
static LIST_HEAD(msg_pending_list);

static struct lock opal_msg_lock = LOCK_UNLOCKED;

int _opal_queue_msg(enum opal_msg_type msg_type, void *data,
		    void (*consumed)(void *data, int status),
		    size_t params_size, const void *params)
{
	struct opal_msg_entry *entry;
	uint64_t entry_size;

	if ((params_size + OPAL_MSG_HDR_SIZE) > OPAL_MSG_SIZE) {
		prlog(PR_DEBUG, "param_size (0x%x) > opal_msg param size (0x%x)\n",
		      (u32)params_size, (u32)(OPAL_MSG_SIZE - OPAL_MSG_HDR_SIZE));
		return OPAL_PARAMETER;
	}

	lock(&opal_msg_lock);

	if (params_size > OPAL_MSG_FIXED_PARAMS_SIZE) {
		entry_size = sizeof(struct opal_msg_entry) + params_size;
		entry_size -= OPAL_MSG_FIXED_PARAMS_SIZE;
		entry = zalloc(entry_size);
		if (entry)
			entry->extended = true;
	} else {
		entry = list_pop(&msg_free_list, struct opal_msg_entry, link);
		if (!entry) {
			prerror("No available node in the free list, allocating\n");
			entry = zalloc(sizeof(struct opal_msg_entry));
		}
	}
	if (!entry) {
		prerror("Allocation failed\n");
		unlock(&opal_msg_lock);
		return OPAL_RESOURCE;
	}

	entry->consumed = consumed;
	entry->data = data;
	entry->msg.msg_type = cpu_to_be32(msg_type);
	entry->msg.size = cpu_to_be32(params_size);
	memcpy(entry->msg.params, params, params_size);

	list_add_tail(&msg_pending_list, &entry->link);
	opal_update_pending_evt(OPAL_EVENT_MSG_PENDING,
				OPAL_EVENT_MSG_PENDING);
	unlock(&opal_msg_lock);

	return OPAL_SUCCESS;
}

static int64_t opal_get_msg(uint64_t *buffer, uint64_t size)
{
	struct opal_msg_entry *entry;
	void (*callback)(void *data, int status);
	void *data;
	uint64_t msg_size;
	int rc = OPAL_SUCCESS;

	if (size < sizeof(struct opal_msg) || !buffer)
		return OPAL_PARAMETER;

	if (!opal_addr_valid(buffer))
		return OPAL_PARAMETER;

	lock(&opal_msg_lock);

	entry = list_pop(&msg_pending_list, struct opal_msg_entry, link);
	if (!entry) {
		unlock(&opal_msg_lock);
		return OPAL_RESOURCE;
	}

	msg_size = OPAL_MSG_HDR_SIZE + be32_to_cpu(entry->msg.size);
	if (size < msg_size) {
		/* Send partial data to Linux */
		prlog(PR_NOTICE, "Sending partial data [msg_type : 0x%x, "
		      "msg_size : 0x%x, buf_size : 0x%x]\n",
		      be32_to_cpu(entry->msg.msg_type),
		      (u32)msg_size, (u32)size);

		entry->msg.size = cpu_to_be32(size - OPAL_MSG_HDR_SIZE);
		msg_size = size;
		rc = OPAL_PARTIAL;
	}

	memcpy((void *)buffer, (void *)&entry->msg, msg_size);
	callback = entry->consumed;
	data = entry->data;

	if (entry->extended)
		free(entry);
	else
		list_add(&msg_free_list, &entry->link);

	if (list_empty(&msg_pending_list))
		opal_update_pending_evt(OPAL_EVENT_MSG_PENDING, 0);

	unlock(&opal_msg_lock);

	if (callback)
		callback(data, rc);

	return rc;
}
opal_call(OPAL_GET_MSG, opal_get_msg, 2);

static int64_t opal_check_completion(uint64_t *buffer, uint64_t size,
				     uint64_t token)
{
	struct opal_msg_entry *entry, *next_entry;
	void (*callback)(void *data, int status) = NULL;
	int rc = OPAL_BUSY;
	void *data = NULL;

	if (!opal_addr_valid(buffer))
		return OPAL_PARAMETER;

	lock(&opal_msg_lock);
	list_for_each_safe(&msg_pending_list, entry, next_entry, link) {
		if (be32_to_cpu(entry->msg.msg_type) == OPAL_MSG_ASYNC_COMP &&
		    be64_to_cpu(entry->msg.params[0]) == token) {
			list_del(&entry->link);
			callback = entry->consumed;
			data = entry->data;
			list_add(&msg_free_list, &entry->link);
			if (list_empty(&msg_pending_list))
				opal_update_pending_evt(OPAL_EVENT_MSG_PENDING,
							0);
			rc = OPAL_SUCCESS;
			break;
		}
	}

	if (rc == OPAL_SUCCESS && size >= sizeof(struct opal_msg))
		memcpy(buffer, &entry->msg, sizeof(entry->msg));

	unlock(&opal_msg_lock);

	if (callback)
		callback(data, OPAL_SUCCESS);

	return rc;

}
opal_call(OPAL_CHECK_ASYNC_COMPLETION, opal_check_completion, 3);

void opal_init_msg(void)
{
	struct opal_msg_entry *entry;
	int i;

	for (i = 0; i < OPAL_MAX_MSGS; i++, entry++) {
                entry = zalloc(sizeof(*entry));
                if (!entry)
                        goto err;
		list_add_tail(&msg_free_list, &entry->link);
        }
        return;

err:
        for (; i > 0; i--) {
                entry = list_pop(&msg_free_list, struct opal_msg_entry, link);
                if (entry)
                        free(entry);
        }
}

