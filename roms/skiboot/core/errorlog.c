// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* This file contains the front end for OPAL error logging. It is used
 * to construct a struct errorlog representing the event/error to be
 * logged which is then passed to the platform specific backend to log
 * the actual errors.
 *
 * Copyright 2013-2017 IBM Corp.
 */

#include <skiboot.h>
#include <lock.h>
#include <errorlog.h>
#include <pool.h>

/*
 * Maximum number buffers that are pre-allocated
 * to hold elogs that are reported on Sapphire and
 * PowerNV.
 */
#define ELOG_WRITE_MAX_RECORD		64
/* Platform log id as per the spec */
static uint32_t sapphire_elog_id = 0xB0000000;

/* Reserved for future use */
/* static uint32_t powernv_elog_id = 0xB1000000; */

/* Pool to allocate elog messages from */
static struct pool elog_pool;
static struct lock elog_lock = LOCK_UNLOCKED;

static bool elog_available = false;

static struct errorlog *get_write_buffer(int opal_event_severity)
{
	struct errorlog *buf;

	if (!elog_available)
		return NULL;

	lock(&elog_lock);
	if (opal_event_severity == OPAL_ERROR_PANIC)
		buf = pool_get(&elog_pool, POOL_HIGH);
	else
		buf = pool_get(&elog_pool, POOL_NORMAL);

	unlock(&elog_lock);
	return buf;
}

/* Reporting of error via struct errorlog */
struct errorlog *opal_elog_create(struct opal_err_info *e_info, uint32_t tag)
{
	struct errorlog *buf;

	buf = get_write_buffer(e_info->sev);
	if (buf) {
		buf->error_event_type = e_info->err_type;
		buf->component_id = e_info->cmp_id;
		buf->subsystem_id = e_info->subsystem;
		buf->event_severity = e_info->sev;
		buf->event_subtype = e_info->event_subtype;
		buf->reason_code = e_info->reason_code;
		buf->elog_origin = ORG_SAPPHIRE;

		lock(&elog_lock);
		buf->plid = ++sapphire_elog_id;
		unlock(&elog_lock);

		/* Initialise the first user dump section */
		log_add_section(buf, tag);
	}

	return buf;
}

/* Add a new user data section to an existing error log */
void log_add_section(struct errorlog *buf, uint32_t tag)
{
	size_t size = sizeof(struct elog_user_data_section) - 1;
	struct elog_user_data_section *tmp;

	if (!buf) {
		prerror("ELOG: Cannot add user data section. "
			"Buffer is invalid\n");
		return;
	}

	if ((buf->user_section_size + size) > OPAL_LOG_MAX_DUMP) {
		prerror("ELOG: Size of dump data overruns buffer\n");
		return;
	}

	tmp = (struct elog_user_data_section *)(buf->user_data_dump +
						buf->user_section_size);
	/* Use DESC if no other tag provided */
	tmp->tag = tag ? cpu_to_be32(tag) : cpu_to_be32(OPAL_ELOG_SEC_DESC);
	tmp->size = cpu_to_be16(size);

	buf->user_section_size += size;
	buf->user_section_count++;
}

void opal_elog_complete(struct errorlog *buf, bool success)
{
	if (!success)
		printf("Unable to log error\n");

	lock(&elog_lock);
	pool_free_object(&elog_pool, buf);
	unlock(&elog_lock);
}

void log_commit(struct errorlog *elog)
{
	int rc;

	if (!elog)
		return;

	if (platform.elog_commit) {
		rc = platform.elog_commit(elog);
		if (rc)
			prerror("ELOG: Platform commit error %d\n", rc);

		return;
	}

	opal_elog_complete(elog, false);
}

void log_append_data(struct errorlog *buf, unsigned char *data, uint16_t size)
{
	struct elog_user_data_section *section;
	uint8_t n_sections;
	char *buffer;
	uint16_t ssize;

	if (!buf) {
		prerror("ELOG: Cannot update user data. Buffer is invalid\n");
		return;
	}

	if ((buf->user_section_size + size) > OPAL_LOG_MAX_DUMP) {
		prerror("ELOG: Size of dump data overruns buffer\n");
		return;
	}

	/* Step through user sections to find latest dump section */
	buffer = buf->user_data_dump;
	n_sections = buf->user_section_count;
	if (!n_sections) {
		prerror("ELOG: User section invalid\n");
		return;
	}

	while (--n_sections) {
		section = (struct elog_user_data_section *)buffer;
		buffer += be16_to_cpu(section->size);
	}

	section = (struct elog_user_data_section *)buffer;
	ssize = be16_to_cpu(section->size);
	buffer += ssize;
	memcpy(buffer, data, size);
	section->size = cpu_to_be16(ssize + size);
	buf->user_section_size += size;
}

void log_append_msg(struct errorlog *buf, const char *fmt, ...)
{
	char err_msg[250];
	va_list list;

	if (!buf) {
		prerror("Tried to append log to NULL buffer\n");
		return;
	}

	va_start(list, fmt);
	vsnprintf(err_msg, sizeof(err_msg), fmt, list);
	va_end(list);

	/* Log the error on to Sapphire console */
	prerror("%s", err_msg);

	log_append_data(buf, err_msg, strlen(err_msg));
}

uint32_t log_simple_error(struct opal_err_info *e_info, const char *fmt, ...)
{
	struct errorlog *buf;
	va_list list;
	char err_msg[250];

	va_start(list, fmt);
	vsnprintf(err_msg, sizeof(err_msg), fmt, list);
	va_end(list);

	/* Log the error on to Sapphire console */
	prerror("%s", err_msg);

	buf = opal_elog_create(e_info, 0);
	if (buf == NULL) {
		prerror("ELOG: Error getting buffer to log error\n");
		return -1;
	}

	log_append_data(buf, err_msg, strlen(err_msg));
	log_commit(buf);

	return buf->plid;
}

int elog_init(void)
{
	/* Pre-allocate memory for records */
	if (pool_init(&elog_pool, sizeof(struct errorlog),
					ELOG_WRITE_MAX_RECORD, 1))
		return OPAL_RESOURCE;

	elog_available = true;
	return 0;
}
