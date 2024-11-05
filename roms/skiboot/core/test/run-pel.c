// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Test for our PEL record generation. Currently this doesn't actually
 * test that the records we generate are correct, but it at least lets
 * us run valgrind over the generation routines to check for buffer
 * overflows, etc.
 *
 * Copyright 2013-2016 IBM Corp.
 */

#include <skiboot.h>
#include <inttypes.h>
#include <assert.h>
#include <pel.h>
#include <errorlog.h>
#include <device.h>

#define TEST_ERROR 0x1234
#define TEST_SUBSYS 0x5678

DEFINE_LOG_ENTRY(TEST_ERROR, OPAL_PLATFORM_ERR_EVT, TEST_SUBSYS,
			OPAL_PLATFORM_FIRMWARE, OPAL_INFO,
			OPAL_NA);

/* Override this for testing. */
#define is_rodata(p) fake_is_rodata(p)

char __rodata_start[16];
#define __rodata_end (__rodata_start + sizeof(__rodata_start))

static inline bool fake_is_rodata(const void *p)
{
	return ((char *)p >= __rodata_start && (char *)p < __rodata_end);
}

#define zalloc(bytes) calloc((bytes), 1)

#include "../device.c"
#include "../pel.c"

struct dt_node *dt_root = NULL;
char dt_prop[] = "DUMMY DT PROP";

int rtc_cache_get_datetime(uint32_t *year_month_day,
			   uint64_t *hour_minute_second_millisecond)
{
	*year_month_day = 0;
	*hour_minute_second_millisecond = 0;

	return 0;
}

int main(void)
{
	char *pel_buf;
	size_t size;
	struct errorlog *elog;
	struct opal_err_info *opal_err_info = &err_TEST_ERROR;
	char *buffer;
	struct elog_user_data_section *tmp;

	dt_root = dt_new_root("");
	dt_add_property_string(dt_root, "model", "run-pel-unittest");

	elog = malloc(sizeof(struct errorlog));
	pel_buf = malloc(PEL_MIN_SIZE + 4);
	assert(elog);
	assert(pel_buf);

	memset(elog, 0, sizeof(struct errorlog));

	elog->error_event_type = opal_err_info->err_type;
	elog->component_id = opal_err_info->cmp_id;
	elog->subsystem_id = opal_err_info->subsystem;
	elog->event_severity = opal_err_info->sev;
	elog->event_subtype = opal_err_info->event_subtype;
	elog->reason_code = opal_err_info->reason_code;
	elog->elog_origin = ORG_SAPPHIRE;

	size = pel_size(elog);

	printf("Test buffer too small: ");
	assert(0 == create_pel_log(elog, NULL, size - 1));

	assert(size <= PEL_MIN_SIZE + 4);
	assert(size == create_pel_log(elog, pel_buf, size));

	memset(elog, 0, sizeof(struct errorlog));

	elog->error_event_type = opal_err_info->err_type;
	elog->component_id = opal_err_info->cmp_id;
	elog->subsystem_id = opal_err_info->subsystem;
	elog->event_severity = opal_err_info->sev;
	elog->event_subtype = opal_err_info->event_subtype;
	elog->reason_code = opal_err_info->reason_code;
	elog->elog_origin = ORG_SAPPHIRE;

	size = pel_size(elog);
	pel_buf = realloc(pel_buf, size);
	assert(pel_buf);

	buffer = elog->user_data_dump + elog->user_section_size;
	tmp = (struct elog_user_data_section *)buffer;
	tmp->tag = OPAL_ELOG_SEC_DESC;  /* ASCII of DESC */
	tmp->size = size + sizeof(struct elog_user_data_section) - 1;
	strcpy(tmp->data_dump, "Hello World!");
	elog->user_section_size += tmp->size;
	elog->user_section_count++;

	size = pel_size(elog);
	pel_buf = realloc(pel_buf, size);
	assert(pel_buf);

	assert(size == create_pel_log(elog, pel_buf, size));

	free(pel_buf);
	free(elog);

	return 0;
}
