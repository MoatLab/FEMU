// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Platform Error Log (PEL) generation
 *
 * Copyright 2014-2016 IBM Corp
 */

#include <string.h>
#include <errorlog.h>
#include <device.h>
#include <fsp.h>
#include <pel.h>
#include <rtc.h>

/* Create MTMS section for sapphire log */
static void create_mtms_section(struct errorlog *elog_data,
					char *pel_buffer, int *pel_offset)
{
	const struct dt_property *p;

	struct opal_mtms_section *mtms = (struct opal_mtms_section *)
				(pel_buffer + *pel_offset);

	mtms->v6header.id = cpu_to_be16(ELOG_SID_MACHINE_TYPE);
	mtms->v6header.length = cpu_to_be16(MTMS_SECTION_SIZE);
	mtms->v6header.version = OPAL_EXT_HRD_VER;
	mtms->v6header.subtype = 0;
	mtms->v6header.component_id = cpu_to_be16(elog_data->component_id);

	memset(mtms->model, 0x00, sizeof(mtms->model));
	memcpy(mtms->model, dt_prop_get(dt_root, "model"), OPAL_SYS_MODEL_LEN);

	memset(mtms->serial_no, 0x00, sizeof(mtms->serial_no));
	p = dt_find_property(dt_root, "system-id");
	if (p)
		memcpy(mtms->serial_no, p->prop, OPAL_SYS_SERIAL_LEN);
	else
		memset(mtms->serial_no, 0, OPAL_SYS_SERIAL_LEN);

	*pel_offset += MTMS_SECTION_SIZE;
}

/* Create extended header section */
static void create_extended_header_section(struct errorlog *elog_data,
					char *pel_buffer, int *pel_offset)
{
	const char  *opalmodel = NULL;
	const struct dt_property *p;
	uint64_t extd_time;
	uint32_t extd_date;

	struct opal_extended_header_section *extdhdr =
			(struct opal_extended_header_section *)
					(pel_buffer + *pel_offset);

	extdhdr->v6header.id = cpu_to_be16(ELOG_SID_EXTENDED_HEADER);
	extdhdr->v6header.length = cpu_to_be16(EXTENDED_HEADER_SECTION_SIZE);
	extdhdr->v6header.version = OPAL_EXT_HRD_VER;
	extdhdr->v6header.subtype = 0;
	extdhdr->v6header.component_id = cpu_to_be16(elog_data->component_id);

	memset(extdhdr->model, 0x00, sizeof(extdhdr->model));
	opalmodel = dt_prop_get(dt_root, "model");
	memcpy(extdhdr->model, opalmodel, OPAL_SYS_MODEL_LEN);

	memset(extdhdr->serial_no, 0x00, sizeof(extdhdr->serial_no));
	p = dt_find_property(dt_root, "system-id");
	if (p)
		memcpy(extdhdr->serial_no, p->prop, OPAL_SYS_SERIAL_LEN);
	else
		memset(extdhdr->serial_no, 0, OPAL_SYS_SERIAL_LEN);

	memset(extdhdr->opal_release_version, 0x00,
				sizeof(extdhdr->opal_release_version));
	memset(extdhdr->opal_subsys_version, 0x00,
				sizeof(extdhdr->opal_subsys_version));

	rtc_cache_get_datetime(&extd_date, &extd_time);
	extdhdr->extended_header_date = cpu_to_be32(extd_date);
	extdhdr->extended_header_time = cpu_to_be32(extd_time >> 32);
	extdhdr->opal_symid_len = 0;

	*pel_offset += EXTENDED_HEADER_SECTION_SIZE;
}

/* set src type */
static void settype(struct opal_src_section *src, uint8_t src_type)
{
	char type[4];
	snprintf(type, sizeof(type), "%02X", src_type);
	memcpy(src->srcstring, type, 2);
}

/* set SRC subsystem type */
static void setsubsys(struct opal_src_section *src, uint8_t src_subsys)
{
	char subsys[4];
	snprintf(subsys, sizeof(subsys), "%02X", src_subsys);
	memcpy(src->srcstring+2, subsys, 2);
}

/* Ser reason code of SRC */
static void setrefcode(struct opal_src_section *src, uint16_t src_refcode)
{
	char refcode[8];
	snprintf(refcode, sizeof(refcode), "%04X", src_refcode);
	memcpy(src->srcstring+4, refcode, 4);
}

/* Create SRC section of OPAL log */
static void create_src_section(struct errorlog *elog_data,
					char *pel_buffer, int *pel_offset)
{
	struct opal_src_section *src = (struct opal_src_section *)
						(pel_buffer + *pel_offset);

	src->v6header.id = cpu_to_be16(ELOG_SID_PRIMARY_SRC);
	src->v6header.length = cpu_to_be16(SRC_SECTION_SIZE);
	src->v6header.version = OPAL_ELOG_VERSION;
	src->v6header.subtype = OPAL_ELOG_SST;
	src->v6header.component_id = cpu_to_be16(elog_data->component_id);

	src->version = OPAL_SRC_SEC_VER;
	src->flags = 0;
	src->wordcount = OPAL_SRC_MAX_WORD_COUNT;
	src->srclength = cpu_to_be16(SRC_LENGTH);
	settype(src, OPAL_SRC_TYPE_ERROR);
	setsubsys(src, OPAL_FAILING_SUBSYSTEM);
	setrefcode(src, elog_data->reason_code);
	memset(src->hexwords, 0 , (8 * 4));
	src->hexwords[0] = cpu_to_be32(OPAL_SRC_FORMAT);
	src->hexwords[4] = cpu_to_be32(elog_data->additional_info[0]);
	src->hexwords[5] = cpu_to_be32(elog_data->additional_info[1]);
	src->hexwords[6] = cpu_to_be32(elog_data->additional_info[2]);
	src->hexwords[7] = cpu_to_be32(elog_data->additional_info[3]);
	*pel_offset += SRC_SECTION_SIZE;
}

/* Create user header section */
static void create_user_header_section(struct errorlog *elog_data,
					char *pel_buffer, int *pel_offset)
{
	struct opal_user_header_section *usrhdr =
				(struct opal_user_header_section *)
						(pel_buffer + *pel_offset);

	usrhdr->v6header.id = cpu_to_be16(ELOG_SID_USER_HEADER);
	usrhdr->v6header.length = cpu_to_be16(USER_HEADER_SECTION_SIZE);
	usrhdr->v6header.version = OPAL_ELOG_VERSION;
	usrhdr->v6header.subtype = OPAL_ELOG_SST;
	usrhdr->v6header.component_id = cpu_to_be16(elog_data->component_id);

	usrhdr->subsystem_id = elog_data->subsystem_id;
	usrhdr->event_scope = 0;
	usrhdr->event_severity = elog_data->event_severity;
	usrhdr->event_type = elog_data->event_subtype;

	if (elog_data->elog_origin == ORG_SAPPHIRE)
		usrhdr->action_flags = cpu_to_be16(ERRL_ACTION_REPORT);
	else
		usrhdr->action_flags = cpu_to_be16(ERRL_ACTION_NONE);

	*pel_offset += USER_HEADER_SECTION_SIZE;
}

/* Create private header section */
static void create_private_header_section(struct errorlog *elog_data,
					char *pel_buffer, int *pel_offset)
{
	uint64_t ctime;
	uint32_t cdate;
	struct opal_private_header_section *privhdr =
				(struct opal_private_header_section *)
								pel_buffer;

	privhdr->v6header.id = cpu_to_be16(ELOG_SID_PRIVATE_HEADER);
	privhdr->v6header.length = cpu_to_be16(PRIVATE_HEADER_SECTION_SIZE);
	privhdr->v6header.version = OPAL_ELOG_VERSION;
	privhdr->v6header.subtype = OPAL_ELOG_SST;
	privhdr->v6header.component_id = cpu_to_be16(elog_data->component_id);
	privhdr->plid = cpu_to_be32(elog_data->plid);

	rtc_cache_get_datetime(&cdate, &ctime);
	privhdr->create_date = cpu_to_be32(cdate);
	privhdr->create_time = cpu_to_be32(ctime >> 32);
	privhdr->section_count = 5;

	privhdr->creator_subid_hi = 0x00;
	privhdr->creator_subid_lo = 0x00;

	if (elog_data->elog_origin == ORG_SAPPHIRE)
		privhdr->creator_id = OPAL_CID_SAPPHIRE;
	else
		privhdr->creator_id = OPAL_CID_POWERNV;

	privhdr->log_entry_id = cpu_to_be32(elog_data->plid); /*entry id is updated by FSP*/

	*pel_offset += PRIVATE_HEADER_SECTION_SIZE;
}

static void create_user_defined_section(struct errorlog *elog_data,
					char *pel_buffer, int *pel_offset)
{
	char *dump = (char *)pel_buffer + *pel_offset;
	char *opal_buf = (char *)elog_data->user_data_dump;
	struct opal_user_section *usrhdr;
	struct elog_user_data_section *opal_usr_data;
	struct opal_private_header_section *privhdr =
			 (struct opal_private_header_section *)pel_buffer;
	int i;

	for (i = 0; i < elog_data->user_section_count; i++) {

		usrhdr = (struct opal_user_section *)dump;
		opal_usr_data = (struct elog_user_data_section *)opal_buf;

		usrhdr->v6header.id = cpu_to_be16(ELOG_SID_USER_DEFINED);
		usrhdr->v6header.length = cpu_to_be16(
					sizeof(struct opal_v6_header) +
					be16_to_cpu(opal_usr_data->size));
		usrhdr->v6header.version = OPAL_ELOG_VERSION;
		usrhdr->v6header.subtype = OPAL_ELOG_SST;
		usrhdr->v6header.component_id = cpu_to_be16(elog_data->component_id);

		memcpy(usrhdr->dump, opal_buf, be16_to_cpu(opal_usr_data->size));
		*pel_offset += be16_to_cpu(usrhdr->v6header.length);
		dump += be16_to_cpu(usrhdr->v6header.length);
		opal_buf += be16_to_cpu(opal_usr_data->size);
		privhdr->section_count++;
	}
}

static size_t pel_user_section_size(struct errorlog *elog_data)
{
	int i;
	size_t total = 0;
	char *opal_buf = (char *)elog_data->user_data_dump;
	struct elog_user_data_section *opal_usr_data;

	for (i = 0; i < elog_data->user_section_count; i++) {
		u16 s;

		opal_usr_data = (struct elog_user_data_section *)opal_buf;
		s = be16_to_cpu(opal_usr_data->size);
		total += sizeof(struct opal_v6_header) + s;
		opal_buf += s;
	}

	return total;
}

size_t pel_size(struct errorlog *elog_data)
{
	return PEL_MIN_SIZE + pel_user_section_size(elog_data);
}

/* Converts an OPAL errorlog into a PEL formatted log */
int create_pel_log(struct errorlog *elog_data, char *pel_buffer,
		   size_t pel_buffer_size)
{
	int pel_offset = 0;

	if (pel_buffer_size < pel_size(elog_data)) {
		prerror("PEL buffer too small to create record\n");
		return 0;
	}

	memset(pel_buffer, 0, pel_buffer_size);

	create_private_header_section(elog_data, pel_buffer, &pel_offset);
	create_user_header_section(elog_data, pel_buffer, &pel_offset);
	create_src_section(elog_data, pel_buffer, &pel_offset);
	create_extended_header_section(elog_data, pel_buffer, &pel_offset);
	create_mtms_section(elog_data, pel_buffer, &pel_offset);
	if (elog_data->user_section_count)
		create_user_defined_section(elog_data, pel_buffer, &pel_offset);

	return pel_offset;
}
