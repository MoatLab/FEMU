// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Sapphire dump design:
 *   - During initialization we setup Memory Dump Source Table (MDST) table
 *     which contains address, size pair.
 *   - We send MDST table update notification to FSP via MBOX command.
 *   - During Sapphire checkstop:
 *     - FSP retrieves HWDUMP.
 *     - FSP retrieves CEC memory based on MDST table.
 *   - Once Sapphire reboot FSP sends new dump avialable notification via HDAT
 *
 * Copyright 2013-2016 IBM Corp.
 */

#include <fsp.h>
#include <psi.h>
#include <opal.h>
#include <lock.h>
#include <skiboot.h>
#include <errorlog.h>
#include <opal-dump.h>

/*
 * Sapphire dump size
 *   This is the maximum memory that FSP can retrieve during checkstop.
 *
 * Note:
 *   Presently we are hardcoding this parameter. Eventually we need
 *   new System parameter so that we can get max size dynamically.
 */
#define MAX_SAPPHIRE_DUMP_SIZE	0x1000000

DEFINE_LOG_ENTRY(OPAL_RC_DUMP_MDST_INIT, OPAL_PLATFORM_ERR_EVT, OPAL_DUMP,
		 OPAL_PLATFORM_FIRMWARE, OPAL_PREDICTIVE_ERR_FAULT_RECTIFY_REBOOT,
		 OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_DUMP_MDST_UPDATE, OPAL_PLATFORM_ERR_EVT, OPAL_DUMP,
		 OPAL_PLATFORM_FIRMWARE,
		 OPAL_PREDICTIVE_ERR_FAULT_RECTIFY_REBOOT,
		 OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_DUMP_MDST_ADD, OPAL_PLATFORM_ERR_EVT, OPAL_DUMP,
		 OPAL_PLATFORM_FIRMWARE, OPAL_INFO, OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_DUMP_MDST_REMOVE, OPAL_PLATFORM_ERR_EVT, OPAL_DUMP,
		 OPAL_PLATFORM_FIRMWARE, OPAL_INFO, OPAL_NA);


static struct mdst_table *mdst_table;
static struct mdst_table *dump_mem_region;

static int cur_mdst_entry;
static int max_mdst_entry;
static int cur_dump_size;
/*
 * Presently both sizes are same.. But if someday FSP gives more space
 * than our TCE mapping then we need this validation..
 *
 * Also once FSP implements MAX_SAPPHIRE_DUMP_SIZE system param, we can
 * move this validation to separate function.
 */
static int max_dump_size = MIN(MAX_SAPPHIRE_DUMP_SIZE, PSI_DMA_HYP_DUMP_SIZE);

/* Protect MDST table entries */
static struct lock mdst_lock = LOCK_UNLOCKED;

static inline uint32_t get_dump_region_map_size(uint64_t addr, uint32_t size)
{
	uint64_t start, end;

	start = addr & ~TCE_MASK;
	end = addr + size;
	end = ALIGN_UP(end, TCE_PSIZE);

	return (end - start);
}

static int dump_region_tce_map(void)
{
	int i;
	uint32_t t_size = 0, size;
	uint64_t addr;

	for (i = 0; i < cur_mdst_entry; i++) {

		addr = be64_to_cpu(dump_mem_region[i].addr) & ~TCE_MASK;
		size = get_dump_region_map_size(be64_to_cpu(dump_mem_region[i].addr),
						be32_to_cpu(dump_mem_region[i].size));

		if (t_size + size > max_dump_size)
			break;

		/* TCE mapping */
		fsp_tce_map(PSI_DMA_HYP_DUMP + t_size, (void *)addr, size);

		/* Add entry to MDST table */
		mdst_table[i].data_region = dump_mem_region[i].data_region;
		mdst_table[i].size = dump_mem_region[i].size;
		mdst_table[i].addr = cpu_to_be64(PSI_DMA_HYP_DUMP + t_size);

		/* TCE alignment adjustment */
		mdst_table[i].addr = cpu_to_be64(be64_to_cpu(mdst_table[i].addr) +
						 (be64_to_cpu(dump_mem_region[i].addr) & 0xfff));

		t_size += size;
	}

	return i;
}

static inline void dump_region_tce_unmap(void)
{
	fsp_tce_unmap(PSI_DMA_HYP_DUMP, PSI_DMA_HYP_DUMP_SIZE);
}

static void update_mdst_table_complete(struct fsp_msg *msg)
{
	uint8_t status = (msg->resp->word1 >> 8) & 0xff;

	if (status)
		log_simple_error(&e_info(OPAL_RC_DUMP_MDST_UPDATE),
				 "MDST: Update table MBOX command failed: "
				 "0x%x\n", status);
	else
		printf("MDST: Table updated.\n");

	fsp_freemsg(msg);
}

/* Send MDST table to FSP */
static int64_t fsp_update_mdst_table(void)
{
	struct fsp_msg *msg;
	int count;
	int rc = OPAL_SUCCESS;

	if (cur_mdst_entry <= 0) {
		printf("MDST: Table is empty\n");
		return OPAL_INTERNAL_ERROR;
	}

	lock(&mdst_lock);

	/* Unmap previous mapping */
	dump_region_tce_unmap();
	count = dump_region_tce_map();

	msg = fsp_mkmsg(FSP_CMD_HYP_MDST_TABLE, 4, 0,
			PSI_DMA_MDST_TABLE,
			sizeof(*mdst_table) * count,
			sizeof(*mdst_table));
	unlock(&mdst_lock);

	if (!msg) {
		log_simple_error(&e_info(OPAL_RC_DUMP_MDST_UPDATE),
				 "MDST: Message allocation failed.!\n");
		rc = OPAL_INTERNAL_ERROR;
	} else if (fsp_queue_msg(msg, update_mdst_table_complete)) {
		log_simple_error(&e_info(OPAL_RC_DUMP_MDST_UPDATE),
				 "MDST: Failed to queue MDST table message.\n");
		fsp_freemsg(msg);
		rc = OPAL_INTERNAL_ERROR;
	}
	return rc;
}

static int dump_region_del_entry(uint32_t id)
{
	int i;
	uint32_t size;
	bool found = false;
	int rc = OPAL_SUCCESS;

	lock(&mdst_lock);

	for (i = 0; i < cur_mdst_entry; i++) {
		if (dump_mem_region[i].data_region != id)
			continue;

		found = true;
		break;
	}

	if (!found) {
		rc = OPAL_PARAMETER;
		goto del_out;
	}

	/* Adjust current dump size */
	size = get_dump_region_map_size(be64_to_cpu(dump_mem_region[i].addr),
					be32_to_cpu(dump_mem_region[i].size));
	cur_dump_size -= size;

	for ( ; i < cur_mdst_entry - 1; i++)
		dump_mem_region[i] = dump_mem_region[i + 1];

	dump_mem_region[i].data_region = 0;
	cur_mdst_entry--;

del_out:
	unlock(&mdst_lock);
	return rc;
}

/* Add entry to MDST table */
static int __dump_region_add_entry(uint32_t id, uint64_t addr, uint32_t size)
{
	int rc = OPAL_INTERNAL_ERROR;
	uint32_t act_size;

	/* Delete function takes lock before modifying table */
	dump_region_del_entry(id);

	lock(&mdst_lock);

	if (cur_mdst_entry >= max_mdst_entry) {
		log_simple_error(&e_info(OPAL_RC_DUMP_MDST_ADD),
				 "MDST: Table is full.\n");
		goto out;
	}

	/* TCE alignment adjustment */
	act_size = get_dump_region_map_size(addr, size);

	/* Make sure we don't cross dump size limit */
	if (cur_dump_size + act_size > max_dump_size) {
		log_simple_error(&e_info(OPAL_RC_DUMP_MDST_ADD),
			 "MDST: 0x%x is crossing max dump size (0x%x) limit.\n",
			 cur_dump_size + act_size, max_dump_size);
		goto out;
	}

	/* Add entry to dump memory region table */
	dump_mem_region[cur_mdst_entry].data_region = (u8)id;
	dump_mem_region[cur_mdst_entry].addr = cpu_to_be64(addr);
	dump_mem_region[cur_mdst_entry].size = cpu_to_be32(size);

	/* Update dump region count and dump size */
	cur_mdst_entry++;
	cur_dump_size += act_size;

	printf("MDST: Addr = 0x%llx [size : 0x%x bytes] added to MDST table.\n",
	       (uint64_t)addr, size);

	rc = OPAL_SUCCESS;

out:
	unlock(&mdst_lock);
	return rc;
}

static int dump_region_add_entries(void)
{
	int rc;

	/* Add console buffer */
	rc = __dump_region_add_entry(DUMP_REGION_CONSOLE,
				     INMEM_CON_START, INMEM_CON_LEN);
	if (rc)
		return rc;

	/* Add HBRT buffer */
	rc = __dump_region_add_entry(DUMP_REGION_HBRT_LOG,
				     HBRT_CON_START, HBRT_CON_LEN);

	return rc;
}

static int64_t fsp_opal_register_dump_region(uint32_t id,
					     uint64_t addr, uint64_t size)
{
	int rc = OPAL_SUCCESS;

	if (!fsp_present())
		return OPAL_UNSUPPORTED;

	/* Validate memory region id */
	if (id < DUMP_REGION_HOST_START || id > DUMP_REGION_HOST_END) {
		log_simple_error(&e_info(OPAL_RC_DUMP_MDST_ADD),
				 "MDST: Invalid dump region id : 0x%x\n", id);
		return OPAL_PARAMETER;
	}

	if (size <= 0) {
		log_simple_error(&e_info(OPAL_RC_DUMP_MDST_ADD),
				 "MDST: Invalid size : 0x%llx\n", size);
		return OPAL_PARAMETER;
	}

	rc = __dump_region_add_entry(id, addr, size);
	if (rc)
		return rc;

	/* Send updated MDST to FSP */
	rc = fsp_update_mdst_table();

	return rc;
}

static int64_t fsp_opal_unregister_dump_region(uint32_t id)
{
	int rc = OPAL_SUCCESS;

	if (!fsp_present())
		return OPAL_UNSUPPORTED;

	/* Validate memory region id */
	if (id < DUMP_REGION_HOST_START || id > DUMP_REGION_HOST_END) {
		log_simple_error(&e_info(OPAL_RC_DUMP_MDST_REMOVE),
				 "MDST: Invalid dump region id : 0x%x\n", id);
		return OPAL_PARAMETER;
	}

	rc = dump_region_del_entry(id);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_DUMP_MDST_REMOVE),
				 "MDST: dump region id : 0x%x not found\n", id);
		return OPAL_PARAMETER;
	}

	/* Send updated MDST to FSP */
	rc = fsp_update_mdst_table();

	return rc;
}

/* TCE mapping */
static inline void mdst_table_tce_map(void)
{
	fsp_tce_map(PSI_DMA_MDST_TABLE, mdst_table, PSI_DMA_MDST_TABLE_SIZE);
}

/* Initialize MDST table */
static int mdst_table_init(void)
{
	dump_mem_region = memalign(TCE_PSIZE, PSI_DMA_MDST_TABLE_SIZE);
	if (!dump_mem_region) {
		log_simple_error(&e_info(OPAL_RC_DUMP_MDST_INIT),
			 "MDST: Failed to allocate memory for dump "
			 "memory region table.\n");
		return -ENOMEM;
	}

	memset(dump_mem_region, 0, PSI_DMA_MDST_TABLE_SIZE);

	mdst_table = memalign(TCE_PSIZE, PSI_DMA_MDST_TABLE_SIZE);
	if (!mdst_table) {
		log_simple_error(&e_info(OPAL_RC_DUMP_MDST_INIT),
			 "MDST: Failed to allocate memory for MDST table.\n");
		return -ENOMEM;
	}

	memset(mdst_table, 0, PSI_DMA_MDST_TABLE_SIZE);
	mdst_table_tce_map();

	max_mdst_entry = PSI_DMA_MDST_TABLE_SIZE / sizeof(*mdst_table);
	printf("MDST: Max entries in MDST table : %d\n", max_mdst_entry);

	return OPAL_SUCCESS;
}

/*
 * Handle FSP R/R event.
 */
static bool fsp_mdst_update_rr(uint32_t cmd_sub_mod,
			       struct fsp_msg *msg __unused)
{
	switch (cmd_sub_mod) {
	case FSP_RESET_START:
		return true;
	case FSP_RELOAD_COMPLETE: /* Send MDST to FSP */
		fsp_update_mdst_table();
		return true;
	}
	return false;
}

static struct fsp_client fsp_mdst_client_rr = {
	.message = fsp_mdst_update_rr,
};

/* Initialize MDST table and send notification to FSP */
void fsp_mdst_table_init(void)
{
	if (!fsp_present())
		return;

	/* OPAL interface */
	opal_register(OPAL_REGISTER_DUMP_REGION,
		      fsp_opal_register_dump_region, 3);
	opal_register(OPAL_UNREGISTER_DUMP_REGION,
		      fsp_opal_unregister_dump_region, 1);

	/* Initiate MDST */
	if (mdst_table_init() != OPAL_SUCCESS)
		return;

	/*
	 * Ignore return code from mdst_table_add_entries so that
	 * we can atleast capture partial dump.
	 */
	dump_region_add_entries();
	fsp_update_mdst_table();

	/* Register for Class AA (FSP R/R) */
	fsp_register_client(&fsp_mdst_client_rr, FSP_MCLASS_RR_EVENT);
}
