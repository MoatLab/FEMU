/* Copyright 2019 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define pr_fmt(fmt)	"DUMP: " fmt

#include <chip.h>
#include <cpu.h>
#include <device.h>
#include <mem-map.h>
#include <mem_region.h>
#include <mem_region-malloc.h>
#include <opal.h>
#include <opal-dump.h>
#include <opal-internal.h>
#include <sbe-p9.h>
#include <skiboot.h>

#include <ccan/endian/endian.h>

#include "hdata/spira.h"

/* XXX Ideally we should use HDAT provided data (proc_dump_area->thread_size).
 *     But we are not getting this data durig boot. Hence lets reserve fixed
 *     memory for architected registers data collection.
 */
#define ARCH_REGS_DATA_SIZE_PER_CHIP	(512 * 1024)

/* Actual address of MDST and MDDT table */
#define MDST_TABLE_BASE		(SKIBOOT_BASE + MDST_TABLE_OFF)
#define MDDT_TABLE_BASE		(SKIBOOT_BASE + MDDT_TABLE_OFF)
#define PROC_DUMP_AREA_BASE	(SKIBOOT_BASE + PROC_DUMP_AREA_OFF)

static struct spira_ntuple *ntuple_mdst;
static struct spira_ntuple *ntuple_mddt;
static struct spira_ntuple *ntuple_mdrt;

static struct mpipl_metadata    *mpipl_metadata;

/* Dump metadata area */
static struct opal_mpipl_fadump *opal_mpipl_data;
static struct opal_mpipl_fadump *opal_mpipl_cpu_data;

/*
 * Number of tags passed by OPAL to kernel after MPIPL boot.
 * Currently it supports below tags:
 *   - CPU register data area
 *   - OPAL metadata area address
 *   - Kernel passed tag during MPIPL registration
 *   - Post MPIPL boot memory size
 */
#define MAX_OPAL_MPIPL_TAGS	0x04
static u64 opal_mpipl_tags[MAX_OPAL_MPIPL_TAGS];
static int opal_mpipl_max_tags = MAX_OPAL_MPIPL_TAGS;

static u64 opal_dump_addr, opal_dump_size;

static bool mpipl_enabled;

static int opal_mpipl_add_entry(u8 region, u64 src, u64 dest, u64 size)
{
	int i;
	int mdst_cnt = be16_to_cpu(ntuple_mdst->act_cnt);
	int mddt_cnt = be16_to_cpu(ntuple_mddt->act_cnt);
	struct mdst_table *mdst;
	struct mddt_table *mddt;

	if (mdst_cnt >= MDST_TABLE_SIZE / sizeof(struct mdst_table)) {
		prlog(PR_DEBUG, "MDST table is full\n");
		return OPAL_RESOURCE;
	}

	if (mddt_cnt >= MDDT_TABLE_SIZE / sizeof(struct mddt_table)) {
		prlog(PR_DEBUG, "MDDT table is full\n");
		return OPAL_RESOURCE;
	}

	/* Use relocated memory address */
	mdst = (void *)(MDST_TABLE_BASE);
	mddt = (void *)(MDDT_TABLE_BASE);

	/* Check for duplicate entry */
	for (i = 0; i < mdst_cnt; i++) {
		if (be64_to_cpu(mdst->addr) == (src | HRMOR_BIT)) {
			prlog(PR_DEBUG,
			      "Duplicate source address : 0x%llx", src);
			return OPAL_PARAMETER;
		}
		mdst++;
	}
	for (i = 0; i < mddt_cnt; i++) {
		if (be64_to_cpu(mddt->addr) == (dest | HRMOR_BIT)) {
			prlog(PR_DEBUG,
			      "Duplicate destination address : 0x%llx", dest);
			return OPAL_PARAMETER;
		}
		mddt++;
	}

	/* Add OPAL source address to MDST entry */
	mdst->addr = cpu_to_be64(src | HRMOR_BIT);
	mdst->data_region = region;
	mdst->size = cpu_to_be32(size);
	ntuple_mdst->act_cnt = cpu_to_be16(mdst_cnt + 1);

	/* Add OPAL destination address to MDDT entry */
	mddt->addr = cpu_to_be64(dest | HRMOR_BIT);
	mddt->data_region = region;
	mddt->size = cpu_to_be32(size);
	ntuple_mddt->act_cnt = cpu_to_be16(mddt_cnt + 1);

	prlog(PR_TRACE, "Added new entry. src : 0x%llx, dest : 0x%llx,"
	      " size : 0x%llx\n", src, dest, size);
	return OPAL_SUCCESS;
}

/* Remove entry from source (MDST) table */
static int opal_mpipl_remove_entry_mdst(bool remove_all, u8 region, u64 src)
{
	bool found = false;
	int i, j;
	int mdst_cnt = be16_to_cpu(ntuple_mdst->act_cnt);
	struct mdst_table *tmp_mdst;
	struct mdst_table *mdst = (void *)(MDST_TABLE_BASE);

	for (i = 0; i < mdst_cnt;) {
		if (mdst->data_region != region) {
			mdst++;
			i++;
			continue;
		}

		if (remove_all != true &&
				be64_to_cpu(mdst->addr) != (src | HRMOR_BIT)) {
			mdst++;
			i++;
			continue;
		}

		tmp_mdst = mdst;
		memset(tmp_mdst, 0, sizeof(struct mdst_table));

		for (j = i; j < mdst_cnt - 1; j++) {
			memcpy((void *)tmp_mdst,
			       (void *)(tmp_mdst + 1), sizeof(struct mdst_table));
			tmp_mdst++;
			memset(tmp_mdst, 0, sizeof(struct mdst_table));
		}

		mdst_cnt--;

		if (remove_all == false) {
			found = true;
			break;
		}
	}  /* end - for loop */

	ntuple_mdst->act_cnt = cpu_to_be16((u16)mdst_cnt);

	if (remove_all == false && found == false) {
		prlog(PR_DEBUG,
		      "Source address [0x%llx] not found in MDST table\n", src);
		return OPAL_PARAMETER;
	}

	return OPAL_SUCCESS;
}

/* Remove entry from destination (MDDT) table */
static int opal_mpipl_remove_entry_mddt(bool remove_all, u8 region, u64 dest)
{
	bool found = false;
	int i, j;
	int mddt_cnt = be16_to_cpu(ntuple_mddt->act_cnt);
	struct mddt_table *tmp_mddt;
	struct mddt_table *mddt = (void *)(MDDT_TABLE_BASE);

	for (i = 0; i < mddt_cnt;) {
		if (mddt->data_region != region) {
			mddt++;
			i++;
			continue;
		}

		if (remove_all != true &&
				be64_to_cpu(mddt->addr) != (dest | HRMOR_BIT)) {
			mddt++;
			i++;
			continue;
		}

		tmp_mddt = mddt;
		memset(tmp_mddt, 0, sizeof(struct mddt_table));

		for (j = i; j < mddt_cnt - 1; j++) {
			memcpy((void *)tmp_mddt,
			       (void *)(tmp_mddt + 1), sizeof(struct mddt_table));
			tmp_mddt++;
			memset(tmp_mddt, 0, sizeof(struct mddt_table));
		}

		mddt_cnt--;

		if (remove_all == false) {
			found = true;
			break;
		}
	}  /* end - for loop */

	ntuple_mddt->act_cnt = cpu_to_be16((u16)mddt_cnt);

	if (remove_all == false && found == false) {
		prlog(PR_DEBUG,
		      "Dest address [0x%llx] not found in MDDT table\n", dest);
		return OPAL_PARAMETER;
	}

	return OPAL_SUCCESS;
}

/* Register for OPAL dump.  */
static void opal_mpipl_register(void)
{
	u64 arch_regs_dest, arch_regs_size;
	struct proc_dump_area *proc_dump = (void *)(PROC_DUMP_AREA_BASE);

	/* Add OPAL reservation detail to MDST/MDDT table */
	opal_mpipl_add_entry(DUMP_REGION_OPAL_MEMORY,
			     SKIBOOT_BASE, opal_dump_addr, opal_dump_size);

	/* Thread size check */
	if (proc_dump->thread_size != 0) {
		prlog(PR_INFO, "Thread register entry size is available, "
		      "but not supported.\n");
	}

	/* Reserve memory used to capture architected register state */
	arch_regs_dest = opal_dump_addr + opal_dump_size;
	arch_regs_size = nr_chips() * ARCH_REGS_DATA_SIZE_PER_CHIP;
	proc_dump->alloc_addr = cpu_to_be64(arch_regs_dest | HRMOR_BIT);
	proc_dump->alloc_size = cpu_to_be32(arch_regs_size);
	prlog(PR_NOTICE, "Architected register dest addr : 0x%llx, "
	      "size : 0x%llx\n", arch_regs_dest, arch_regs_size);
}

static int payload_mpipl_register(u64 src, u64 dest, u64 size)
{
	if (!opal_addr_valid((void *)src)) {
		prlog(PR_DEBUG, "Invalid source address [0x%llx]\n", src);
		return OPAL_PARAMETER;
	}

	if (!opal_addr_valid((void *)dest)) {
		prlog(PR_DEBUG, "Invalid dest address [0x%llx]\n", dest);
		return OPAL_PARAMETER;
	}

	if (size <= 0) {
		prlog(PR_DEBUG, "Invalid size [0x%llx]\n", size);
		return OPAL_PARAMETER;
	}

	return opal_mpipl_add_entry(DUMP_REGION_KERNEL, src, dest, size);
}

static int payload_mpipl_unregister(u64 src, u64 dest)
{
	int rc;

	/* Remove src from MDST table */
	rc = opal_mpipl_remove_entry_mdst(false, DUMP_REGION_KERNEL, src);
	if (rc)
		return rc;

	/* Remove dest from MDDT table */
	rc = opal_mpipl_remove_entry_mddt(false, DUMP_REGION_KERNEL, dest);
	return rc;
}

static int payload_mpipl_unregister_all(void)
{
	opal_mpipl_remove_entry_mdst(true, DUMP_REGION_KERNEL, 0);
	opal_mpipl_remove_entry_mddt(true, DUMP_REGION_KERNEL, 0);

	return OPAL_SUCCESS;
}

static int64_t opal_mpipl_update(enum opal_mpipl_ops ops,
				 u64 src, u64 dest, u64 size)
{
	int rc;

	switch (ops) {
	case OPAL_MPIPL_ADD_RANGE:
		rc = payload_mpipl_register(src, dest, size);
		if (!rc)
			prlog(PR_NOTICE, "Payload registered for MPIPL\n");
		break;
	case OPAL_MPIPL_REMOVE_RANGE:
		rc = payload_mpipl_unregister(src, dest);
		if (!rc) {
			prlog(PR_NOTICE, "Payload removed entry from MPIPL."
			      "[src : 0x%llx, dest : 0x%llx]\n", src, dest);
		}
		break;
	case OPAL_MPIPL_REMOVE_ALL:
		rc = payload_mpipl_unregister_all();
		if (!rc)
			prlog(PR_NOTICE, "Payload unregistered for MPIPL\n");
		break;
	case OPAL_MPIPL_FREE_PRESERVED_MEMORY:
		/* Clear tags */
		memset(&opal_mpipl_tags, 0, (sizeof(u64) * MAX_OPAL_MPIPL_TAGS));
		opal_mpipl_max_tags = 0;
		/* Release memory */
		free(opal_mpipl_data);
		opal_mpipl_data = NULL;
		free(opal_mpipl_cpu_data);
		opal_mpipl_cpu_data = NULL;
		/* Clear MDRT table */
		memset((void *)MDRT_TABLE_BASE, 0, MDRT_TABLE_SIZE);
		/* Set MDRT count to max allocated count */
		ntuple_mdrt->act_cnt = cpu_to_be16(MDRT_TABLE_SIZE / sizeof(struct mdrt_table));
		rc = OPAL_SUCCESS;
		prlog(PR_NOTICE, "Payload Invalidated MPIPL\n");
		break;
	default:
		prlog(PR_DEBUG, "Unsupported MPIPL update operation : 0x%x\n", ops);
		rc = OPAL_PARAMETER;
		break;
	}

	return rc;
}

static int64_t opal_mpipl_register_tag(enum opal_mpipl_tags tag,
				       uint64_t tag_val)
{
	int rc = OPAL_SUCCESS;

	switch (tag) {
	case OPAL_MPIPL_TAG_BOOT_MEM:
		if (tag_val <= 0 || tag_val > top_of_ram) {
			prlog(PR_DEBUG, "Payload sent invalid boot mem size"
			      " :  0x%llx\n", tag_val);
			rc = OPAL_PARAMETER;
		} else {
			mpipl_metadata->boot_mem_size = tag_val;
			prlog(PR_NOTICE, "Boot mem size : 0x%llx\n", tag_val);
		}
		break;
	case OPAL_MPIPL_TAG_KERNEL:
		mpipl_metadata->kernel_tag = tag_val;
		prlog(PR_NOTICE, "Payload sent metadata tag : 0x%llx\n", tag_val);
		break;
	default:
		prlog(PR_DEBUG, "Payload sent unsupported tag : 0x%x\n", tag);
		rc = OPAL_PARAMETER;
		break;
	}
	return rc;
}

static uint64_t opal_mpipl_query_tag(enum opal_mpipl_tags tag, __be64 *tag_val)
{
	if (!opal_addr_valid(tag_val)) {
		prlog(PR_DEBUG, "Invalid tag address\n");
		return OPAL_PARAMETER;
	}

	if (tag >= opal_mpipl_max_tags)
		return OPAL_PARAMETER;

	*tag_val = cpu_to_be64(opal_mpipl_tags[tag]);
	return OPAL_SUCCESS;
}

static inline void post_mpipl_get_preserved_tags(void)
{
	if (mpipl_metadata->kernel_tag)
		opal_mpipl_tags[OPAL_MPIPL_TAG_KERNEL] = mpipl_metadata->kernel_tag;
	if (mpipl_metadata->boot_mem_size)
		opal_mpipl_tags[OPAL_MPIPL_TAG_BOOT_MEM] = mpipl_metadata->boot_mem_size;
}

static void post_mpipl_arch_regs_data(void)
{
	struct proc_dump_area *proc_dump = (void *)(PROC_DUMP_AREA_BASE);

	if (proc_dump->dest_addr == 0) {
		prlog(PR_DEBUG, "Invalid CPU registers destination address\n");
		return;
	}

	if (proc_dump->act_size == 0) {
		prlog(PR_DEBUG, "Invalid CPU registers destination size\n");
		return;
	}

	opal_mpipl_cpu_data = zalloc(sizeof(struct opal_mpipl_fadump) +
				sizeof(struct opal_mpipl_region));
	if (!opal_mpipl_cpu_data) {
		prlog(PR_ERR, "Failed to allocate memory\n");
		return;
	}

	/* Fill CPU register details */
	opal_mpipl_cpu_data->version = OPAL_MPIPL_VERSION;
	opal_mpipl_cpu_data->cpu_data_version = cpu_to_be32((u32)proc_dump->version);
	opal_mpipl_cpu_data->cpu_data_size = proc_dump->thread_size;
	opal_mpipl_cpu_data->region_cnt = cpu_to_be32(1);

	opal_mpipl_cpu_data->region[0].src  = proc_dump->dest_addr & ~(cpu_to_be64(HRMOR_BIT));
	opal_mpipl_cpu_data->region[0].dest = proc_dump->dest_addr & ~(cpu_to_be64(HRMOR_BIT));
	opal_mpipl_cpu_data->region[0].size = cpu_to_be64(be32_to_cpu(proc_dump->act_size));

	/* Update tag */
	opal_mpipl_tags[OPAL_MPIPL_TAG_CPU] = (u64)opal_mpipl_cpu_data;
}

static void post_mpipl_get_opal_data(void)
{
	struct mdrt_table *mdrt = (void *)(MDRT_TABLE_BASE);
	int i, j = 0, count = 0;
	int mdrt_cnt = be16_to_cpu(ntuple_mdrt->act_cnt);
	struct opal_mpipl_region *region;

	/* Count OPAL dump regions */
	for (i = 0; i < mdrt_cnt; i++) {
		if (mdrt->data_region == DUMP_REGION_OPAL_MEMORY)
			count++;
		mdrt++;
	}

	if (count == 0) {
		prlog(PR_INFO, "OPAL dump is not available\n");
		return;
	}

	opal_mpipl_data = zalloc(sizeof(struct opal_mpipl_fadump) +
				 count * sizeof(struct opal_mpipl_region));
	if (!opal_mpipl_data) {
		prlog(PR_ERR, "Failed to allocate memory\n");
		return;
	}

	/* Fill OPAL dump details */
	opal_mpipl_data->version = OPAL_MPIPL_VERSION;
	opal_mpipl_data->crashing_pir = cpu_to_be32(mpipl_metadata->crashing_pir);
	opal_mpipl_data->region_cnt = cpu_to_be32(count);
	region = opal_mpipl_data->region;

	mdrt = (void *)(MDRT_TABLE_BASE);
	for (i = 0; i < mdrt_cnt; i++) {
		if (mdrt->data_region != DUMP_REGION_OPAL_MEMORY) {
			mdrt++;
			continue;
		}

		region[j].src  = mdrt->src_addr  & ~(cpu_to_be64(HRMOR_BIT));
		region[j].dest = mdrt->dest_addr & ~(cpu_to_be64(HRMOR_BIT));
		region[j].size = cpu_to_be64(be32_to_cpu(mdrt->size));

		prlog(PR_NOTICE, "OPAL reserved region %d - src : 0x%llx, "
		      "dest : 0x%llx, size : 0x%llx\n", j,
		      be64_to_cpu(region[j].src), be64_to_cpu(region[j].dest),
		      be64_to_cpu(region[j].size));

		mdrt++;
		j++;
		if (j == count)
			break;
	}

	opal_mpipl_tags[OPAL_MPIPL_TAG_OPAL] = (u64)opal_mpipl_data;
}

void opal_mpipl_save_crashing_pir(void)
{
	if (!is_mpipl_enabled())
		return;

	mpipl_metadata->crashing_pir = this_cpu()->pir;
	prlog(PR_NOTICE, "Crashing PIR = 0x%x\n", this_cpu()->pir);
}

void opal_mpipl_reserve_mem(void)
{
	struct dt_node *opal_node, *dump_node;
	u64 arch_regs_dest, arch_regs_size;

	opal_node = dt_find_by_path(dt_root, "ibm,opal");
	if (!opal_node)
		return;

	dump_node = dt_find_by_path(opal_node, "dump");
	if (!dump_node)
		return;

	/* Calculcate and Reserve OPAL dump destination memory */
	opal_dump_size = SKIBOOT_SIZE + (cpu_max_pir + 1) * STACK_SIZE;
	opal_dump_addr = SKIBOOT_BASE + opal_dump_size;
	mem_reserve_fw("ibm,firmware-dump",
		       opal_dump_addr, opal_dump_size);

	/* Reserve memory to capture CPU register data */
	arch_regs_dest = opal_dump_addr + opal_dump_size;
	arch_regs_size = nr_chips() * ARCH_REGS_DATA_SIZE_PER_CHIP;
	mem_reserve_fw("ibm,firmware-arch-registers",
		       arch_regs_dest, arch_regs_size);
}

bool is_mpipl_enabled(void)
{
	return mpipl_enabled;
}

void opal_mpipl_init(void)
{
	void *mdst_base = (void *)MDST_TABLE_BASE;
	void *mddt_base = (void *)MDDT_TABLE_BASE;
	struct dt_node *dump_node;

	dump_node = dt_find_by_path(opal_node, "dump");
	if (!dump_node)
		return;

	/* Get MDST and MDDT ntuple from SPIRAH */
	ntuple_mdst = &(spirah.ntuples.mdump_src);
	ntuple_mddt = &(spirah.ntuples.mdump_dst);
	ntuple_mdrt = &(spirah.ntuples.mdump_res);

	/* Get metadata area pointer */
	mpipl_metadata = (void *)(DUMP_METADATA_AREA_BASE);

	if (dt_find_property(dump_node, "mpipl-boot")) {
		disable_fast_reboot("MPIPL Boot");

		post_mpipl_get_preserved_tags();
		post_mpipl_get_opal_data();
		post_mpipl_arch_regs_data();
	}

	/* Clear OPAL metadata area */
	if (sizeof(struct mpipl_metadata) > DUMP_METADATA_AREA_SIZE) {
		prlog(PR_ERR, "INSUFFICIENT OPAL METADATA AREA\n");
		prlog(PR_ERR, "INCREASE OPAL MEDTADATA AREA SIZE\n");
		assert(false);
	}
	memset(mpipl_metadata, 0, sizeof(struct mpipl_metadata));

	/* Clear MDST and MDDT table */
	memset(mdst_base, 0, MDST_TABLE_SIZE);
	ntuple_mdst->act_cnt = 0;
	memset(mddt_base, 0, MDDT_TABLE_SIZE);
	ntuple_mddt->act_cnt = 0;

	opal_mpipl_register();

	/* Send OPAL relocated base address to SBE */
	p9_sbe_send_relocated_base(SKIBOOT_BASE);

	/* OPAL API for MPIPL update */
	opal_register(OPAL_MPIPL_UPDATE, opal_mpipl_update, 4);
	opal_register(OPAL_MPIPL_REGISTER_TAG, opal_mpipl_register_tag, 2);
	opal_register(OPAL_MPIPL_QUERY_TAG, opal_mpipl_query_tag, 2);

	/* Enable MPIPL */
	mpipl_enabled = true;
}
