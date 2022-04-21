// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2019 IBM Corp.
 */

#include <skiboot.h>
#include <chip.h>
#include <xscom.h>
#include <timebase.h>
#include <xscom-p9-regs.h>
#include <cache-p9.h>

/* Registers and bits used to clear the L2 and L3 cache */
#define L2_PRD_PURGE_CMD_REG			0x1080e
#define   L2_PRD_PURGE_CMD_TRIGGER		PPC_BIT(0)
#define   L2_PRD_PURGE_CMD_TYPE_MASK		PPC_BITMASK(1, 4)
#define     L2CAC_FLUSH				0x0
#define   L2_PRD_PURGE_CMD_REG_BUSY		PPC_BIT(9)
#define L3_PRD_PURGE_REG			0x1180e
#define   L3_PRD_PURGE_REQ			PPC_BIT(0)
#define   L3_PRD_PURGE_TTYPE_MASK		PPC_BITMASK(1, 4)
#define     L3_FULL_PURGE			0x0

#define L2_L3_PRD_PURGE_TIMEOUT_MS		20

static int start_l2_purge(uint32_t chip_id, uint32_t core_id)
{
	uint64_t addr = XSCOM_ADDR_P9_EX(core_id, L2_PRD_PURGE_CMD_REG);
	int rc;

	rc = xscom_write_mask(chip_id, addr, L2CAC_FLUSH,
			      L2_PRD_PURGE_CMD_TYPE_MASK);
	if (!rc)
		rc = xscom_write_mask(chip_id, addr, L2_PRD_PURGE_CMD_TRIGGER,
			      L2_PRD_PURGE_CMD_TRIGGER);
	if (rc)
		prlog(PR_ERR, "PURGE L2 on core 0x%x: XSCOM write_mask "
		      "failed %i\n", core_id, rc);
	return rc;
}

static int wait_l2_purge(uint32_t chip_id, uint32_t core_id)
{
	uint64_t val;
	uint64_t addr = XSCOM_ADDR_P9_EX(core_id, L2_PRD_PURGE_CMD_REG);
	unsigned long now = mftb();
	unsigned long end = now + msecs_to_tb(L2_L3_PRD_PURGE_TIMEOUT_MS);
	int rc;

	while (1) {
		rc = xscom_read(chip_id, addr, &val);
		if (rc) {
			prlog(PR_ERR, "PURGE L2 on core 0x%x: XSCOM read "
			      "failed %i\n", core_id, rc);
			break;
		}
		if (!(val & L2_PRD_PURGE_CMD_REG_BUSY))
			break;
		now = mftb();
		if (tb_compare(now, end) == TB_AAFTERB) {
			prlog(PR_ERR, "PURGE L2 on core 0x%x timed out %i\n",
			      core_id, rc);
			return OPAL_BUSY;
		}
	}

	/* We have to clear the trigger bit ourselves */
	val &= ~L2_PRD_PURGE_CMD_TRIGGER;
	rc = xscom_write(chip_id, addr, val);
	if (rc)
		prlog(PR_ERR, "PURGE L2 on core 0x%x: XSCOM write failed %i\n",
		      core_id, rc);
	return rc;
}

static int start_l3_purge(uint32_t chip_id, uint32_t core_id)
{
	uint64_t addr = XSCOM_ADDR_P9_EX(core_id, L3_PRD_PURGE_REG);
	int rc;

	rc = xscom_write_mask(chip_id, addr, L3_FULL_PURGE,
			      L3_PRD_PURGE_TTYPE_MASK);
	if (!rc)
		rc = xscom_write_mask(chip_id, addr, L3_PRD_PURGE_REQ,
			      L3_PRD_PURGE_REQ);
	if (rc)
		prlog(PR_ERR, "PURGE L3 on core 0x%x: XSCOM write_mask "
		      "failed %i\n", core_id, rc);
	return rc;
}

static int wait_l3_purge(uint32_t chip_id, uint32_t core_id)
{
	uint64_t val;
	uint64_t addr = XSCOM_ADDR_P9_EX(core_id, L3_PRD_PURGE_REG);
	unsigned long now = mftb();
	unsigned long end = now + msecs_to_tb(L2_L3_PRD_PURGE_TIMEOUT_MS);
	int rc;

	/* Trigger bit is automatically set to zero when flushing is done */
	while (1) {
		rc = xscom_read(chip_id, addr, &val);
		if (rc) {
			prlog(PR_ERR, "PURGE L3 on core 0x%x: XSCOM read "
			      "failed %i\n", core_id, rc);
			break;
		}
		if (!(val & L3_PRD_PURGE_REQ))
			break;
		now = mftb();
		if (tb_compare(now, end) == TB_AAFTERB) {
			prlog(PR_ERR, "PURGE L3 on core 0x%x timed out %i\n",
			      core_id, rc);
			return OPAL_BUSY;
		}
	}
	return rc;
}

int64_t purge_l2_l3_caches(void)
{
	struct cpu_thread *t;
	uint64_t core_id, prev_core_id = (uint64_t)-1;
	int rc;
	unsigned long now = mftb();

	for_each_ungarded_cpu(t) {
		/* Only need to do it once per core chiplet */
		core_id = pir_to_core_id(t->pir);
		if (prev_core_id == core_id)
			continue;
		prev_core_id = core_id;
		rc = start_l2_purge(t->chip_id, core_id);
		if (rc)
			goto trace_exit;
		rc = start_l3_purge(t->chip_id, core_id);
		if (rc)
			goto trace_exit;
	}

	prev_core_id = (uint64_t)-1;
	for_each_ungarded_cpu(t) {
		/* Only need to do it once per core chiplet */
		core_id = pir_to_core_id(t->pir);
		if (prev_core_id == core_id)
			continue;
		prev_core_id = core_id;

		rc = wait_l2_purge(t->chip_id, core_id);
		if (rc)
			goto trace_exit;
		rc = wait_l3_purge(t->chip_id, core_id);
		if (rc)
			goto trace_exit;
	}

trace_exit:
	prlog(PR_TRACE, "L2/L3 purging took %ldus\n",
			tb_to_usecs(mftb() - now));

	return rc;
}
