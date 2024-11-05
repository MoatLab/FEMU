// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2020 IBM Corp.
 */
#include <timebase.h>
#include <pau.h>

#define PAU_PHY_INIT_TIMEOUT		8000 /* ms */

#define PAU_PHY_ADDR_REG		0x10012C0D
#define PAU_PHY_ADDR_CHIPLET		PPC_BITMASK(32, 39)
#define PAU_PHY_ADDR_SRAM_ADDR		PPC_BITMASK(15, 31)
#define PAU_PHY_DATA_REG		0x10012C0E
#define PAU_PHY_DATA_CHIPLET		PPC_BITMASK(32, 39)

#define PAU_MAX_PHY_LANE		18

/*
 * We configure the PHY using the memory mapped SRAM, which is
 * accessible through a pair of (addr, data) registers. The caveat is
 * that accesses to the SRAM must be 64-bit aligned, yet the PHY
 * registers are 16-bit, so special care is needed.
 *
 * A PAU chiplet may control up to 2 OP units = 4 links and each link
 * has its own virtual PHB in skiboot. They can be initialized or
 * reset concurrently so we need a lock when accessing the SRAM.

 * See section "5.2.5 PPE SRAM" of the workbook for the layout of the
 * SRAM registers. Here is the subset of the table which is meaningful
 * for us, since we're only touching a few registers:
 *
 *   Address      Bytes     Linker Symbol        Description
 *   FFFF_11B0    16        _fw_regs0_start      fw_regs for thread 0
 *   FFFF_11C0    16        _fw_regs1_start      fw_regs for thread 1
 *
 *   FFFF_2800    1024      _mem_regs0_start     mem_regs for thread 0
 *   FFFF_2C00    1024      _mem_regs1_start     mem_regs for thread 1
 *
 * In each PAU, per-group registers are replicated for every OP (each
 * OP units is being called a 'thread' in the workbook).
 * Per-lane registers have an offset < 0x10 and are replicated for
 * each lane. Their offset in their section is:
 *   0byyyyyxxxx (y = 5-bit lane number, x = 4-bit per-lane register offset)
 */

struct PPE_sram_section {
	uint32_t offset;
	uint32_t size;
};

static struct PPE_sram_section PPE_FIRMWARE = { 0x111B0, 0x10 };
static struct PPE_sram_section PPE_MEMORY   = { 0x12800, 0x400 };

struct PPE_sram_reg {
	struct PPE_sram_section *section;
	uint32_t offset;
};

/* PPE firmware */
static struct PPE_sram_reg PAU_PHY_EXT_CMD_LANES_00_15 = { &PPE_FIRMWARE, 0x000 };
static struct PPE_sram_reg PAU_PHY_EXT_CMD_LANES_16_31 = { &PPE_FIRMWARE, 0x001 };
static struct PPE_sram_reg PAU_PHY_EXT_CMD_REQ         = { &PPE_FIRMWARE, 0x002 };
#define PAU_PHY_EXT_CMD_REQ_IO_RESET	PPC_BIT16(1)
#define PAU_PHY_EXT_CMD_REQ_DCCAL	PPC_BIT16(3)
#define PAU_PHY_EXT_CMD_REQ_TX_ZCAL	PPC_BIT16(4)
#define PAU_PHY_EXT_CMD_REQ_TX_FFE	PPC_BIT16(5)
#define PAU_PHY_EXT_CMD_REQ_POWER_ON	PPC_BIT16(7)
static struct PPE_sram_reg PAU_PHY_EXT_CMD_DONE        = { &PPE_FIRMWARE, 0x005 };

/* PPE memory */
static struct PPE_sram_reg PAU_PHY_RX_PPE_CNTL1        = { &PPE_MEMORY, 0x000 };
#define PAU_PHY_RX_ENABLE_AUTO_RECAL	PPC_BIT16(1)

enum pau_phy_status {
	PAU_PROC_INPROGRESS,
	PAU_PROC_COMPLETE,
	PAU_PROC_NEXT,
	PAU_PROC_FAILED
};

struct procedure {
	const char *name;
	uint32_t (*steps[])(struct pau_dev *);
};

#define DEFINE_PROCEDURE(NAME, STEPS...)		\
	static struct procedure procedure_##NAME = {	\
		.name = #NAME,				\
		.steps = { STEPS }			\
	}

/*
 * We could/should have one phy_sram_lock per PAU chiplet. Each PAU
 * chiplet drives 2 OPT units.  Since we don't have a PAU chiplet
 * structure to host the lock and don't anticipate much contention, we
 * go with a global lock for now
 */
static struct lock phy_sram_lock = LOCK_UNLOCKED;

static int get_thread_id(uint32_t op_unit)
{
	int ppe_thread[8] = { 0, 1, 1, 0, 1, 0, 1, 0 };

	/* static mapping between OP unit and PPE thread ID */
	if (op_unit >= sizeof(ppe_thread))
		return -1;
	return ppe_thread[op_unit];
}

/*
 * Compute the address in the memory mapped SRAM of a 16-bit PHY register
 */
static uint32_t pau_phy_sram_addr(struct pau_dev *dev,
				  struct PPE_sram_reg *reg,
				  int lane)
{
	uint32_t base, addr;

	base = reg->section->offset +
	       reg->section->size * get_thread_id(dev->op_unit);
	addr = reg->offset;
	if (lane >= 0) {
		assert(reg->offset < 0x10);
		addr += lane << 4;
	}
	addr <<= 1; // each register is 16-bit
	return base + addr;
}

static void pau_phy_set_access(struct pau_dev *dev,
			       struct PPE_sram_reg *reg, int lane,
			       uint64_t *data_addr, uint64_t *mask)
{
	struct pau *pau = dev->pau;
	uint64_t scom_addr, sram_addr, addr, bit_start;

	scom_addr = SETFIELD(PAU_PHY_ADDR_CHIPLET, PAU_PHY_ADDR_REG,
			     pau->op_chiplet);
	sram_addr = pau_phy_sram_addr(dev, reg, lane);
	bit_start = 8 * (sram_addr & 7);

	addr = SETFIELD(PAU_PHY_ADDR_SRAM_ADDR, 0ull, sram_addr & 0xFFFFFFF8);
	xscom_write(pau->chip_id, scom_addr, addr);

	*data_addr = SETFIELD(PAU_PHY_DATA_CHIPLET, PAU_PHY_DATA_REG,
			      pau->op_chiplet);
	*mask = PPC_BITMASK(bit_start, bit_start + 15);
}

static void pau_phy_write_lane(struct pau_dev *dev,
			       struct PPE_sram_reg *reg, int lane,
			       uint16_t val)
{
	struct pau *pau = dev->pau;
	uint64_t data_addr, scom_val, mask;

	lock(&phy_sram_lock);
	pau_phy_set_access(dev, reg, lane, &data_addr, &mask);
	xscom_read(pau->chip_id, data_addr, &scom_val);
	scom_val = SETFIELD(mask, scom_val, val);
	xscom_write(pau->chip_id, data_addr, scom_val);
	unlock(&phy_sram_lock);
}

static uint16_t pau_phy_read_lane(struct pau_dev *dev,
				  struct PPE_sram_reg *reg, int lane)
{
	struct pau *pau = dev->pau;
	uint64_t data_addr, scom_val, mask;
	uint16_t res;

	lock(&phy_sram_lock);
	pau_phy_set_access(dev, reg, lane, &data_addr, &mask);
	xscom_read(pau->chip_id, data_addr, &scom_val);
	res = GETFIELD(mask, scom_val);
	unlock(&phy_sram_lock);
	return res;
}

static void pau_phy_write(struct pau_dev *dev, struct PPE_sram_reg *reg,
			  uint16_t val)
{
	pau_phy_write_lane(dev, reg, -1, val);
}

static uint16_t pau_phy_read(struct pau_dev *dev, struct PPE_sram_reg *reg)
{
	return pau_phy_read_lane(dev, reg, -1);
}

static uint16_t get_reset_request_val(void)
{
	return PAU_PHY_EXT_CMD_REQ_IO_RESET |
		PAU_PHY_EXT_CMD_REQ_DCCAL |
		PAU_PHY_EXT_CMD_REQ_TX_ZCAL |
		PAU_PHY_EXT_CMD_REQ_TX_FFE |
		PAU_PHY_EXT_CMD_REQ_POWER_ON;
}

static uint32_t reset_start(struct pau_dev *dev)
{
	uint16_t val16;

	// Procedure IO_INIT_RESET_PON

	// Clear external command request / done registers
	val16 = 0;
	pau_phy_write(dev, &PAU_PHY_EXT_CMD_REQ, val16);
	pau_phy_write(dev, &PAU_PHY_EXT_CMD_DONE, val16);

	// Write the external command lanes to target
	val16 = dev->phy_lane_mask >> 16;
	pau_phy_write(dev, &PAU_PHY_EXT_CMD_LANES_00_15, val16);
	val16 = dev->phy_lane_mask & 0xFFFF;
	pau_phy_write(dev, &PAU_PHY_EXT_CMD_LANES_16_31, val16);

	// Initialize PHY Lanes
	val16 = get_reset_request_val();
	pau_phy_write(dev, &PAU_PHY_EXT_CMD_REQ, val16);
	return PAU_PROC_NEXT;
}

static uint32_t reset_check(struct pau_dev *dev)
{
	uint16_t val16, done;

	val16 = get_reset_request_val();
	done = pau_phy_read(dev, &PAU_PHY_EXT_CMD_DONE);

	if (val16 == done)
		return PAU_PROC_NEXT;
	else
		return PAU_PROC_INPROGRESS;
}

static uint32_t enable_recal(struct pau_dev *dev)
{
	uint32_t lane;

	// Enable auto-recalibration
	for (lane = 0; lane <= PAU_MAX_PHY_LANE; lane++)
		if (!(dev->phy_lane_mask & (1 << (31 - lane))))
			continue;
		else
			pau_phy_write_lane(dev, &PAU_PHY_RX_PPE_CNTL1,
					   lane, PAU_PHY_RX_ENABLE_AUTO_RECAL);

	return PAU_PROC_COMPLETE;
}

DEFINE_PROCEDURE(phy_reset, reset_start, reset_check, enable_recal);

static enum pau_phy_status run_steps(struct pau_dev *dev)
{
	struct procedure *p = &procedure_phy_reset;
	struct phy_proc_state *procedure_state = &dev->pau->procedure_state;
	enum pau_phy_status rc;

	do {
		rc = p->steps[procedure_state->step](dev);
		if (rc == PAU_PROC_NEXT) {
			procedure_state->step++;
			PAUDEVDBG(dev, "Running procedure %s step %d\n",
				  p->name, procedure_state->step);
		}
	} while (rc == PAU_PROC_NEXT);
	return rc;
}

static enum pau_phy_status run_procedure(struct pau_dev *dev)
{
	struct procedure *p = &procedure_phy_reset;
	struct phy_proc_state *procedure_state = &dev->pau->procedure_state;
	enum pau_phy_status rc;

	do {
		rc = run_steps(dev);
		if (rc == PAU_PROC_INPROGRESS) {
			if (tb_compare(mftb(), procedure_state->timeout) == TB_AAFTERB) {
				PAUDEVERR(dev, "Procedure %s timed out\n", p->name);
				rc = PAU_PROC_FAILED;
			} else {
				time_wait_ms(1);
			}
		}
	} while (rc == PAU_PROC_INPROGRESS);
	return rc;
}

int pau_dev_phy_reset(struct pau_dev *dev)
{
	struct procedure *p = &procedure_phy_reset;
	struct phy_proc_state *procedure_state = &dev->pau->procedure_state;
	enum pau_phy_status rc;

	lock(&procedure_state->lock);
	procedure_state->step = 0;
	procedure_state->timeout = mftb() + msecs_to_tb(PAU_PHY_INIT_TIMEOUT);
	PAUDEVDBG(dev, "Running procedure %s step %d\n",
		  p->name, procedure_state->step);
	rc = run_procedure(dev);
	unlock(&procedure_state->lock);

	if (rc == PAU_PROC_COMPLETE) {
		PAUDEVDBG(dev, "Procedure %s complete\n", p->name);
		return OPAL_SUCCESS;
	}
	PAUDEVDBG(dev, "Procedure %s failed\n", p->name);
	return OPAL_HARDWARE;
}
