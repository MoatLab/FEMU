// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * NPU (NVLink1, POWER8NVL) Hardware Procedures
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <skiboot.h>
#include <io.h>
#include <timebase.h>
#include <pci.h>
#include <pci-virt.h>
#include <interrupts.h>
#include <npu-regs.h>
#include <npu.h>
#include <xscom.h>

typedef uint32_t (*step)(struct npu_dev *);

struct procedure {
	const char *name;
	step steps[];
};

#define DEFINE_PROCEDURE(NAME, STEPS...)		\
	static struct procedure procedure_##NAME =	\
	{.name = #NAME, .steps = {NAME, ##STEPS}}

#define PROCEDURE_INPROGRESS	(1 << 31)
#define PROCEDURE_COMPLETE	(1 << 30)
#define PROCEDURE_NEXT		(1 << 29)
#define PROCEDURE_FAILED	2
#define PROCEDURE_ABORTED 	3
#define PROCEDURE_UNSUPPORTED	4

/* Mask defining which status bits we want to expose */
#define PROCEDURE_STATUS_MASK	0xc000000f

/* Accesors for PHY registers. These can be done either via MMIO or SCOM. */
static bool pl_use_scom = 1;
static void phy_write(struct npu_dev *npu_dev, uint64_t addr, uint32_t val)
{
	if (pl_use_scom)
		xscom_write(npu_dev->npu->chip_id, npu_dev->pl_xscom_base | addr, val);
	else
		out_be16((void *) npu_dev->pl_base + PL_MMIO_ADDR(addr), val);
}

static uint16_t phy_read(struct npu_dev *npu_dev, uint64_t addr)
{
	uint64_t val;

	if (pl_use_scom)
		xscom_read(npu_dev->npu->chip_id, npu_dev->pl_xscom_base + addr, &val);
	else
		val = in_be16((void *) npu_dev->pl_base + PL_MMIO_ADDR(addr));

	return val & 0xffff;
}

/* The DL registers can be accessed indirectly via the NTL */
static void dl_write(struct npu_dev *npu_dev, uint32_t addr, uint32_t val)
{
	xscom_write(npu_dev->npu->chip_id,
		    npu_dev->xscom + NX_DL_REG_ADDR, addr);
	xscom_write(npu_dev->npu->chip_id,
		    npu_dev->xscom + NX_DL_REG_DATA, val);
}

static uint64_t __unused dl_read(struct npu_dev *npu_dev, uint32_t addr)
{
	uint64_t val;

	xscom_write(npu_dev->npu->chip_id,
		    npu_dev->xscom + NX_DL_REG_ADDR, addr);
	xscom_read(npu_dev->npu->chip_id,
		   npu_dev->xscom + NX_DL_REG_DATA, &val);
	return val;
}

/* Our hardware bits are backwards here. The lane vectors are 16-bit
 * values represented in IBM bit ordering. This means lane 0 is
 * represented by bit 15 in most of the registers. Internally we keep
 * this sane (ie. npu_dev->lane_mask[0] == lane 0) as we need sane
 * numbering for set_lane_reg() anyway.  */
static uint32_t phy_lane_mask(struct npu_dev *npu_dev)
{
	/* We only train 8 lanes at a time so we don't do a full
	 * bit-swap */
	assert(npu_dev->lane_mask == 0xff00 || npu_dev->lane_mask == 0xff);

	return ~npu_dev->lane_mask & 0xffff;
}

static void set_lane_reg(struct npu_dev *npu_dev, uint64_t base_reg,
			 uint64_t data, uint64_t mask)
{
	uint64_t val, i;
	uint32_t lane_mask = npu_dev->lane_mask;

	for (i = 0; i <= 23; i++) {
		if (lane_mask & (1ul << i)) {
			uint64_t tx_rxcal_reg = base_reg + (i << 32);
			val = phy_read(npu_dev, tx_rxcal_reg);
			val = (val & ~mask) | data;
			phy_write(npu_dev, tx_rxcal_reg, val);
		}
	}
}

static uint32_t stop(struct npu_dev *npu_dev __unused)
{
	return PROCEDURE_COMPLETE | PROCEDURE_ABORTED;
}
DEFINE_PROCEDURE(stop);

static uint32_t nop(struct npu_dev *npu_dev __unused)
{
	return PROCEDURE_COMPLETE;
}
DEFINE_PROCEDURE(nop);

/* Procedure 1.2.1 (RESET_NPU_DL) from opt_programmerguide.odt. Also
 * incorporates AT reset. */
static uint32_t reset_npu_dl(struct npu_dev *npu_dev)
{
	uint64_t val;

	/* Assert NPU reset */
	xscom_read(npu_dev->npu->chip_id, npu_dev->xscom + NX_NTL_CONTROL, &val);
	val |= NTL_CONTROL_RESET;
	xscom_write(npu_dev->npu->chip_id, npu_dev->xscom + NX_NTL_CONTROL, val);

	/* Put the Nvidia logic in reset */
	dl_write(npu_dev, NDL_CONTROL, 0xe8000000);

	/* Release Nvidia logic from reset */
	dl_write(npu_dev, NDL_CONTROL, 0);

	/* Release NPU from reset */
	val &= ~NTL_CONTROL_RESET;
	xscom_write(npu_dev->npu->chip_id, npu_dev->xscom + NX_NTL_CONTROL, val);

	/* Setup up TL credits */
	xscom_write(npu_dev->npu->chip_id, npu_dev->xscom + NX_TL_CMD_CR, PPC_BIT(0));
	xscom_write(npu_dev->npu->chip_id, npu_dev->xscom + NX_TL_CMD_D_CR, PPC_BIT(0));
	xscom_write(npu_dev->npu->chip_id, npu_dev->xscom + NX_TL_RSP_CR, PPC_BIT(15));
	xscom_write(npu_dev->npu->chip_id, npu_dev->xscom + NX_TL_RSP_D_CR, PPC_BIT(15));

	/* Reset error registers.  TODO: are there more we should clear here? */
	npu_ioda_sel(npu_dev->npu, NPU_IODA_TBL_PESTB, 0, true);
	for (val = 0; val < NPU_NUM_OF_PES; val++)
		out_be64(npu_dev->npu->at_regs + NPU_IODA_DATA0, 0);

	return PROCEDURE_COMPLETE;
}
DEFINE_PROCEDURE(reset_npu_dl);

/* Procedures 1.2.3 (reset_lanes) & 1.2.4
 * (io_register_write_reset_values) */
static uint32_t phy_reset(struct npu_dev *npu_dev)
{
	uint16_t val;

	/* Lower run_lane inputs for lanes to be reset */
	val = phy_read(npu_dev, RX_RUN_LANE_VEC_0_15);
	val &= ~phy_lane_mask(npu_dev);
	phy_write(npu_dev, RX_RUN_LANE_VEC_0_15, val);

	return PROCEDURE_NEXT;
}

static uint32_t phy_reset_wait(struct npu_dev *npu_dev)
{
	uint16_t val;

	/* Wait for lane busy outputs to go to zero for lanes to be
	 * reset */
	val = phy_read(npu_dev, RX_LANE_BUSY_VEC_0_15);
	if (val & phy_lane_mask(npu_dev))
		return PROCEDURE_INPROGRESS;

	return PROCEDURE_NEXT;
}

static uint32_t phy_reset_complete(struct npu_dev *npu_dev)
{
	uint16_t val;
	uint32_t lane_mask = phy_lane_mask(npu_dev);

	/* Set ioreset_vec for the desired lanes bit positions */
	val = phy_read(npu_dev, RX_IORESET_VEC_0_15);
	phy_write(npu_dev, RX_IORESET_VEC_0_15, val | lane_mask);

	val = phy_read(npu_dev, TX_IORESET_VEC_0_15);
	phy_write(npu_dev, TX_IORESET_VEC_0_15, val | lane_mask);

	/* Clear ioreset_vec */
	val = phy_read(npu_dev, RX_IORESET_VEC_0_15);
	phy_write(npu_dev, RX_IORESET_VEC_0_15, val & ~lane_mask);

	val = phy_read(npu_dev, TX_IORESET_VEC_0_15);
	phy_write(npu_dev, TX_IORESET_VEC_0_15, val & ~lane_mask);

	/* Reset RX phase rotators */
	set_lane_reg(npu_dev, RX_PR_CNTL_PL, RX_PR_RESET, RX_PR_RESET);
	set_lane_reg(npu_dev, RX_PR_CNTL_PL, 0, RX_PR_RESET);

	/* Restore registers from scominit that may have changed */
	set_lane_reg(npu_dev, RX_PR_MODE, 0x8, RX_PR_PHASE_STEP);
	set_lane_reg(npu_dev, RX_A_DAC_CNTL,
		     0x7 << MASK_TO_LSH(RX_PR_IQ_RES_SEL),
		     RX_PR_IQ_RES_SEL);
	set_lane_reg(npu_dev, TX_MODE1_PL, 0, TX_LANE_PDWN);
	set_lane_reg(npu_dev, RX_BANK_CONTROLS, 0, RX_LANE_ANA_PDWN);
	set_lane_reg(npu_dev, RX_MODE, 0, RX_LANE_DIG_PDWN);

	return PROCEDURE_COMPLETE;
}
DEFINE_PROCEDURE(phy_reset, phy_reset_wait, phy_reset_complete);

/* Round a fixed decimal number. Frac is the number of fractional
 * bits */
static uint32_t round(uint32_t val, int frac)
{
	if (val >> (frac - 1) & 0x1)
		return (val >> frac) + 1;
	else
		return val >> frac;
}

#define ZCAL_MIN	(10 << 3)
#define ZCAL_MAX	(40 << 3)
#define ZCAL_K0		0x0
#define ZCAL_M 		128
/* TODO: add a test case for the following values:

   Initial values:
     zcal_n = 0xda;
     zcal_p = 0xc7;

   Results:
   	pre_p = 0x0
	pre_n = 0x0
	margin_p = 0x0
	margin_n = 0x0
	total_en_p = 0x32
	total_en_n = 0x37
 */

static uint32_t phy_tx_zcal(struct npu_dev *npu_dev)
{
	uint64_t val;

	if (npu_dev->index < 2 && npu_dev->npu->tx_zcal_complete[0])
		return PROCEDURE_COMPLETE;

	if (npu_dev->index >= 2 && npu_dev->npu->tx_zcal_complete[1])
		return PROCEDURE_COMPLETE;

	/* Start calibration */
	val = phy_read(npu_dev, TX_IMPCAL_SWO1_PB);
	val &= TX_ZCAL_SWO_EN;
	phy_write(npu_dev, TX_IMPCAL_SWO1_PB, val);
	phy_write(npu_dev, TX_IMPCAL_SWO2_PB, 0x50 << 2);
	val = phy_read(npu_dev, TX_IMPCAL_PB);
	val |= TX_ZCAL_REQ;
	phy_write(npu_dev, TX_IMPCAL_PB, val);

	return PROCEDURE_NEXT;
}

static uint32_t phy_tx_zcal_wait(struct npu_dev *npu_dev)
{
	uint64_t val;

	val = phy_read(npu_dev, TX_IMPCAL_PB);
	if (!(val & TX_ZCAL_DONE))
		return PROCEDURE_INPROGRESS;

	if (val & TX_ZCAL_ERROR)
		return PROCEDURE_COMPLETE | PROCEDURE_FAILED;

	return PROCEDURE_NEXT;
}

static uint32_t phy_tx_zcal_calculate(struct npu_dev *npu_dev)
{
	uint64_t val;
	uint64_t zcal_n;
	uint64_t zcal_p;
	uint64_t margin_n;
	uint64_t margin_p;
	uint64_t pre_n;
	uint64_t pre_p;
	uint64_t total_en_n;
	uint64_t total_en_p;

	val = phy_read(npu_dev, TX_IMPCAL_NVAL_PB);
	zcal_n = GETFIELD(TX_ZCAL_N, val);
	val = phy_read(npu_dev, TX_IMPCAL_PVAL_PB);
	zcal_p = GETFIELD(TX_ZCAL_P, val);

	if ((zcal_n < ZCAL_MIN) || (zcal_n > ZCAL_MAX) ||
	    (zcal_p < ZCAL_MIN) || (zcal_p > ZCAL_MAX))
		return PROCEDURE_COMPLETE | PROCEDURE_FAILED;

	margin_n = (0x80 - ZCAL_M) * zcal_n / 2;
	margin_p = (0x80 - ZCAL_M) * zcal_p / 2;
	pre_n = (((0x80 * zcal_n) - (2 * margin_n)) * ZCAL_K0) / 0x80;
	pre_p = (((0x80 * zcal_p) - (2 * margin_p)) * ZCAL_K0) / 0x80;

	total_en_n = 0x80 * zcal_n - (2 * margin_n) - (pre_n & 1023);
	total_en_p = 0x80 * zcal_p - (2 * margin_p) - (pre_p & 1023);

	pre_p = round(pre_p, 9);
	pre_n = round(pre_n, 9);
	margin_p = round(margin_p, 9);
	margin_n = round(margin_n, 9);
	total_en_p = round(total_en_p, 9);
	total_en_n = round(total_en_n, 9);

	val = SETFIELD(TX_FFE_TOTAL_ENABLE_N_ENC, 0, total_en_n);
	val = SETFIELD(TX_FFE_TOTAL_ENABLE_P_ENC, val, total_en_p);
	phy_write(npu_dev, TX_FFE_TOTAL_2RSTEP_EN, val);

	val = SETFIELD(TX_FFE_PRE_N_SEL_ENC, 0, pre_n);
	val = SETFIELD(TX_FFE_PRE_P_SEL_ENC, val, pre_p);
	phy_write(npu_dev, TX_FFE_PRE_2RSTEP_SEL, val);

	val = SETFIELD(TX_FFE_MARGIN_PD_N_SEL_ENC, 0, margin_n);
	val = SETFIELD(TX_FFE_MARGIN_PU_P_SEL_ENC, val, margin_p);
	phy_write(npu_dev, TX_FFE_MARGIN_2RSTEP_SEL, val);

	if (npu_dev->index < 2)
		npu_dev->npu->tx_zcal_complete[0] = true;
	else
		npu_dev->npu->tx_zcal_complete[1] = true;

	return PROCEDURE_COMPLETE;
}
DEFINE_PROCEDURE(phy_tx_zcal, phy_tx_zcal_wait, phy_tx_zcal_calculate);

static uint32_t phy_enable_tx_rxcal(struct npu_dev *npu_dev)
{
	/* Turn common mode on */
	set_lane_reg(npu_dev, TX_MODE2_PL, TX_RXCAL, TX_RXCAL);

	return PROCEDURE_COMPLETE;
}
DEFINE_PROCEDURE(phy_enable_tx_rxcal);

static uint32_t phy_disable_tx_rxcal(struct npu_dev *npu_dev)
{
	/* Turn common mode off */
	set_lane_reg(npu_dev, TX_MODE2_PL, 0, TX_RXCAL);

	return PROCEDURE_COMPLETE;
}
DEFINE_PROCEDURE(phy_disable_tx_rxcal);

static uint32_t phy_rx_dccal(struct npu_dev *npu_dev)
{
	if (phy_read(npu_dev, RX_LANE_BUSY_VEC_0_15)
	    & ~phy_read(npu_dev, RX_INIT_DONE_VEC_0_15))
		return PROCEDURE_INPROGRESS;

	return PROCEDURE_NEXT;
}

static uint32_t phy_rx_dccal_start(struct npu_dev *npu_dev)
{
	uint64_t val;

	/* Save EO step control */
	val = phy_read(npu_dev, RX_EO_STEP_CNTL_PG);
	npu_dev->procedure_data = val;

	phy_write(npu_dev, RX_EO_STEP_CNTL_PG,
		  RX_EO_ENABLE_LATCH_OFFSET_CAL
		  | RX_EO_ENABLE_CM_COARSE_CAL);

	val = phy_read(npu_dev, RX_RECAL_ABORT_VEC_0_15);
	val |= phy_lane_mask(npu_dev);
	phy_write(npu_dev, RX_RECAL_ABORT_VEC_0_15, val);

	val = phy_read(npu_dev, RX_RUN_LANE_VEC_0_15);
	val |= phy_lane_mask(npu_dev);
	phy_write(npu_dev, RX_RUN_LANE_VEC_0_15, val);

	return PROCEDURE_NEXT;
}

static uint32_t phy_rx_dccal_complete(struct npu_dev *npu_dev)
{
	/* Poll for completion on relevant lanes */
	if ((phy_read(npu_dev, RX_INIT_DONE_VEC_0_15) & phy_lane_mask(npu_dev))
	    != phy_lane_mask(npu_dev))
		return PROCEDURE_INPROGRESS;

	return PROCEDURE_NEXT;
}

static uint32_t phy_rx_dccal_fifo_init(struct npu_dev *npu_dev)
{
	uint64_t val;

	val = phy_read(npu_dev, RX_RUN_LANE_VEC_0_15);
	val &= ~phy_lane_mask(npu_dev);
	phy_write(npu_dev, RX_RUN_LANE_VEC_0_15, val);

	/* Turn off recal abort */
	val = phy_read(npu_dev, RX_RECAL_ABORT_VEC_0_15);
	val &= ~phy_lane_mask(npu_dev);
	phy_write(npu_dev, RX_RECAL_ABORT_VEC_0_15, val);

	/* Restore original settings */
	phy_write(npu_dev, RX_EO_STEP_CNTL_PG, npu_dev->procedure_data);

	/* FIFO Init */
	set_lane_reg(npu_dev, TX_MODE2_PL, 0, TX_UNLOAD_CLK_DISABLE);
	set_lane_reg(npu_dev, TX_CNTL_STAT2, TX_FIFO_INIT, TX_FIFO_INIT);
	set_lane_reg(npu_dev, TX_MODE2_PL, TX_UNLOAD_CLK_DISABLE,
		     TX_UNLOAD_CLK_DISABLE);

	return PROCEDURE_COMPLETE;
}
DEFINE_PROCEDURE(phy_rx_dccal, phy_rx_dccal_start, phy_rx_dccal_complete,
		 phy_rx_dccal_fifo_init);

static uint32_t phy_rx_training(struct npu_dev *npu_dev)
{
	uint16_t val;

	if (!npu_dev->procedure_data) {
		val = phy_read(npu_dev, RX_RUN_LANE_VEC_0_15);
		val |= phy_lane_mask(npu_dev);
		phy_write(npu_dev, RX_RUN_LANE_VEC_0_15, val);
	}

	npu_dev->procedure_data++;
	if (npu_dev->procedure_data >= 1000000)
		return PROCEDURE_COMPLETE | PROCEDURE_FAILED;

	val = phy_read(npu_dev, RX_RUN_LANE_VEC_0_15);
	if ((val & phy_lane_mask(npu_dev)) != phy_lane_mask(npu_dev))
		return PROCEDURE_INPROGRESS;

	return PROCEDURE_COMPLETE;
}
DEFINE_PROCEDURE(phy_rx_training);

static struct procedure *npu_procedures[] = {
	&procedure_stop,
	&procedure_nop,
	NULL,
	NULL,
	&procedure_phy_reset,
	&procedure_phy_tx_zcal,
	&procedure_phy_rx_dccal,
	&procedure_phy_enable_tx_rxcal,
	&procedure_phy_disable_tx_rxcal,
	&procedure_phy_rx_training,
	&procedure_reset_npu_dl,

	/* Place holders for pre-terminate and terminate procedures */
	&procedure_nop,
	&procedure_nop};

/* Run a procedure step(s) and return status */
static uint32_t get_procedure_status(struct npu_dev *dev)
{
	uint32_t result;
	uint16_t procedure = dev->procedure_number;
	uint16_t step = dev->procedure_step;
	const char *name = npu_procedures[procedure]->name;

	do {
		result = npu_procedures[procedure]->steps[step](dev);

		if (result & PROCEDURE_NEXT) {
			step++;
			NPUDEVINF(dev, "Running procedure %s step %d\n", name, step);
		}
	} while (result & PROCEDURE_NEXT);

	dev->procedure_step = step;

	if (result & PROCEDURE_COMPLETE)
		NPUDEVINF(dev, "Procedure %s complete\n", name);
	else if (mftb() > dev->procedure_tb + msecs_to_tb(100)) {
		NPUDEVINF(dev, "Procedure %s timed out\n", name);
		result = PROCEDURE_COMPLETE | PROCEDURE_FAILED;
	}

	/* Mask off internal state bits */
	dev->procedure_status = result & PROCEDURE_STATUS_MASK;

	return dev->procedure_status;
}

static int64_t npu_dev_procedure_read(struct npu_dev *dev, uint32_t offset,
				      uint32_t size, uint32_t *data)
{
	int64_t rc = OPAL_SUCCESS;

	if (size != 4) {
		/* Short config reads are not supported */
		prlog(PR_ERR, "NPU%d: Short read of procedure register\n", dev->npu->phb.opal_id);
		return OPAL_PARAMETER;
	}

	*data = 0;

	switch (offset) {
	case 0:
		/* Only run the procedure if not already complete */
		if (dev->procedure_status & PROCEDURE_COMPLETE)
			*data = dev->procedure_status;
		else
			*data = get_procedure_status(dev);

		break;

	case 4:
		*data = dev->procedure_number;
		break;

	default:
		prlog(PR_ERR, "NPU%d: Invalid vendor specific offset 0x%08x\n",
		      dev->npu->phb.opal_id, offset);
		rc = OPAL_PARAMETER;
	}

	return rc;
}

static int64_t npu_dev_procedure_write(struct npu_dev *dev, uint32_t offset,
				       uint32_t size, uint32_t data)
{
	const char *name;
	int64_t rc = OPAL_SUCCESS;

	if (size != 4) {
		/* Short config writes are not supported */
		prlog(PR_ERR, "NPU%d: Short read of procedure register\n",
		      dev->npu->phb.opal_id);
		return OPAL_PARAMETER;
	}

	switch (offset) {
	case 0:
		/* We ignore writes to the status register */
		NPUDEVINF(dev, "Ignoring writes to status register\n");
		break;

	case 4:
		if (data >= ARRAY_SIZE(npu_procedures) ||
		    !npu_procedures[data]) {
			NPUDEVINF(dev, "Unsupported procedure number %d\n", data);
			dev->procedure_status = PROCEDURE_COMPLETE
				| PROCEDURE_UNSUPPORTED;
			break;
		}

		name = npu_procedures[data]->name;
		if (dev->procedure_number == data
		    && !(dev->procedure_status & PROCEDURE_COMPLETE))
			NPUDEVINF(dev, "Restarting procuedure %s\n", name);
		else
			NPUDEVINF(dev, "Starting procedure %s\n", name);

		dev->procedure_status = PROCEDURE_INPROGRESS;
		dev->procedure_number = data;
		dev->procedure_step = 0;
		dev->procedure_data = 0;
		dev->procedure_tb = mftb();
		break;

	default:
		NPUDEVINF(dev, "Invalid vendor specific offset 0x%08x\n", offset);
		rc = OPAL_PARAMETER;
	}

	return rc;
}

int64_t npu_dev_procedure(void *dev, struct pci_cfg_reg_filter *pcrf,
			  uint32_t offset, uint32_t len, uint32_t *data,
			  bool write)
{
	struct pci_virt_device *pvd = dev;
	struct npu_dev *ndev = pvd->data;

	if (write)
		return npu_dev_procedure_write(ndev, offset - pcrf->start,
					       len, *data);

	return npu_dev_procedure_read(ndev, offset - pcrf->start, len, data);
}

void npu_dev_procedure_reset(struct npu_dev *dev)
{
	dev->procedure_status = 0;
	dev->procedure_number = 0;
	dev->procedure_step = 0;
	dev->procedure_data = 0;
}
