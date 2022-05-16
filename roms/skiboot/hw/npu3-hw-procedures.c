// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2019 IBM Corp.
 */

#include <skiboot.h>
#include <npu3.h>
#include <npu3-regs.h>
#include <timebase.h>
#include <xscom.h>
#include <xscom-p9-regs.h>

#define NPU3DEVLOG(l, dev, fmt, a...)		\
	prlog(l, "NPU[%d:%d:%d]: " fmt,		\
	      (dev)->npu->chip_id,		\
	      (dev)->npu->index,		\
	      (dev)->index, ##a)
#define NPU3DEVDBG(dev, fmt, a...) NPU3DEVLOG(PR_DEBUG, dev, fmt, ##a)
#define NPU3DEVINF(dev, fmt, a...) NPU3DEVLOG(PR_INFO, dev, fmt, ##a)
#define NPU3DEVERR(dev, fmt, a...) NPU3DEVLOG(PR_ERR, dev, fmt, ##a)

/*
 * The documentation for the PHY training is written in terms of bits within an
 * actual register so we use that representation here.
 */
struct npu3_phy_reg {
	uint64_t offset;
	uint64_t mask;
};

static struct npu3_phy_reg
NPU3_PHY_RX_RUN_LANE			= { 0x0c8, PPC_BIT(48) },
NPU3_PHY_RX_IORESET			= { 0x096, PPC_BIT(63) },
NPU3_PHY_TX_IORESET			= { 0x113, PPC_BIT(48) },
NPU3_PHY_RX_PR_RESET			= { 0x096, PPC_BIT(62) },
NPU3_PHY_RX_LANE_ANA_PDWN		= { 0x002, PPC_BIT(54) },
NPU3_PHY_RX_LANE_DIG_PDWN		= { 0x088, PPC_BIT(48) },
NPU3_PHY_RX_PR_PHASE_STEP		= { 0x08a, PPC_BITMASK(60, 63) },
NPU3_PHY_TX_LANE_PDWN			= { 0x101, PPC_BIT(48) },
NPU3_PHY_RX_RUN_DCCAL			= { 0x0c8, PPC_BIT(49) },
NPU3_PHY_RX_DCCAL_DONE			= { 0x0ca, PPC_BIT(49) },
NPU3_PHY_RX_LANE_BUSY			= { 0x0ca, PPC_BIT(50) },
NPU3_PHY_RX_B_BANK_CONTROLS		= { 0x002, PPC_BITMASK(58, 63) },
NPU3_PHY_TX_UNLOAD_CLK_DISABLE		= { 0x103, PPC_BIT(56) },
NPU3_PHY_TX_FIFO_INIT			= { 0x105, PPC_BIT(53) },
NPU3_PHY_TX_RXCAL			= { 0x103, PPC_BIT(57) },
NPU3_PHY_RX_INIT_DONE			= { 0x0ca, PPC_BIT(48) },
NPU3_PHY_RX_PR_EDGE_TRACK_CNTL		= { 0x092, PPC_BITMASK(48, 49) },
NPU3_PHY_RX_PR_FW_OFF			= { 0x08a, PPC_BIT(56) },
NPU3_PHY_RX_PR_FW_INERTIA_AMT		= { 0x08a, PPC_BITMASK(57, 59) },
NPU3_PHY_RX_CFG_LTE_MC			= { 0x000, PPC_BITMASK(60, 63) },
NPU3_PHY_RX_A_INTEG_COARSE_GAIN		= { 0x00a, PPC_BITMASK(48, 51) },
NPU3_PHY_RX_B_INTEG_COARSE_GAIN		= { 0x026, PPC_BITMASK(48, 51) },
NPU3_PHY_RX_E_INTEG_COARSE_GAIN		= { 0x030, PPC_BITMASK(48, 51) },

/* These registers are per-PHY, not per lane */
NPU3_PHY_TX_ZCAL_SWO_EN			= { 0x3c9, PPC_BIT(48) },
NPU3_PHY_TX_ZCAL_REQ			= { 0x3c1, PPC_BIT(49) },
NPU3_PHY_TX_ZCAL_DONE			= { 0x3c1, PPC_BIT(50) },
NPU3_PHY_TX_ZCAL_ERROR			= { 0x3c1, PPC_BIT(51) },
NPU3_PHY_TX_ZCAL_N			= { 0x3c3, PPC_BITMASK(48, 56) },
NPU3_PHY_TX_ZCAL_P			= { 0x3c5, PPC_BITMASK(48, 56) },
NPU3_PHY_TX_PSEG_PRE_EN			= { 0x34d, PPC_BITMASK(51, 55) },
NPU3_PHY_TX_PSEG_PRE_SELECT		= { 0x34d, PPC_BITMASK(56, 60) },
NPU3_PHY_TX_NSEG_PRE_EN			= { 0x34f, PPC_BITMASK(51, 55) },
NPU3_PHY_TX_NSEG_PRE_SELECT		= { 0x34f, PPC_BITMASK(56, 60) },
NPU3_PHY_TX_PSEG_POST_EN		= { 0x361, PPC_BITMASK(49, 55) },
NPU3_PHY_TX_PSEG_POST_SELECT		= { 0x361, PPC_BITMASK(56, 62) },
NPU3_PHY_TX_NSEG_POST_EN		= { 0x363, PPC_BITMASK(49, 55) },
NPU3_PHY_TX_NSEG_POST_SELECT		= { 0x363, PPC_BITMASK(56, 62) },
NPU3_PHY_TX_PSEG_MARGINPU_EN		= { 0x351, PPC_BITMASK(48, 55) },
NPU3_PHY_TX_NSEG_MARGINPU_EN		= { 0x353, PPC_BITMASK(48, 55) },
NPU3_PHY_TX_PSEG_MARGINPD_EN		= { 0x351, PPC_BITMASK(56, 63) },
NPU3_PHY_TX_NSEG_MARGINPD_EN		= { 0x353, PPC_BITMASK(56, 63) },
NPU3_PHY_TX_MARGINPU_SELECT		= { 0x355, PPC_BITMASK(48, 55) },
NPU3_PHY_TX_MARGINPD_SELECT		= { 0x355, PPC_BITMASK(56, 63) },
NPU3_PHY_TX_PSEG_MAIN_EN		= { 0x357, PPC_BITMASK(51, 57) },
NPU3_PHY_TX_NSEG_MAIN_EN		= { 0x359, PPC_BITMASK(51, 57) },
NPU3_PHY_RX_CLKDIST_PDWN		= { 0x204, PPC_BITMASK(48, 50) },
NPU3_PHY_RX_IREF_PDWN			= { 0x230, PPC_BIT(54) },
NPU3_PHY_TX_CLKDIST_PDWN		= { 0x305, PPC_BITMASK(48, 50) },
NPU3_PHY_RX_CTL_DATASM_CLKDIST_PDWN	= { 0x2e0, PPC_BIT(60) };

static uint64_t npu3_phy_scom(struct npu3_dev *dev, struct npu3_phy_reg *reg,
			      int lane)
{
	uint64_t scom;

	/* Don't specify a lane for a non-per-lane register */
	if (lane >= 0)
		assert(reg->offset < 0x200);
	else
		assert(reg->offset >= 0x200);

	scom = OB_INDIRECT(dev->ob_chiplet);
	scom = SETFIELD(PPC_BITMASK(12, 21), scom, reg->offset);

	if (lane > 0)
		scom = SETFIELD(PPC_BITMASK(27, 31), scom, lane);

	return scom;
}

static void npu3_phy_write_lane(struct npu3_dev *dev, struct npu3_phy_reg *reg,
				int lane, uint64_t val)
{
	struct npu3 *npu = dev->npu;
	uint64_t scom, scom_val;

	scom = npu3_phy_scom(dev, reg, lane);

	xscom_read(npu->chip_id, scom, &scom_val);
	scom_val = SETFIELD(reg->mask, scom_val, val);
	xscom_write(npu->chip_id, scom, scom_val);
}

static uint64_t npu3_phy_read_lane(struct npu3_dev *dev,
				   struct npu3_phy_reg *reg,
				   int lane)
{
	struct npu3 *npu = dev->npu;
	uint64_t scom, scom_val;

	scom = npu3_phy_scom(dev, reg, lane);
	xscom_read(npu->chip_id, scom, &scom_val);

	return GETFIELD(reg->mask, scom_val);
}

static inline void npu3_phy_write(struct npu3_dev *dev,
				  struct npu3_phy_reg *reg,
				  uint64_t val)
{
	npu3_phy_write_lane(dev, reg, -1, val);
}

static inline uint64_t npu3_phy_read(struct npu3_dev *dev,
				     struct npu3_phy_reg *reg)
{
	return npu3_phy_read_lane(dev, reg, -1);
}

struct procedure {
	const char *name;
	uint32_t (*steps[])(struct npu3_dev *);
};

#define DEFINE_PROCEDURE(NAME, STEPS...)	\
static struct procedure procedure_##NAME = {	\
	.name = #NAME,				\
	.steps = { NAME, ##STEPS }		\
}

static uint32_t stop(struct npu3_dev *npu_dev __unused)
{
	return NPU3_PROC_COMPLETE | NPU3_PROC_ABORTED;
}

DEFINE_PROCEDURE(stop);

static uint32_t nop(struct npu3_dev *npu_dev __unused)
{
	return NPU3_PROC_COMPLETE;
}

DEFINE_PROCEDURE(nop);

static void set_iovalid(struct npu3_dev *dev, bool raise)
{
	struct npu3 *npu = dev->npu;
	uint64_t reg, val;

	reg = OB_CPLT_CONF1(dev->ob_chiplet);

	xscom_read(npu->chip_id, reg, &val);
	val = SETFIELD(OB_CPLT_CONF1_NV_IOVALID(dev->index), val, raise);
	xscom_write(npu->chip_id, reg, val);
}

#define NPU3_PHY_LANES 24

#define npu3_for_each_lane(lane, dev)				\
	for (lane = 0; lane < NPU3_PHY_LANES; lane++)		\
		if (dev->phy_lane_mask & PPC_BIT32(lane))	\

static uint32_t phy_reset(struct npu3_dev *dev)
{
	uint32_t lane;

	set_iovalid(dev, false);

	npu3_for_each_lane(lane, dev)
		npu3_phy_write_lane(dev, &NPU3_PHY_RX_RUN_LANE, lane, 0);

	return NPU3_PROC_NEXT;
}

static uint32_t phy_reset_wait(struct npu3_dev *dev)
{
	int lane;

	/* Wait for all lanes to become inactive */
	npu3_for_each_lane(lane, dev)
		if (npu3_phy_read_lane(dev, &NPU3_PHY_RX_LANE_BUSY, lane))
			return NPU3_PROC_INPROGRESS;

	npu3_for_each_lane(lane, dev) {
		/* Set lane in reset */
		npu3_phy_write_lane(dev, &NPU3_PHY_RX_IORESET, lane, 1);
		npu3_phy_write_lane(dev, &NPU3_PHY_TX_IORESET, lane, 1);

		/* Release lane from reset */
		npu3_phy_write_lane(dev, &NPU3_PHY_RX_IORESET, lane, 0);
		npu3_phy_write_lane(dev, &NPU3_PHY_TX_IORESET, lane, 0);

		/* Reset the phase rotator */
		npu3_phy_write_lane(dev, &NPU3_PHY_RX_PR_RESET, lane, 1);
		npu3_phy_write_lane(dev, &NPU3_PHY_RX_PR_RESET, lane, 0);
	}

	return NPU3_PROC_NEXT;
}

/* Procedure 1.2.3 - Initialise I/O PHY Registers */
static uint32_t phy_reset_complete(struct npu3_dev *dev)
{
	int lane;

	npu3_for_each_lane(lane, dev) {
		npu3_phy_write_lane(dev, &NPU3_PHY_RX_LANE_ANA_PDWN, lane, 0);
		npu3_phy_write_lane(dev, &NPU3_PHY_RX_LANE_DIG_PDWN, lane, 0);
		npu3_phy_write_lane(dev, &NPU3_PHY_RX_PR_PHASE_STEP, lane, 0xc);
		npu3_phy_write_lane(dev, &NPU3_PHY_TX_LANE_PDWN, lane, 0);
		npu3_phy_write_lane(dev, &NPU3_PHY_RX_PR_FW_INERTIA_AMT, lane, 4);
		npu3_phy_write_lane(dev, &NPU3_PHY_RX_CFG_LTE_MC, lane, 3);
		npu3_phy_write_lane(dev, &NPU3_PHY_RX_A_INTEG_COARSE_GAIN, lane, 11);
		npu3_phy_write_lane(dev, &NPU3_PHY_RX_B_INTEG_COARSE_GAIN, lane, 11);
		npu3_phy_write_lane(dev, &NPU3_PHY_RX_E_INTEG_COARSE_GAIN, lane, 11);
	}

	set_iovalid(dev, true);

	return NPU3_PROC_COMPLETE;
}

DEFINE_PROCEDURE(phy_reset, phy_reset_wait, phy_reset_complete);

/* Procedure 1.2.6 - I/O PHY Tx Impedance Calibration */
static uint32_t phy_tx_zcal(struct npu3_dev *dev)
{
	if (dev->npu->tx_zcal_complete)
		return NPU3_PROC_COMPLETE;

	/* Turn off SW enable and enable zcal state machine */
	npu3_phy_write(dev, &NPU3_PHY_TX_ZCAL_SWO_EN, 0);

	/* Start impedance calibration state machine */
	npu3_phy_write(dev, &NPU3_PHY_TX_ZCAL_REQ, 1);

	return NPU3_PROC_NEXT;
}

static uint32_t phy_tx_zcal_wait(struct npu3_dev *dev)
{
	if (npu3_phy_read(dev, &NPU3_PHY_TX_ZCAL_ERROR))
		return NPU3_PROC_COMPLETE | NPU3_PROC_FAILED;

	if (!npu3_phy_read(dev, &NPU3_PHY_TX_ZCAL_DONE))
		return NPU3_PROC_INPROGRESS;

	return NPU3_PROC_NEXT;
}

#define MARGIN_RATIO		0
#define FFE_PRE_COEFF		0
#define FFE_POST_COEFF		0

#define PRE_WIDTH		5
#define POST_WIDTH		7
#define MAIN_WIDTH		7
#define ZCAL_MIN		(16 * 2)
#define ZCAL_MAX		(33 * 2)
#define PRECURSOR_X2_MAX	(4 * 2 + 1)
#define POSTCURSOR_X2_MAX	(6 * 2 + 1)
#define MARGIN_X2_MAX		(8 * 2)
#define MAIN_X2_MAX		(6 * 2 + 1)
#define TOTAL_X2_MAX		(PRECURSOR_X2_MAX + POSTCURSOR_X2_MAX + \
				 2 * MARGIN_X2_MAX + MAIN_X2_MAX)

static uint32_t therm(uint32_t dec)
{
	return (0x1 << dec) - 1;
}

static uint32_t therm_with_half(uint32_t dec, uint8_t width)
{
	/* If the LSB of the 2r equivalent is on, then we need to set the 2r bit (MSB) */
	uint32_t half_on = (dec & 0x1) << (width - 1);

	/* Shift the 2r equivalent to a 1r value and convert to a thermometer code. */
	uint32_t x1_equiv = ((1 << (dec >> 1)) - 1);

	/* Combine 1r equivalent thermometer code + the 2r MSB value. */
	return half_on | x1_equiv;
}

static uint32_t phy_tx_zcal_calculate(struct npu3_dev *dev)
{
	int p_value, n_value;
	uint32_t zcal_n;
	uint32_t zcal_p;
	uint32_t p_main_enable = MAIN_X2_MAX;
	uint32_t p_margin_pu_enable = MARGIN_X2_MAX;
	uint32_t p_margin_pd_enable = MARGIN_X2_MAX;
	uint32_t p_precursor_select;
	uint32_t p_postcursor_select;
	uint32_t margin_pu_select;
	uint32_t n_main_enable = MAIN_X2_MAX;
	uint32_t n_margin_pu_enable = MARGIN_X2_MAX;
	uint32_t n_margin_pd_enable = MARGIN_X2_MAX;
	uint32_t n_precursor_select;
	uint32_t n_postcursor_select;
	uint32_t margin_pd_select;
	uint32_t margin_select;

	/* Convert the value from 8R to 2R by / 4 */
	zcal_n = npu3_phy_read(dev, &NPU3_PHY_TX_ZCAL_N) / 4;
	zcal_p = npu3_phy_read(dev, &NPU3_PHY_TX_ZCAL_P) / 4;

	/*
	 * Again, if the hardware detects an unexpected condition it's
	 * better just to fail loudly.
	 */
	if (zcal_n < ZCAL_MIN || zcal_n > ZCAL_MAX ||
	    zcal_p < ZCAL_MIN || zcal_p > ZCAL_MAX)
		return NPU3_PROC_COMPLETE | NPU3_PROC_FAILED;

	p_value = zcal_p - TOTAL_X2_MAX;
	p_precursor_select = p_value * FFE_PRE_COEFF / 128;
	p_postcursor_select = p_value * FFE_POST_COEFF / 128;
	margin_pu_select = p_value * MARGIN_RATIO / 256;

	if (p_value % 2) {
		p_main_enable--;
		p_value++;
	}

	while (p_value < 0) {
		if (p_main_enable > 1) {
			p_main_enable -= 2;
		} else if (p_margin_pu_enable + p_margin_pd_enable > 0) {
			if (p_margin_pu_enable == p_margin_pd_enable)
				p_margin_pd_enable -= 2;
			else
				p_margin_pu_enable -= 2;
		}
		p_value += 2;
	}

	n_value = zcal_n - TOTAL_X2_MAX;
	n_precursor_select = n_value * FFE_PRE_COEFF / 128;
	n_postcursor_select = n_value * FFE_POST_COEFF / 128;
	margin_pd_select = p_value * MARGIN_RATIO / 256;

	if (n_value % 2) {
		n_main_enable--;
		n_value++;
	}

	while (n_value < 0) {
		if (n_main_enable > 1) {
			n_main_enable -= 2;
		} else if (n_margin_pu_enable + n_margin_pd_enable > 0) {
			if (n_margin_pu_enable == n_margin_pd_enable)
				n_margin_pd_enable -= 2;
			else
				n_margin_pu_enable -= 2;
		}
		n_value += 2;
	}

	margin_select = therm((margin_pu_select + 1) / 2) &
			therm((margin_pd_select + 1) / 2) &
			therm((p_margin_pu_enable + 1) / 2) &
			therm((p_margin_pd_enable + 1) / 2) &
			therm((n_margin_pu_enable + 1) / 2) &
			therm((n_margin_pd_enable + 1) / 2);

	npu3_phy_write(dev, &NPU3_PHY_TX_PSEG_PRE_EN,      therm_with_half(PRECURSOR_X2_MAX, PRE_WIDTH));
	npu3_phy_write(dev, &NPU3_PHY_TX_PSEG_PRE_SELECT,  therm_with_half(p_precursor_select, PRE_WIDTH));
	npu3_phy_write(dev, &NPU3_PHY_TX_PSEG_POST_EN,     therm_with_half(POSTCURSOR_X2_MAX, POST_WIDTH));
	npu3_phy_write(dev, &NPU3_PHY_TX_PSEG_POST_SELECT, therm_with_half(p_postcursor_select, POST_WIDTH));
	npu3_phy_write(dev, &NPU3_PHY_TX_PSEG_MARGINPU_EN, therm((p_margin_pu_enable + 1) / 2));
	npu3_phy_write(dev, &NPU3_PHY_TX_PSEG_MARGINPD_EN, therm((p_margin_pd_enable + 1) / 2));
	npu3_phy_write(dev, &NPU3_PHY_TX_PSEG_MAIN_EN,     therm_with_half(p_main_enable, MAIN_WIDTH));

	npu3_phy_write(dev, &NPU3_PHY_TX_NSEG_PRE_EN,      therm_with_half(PRECURSOR_X2_MAX, PRE_WIDTH));
	npu3_phy_write(dev, &NPU3_PHY_TX_NSEG_PRE_SELECT,  therm_with_half(n_precursor_select, PRE_WIDTH));
	npu3_phy_write(dev, &NPU3_PHY_TX_NSEG_POST_EN,     therm_with_half(POSTCURSOR_X2_MAX, POST_WIDTH));
	npu3_phy_write(dev, &NPU3_PHY_TX_NSEG_POST_SELECT, therm_with_half(n_postcursor_select, POST_WIDTH));
	npu3_phy_write(dev, &NPU3_PHY_TX_NSEG_MARGINPU_EN, therm((n_margin_pu_enable + 1) / 2));
	npu3_phy_write(dev, &NPU3_PHY_TX_NSEG_MARGINPD_EN, therm((n_margin_pd_enable + 1) / 2));
	npu3_phy_write(dev, &NPU3_PHY_TX_NSEG_MAIN_EN,     therm_with_half(n_main_enable, MAIN_WIDTH));

	npu3_phy_write(dev, &NPU3_PHY_TX_MARGINPU_SELECT,  therm(margin_select + 1) / 2);
	npu3_phy_write(dev, &NPU3_PHY_TX_MARGINPD_SELECT,  therm(margin_select + 1) / 2);

	dev->npu->tx_zcal_complete = true;

	return NPU3_PROC_COMPLETE;
}

DEFINE_PROCEDURE(phy_tx_zcal, phy_tx_zcal_wait, phy_tx_zcal_calculate);

/* Procedure 1.2.4 - I/O PHY DC Calibration */
static uint32_t phy_rx_dccal(struct npu3_dev *dev)
{
	int lane;

	set_iovalid(dev, false);

	npu3_for_each_lane(lane, dev)
		npu3_phy_write_lane(dev, &NPU3_PHY_RX_PR_FW_OFF, lane, 1);

	npu3_for_each_lane(lane, dev)
		npu3_phy_write_lane(dev, &NPU3_PHY_RX_RUN_DCCAL, lane, 1);

	return NPU3_PROC_NEXT;
}

static uint32_t phy_rx_dccal_complete(struct npu3_dev *dev)
{
	int lane;

	npu3_for_each_lane(lane, dev)
		if (!npu3_phy_read_lane(dev, &NPU3_PHY_RX_DCCAL_DONE, lane))
			return NPU3_PROC_INPROGRESS;

	npu3_for_each_lane(lane, dev)
		npu3_phy_write_lane(dev, &NPU3_PHY_RX_RUN_DCCAL, lane, 0);

	npu3_for_each_lane(lane, dev) {
		npu3_phy_write_lane(dev, &NPU3_PHY_RX_B_BANK_CONTROLS, lane, 0);
		npu3_phy_write_lane(dev, &NPU3_PHY_RX_PR_EDGE_TRACK_CNTL, lane, 0);
		npu3_phy_write_lane(dev, &NPU3_PHY_RX_PR_FW_OFF, lane, 0);
	}

	return NPU3_PROC_NEXT;
}

/* Procedure 1.2.5 - IO PHY Tx FIFO Init */
static uint32_t phy_tx_fifo_init(struct npu3_dev *dev)
{
	int lane;

	npu3_for_each_lane(lane, dev) {
		npu3_phy_write_lane(dev, &NPU3_PHY_TX_UNLOAD_CLK_DISABLE, lane, 0);
		npu3_phy_write_lane(dev, &NPU3_PHY_TX_FIFO_INIT, lane, 1);
		npu3_phy_write_lane(dev, &NPU3_PHY_TX_UNLOAD_CLK_DISABLE, lane, 1);
	}

	set_iovalid(dev, true);

	return NPU3_PROC_COMPLETE;
}

DEFINE_PROCEDURE(phy_rx_dccal, phy_rx_dccal_complete, phy_tx_fifo_init);

/* Procedure 1.2.8 - Enable Downstream Link Training */
static uint32_t phy_enable_tx_rxcal(struct npu3_dev *dev)
{
	int lane;

	npu3_for_each_lane(lane, dev)
		npu3_phy_write_lane(dev, &NPU3_PHY_TX_RXCAL, lane, 1);

	return NPU3_PROC_COMPLETE;
}
DEFINE_PROCEDURE(phy_enable_tx_rxcal);

/* Procedure 1.2.9 - Disable Downstream Link Training */
static uint32_t phy_disable_tx_rxcal(struct npu3_dev *dev)
{
	int lane;

	npu3_for_each_lane(lane, dev)
		npu3_phy_write_lane(dev, &NPU3_PHY_TX_RXCAL, lane, 0);

	return NPU3_PROC_COMPLETE;
}
DEFINE_PROCEDURE(phy_disable_tx_rxcal);

/* Procedure 1.2.7 - I/O PHY Upstream Link Training */
static uint32_t phy_rx_training(struct npu3_dev *dev)
{
	int lane;

	npu3_for_each_lane(lane, dev)
		npu3_phy_write_lane(dev, &NPU3_PHY_RX_RUN_LANE, lane, 1);

	return NPU3_PROC_NEXT;
}

static uint32_t phy_rx_training_wait(struct npu3_dev *dev)
{
	int lane;

	npu3_for_each_lane(lane, dev)
		if (!npu3_phy_read_lane(dev, &NPU3_PHY_RX_INIT_DONE, lane))
			return NPU3_PROC_INPROGRESS;

	return NPU3_PROC_COMPLETE;
}

DEFINE_PROCEDURE(phy_rx_training, phy_rx_training_wait);

static void npu3_dev_fence_set(struct npu3_dev *dev, uint8_t state)
{
	struct npu3 *npu = dev->npu;
	uint64_t val;

	val = npu3_read(npu, NPU3_NTL_MISC_CFG1(dev->index));
	val = SETFIELD(NPU3_NTL_MISC_CFG1_NTL_RESET, val, state);
	npu3_write(npu, NPU3_NTL_MISC_CFG1(dev->index), val);
}

static uint8_t npu3_dev_fence_get(struct npu3_dev *dev)
{
	uint64_t val;

	val = npu3_read(dev->npu, NPU3_NTL_CQ_FENCE_STATUS(dev->index));
	return GETFIELD(NPU3_NTL_CQ_FENCE_STATUS_FIELD, val);
}

/* Procedure 1.2.1 - Reset NPU/NDL */
static uint32_t reset_ntl(struct npu3_dev *dev)
{
	struct npu3 *npu = dev->npu;
	uint64_t val;
	int lane;

	set_iovalid(dev, true);

	/* Power on clocks */
	npu3_phy_write(dev, &NPU3_PHY_RX_CLKDIST_PDWN, 0);
	npu3_phy_write(dev, &NPU3_PHY_RX_IREF_PDWN, 1);
	npu3_phy_write(dev, &NPU3_PHY_TX_CLKDIST_PDWN, 0);
	npu3_phy_write(dev, &NPU3_PHY_RX_CTL_DATASM_CLKDIST_PDWN, 0);

	npu3_for_each_lane(lane, dev) {
		npu3_phy_write_lane(dev, &NPU3_PHY_RX_LANE_ANA_PDWN, lane, 0);
		npu3_phy_write_lane(dev, &NPU3_PHY_RX_LANE_DIG_PDWN, lane, 0);
		npu3_phy_write_lane(dev, &NPU3_PHY_TX_LANE_PDWN, lane, 0);
	}

	/* Write PRI */
	val = SETFIELD(NPU3_NTL_PRI_CFG_NDL, 0ull, dev->index);
	npu3_write(npu, NPU3_NTL_PRI_CFG(dev->index), val);

	/* Disable parity checking */
	val = npu3_read(npu, NPU3_NTL_MISC_CFG2(dev->index));
	val &= ~(NPU3_NTL_MISC_CFG2_NDL_RX_PARITY_ENA |
		 NPU3_NTL_MISC_CFG2_NDL_TX_PARITY_ENA |
		 NPU3_NTL_MISC_CFG2_NDL_PRI_PARITY_ENA);
	npu3_write(npu, NPU3_NTL_MISC_CFG2(dev->index), val);

	if (dev->type == NPU3_DEV_TYPE_NVLINK)
		npu3_pvd_flag_clear(dev, NPU3_DEV_DL_RESET);

	npu3_dev_fence_set(dev, NPU3_NTL_CQ_FENCE_STATUS_FULL);

	return NPU3_PROC_NEXT;
}

static uint32_t reset_ndl(struct npu3_dev *dev)
{
	struct npu3 *npu = dev->npu;
	uint64_t reg;
	uint32_t val32;

	if (npu3_dev_fence_get(dev) != NPU3_NTL_CQ_FENCE_STATUS_FULL)
		return NPU3_PROC_INPROGRESS;

	reg = NPU3_DLPL_CTL(dev->index);
	val32 = npu3_read_4b(npu, reg);
	val32 |= NPU3_DLPL_CTL_RESET_RX | NPU3_DLPL_CTL_RESET_MISC;
	npu3_write_4b(npu, reg, val32);

	val32 = npu3_read_4b(npu, reg);
	val32 &= ~(NPU3_DLPL_CTL_RESET_RX | NPU3_DLPL_CTL_RESET_MISC);
	npu3_write_4b(npu, reg, val32);

	reg = NPU3_DLPL_CFG(dev->index);
	val32 = NPU3_DLPL_CFG_PRI_BYTESWAP;
	npu3_write_4b(npu, reg, val32);

	/* Clear FIR bits */
	for (uint32_t i = 0; i < NPU3_FIR_MAX; i++)
		xscom_write(npu->chip_id, npu->xscom_base + NPU3_FIR(i), 0ull);

	npu3_dev_fence_set(dev, NPU3_NTL_CQ_FENCE_STATUS_HALF);

	return NPU3_PROC_NEXT;
}

static uint32_t reset_ntl_release(struct npu3_dev *dev)
{
	struct npu3 *npu = dev->npu;
	uint32_t i = dev->index;

	if (npu3_dev_fence_get(dev) != NPU3_NTL_CQ_FENCE_STATUS_HALF)
		return NPU3_PROC_INPROGRESS;

	/* Credit setup */
	npu3_write(npu, NPU3_NTL_CREQ_HDR_CRED_SND(i), 0x0200000000000000);
	npu3_write(npu, NPU3_NTL_PRB_HDR_CRED_SND(i),  0x0200000000000000);
	npu3_write(npu, NPU3_NTL_ATR_HDR_CRED_SND(i),  0x0200000000000000);
	npu3_write(npu, NPU3_NTL_RSP_HDR_CRED_SND(i),  0x0200000000000000);
	npu3_write(npu, NPU3_NTL_CREQ_DAT_CRED_SND(i), 0x1000000000000000);
	npu3_write(npu, NPU3_NTL_RSP_DAT_CRED_SND(i),  0x1000000000000000);

	npu3_write(npu, NPU3_NTL_CREQ_HDR_CRED_RCV(i), 0x0000be0000000000);
	npu3_write(npu, NPU3_NTL_DGD_HDR_CRED_RCV(i),  0x0000640000000000);
	npu3_write(npu, NPU3_NTL_ATSD_HDR_CRED_RCV(i), 0x0000200000000000);
	npu3_write(npu, NPU3_NTL_RSP_HDR_CRED_RCV(i),  0x0000be0000000000);
	npu3_write(npu, NPU3_NTL_CREQ_DAT_CRED_RCV(i), 0x0001000000000000);
	npu3_write(npu, NPU3_NTL_RSP_DAT_CRED_RCV(i),  0x0001000000000000);

	npu3_dev_fence_set(dev, NPU3_NTL_CQ_FENCE_STATUS_NONE);

	return NPU3_PROC_NEXT;
}

static uint32_t reset_ntl_finish(struct npu3_dev *dev) {
	struct npu3 *npu = dev->npu;
	uint64_t val;

	if (npu3_dev_fence_get(dev) != NPU3_NTL_CQ_FENCE_STATUS_NONE)
		return NPU3_PROC_INPROGRESS;

	/* Enable parity checking */
	val = npu3_read(npu, NPU3_NTL_MISC_CFG2(dev->index));
	val |= NPU3_NTL_MISC_CFG2_NDL_RX_PARITY_ENA |
	       NPU3_NTL_MISC_CFG2_NDL_TX_PARITY_ENA |
	       NPU3_NTL_MISC_CFG2_NDL_PRI_PARITY_ENA;
	npu3_write(npu, NPU3_NTL_MISC_CFG2(dev->index), val);

	if (dev->type == NPU3_DEV_TYPE_NVLINK)
		npu3_pvd_flag_set(dev, NPU3_DEV_DL_RESET);

	return NPU3_PROC_COMPLETE;
}

DEFINE_PROCEDURE(reset_ntl, reset_ndl, reset_ntl_release, reset_ntl_finish);

static int npu3_dev_regcmp(struct npu3_dev *dev, uint64_t reg,
			   const char *reg_name, uint64_t expected)
{
	uint64_t val;

	val = npu3_read(dev->npu, reg);
	if (val == expected)
		return 0;

	NPU3DEVERR(dev, "%s: expected 0x%llx, read 0x%llx\n",
		   reg_name, expected, val);

	return 1;
}

#define REGCMP(reg, expected) \
	npu3_dev_regcmp(dev, reg(dev->index), #reg, expected)

static uint32_t check_credits(struct npu3_dev *dev)
{
	/* Use bitwise OR to prevent short-circuit evaluation */
	if (REGCMP(NPU3_NTL_CREQ_HDR_CRED_RCV, 0x0be0be0000000000ull) |
	    REGCMP(NPU3_NTL_DGD_HDR_CRED_RCV,  0x0640640000000000ull) |
	    REGCMP(NPU3_NTL_ATSD_HDR_CRED_RCV, 0x0200200000000000ull) |
	    REGCMP(NPU3_NTL_RSP_HDR_CRED_RCV,  0x0be0be0000000000ull) |
	    REGCMP(NPU3_NTL_CREQ_DAT_CRED_RCV, 0x1001000000000000ull) |
	    REGCMP(NPU3_NTL_RSP_DAT_CRED_RCV,  0x1001000000000000ull))
		return NPU3_PROC_COMPLETE | NPU3_PROC_FAILED;

	return NPU3_PROC_COMPLETE;
}

DEFINE_PROCEDURE(check_credits);

static struct procedure *procedures[] = {
	 [0] = &procedure_stop,
	 [1] = &procedure_nop,
	 [4] = &procedure_phy_reset,
	 [5] = &procedure_phy_tx_zcal,
	 [6] = &procedure_phy_rx_dccal,
	 [7] = &procedure_phy_enable_tx_rxcal,
	 [8] = &procedure_phy_disable_tx_rxcal,
	 [9] = &procedure_phy_rx_training,
	[10] = &procedure_reset_ntl,
	[11] = &procedure_nop, /* Placeholder for pre-terminate */
	[12] = &procedure_nop, /* Placeholder for terminate */
	[13] = &procedure_check_credits,
};

void npu3_dev_procedure_init(struct npu3_dev *dev, uint32_t pnum)
{
	struct npu3_procedure *proc = &dev->proc;
	const char *name;

	if (pnum >= ARRAY_SIZE(procedures) || !procedures[pnum]) {
		NPU3DEVERR(dev, "Unsupported procedure number %d\n", pnum);
		proc->status = NPU3_PROC_COMPLETE | NPU3_PROC_UNSUPPORTED;
		return;
	}

	name = procedures[pnum]->name;

	if (proc->number == pnum && !(proc->status & NPU3_PROC_COMPLETE))
		NPU3DEVINF(dev, "Restarting procedure %s\n", name);
	else
		NPU3DEVINF(dev, "Starting procedure %s\n", name);

	proc->status = NPU3_PROC_INPROGRESS;
	proc->number = pnum;
	proc->step = 0;
	proc->timeout = mftb() + msecs_to_tb(1000);
}

static uint32_t npu3_dev_procedure_run_step(struct npu3_dev *dev)
{
	struct npu3_procedure *proc = &dev->proc;
	uint32_t result;

	result = procedures[proc->number]->steps[proc->step](dev);
	if (result & NPU3_PROC_NEXT) {
		proc->step++;

		NPU3DEVINF(dev, "Running procedure %s step %d\n",
			   procedures[proc->number]->name, proc->step);
	}

	return result;
}

static void npu3_dev_procedure_run(struct npu3_dev *dev)
{
	struct npu3_procedure *proc = &dev->proc;
	const char *name;
	uint32_t result;

	do {
		result = npu3_dev_procedure_run_step(dev);
	} while (result & NPU3_PROC_NEXT);

	name = procedures[proc->number]->name;

	if (result & NPU3_PROC_COMPLETE) {
		NPU3DEVINF(dev, "Procedure %s complete\n", name);
	} else if (tb_compare(mftb(), proc->timeout) == TB_AAFTERB) {
		NPU3DEVINF(dev, "Procedure %s timed out\n", name);
		result = NPU3_PROC_COMPLETE | NPU3_PROC_FAILED;
	}

	/* Mask off internal state bits */
	proc->status = result & NPU3_PROC_STATUS_MASK;
}

uint32_t npu3_dev_procedure_status(struct npu3_dev *dev)
{
	/* Run the procedure if not already complete */
	if (!(dev->proc.status & NPU3_PROC_COMPLETE))
		npu3_dev_procedure_run(dev);

	return dev->proc.status;
}

int64_t npu3_dev_reset(struct npu3_dev *dev)
{
	unsigned long timeout;

	reset_ntl(dev);
	timeout = mftb() + msecs_to_tb(1000);

	while (npu3_dev_fence_get(dev) != NPU3_NTL_CQ_FENCE_STATUS_FULL) {
		if (tb_compare(mftb(), timeout) == TB_AAFTERB) {
			NPU3DEVINF(dev, "Device reset timed out\n");
			return OPAL_BUSY;
		}
	}

	return OPAL_SUCCESS;
}
