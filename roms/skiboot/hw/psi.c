// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Service Processor serial console handling code
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <io.h>
#include <psi.h>
#include <fsp.h>
#include <opal.h>
#include <interrupts.h>
#include <cpu.h>
#include <dio-p9.h>
#include <trace.h>
#include <xscom.h>
#include <chip.h>
#include <lpc.h>
#include <i2c.h>
#include <timebase.h>
#include <platform.h>
#include <errorlog.h>
#include <xive.h>
#include <sbe-p9.h>
#include <phys-map.h>
#include <occ.h>

static LIST_HEAD(psis);
static u64 psi_link_timer;
static u64 psi_link_timeout;
static bool psi_link_poll_active;

static void psi_activate_phb(struct psi *psi);

struct lock psi_lock = LOCK_UNLOCKED;

DEFINE_LOG_ENTRY(OPAL_RC_PSI_TIMEOUT, OPAL_PLATFORM_ERR_EVT, OPAL_PSI,
		OPAL_PLATFORM_FIRMWARE,
		OPAL_UNRECOVERABLE_ERR_LOSS_OF_FUNCTION, OPAL_NA);

void psi_set_link_polling(bool active)
{
	printf("PSI: %sing link polling\n",
	       active ? "start" : "stopp");
	psi_link_poll_active = active;
}

void psi_disable_link(struct psi *psi)
{
	lock(&psi_lock);

	/*
	 * Note: This can be called with the link already down but
	 * not detected as such yet by this layer since psi_check_link_active()
	 * operates locklessly and thus won't update the PSI structure. This
	 * is a non-issue, the only consequence is the messages in the log
	 * mentioning first the link having gone down then being disabled.
	 */
	if (psi->active) {
		u64 reg;
		psi->active = false;

		/* Mask errors in SEMR */
		reg = in_be64(psi->regs + PSIHB_SEMR);
		reg &= ((0xfffull << 36) | (0xfffull << 20));
		out_be64(psi->regs + PSIHB_SEMR, reg);
		printf("PSI: SEMR set to %llx\n", reg);

		/* Reset all the error bits in PSIHB_CR and
		 * disable FSP interrupts
		 */
		reg = in_be64(psi->regs + PSIHB_CR);
		reg &= ~(0x7ffull << 20);
		reg &= ~PSIHB_CR_PSI_LINK_ENABLE;	/* flip link enable */
		/*
		 * Ensure no commands/spurious interrupts reach
		 * the processor, by flipping the command enable.
		 */
		reg &= ~PSIHB_CR_FSP_CMD_ENABLE;
		reg &= ~PSIHB_CR_FSP_IRQ_ENABLE;
		reg &= ~PSIHB_CR_FSP_IRQ; /* Clear interrupt state too */
		printf("PSI[0x%03x]: Disabling link!\n", psi->chip_id);
		out_be64(psi->regs + PSIHB_CR, reg);
		printf("PSI: PSIHB_CR (error bits) set to %llx\n",
				in_be64(psi->regs + PSIHB_CR));
		psi_set_link_polling(true);
	}

	unlock(&psi_lock);
}

/*
 * Resetting the FSP is a multi step sequence:
 * 1. Read the PSIHBCR
 * 2. Set the PSIHBCR[6] -- write register back.
 * 3. Read PSIHBCR again
 * 4. Reset PSIHBCR[6] -- write register back.
 */
void psi_reset_fsp(struct psi *psi)
{
	lock(&psi_lock);

	if (psi->active) {
		u64 reg;

		printf("PSI: Driving FSP reset via PSI\n");
		reg = in_be64(psi->regs + PSIHB_CR);
		reg &= ~(0xfffull << 20);	/* Reset error bits */
		reg |= PSIHB_CR_FSP_RESET;	/* FSP reset trigger start */
		out_be64(psi->regs + PSIHB_CR, reg);
		printf("PSI[0x%03x]: FSP reset start PSIHBCR set to %llx\n",
			psi->chip_id, in_be64(psi->regs + PSIHB_CR));

		reg = in_be64(psi->regs + PSIHB_CR);
		reg &= ~PSIHB_CR_FSP_RESET;	/* Clear FSP reset bit */
		out_be64(psi->regs + PSIHB_CR, reg);	/* Complete reset */
		printf("PSI[0x%03x]: FSP reset complete. PSIHBCR set to %llx\n",
			psi->chip_id, in_be64(psi->regs + PSIHB_CR));
	}
	unlock(&psi_lock);

	/* Now bring down the PSI link too... */
	psi_disable_link(psi);
}

bool psi_check_link_active(struct psi *psi)
{
	u64 val = in_be64(psi->regs + PSIHB_CR);

	/*
	 * Unlocked, used during fsp_poke_msg so we really want
	 * to avoid fancy link re-entrancy and deadlocks here
	 */
	if (!psi->active)
		return false;
	return (val & PSIHB_CR_PSI_LINK_ENABLE) &&
		(val & PSIHB_CR_FSP_LINK_ACTIVE);
}

struct psi *psi_find_link(uint32_t chip_id)
{
	struct psi *psi;

	list_for_each(&psis, psi, list) {
		if (psi->chip_id == chip_id)
			return psi;
	}
	return NULL;
}

#define PSI_LINK_CHECK_INTERVAL		10	/* Interval in secs */
#define PSI_LINK_RECOVERY_TIMEOUT	1800	/* 30 minutes */

static void psi_link_poll(void *data __unused)
{
	struct psi *psi;
	u64 now;

	if (!psi_link_poll_active)
		return;

	now = mftb();
	if (psi_link_timer == 0 ||
		(tb_compare(now, psi_link_timer) == TB_AAFTERB) ||
		(tb_compare(now, psi_link_timer) == TB_AEQUALB)) {

		lock(&psi_lock);

		list_for_each(&psis, psi, list) {
			u64 val;

			if (psi->active)
				continue;

			val = in_be64(psi->regs + PSIHB_CR);

			printf("PSI[0x%03x]: Poll CR=0x%016llx\n",
			       psi->chip_id, val);

			if ((val & PSIHB_CR_PSI_LINK_ENABLE) &&
			    (val & PSIHB_CR_FSP_LINK_ACTIVE)) {
				printf("PSI[0x%03x]: Found active link!\n",
				       psi->chip_id);
				psi_link_timeout = 0;
				psi->active = true;
				psi_activate_phb(psi);
				psi_set_link_polling(false);
				unlock(&psi_lock);
				if (platform.psi && platform.psi->link_established)
					platform.psi->link_established();
				return;
			}
		}
		if (!psi_link_timeout)
			psi_link_timeout =
				now + secs_to_tb(PSI_LINK_RECOVERY_TIMEOUT);

		if (tb_compare(now, psi_link_timeout) == TB_AAFTERB) {
			log_simple_error(&e_info(OPAL_RC_PSI_TIMEOUT),
				"PSI: Link timeout -- loss of FSP\n");
			/* Reset the link timeout and continue looking */
			psi_link_timeout = 0;
		}

		/* Poll every 10 seconds */
		psi_link_timer = now + secs_to_tb(PSI_LINK_CHECK_INTERVAL);

		unlock(&psi_lock);
	}
}

void psi_enable_fsp_interrupt(struct psi *psi)
{
	/* Enable FSP interrupts in the GXHB */
	lock(&psi_lock);
	out_be64(psi->regs + PSIHB_CR,
		 in_be64(psi->regs + PSIHB_CR) | PSIHB_CR_FSP_IRQ_ENABLE);
	unlock(&psi_lock);
}

/* Multiple bits can be set on errors */
static void decode_psihb_error(u64 val)
{
	if (val & PSIHB_CR_PSI_ERROR)
		printf("PSI: PSI Reported Error\n");
	if (val & PSIHB_CR_PSI_LINK_INACTIVE)
		printf("PSI: PSI Link Inactive Transition\n");
	if (val & PSIHB_CR_FSP_ACK_TIMEOUT)
		printf("PSI: FSP Ack Timeout\n");
	if (val & PSIHB_CR_MMIO_LOAD_TIMEOUT)
		printf("PSI: MMIO Load Timeout\n");
	if (val & PSIHB_CR_MMIO_LENGTH_ERROR)
		printf("PSI: MMIO Length Error\n");
	if (val & PSIHB_CR_MMIO_ADDRESS_ERROR)
		printf("PSI: MMIO Address Error\n");
	if (val & PSIHB_CR_MMIO_TYPE_ERROR)
		printf("PSI: MMIO Type Error\n");
	if (val & PSIHB_CR_UE)
		printf("PSI: UE Detected\n");
	if (val & PSIHB_CR_PARITY_ERROR)
		printf("PSI: Internal Parity Error\n");
	if (val & PSIHB_CR_SYNC_ERR_ALERT1)
		printf("PSI: Sync Error Alert1\n");
	if (val & PSIHB_CR_SYNC_ERR_ALERT2)
		printf("PSI: Sync Error Alert2\n");
	if (val & PSIHB_CR_FSP_COMMAND_ERROR)
		printf("PSI: FSP Command Error\n");
}


static void handle_psi_interrupt(struct psi *psi, u64 val)
{
	printf("PSI[0x%03x]: PSI mgmnt interrupt CR=0x%016llx\n",
	       psi->chip_id, val);

	if (val & (0xfffull << 20)) {
		decode_psihb_error(val);
		psi_disable_link(psi);
	} else if (val & (0x1full << 11))
		printf("PSI: FSP error detected\n");
}

static void psi_spurious_fsp_irq(struct psi *psi)
{
	u64 reg, bit;

	prlog(PR_NOTICE, "PSI: Spurious interrupt, attempting clear\n");

	if (proc_gen == proc_gen_p10) {
		reg = PSIHB_XSCOM_P10_HBCSR_CLR;
		bit = PSIHB_XSCOM_P10_HBSCR_FSP_IRQ;
	} else if (proc_gen == proc_gen_p9) {
		reg = PSIHB_XSCOM_P9_HBCSR_CLR;
		bit = PSIHB_XSCOM_P9_HBSCR_FSP_IRQ;
	} else if (proc_gen == proc_gen_p8) {
		reg = PSIHB_XSCOM_P8_HBCSR_CLR;
		bit = PSIHB_XSCOM_P8_HBSCR_FSP_IRQ;
	} else {
		assert(false);
	}
	xscom_write(psi->chip_id, psi->xscom_base + reg, bit);
}

bool psi_poll_fsp_interrupt(struct psi *psi)
{
	return !!(in_be64(psi->regs + PSIHB_CR) & PSIHB_CR_FSP_IRQ);
}

static void psihb_interrupt(struct irq_source *is, uint32_t isn __unused)
{
	struct psi *psi = is->data;
	u64 val;

	val = in_be64(psi->regs + PSIHB_CR);

	if (psi_link_poll_active) {
		printf("PSI[0x%03x]: PSI interrupt CR=0x%016llx (A=%d)\n",
		       psi->chip_id, val, psi->active);
	}

	/* Handle PSI interrupts first in case it's a link down */
	if (val & PSIHB_CR_PSI_IRQ) {
		handle_psi_interrupt(psi, val);

		/*
		 * If the link went down, re-read PSIHB_CR as
		 * the FSP interrupt might have been cleared.
		 */
		if (!psi->active)
			val = in_be64(psi->regs + PSIHB_CR);
	}


	/*
	 * We avoid forwarding FSP interrupts if the link isn't
	 * active. They should be masked anyway but it looks
	 * like the CR bit can remain set.
	 */
	if (val & PSIHB_CR_FSP_IRQ) {
		/*
		 * We have a case a flood with FSP mailbox interrupts
		 * when the link is down, see if we manage to clear
		 * the condition
		 */
		if (!psi->active)
			psi_spurious_fsp_irq(psi);
		else {
			if (platform.psi && platform.psi->fsp_interrupt)
				platform.psi->fsp_interrupt();
		}
	}

	if (platform.psi && platform.psi->psihb_interrupt)
		platform.psi->psihb_interrupt();
}


static const uint32_t psi_p8_irq_to_xivr[P8_IRQ_PSI_IRQ_COUNT] = {
	[P8_IRQ_PSI_FSP]	= PSIHB_XIVR_FSP,
	[P8_IRQ_PSI_OCC]	= PSIHB_XIVR_OCC,
	[P8_IRQ_PSI_FSI]	= PSIHB_XIVR_FSI,
	[P8_IRQ_PSI_LPC]	= PSIHB_XIVR_LPC,
	[P8_IRQ_PSI_LOCAL_ERR]	= PSIHB_XIVR_LOCAL_ERR,
	[P8_IRQ_PSI_EXTERNAL]= PSIHB_XIVR_HOST_ERR,
};

static void psi_cleanup_irq(struct psi *psi)
{
	uint32_t irq;
	uint64_t xivr, xivr_p;

	for (irq = 0; irq < P8_IRQ_PSI_IRQ_COUNT; irq++) {
		prlog(PR_DEBUG, "PSI[0x%03x]: Cleaning up IRQ %d\n",
		      psi->chip_id, irq);

		xivr_p = psi_p8_irq_to_xivr[irq];
		xivr = in_be64(psi->regs + xivr_p);
		xivr |= (0xffull << 32);
		out_be64(psi->regs + xivr_p, xivr);
		time_wait_ms_nopoll(10);
		xivr = in_be64(psi->regs + xivr_p);
		if (xivr & PPC_BIT(39)) {
			printf(" Need EOI !\n");
			icp_send_eoi(psi->interrupt + irq);
		}
	}
}

/* Called on a fast reset, make sure we aren't stuck with
 * an accepted and never EOId PSI interrupt
 */
void psi_irq_reset(void)
{
	struct psi *psi;

	printf("PSI: Hot reset!\n");

	assert(proc_gen == proc_gen_p8);

	list_for_each(&psis, psi, list) {
		psi_cleanup_irq(psi);
	}
}

static int64_t psi_p8_set_xive(struct irq_source *is, uint32_t isn,
			       uint16_t server, uint8_t priority)
{
	struct psi *psi = is->data;
	uint64_t xivr_p, xivr;
	uint32_t irq_idx = isn & 7;

	if (irq_idx >= P8_IRQ_PSI_IRQ_COUNT)
 		return OPAL_PARAMETER;
	xivr_p = psi_p8_irq_to_xivr[irq_idx];

	/* Populate the XIVR */
	xivr  = (uint64_t)server << 40;
	xivr |= (uint64_t)priority << 32;
	xivr |= (uint64_t)(isn & 7) << 29;

	out_be64(psi->regs + xivr_p, xivr);

	return OPAL_SUCCESS;
}

static int64_t psi_p8_get_xive(struct irq_source *is, uint32_t isn __unused,
			       uint16_t *server, uint8_t *priority)
{
	struct psi *psi = is->data;
	uint64_t xivr_p, xivr;
	uint32_t irq_idx = isn & 7;

	if (irq_idx >= P8_IRQ_PSI_IRQ_COUNT)
 		return OPAL_PARAMETER;

	xivr_p = psi_p8_irq_to_xivr[irq_idx];

	/* Read & decode the XIVR */
	xivr = in_be64(psi->regs + xivr_p);

	*server = (xivr >> 40) & 0xffff;
	*priority = (xivr >> 32) & 0xff;

	return OPAL_SUCCESS;
}

static void psihb_p8_interrupt(struct irq_source *is, uint32_t isn)
{
	struct psi *psi = is->data;
	uint32_t idx = isn - psi->interrupt;

	switch (idx) {
	case P8_IRQ_PSI_FSP:
		psihb_interrupt(is, isn);
		break;
	case P8_IRQ_PSI_OCC:
		occ_p8_interrupt(psi->chip_id);
		break;
	case P8_IRQ_PSI_FSI:
		printf("PSI: FSI irq received\n");
		break;
	case P8_IRQ_PSI_LPC:
		lpc_interrupt(psi->chip_id);

		/*
		 * i2c interrupts are ORed with the LPC ones on
		 * Murano DD2.1 and Venice DD2.0
		 */
		p8_i2c_interrupt(psi->chip_id);
		break;
	case P8_IRQ_PSI_LOCAL_ERR:
		prd_psi_interrupt(psi->chip_id);
		break;
	case P8_IRQ_PSI_EXTERNAL:
		if (platform.external_irq)
			platform.external_irq(psi->chip_id);
		break;
	}

	/*
	 * TODO: Per Vicente Chung, CRESPs don't generate interrupts,
	 * and are just informational. Need to define the policy
	 * to handle them.
	 */
}

static uint64_t psi_p8_irq_attributes(struct irq_source *is, uint32_t isn)
{
	struct psi *psi = is->data;
	uint32_t idx = isn - psi->interrupt;
	uint64_t attr;

	if (psi->no_lpc_irqs && idx == P8_IRQ_PSI_LPC)
		return IRQ_ATTR_TARGET_LINUX;

	/* Only direct external interrupts to OPAL if we have a handler */
	if (idx == P8_IRQ_PSI_EXTERNAL && !platform.external_irq)
		return IRQ_ATTR_TARGET_LINUX;

	attr = IRQ_ATTR_TARGET_OPAL | IRQ_ATTR_TYPE_LSI;
	if (idx == P8_IRQ_PSI_EXTERNAL || idx == P8_IRQ_PSI_LPC ||
	    idx == P8_IRQ_PSI_FSP)
		attr |= IRQ_ATTR_TARGET_FREQUENT;
	return attr;
}

static char *psi_p8_irq_name(struct irq_source *is, uint32_t isn)
{
	struct psi *psi = is->data;
	uint32_t idx = isn - psi->interrupt;
	char tmp[30];

	static const char *names[P8_IRQ_PSI_IRQ_COUNT] = {
		"fsp",
		"occ",
		"fsi",
		"lpchc",
		"local_err",
		"external",
	};

	if (idx >= P8_IRQ_PSI_IRQ_COUNT)
		return NULL;

	snprintf(tmp, sizeof(tmp), "psi#%x:%s",
		 psi->chip_id, names[idx]);

	return strdup(tmp);
}

static const struct irq_source_ops psi_p8_irq_ops = {
	.get_xive = psi_p8_get_xive,
	.set_xive = psi_p8_set_xive,
	.interrupt = psihb_p8_interrupt,
	.attributes = psi_p8_irq_attributes,
	.name = psi_p8_irq_name,
};

static const char *psi_p9_irq_names[P9_PSI_NUM_IRQS] = {
	"fsp",
	"occ",
	"fsi",
	"lpchc",
	"local_err",
	"global_err",
	"external",
	"lpc_serirq_mux0", /* Have a callback to get name ? */
	"lpc_serirq_mux1", /* Have a callback to get name ? */
	"lpc_serirq_mux2", /* Have a callback to get name ? */
	"lpc_serirq_mux3", /* Have a callback to get name ? */
	"i2c",
	"dio",
	"psu"
};

static void psi_p9_mask_all(struct psi *psi)
{
	struct irq_source *is;
	int isn;

	/* Mask all sources */
	is = irq_find_source(psi->interrupt);
	for (isn = is->start; isn < is->end; isn++)
		xive_source_mask(is, isn);
}

static void psi_p9_mask_unhandled_irq(struct irq_source *is, uint32_t isn)
{
	struct psi *psi = is->data;
	int idx = isn - psi->interrupt;
	const char *name;

	if (idx < ARRAY_SIZE(psi_p9_irq_names))
		name = psi_p9_irq_names[idx];
	else
		name = "unknown!";

	prerror("PSI[0x%03x]: Masking unhandled LSI %d (%s)\n",
			psi->chip_id, idx, name);

	/*
	 * All the PSI interrupts are LSIs and will be constantly re-fired
	 * unless the underlying interrupt condition is cleared. If we don't
	 * have a handler for the interrupt then it needs to be masked to
	 * prevent the IRQ from locking up the thread which handles it.
	 */
	switch (proc_gen) {
	case proc_gen_p9:
		xive_source_mask(is, isn);
		break;
	case proc_gen_p10:
		xive2_source_mask(is, isn);
		return;
	default:
		assert(false);
	}

}

static void psihb_p9_interrupt(struct irq_source *is, uint32_t isn)
{
	struct psi *psi = is->data;
	uint32_t idx = isn - psi->interrupt;

	switch (idx) {
	case P9_PSI_IRQ_PSI:
		psihb_interrupt(is, isn);
		break;
	case P9_PSI_IRQ_OCC:
		occ_p9_interrupt(psi->chip_id);
		break;
	case P9_PSI_IRQ_LPCHC:
		lpc_interrupt(psi->chip_id);
		break;
	case P9_PSI_IRQ_LOCAL_ERR:
		prd_psi_interrupt(psi->chip_id);
		break;
	case P9_PSI_IRQ_EXTERNAL:
		if (platform.external_irq)
			platform.external_irq(psi->chip_id);
		else
			psi_p9_mask_unhandled_irq(is, isn);
		break;
	case P9_PSI_IRQ_LPC_SIRQ0:
	case P9_PSI_IRQ_LPC_SIRQ1:
	case P9_PSI_IRQ_LPC_SIRQ2:
	case P9_PSI_IRQ_LPC_SIRQ3:
		lpc_serirq(psi->chip_id, idx - P9_PSI_IRQ_LPC_SIRQ0);
		break;
	case P9_PSI_IRQ_SBE_I2C:
		p8_i2c_interrupt(psi->chip_id);
		break;
	case P9_PSI_IRQ_DIO:
		printf("PSI: DIO irq received\n");
		dio_interrupt_handler(psi->chip_id);
		break;
	case P9_PSI_IRQ_PSU:
		p9_sbe_interrupt(psi->chip_id);
		break;

	default:
		psi_p9_mask_unhandled_irq(is, isn);
	}
}

static uint64_t psi_p9_irq_attributes(struct irq_source *is __unused,
				      uint32_t isn)
{
	struct psi *psi = is->data;
	unsigned int idx = isn & 0xf;
	bool is_lpc_serirq;

	 is_lpc_serirq =
		 (idx == P9_PSI_IRQ_LPC_SIRQ0 ||
		  idx == P9_PSI_IRQ_LPC_SIRQ1 ||
		  idx == P9_PSI_IRQ_LPC_SIRQ2 ||
		  idx == P9_PSI_IRQ_LPC_SIRQ3);

	/* If LPC interrupts are disabled, route them to Linux
	 * (who will not request them since they aren't referenced
	 * in the device tree)
	 */
	 if (is_lpc_serirq && psi->no_lpc_irqs)
		return IRQ_ATTR_TARGET_LINUX;

	 /* For serirq, check the LPC layer for policy */
	 if (is_lpc_serirq)
		 return lpc_get_irq_policy(psi->chip_id, idx - P9_PSI_IRQ_LPC_SIRQ0);

	/* Only direct external interrupts to OPAL if we have a handler */
	if (idx == P9_PSI_IRQ_EXTERNAL && !platform.external_irq)
		return IRQ_ATTR_TARGET_LINUX | IRQ_ATTR_TYPE_LSI;

	return IRQ_ATTR_TARGET_OPAL | IRQ_ATTR_TYPE_LSI;
}

static char *psi_p9_irq_name(struct irq_source *is, uint32_t isn)
{
	struct psi *psi = is->data;
	uint32_t idx = isn - psi->interrupt;
	char tmp[30];

	if (idx >= ARRAY_SIZE(psi_p9_irq_names))
		return NULL;

	snprintf(tmp, sizeof(tmp), "psi#%x:%s",
		 psi->chip_id, psi_p9_irq_names[idx]);

	return strdup(tmp);
}

static const struct irq_source_ops psi_p9_irq_ops = {
	.interrupt = psihb_p9_interrupt,
	.attributes = psi_p9_irq_attributes,
	.name = psi_p9_irq_name,
};

static void psi_init_p8_interrupts(struct psi *psi)
{
	uint32_t irq;
	uint64_t xivr_p;

	/* On P8 we get a block of 8, set up the base/mask
	 * and mask all the sources for now
	 */
	out_be64(psi->regs + PSIHB_IRSN,
		 SETFIELD(PSIHB_IRSN_COMP, 0ul, psi->interrupt) |
		 SETFIELD(PSIHB_IRSN_MASK, 0ul, 0x7fff8ul) |
		 PSIHB_IRSN_DOWNSTREAM_EN |
		 PSIHB_IRSN_UPSTREAM_EN);

	for (irq = 0; irq < P8_IRQ_PSI_IRQ_COUNT; irq++) {
		xivr_p = psi_p8_irq_to_xivr[irq];
		out_be64(psi->regs  + xivr_p, (0xffull << 32) | (irq << 29));
	}

	/*
	 * Register the IRQ sources FSP, OCC, FSI, LPC
	 * and Local Error. Host Error is actually the
	 * external interrupt and the policy for that comes
	 * from the platform
	 */
	register_irq_source(&psi_p8_irq_ops, psi,
			    psi->interrupt, P8_IRQ_PSI_IRQ_COUNT);
}

static void psi_init_p9_interrupts(struct psi *psi)
{
	struct proc_chip *chip;
	u64 val;

	/* Grab chip */
	chip = get_chip(psi->chip_id);
	if (!chip)
		return;

	/* Configure the CI BAR */
	phys_map_get(chip->id, PSIHB_ESB, 0, &val, NULL);
	val |= PSIHB_ESB_CI_VALID;
	out_be64(psi->regs + PSIHB_ESB_CI_BASE, val);

	val = in_be64(psi->regs + PSIHB_ESB_CI_BASE);
	psi->esb_mmio = (void *)(val & ~PSIHB_ESB_CI_VALID);
	prlog(PR_DEBUG, "PSI[0x%03x]: ESB MMIO at @%p\n",
	       psi->chip_id, psi->esb_mmio);

	/* Register sources */
	prlog(PR_DEBUG,
	      "PSI[0x%03x]: Interrupts sources registered for P9 DD2.x\n",
	      psi->chip_id);
	xive_register_hw_source(psi->interrupt, P9_PSI_NUM_IRQS,
				12, psi->esb_mmio, XIVE_SRC_LSI,
				psi, &psi_p9_irq_ops);

	psi_p9_mask_all(psi);

	/* Setup interrupt offset */
	val = xive_get_notify_base(psi->interrupt);
	val <<= 32;
	out_be64(psi->regs + PSIHB_IVT_OFFSET, val);

	/* Grab and configure the notification port */
	val = xive_get_notify_port(psi->chip_id, XIVE_HW_SRC_PSI);
	val |= PSIHB_ESB_NOTIF_VALID;
	out_be64(psi->regs + PSIHB_ESB_NOTIF_ADDR, val);

	/* Reset irq handling and switch to ESB mode */
	out_be64(psi->regs + PSIHB_INTERRUPT_CONTROL, PSIHB_IRQ_RESET);
	out_be64(psi->regs + PSIHB_INTERRUPT_CONTROL, 0);
}

/*
 * P9 and P10 have the same PSIHB interface
 */
static const struct irq_source_ops psi_p10_irq_ops = {
	.interrupt = psihb_p9_interrupt,
	.attributes = psi_p9_irq_attributes,
	.name = psi_p9_irq_name,
};

#define PSIHB10_CAN_STORE_EOI(x) XIVE2_STORE_EOI_ENABLED

static void psi_init_p10_interrupts(struct psi *psi)
{
	struct proc_chip *chip;
	u64 val;
	uint32_t esb_shift = 16;
	uint32_t flags = XIVE_SRC_LSI;
	struct irq_source *is;
	int isn;

	/* Grab chip */
	chip = get_chip(psi->chip_id);
	if (!chip)
		return;

	/* Configure the CI BAR */
	phys_map_get(chip->id, PSIHB_ESB, 0, &val, NULL);
	val |= PSIHB_ESB_CI_VALID;
	if (esb_shift == 16)
		val |= PSIHB10_ESB_CI_64K;
	out_be64(psi->regs + PSIHB_ESB_CI_BASE, val);

	val = in_be64(psi->regs + PSIHB_ESB_CI_BASE);
	psi->esb_mmio = (void *)(val & ~(PSIHB_ESB_CI_VALID|PSIHB10_ESB_CI_64K));
	prlog(PR_DEBUG, "PSI[0x%03x]: ESB MMIO at @%p\n",
	       psi->chip_id, psi->esb_mmio);

	/* Store EOI */
	if (PSIHB10_CAN_STORE_EOI(psi)) {
		val = in_be64(psi->regs + PSIHB_CR);
		val |= PSIHB10_CR_STORE_EOI;
		out_be64(psi->regs + PSIHB_CR, val);
		prlog(PR_DEBUG, "PSI[0x%03x]: store EOI is enabled\n",
		      psi->chip_id);
		flags |= XIVE_SRC_STORE_EOI;
	}

	/* Register sources */
	prlog(PR_DEBUG,
	      "PSI[0x%03x]: Interrupts sources registered for P10 DD%i.%i\n",
	      psi->chip_id, 0xf & (chip->ec_level >> 4), chip->ec_level & 0xf);

	xive2_register_hw_source(psi->interrupt, P9_PSI_NUM_IRQS,
				esb_shift, psi->esb_mmio, flags,
				psi, &psi_p10_irq_ops);

	/* Mask all sources */
	is = irq_find_source(psi->interrupt);
	for (isn = is->start; isn < is->end; isn++)
		xive2_source_mask(is, isn);

	/* Setup interrupt offset */
	val = xive2_get_notify_base(psi->interrupt);
	val <<= 32;
	out_be64(psi->regs + PSIHB_IVT_OFFSET, val);

	/* Grab and configure the notification port */
	val = xive2_get_notify_port(psi->chip_id, XIVE_HW_SRC_PSI);
	val |= PSIHB_ESB_NOTIF_VALID;
	out_be64(psi->regs + PSIHB_ESB_NOTIF_ADDR, val);

	/* Reset irq handling and switch to ESB mode */
	out_be64(psi->regs + PSIHB_INTERRUPT_CONTROL, PSIHB_IRQ_RESET);
	out_be64(psi->regs + PSIHB_INTERRUPT_CONTROL, 0);
}

static void psi_init_interrupts(struct psi *psi)
{
	/* Configure the interrupt BUID and mask it */
	switch (proc_gen) {
	case proc_gen_p8:
		psi_init_p8_interrupts(psi);
		break;
	case proc_gen_p9:
		psi_init_p9_interrupts(psi);
		break;
	case proc_gen_p10:
		psi_init_p10_interrupts(psi);
		break;
	default:
		/* Unknown: just no interrupts */
		prerror("PSI: Unknown interrupt type\n");
	}
}

static void psi_activate_phb(struct psi *psi)
{
	u64 reg;

	/*
	 * Disable interrupt emission in the control register,
	 * it will be re-enabled later, after the mailbox one
	 * will have been enabled.
	 */
	reg = in_be64(psi->regs + PSIHB_CR);
	reg &= ~PSIHB_CR_FSP_IRQ_ENABLE;
	out_be64(psi->regs + PSIHB_CR, reg);

	/* Enable interrupts in the mask register. We enable everything
	 * except for bit "FSP command error detected" which the doc
	 * (P7 BookIV) says should be masked for normal ops. It also
	 * seems to be masked under OPAL.
	 */
	reg = 0x0000010000100000ull;
	out_be64(psi->regs + PSIHB_SEMR, reg);

#if 0
	/* Dump the GXHB registers */
	printf("  PSIHB_BBAR   : %llx\n",
	       in_be64(psi->regs + PSIHB_BBAR));
	printf("  PSIHB_FSPBAR : %llx\n",
	       in_be64(psi->regs + PSIHB_FSPBAR));
	printf("  PSIHB_FSPMMR : %llx\n",
	       in_be64(psi->regs + PSIHB_FSPMMR));
	printf("  PSIHB_TAR    : %llx\n",
	       in_be64(psi->regs + PSIHB_TAR));
	printf("  PSIHB_CR     : %llx\n",
	       in_be64(psi->regs + PSIHB_CR));
	printf("  PSIHB_SEMR   : %llx\n",
	       in_be64(psi->regs + PSIHB_SEMR));
	printf("  PSIHB_XIVR   : %llx\n",
	       in_be64(psi->regs + PSIHB_XIVR));
#endif
}

static void psi_create_p9_int_map(struct psi *psi, struct dt_node *np)
{
	__be32 map[P9_PSI_NUM_IRQS][4];
	int i;

	for (i = 0; i < P9_PSI_NUM_IRQS; i++) {
		map[i][0] = cpu_to_be32(i);
		map[i][1] = cpu_to_be32(get_ics_phandle());
		map[i][2] = cpu_to_be32(psi->interrupt + i);
		map[i][3] = cpu_to_be32(1);
	}
	dt_add_property(np, "interrupt-map", map, sizeof(map));
	dt_add_property_cells(np, "#address-cells", 0);
	dt_add_property_cells(np, "#interrupt-cells", 1);
}

static void psi_create_mm_dtnode(struct psi *psi)
{
	struct dt_node *np;
	uint64_t addr = (uint64_t)psi->regs;

	np = dt_new_addr(dt_root, "psi", addr);
	if (!np)
		return;

	/* Hard wire size to 4G */
	dt_add_property_u64s(np, "reg", addr, 0x100000000ull);
	switch (proc_gen) {
	case proc_gen_p8:
		dt_add_property_strings(np, "compatible", "ibm,psi",
					"ibm,power8-psi");
		break;
	case proc_gen_p9:
	case proc_gen_p10:
		dt_add_property_strings(np, "compatible", "ibm,psi",
					"ibm,power9-psi");
		psi_create_p9_int_map(psi, np);
		break;
	default:
		assert(0);
		break;
	}
	dt_add_property_cells(np, "interrupt-parent", get_ics_phandle());
	dt_add_property_cells(np, "interrupts", psi->interrupt, 1);
	dt_add_property_cells(np, "ibm,chip-id", psi->chip_id);
	psi->node = np;
}

static struct psi *alloc_psi(struct proc_chip *chip, uint64_t base)
{
	struct psi *psi;

	psi = zalloc(sizeof(struct psi));
	if (!psi) {
		prerror("PSI: Could not allocate memory\n");
		return NULL;
	}
	psi->xscom_base = base;
	psi->chip_id = chip->id;
	return psi;
}

static struct psi *psi_probe_p8(struct proc_chip *chip, u64 base)
{
	struct psi *psi = NULL;
	uint64_t rc, val;

	rc = xscom_read(chip->id, base + PSIHB_XSCOM_P8_BASE, &val);
	if (rc) {
		prerror("PSI[0x%03x]: Error %llx reading PSIHB BAR\n",
			chip->id, rc);
		return NULL;
	}
	if (val & PSIHB_XSCOM_P8_HBBAR_EN) {
		psi = alloc_psi(chip, base);
		if (!psi)
			return NULL;
		psi->regs = (void *)(val & ~PSIHB_XSCOM_P8_HBBAR_EN);
		psi->interrupt = get_psi_interrupt(chip->id);
	} else
		printf("PSI[0x%03x]: Working chip not found\n", chip->id);

	return psi;
}

static struct psi *psi_probe_p9(struct proc_chip *chip, u64 base)
{
	struct psi *psi = NULL;
	uint64_t addr;

	phys_map_get(chip->id, PSIHB_REG, 0, &addr, NULL);
	xscom_write(chip->id, base + PSIHB_XSCOM_P9_BASE,
		    addr | PSIHB_XSCOM_P9_HBBAR_EN);

	psi = alloc_psi(chip, base);
	if (!psi)
		return NULL;
	psi->regs = (void *)addr;
	psi->interrupt = xive_alloc_hw_irqs(chip->id, P9_PSI_NUM_IRQS, 16);
	return psi;
}

static struct psi *psi_probe_p10(struct proc_chip *chip, u64 base)
{
	struct psi *psi = NULL;
	uint64_t addr;

	phys_map_get(chip->id, PSIHB_REG, 0, &addr, NULL);
	xscom_write(chip->id, base + PSIHB_XSCOM_P9_BASE,
		    addr | PSIHB_XSCOM_P9_HBBAR_EN);

	psi = alloc_psi(chip, base);
	if (!psi)
		return NULL;
	psi->regs = (void *)addr;
	psi->interrupt = xive2_alloc_hw_irqs(chip->id, P9_PSI_NUM_IRQS, 16);
	return psi;
}

static bool psi_init_psihb(struct dt_node *psihb)
{
	uint32_t chip_id = dt_get_chip_id(psihb);
	struct proc_chip *chip = get_chip(chip_id);
	struct psi *psi = NULL;
	u64 base, val;

	if (!chip) {
		prerror("PSI: Can't find chip!\n");
		return false;
	}

	base = dt_get_address(psihb, 0, NULL);

	if (dt_node_is_compatible(psihb, "ibm,power8-psihb-x"))
		psi = psi_probe_p8(chip, base);
	else if (dt_node_is_compatible(psihb, "ibm,power9-psihb-x"))
		psi = psi_probe_p9(chip, base);
	else if (dt_node_is_compatible(psihb, "ibm,power10-psihb-x"))
		psi = psi_probe_p10(chip, base);
	else {
		prerror("PSI: Unknown processor type\n");
		return false;
	}
	if (!psi)
		return false;

	list_add(&psis, &psi->list);

	val = in_be64(psi->regs + PSIHB_CR);
	if (val & PSIHB_CR_FSP_LINK_ACTIVE) {
		lock(&psi_lock);
		psi->active = true;
		unlock(&psi_lock);
	}
	chip->psi = psi;

	if (dt_has_node_property(psihb, "no-lpc-interrupts", NULL))
		psi->no_lpc_irqs = true;

	psi_activate_phb(psi);
	psi_init_interrupts(psi);
	psi_create_mm_dtnode(psi);

	prlog(PR_INFO, "PSI[0x%03x]: Found PSI bridge [active=%d]\n",
	      psi->chip_id, psi->active);
	return true;
}

void psi_fsp_link_in_use(struct psi *psi __unused)
{
	static bool poller_created = false;

	/* Do this once only */
	if (!poller_created) {
		poller_created = true;
		opal_add_poller(psi_link_poll, NULL);
	}
}

struct psi *psi_find_functional_chip(void)
{
	return list_top(&psis, struct psi, list);
}

void psi_init(void)
{
	struct dt_node *np;

	dt_for_each_compatible(dt_root, np, "ibm,psihb-x")
		psi_init_psihb(np);
}


