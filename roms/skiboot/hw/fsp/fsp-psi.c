// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#include <io.h>
#include <psi.h>
#include <lock.h>
#include <fsp.h>

static void psi_tce_enable(struct psi *psi, bool enable)
{
	void *addr = psi->regs + PSIHB_PHBSCR;
	u64 val;

	val = in_be64(addr);
	if (enable)
		val |=  PSIHB_PHBSCR_TCE_ENABLE;
	else
		val &= ~PSIHB_PHBSCR_TCE_ENABLE;
	out_be64(addr, val);
}

/*
 * Configure the PSI interface for communicating with
 * an FSP, such as enabling the TCEs, FSP commands,
 * etc...
 */
void psi_init_for_fsp(struct psi *psi)
{
	uint64_t reg;
	bool enable_tce = true;

	lock(&psi_lock);

	/* Disable and setup TCE base address */
	psi_tce_enable(psi, false);

	switch (proc_gen) {
	case proc_gen_p8:
	case proc_gen_p9:
	case proc_gen_p10:
		out_be64(psi->regs + PSIHB_TAR, PSI_TCE_TABLE_BASE |
			 PSIHB_TAR_256K_ENTRIES);
		break;
	default:
		enable_tce = false;
	};

	/* Enable various other configuration register bits based
	 * on what pHyp does. We keep interrupts disabled until
	 * after the mailbox has been properly configured. We assume
	 * basic stuff such as PSI link enable is already there.
	 *
	 *  - FSP CMD Enable
	 *  - FSP MMIO Enable
	 *  - TCE Enable
	 *  - Error response enable
	 *
	 * Clear all other error bits
	 */
	if (!psi->active) {
		prerror("PSI: psi_init_for_fsp() called on inactive link!\n");
		unlock(&psi_lock);
		return;
	}

	reg = in_be64(psi->regs + PSIHB_CR);
	reg |= PSIHB_CR_FSP_CMD_ENABLE;
	reg |= PSIHB_CR_FSP_MMIO_ENABLE;
	reg |= PSIHB_CR_FSP_ERR_RSP_ENABLE;
	reg &= ~0x00000000ffffffffull;
	out_be64(psi->regs + PSIHB_CR, reg);
	psi_tce_enable(psi, enable_tce);

	unlock(&psi_lock);
}
