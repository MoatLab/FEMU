/*
 * Copyright (c) 2010-2011 Atheros Communications Inc.
 *
 * Modified for iPXE by Scott K Logan <logans@cottsay.net> July 2011
 * Original from Linux kernel 3.0.1
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <ipxe/io.h>

#include "hw.h"
#include "hw-ops.h"
#include "ar9003_phy.h"

#define MAX_MEASUREMENT	8
#define MAX_MAG_DELTA	11
#define MAX_PHS_DELTA	10

struct coeff {
	int mag_coeff[AR9300_MAX_CHAINS][MAX_MEASUREMENT];
	int phs_coeff[AR9300_MAX_CHAINS][MAX_MEASUREMENT];
	int iqc_coeff[2];
};

enum ar9003_cal_types {
	IQ_MISMATCH_CAL = BIT(0),
	TEMP_COMP_CAL = BIT(1),
};

static void ar9003_hw_setup_calibration(struct ath_hw *ah,
					struct ath9k_cal_list *currCal)
{
	/* Select calibration to run */
	switch (currCal->calData->calType) {
	case IQ_MISMATCH_CAL:
		/*
		 * Start calibration with
		 * 2^(INIT_IQCAL_LOG_COUNT_MAX+1) samples
		 */
		REG_RMW_FIELD(ah, AR_PHY_TIMING4,
			      AR_PHY_TIMING4_IQCAL_LOG_COUNT_MAX,
		currCal->calData->calCountMax);
		REG_WRITE(ah, AR_PHY_CALMODE, AR_PHY_CALMODE_IQ);

		DBG2("ath9k: "
			"starting IQ Mismatch Calibration\n");

		/* Kick-off cal */
		REG_SET_BIT(ah, AR_PHY_TIMING4, AR_PHY_TIMING4_DO_CAL);
		break;
	case TEMP_COMP_CAL:
		REG_RMW_FIELD(ah, AR_PHY_65NM_CH0_THERM,
			      AR_PHY_65NM_CH0_THERM_LOCAL, 1);
		REG_RMW_FIELD(ah, AR_PHY_65NM_CH0_THERM,
			      AR_PHY_65NM_CH0_THERM_START, 1);

		DBG2("ath9k: "
			"starting Temperature Compensation Calibration\n");
		break;
	}
}

/*
 * Generic calibration routine.
 * Recalibrate the lower PHY chips to account for temperature/environment
 * changes.
 */
static int ar9003_hw_per_calibration(struct ath_hw *ah,
				      struct ath9k_channel *ichan __unused,
				      u8 rxchainmask,
				      struct ath9k_cal_list *currCal)
{
	struct ath9k_hw_cal_data *caldata = ah->caldata;
	/* Cal is assumed not done until explicitly set below */
	int iscaldone = 0;

	/* Calibration in progress. */
	if (currCal->calState == CAL_RUNNING) {
		/* Check to see if it has finished. */
		if (!(REG_READ(ah, AR_PHY_TIMING4) & AR_PHY_TIMING4_DO_CAL)) {
			/*
			* Accumulate cal measures for active chains
			*/
			currCal->calData->calCollect(ah);
			ah->cal_samples++;

			if (ah->cal_samples >=
			    currCal->calData->calNumSamples) {
				unsigned int i, numChains = 0;
				for (i = 0; i < AR9300_MAX_CHAINS; i++) {
					if (rxchainmask & (1 << i))
						numChains++;
				}

				/*
				* Process accumulated data
				*/
				currCal->calData->calPostProc(ah, numChains);

				/* Calibration has finished. */
				caldata->CalValid |= currCal->calData->calType;
				currCal->calState = CAL_DONE;
				iscaldone = 1;
			} else {
			/*
			 * Set-up collection of another sub-sample until we
			 * get desired number
			 */
			ar9003_hw_setup_calibration(ah, currCal);
			}
		}
	} else if (!(caldata->CalValid & currCal->calData->calType)) {
		/* If current cal is marked invalid in channel, kick it off */
		ath9k_hw_reset_calibration(ah, currCal);
	}

	return iscaldone;
}

static int ar9003_hw_calibrate(struct ath_hw *ah,
				struct ath9k_channel *chan,
				u8 rxchainmask,
				int longcal)
{
	int iscaldone = 1;
	struct ath9k_cal_list *currCal = ah->cal_list_curr;

	/*
	 * For given calibration:
	 * 1. Call generic cal routine
	 * 2. When this cal is done (isCalDone) if we have more cals waiting
	 *    (eg after reset), mask this to upper layers by not propagating
	 *    isCalDone if it is set to TRUE.
	 *    Instead, change isCalDone to FALSE and setup the waiting cal(s)
	 *    to be run.
	 */
	if (currCal &&
	    (currCal->calState == CAL_RUNNING ||
	     currCal->calState == CAL_WAITING)) {
		iscaldone = ar9003_hw_per_calibration(ah, chan,
						      rxchainmask, currCal);
		if (iscaldone) {
			ah->cal_list_curr = currCal = currCal->calNext;

			if (currCal->calState == CAL_WAITING) {
				iscaldone = 0;
				ath9k_hw_reset_calibration(ah, currCal);
			}
		}
	}

	/* Do NF cal only at longer intervals */
	if (longcal) {
		/*
		 * Get the value from the previous NF cal and update
		 * history buffer.
		 */
		ath9k_hw_getnf(ah, chan);

		/*
		 * Load the NF from history buffer of the current channel.
		 * NF is slow time-variant, so it is OK to use a historical
		 * value.
		 */
		ath9k_hw_loadnf(ah, ah->curchan);

		/* start NF calibration, without updating BB NF register */
		ath9k_hw_start_nfcal(ah, 0);
	}

	return iscaldone;
}

static void ar9003_hw_iqcal_collect(struct ath_hw *ah)
{
	int i;

	/* Accumulate IQ cal measures for active chains */
	for (i = 0; i < AR5416_MAX_CHAINS; i++) {
		if (ah->txchainmask & BIT(i)) {
			ah->totalPowerMeasI[i] +=
				REG_READ(ah, AR_PHY_CAL_MEAS_0(i));
			ah->totalPowerMeasQ[i] +=
				REG_READ(ah, AR_PHY_CAL_MEAS_1(i));
			ah->totalIqCorrMeas[i] +=
				(int32_t) REG_READ(ah, AR_PHY_CAL_MEAS_2(i));
			DBG2("ath9k: "
				"%d: Chn %d pmi=0x%08x;pmq=0x%08x;iqcm=0x%08x;\n",
				ah->cal_samples, i, ah->totalPowerMeasI[i],
				ah->totalPowerMeasQ[i],
				ah->totalIqCorrMeas[i]);
		}
	}
}

static void ar9003_hw_iqcalibrate(struct ath_hw *ah, u8 numChains)
{
	u32 powerMeasQ, powerMeasI, iqCorrMeas;
	u32 qCoffDenom, iCoffDenom;
	int32_t qCoff, iCoff;
	int iqCorrNeg, i;
	static const uint32_t offset_array[3] = {
		AR_PHY_RX_IQCAL_CORR_B0,
		AR_PHY_RX_IQCAL_CORR_B1,
		AR_PHY_RX_IQCAL_CORR_B2,
	};

	for (i = 0; i < numChains; i++) {
		powerMeasI = ah->totalPowerMeasI[i];
		powerMeasQ = ah->totalPowerMeasQ[i];
		iqCorrMeas = ah->totalIqCorrMeas[i];

		DBG2("ath9k: "
			"Starting IQ Cal and Correction for Chain %d\n",
			i);

		DBG2("ath9k: "
			"Orignal: Chn %diq_corr_meas = 0x%08x\n",
			i, ah->totalIqCorrMeas[i]);

		iqCorrNeg = 0;

		if (iqCorrMeas > 0x80000000) {
			iqCorrMeas = (0xffffffff - iqCorrMeas) + 1;
			iqCorrNeg = 1;
		}

		DBG2("ath9k: "
			"Chn %d pwr_meas_i = 0x%08x\n", i, powerMeasI);
		DBG2("ath9k: "
			"Chn %d pwr_meas_q = 0x%08x\n", i, powerMeasQ);
		DBG2("ath9k: iqCorrNeg is 0x%08x\n",
			iqCorrNeg);

		iCoffDenom = (powerMeasI / 2 + powerMeasQ / 2) / 256;
		qCoffDenom = powerMeasQ / 64;

		if ((iCoffDenom != 0) && (qCoffDenom != 0)) {
			iCoff = iqCorrMeas / iCoffDenom;
			qCoff = powerMeasI / qCoffDenom - 64;
			DBG2("ath9k: "
				"Chn %d iCoff = 0x%08x\n", i, iCoff);
			DBG2("ath9k: "
				"Chn %d qCoff = 0x%08x\n", i, qCoff);

			/* Force bounds on iCoff */
			if (iCoff >= 63)
				iCoff = 63;
			else if (iCoff <= -63)
				iCoff = -63;

			/* Negate iCoff if iqCorrNeg == 0 */
			if (iqCorrNeg == 0x0)
				iCoff = -iCoff;

			/* Force bounds on qCoff */
			if (qCoff >= 63)
				qCoff = 63;
			else if (qCoff <= -63)
				qCoff = -63;

			iCoff = iCoff & 0x7f;
			qCoff = qCoff & 0x7f;

			DBG2("ath9k: "
				"Chn %d : iCoff = 0x%x  qCoff = 0x%x\n",
				i, iCoff, qCoff);
			DBG2("ath9k: "
				"Register offset (0x%04x) before update = 0x%x\n",
				offset_array[i],
				REG_READ(ah, offset_array[i]));

			REG_RMW_FIELD(ah, offset_array[i],
				      AR_PHY_RX_IQCAL_CORR_IQCORR_Q_I_COFF,
				      iCoff);
			REG_RMW_FIELD(ah, offset_array[i],
				      AR_PHY_RX_IQCAL_CORR_IQCORR_Q_Q_COFF,
				      qCoff);
			DBG2("ath9k: "
				"Register offset (0x%04x) QI COFF (bitfields 0x%08x) after update = 0x%x\n",
				offset_array[i],
				AR_PHY_RX_IQCAL_CORR_IQCORR_Q_I_COFF,
				REG_READ(ah, offset_array[i]));
			DBG2("ath9k: "
				"Register offset (0x%04x) QQ COFF (bitfields 0x%08x) after update = 0x%x\n",
				offset_array[i],
				AR_PHY_RX_IQCAL_CORR_IQCORR_Q_Q_COFF,
				REG_READ(ah, offset_array[i]));

			DBG2("ath9k: "
				"IQ Cal and Correction done for Chain %d\n", i);
		}
	}

	REG_SET_BIT(ah, AR_PHY_RX_IQCAL_CORR_B0,
		    AR_PHY_RX_IQCAL_CORR_IQCORR_ENABLE);
	DBG2("ath9k: "
		"IQ Cal and Correction (offset 0x%04x) enabled (bit position 0x%08x). New Value 0x%08x\n",
		(unsigned) (AR_PHY_RX_IQCAL_CORR_B0),
		AR_PHY_RX_IQCAL_CORR_IQCORR_ENABLE,
		REG_READ(ah, AR_PHY_RX_IQCAL_CORR_B0));
}

static const struct ath9k_percal_data iq_cal_single_sample = {
	IQ_MISMATCH_CAL,
	MIN_CAL_SAMPLES,
	PER_MAX_LOG_COUNT,
	ar9003_hw_iqcal_collect,
	ar9003_hw_iqcalibrate
};

static void ar9003_hw_init_cal_settings(struct ath_hw *ah)
{
	ah->iq_caldata.calData = &iq_cal_single_sample;
}

/*
 * solve 4x4 linear equation used in loopback iq cal.
 */
static int ar9003_hw_solve_iq_cal(struct ath_hw *ah __unused,
				   s32 sin_2phi_1,
				   s32 cos_2phi_1,
				   s32 sin_2phi_2,
				   s32 cos_2phi_2,
				   s32 mag_a0_d0,
				   s32 phs_a0_d0,
				   s32 mag_a1_d0,
				   s32 phs_a1_d0,
				   s32 solved_eq[])
{
	s32 f1 = cos_2phi_1 - cos_2phi_2,
	    f3 = sin_2phi_1 - sin_2phi_2,
	    f2;
	s32 mag_tx, phs_tx, mag_rx, phs_rx;
	const s32 result_shift = 1 << 15;

	f2 = (f1 * f1 + f3 * f3) / result_shift;

	if (!f2) {
		DBG("ath9k: Divide by 0\n");
		return 0;
	}

	/* mag mismatch, tx */
	mag_tx = f1 * (mag_a0_d0  - mag_a1_d0) + f3 * (phs_a0_d0 - phs_a1_d0);
	/* phs mismatch, tx */
	phs_tx = f3 * (-mag_a0_d0 + mag_a1_d0) + f1 * (phs_a0_d0 - phs_a1_d0);

	mag_tx = (mag_tx / f2);
	phs_tx = (phs_tx / f2);

	/* mag mismatch, rx */
	mag_rx = mag_a0_d0 - (cos_2phi_1 * mag_tx + sin_2phi_1 * phs_tx) /
		 result_shift;
	/* phs mismatch, rx */
	phs_rx = phs_a0_d0 + (sin_2phi_1 * mag_tx - cos_2phi_1 * phs_tx) /
		 result_shift;

	solved_eq[0] = mag_tx;
	solved_eq[1] = phs_tx;
	solved_eq[2] = mag_rx;
	solved_eq[3] = phs_rx;

	return 1;
}

static s32 ar9003_hw_find_mag_approx(struct ath_hw *ah __unused, s32 in_re, s32 in_im)
{
	s32 abs_i = abs(in_re),
	    abs_q = abs(in_im),
	    max_abs, min_abs;

	if (abs_i > abs_q) {
		max_abs = abs_i;
		min_abs = abs_q;
	} else {
		max_abs = abs_q;
		min_abs = abs_i;
	}

	return max_abs - (max_abs / 32) + (min_abs / 8) + (min_abs / 4);
}

#define DELPT 32

static int ar9003_hw_calc_iq_corr(struct ath_hw *ah,
				   s32 chain_idx,
				   const s32 iq_res[],
				   s32 iqc_coeff[])
{
	s32 i2_m_q2_a0_d0, i2_p_q2_a0_d0, iq_corr_a0_d0,
	    i2_m_q2_a0_d1, i2_p_q2_a0_d1, iq_corr_a0_d1,
	    i2_m_q2_a1_d0, i2_p_q2_a1_d0, iq_corr_a1_d0,
	    i2_m_q2_a1_d1, i2_p_q2_a1_d1, iq_corr_a1_d1;
	s32 mag_a0_d0, mag_a1_d0, mag_a0_d1, mag_a1_d1,
	    phs_a0_d0, phs_a1_d0, phs_a0_d1, phs_a1_d1,
	    sin_2phi_1, cos_2phi_1,
	    sin_2phi_2, cos_2phi_2;
	s32 mag_tx, phs_tx, mag_rx, phs_rx;
	s32 solved_eq[4], mag_corr_tx, phs_corr_tx, mag_corr_rx, phs_corr_rx,
	    q_q_coff, q_i_coff;
	const s32 res_scale = 1 << 15;
	const s32 delpt_shift = 1 << 8;
	s32 mag1, mag2;

	i2_m_q2_a0_d0 = iq_res[0] & 0xfff;
	i2_p_q2_a0_d0 = (iq_res[0] >> 12) & 0xfff;
	iq_corr_a0_d0 = ((iq_res[0] >> 24) & 0xff) + ((iq_res[1] & 0xf) << 8);

	if (i2_m_q2_a0_d0 > 0x800)
		i2_m_q2_a0_d0 = -((0xfff - i2_m_q2_a0_d0) + 1);

	if (i2_p_q2_a0_d0 > 0x800)
		i2_p_q2_a0_d0 = -((0xfff - i2_p_q2_a0_d0) + 1);

	if (iq_corr_a0_d0 > 0x800)
		iq_corr_a0_d0 = -((0xfff - iq_corr_a0_d0) + 1);

	i2_m_q2_a0_d1 = (iq_res[1] >> 4) & 0xfff;
	i2_p_q2_a0_d1 = (iq_res[2] & 0xfff);
	iq_corr_a0_d1 = (iq_res[2] >> 12) & 0xfff;

	if (i2_m_q2_a0_d1 > 0x800)
		i2_m_q2_a0_d1 = -((0xfff - i2_m_q2_a0_d1) + 1);

	if (i2_p_q2_a0_d1 > 0x800)
		i2_p_q2_a0_d1 = -((0xfff - i2_p_q2_a0_d1) + 1);

	if (iq_corr_a0_d1 > 0x800)
		iq_corr_a0_d1 = -((0xfff - iq_corr_a0_d1) + 1);

	i2_m_q2_a1_d0 = ((iq_res[2] >> 24) & 0xff) + ((iq_res[3] & 0xf) << 8);
	i2_p_q2_a1_d0 = (iq_res[3] >> 4) & 0xfff;
	iq_corr_a1_d0 = iq_res[4] & 0xfff;

	if (i2_m_q2_a1_d0 > 0x800)
		i2_m_q2_a1_d0 = -((0xfff - i2_m_q2_a1_d0) + 1);

	if (i2_p_q2_a1_d0 > 0x800)
		i2_p_q2_a1_d0 = -((0xfff - i2_p_q2_a1_d0) + 1);

	if (iq_corr_a1_d0 > 0x800)
		iq_corr_a1_d0 = -((0xfff - iq_corr_a1_d0) + 1);

	i2_m_q2_a1_d1 = (iq_res[4] >> 12) & 0xfff;
	i2_p_q2_a1_d1 = ((iq_res[4] >> 24) & 0xff) + ((iq_res[5] & 0xf) << 8);
	iq_corr_a1_d1 = (iq_res[5] >> 4) & 0xfff;

	if (i2_m_q2_a1_d1 > 0x800)
		i2_m_q2_a1_d1 = -((0xfff - i2_m_q2_a1_d1) + 1);

	if (i2_p_q2_a1_d1 > 0x800)
		i2_p_q2_a1_d1 = -((0xfff - i2_p_q2_a1_d1) + 1);

	if (iq_corr_a1_d1 > 0x800)
		iq_corr_a1_d1 = -((0xfff - iq_corr_a1_d1) + 1);

	if ((i2_p_q2_a0_d0 == 0) || (i2_p_q2_a0_d1 == 0) ||
	    (i2_p_q2_a1_d0 == 0) || (i2_p_q2_a1_d1 == 0)) {
		DBG("ath9k: "
			"Divide by 0:\n"
			"a0_d0=%d\n"
			"a0_d1=%d\n"
			"a2_d0=%d\n"
			"a1_d1=%d\n",
			i2_p_q2_a0_d0, i2_p_q2_a0_d1,
			i2_p_q2_a1_d0, i2_p_q2_a1_d1);
		return 0;
	}

	mag_a0_d0 = (i2_m_q2_a0_d0 * res_scale) / i2_p_q2_a0_d0;
	phs_a0_d0 = (iq_corr_a0_d0 * res_scale) / i2_p_q2_a0_d0;

	mag_a0_d1 = (i2_m_q2_a0_d1 * res_scale) / i2_p_q2_a0_d1;
	phs_a0_d1 = (iq_corr_a0_d1 * res_scale) / i2_p_q2_a0_d1;

	mag_a1_d0 = (i2_m_q2_a1_d0 * res_scale) / i2_p_q2_a1_d0;
	phs_a1_d0 = (iq_corr_a1_d0 * res_scale) / i2_p_q2_a1_d0;

	mag_a1_d1 = (i2_m_q2_a1_d1 * res_scale) / i2_p_q2_a1_d1;
	phs_a1_d1 = (iq_corr_a1_d1 * res_scale) / i2_p_q2_a1_d1;

	/* w/o analog phase shift */
	sin_2phi_1 = (((mag_a0_d0 - mag_a0_d1) * delpt_shift) / DELPT);
	/* w/o analog phase shift */
	cos_2phi_1 = (((phs_a0_d1 - phs_a0_d0) * delpt_shift) / DELPT);
	/* w/  analog phase shift */
	sin_2phi_2 = (((mag_a1_d0 - mag_a1_d1) * delpt_shift) / DELPT);
	/* w/  analog phase shift */
	cos_2phi_2 = (((phs_a1_d1 - phs_a1_d0) * delpt_shift) / DELPT);

	/*
	 * force sin^2 + cos^2 = 1;
	 * find magnitude by approximation
	 */
	mag1 = ar9003_hw_find_mag_approx(ah, cos_2phi_1, sin_2phi_1);
	mag2 = ar9003_hw_find_mag_approx(ah, cos_2phi_2, sin_2phi_2);

	if ((mag1 == 0) || (mag2 == 0)) {
		DBG("ath9k: "
			"Divide by 0: mag1=%d, mag2=%d\n",
			mag1, mag2);
		return 0;
	}

	/* normalization sin and cos by mag */
	sin_2phi_1 = (sin_2phi_1 * res_scale / mag1);
	cos_2phi_1 = (cos_2phi_1 * res_scale / mag1);
	sin_2phi_2 = (sin_2phi_2 * res_scale / mag2);
	cos_2phi_2 = (cos_2phi_2 * res_scale / mag2);

	/* calculate IQ mismatch */
	if (!ar9003_hw_solve_iq_cal(ah,
			     sin_2phi_1, cos_2phi_1,
			     sin_2phi_2, cos_2phi_2,
			     mag_a0_d0, phs_a0_d0,
			     mag_a1_d0,
			     phs_a1_d0, solved_eq)) {
		DBG("ath9k: "
			"Call to ar9003_hw_solve_iq_cal() failed.\n");
		return 0;
	}

	mag_tx = solved_eq[0];
	phs_tx = solved_eq[1];
	mag_rx = solved_eq[2];
	phs_rx = solved_eq[3];

	DBG2("ath9k: "
		"chain %d: mag mismatch=%d phase mismatch=%d\n",
		chain_idx, mag_tx/res_scale, phs_tx/res_scale);

	if (res_scale == mag_tx) {
		DBG("ath9k: "
			"Divide by 0: mag_tx=%d, res_scale=%d\n",
			mag_tx, res_scale);
		return 0;
	}

	/* calculate and quantize Tx IQ correction factor */
	mag_corr_tx = (mag_tx * res_scale) / (res_scale - mag_tx);
	phs_corr_tx = -phs_tx;

	q_q_coff = (mag_corr_tx * 128 / res_scale);
	q_i_coff = (phs_corr_tx * 256 / res_scale);

	DBG2("ath9k: "
		"tx chain %d: mag corr=%d  phase corr=%d\n",
		chain_idx, q_q_coff, q_i_coff);

	if (q_i_coff < -63)
		q_i_coff = -63;
	if (q_i_coff > 63)
		q_i_coff = 63;
	if (q_q_coff < -63)
		q_q_coff = -63;
	if (q_q_coff > 63)
		q_q_coff = 63;

	iqc_coeff[0] = (q_q_coff * 128) + q_i_coff;

	DBG2("ath9k: "
		"tx chain %d: iq corr coeff=%x\n",
		chain_idx, iqc_coeff[0]);

	if (-mag_rx == res_scale) {
		DBG("ath9k: "
			"Divide by 0: mag_rx=%d, res_scale=%d\n",
			mag_rx, res_scale);
		return 0;
	}

	/* calculate and quantize Rx IQ correction factors */
	mag_corr_rx = (-mag_rx * res_scale) / (res_scale + mag_rx);
	phs_corr_rx = -phs_rx;

	q_q_coff = (mag_corr_rx * 128 / res_scale);
	q_i_coff = (phs_corr_rx * 256 / res_scale);

	DBG("ath9k: "
		"rx chain %d: mag corr=%d  phase corr=%d\n",
		chain_idx, q_q_coff, q_i_coff);

	if (q_i_coff < -63)
		q_i_coff = -63;
	if (q_i_coff > 63)
		q_i_coff = 63;
	if (q_q_coff < -63)
		q_q_coff = -63;
	if (q_q_coff > 63)
		q_q_coff = 63;

	iqc_coeff[1] = (q_q_coff * 128) + q_i_coff;

	DBG2("ath9k: "
		"rx chain %d: iq corr coeff=%x\n",
		chain_idx, iqc_coeff[1]);

	return 1;
}

static void ar9003_hw_detect_outlier(int *mp_coeff, int nmeasurement,
				     int max_delta)
{
	int mp_max = -64, max_idx = 0;
	int mp_min = 63, min_idx = 0;
	int mp_avg = 0, i, outlier_idx = 0;

	/* find min/max mismatch across all calibrated gains */
	for (i = 0; i < nmeasurement; i++) {
		mp_avg += mp_coeff[i];
		if (mp_coeff[i] > mp_max) {
			mp_max = mp_coeff[i];
			max_idx = i;
		} else if (mp_coeff[i] < mp_min) {
			mp_min = mp_coeff[i];
			min_idx = i;
		}
	}

	/* find average (exclude max abs value) */
	for (i = 0; i < nmeasurement; i++) {
		if ((abs(mp_coeff[i]) < abs(mp_max)) ||
		    (abs(mp_coeff[i]) < abs(mp_min)))
			mp_avg += mp_coeff[i];
	}
	mp_avg /= (nmeasurement - 1);

	/* detect outlier */
	if (abs(mp_max - mp_min) > max_delta) {
		if (abs(mp_max - mp_avg) > abs(mp_min - mp_avg))
			outlier_idx = max_idx;
		else
			outlier_idx = min_idx;
	}
	mp_coeff[outlier_idx] = mp_avg;
}

static void ar9003_hw_tx_iqcal_load_avg_2_passes(struct ath_hw *ah,
						 u8 num_chains,
						 struct coeff *coeff)
{
	int i, im, nmeasurement;
	u32 tx_corr_coeff[MAX_MEASUREMENT][AR9300_MAX_CHAINS];

	memset(tx_corr_coeff, 0, sizeof(tx_corr_coeff));
	for (i = 0; i < MAX_MEASUREMENT / 2; i++) {
		tx_corr_coeff[i * 2][0] = tx_corr_coeff[(i * 2) + 1][0] =
					AR_PHY_TX_IQCAL_CORR_COEFF_B0(i);
		if (!AR_SREV_9485(ah)) {
			tx_corr_coeff[i * 2][1] =
			tx_corr_coeff[(i * 2) + 1][1] =
					AR_PHY_TX_IQCAL_CORR_COEFF_B1(i);

			tx_corr_coeff[i * 2][2] =
			tx_corr_coeff[(i * 2) + 1][2] =
					AR_PHY_TX_IQCAL_CORR_COEFF_B2(i);
		}
	}

	/* Load the average of 2 passes */
	for (i = 0; i < num_chains; i++) {
		nmeasurement = REG_READ_FIELD(ah,
				AR_PHY_TX_IQCAL_STATUS_B0,
				AR_PHY_CALIBRATED_GAINS_0);

		if (nmeasurement > MAX_MEASUREMENT)
			nmeasurement = MAX_MEASUREMENT;

		/* detect outlier only if nmeasurement > 1 */
		if (nmeasurement > 1) {
			/* Detect magnitude outlier */
			ar9003_hw_detect_outlier(coeff->mag_coeff[i],
					nmeasurement, MAX_MAG_DELTA);

			/* Detect phase outlier */
			ar9003_hw_detect_outlier(coeff->phs_coeff[i],
					nmeasurement, MAX_PHS_DELTA);
		}

		for (im = 0; im < nmeasurement; im++) {

			coeff->iqc_coeff[0] = (coeff->mag_coeff[i][im] & 0x7f) |
				((coeff->phs_coeff[i][im] & 0x7f) << 7);

			if ((im % 2) == 0)
				REG_RMW_FIELD(ah, tx_corr_coeff[im][i],
					AR_PHY_TX_IQCAL_CORR_COEFF_00_COEFF_TABLE,
					coeff->iqc_coeff[0]);
			else
				REG_RMW_FIELD(ah, tx_corr_coeff[im][i],
					AR_PHY_TX_IQCAL_CORR_COEFF_01_COEFF_TABLE,
					coeff->iqc_coeff[0]);
		}
	}

	REG_RMW_FIELD(ah, AR_PHY_TX_IQCAL_CONTROL_3,
		      AR_PHY_TX_IQCAL_CONTROL_3_IQCORR_EN, 0x1);
	REG_RMW_FIELD(ah, AR_PHY_RX_IQCAL_CORR_B0,
		      AR_PHY_RX_IQCAL_CORR_B0_LOOPBACK_IQCORR_EN, 0x1);

	return;

}

static int ar9003_hw_tx_iq_cal_run(struct ath_hw *ah)
{
	u8 tx_gain_forced;

	tx_gain_forced = REG_READ_FIELD(ah, AR_PHY_TX_FORCED_GAIN,
					AR_PHY_TXGAIN_FORCE);
	if (tx_gain_forced)
		REG_RMW_FIELD(ah, AR_PHY_TX_FORCED_GAIN,
			      AR_PHY_TXGAIN_FORCE, 0);

	REG_RMW_FIELD(ah, AR_PHY_TX_IQCAL_START,
		      AR_PHY_TX_IQCAL_START_DO_CAL, 1);

	if (!ath9k_hw_wait(ah, AR_PHY_TX_IQCAL_START,
			AR_PHY_TX_IQCAL_START_DO_CAL, 0,
			AH_WAIT_TIMEOUT)) {
		DBG2("ath9k: "
			"Tx IQ Cal is not completed.\n");
		return 0;
	}
	return 1;
}

static void ar9003_hw_tx_iq_cal_post_proc(struct ath_hw *ah)
{
	const u32 txiqcal_status[AR9300_MAX_CHAINS] = {
		AR_PHY_TX_IQCAL_STATUS_B0,
		AR_PHY_TX_IQCAL_STATUS_B1,
		AR_PHY_TX_IQCAL_STATUS_B2,
	};
	const uint32_t chan_info_tab[] = {
		AR_PHY_CHAN_INFO_TAB_0,
		AR_PHY_CHAN_INFO_TAB_1,
		AR_PHY_CHAN_INFO_TAB_2,
	};
	struct coeff coeff;
	s32 iq_res[6];
	u8 num_chains = 0;
	int i, im, j;
	int nmeasurement;

	for (i = 0; i < AR9300_MAX_CHAINS; i++) {
		if (ah->txchainmask & (1 << i))
			num_chains++;
	}

	for (i = 0; i < num_chains; i++) {
		nmeasurement = REG_READ_FIELD(ah,
				AR_PHY_TX_IQCAL_STATUS_B0,
				AR_PHY_CALIBRATED_GAINS_0);
		if (nmeasurement > MAX_MEASUREMENT)
			nmeasurement = MAX_MEASUREMENT;

		for (im = 0; im < nmeasurement; im++) {
			DBG2("ath9k: "
				"Doing Tx IQ Cal for chain %d.\n", i);

			if (REG_READ(ah, txiqcal_status[i]) &
					AR_PHY_TX_IQCAL_STATUS_FAILED) {
				DBG("ath9k: "
					"Tx IQ Cal failed for chain %d.\n", i);
				goto tx_iqcal_fail;
			}

			for (j = 0; j < 3; j++) {
				u32 idx = 2 * j, offset = 4 * (3 * im + j);

				REG_RMW_FIELD(ah,
						AR_PHY_CHAN_INFO_MEMORY,
						AR_PHY_CHAN_INFO_TAB_S2_READ,
						0);

				/* 32 bits */
				iq_res[idx] = REG_READ(ah,
						chan_info_tab[i] +
						offset);

				REG_RMW_FIELD(ah,
						AR_PHY_CHAN_INFO_MEMORY,
						AR_PHY_CHAN_INFO_TAB_S2_READ,
						1);

				/* 16 bits */
				iq_res[idx + 1] = 0xffff & REG_READ(ah,
						chan_info_tab[i] + offset);

				DBG2("ath9k: "
					"IQ RES[%d]=0x%x"
					"IQ_RES[%d]=0x%x\n",
					idx, iq_res[idx], idx + 1,
					iq_res[idx + 1]);
			}

			if (!ar9003_hw_calc_iq_corr(ah, i, iq_res,
						coeff.iqc_coeff)) {
				DBG("ath9k: "
					"Failed in calculation of \
					IQ correction.\n");
				goto tx_iqcal_fail;
			}

			coeff.mag_coeff[i][im] = coeff.iqc_coeff[0] & 0x7f;
			coeff.phs_coeff[i][im] =
				(coeff.iqc_coeff[0] >> 7) & 0x7f;

			if (coeff.mag_coeff[i][im] > 63)
				coeff.mag_coeff[i][im] -= 128;
			if (coeff.phs_coeff[i][im] > 63)
				coeff.phs_coeff[i][im] -= 128;
		}
	}
	ar9003_hw_tx_iqcal_load_avg_2_passes(ah, num_chains, &coeff);

	return;

tx_iqcal_fail:
	DBG("ath9k: Tx IQ Cal failed\n");
	return;
}
static int ar9003_hw_init_cal(struct ath_hw *ah,
			       struct ath9k_channel *chan __unused)
{
	struct ath9k_hw_capabilities *pCap = &ah->caps;
	int val;
	int txiqcal_done = 0;

	val = REG_READ(ah, AR_ENT_OTP);
	DBG2("ath9k: ath9k: AR_ENT_OTP 0x%x\n", val);

	/* Configure rx/tx chains before running AGC/TxiQ cals */
	if (val & AR_ENT_OTP_CHAIN2_DISABLE)
		ar9003_hw_set_chain_masks(ah, 0x3, 0x3);
	else
		ar9003_hw_set_chain_masks(ah, pCap->rx_chainmask,
					  pCap->tx_chainmask);

	/* Do Tx IQ Calibration */
	REG_RMW_FIELD(ah, AR_PHY_TX_IQCAL_CONTROL_1,
		      AR_PHY_TX_IQCAL_CONTROL_1_IQCORR_I_Q_COFF_DELPT,
		      DELPT);

	/*
	 * For AR9485 or later chips, TxIQ cal runs as part of
	 * AGC calibration
	 */
	if (AR_SREV_9485_OR_LATER(ah))
		txiqcal_done = 1;
	else {
		txiqcal_done = ar9003_hw_tx_iq_cal_run(ah);
		REG_WRITE(ah, AR_PHY_ACTIVE, AR_PHY_ACTIVE_DIS);
		udelay(5);
		REG_WRITE(ah, AR_PHY_ACTIVE, AR_PHY_ACTIVE_EN);
	}

	/* Calibrate the AGC */
	REG_WRITE(ah, AR_PHY_AGC_CONTROL,
		  REG_READ(ah, AR_PHY_AGC_CONTROL) |
		  AR_PHY_AGC_CONTROL_CAL);

	/* Poll for offset calibration complete */
	if (!ath9k_hw_wait(ah, AR_PHY_AGC_CONTROL, AR_PHY_AGC_CONTROL_CAL,
			   0, AH_WAIT_TIMEOUT)) {
		DBG("ath9k: "
			"offset calibration failed to complete in 1ms; noisy environment?\n");
		return 0;
	}

	if (txiqcal_done)
		ar9003_hw_tx_iq_cal_post_proc(ah);

	/* Revert chainmasks to their original values before NF cal */
	ar9003_hw_set_chain_masks(ah, ah->rxchainmask, ah->txchainmask);

	ath9k_hw_start_nfcal(ah, 1);

	/* Initialize list pointers */
	ah->cal_list = ah->cal_list_last = ah->cal_list_curr = NULL;
	ah->supp_cals = IQ_MISMATCH_CAL;

	if (ah->supp_cals & IQ_MISMATCH_CAL) {
		INIT_CAL(&ah->iq_caldata);
		INSERT_CAL(ah, &ah->iq_caldata);
		DBG2("ath9k: "
			"enabling IQ Calibration.\n");
	}

	if (ah->supp_cals & TEMP_COMP_CAL) {
		INIT_CAL(&ah->tempCompCalData);
		INSERT_CAL(ah, &ah->tempCompCalData);
		DBG2("ath9k: "
			"enabling Temperature Compensation Calibration.\n");
	}

	/* Initialize current pointer to first element in list */
	ah->cal_list_curr = ah->cal_list;

	if (ah->cal_list_curr)
		ath9k_hw_reset_calibration(ah, ah->cal_list_curr);

	if (ah->caldata)
		ah->caldata->CalValid = 0;

	return 1;
}

void ar9003_hw_attach_calib_ops(struct ath_hw *ah)
{
	struct ath_hw_private_ops *priv_ops = ath9k_hw_private_ops(ah);
	struct ath_hw_ops *ops = ath9k_hw_ops(ah);

	priv_ops->init_cal_settings = ar9003_hw_init_cal_settings;
	priv_ops->init_cal = ar9003_hw_init_cal;
	priv_ops->setup_calibration = ar9003_hw_setup_calibration;

	ops->calibrate = ar9003_hw_calibrate;
}
