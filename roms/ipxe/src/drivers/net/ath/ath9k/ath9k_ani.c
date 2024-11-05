/*
 * Copyright (c) 2008-2011 Atheros Communications Inc.
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

#include "hw.h"
#include "hw-ops.h"

struct ani_ofdm_level_entry {
	int spur_immunity_level;
	int fir_step_level;
	int ofdm_weak_signal_on;
};

/* values here are relative to the INI */

/*
 * Legend:
 *
 * SI: Spur immunity
 * FS: FIR Step
 * WS: OFDM / CCK Weak Signal detection
 * MRC-CCK: Maximal Ratio Combining for CCK
 */

static const struct ani_ofdm_level_entry ofdm_level_table[] = {
	/* SI  FS  WS */
	{  0,  0,  1  }, /* lvl 0 */
	{  1,  1,  1  }, /* lvl 1 */
	{  2,  2,  1  }, /* lvl 2 */
	{  3,  2,  1  }, /* lvl 3  (default) */
	{  4,  3,  1  }, /* lvl 4 */
	{  5,  4,  1  }, /* lvl 5 */
	{  6,  5,  1  }, /* lvl 6 */
	{  7,  6,  1  }, /* lvl 7 */
	{  7,  7,  1  }, /* lvl 8 */
	{  7,  8,  0  }  /* lvl 9 */
};
#define ATH9K_ANI_OFDM_NUM_LEVEL \
	ARRAY_SIZE(ofdm_level_table)
#define ATH9K_ANI_OFDM_MAX_LEVEL \
	(ATH9K_ANI_OFDM_NUM_LEVEL-1)
#define ATH9K_ANI_OFDM_DEF_LEVEL \
	3 /* default level - matches the INI settings */

/*
 * MRC (Maximal Ratio Combining) has always been used with multi-antenna ofdm.
 * With OFDM for single stream you just add up all antenna inputs, you're
 * only interested in what you get after FFT. Signal aligment is also not
 * required for OFDM because any phase difference adds up in the frequency
 * domain.
 *
 * MRC requires extra work for use with CCK. You need to align the antenna
 * signals from the different antenna before you can add the signals together.
 * You need aligment of signals as CCK is in time domain, so addition can cancel
 * your signal completely if phase is 180 degrees (think of adding sine waves).
 * You also need to remove noise before the addition and this is where ANI
 * MRC CCK comes into play. One of the antenna inputs may be stronger but
 * lower SNR, so just adding after alignment can be dangerous.
 *
 * Regardless of alignment in time, the antenna signals add constructively after
 * FFT and improve your reception. For more information:
 *
 * http://en.wikipedia.org/wiki/Maximal-ratio_combining
 */

struct ani_cck_level_entry {
	int fir_step_level;
	int mrc_cck_on;
};

static const struct ani_cck_level_entry cck_level_table[] = {
	/* FS  MRC-CCK  */
	{  0,  1  }, /* lvl 0 */
	{  1,  1  }, /* lvl 1 */
	{  2,  1  }, /* lvl 2  (default) */
	{  3,  1  }, /* lvl 3 */
	{  4,  0  }, /* lvl 4 */
	{  5,  0  }, /* lvl 5 */
	{  6,  0  }, /* lvl 6 */
	{  7,  0  }, /* lvl 7 (only for high rssi) */
	{  8,  0  }  /* lvl 8 (only for high rssi) */
};

#define ATH9K_ANI_CCK_NUM_LEVEL \
	ARRAY_SIZE(cck_level_table)
#define ATH9K_ANI_CCK_MAX_LEVEL \
	(ATH9K_ANI_CCK_NUM_LEVEL-1)
#define ATH9K_ANI_CCK_MAX_LEVEL_LOW_RSSI \
	(ATH9K_ANI_CCK_NUM_LEVEL-3)
#define ATH9K_ANI_CCK_DEF_LEVEL \
	2 /* default level - matches the INI settings */

static int use_new_ani(struct ath_hw *ah)
{
	return AR_SREV_9300_20_OR_LATER(ah) || modparam_force_new_ani;
}

static void ath9k_hw_update_mibstats(struct ath_hw *ah,
				     struct ath9k_mib_stats *stats)
{
	stats->ackrcv_bad += REG_READ(ah, AR_ACK_FAIL);
	stats->rts_bad += REG_READ(ah, AR_RTS_FAIL);
	stats->fcs_bad += REG_READ(ah, AR_FCS_FAIL);
	stats->rts_good += REG_READ(ah, AR_RTS_OK);
	stats->beacons += REG_READ(ah, AR_BEACON_CNT);
}

static void ath9k_ani_restart(struct ath_hw *ah)
{
	struct ar5416AniState *aniState;
	u32 ofdm_base = 0, cck_base = 0;

	if (!DO_ANI(ah))
		return;

	aniState = &ah->curchan->ani;
	aniState->listenTime = 0;

	if (!use_new_ani(ah)) {
		ofdm_base = AR_PHY_COUNTMAX - ah->config.ofdm_trig_high;
		cck_base = AR_PHY_COUNTMAX - ah->config.cck_trig_high;
	}

	DBG2("ath9k: "
		"Writing ofdmbase=%d   cckbase=%d\n", ofdm_base, cck_base);

	ENABLE_REGWRITE_BUFFER(ah);

	REG_WRITE(ah, AR_PHY_ERR_1, ofdm_base);
	REG_WRITE(ah, AR_PHY_ERR_2, cck_base);
	REG_WRITE(ah, AR_PHY_ERR_MASK_1, AR_PHY_ERR_OFDM_TIMING);
	REG_WRITE(ah, AR_PHY_ERR_MASK_2, AR_PHY_ERR_CCK_TIMING);

	REGWRITE_BUFFER_FLUSH(ah);

	ath9k_hw_update_mibstats(ah, &ah->ah_mibStats);

	aniState->ofdmPhyErrCount = 0;
	aniState->cckPhyErrCount = 0;
}

static void ath9k_hw_ani_ofdm_err_trigger_old(struct ath_hw *ah)
{
	struct ar5416AniState *aniState;
	int32_t rssi;

	aniState = &ah->curchan->ani;

	if (aniState->noiseImmunityLevel < HAL_NOISE_IMMUNE_MAX) {
		if (ath9k_hw_ani_control(ah, ATH9K_ANI_NOISE_IMMUNITY_LEVEL,
					 aniState->noiseImmunityLevel + 1)) {
			return;
		}
	}

	if (aniState->spurImmunityLevel < HAL_SPUR_IMMUNE_MAX) {
		if (ath9k_hw_ani_control(ah, ATH9K_ANI_SPUR_IMMUNITY_LEVEL,
					 aniState->spurImmunityLevel + 1)) {
			return;
		}
	}

	rssi = BEACON_RSSI(ah);
	if (rssi > aniState->rssiThrHigh) {
		if (aniState->ofdmWeakSigDetect) {
			if (ath9k_hw_ani_control(ah,
					 ATH9K_ANI_OFDM_WEAK_SIGNAL_DETECTION,
					 0)) {
				ath9k_hw_ani_control(ah,
					ATH9K_ANI_SPUR_IMMUNITY_LEVEL, 0);
				return;
			}
		}
		if (aniState->firstepLevel < HAL_FIRST_STEP_MAX) {
			ath9k_hw_ani_control(ah, ATH9K_ANI_FIRSTEP_LEVEL,
					     aniState->firstepLevel + 1);
			return;
		}
	} else if (rssi > aniState->rssiThrLow) {
		if (!aniState->ofdmWeakSigDetect)
			ath9k_hw_ani_control(ah,
				     ATH9K_ANI_OFDM_WEAK_SIGNAL_DETECTION,
				     1);
		if (aniState->firstepLevel < HAL_FIRST_STEP_MAX)
			ath9k_hw_ani_control(ah, ATH9K_ANI_FIRSTEP_LEVEL,
					     aniState->firstepLevel + 1);
		return;
	} else {
		if ((ah->dev->channels + ah->dev->channel)->band == NET80211_BAND_2GHZ) {
			if (aniState->ofdmWeakSigDetect)
				ath9k_hw_ani_control(ah,
				     ATH9K_ANI_OFDM_WEAK_SIGNAL_DETECTION,
				     0);
			if (aniState->firstepLevel > 0)
				ath9k_hw_ani_control(ah,
					     ATH9K_ANI_FIRSTEP_LEVEL, 0);
			return;
		}
	}
}

static void ath9k_hw_ani_cck_err_trigger_old(struct ath_hw *ah)
{
	struct ar5416AniState *aniState;
	int32_t rssi;

	aniState = &ah->curchan->ani;
	if (aniState->noiseImmunityLevel < HAL_NOISE_IMMUNE_MAX) {
		if (ath9k_hw_ani_control(ah, ATH9K_ANI_NOISE_IMMUNITY_LEVEL,
					 aniState->noiseImmunityLevel + 1)) {
			return;
		}
	}
	rssi = BEACON_RSSI(ah);
	if (rssi > aniState->rssiThrLow) {
		if (aniState->firstepLevel < HAL_FIRST_STEP_MAX)
			ath9k_hw_ani_control(ah, ATH9K_ANI_FIRSTEP_LEVEL,
					     aniState->firstepLevel + 1);
	} else {
		if ((ah->dev->channels + ah->dev->channel)->band == NET80211_BAND_2GHZ) {
			if (aniState->firstepLevel > 0)
				ath9k_hw_ani_control(ah,
					     ATH9K_ANI_FIRSTEP_LEVEL, 0);
		}
	}
}

/* Adjust the OFDM Noise Immunity Level */
static void ath9k_hw_set_ofdm_nil(struct ath_hw *ah, u8 immunityLevel)
{
	struct ar5416AniState *aniState = &ah->curchan->ani;
	const struct ani_ofdm_level_entry *entry_ofdm;
	const struct ani_cck_level_entry *entry_cck;

	aniState->noiseFloor = BEACON_RSSI(ah);

	DBG2("ath9k: "
		"**** ofdmlevel %d=>%d, rssi=%d[lo=%d hi=%d]\n",
		aniState->ofdmNoiseImmunityLevel,
		immunityLevel, aniState->noiseFloor,
		aniState->rssiThrLow, aniState->rssiThrHigh);

	aniState->ofdmNoiseImmunityLevel = immunityLevel;

	entry_ofdm = &ofdm_level_table[aniState->ofdmNoiseImmunityLevel];
	entry_cck = &cck_level_table[aniState->cckNoiseImmunityLevel];

	if (aniState->spurImmunityLevel != entry_ofdm->spur_immunity_level)
		ath9k_hw_ani_control(ah,
				     ATH9K_ANI_SPUR_IMMUNITY_LEVEL,
				     entry_ofdm->spur_immunity_level);

	if (aniState->firstepLevel != entry_ofdm->fir_step_level &&
	    entry_ofdm->fir_step_level >= entry_cck->fir_step_level)
		ath9k_hw_ani_control(ah,
				     ATH9K_ANI_FIRSTEP_LEVEL,
				     entry_ofdm->fir_step_level);
}

static void ath9k_hw_ani_ofdm_err_trigger(struct ath_hw *ah)
{
	struct ar5416AniState *aniState;

	if (!DO_ANI(ah))
		return;

	if (!use_new_ani(ah)) {
		ath9k_hw_ani_ofdm_err_trigger_old(ah);
		return;
	}

	aniState = &ah->curchan->ani;

	if (aniState->ofdmNoiseImmunityLevel < ATH9K_ANI_OFDM_MAX_LEVEL)
		ath9k_hw_set_ofdm_nil(ah, aniState->ofdmNoiseImmunityLevel + 1);
}

/*
 * Set the ANI settings to match an CCK level.
 */
static void ath9k_hw_set_cck_nil(struct ath_hw *ah, uint8_t immunityLevel)
{
	struct ar5416AniState *aniState = &ah->curchan->ani;
	const struct ani_ofdm_level_entry *entry_ofdm;
	const struct ani_cck_level_entry *entry_cck;

	aniState->noiseFloor = BEACON_RSSI(ah);
	DBG2("ath9k: "
		"**** ccklevel %d=>%d, rssi=%d[lo=%d hi=%d]\n",
		aniState->cckNoiseImmunityLevel, immunityLevel,
		aniState->noiseFloor, aniState->rssiThrLow,
		aniState->rssiThrHigh);

	if (aniState->noiseFloor <= (unsigned int)aniState->rssiThrLow &&
	    immunityLevel > ATH9K_ANI_CCK_MAX_LEVEL_LOW_RSSI)
		immunityLevel = ATH9K_ANI_CCK_MAX_LEVEL_LOW_RSSI;

	aniState->cckNoiseImmunityLevel = immunityLevel;

	entry_ofdm = &ofdm_level_table[aniState->ofdmNoiseImmunityLevel];
	entry_cck = &cck_level_table[aniState->cckNoiseImmunityLevel];

	if (aniState->firstepLevel != entry_cck->fir_step_level &&
	    entry_cck->fir_step_level >= entry_ofdm->fir_step_level)
		ath9k_hw_ani_control(ah,
				     ATH9K_ANI_FIRSTEP_LEVEL,
				     entry_cck->fir_step_level);

	/* Skip MRC CCK for pre AR9003 families */
	if (!AR_SREV_9300_20_OR_LATER(ah) || AR_SREV_9485(ah))
		return;

	if (aniState->mrcCCKOff == entry_cck->mrc_cck_on)
		ath9k_hw_ani_control(ah,
				     ATH9K_ANI_MRC_CCK,
				     entry_cck->mrc_cck_on);
}

static void ath9k_hw_ani_cck_err_trigger(struct ath_hw *ah)
{
	struct ar5416AniState *aniState;

	if (!DO_ANI(ah))
		return;

	if (!use_new_ani(ah)) {
		ath9k_hw_ani_cck_err_trigger_old(ah);
		return;
	}

	aniState = &ah->curchan->ani;

	if (aniState->cckNoiseImmunityLevel < ATH9K_ANI_CCK_MAX_LEVEL)
		ath9k_hw_set_cck_nil(ah, aniState->cckNoiseImmunityLevel + 1);
}

static void ath9k_hw_ani_lower_immunity_old(struct ath_hw *ah)
{
	struct ar5416AniState *aniState;
	int32_t rssi;

	aniState = &ah->curchan->ani;

	rssi = BEACON_RSSI(ah);
	if (rssi > aniState->rssiThrHigh) {
		/* XXX: Handle me */
	} else if (rssi > aniState->rssiThrLow) {
		if (!aniState->ofdmWeakSigDetect) {
			if (ath9k_hw_ani_control(ah,
				 ATH9K_ANI_OFDM_WEAK_SIGNAL_DETECTION,
				 1) == 1)
				return;
		}
		if (aniState->firstepLevel > 0) {
			if (ath9k_hw_ani_control(ah,
				 ATH9K_ANI_FIRSTEP_LEVEL,
				 aniState->firstepLevel - 1) == 1)
				return;
		}
	} else {
		if (aniState->firstepLevel > 0) {
			if (ath9k_hw_ani_control(ah,
				 ATH9K_ANI_FIRSTEP_LEVEL,
				 aniState->firstepLevel - 1) == 1)
				return;
		}
	}

	if (aniState->spurImmunityLevel > 0) {
		if (ath9k_hw_ani_control(ah, ATH9K_ANI_SPUR_IMMUNITY_LEVEL,
					 aniState->spurImmunityLevel - 1))
			return;
	}

	if (aniState->noiseImmunityLevel > 0) {
		ath9k_hw_ani_control(ah, ATH9K_ANI_NOISE_IMMUNITY_LEVEL,
				     aniState->noiseImmunityLevel - 1);
		return;
	}
}

/*
 * only lower either OFDM or CCK errors per turn
 * we lower the other one next time
 */
static void ath9k_hw_ani_lower_immunity(struct ath_hw *ah)
{
	struct ar5416AniState *aniState;

	aniState = &ah->curchan->ani;

	if (!use_new_ani(ah)) {
		ath9k_hw_ani_lower_immunity_old(ah);
		return;
	}

	/* lower OFDM noise immunity */
	if (aniState->ofdmNoiseImmunityLevel > 0 &&
	    (aniState->ofdmsTurn || aniState->cckNoiseImmunityLevel == 0)) {
		ath9k_hw_set_ofdm_nil(ah, aniState->ofdmNoiseImmunityLevel - 1);
		return;
	}

	/* lower CCK noise immunity */
	if (aniState->cckNoiseImmunityLevel > 0)
		ath9k_hw_set_cck_nil(ah, aniState->cckNoiseImmunityLevel - 1);
}

static void ath9k_ani_reset_old(struct ath_hw *ah)
{
	struct ar5416AniState *aniState;

	if (!DO_ANI(ah))
		return;

	aniState = &ah->curchan->ani;

	if (aniState->noiseImmunityLevel != 0)
		ath9k_hw_ani_control(ah, ATH9K_ANI_NOISE_IMMUNITY_LEVEL,
				     aniState->noiseImmunityLevel);
	if (aniState->spurImmunityLevel != 0)
		ath9k_hw_ani_control(ah, ATH9K_ANI_SPUR_IMMUNITY_LEVEL,
				     aniState->spurImmunityLevel);
	if (!aniState->ofdmWeakSigDetect)
		ath9k_hw_ani_control(ah, ATH9K_ANI_OFDM_WEAK_SIGNAL_DETECTION,
				     aniState->ofdmWeakSigDetect);
	if (aniState->cckWeakSigThreshold)
		ath9k_hw_ani_control(ah, ATH9K_ANI_CCK_WEAK_SIGNAL_THR,
				     aniState->cckWeakSigThreshold);
	if (aniState->firstepLevel != 0)
		ath9k_hw_ani_control(ah, ATH9K_ANI_FIRSTEP_LEVEL,
				     aniState->firstepLevel);

	ath9k_hw_setrxfilter(ah, ath9k_hw_getrxfilter(ah) &
			     ~ATH9K_RX_FILTER_PHYERR);
	ath9k_ani_restart(ah);

	ENABLE_REGWRITE_BUFFER(ah);

	REG_WRITE(ah, AR_PHY_ERR_MASK_1, AR_PHY_ERR_OFDM_TIMING);
	REG_WRITE(ah, AR_PHY_ERR_MASK_2, AR_PHY_ERR_CCK_TIMING);

	REGWRITE_BUFFER_FLUSH(ah);
}

/*
 * Restore the ANI parameters in the HAL and reset the statistics.
 * This routine should be called for every hardware reset and for
 * every channel change.
 */
void ath9k_ani_reset(struct ath_hw *ah, int is_scanning)
{
	struct ar5416AniState *aniState = &ah->curchan->ani;
	struct ath9k_channel *chan = ah->curchan;

	if (!DO_ANI(ah))
		return;

	if (!use_new_ani(ah))
		return ath9k_ani_reset_old(ah);

	ah->stats.ast_ani_reset++;

	/* always allow mode (on/off) to be controlled */
	ah->ani_function |= ATH9K_ANI_MODE;

	if (is_scanning) {
		/*
		 * If we're scanning or in AP mode, the defaults (ini)
		 * should be in place. For an AP we assume the historical
		 * levels for this channel are probably outdated so start
		 * from defaults instead.
		 */
		if (aniState->ofdmNoiseImmunityLevel !=
		    ATH9K_ANI_OFDM_DEF_LEVEL ||
		    aniState->cckNoiseImmunityLevel !=
		    ATH9K_ANI_CCK_DEF_LEVEL) {
			DBG("ath9k: "
				"Restore defaults: chan %d Mhz/0x%x is_scanning=%d ofdm:%d cck:%d\n",
				chan->channel,
				chan->channelFlags,
				is_scanning,
				aniState->ofdmNoiseImmunityLevel,
				aniState->cckNoiseImmunityLevel);

			ath9k_hw_set_ofdm_nil(ah, ATH9K_ANI_OFDM_DEF_LEVEL);
			ath9k_hw_set_cck_nil(ah, ATH9K_ANI_CCK_DEF_LEVEL);
		}
	} else {
		/*
		 * restore historical levels for this channel
		 */
		DBG2("ath9k: "
			"Restore history: chan %d Mhz/0x%x is_scanning=%d ofdm:%d cck:%d\n",
			chan->channel,
			chan->channelFlags,
			is_scanning,
			aniState->ofdmNoiseImmunityLevel,
			aniState->cckNoiseImmunityLevel);

			ath9k_hw_set_ofdm_nil(ah,
					      aniState->ofdmNoiseImmunityLevel);
			ath9k_hw_set_cck_nil(ah,
					     aniState->cckNoiseImmunityLevel);
	}

	/*
	 * enable phy counters if hw supports or if not, enable phy
	 * interrupts (so we can count each one)
	 */
	ath9k_ani_restart(ah);

	ENABLE_REGWRITE_BUFFER(ah);

	REG_WRITE(ah, AR_PHY_ERR_MASK_1, AR_PHY_ERR_OFDM_TIMING);
	REG_WRITE(ah, AR_PHY_ERR_MASK_2, AR_PHY_ERR_CCK_TIMING);

	REGWRITE_BUFFER_FLUSH(ah);
}

static int ath9k_hw_ani_read_counters(struct ath_hw *ah)
{
	struct ath_common *common = ath9k_hw_common(ah);
	struct ar5416AniState *aniState = &ah->curchan->ani;
	u32 ofdm_base = 0;
	u32 cck_base = 0;
	u32 ofdmPhyErrCnt, cckPhyErrCnt;
	u32 phyCnt1, phyCnt2;
	int32_t listenTime;

	ath_hw_cycle_counters_update(common);
	listenTime = ath_hw_get_listen_time(common);

	if (listenTime <= 0) {
		ah->stats.ast_ani_lneg++;
		ath9k_ani_restart(ah);
		return 0;
	}

	if (!use_new_ani(ah)) {
		ofdm_base = AR_PHY_COUNTMAX - ah->config.ofdm_trig_high;
		cck_base = AR_PHY_COUNTMAX - ah->config.cck_trig_high;
	}

	aniState->listenTime += listenTime;

	phyCnt1 = REG_READ(ah, AR_PHY_ERR_1);
	phyCnt2 = REG_READ(ah, AR_PHY_ERR_2);

	if (!use_new_ani(ah) && (phyCnt1 < ofdm_base || phyCnt2 < cck_base)) {
		if (phyCnt1 < ofdm_base) {
			DBG2("ath9k: "
				"phyCnt1 0x%x, resetting counter value to 0x%x\n",
				phyCnt1, ofdm_base);
			REG_WRITE(ah, AR_PHY_ERR_1, ofdm_base);
			REG_WRITE(ah, AR_PHY_ERR_MASK_1,
				  AR_PHY_ERR_OFDM_TIMING);
		}
		if (phyCnt2 < cck_base) {
			DBG2("ath9k: "
				"phyCnt2 0x%x, resetting counter value to 0x%x\n",
				phyCnt2, cck_base);
			REG_WRITE(ah, AR_PHY_ERR_2, cck_base);
			REG_WRITE(ah, AR_PHY_ERR_MASK_2,
				  AR_PHY_ERR_CCK_TIMING);
		}
		return 0;
	}

	ofdmPhyErrCnt = phyCnt1 - ofdm_base;
	ah->stats.ast_ani_ofdmerrs +=
		ofdmPhyErrCnt - aniState->ofdmPhyErrCount;
	aniState->ofdmPhyErrCount = ofdmPhyErrCnt;

	cckPhyErrCnt = phyCnt2 - cck_base;
	ah->stats.ast_ani_cckerrs +=
		cckPhyErrCnt - aniState->cckPhyErrCount;
	aniState->cckPhyErrCount = cckPhyErrCnt;
	return 1;
}

void ath9k_hw_ani_monitor(struct ath_hw *ah, struct ath9k_channel *chan __unused)
{
	struct ar5416AniState *aniState;
	u32 ofdmPhyErrRate, cckPhyErrRate;

	if (!DO_ANI(ah))
		return;

	aniState = &ah->curchan->ani;
	if (!aniState)
		return;

	if (!ath9k_hw_ani_read_counters(ah))
		return;

	ofdmPhyErrRate = aniState->ofdmPhyErrCount * 1000 /
			 aniState->listenTime;
	cckPhyErrRate =  aniState->cckPhyErrCount * 1000 /
			 aniState->listenTime;

	DBG2("ath9k: "
		"listenTime=%d OFDM:%d errs=%d/s CCK:%d errs=%d/s ofdm_turn=%d\n",
		aniState->listenTime,
		aniState->ofdmNoiseImmunityLevel,
		ofdmPhyErrRate, aniState->cckNoiseImmunityLevel,
		cckPhyErrRate, aniState->ofdmsTurn);

	if (aniState->listenTime > 5 * ah->aniperiod) {
		if (ofdmPhyErrRate <= ah->config.ofdm_trig_low &&
		    cckPhyErrRate <= ah->config.cck_trig_low) {
			ath9k_hw_ani_lower_immunity(ah);
			aniState->ofdmsTurn = !aniState->ofdmsTurn;
		}
		ath9k_ani_restart(ah);
	} else if (aniState->listenTime > ah->aniperiod) {
		/* check to see if need to raise immunity */
		if (ofdmPhyErrRate > ah->config.ofdm_trig_high &&
		    (cckPhyErrRate <= ah->config.cck_trig_high ||
		     aniState->ofdmsTurn)) {
			ath9k_hw_ani_ofdm_err_trigger(ah);
			ath9k_ani_restart(ah);
			aniState->ofdmsTurn = 0;
		} else if (cckPhyErrRate > ah->config.cck_trig_high) {
			ath9k_hw_ani_cck_err_trigger(ah);
			ath9k_ani_restart(ah);
			aniState->ofdmsTurn = 1;
		}
	}
}

void ath9k_hw_ani_setup(struct ath_hw *ah)
{
	int i;

	static const int totalSizeDesired[] = { -55, -55, -55, -55, -62 };
	static const int coarseHigh[] = { -14, -14, -14, -14, -12 };
	static const int coarseLow[] = { -64, -64, -64, -64, -70 };
	static const int firpwr[] = { -78, -78, -78, -78, -80 };

	for (i = 0; i < 5; i++) {
		ah->totalSizeDesired[i] = totalSizeDesired[i];
		ah->coarse_high[i] = coarseHigh[i];
		ah->coarse_low[i] = coarseLow[i];
		ah->firpwr[i] = firpwr[i];
	}
}

void ath9k_hw_ani_init(struct ath_hw *ah)
{
	unsigned int i;

	DBG2("ath9k: Initialize ANI\n");

	if (use_new_ani(ah)) {
		ah->config.ofdm_trig_high = ATH9K_ANI_OFDM_TRIG_HIGH_NEW;
		ah->config.ofdm_trig_low = ATH9K_ANI_OFDM_TRIG_LOW_NEW;

		ah->config.cck_trig_high = ATH9K_ANI_CCK_TRIG_HIGH_NEW;
		ah->config.cck_trig_low = ATH9K_ANI_CCK_TRIG_LOW_NEW;
	} else {
		ah->config.ofdm_trig_high = ATH9K_ANI_OFDM_TRIG_HIGH_OLD;
		ah->config.ofdm_trig_low = ATH9K_ANI_OFDM_TRIG_LOW_OLD;

		ah->config.cck_trig_high = ATH9K_ANI_CCK_TRIG_HIGH_OLD;
		ah->config.cck_trig_low = ATH9K_ANI_CCK_TRIG_LOW_OLD;
	}

	for (i = 0; i < ARRAY_SIZE(ah->channels); i++) {
		struct ath9k_channel *chan = &ah->channels[i];
		struct ar5416AniState *ani = &chan->ani;

		if (use_new_ani(ah)) {
			ani->spurImmunityLevel =
				ATH9K_ANI_SPUR_IMMUNE_LVL_NEW;

			ani->firstepLevel = ATH9K_ANI_FIRSTEP_LVL_NEW;

			if (AR_SREV_9300_20_OR_LATER(ah))
				ani->mrcCCKOff =
					!ATH9K_ANI_ENABLE_MRC_CCK;
			else
				ani->mrcCCKOff = 1;

			ani->ofdmsTurn = 1;
		} else {
			ani->spurImmunityLevel =
				ATH9K_ANI_SPUR_IMMUNE_LVL_OLD;
			ani->firstepLevel = ATH9K_ANI_FIRSTEP_LVL_OLD;

			ani->cckWeakSigThreshold =
				ATH9K_ANI_CCK_WEAK_SIG_THR;
		}

		ani->rssiThrHigh = ATH9K_ANI_RSSI_THR_HIGH;
		ani->rssiThrLow = ATH9K_ANI_RSSI_THR_LOW;
		ani->ofdmWeakSigDetect =
			ATH9K_ANI_USE_OFDM_WEAK_SIG;
		ani->cckNoiseImmunityLevel = ATH9K_ANI_CCK_DEF_LEVEL;
	}

	/*
	 * since we expect some ongoing maintenance on the tables, let's sanity
	 * check here default level should not modify INI setting.
	 */
	if (use_new_ani(ah)) {
		ah->aniperiod = ATH9K_ANI_PERIOD_NEW;
		ah->config.ani_poll_interval = ATH9K_ANI_POLLINTERVAL_NEW;
	} else {
		ah->aniperiod = ATH9K_ANI_PERIOD_OLD;
		ah->config.ani_poll_interval = ATH9K_ANI_POLLINTERVAL_OLD;
	}

	if (ah->config.enable_ani)
		ah->proc_phyerr |= HAL_PROCESS_ANI;

	ath9k_ani_restart(ah);
}
