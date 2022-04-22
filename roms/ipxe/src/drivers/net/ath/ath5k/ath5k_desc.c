/*
 * Copyright (c) 2004-2008 Reyk Floeter <reyk@openbsd.org>
 * Copyright (c) 2006-2008 Nick Kossifidis <mickflemm@gmail.com>
 * Copyright (c) 2007-2008 Pavel Roskin <proski@gnu.org>
 *
 * Lightly modified for iPXE, July 2009, by Joshua Oreman <oremanj@rwcr.net>.
 *
 * Permission to use, copy, modify, and distribute this software for any
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
 *
 */

FILE_LICENCE ( MIT );

/******************************\
 Hardware Descriptor Functions
\******************************/

#include "ath5k.h"
#include "reg.h"
#include "base.h"

/*
 * TX Descriptors
 */

#define FCS_LEN	4

/*
 * Initialize the 2-word tx control descriptor on 5210/5211
 */
static int
ath5k_hw_setup_2word_tx_desc(struct ath5k_hw *ah, struct ath5k_desc *desc,
	unsigned int pkt_len, unsigned int hdr_len, enum ath5k_pkt_type type,
	unsigned int tx_power __unused, unsigned int tx_rate0, unsigned int tx_tries0,
	unsigned int key_index __unused, unsigned int antenna_mode, unsigned int flags,
	unsigned int rtscts_rate __unused, unsigned int rtscts_duration)
{
	u32 frame_type;
	struct ath5k_hw_2w_tx_ctl *tx_ctl;
	unsigned int frame_len;

	tx_ctl = &desc->ud.ds_tx5210.tx_ctl;

	/*
	 * Validate input
	 * - Zero retries don't make sense.
	 * - A zero rate will put the HW into a mode where it continously sends
	 *   noise on the channel, so it is important to avoid this.
	 */
	if (tx_tries0 == 0) {
		DBG("ath5k: zero retries\n");
		return -EINVAL;
	}
	if (tx_rate0 == 0) {
		DBG("ath5k: zero rate\n");
		return -EINVAL;
	}

	/* Clear descriptor */
	memset(&desc->ud.ds_tx5210, 0, sizeof(struct ath5k_hw_5210_tx_desc));

	/* Setup control descriptor */

	/* Verify and set frame length */

	frame_len = pkt_len + FCS_LEN;

	if (frame_len & ~AR5K_2W_TX_DESC_CTL0_FRAME_LEN)
		return -EINVAL;

	tx_ctl->tx_control_0 = frame_len & AR5K_2W_TX_DESC_CTL0_FRAME_LEN;

	/* Verify and set buffer length */

	if (pkt_len & ~AR5K_2W_TX_DESC_CTL1_BUF_LEN)
		return -EINVAL;

	tx_ctl->tx_control_1 = pkt_len & AR5K_2W_TX_DESC_CTL1_BUF_LEN;

	/*
	 * Verify and set header length
	 * XXX: I only found that on 5210 code, does it work on 5211 ?
	 */
	if (ah->ah_version == AR5K_AR5210) {
		if (hdr_len & ~AR5K_2W_TX_DESC_CTL0_HEADER_LEN)
			return -EINVAL;
		tx_ctl->tx_control_0 |=
			AR5K_REG_SM(hdr_len, AR5K_2W_TX_DESC_CTL0_HEADER_LEN);
	}

	/*Diferences between 5210-5211*/
	if (ah->ah_version == AR5K_AR5210) {
		switch (type) {
		case AR5K_PKT_TYPE_BEACON:
		case AR5K_PKT_TYPE_PROBE_RESP:
			frame_type = AR5K_AR5210_TX_DESC_FRAME_TYPE_NO_DELAY;
			break;
		case AR5K_PKT_TYPE_PIFS:
			frame_type = AR5K_AR5210_TX_DESC_FRAME_TYPE_PIFS;
			break;
		default:
			frame_type = type /*<< 2 ?*/;
			break;
		}

		tx_ctl->tx_control_0 |=
		AR5K_REG_SM(frame_type, AR5K_2W_TX_DESC_CTL0_FRAME_TYPE) |
		AR5K_REG_SM(tx_rate0, AR5K_2W_TX_DESC_CTL0_XMIT_RATE);

	} else {
		tx_ctl->tx_control_0 |=
			AR5K_REG_SM(tx_rate0, AR5K_2W_TX_DESC_CTL0_XMIT_RATE) |
			AR5K_REG_SM(antenna_mode,
				AR5K_2W_TX_DESC_CTL0_ANT_MODE_XMIT);
		tx_ctl->tx_control_1 |=
			AR5K_REG_SM(type, AR5K_2W_TX_DESC_CTL1_FRAME_TYPE);
	}
#define _TX_FLAGS(_c, _flag)					\
	if (flags & AR5K_TXDESC_##_flag) {			\
		tx_ctl->tx_control_##_c |=			\
			AR5K_2W_TX_DESC_CTL##_c##_##_flag;	\
	}

	_TX_FLAGS(0, CLRDMASK);
	_TX_FLAGS(0, VEOL);
	_TX_FLAGS(0, INTREQ);
	_TX_FLAGS(0, RTSENA);
	_TX_FLAGS(1, NOACK);

#undef _TX_FLAGS

	/*
	 * RTS/CTS Duration [5210 ?]
	 */
	if ((ah->ah_version == AR5K_AR5210) &&
			(flags & (AR5K_TXDESC_RTSENA | AR5K_TXDESC_CTSENA)))
		tx_ctl->tx_control_1 |= rtscts_duration &
				AR5K_2W_TX_DESC_CTL1_RTS_DURATION;

	return 0;
}

/*
 * Initialize the 4-word tx control descriptor on 5212
 */
static int ath5k_hw_setup_4word_tx_desc(struct ath5k_hw *ah,
	struct ath5k_desc *desc, unsigned int pkt_len, unsigned int hdr_len __unused,
	enum ath5k_pkt_type type, unsigned int tx_power, unsigned int tx_rate0,
	unsigned int tx_tries0, unsigned int key_index __unused,
	unsigned int antenna_mode, unsigned int flags,
	unsigned int rtscts_rate,
	unsigned int rtscts_duration)
{
	struct ath5k_hw_4w_tx_ctl *tx_ctl;
	unsigned int frame_len;

	tx_ctl = &desc->ud.ds_tx5212.tx_ctl;

	/*
	 * Validate input
	 * - Zero retries don't make sense.
	 * - A zero rate will put the HW into a mode where it continously sends
	 *   noise on the channel, so it is important to avoid this.
	 */
	if (tx_tries0 == 0) {
		DBG("ath5k: zero retries\n");
		return -EINVAL;
	}
	if (tx_rate0 == 0) {
		DBG("ath5k: zero rate\n");
		return -EINVAL;
	}

	tx_power += ah->ah_txpower.txp_offset;
	if (tx_power > AR5K_TUNE_MAX_TXPOWER)
		tx_power = AR5K_TUNE_MAX_TXPOWER;

	/* Clear descriptor */
	memset(&desc->ud.ds_tx5212, 0, sizeof(struct ath5k_hw_5212_tx_desc));

	/* Setup control descriptor */

	/* Verify and set frame length */

	frame_len = pkt_len + FCS_LEN;

	if (frame_len & ~AR5K_4W_TX_DESC_CTL0_FRAME_LEN)
		return -EINVAL;

	tx_ctl->tx_control_0 = frame_len & AR5K_4W_TX_DESC_CTL0_FRAME_LEN;

	/* Verify and set buffer length */

	if (pkt_len & ~AR5K_4W_TX_DESC_CTL1_BUF_LEN)
		return -EINVAL;

	tx_ctl->tx_control_1 = pkt_len & AR5K_4W_TX_DESC_CTL1_BUF_LEN;

	tx_ctl->tx_control_0 |=
		AR5K_REG_SM(tx_power, AR5K_4W_TX_DESC_CTL0_XMIT_POWER) |
		AR5K_REG_SM(antenna_mode, AR5K_4W_TX_DESC_CTL0_ANT_MODE_XMIT);
	tx_ctl->tx_control_1 |= AR5K_REG_SM(type,
					AR5K_4W_TX_DESC_CTL1_FRAME_TYPE);
	tx_ctl->tx_control_2 = AR5K_REG_SM(tx_tries0 + AR5K_TUNE_HWTXTRIES,
					AR5K_4W_TX_DESC_CTL2_XMIT_TRIES0);
	tx_ctl->tx_control_3 = tx_rate0 & AR5K_4W_TX_DESC_CTL3_XMIT_RATE0;

#define _TX_FLAGS(_c, _flag)					\
	if (flags & AR5K_TXDESC_##_flag) {			\
		tx_ctl->tx_control_##_c |=			\
			AR5K_4W_TX_DESC_CTL##_c##_##_flag;	\
	}

	_TX_FLAGS(0, CLRDMASK);
	_TX_FLAGS(0, VEOL);
	_TX_FLAGS(0, INTREQ);
	_TX_FLAGS(0, RTSENA);
	_TX_FLAGS(0, CTSENA);
	_TX_FLAGS(1, NOACK);

#undef _TX_FLAGS

	/*
	 * RTS/CTS
	 */
	if (flags & (AR5K_TXDESC_RTSENA | AR5K_TXDESC_CTSENA)) {
		if ((flags & AR5K_TXDESC_RTSENA) &&
				(flags & AR5K_TXDESC_CTSENA))
			return -EINVAL;
		tx_ctl->tx_control_2 |= rtscts_duration &
				AR5K_4W_TX_DESC_CTL2_RTS_DURATION;
		tx_ctl->tx_control_3 |= AR5K_REG_SM(rtscts_rate,
				AR5K_4W_TX_DESC_CTL3_RTS_CTS_RATE);
	}

	return 0;
}

/*
 * Proccess the tx status descriptor on 5210/5211
 */
static int ath5k_hw_proc_2word_tx_status(struct ath5k_hw *ah __unused,
		struct ath5k_desc *desc, struct ath5k_tx_status *ts)
{
	struct ath5k_hw_2w_tx_ctl *tx_ctl;
	struct ath5k_hw_tx_status *tx_status;

	tx_ctl = &desc->ud.ds_tx5210.tx_ctl;
	tx_status = &desc->ud.ds_tx5210.tx_stat;

	/* No frame has been send or error */
	if ((tx_status->tx_status_1 & AR5K_DESC_TX_STATUS1_DONE) == 0)
		return -EINPROGRESS;

	/*
	 * Get descriptor status
	 */
	ts->ts_tstamp = AR5K_REG_MS(tx_status->tx_status_0,
		AR5K_DESC_TX_STATUS0_SEND_TIMESTAMP);
	ts->ts_shortretry = AR5K_REG_MS(tx_status->tx_status_0,
		AR5K_DESC_TX_STATUS0_SHORT_RETRY_COUNT);
	ts->ts_longretry = AR5K_REG_MS(tx_status->tx_status_0,
		AR5K_DESC_TX_STATUS0_LONG_RETRY_COUNT);
	/*TODO: ts->ts_virtcol + test*/
	ts->ts_seqnum = AR5K_REG_MS(tx_status->tx_status_1,
		AR5K_DESC_TX_STATUS1_SEQ_NUM);
	ts->ts_rssi = AR5K_REG_MS(tx_status->tx_status_1,
		AR5K_DESC_TX_STATUS1_ACK_SIG_STRENGTH);
	ts->ts_antenna = 1;
	ts->ts_status = 0;
	ts->ts_rate[0] = AR5K_REG_MS(tx_ctl->tx_control_0,
		AR5K_2W_TX_DESC_CTL0_XMIT_RATE);
	ts->ts_retry[0] = ts->ts_longretry;
	ts->ts_final_idx = 0;

	if (!(tx_status->tx_status_0 & AR5K_DESC_TX_STATUS0_FRAME_XMIT_OK)) {
		if (tx_status->tx_status_0 &
				AR5K_DESC_TX_STATUS0_EXCESSIVE_RETRIES)
			ts->ts_status |= AR5K_TXERR_XRETRY;

		if (tx_status->tx_status_0 & AR5K_DESC_TX_STATUS0_FIFO_UNDERRUN)
			ts->ts_status |= AR5K_TXERR_FIFO;

		if (tx_status->tx_status_0 & AR5K_DESC_TX_STATUS0_FILTERED)
			ts->ts_status |= AR5K_TXERR_FILT;
	}

	return 0;
}

/*
 * Proccess a tx status descriptor on 5212
 */
static int ath5k_hw_proc_4word_tx_status(struct ath5k_hw *ah __unused,
		struct ath5k_desc *desc, struct ath5k_tx_status *ts)
{
	struct ath5k_hw_4w_tx_ctl *tx_ctl;
	struct ath5k_hw_tx_status *tx_status;

	tx_ctl = &desc->ud.ds_tx5212.tx_ctl;
	tx_status = &desc->ud.ds_tx5212.tx_stat;

	/* No frame has been send or error */
	if (!(tx_status->tx_status_1 & AR5K_DESC_TX_STATUS1_DONE))
		return -EINPROGRESS;

	/*
	 * Get descriptor status
	 */
	ts->ts_tstamp = AR5K_REG_MS(tx_status->tx_status_0,
		AR5K_DESC_TX_STATUS0_SEND_TIMESTAMP);
	ts->ts_shortretry = AR5K_REG_MS(tx_status->tx_status_0,
		AR5K_DESC_TX_STATUS0_SHORT_RETRY_COUNT);
	ts->ts_longretry = AR5K_REG_MS(tx_status->tx_status_0,
		AR5K_DESC_TX_STATUS0_LONG_RETRY_COUNT);
	ts->ts_seqnum = AR5K_REG_MS(tx_status->tx_status_1,
		AR5K_DESC_TX_STATUS1_SEQ_NUM);
	ts->ts_rssi = AR5K_REG_MS(tx_status->tx_status_1,
		AR5K_DESC_TX_STATUS1_ACK_SIG_STRENGTH);
	ts->ts_antenna = (tx_status->tx_status_1 &
		AR5K_DESC_TX_STATUS1_XMIT_ANTENNA) ? 2 : 1;
	ts->ts_status = 0;

	ts->ts_final_idx = AR5K_REG_MS(tx_status->tx_status_1,
			AR5K_DESC_TX_STATUS1_FINAL_TS_INDEX);

	ts->ts_retry[0] = ts->ts_longretry;
	ts->ts_rate[0] = tx_ctl->tx_control_3 &
		AR5K_4W_TX_DESC_CTL3_XMIT_RATE0;

	/* TX error */
	if (!(tx_status->tx_status_0 & AR5K_DESC_TX_STATUS0_FRAME_XMIT_OK)) {
		if (tx_status->tx_status_0 &
				AR5K_DESC_TX_STATUS0_EXCESSIVE_RETRIES)
			ts->ts_status |= AR5K_TXERR_XRETRY;

		if (tx_status->tx_status_0 & AR5K_DESC_TX_STATUS0_FIFO_UNDERRUN)
			ts->ts_status |= AR5K_TXERR_FIFO;

		if (tx_status->tx_status_0 & AR5K_DESC_TX_STATUS0_FILTERED)
			ts->ts_status |= AR5K_TXERR_FILT;
	}

	return 0;
}

/*
 * RX Descriptors
 */

/*
 * Initialize an rx control descriptor
 */
static int ath5k_hw_setup_rx_desc(struct ath5k_hw *ah __unused,
				  struct ath5k_desc *desc,
				  u32 size, unsigned int flags)
{
	struct ath5k_hw_rx_ctl *rx_ctl;

	rx_ctl = &desc->ud.ds_rx.rx_ctl;

	/*
	 * Clear the descriptor
	 * If we don't clean the status descriptor,
	 * while scanning we get too many results,
	 * most of them virtual, after some secs
	 * of scanning system hangs. M.F.
	*/
	memset(&desc->ud.ds_rx, 0, sizeof(struct ath5k_hw_all_rx_desc));

	/* Setup descriptor */
	rx_ctl->rx_control_1 = size & AR5K_DESC_RX_CTL1_BUF_LEN;
	if (rx_ctl->rx_control_1 != size)
		return -EINVAL;

	if (flags & AR5K_RXDESC_INTREQ)
		rx_ctl->rx_control_1 |= AR5K_DESC_RX_CTL1_INTREQ;

	return 0;
}

/*
 * Proccess the rx status descriptor on 5210/5211
 */
static int ath5k_hw_proc_5210_rx_status(struct ath5k_hw *ah __unused,
		struct ath5k_desc *desc, struct ath5k_rx_status *rs)
{
	struct ath5k_hw_rx_status *rx_status;

	rx_status = &desc->ud.ds_rx.u.rx_stat;

	/* No frame received / not ready */
	if (!(rx_status->rx_status_1 & AR5K_5210_RX_DESC_STATUS1_DONE))
		return -EINPROGRESS;

	/*
	 * Frame receive status
	 */
	rs->rs_datalen = rx_status->rx_status_0 &
		AR5K_5210_RX_DESC_STATUS0_DATA_LEN;
	rs->rs_rssi = AR5K_REG_MS(rx_status->rx_status_0,
		AR5K_5210_RX_DESC_STATUS0_RECEIVE_SIGNAL);
	rs->rs_rate = AR5K_REG_MS(rx_status->rx_status_0,
		AR5K_5210_RX_DESC_STATUS0_RECEIVE_RATE);
	rs->rs_antenna = AR5K_REG_MS(rx_status->rx_status_0,
		AR5K_5210_RX_DESC_STATUS0_RECEIVE_ANTENNA);
	rs->rs_more = !!(rx_status->rx_status_0 &
		AR5K_5210_RX_DESC_STATUS0_MORE);
	/* TODO: this timestamp is 13 bit, later on we assume 15 bit */
	rs->rs_tstamp = AR5K_REG_MS(rx_status->rx_status_1,
		AR5K_5210_RX_DESC_STATUS1_RECEIVE_TIMESTAMP);
	rs->rs_status = 0;
	rs->rs_phyerr = 0;
	rs->rs_keyix = AR5K_RXKEYIX_INVALID;

	/*
	 * Receive/descriptor errors
	 */
	if (!(rx_status->rx_status_1 &
	      AR5K_5210_RX_DESC_STATUS1_FRAME_RECEIVE_OK)) {
		if (rx_status->rx_status_1 &
				AR5K_5210_RX_DESC_STATUS1_CRC_ERROR)
			rs->rs_status |= AR5K_RXERR_CRC;

		if (rx_status->rx_status_1 &
				AR5K_5210_RX_DESC_STATUS1_FIFO_OVERRUN)
			rs->rs_status |= AR5K_RXERR_FIFO;

		if (rx_status->rx_status_1 &
				AR5K_5210_RX_DESC_STATUS1_PHY_ERROR) {
			rs->rs_status |= AR5K_RXERR_PHY;
			rs->rs_phyerr |= AR5K_REG_MS(rx_status->rx_status_1,
				AR5K_5210_RX_DESC_STATUS1_PHY_ERROR);
		}

		if (rx_status->rx_status_1 &
				AR5K_5210_RX_DESC_STATUS1_DECRYPT_CRC_ERROR)
			rs->rs_status |= AR5K_RXERR_DECRYPT;
	}

	return 0;
}

/*
 * Proccess the rx status descriptor on 5212
 */
static int ath5k_hw_proc_5212_rx_status(struct ath5k_hw *ah __unused,
		struct ath5k_desc *desc, struct ath5k_rx_status *rs)
{
	struct ath5k_hw_rx_status *rx_status;
	struct ath5k_hw_rx_error *rx_err;

	rx_status = &desc->ud.ds_rx.u.rx_stat;

	/* Overlay on error */
	rx_err = &desc->ud.ds_rx.u.rx_err;

	/* No frame received / not ready */
	if (!(rx_status->rx_status_1 & AR5K_5212_RX_DESC_STATUS1_DONE))
		return -EINPROGRESS;

	/*
	 * Frame receive status
	 */
	rs->rs_datalen = rx_status->rx_status_0 &
		AR5K_5212_RX_DESC_STATUS0_DATA_LEN;
	rs->rs_rssi = AR5K_REG_MS(rx_status->rx_status_0,
		AR5K_5212_RX_DESC_STATUS0_RECEIVE_SIGNAL);
	rs->rs_rate = AR5K_REG_MS(rx_status->rx_status_0,
		AR5K_5212_RX_DESC_STATUS0_RECEIVE_RATE);
	rs->rs_antenna = AR5K_REG_MS(rx_status->rx_status_0,
		AR5K_5212_RX_DESC_STATUS0_RECEIVE_ANTENNA);
	rs->rs_more = !!(rx_status->rx_status_0 &
		AR5K_5212_RX_DESC_STATUS0_MORE);
	rs->rs_tstamp = AR5K_REG_MS(rx_status->rx_status_1,
		AR5K_5212_RX_DESC_STATUS1_RECEIVE_TIMESTAMP);
	rs->rs_status = 0;
	rs->rs_phyerr = 0;
	rs->rs_keyix = AR5K_RXKEYIX_INVALID;

	/*
	 * Receive/descriptor errors
	 */
	if (!(rx_status->rx_status_1 &
	      AR5K_5212_RX_DESC_STATUS1_FRAME_RECEIVE_OK)) {
		if (rx_status->rx_status_1 &
				AR5K_5212_RX_DESC_STATUS1_CRC_ERROR)
			rs->rs_status |= AR5K_RXERR_CRC;

		if (rx_status->rx_status_1 &
				AR5K_5212_RX_DESC_STATUS1_PHY_ERROR) {
			rs->rs_status |= AR5K_RXERR_PHY;
			rs->rs_phyerr |= AR5K_REG_MS(rx_err->rx_error_1,
					   AR5K_RX_DESC_ERROR1_PHY_ERROR_CODE);
		}

		if (rx_status->rx_status_1 &
				AR5K_5212_RX_DESC_STATUS1_DECRYPT_CRC_ERROR)
			rs->rs_status |= AR5K_RXERR_DECRYPT;

		if (rx_status->rx_status_1 &
				AR5K_5212_RX_DESC_STATUS1_MIC_ERROR)
			rs->rs_status |= AR5K_RXERR_MIC;
	}

	return 0;
}

/*
 * Init function pointers inside ath5k_hw struct
 */
int ath5k_hw_init_desc_functions(struct ath5k_hw *ah)
{

	if (ah->ah_version != AR5K_AR5210 &&
	    ah->ah_version != AR5K_AR5211 &&
	    ah->ah_version != AR5K_AR5212)
		return -ENOTSUP;

	if (ah->ah_version == AR5K_AR5212) {
		ah->ah_setup_rx_desc = ath5k_hw_setup_rx_desc;
		ah->ah_setup_tx_desc = ath5k_hw_setup_4word_tx_desc;
		ah->ah_proc_tx_desc = ath5k_hw_proc_4word_tx_status;
	} else {
		ah->ah_setup_rx_desc = ath5k_hw_setup_rx_desc;
		ah->ah_setup_tx_desc = ath5k_hw_setup_2word_tx_desc;
		ah->ah_proc_tx_desc = ath5k_hw_proc_2word_tx_status;
	}

	if (ah->ah_version == AR5K_AR5212)
		ah->ah_proc_rx_desc = ath5k_hw_proc_5212_rx_status;
	else if (ah->ah_version <= AR5K_AR5211)
		ah->ah_proc_rx_desc = ath5k_hw_proc_5210_rx_status;

	return 0;
}

