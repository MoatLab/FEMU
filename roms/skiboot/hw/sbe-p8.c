// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * POWER8 Self Boot Engine (SLW - SLeep/Winkle)
 *
 * Copyright 2013-2018 IBM Corp.
 */

#include <device.h>
#include <sbe-p8.h>
#include <skiboot.h>
#include <timebase.h>
#include <xscom.h>

/* SLW timer related stuff */
static bool sbe_has_timer;
static uint64_t sbe_timer_inc;
static uint64_t sbe_timer_target;
static uint32_t sbe_timer_chip;
static uint64_t sbe_last_gen;
static uint64_t sbe_last_gen_stamp;

static void p8_sbe_dump_timer_ffdc(void)
{
	uint64_t i, val;
	int64_t rc;

	static const uint32_t dump_regs[] = {
		0xe0000, 0xe0001, 0xe0002, 0xe0003,
		0xe0004, 0xe0005, 0xe0006, 0xe0007,
		0xe0008, 0xe0009, 0xe000a, 0xe000b,
		0xe000c, 0xe000d, 0xe000e, 0xe000f,
		0xe0010, 0xe0011, 0xe0012, 0xe0013,
		0xe0014, 0xe0015, 0xe0016, 0xe0017,
		0xe0018, 0xe0019,
		0x5001c,
		0x50038, 0x50039, 0x5003a, 0x5003b
	};

	/**
	 * @fwts-label SLWRegisterDump
	 * @fwts-advice An error condition occurred in sleep/winkle
	 * engines timer state machine. Dumping debug information to
	 * root-cause. OPAL/skiboot may be stuck on some operation that
	 * requires SLW timer state machine (e.g. core powersaving)
	 */
	prlog(PR_DEBUG, "SLW: Register state:\n");

	for (i = 0; i < ARRAY_SIZE(dump_regs); i++) {
		uint32_t reg = dump_regs[i];
		rc = xscom_read(sbe_timer_chip, reg, &val);
		if (rc) {
			prlog(PR_DEBUG, "SLW: XSCOM error %lld reading"
			      " reg 0x%x\n", rc, reg);
			break;
		}
		prlog(PR_DEBUG, "SLW:  %5x = %016llx\n", reg, val);
	}
}

/* This is called with the timer lock held, so there is no
 * issue with re-entrancy or concurrence
 */
void p8_sbe_update_timer_expiry(uint64_t new_target)
{
	uint64_t count, gen, gen2, req, now;
	int64_t rc;

	if (!sbe_has_timer || new_target == sbe_timer_target)
		return;

	sbe_timer_target = new_target;

	_xscom_lock();
	now = mftb();
	/* Calculate how many increments from now, rounded up */
	if (now < new_target)
		count = (new_target - now + sbe_timer_inc - 1) / sbe_timer_inc;
	else
		count = 1;

	/* Max counter is 24-bit */
	if (count > 0xffffff)
		count = 0xffffff;
	/* Fabricate update request */
	req = (1ull << 63) | (count << 32);

	prlog(PR_TRACE, "SLW: TMR expiry: 0x%llx, req: %016llx\n", count, req);

	do {
		/* Grab generation and spin if odd */
		for (;;) {
			rc = _xscom_read(sbe_timer_chip, 0xE0006, &gen, false);
			if (rc) {
				prerror("SLW: Error %lld reading tmr gen "
					" count\n", rc);
				_xscom_unlock();
				return;
			}
			if (!(gen & 1))
				break;
			if (tb_compare(now + msecs_to_tb(1), mftb()) == TB_ABEFOREB) {
				/**
				 * @fwts-label SLWTimerStuck
				 * @fwts-advice The SLeep/Winkle Engine (SLW)
				 * failed to increment the generation number
				 * within our timeout period (it *should* have
				 * done so within ~10us, not >1ms. OPAL uses
				 * the SLW timer to schedule some operations,
				 * but can fall back to the (much less frequent
				 * OPAL poller, which although does not affect
				 * functionality, runs *much* less frequently.
				 * This could have the effect of slow I2C
				 * operations (for example). It may also mean
				 * that you *had* an increase in jitter, due
				 * to slow interactions with SLW.
				 * This error may also occur if the machine
				 * is connected to via soft FSI.
				 */
				prerror("SLW: timer stuck, falling back to OPAL pollers. You will likely have slower I2C and may have experienced increased jitter.\n");
				prlog(PR_DEBUG, "SLW: Stuck with odd generation !\n");
				_xscom_unlock();
				sbe_has_timer = false;
				p8_sbe_dump_timer_ffdc();
				return;
			}
		}

		rc = _xscom_write(sbe_timer_chip, 0x5003A, req, false);
		if (rc) {
			prerror("SLW: Error %lld writing tmr request\n", rc);
			_xscom_unlock();
			return;
		}

		/* Re-check gen count */
		rc = _xscom_read(sbe_timer_chip, 0xE0006, &gen2, false);
		if (rc) {
			prerror("SLW: Error %lld re-reading tmr gen "
				" count\n", rc);
			_xscom_unlock();
			return;
		}
	} while(gen != gen2);
	_xscom_unlock();

	/* Check if the timer is working. If at least 1ms has elapsed
	 * since the last call to this function, check that the gen
	 * count has changed
	 */
	if (tb_compare(sbe_last_gen_stamp + msecs_to_tb(1), now)
	    == TB_ABEFOREB) {
		if (sbe_last_gen == gen) {
			prlog(PR_ERR,
			      "SLW: Timer appears to not be running !\n");
			sbe_has_timer = false;
			p8_sbe_dump_timer_ffdc();
		}
		sbe_last_gen = gen;
		sbe_last_gen_stamp = mftb();
	}

	prlog(PR_TRACE, "SLW: gen: %llx\n", gen);
}

bool p8_sbe_timer_ok(void)
{
	return sbe_has_timer;
}

void p8_sbe_init_timer(void)
{
	struct dt_node *np;
	int64_t rc;
	uint32_t tick_us;

	np = dt_find_compatible_node(dt_root, NULL, "ibm,power8-sbe-timer");
	if (!np)
		return;

	sbe_timer_chip = dt_get_chip_id(np);
	tick_us = dt_prop_get_u32(np, "tick-time-us");
	sbe_timer_inc = usecs_to_tb(tick_us);
	sbe_timer_target = ~0ull;

	rc = xscom_read(sbe_timer_chip, 0xE0006, &sbe_last_gen);
	if (rc) {
		prerror("SLW: Error %lld reading tmr gen count\n", rc);
		return;
	}
	sbe_last_gen_stamp = mftb();

	prlog(PR_INFO, "SLW: Timer facility on chip %d, resolution %dus\n",
	      sbe_timer_chip, tick_us);
	sbe_has_timer = true;
}
