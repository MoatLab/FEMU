// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Real Time Clock hanging off LPC
 *
 * Copyright 2015 IBM Corp.
 */

#include <stdlib.h>
#include <string.h>
#include <ipmi.h>
#include <time.h>
#include <time-utils.h>
#include <device.h>
#include <opal.h>
#include <rtc.h>
#include <lpc.h>
#include <lock.h>
#include <timebase.h>

/* Legacy RTC registers */
#define RTC_REG_SECONDS		0
#define RTC_REG_MINUTES		2
#define RTC_REG_HOURS		4
#define RTC_REG_DAY_OF_WEEK	6
#define RTC_REG_DAY_OF_MONTH	7
#define RTC_REG_MONTH		8
#define RTC_REG_YEAR		9
#define RTC_REG_A		10
#define   RTC_REG_A_UIP			0x80
#define RTC_REG_B		11
#define   RTC_REG_B_DIS_UPD		0x80
#define   RTC_REG_B_PIE			0x40
#define   RTC_REG_B_AIE			0x20
#define   RTC_REG_B_UIE			0x10
#define   RTC_REG_B_SQWE		0x08
#define   RTC_REG_B_DM_BINARY		0x04
#define   RTC_REG_B_24H			0x02
#define   RTC_REG_B_DST_EN		0x01
#define RTC_REG_C		12
#define RTC_REG_D		13
#define   RTC_REG_D_VALID		0x80

/* Init value is no interrupts, 24H mode, updates enabled */
#define RTC_REG_B_INIT		(RTC_REG_B_24H)

static u32 rtc_port;
static struct lock rtc_lock = LOCK_UNLOCKED;

static uint8_t rtc_read(uint8_t reg)
{
	lpc_outb(reg, rtc_port);
	return lpc_inb(rtc_port + 1);
}

static void rtc_write(uint8_t reg, uint8_t val)
{
	lpc_outb(reg, rtc_port);
	lpc_outb(val, rtc_port + 1);
}

static bool lpc_rtc_read_tm(struct tm *tm)
{
	struct tm tm2;
	unsigned int loops = 0;

	/* Read until two series provide identical values, this
	 * should deal with update races in all practical cases
	 */
	for (;;) {
		tm2 = *tm;
		tm->tm_sec = rtc_read(RTC_REG_SECONDS);
		tm->tm_min = rtc_read(RTC_REG_MINUTES);
		tm->tm_hour = rtc_read(RTC_REG_HOURS);
		tm->tm_mday = rtc_read(RTC_REG_DAY_OF_MONTH);
		tm->tm_mon = rtc_read(RTC_REG_MONTH);
		tm->tm_year = rtc_read(RTC_REG_YEAR);
		if (loops > 0 && memcmp(&tm2, tm, sizeof(struct tm)) == 0)
			break;
		loops++;
		if (loops > 10) {
			prerror("RTC: Failed to obtain stable values\n");
			return false;
		}
	}
	tm->tm_sec = bcd_byte(tm->tm_sec, 0);
	tm->tm_min = bcd_byte(tm->tm_min, 0);
	tm->tm_hour = bcd_byte(tm->tm_hour, 0);
	tm->tm_mday = bcd_byte(tm->tm_mday, 0);
	tm->tm_mon = bcd_byte(tm->tm_mon, 0) - 1;
	tm->tm_year = bcd_byte(tm->tm_year, 0);

	/* 2000 wrap */
	if (tm->tm_year < 69)
		tm->tm_year += 100;

	/* Base */
	tm->tm_year += 1900;

	return true;
}

static void lpc_rtc_write_tm(struct tm *tm __unused)
{
	/* XXX */
}

static void lpc_init_time(void)
{
	uint8_t val;
	struct tm tm;
	bool valid;

	memset(&tm, 0, sizeof(tm));

	lock(&rtc_lock);

	/* If update is in progress, wait a bit */
	val = rtc_read(RTC_REG_A);
	if (val & RTC_REG_A_UIP)
		time_wait_ms(10);

	/* Read from RTC */
	valid = lpc_rtc_read_tm(&tm);

	unlock(&rtc_lock);

	/* Update cache */
	if (valid)
		rtc_cache_update(&tm);
}

static void lpc_init_hw(void)
{
	lock(&rtc_lock);

	/* Set REG B to a suitable default */
	rtc_write(RTC_REG_B, RTC_REG_B_INIT);

	unlock(&rtc_lock);
}

static int64_t lpc_opal_rtc_read(__be32 *__ymd, __be64 *__hmsm)
{
	uint8_t val;
	int64_t rc = OPAL_SUCCESS;
	struct tm tm;
	uint32_t ymd;
	uint64_t hmsm;

	if (!__ymd || !__hmsm)
		return OPAL_PARAMETER;

	/* Return busy if updating. This is somewhat racy, but will
	 * do for now, most RTCs nowadays are smart enough to atomically
	 * update. Alternatively we could just read from the cache...
	 */
	lock(&rtc_lock);
	val = rtc_read(RTC_REG_A);
	if (val & RTC_REG_A_UIP) {
		unlock(&rtc_lock);
		return OPAL_BUSY_EVENT;
	}

	/* Read from RTC */
	if (lpc_rtc_read_tm(&tm))
		rc = OPAL_SUCCESS;
	else
		rc = OPAL_HARDWARE;
	unlock(&rtc_lock);

	if (rc == OPAL_SUCCESS) {
		/* Update cache */
		rtc_cache_update(&tm);

		/* Convert to OPAL time */
		tm_to_datetime(&tm, &ymd, &hmsm);
		*__ymd = cpu_to_be32(ymd);
		*__hmsm = cpu_to_be64(hmsm);
	}

	return rc;
}

static int64_t lpc_opal_rtc_write(uint32_t year_month_day,
				  uint64_t hour_minute_second_millisecond)
{
	struct tm tm;

	/* Convert to struct tm */
	datetime_to_tm(year_month_day, hour_minute_second_millisecond, &tm);

	/* Write it out */
	lock(&rtc_lock);
	lpc_rtc_write_tm(&tm);
	unlock(&rtc_lock);

	return OPAL_SUCCESS;
}

void lpc_rtc_init(void)
{
	struct dt_node *rtc_node, *np;

	if (!lpc_present())
		return;

	/* We support only one */
	rtc_node = dt_find_compatible_node(dt_root, NULL, "pnpPNP,b00");
	if (!rtc_node)
		return;

	/* Get IO base */
	rtc_port = dt_prop_get_cell_def(rtc_node, "reg", 1, 0);
	if (!rtc_port) {
		prerror("RTC: Can't find reg property\n");
		return;
	}
	if (dt_prop_get_cell_def(rtc_node, "reg", 0, 0) != OPAL_LPC_IO) {
		prerror("RTC: Unsupported address type\n");
		return;
	}

	/* Init the HW */
	lpc_init_hw();

	/* Create OPAL API node and register OPAL calls */
	np = dt_new(opal_node, "rtc");
	dt_add_property_strings(np, "compatible", "ibm,opal-rtc");

	opal_register(OPAL_RTC_READ, lpc_opal_rtc_read, 2);
	opal_register(OPAL_RTC_WRITE, lpc_opal_rtc_write, 2);

	/* Initialise the rtc cache */
	lpc_init_time();
}
