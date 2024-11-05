// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2017 IBM Corp. */

#include <skiboot.h>
#include <opal.h>
#include <mem_region.h>
#include <device.h>
#include <timebase.h>
#include <time-utils.h>
#include <lock.h>

/* timebase when tm_offset was assigned */
static unsigned long tb_synctime;

/*
 * Absolute time that was last assigned.
 * Current rtc value is calculated from this.
*/
static struct tm tm_offset;

/* protects tm_offset & tb_synctime */
static struct lock emulation_lock;

static int64_t fake_rtc_write(uint32_t ymd, uint64_t hmsm)
{

	lock(&emulation_lock);

	datetime_to_tm(ymd, hmsm, &tm_offset);
	tb_synctime = mftb();

	unlock(&emulation_lock);

	return OPAL_SUCCESS;
}

static int64_t fake_rtc_read(__be32 *__ymd, __be64 *__hmsm)
{

	time_t sec;
	struct tm tm_calculated;
	uint32_t ymd;
	uint64_t hmsm;

	if (!__ymd || !__hmsm)
		return OPAL_PARAMETER;

	/* Compute the emulated clock value */
	lock(&emulation_lock);

	sec = tb_to_secs(mftb() - tb_synctime) + mktime(&tm_offset);
	gmtime_r(&sec, &tm_calculated);
	tm_to_datetime(&tm_calculated, &ymd, &hmsm);

	unlock(&emulation_lock);

	*__ymd = cpu_to_be32(ymd);
	*__hmsm = cpu_to_be64(hmsm);

	return OPAL_SUCCESS;
}

void fake_rtc_init(void)
{
	struct mem_region *rtc_region = NULL;
	uint32_t *rtc = NULL, *fake_ymd;
	uint64_t *fake_hmsm;
	struct dt_node *np;

	/* Read initial values from reserved memory */
	rtc_region = find_mem_region("ibm,fake-rtc");

	/* Should we register anyway? */
	if (!rtc_region) {
		prlog(PR_TRACE, "No initial RTC value found\n");
		return;
	}

	init_lock(&emulation_lock);

	/* Fetch the initial rtc values */
	rtc = (uint32_t *) rtc_region->start;

	fake_ymd = rtc;
	fake_hmsm = ((uint64_t *) &rtc[1]);

	fake_rtc_write(*fake_ymd, *fake_hmsm);

	/* Register opal calls */
	opal_register(OPAL_RTC_READ, fake_rtc_read, 2);
	opal_register(OPAL_RTC_WRITE, fake_rtc_write, 2);

	/* add the fake rtc dt node */
	np = dt_new(opal_node, "rtc");
	dt_add_property_strings(np, "compatible", "ibm,opal-rtc");

	prlog(PR_TRACE, "Init fake RTC to Date:%d-%d-%d Time:%d-%d-%d\n",
	      tm_offset.tm_mon, tm_offset.tm_mday, tm_offset.tm_year,
	      tm_offset.tm_hour, tm_offset.tm_min, tm_offset.tm_sec);
}
