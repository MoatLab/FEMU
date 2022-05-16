// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Real Time Clock (RTC) attached to FSP
 *
 * Copyright 2013-2017 IBM Corp.
 */

#include <skiboot.h>
#include <fsp.h>
#include <lock.h>
#include <timebase.h>
#include <time.h>
#include <time-utils.h>
#include <opal-api.h>
#include <opal-msg.h>
#include <errorlog.h>
#include <device.h>

/*
 * Note on how those operate:
 *
 * Because the RTC calls can be pretty slow, these functions will shoot
 * an asynchronous request to the FSP (if none is already pending)
 *
 * The requests will return OPAL_BUSY_EVENT as long as the event has
 * not been completed.
 *
 * WARNING: An attempt at doing an RTC write while one is already pending
 * will simply ignore the new arguments and continue returning
 * OPAL_BUSY_EVENT. This is to be compatible with existing Linux code.
 *
 * Completion of the request will result in an event OPAL_EVENT_RTC
 * being signaled, which will remain raised until a corresponding call
 * to opal_rtc_read() or opal_rtc_write() finally returns OPAL_SUCCESS,
 * at which point the operation is complete and the event cleared.
 *
 * If we end up taking longer than rtc_read_timeout_ms millieconds waiting
 * for the response from a read request, we simply return a cached value (plus
 * an offset calculated from the timebase. When the read request finally
 * returns, we update our cache value accordingly.
 *
 * There is two separate set of state for reads and writes. If both are
 * attempted at the same time, the event bit will remain set as long as either
 * of the two has a pending event to signal.
 */

#include <rtc.h>

/* All of the below state is protected by rtc_lock.
 * It should be held for the shortest amount of time possible.
 * Certainly not across calls to FSP.
 */
static struct lock rtc_lock;

static enum {
	RTC_TOD_VALID,
	RTC_TOD_INVALID,
	RTC_TOD_PERMANENT_ERROR,
} rtc_tod_state = RTC_TOD_INVALID;

/* State machine for getting an RTC request.
 * RTC_{READ/WRITE}_NO_REQUEST -> RTC_{READ/WRITE}_PENDING_REQUEST (one in flight)
 * RTC_{READ/WRITE}_PENDING_REQUEST -> RTC_{READ/WRITE}_REQUEST_AVAILABLE,
 * when FSP responds
 * RTC_{READ/WRITE}_REQUEST_AVAILABLE -> RTC_{READ/WRITE}_NO_REQUEST,
 * when OS retrieves it
 */
static enum {
	RTC_READ_NO_REQUEST,
	RTC_READ_PENDING_REQUEST,
	RTC_READ_REQUEST_AVAILABLE,
} rtc_read_request_state = RTC_READ_NO_REQUEST;

static enum {
	RTC_WRITE_NO_REQUEST,
	RTC_WRITE_PENDING_REQUEST,
	RTC_WRITE_REQUEST_AVAILABLE,
} rtc_write_request_state = RTC_WRITE_NO_REQUEST;

static bool rtc_tod_cache_dirty = false;

struct opal_tpo_data {
	uint64_t tpo_async_token;
	__be32 *year_month_day;
	__be32 *hour_min;
};

/* Timebase value when we last initiated a RTC read request */
static unsigned long read_req_tb;

/* If a RTC read takes longer than this, we return a value generated
 * from the cache + timebase */
static const int rtc_read_timeout_ms = 1500;

DEFINE_LOG_ENTRY(OPAL_RC_RTC_TOD, OPAL_PLATFORM_ERR_EVT, OPAL_RTC,
			OPAL_PLATFORM_FIRMWARE, OPAL_INFO, OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_RTC_READ, OPAL_PLATFORM_ERR_EVT, OPAL_RTC,
			OPAL_PLATFORM_FIRMWARE, OPAL_INFO, OPAL_NA);

static void fsp_tpo_req_complete(struct fsp_msg *read_resp)
{
	struct opal_tpo_data *attr = read_resp->user_data;
	int val;
	int rc;

	val = (read_resp->resp->word1 >> 8) & 0xff;
	switch (val) {
	case FSP_STATUS_TOD_RESET:
		log_simple_error(&e_info(OPAL_RC_RTC_TOD),
			"RTC TPO in invalid state\n");
		rc = OPAL_INTERNAL_ERROR;
		break;

	case FSP_STATUS_TOD_PERMANENT_ERROR:
		log_simple_error(&e_info(OPAL_RC_RTC_TOD),
			"RTC TPO in permanent error state\n");
		rc = OPAL_INTERNAL_ERROR;
		break;
	case FSP_STATUS_INVALID_DATA:
		log_simple_error(&e_info(OPAL_RC_RTC_TOD),
			"RTC TPO: Invalid data\n");
		rc = OPAL_PARAMETER;
		break;
	case FSP_STATUS_SUCCESS:
		/* Save the read TPO value in our cache */
		if (attr->year_month_day)
			*attr->year_month_day = cpu_to_be32(fsp_msg_get_data_word(read_resp->resp, 0));
		if (attr->hour_min)
			*attr->hour_min = cpu_to_be32(fsp_msg_get_data_word(read_resp->resp, 1));
		rc = OPAL_SUCCESS;
		break;

	default:
		log_simple_error(&e_info(OPAL_RC_RTC_TOD),
			"TPO read failed: %d\n", val);
		rc = OPAL_INTERNAL_ERROR;
		break;
	}
	opal_queue_msg(OPAL_MSG_ASYNC_COMP, NULL, NULL,
		       cpu_to_be64(attr->tpo_async_token),
		       cpu_to_be64(rc));
	free(attr);
	fsp_freemsg(read_resp);
}

static void fsp_rtc_process_read(struct fsp_msg *read_resp)
{
	int val = (read_resp->word1 >> 8) & 0xff;
	struct tm tm;

	assert(lock_held_by_me(&rtc_lock));

	assert(rtc_read_request_state == RTC_READ_PENDING_REQUEST);

	switch (val) {
	case FSP_STATUS_TOD_RESET:
		log_simple_error(&e_info(OPAL_RC_RTC_TOD),
				"RTC TOD in invalid state\n");
		rtc_tod_state = RTC_TOD_INVALID;
		break;

	case FSP_STATUS_TOD_PERMANENT_ERROR:
		log_simple_error(&e_info(OPAL_RC_RTC_TOD),
			"RTC TOD in permanent error state\n");
		rtc_tod_state = RTC_TOD_PERMANENT_ERROR;
		break;

	case FSP_STATUS_SUCCESS:
		/* Save the read RTC value in our cache */
		rtc_tod_state = RTC_TOD_VALID;
		datetime_to_tm(fsp_msg_get_data_word(read_resp, 0),
			       (u64)fsp_msg_get_data_word(read_resp, 1) << 32, &tm);
		rtc_cache_update(&tm);
		prlog(PR_TRACE, "FSP-RTC Got time: %d-%d-%d %d:%d:%d\n",
		      tm.tm_year, tm.tm_mon, tm.tm_mday,
		      tm.tm_hour, tm.tm_min, tm.tm_sec);
		break;

	default:
		log_simple_error(&e_info(OPAL_RC_RTC_TOD),
				"RTC TOD read failed: %d\n", val);
		rtc_tod_state = RTC_TOD_INVALID;
	}
	rtc_read_request_state = RTC_READ_REQUEST_AVAILABLE;
}

static void opal_rtc_eval_events(bool read_write)
{
	bool request_available;

	if (read_write)
		request_available = (rtc_read_request_state ==
				     RTC_READ_REQUEST_AVAILABLE);
	else
		request_available = (rtc_write_request_state ==
				    RTC_WRITE_REQUEST_AVAILABLE);

	assert(lock_held_by_me(&rtc_lock));
	opal_update_pending_evt(OPAL_EVENT_RTC,
				request_available ? OPAL_EVENT_RTC : 0);
}

static void fsp_rtc_req_complete(struct fsp_msg *msg)
{
	lock(&rtc_lock);
	prlog(PR_TRACE, "RTC completion %p\n", msg);

	if (fsp_msg_cmd(msg) == (FSP_CMD_READ_TOD & 0xffffff)) {
		fsp_rtc_process_read(msg->resp);
		opal_rtc_eval_events(true);
	} else {
		assert(rtc_write_request_state == RTC_WRITE_PENDING_REQUEST);
		rtc_write_request_state = RTC_WRITE_REQUEST_AVAILABLE;
		opal_rtc_eval_events(false);
	}

	unlock(&rtc_lock);
	fsp_freemsg(msg);
}

static int64_t fsp_rtc_send_read_request(void)
{
	struct fsp_msg *msg;
	int rc;

	assert(lock_held_by_me(&rtc_lock));
	assert(rtc_read_request_state == RTC_READ_NO_REQUEST);

	msg = fsp_mkmsg(FSP_CMD_READ_TOD, 0);
	if (!msg) {
		log_simple_error(&e_info(OPAL_RC_RTC_READ),
			"RTC: failed to allocate read message\n");
		return OPAL_INTERNAL_ERROR;
	}

	rc = fsp_queue_msg(msg, fsp_rtc_req_complete);
	if (rc) {
		fsp_freemsg(msg);
		log_simple_error(&e_info(OPAL_RC_RTC_READ),
			"RTC: failed to queue read message: %d\n", rc);
		return OPAL_INTERNAL_ERROR;
	}

	rtc_read_request_state = RTC_READ_PENDING_REQUEST;

	read_req_tb = mftb();

	return OPAL_BUSY_EVENT;
}

static int64_t fsp_opal_rtc_read(__be32 *__ymd, __be64 *__hmsm)
{
	int64_t rc;
	uint32_t ymd;
	uint64_t hmsm;

	if (!__ymd || !__hmsm)
		return OPAL_PARAMETER;

	lock(&rtc_lock);

	if (rtc_tod_state == RTC_TOD_PERMANENT_ERROR) {
		rc = OPAL_HARDWARE;
		goto out;
	}

	/* During R/R of FSP, read cached TOD */
	if (fsp_in_rr()) {
		if (rtc_tod_state == RTC_TOD_VALID) {
			rtc_cache_get_datetime(&ymd, &hmsm);
			rc = OPAL_SUCCESS;
		} else {
			rc = OPAL_INTERNAL_ERROR;
		}
		goto out;
	}

	/* If we don't have a read pending already, fire off a request and
	 * return */
	if (rtc_read_request_state == RTC_READ_NO_REQUEST) {
		prlog(PR_TRACE, "Sending new RTC read request\n");
		rc = fsp_rtc_send_read_request();
	/* If our pending read is done, clear events and return the time
	 * from the cache */
	} else if (rtc_read_request_state == RTC_READ_REQUEST_AVAILABLE) {
                prlog(PR_TRACE, "RTC read complete, state %d\n", rtc_tod_state);
		rtc_read_request_state = RTC_READ_NO_REQUEST;

                opal_rtc_eval_events(true);

                if (rtc_tod_state == RTC_TOD_VALID) {
                        rtc_cache_get_datetime(&ymd, &hmsm);
                        prlog(PR_TRACE,"FSP-RTC Cached datetime: %x %llx\n",
                              ymd, hmsm);
                        rc = OPAL_SUCCESS;
                } else {
                        rc = OPAL_INTERNAL_ERROR;
		}

	/* Timeout: return our cached value (updated from tb), but leave the
	 * read request pending so it will update the cache later */
	} else if (mftb() > read_req_tb + msecs_to_tb(rtc_read_timeout_ms)) {
		prlog(PR_TRACE, "RTC read timed out\n");

		if (rtc_tod_state == RTC_TOD_VALID) {
			rtc_cache_get_datetime(&ymd, &hmsm);
			rc = OPAL_SUCCESS;
		} else {
                        rc = OPAL_INTERNAL_ERROR;
		}
	/* Otherwise, we're still waiting on the read to complete */
	} else {
		assert(rtc_read_request_state == RTC_READ_PENDING_REQUEST);
		rc = OPAL_BUSY_EVENT;
	}
out:
	unlock(&rtc_lock);

	if (rc == OPAL_SUCCESS) {
		*__ymd = cpu_to_be32(ymd);
		*__hmsm = cpu_to_be64(hmsm);
	}

	return rc;
}

static int64_t fsp_rtc_send_write_request(uint32_t year_month_day,
					  uint64_t hour_minute_second_millisecond)
{
	struct fsp_msg *msg;
	uint32_t w0, w1, w2;

	assert(lock_held_by_me(&rtc_lock));
	assert(rtc_write_request_state == RTC_WRITE_NO_REQUEST);

	/* Create a request and send it. Just like for read, we ignore
	 * the "millisecond" field which is probably supposed to be
	 * microseconds and which Linux ignores as well anyway
	 */
	w0 = year_month_day;
	w1 = (hour_minute_second_millisecond >> 32) & 0xffffff00;
	w2 = 0;

	msg = fsp_mkmsg(FSP_CMD_WRITE_TOD, 3, w0, w1, w2);
	if (!msg) {
		prlog(PR_TRACE, " -> allocation failed !\n");
		return OPAL_INTERNAL_ERROR;
	}
	prlog(PR_TRACE, " -> req at %p\n", msg);

	if (fsp_queue_msg(msg, fsp_rtc_req_complete)) {
		prlog(PR_TRACE, " -> queueing failed !\n");
		fsp_freemsg(msg);
		return OPAL_INTERNAL_ERROR;
	}

	rtc_write_request_state = RTC_WRITE_PENDING_REQUEST;

	return OPAL_BUSY_EVENT;
}

static int64_t fsp_opal_rtc_write(uint32_t year_month_day,
				  uint64_t hour_minute_second_millisecond)
{
	int rc;
	struct tm tm;

	lock(&rtc_lock);
	if (rtc_tod_state == RTC_TOD_PERMANENT_ERROR) {
		rc = OPAL_HARDWARE;
		goto out;
	}

	if (fsp_in_rr()) {
		datetime_to_tm(year_month_day,
			       hour_minute_second_millisecond, &tm);
		rtc_cache_update(&tm);
		rtc_tod_cache_dirty = true;
		rc = OPAL_SUCCESS;
		goto out;
	}

	if (rtc_write_request_state == RTC_WRITE_NO_REQUEST) {
		prlog(PR_TRACE, "Sending new RTC write request\n");
		rc = fsp_rtc_send_write_request(year_month_day,
						hour_minute_second_millisecond);
	} else if (rtc_write_request_state == RTC_WRITE_PENDING_REQUEST) {
		rc = OPAL_BUSY_EVENT;
	} else {
		assert(rtc_write_request_state == RTC_WRITE_REQUEST_AVAILABLE);
		rtc_write_request_state = RTC_WRITE_NO_REQUEST;

		opal_rtc_eval_events(false);
		rc = OPAL_SUCCESS;
	}

out:
	unlock(&rtc_lock);
	return rc;
}

/* Set timed power on values to fsp */
static int64_t fsp_opal_tpo_write(uint64_t async_token, uint32_t y_m_d,
			uint32_t hr_min)
{
	static struct opal_tpo_data *attr;
	struct fsp_msg *msg;

	if (!fsp_present())
		return OPAL_HARDWARE;

	attr = zalloc(sizeof(struct opal_tpo_data));
	if (!attr)
		return OPAL_NO_MEM;

	/* Create a request and send it.*/
	attr->tpo_async_token = async_token;

	/* check if this is a disable tpo request */
	if (y_m_d == 0 && hr_min == 0) {
		prlog(PR_TRACE, "Sending TPO disable request...\n");
		msg = fsp_mkmsg(FSP_CMD_TPO_DISABLE, 0);
	} else {
		prlog(PR_TRACE, "Sending TPO write request...\n");
		msg = fsp_mkmsg(FSP_CMD_TPO_WRITE, 2, y_m_d, hr_min);
	}

	if (!msg) {
		prerror("TPO: Failed to create message for WRITE to FSP\n");
		free(attr);
		return OPAL_INTERNAL_ERROR;
	}
	msg->user_data = attr;
	if (fsp_queue_msg(msg, fsp_tpo_req_complete)) {
		free(attr);
		fsp_freemsg(msg);
		return OPAL_INTERNAL_ERROR;
	}
	return OPAL_ASYNC_COMPLETION;
}

/* Read Timed power on (TPO) from FSP */
static int64_t fsp_opal_tpo_read(uint64_t async_token, __be32 *y_m_d,
			__be32 *hr_min)
{
	static struct opal_tpo_data *attr;
	struct fsp_msg *msg;
	int64_t rc;

	if (!fsp_present())
		return OPAL_HARDWARE;

	if (!y_m_d || !hr_min)
		return OPAL_PARAMETER;

	attr = zalloc(sizeof(*attr));
	if (!attr)
		return OPAL_NO_MEM;

	/* Send read requet to FSP */
	attr->tpo_async_token = async_token;
	attr->year_month_day = y_m_d;
	attr->hour_min = hr_min;

	prlog(PR_TRACE, "Sending new TPO read request\n");
	msg = fsp_mkmsg(FSP_CMD_TPO_READ, 0);
	if (!msg) {
		log_simple_error(&e_info(OPAL_RC_RTC_READ),
			"TPO: failed to allocate read message\n");
		free(attr);
		return OPAL_INTERNAL_ERROR;
	}
	msg->user_data = attr;
	rc = fsp_queue_msg(msg, fsp_tpo_req_complete);
	if (rc) {
		free(attr);
		fsp_freemsg(msg);
		log_simple_error(&e_info(OPAL_RC_RTC_READ),
			"TPO: failed to queue read message: %lld\n", rc);
		return OPAL_INTERNAL_ERROR;
	}
	return OPAL_ASYNC_COMPLETION;
}

static void rtc_flush_cached_tod(void)
{
	struct fsp_msg *msg;
	uint64_t h_m_s_m;
	uint32_t y_m_d;

	if (rtc_cache_get_datetime(&y_m_d, &h_m_s_m))
		return;
	msg = fsp_mkmsg(FSP_CMD_WRITE_TOD, 3, y_m_d,
			(h_m_s_m >> 32) & 0xffffff00, 0);
	if (!msg) {
		prerror("TPO: %s : Failed to allocate write TOD message\n",
			__func__);
		return;
	}
	if (fsp_queue_msg(msg, fsp_freemsg)) {
		fsp_freemsg(msg);
		prerror("TPO: %s : Failed to queue WRITE_TOD command\n",
			__func__);
		return;
	}
}

static bool fsp_rtc_msg_rr(u32 cmd_sub_mod, struct fsp_msg *msg)
{

	int rc = false;
	assert(msg == NULL);

	switch (cmd_sub_mod) {
	case FSP_RESET_START:
		rc = true;
		break;
	case FSP_RELOAD_COMPLETE:
		lock(&rtc_lock);
		if (rtc_tod_cache_dirty) {
			rtc_flush_cached_tod();
			rtc_tod_cache_dirty = false;
		}
		unlock(&rtc_lock);
		rc = true;
		break;
	}

	return rc;
}

static struct fsp_client fsp_rtc_client_rr = {
	.message = fsp_rtc_msg_rr,
};

void fsp_rtc_init(void)
{
	struct dt_node *np;

	if (!fsp_present()) {
		rtc_tod_state = RTC_TOD_PERMANENT_ERROR;
		return;
	}

	opal_register(OPAL_RTC_READ, fsp_opal_rtc_read, 2);
	opal_register(OPAL_RTC_WRITE, fsp_opal_rtc_write, 2);
	opal_register(OPAL_WRITE_TPO, fsp_opal_tpo_write, 3);
	opal_register(OPAL_READ_TPO,  fsp_opal_tpo_read, 3);

	np = dt_new(opal_node, "rtc");
	dt_add_property_strings(np, "compatible", "ibm,opal-rtc");
	dt_add_property(np, "has-tpo", NULL, 0);

	/* Register for the reset/reload event */
	fsp_register_client(&fsp_rtc_client_rr, FSP_MCLASS_RR_EVENT);

	prlog(PR_TRACE, "Getting initial RTC TOD\n");

	/* We don't wait for RTC response and this is actually okay as
	 * any OPAL callers will wait correctly and if we ever have
	 * internal users then they should check the state properly
	 */
	lock(&rtc_lock);
	fsp_rtc_send_read_request();
	unlock(&rtc_lock);
}
