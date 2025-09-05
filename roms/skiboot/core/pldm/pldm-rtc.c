// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// Copyright 2022 IBM Corp.

#define pr_fmt(fmt) "PLDM: " fmt

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <time-utils.h>
#include <device.h>
#include <opal.h>
#include <rtc.h>
#include <bios.h>
#include <utils.h>
#include "pldm.h"

struct get_date_time_resp {
	uint8_t completion_code;
	uint8_t seconds;
	uint8_t minutes;
	uint8_t hours;
	uint8_t day;
	uint8_t month;
	uint16_t year;
};

static enum {idle, waiting, updated, error} time_status;

static void cache_get_datetime(struct tm *tm)
{
	if (tm == NULL)
		time_status = error;
	else {
		rtc_cache_update(tm);
		time_status = updated;
	}
}

static void get_date_time_req_complete(struct pldm_rx_data *rx,
				       void *data __unused)
{
	struct get_date_time_resp response;
	size_t payload_len;
	struct tm tm;
	int rc;

	if (rx == NULL) {
		prlog(PR_ERR, "%s: Response not received\n", __func__);
		cache_get_datetime(NULL);
		return;
	}

	/* Decode the message */
	payload_len = rx->msg_len - sizeof(struct pldm_msg_hdr);
	rc = decode_get_date_time_resp(
			rx->msg,
			payload_len,
			&response.completion_code,
			&response.seconds,
			&response.minutes,
			&response.hours,
			&response.day,
			&response.month,
			&response.year);
	if (rc != PLDM_SUCCESS || response.completion_code != PLDM_SUCCESS) {
		prlog(PR_ERR, "Decode GetBiosDateTimeReq Error, rc: %d, cc: %d\n",
				rc, response.completion_code);
		cache_get_datetime(NULL);
		return;
	}

	/* The data arrives from BMC in BCD format. Convert it to
	 * decimal for processing
	 */
	tm.tm_sec = bcd2dec8(response.seconds);
	tm.tm_min = bcd2dec8(response.minutes);
	tm.tm_hour = bcd2dec8(response.hours);
	tm.tm_mday = bcd2dec8(response.day);
	tm.tm_mon = bcd2dec8(response.month);
	tm.tm_year = bcd2dec16(response.year);

	if (!is_time_legal(tm.tm_sec, tm.tm_min, tm.tm_hour,
			   tm.tm_mday, tm.tm_mon, tm.tm_year)) {
		prlog(PR_ERR, "%s: Invalid date time value\n", __func__);
		cache_get_datetime(NULL);
		return;
	}

	cache_get_datetime(&tm);
}

/*
 * Send a PLDM GetBiosDateTime request message
 */
static int get_date_time_req(void)
{
	size_t data_size = PLDM_MSG_SIZE(0); /* the command doesn't have a message payload */
	struct pldm_tx_data *tx = NULL;
	int rc;

	/* Encode the date time request */
	tx = zalloc(sizeof(struct pldm_tx_data) + data_size);
	if (!tx)
		return OPAL_NO_MEM;
	tx->data_size = data_size;

	rc = encode_get_date_time_req(DEFAULT_INSTANCE_ID,
				      (struct pldm_msg *)tx->data);
	if (rc != PLDM_SUCCESS) {
		prlog(PR_ERR, "Encode GetBiosDateTimeReq Error, rc: %d\n", rc);
		free(tx);
		return OPAL_PARAMETER;
	}

	/* Queue and get the response message bytes */
	rc = pldm_requester_queue(tx, get_date_time_req_complete, NULL);
	if (rc) {
		prlog(PR_ERR, "Communication Error, req: GetBiosDateTimeReq, rc: %d\n", rc);
		free(tx);
		return rc;
	}

	free(tx);
	return OPAL_SUCCESS;
}

static int64_t pldm_opal_rtc_read(__be32 *__ymd, __be64 *__hmsm)
{
	uint32_t ymd;
	uint64_t hmsm;
	int rc = OPAL_SUCCESS;

	if (!__ymd || !__hmsm)
		return OPAL_PARAMETER;

	switch (time_status) {
	case idle:
		rc = get_date_time_req();
		if (rc)
			return OPAL_HARDWARE;
		time_status = waiting;
		rc = OPAL_BUSY_EVENT;
		break;

	case waiting:
		rc = OPAL_BUSY_EVENT;
		break;

	case updated:
		rtc_cache_get_datetime(&ymd, &hmsm);
		*__ymd = cpu_to_be32(ymd);
		*__hmsm = cpu_to_be64(hmsm);
		time_status = idle;
		rc = OPAL_SUCCESS;
		break;

	case error:
		time_status = idle;
		rc = OPAL_HARDWARE;
		break;
	}

	return rc;
}

/*
 * Receive the PLDM SetBiosDateTime response
 */
static void set_date_time_req_complete(struct pldm_rx_data *rx,
				       void *data __unused)
{
	uint8_t completion_code;
	size_t payload_len;
	int rc;

	if (rx == NULL) {
		prlog(PR_ERR, "%s: Response not received\n", __func__);
		return;
	}

	/* Decode the message */
	payload_len = rx->msg_len - sizeof(struct pldm_msg_hdr);

	rc = decode_set_date_time_resp(rx->msg,
				       payload_len,
				       &completion_code);
	if (rc != PLDM_SUCCESS || (completion_code > PLDM_ERROR)) {
		/* FIXME: Time value from OPAL_RTC_WRITE is never correct */
		prlog(PR_ERR, "Decode SetBiosDateTimeReq Error, rc: %d, cc: %d\n",
			       rc, completion_code);
	}
}

/*
 * Send a PLDM SetBiosDateTime request message
 */
static int set_date_time_req(struct tm *tm)
{
	size_t data_size = PLDM_MSG_SIZE(struct pldm_set_date_time_req);
	struct pldm_tx_data *tx = NULL;
	int rc;

	/* Encode the date time request */
	tx = zalloc(sizeof(struct pldm_tx_data) + data_size);
	if (!tx)
		return OPAL_NO_MEM;
	tx->data_size = data_size;

	rc = encode_set_date_time_req(
				DEFAULT_INSTANCE_ID,
				tm->tm_sec, tm->tm_min, tm->tm_hour,
				tm->tm_mday, tm->tm_mon, tm->tm_year,
				(struct pldm_msg *)tx->data,
				sizeof(struct pldm_set_date_time_req));
	if (rc != PLDM_SUCCESS) {
		prlog(PR_ERR, "Encode SetBiosDateTimeReq Error, rc: %d\n",
			      rc);
		free(tx);
		return OPAL_PARAMETER;
	}

	/* Queue and get the response message bytes */
	rc = pldm_requester_queue(tx, set_date_time_req_complete, NULL);
	if (rc) {
		prlog(PR_ERR, "Communication Error, req: SetBiosDateTimeReq, rc: %d\n", rc);
		free(tx);
		return rc;
	}

	free(tx);
	return OPAL_SUCCESS;
}

static int64_t pldm_opal_rtc_write(uint32_t year_month_day,
				   uint64_t hour_minute_second_millisecond)
{
	struct tm tm;
	int rc;

	datetime_to_tm(year_month_day, hour_minute_second_millisecond, &tm);

	rc = set_date_time_req(&tm);
	if (rc == OPAL_BUSY)
		return OPAL_BUSY;

	return OPAL_SUCCESS;
}

void pldm_rtc_init(void)
{
	struct dt_node *np = dt_new(opal_node, "rtc");

	dt_add_property_strings(np, "compatible", "ibm,opal-rtc");

	opal_register(OPAL_RTC_READ, pldm_opal_rtc_read, 2);
	opal_register(OPAL_RTC_WRITE, pldm_opal_rtc_write, 2);

	/* Initialise the rtc cache */
	get_date_time_req();
}
