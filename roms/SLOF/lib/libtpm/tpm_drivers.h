/*****************************************************************************
 * Copyright (c) 2015-2020 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#ifndef TPM_DRIVERS_H
#define TPM_DRIVERS_H

#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#include "tcgbios_int.h"

enum tpm_duration_type {
	TPM_DURATION_TYPE_SHORT = 0,
	TPM_DURATION_TYPE_MEDIUM,
	TPM_DURATION_TYPE_LONG,
};

/* firmware driver states */
typedef enum {
	VTPM_DRV_STATE_INVALID = 0,
	VTPM_DRV_STATE_INIT_CALLED = 1,
	VTPM_DRV_STATE_REG_CRQ = 2,
	VTPM_DRV_STATE_WAIT_INIT = 3,
	VTPM_DRV_STATE_SEND_INIT = 4,
	VTPM_DRV_STATE_FAILURE = 5,
	VTPM_DRV_STATE_WAIT_INIT_COMP = 6,
	VTPM_DRV_STATE_SEND_INIT_COMP = 7,
	VTPM_DRV_STATE_SEND_GET_VERSION = 8,
	VTPM_DRV_STATE_WAIT_VERSION = 9,
	VTPM_DRV_STATE_CHECK_VERSION = 10,
	VTPM_DRV_STATE_SEND_BUFSIZE_REQ = 11,
	VTPM_DRV_STATE_WAIT_BUFSIZE = 12,
	VTPM_DRV_STATE_ALLOC_RTCE_BUF = 13,
	VTPM_DRV_STATE_SEND_TPM_CMD = 14,
	VTPM_DRV_STATE_WAIT_TPM_RSP = 15,
} vtpm_drv_state;

/* firmware driver errors */
typedef enum {
	VTPM_DRV_ERROR_NO_FAILURE = -1,
	VTPM_DRV_ERROR_NOT_FOUND_TIMEOUT = 0,
	VTPM_DRV_ERROR_UNEXPECTED_REG_ERROR = 1,
	VTPM_DRV_ERROR_PARTNER_FAILED = 2,
	VTPM_DRV_ERROR_UNEXPECTED_TSP_ERROR = 3,
	VTPM_DRV_ERROR_TPM_PROTOCOL_ERROR = 4,
	VTPM_DRV_ERROR_WAIT_TIMEOUT = 5,
	VTPM_DRV_ERROR_UNEXPECTED_SEND_ERROR = 6,
	VTPM_DRV_ERROR_CRQ_OPEN_FAIL = 7,
	VTPM_DRV_ERROR_BAD_STATE = 8,
	VTPM_DRV_ERROR_TPM_FAIL = 9,
	VTPM_DRV_ERROR_TPM_CRQ_ERROR = 10,
	VTPM_DRV_ERROR_BAD_VERSION = 11,
	VTPM_DRV_ERROR_BAD_RTCE_SIZE = 12,
	VTPM_DRV_ERROR_SML_FAILURE = 13,
	VTPM_DRV_ERROR_SML_HANDED_OVER = 14,
} vtpm_drv_error;

/* the max. buffer size by the external TPM is 4k */
#define PAPR_VTPM_MAX_BUFFER_SIZE       4096

/* exported functions */
bool spapr_is_vtpm_present(void);
void spapr_vtpm_finalize(void);
vtpm_drv_error spapr_vtpm_get_error(void);
void spapr_vtpm_set_error(vtpm_drv_error errcode);

struct tpm_req_header;
int spapr_transmit(uint8_t locty, struct tpm_req_header *req,
                   void *respbuffer, uint32_t *respbufferlen,
                   enum tpm_duration_type to_t);

#endif /* TPM_DRIVERS_H */
