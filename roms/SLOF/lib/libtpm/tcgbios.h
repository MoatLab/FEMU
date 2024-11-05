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

#ifndef TCGBIOS_H
#define TCGBIOS_H

#include <stdint.h>
#include <stdbool.h>

uint32_t tpm_start(void);
void tpm_finalize(void);
uint32_t tpm_leave_firmware(void);
uint32_t tpm_measure_scrtm(void);
void tpm_set_log_parameters(void *address, size_t size);
uint32_t tpm_get_logsize(void);
uint32_t tpm_measure_bcv_mbr(uint32_t bootdrv, const uint8_t *addr,
                             uint32_t length);
uint32_t tpm_add_event_separators(uint32_t start_pcr, uint32_t end_pcr);
uint32_t tpm_driver_get_failure_reason(void);
void tpm_driver_set_failure_reason(uint32_t errcode);
bool tpm_is_working(void);
void tpm20_menu(void);
void tpm_gpt_set_lba1(const uint8_t *addr, uint32_t length);
void tpm_gpt_add_entry(const uint8_t *addr, uint32_t length);
uint32_t tpm_measure_gpt(void);
uint32_t tpm_hash_log_extend_event_buffer(uint32_t pcrindex,
					  uint32_t eventtype,
					  const void *data, uint64_t datalen,
					  const char *desc, uint32_t desclen,
					  bool is_elf);
uint32_t tpm_2hash_ext_log(uint32_t pcrindex,
			   uint32_t eventtype,
			   const char *info, uint32_t infolen,
			   const void *data, uint64_t datalen);

#endif /* TCGBIOS_H */
