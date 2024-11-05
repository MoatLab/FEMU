// SPDX-License-Identifier: Apache-2.0
/* Copyright 2020 IBM Corp. */

#ifndef __RAS_H
#define __RAS_H

#include <compiler.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <bitutils.h>
#include <types.h>

#include <ccan/container_of/container_of.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>
#include <ccan/str/str.h>

#include <processor.h>

#define MCE_NO_ERROR			0x0001
#define MCE_UNKNOWN			0x0002
#define MCE_INSNFETCH			0x0004
#define MCE_LOADSTORE			0x0008
#define MCE_TABLE_WALK			0x0010
#define MCE_IMPRECISE			0x0020
#define MCE_MEMORY_ERROR		0x0040
#define MCE_SLB_ERROR			0x0080
#define MCE_ERAT_ERROR			0x0100
#define MCE_TLB_ERROR			0x0200
#define MCE_TLBIE_ERROR			0x0400
#define MCE_INVOLVED_EA			0x0800
#define MCE_INVOLVED_PA			0x1000

void decode_mce(uint64_t srr0, uint64_t srr1,
		uint32_t dsisr, uint64_t dar,
		uint64_t *type, const char **error_str,
		uint64_t *address);

#endif /* __RAS_H */
