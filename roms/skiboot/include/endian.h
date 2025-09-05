// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2022 IBM Corp. */

#ifndef _ENDIAN_H_
#define _ENDIAN_H_

#include <ccan/endian/endian.h>

/* use the ccan endian conversion functions */
#define htobe16 cpu_to_be16
#define htobe32 cpu_to_be32
#define htole16 cpu_to_le16
#define htole32 cpu_to_le32
#define htobe64 cpu_to_be64
#define htole64 cpu_to_le64

#define be16toh be16_to_cpu
#define be32toh be32_to_cpu
#define le16toh le16_to_cpu
#define le32toh le32_to_cpu
#define le64toh le64_to_cpu
#define be64toh be64_to_cpu

#endif /* _ENDIAN_H_ */
