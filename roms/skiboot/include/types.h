// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2015 IBM Corp. */

#ifndef __TYPES_H
#define __TYPES_H
#include <ccan/short_types/short_types.h>
#include <ccan/endian/endian.h>

/* These are currently just for clarity, but we could apply sparse. */
typedef beint16_t __be16;
typedef beint32_t __be32;
typedef beint64_t __be64;

typedef leint16_t __le16;
typedef leint32_t __le32;
typedef leint64_t __le64;

#endif /* __TYPES_H */

