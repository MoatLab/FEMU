// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2017 IBM Corp. */

#ifndef __PSR_H
#define __PSR_H

#include <opal.h>

enum psr_class {
	PSR_CLASS_OCC,
};

/*
 * PSR handle is defined as u32. The first and last bytes are
 * used to indicate the class and type. RID indiactes psr class
 * specific data. For PSR_CLASS_OCC psr class RID is the chip index.
 *
 *	| Class |Reserved|  RID	| Type |
 *	|-------|--------|------|------|
 */

#define psr_make_handle(class, rid, type) (((class & 0xF) << 24) | \
					   ((rid & 0xF) << 8) | (type & 0xF))

#define psr_get_class(handle)	((handle >> 24) & 0xF)
#define psr_get_rid(handle)	((handle >> 8) & 0xF)
#define psr_get_type(handle)	(handle & 0xF)

/* Powercap OCC interface */
int occ_get_psr(u32 handle, u32 *ratio);
int occ_set_psr(u32 handle, int token, u32 ratio);

#endif /* __PSR_H */
