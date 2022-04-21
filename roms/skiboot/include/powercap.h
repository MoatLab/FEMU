// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2017 IBM Corp. */

#ifndef __POWERCAP_H
#define __POWERCAP_H

#include <opal.h>

enum powercap_class {
	POWERCAP_CLASS_OCC,
};

/*
 * Powercap handle is defined as u32. The first and last bytes are
 * used to indicate the class and attribute.
 *
 *	| Class |    Reserved   | Attribute |
 *	|-------|---------------|-----------|
 */

#define powercap_make_handle(class, attr) (((class & 0xF) << 24) | (attr & 0xF))

#define powercap_get_class(handle)	((handle >> 24) & 0xF)
#define powercap_get_attr(handle)	(handle & 0xF)

/* Powercap OCC interface */
int occ_get_powercap(u32 handle, u32 *pcap);
int __attribute__((__const__)) occ_set_powercap(u32 handle, int token, u32 pcap);

#endif /* __POWERCAP_H */
