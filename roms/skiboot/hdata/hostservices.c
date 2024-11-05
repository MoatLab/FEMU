// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2017 IBM Corp. */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include <libfdt/libfdt.h>
#include <skiboot.h>
#include <device.h>
#include <compiler.h>
#include <hostservices.h>

#include "spira.h"
#include "hdata.h"

static void merge_property(const struct dt_node *src_root,
			   struct dt_node *dst_root,
			   const char *name)
{
	const struct dt_property *src;
	struct dt_property *dst;

	/* Nothing to merge if old one doesn't exist. */
	src = dt_find_property(src_root, name);
	if (!src)
		return;

	/* Just create a new one if there's none in dst. */
	dst = __dt_find_property(dst_root, name);
	if (!dst) {
		dt_add_property(dst_root, name, src->prop, src->len);
		return;
	}

	/* Append src to dst. */
	dt_resize_property(&dst, dst->len + src->len);
	memcpy(dst->prop + dst->len, src->prop, src->len);
}

static void hservice_parse_dt_tree(const struct dt_node *src)
{
	const struct dt_property *sprop;

	/* Copy/merge reserved names & ranges properties. */
	list_for_each(&src->properties, sprop, list) {
		if (streq(sprop->name, "reserved-names") ||
		    streq(sprop->name, "reserved-ranges") ||
		    streq(sprop->name, "ibm,enabled-idle-states"))
			merge_property(src, dt_root, sprop->name);
	}
}

/* Get host services information from hdat. */
bool hservices_from_hdat(const void *fdt, size_t size)
{
	int err;
	struct dt_node *hservices;

	prlog(PR_DEBUG, "HBRT: Found mini-DT at 0x%p size: 0x%08lx\n",
	      fdt, size);

	/* For diagnostic purposes, we copy the whole blob over */
	dt_add_property(dt_root, "ibm,hbrt-mini-fdt", fdt, size);

	/* Parse & extract relevant properties */
	err = fdt_check_header(fdt);
	if (err) {
		prerror("HBRT: fdt blob %p hdr error %d\n", fdt, err);
		return false;
	}

	hservices = dt_new_root("ibm,hostservices");
	err = dt_expand_node(hservices, fdt, 0);
	if (err < 0) {
		prerror("HBRT: fdt blob %p parse error %d\n", fdt, err);
		return false;
	}

	hservice_parse_dt_tree(hservices);
	dt_free(hservices);
	return true;
}

