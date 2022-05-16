// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2015-2017 IBM Corp. */

#include <skiboot.h>
#include <stdlib.h>

#include "../include/device.h"

/* dump_dt() is used in hdata/test/hdata_to_dt.c and core/test/run-device.c
 * this file is directly #included in both
 */

static void indent_num(unsigned indent)
{
	unsigned int i;

	for (i = 0; i < indent; i++)
		putc(' ', stdout);
}

static void dump_val(unsigned indent, const void *prop, size_t size)
{
	size_t i;
	int width = 78 - indent;

	for (i = 0; i < size; i++) {
		printf("%02x", ((unsigned char *)prop)[i]);
		width -= 2;
		if(width < 2) {
			printf("\n");
			indent_num(indent);
			width = 80 - indent;
		}
	}
}

void dump_dt(const struct dt_node *root, unsigned indent, bool show_props);

void dump_dt(const struct dt_node *root, unsigned indent, bool show_props)
{
	const struct dt_node *i;
	const struct dt_property *p;

	indent_num(indent);
	printf("node: %s\n", root->name);

	if (show_props) {
		list_for_each(&root->properties, p, list) {
			indent_num(indent);
			printf("prop: %s size: %zu val: ", p->name, p->len);
			dump_val(indent, p->prop, p->len);
			printf("\n");
		}
	}

	list_for_each(&root->children, i, list)
		dump_dt(i, indent + 2, show_props);
}

