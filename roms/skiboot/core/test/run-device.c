// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2012-2018 IBM Corp.
 */

#include <skiboot.h>
#include <stdlib.h>

/* Override this for testing. */
#define is_rodata(p) fake_is_rodata(p)

char __rodata_start[16];
#define __rodata_end (__rodata_start + sizeof(__rodata_start))

static inline bool fake_is_rodata(const void *p)
{
	return ((char *)p >= __rodata_start && (char *)p < __rodata_end);
}

#define zalloc(bytes) calloc((bytes), 1)

#include "../device.c"
#include <assert.h>
#include "../../test/dt_common.c"
const char *prop_to_fix[] = {"something", NULL};
const char **props_to_fix(struct dt_node *node);

static void check_path(const struct dt_node *node, const char * expected_path)
{
	char * path;
	path = dt_get_path(node);
	if (strcmp(path, expected_path) != 0) {
		printf("check_path: expected %s, got %s\n", expected_path, path);
	}
	assert(strcmp(path, expected_path) == 0);
	free(path);
}

/* constructs a random nodes only device tree */
static void build_tree(int max_depth, int min_depth, struct dt_node *parent)
{
	char name[64];
	int i;

	for (i = 0; i < max_depth; i++) {
		struct dt_node *new;

		snprintf(name, sizeof name, "prefix@%.8x", rand());

		new = dt_new(parent, name);

		if(max_depth > min_depth)
			build_tree(max_depth - 1, min_depth, new);
	}
}

static bool is_sorted(const struct dt_node *root)
{
	struct dt_node *end = list_tail(&root->children, struct dt_node, list);
	struct dt_node *node;

	dt_for_each_child(root, node) {
		struct dt_node *next =
			list_entry(node->list.next, struct dt_node, list);

		/* current node must be "less than" the next node */
		if (node != end && dt_cmp_subnodes(node, next) != -1) {
			printf("nodes '%s' and '%s' out of order\n",
				node->name, next->name);

			return false;
		}

		if (!is_sorted(node))
			return false;
	}

	return true;
}

/*handler for phandle fixup test */
const char **props_to_fix(struct dt_node *node)
{
	const struct dt_property *prop;

	prop = dt_find_property(node, "something");
	if (prop)
		return prop_to_fix;

	return NULL;
}

int main(void)
{
	struct dt_node *root, *other_root, *c1, *c2, *c2_c, *gc1, *gc2, *gc3, *ggc1, *ggc2;
	struct dt_node *addrs, *addr1, *addr2;
	struct dt_node *i, *subtree, *ev1, *ut1, *ut2;
	const struct dt_property *p;
	struct dt_property *p2;
	unsigned int n;
	char *s;
	size_t sz;
	u32 phandle, ev1_ph, new_prop_ph;

	root = dt_new_root("");
	assert(!list_top(&root->properties, struct dt_property, list));
	check_path(root, "/");

	c1 = dt_new_check(root, "c1");
	assert(!list_top(&c1->properties, struct dt_property, list));
	check_path(c1, "/c1");
	assert(dt_find_by_name(root, "c1") == c1);
	assert(dt_find_by_path(root, "/c1") == c1);
	assert(dt_new(root, "c1") == NULL);

	c2 = dt_new(root, "c2");
	c2_c = dt_new_check(root, "c2");
	assert(c2 == c2_c);
	assert(!list_top(&c2->properties, struct dt_property, list));
	check_path(c2, "/c2");
	assert(dt_find_by_name(root, "c2") == c2);
	assert(dt_find_by_path(root, "/c2") == c2);

	gc1 = dt_new(c1, "gc1");
	assert(!list_top(&gc1->properties, struct dt_property, list));
	check_path(gc1, "/c1/gc1");
	assert(dt_find_by_name(root, "gc1") == gc1);
	assert(dt_find_by_path(root, "/c1/gc1") == gc1);

	gc2 = dt_new(c1, "gc2");
	assert(!list_top(&gc2->properties, struct dt_property, list));
	check_path(gc2, "/c1/gc2");
	assert(dt_find_by_name(root, "gc2") == gc2);
	assert(dt_find_by_path(root, "/c1/gc2") == gc2);

	gc3 = dt_new(c1, "gc3");
	assert(!list_top(&gc3->properties, struct dt_property, list));
	check_path(gc3, "/c1/gc3");
	assert(dt_find_by_name(root, "gc3") == gc3);
	assert(dt_find_by_path(root, "/c1/gc3") == gc3);

	ggc1 = dt_new(gc1, "ggc1");
	assert(!list_top(&ggc1->properties, struct dt_property, list));
	check_path(ggc1, "/c1/gc1/ggc1");
	assert(dt_find_by_name(root, "ggc1") == ggc1);
	assert(dt_find_by_path(root, "/c1/gc1/ggc1") == ggc1);

	addrs = dt_new(root, "addrs");
	assert(!list_top(&addrs->properties, struct dt_property, list));
	check_path(addrs, "/addrs");
	assert(dt_find_by_name(root, "addrs") == addrs);
	assert(dt_find_by_path(root, "/addrs") == addrs);

	addr1 = dt_new_addr(addrs, "addr", 0x1337);
	assert(!list_top(&addr1->properties, struct dt_property, list));
	check_path(addr1, "/addrs/addr@1337");
	assert(dt_find_by_name(root, "addr@1337") == addr1);
	assert(dt_find_by_name_addr(root, "addr", 0x1337) == addr1);
	assert(dt_find_by_path(root, "/addrs/addr@1337") == addr1);
	assert(dt_new_addr(addrs, "addr", 0x1337) == NULL);

	addr2 = dt_new_2addr(addrs, "2addr", 0xdead, 0xbeef);
	assert(!list_top(&addr2->properties, struct dt_property, list));
	check_path(addr2, "/addrs/2addr@dead,beef");
	assert(dt_find_by_name(root, "2addr@dead,beef") == addr2);
	assert(dt_find_by_path(root, "/addrs/2addr@dead,beef") == addr2);
	assert(dt_new_2addr(addrs, "2addr", 0xdead, 0xbeef) == NULL);

	/* Test walking the tree, checking and setting values */
	for (n = 0, i = dt_first(root); i; i = dt_next(root, i), n++) {
		assert(!list_top(&i->properties, struct dt_property, list));
		dt_add_property_cells(i, "visited", 1);
	}
	assert(n == 9);

	for (n = 0, i = dt_first(root); i; i = dt_next(root, i), n++) {
		p = list_top(&i->properties, struct dt_property, list);
		assert(strcmp(p->name, "visited") == 0);
		assert(p->len == sizeof(u32));
		assert(fdt32_to_cpu(*(u32 *)p->prop) == 1);
	}
	assert(n == 9);

	/* Test cells */
	dt_add_property_cells(c1, "some-property", 1, 2, 3);
	p = dt_find_property(c1, "some-property");
	assert(p);
	assert(strcmp(p->name, "some-property") == 0);
	assert(p->len == sizeof(u32) * 3);
	assert(fdt32_to_cpu(*(u32 *)p->prop) == 1);
	assert(dt_prop_get_cell(c1, "some-property", 0) == 1);
	assert(fdt32_to_cpu(*((u32 *)p->prop + 1)) == 2);
	assert(dt_prop_get_cell(c1, "some-property", 1) == 2);
	assert(fdt32_to_cpu(*((u32 *)p->prop + 2)) == 3);
	assert(dt_prop_get_cell_def(c1, "some-property", 2, 42) == 3);

	assert(dt_prop_get_cell_def(c1, "not-a-property", 2, 42) == 42);

	/* Test u64s */
	dt_add_property_u64s(c2, "some-property", (2LL << 33), (3LL << 33), (4LL << 33));
	p = dt_find_property(c2, "some-property");
	assert(p);
	assert(p->len == sizeof(u64) * 3);
	assert(fdt64_to_cpu(*(u64 *)p->prop) == (2LL << 33));
	assert(fdt64_to_cpu(*((u64 *)p->prop + 1)) == (3LL << 33));
	assert(fdt64_to_cpu(*((u64 *)p->prop + 2)) == (4LL << 33));

	/* Test u32/u64 get defaults */
	assert(dt_prop_get_u32_def(c1, "u32", 42) == 42);
	dt_add_property_cells(c1, "u32", 1337);
	assert(dt_prop_get_u32_def(c1, "u32", 42) == 1337);
	assert(dt_prop_get_u32(c1, "u32") == 1337);

	assert(dt_prop_get_u64_def(c1, "u64", (42LL << 42)) == (42LL << 42));
	dt_add_property_u64s(c1, "u64", (1337LL << 42));
	assert(dt_prop_get_u64_def(c1, "u64", (42LL << 42)) == (1337LL << 42));
	assert(dt_prop_get_u64(c1, "u64") == (1337LL << 42));

	/* Test freeing a single node */
	assert(!list_empty(&gc1->children));
	dt_free(ggc1);
	assert(list_empty(&gc1->children));

	/* Test rodata logic. */
	assert(!is_rodata("hello"));
	assert(is_rodata(__rodata_start));
	strcpy(__rodata_start, "name");
	ggc1 = dt_new(root, __rodata_start);
	assert(ggc1->name == __rodata_start);

	/* Test string node. */
	dt_add_property_string(ggc1, "somestring", "someval");
	assert(dt_has_node_property(ggc1, "somestring", "someval"));
	assert(!dt_has_node_property(ggc1, "somestrin", "someval"));
	assert(!dt_has_node_property(ggc1, "somestring", "someva"));
	assert(!dt_has_node_property(ggc1, "somestring", "somevale"));

	/* Test nstr, which allows for non-null-terminated inputs */
	dt_add_property_nstr(ggc1, "nstring", "somevalue_long", 7);
	assert(dt_has_node_property(ggc1, "nstring", "someval"));
	assert(!dt_has_node_property(ggc1, "nstring", "someva"));
	assert(!dt_has_node_property(ggc1, "nstring", "somevalue_long"));

	/* Test multiple strings */
	dt_add_property_strings(ggc1, "somestrings",
				"These", "are", "strings!");
	p = dt_find_property(ggc1, "somestrings");
	assert(p);
	assert(p->len == sizeof(char) * (6 + 4 + 9));
	s = (char *)p->prop;
	assert(strcmp(s, "These") == 0);
	assert(strlen(s) == 5);
	s += 6;
	assert(strcmp(s, "are") == 0);
	assert(strlen(s) == 3);
	s += 4;
	assert(strcmp(s, "strings!") == 0);
	assert(strlen(s) == 8);
	s += 9;
	assert(s == (char *)p->prop + p->len);
	assert(dt_prop_find_string(p, "These"));
	/* dt_prop_find_string is case insensitve */
	assert(dt_prop_find_string(p, "ARE"));
	assert(!dt_prop_find_string(p, "integers!"));
	/* And always returns false for NULL properties */
	assert(!dt_prop_find_string(NULL, "anything!"));

	/* Test more get/get_def varieties */
	assert(dt_prop_get_def(c1, "does-not-exist", NULL) == NULL);
	sz = 0xbad;
	assert(dt_prop_get_def_size(c1, "does-not-exist", NULL, &sz) == NULL);
	assert(sz == 0);
	dt_add_property_string(c1, "another-property", "xyzzy");
	assert(dt_prop_get_def(c1, "another-property", NULL) != NULL);
	assert(strcmp(dt_prop_get(c1, "another-property"), "xyzzy") == 0);
	n = 0xbad;
	assert(dt_prop_get_def_size(c1, "another-property", NULL, &sz) != NULL);
	assert(sz == strlen("xyzzy") + 1);

	/* Test resizing property. */
	p = p2 = __dt_find_property(c1, "some-property");
	assert(p);
	n = p2->len;
	while (p2 == p) {
		n *= 2;
		dt_resize_property(&p2, n);
	}

	assert(dt_find_property(c1, "some-property") == p2);
	list_check(&c1->properties, "properties after resizing");

	dt_del_property(c1, p2);
	list_check(&c1->properties, "properties after delete");

	/* No leaks for valgrind! */
	dt_free(root);

	/* Test compatible and chip id. */
	root = dt_new_root("");

	c1 = dt_new(root, "chip1");
	dt_add_property_cells(c1, "ibm,chip-id", 0xcafe);
	assert(dt_get_chip_id(c1) == 0xcafe);
	dt_add_property_strings(c1, "compatible",
				"specific-fake-chip",
				"generic-fake-chip");
	assert(dt_node_is_compatible(c1, "specific-fake-chip"));
	assert(dt_node_is_compatible(c1, "generic-fake-chip"));

	c2 = dt_new(root, "chip2");
	dt_add_property_cells(c2, "ibm,chip-id", 0xbeef);
	assert(dt_get_chip_id(c2) == 0xbeef);
	dt_add_property_strings(c2, "compatible",
				"specific-fake-bus",
				"generic-fake-bus");

	gc1 = dt_new(c1, "coprocessor1");
	dt_add_property_strings(gc1, "compatible",
				"specific-fake-coprocessor");
	gc2 = dt_new(gc1, "coprocessor2");
	dt_add_property_strings(gc2, "compatible",
				"specific-fake-coprocessor");
	gc3 = dt_new(c1, "coprocessor3");
	dt_add_property_strings(gc3, "compatible",
				"specific-fake-coprocessor");


	assert(dt_find_compatible_node(root, NULL, "generic-fake-bus") == c2);
	assert(dt_find_compatible_node(root, c2, "generic-fake-bus") == NULL);

	/* we can find all compatible nodes */
	assert(dt_find_compatible_node(c1, NULL, "specific-fake-coprocessor") == gc1);
	assert(dt_find_compatible_node(c1, gc1, "specific-fake-coprocessor") == gc2);
	assert(dt_find_compatible_node(c1, gc2, "specific-fake-coprocessor") == gc3);
	assert(dt_find_compatible_node(c1, gc3, "specific-fake-coprocessor") == NULL);
	assert(dt_find_compatible_node(root, NULL, "specific-fake-coprocessor") == gc1);
	assert(dt_find_compatible_node(root, gc1, "specific-fake-coprocessor") == gc2);
	assert(dt_find_compatible_node(root, gc2, "specific-fake-coprocessor") == gc3);
	assert(dt_find_compatible_node(root, gc3, "specific-fake-coprocessor") == NULL);

	/* we can find the coprocessor once on the cpu */
	assert(dt_find_compatible_node_on_chip(root,
					       NULL,
					       "specific-fake-coprocessor",
					       0xcafe) == gc1);
	assert(dt_find_compatible_node_on_chip(root,
					       gc1,
					       "specific-fake-coprocessor",
					       0xcafe) == gc2);
	assert(dt_find_compatible_node_on_chip(root,
					       gc2,
					       "specific-fake-coprocessor",
					       0xcafe) == gc3);
	assert(dt_find_compatible_node_on_chip(root,
					       gc3,
					       "specific-fake-coprocessor",
					       0xcafe) == NULL);

	/* we can't find the coprocessor on the bus */
	assert(dt_find_compatible_node_on_chip(root,
					       NULL,
					       "specific-fake-coprocessor",
					       0xbeef) == NULL);

	/* Test phandles. We override the automatically generated one. */
	phandle = 0xf00;
	dt_add_property(gc3, "phandle", (const void *)&phandle, 4);
	assert(last_phandle == 0xf00);
	assert(dt_find_by_phandle(root, 0xf00) == gc3);
	assert(dt_find_by_phandle(root, 0xf0f) == NULL);

	dt_free(root);

	/* basic sorting */
	root = dt_new_root("rewt");
	dt_new(root, "a@1");
	dt_new(root, "a@2");
	dt_new(root, "a@3");
	dt_new(root, "a@4");
	dt_new(root, "b@4");
	dt_new(root, "c@4");

	assert(is_sorted(root));

	/* Now test dt_attach_root */
	other_root = dt_new_root("other_root");
	dt_new(other_root, "d@1");

	assert(dt_attach_root(root, other_root));
	other_root = dt_new_root("other_root");
	assert(!dt_attach_root(root, other_root));
	dt_free(root);

	/* Test child node sorting */
	root = dt_new_root("test root");
	build_tree(5, 3, root);

	if (!is_sorted(root)) {
		dump_dt(root, 1, false);
	}
	assert(is_sorted(root));

	dt_free(root);

	/* check dt_translate_address */

	/* NB: the root bus has two address cells */
	root = dt_new_root("");

	c1 = dt_new_addr(root, "some-32bit-bus", 0x80000000);
	dt_add_property_cells(c1, "#address-cells", 1);
	dt_add_property_cells(c1, "#size-cells", 1);
	dt_add_property_cells(c1, "ranges", 0x0, 0x8, 0x0, 0x1000);

	gc1 = dt_new_addr(c1, "test", 0x0500);
	dt_add_property_cells(gc1, "reg", 0x0500, 0x10);

	assert(dt_translate_address(gc1, 0, NULL) == 0x800000500ul);

	/* try three level translation */

	gc2 = dt_new_addr(c1, "another-32bit-bus", 0x40000000);
	dt_add_property_cells(gc2, "#address-cells", 1);
	dt_add_property_cells(gc2, "#size-cells", 1);
	dt_add_property_cells(gc2, "ranges",	0x0, 0x600, 0x100,
						0x100, 0x800, 0x100);

	ggc1 = dt_new_addr(gc2, "test", 0x50);
	dt_add_property_cells(ggc1, "reg", 0x50, 0x10);
	assert(dt_translate_address(ggc1, 0, NULL) == 0x800000650ul);

	/* test multiple ranges work */
	ggc2 = dt_new_addr(gc2, "test", 0x150);
	dt_add_property_cells(ggc2, "reg", 0x150, 0x10);
	assert(dt_translate_address(ggc2, 0, NULL) == 0x800000850ul);

	/* try 64bit -> 64bit */

	c2 = dt_new_addr(root, "some-64bit-bus", 0xe00000000);
	dt_add_property_cells(c2, "#address-cells", 2);
	dt_add_property_cells(c2, "#size-cells", 2);
	dt_add_property_cells(c2, "ranges", 0x0, 0x0, 0xe, 0x0, 0x2, 0x0);

	gc2 = dt_new_addr(c2, "test", 0x100000000ul);
	dt_add_property_u64s(gc2, "reg", 0x100000000ul, 0x10ul);
	assert(dt_translate_address(gc2, 0, NULL) == 0xf00000000ul);

	dt_free(root);

	/* phandle fixup test */
	subtree = dt_new_root("subtree");
	ev1 = dt_new(subtree, "ev@1");
	ev1_ph = ev1->phandle;
	dt_new(ev1,"a@1");
	dt_new(ev1,"a@2");
	dt_new(ev1,"a@3");
	ut1 = dt_new(subtree, "ut@1");
	dt_add_property(ut1, "something", (const void *)&ev1->phandle, 4);
	ut2 = dt_new(subtree, "ut@2");
	dt_add_property(ut2, "something", (const void *)&ev1->phandle, 4);

	dt_adjust_subtree_phandle(subtree, props_to_fix);
	assert(!(ev1->phandle == ev1_ph));
	new_prop_ph = dt_prop_get_u32(ut1, "something");
	assert(!(new_prop_ph == ev1_ph));
	new_prop_ph = dt_prop_get_u32(ut2, "something");
	assert(!(new_prop_ph == ev1_ph));
	dt_free(subtree);
	return 0;
}

