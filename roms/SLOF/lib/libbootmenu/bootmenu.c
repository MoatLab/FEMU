/*****************************************************************************
 * Boot menu: Displays boot devices and waits for user to select one
 *
 * Copyright 2017 Red Hat, Inc.
 *
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     Thomas Huth, Red Hat Inc. - initial implementation
 *****************************************************************************/

#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <paflof.h>
#include <helpers.h>
#include "bootmenu.h"

#define MAX_DEVS 36        /* Enough for 10 digits + 26 letters */
#define MAX_ALIAS_LEN 8    /* Maximum length of alias names */

struct bootdev {
	char alias[MAX_ALIAS_LEN];
	char *path;
};

static int nr_devs;
static struct bootdev bootdevs[MAX_DEVS];

/**
 * Look up an alias name.
 * @return The NUL-terminated device tree path (should be released with free()
 *         when it's not required anymore), or NULL if it can't be found.
 */
static char *find_alias(char *alias)
{
	char *path;
	long len;

	forth_push((unsigned long)alias);
	forth_push(strlen(alias));
	forth_eval("find-alias");

	len = forth_pop();
	if (!len)
		return NULL;

	path = malloc(len + 1);
	if (!path) {
		puts("Out of memory in find_alias");
		return NULL;
	}
	memcpy(path, (void *)forth_pop(), len);
	path[len] = '\0';

	return path;
}

static void bootmenu_populate_devs_alias(const char *alias)
{
	int idx;

	for (idx = 0; idx <= 9 && nr_devs < MAX_DEVS; idx++, nr_devs++) {
		char *cur_alias = bootdevs[nr_devs].alias;
		if (idx == 0)
			strcpy(cur_alias, alias);
		else
			sprintf(cur_alias, "%s%i", alias, idx);
		bootdevs[nr_devs].path = find_alias(cur_alias);
		if (!bootdevs[nr_devs].path)
			break;
	}
}

static void bootmenu_populate_devs(void)
{
	bootmenu_populate_devs_alias("cdrom");
	bootmenu_populate_devs_alias("disk");
	bootmenu_populate_devs_alias("net");
}

static void bootmenu_free_devs(void)
{
	while (nr_devs-- > 0) {
		free(bootdevs[nr_devs].path);
		bootdevs[nr_devs].path = NULL;
	}
}

static void bootmenu_show_devs(void)
{
	int i;

	for (i = 0; i < nr_devs; i++) {
		printf("%c) %6s : %s\n", i < 9 ? '1' + i : 'a' + i - 9,
		       bootdevs[i].alias, bootdevs[i].path);
	}
}

static bool has_key(void)
{
	forth_eval("key?");
	return forth_pop();
}

static char get_key(void)
{
	forth_eval("key");
	return forth_pop();
}

/* Flush pending key presses */
static void flush_keys(void)
{
	uint32_t start;

	start = SLOF_GetTimer();
	while (SLOF_GetTimer() - start < 10) {
		if (has_key()) {
			get_key();
			start = SLOF_GetTimer();
		}
	}
}

static int bootmenu_get_selection(void)
{
	char key = 0;
	int sel;

	do {
		sel = -1;
		if (!has_key())
			continue;
		key = get_key();
		switch (key) {
		case '0':
			return -1;
		case '1' ... '9':
			sel = key - '1';
			break;
		case 'a' ... 'z':
			sel = key - 'a' + 9;
			break;
		case 'A' ... 'Z':
			sel = key - 'A' + 9;
			break;
		default:
			/* Might be another escape code (F12) ... skip it */
			flush_keys();
			break;
		}
	} while (sel < 0 || sel >= nr_devs);

	return sel;
}

void bootmenu(void)
{
	int sel;

	bootmenu_populate_devs();
	if (!nr_devs) {
		puts("No available boot devices!");
		return;
	}

	puts("\nSelect boot device (or press '0' to abort):");
	bootmenu_show_devs();

	if (has_key())		/* In case the user hammered on F12 */
		flush_keys();

	sel = bootmenu_get_selection();
	if (sel < 0) {
		forth_push(0);
	} else {
		forth_push((unsigned long)bootdevs[sel].alias);
		forth_push(strlen(bootdevs[sel].alias));
	}

	bootmenu_free_devs();
}
