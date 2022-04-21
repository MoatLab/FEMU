// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * libgcov skeleton reimplementation to build skiboot with gcov support
 *
 * Copyright 2015-2018 IBM Corp.
 */

#include <skiboot.h>
#include <compiler.h>
#include <stdio.h>

typedef long gcov_type;

/*
 * This is GCC internal data structure. See GCC libgcc/libgcov.h for
 * details.
 *
 * If gcc changes this, we have to change it.
 */

typedef unsigned int gcov_unsigned_int;

#if __GNUC__ == 4 && __GNUC_MINOR__ >= 9
#define GCOV_COUNTERS                   9
#else
#define GCOV_COUNTERS                   8
#endif

struct gcov_info
{
        gcov_unsigned_int version;
        struct gcov_info *next;
        gcov_unsigned_int stamp;
        const char *filename;
        void (*merge[GCOV_COUNTERS])(gcov_type *, unsigned int);
        unsigned int n_functions;
        struct gcov_fn_info **functions;
};

/* We have a list of all gcov info set up at startup */
struct gcov_info *gcov_info_list;

void __gcov_init(struct gcov_info* f);
void skiboot_gcov_done(void);
void __gcov_flush(void);
void __gcov_merge_add(gcov_type *counters, unsigned int n_counters);
void __gcov_merge_single(gcov_type *counters, unsigned int n_counters);
void __gcov_merge_delta(gcov_type *counters, unsigned int n_counters);
void __gcov_merge_ior(gcov_type *counters, unsigned int n_counters);
void __gcov_merge_time_profile(gcov_type *counters, unsigned int n_counters);
void __gcov_exit(void);

void __gcov_init(struct gcov_info* f)
{
	static gcov_unsigned_int version = 0;

	if (version == 0) {
		printf("GCOV version: %u\n", f->version);
		version = f->version;
	}

	if (gcov_info_list)
		f->next = gcov_info_list;

	gcov_info_list = f;
	return;
}

void skiboot_gcov_done(void)
{
	struct gcov_info *i = gcov_info_list;

	if (i->filename)
		printf("GCOV: gcov_info_list looks sane (first file: %s)\n",
		       i->filename);
	else
		prlog(PR_WARNING, "GCOV: gcov_info_list doesn't look sane. "
		      "i->filename == NULL.");

	printf("GCOV: gcov_info_list at 0x%p\n", gcov_info_list);
}

void __gcov_merge_add(gcov_type *counters, unsigned int n_counters)
{
	(void)counters;
	(void)n_counters;

	return;
}

void __gcov_flush(void)
{
	return;
}

void __gcov_merge_single(gcov_type *counters, unsigned int n_counters)
{
	(void)counters;
	(void)n_counters;

	return;
}

void __gcov_merge_delta(gcov_type *counters, unsigned int n_counters)
{
	(void)counters;
	(void)n_counters;

	return;
}

void __gcov_merge_ior(gcov_type *counters, unsigned int n_counters)
{
	(void)counters;
	(void)n_counters;
	return;
}

void __gcov_merge_time_profile(gcov_type *counters, unsigned int n_counters)
{
	(void)counters;
	(void)n_counters;
}

void __gcov_exit(void)
{
}
