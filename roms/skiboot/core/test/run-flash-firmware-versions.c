// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2018-2019 IBM Corp.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <malloc.h>
#include <stdint.h>


#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>


#include <interrupts.h>
#include <bitutils.h>

#include <compiler.h>

/*
 * Skiboot malloc stubs
 *
 * The actual prototypes for these are defined in mem_region-malloc.h,
 * but that file also #defines malloc, and friends so we don't pull that in
 * directly.
 */

#define DEFAULT_ALIGN __alignof__(long)

void *__memalign(size_t blocksize, size_t bytes, const char *location __unused);
void *__memalign(size_t blocksize, size_t bytes, const char *location __unused)
{
	return memalign(blocksize, bytes);
}

void *__malloc(size_t bytes, const char *location);
void *__malloc(size_t bytes, const char *location)
{
	return __memalign(DEFAULT_ALIGN, bytes, location);
}

void __free(void *p, const char *location __unused);
void __free(void *p, const char *location __unused)
{
	free(p);
}

void *__realloc(void *ptr, size_t size, const char *location __unused);
void *__realloc(void *ptr, size_t size, const char *location __unused)
{
	return realloc(ptr, size);
}

void *__zalloc(size_t bytes, const char *location);
void *__zalloc(size_t bytes, const char *location)
{
	void *p = __malloc(bytes, location);

	if (p)
		memset(p, 0, bytes);
	return p;
}

#include <mem_region-malloc.h>

#include <opal-api.h>

#include "../../libfdt/fdt.c"
#include "../../libfdt/fdt_ro.c"
#include "../../libfdt/fdt_sw.c"
#include "../../libfdt/fdt_strerror.c"

#include "../../core/device.c"

#include "../../libstb/container-utils.h"
#include "../../libstb/container.h"
#include "../../libstb/container.c"

#include "../flash-firmware-versions.c"
#include <assert.h>

char __rodata_start[1], __rodata_end[1];

const char version[]="Hello world!";

enum proc_gen proc_gen = proc_gen_p8;

static char *loaded_version_buf;
static size_t loaded_version_buf_size;

#define min(x,y) ((x) < (y) ? x : y)

int start_preload_resource(enum resource_id id, uint32_t subid,
			   void *buf, size_t *len)
{
	(void)id;
	(void)subid;
	(void)buf;
	if (loaded_version_buf) {
		*len = min(*len, loaded_version_buf_size);
		memcpy(buf, loaded_version_buf, *len);
	} else {
		*len = 0;
	}

	return 0;
}

int wait_for_resource_loaded(enum resource_id id, uint32_t idx)
{
	(void)id;
	(void)idx;
	return 0;
}

int main(int argc, char *argv[])
{
	int fd;
	struct stat ver_st;
	int r;

	dt_root = dt_new_root("");

	if (argc > 1) {
		fd = open(argv[1], O_RDONLY);

		assert(fd > 0);
		r = fstat(fd, &ver_st);
		assert(r == 0);

		loaded_version_buf = mmap(NULL, ver_st.st_size,
					  PROT_READ, MAP_PRIVATE, fd, 0);
		assert(loaded_version_buf != (char*)-1);
		loaded_version_buf_size = ver_st.st_size;
	}

	flash_fw_version_preload();

	proc_gen = proc_gen_p9;
	flash_fw_version_preload();
	flash_dt_add_fw_version();

	return 0;
}

