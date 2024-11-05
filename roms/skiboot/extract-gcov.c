// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2015-2018 IBM Corp. */

#define _DEFAULT_SOURCE
#include <ccan/short_types/short_types.h>
#include <endian.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

typedef u32 gcov_unsigned_int;

/* You will need to pass -DTARGET__GNUC__=blah when building */
#if (__GNUC__ >= 7)
#define GCOV_COUNTERS                   9
#else
#if TARGET__GNUC__ >= 6 || (TARGET__GNUC__ >= 5 && TARGET__GNUC_MINOR__ >= 1)
#define GCOV_COUNTERS                   10
#else
#if TARGET__GNUC__ >= 4 && TARGET__GNUC_MINOR__ >= 9
#define GCOV_COUNTERS                   9
#else
#define GCOV_COUNTERS                   8
#endif /* GCC 4.9 */
#endif /* GCC 5.1 */
#endif /* GCC 7 */
typedef u64 gcov_type;

struct gcov_info
{
        gcov_unsigned_int version;
	u32 _padding;
        struct gcov_info *next;
        gcov_unsigned_int stamp;
	u32 _padding2;
        const char *filename;
        u64 merge[GCOV_COUNTERS];
        unsigned int n_functions;
	u32 _padding3;
        struct gcov_fn_info **functions;
};

struct gcov_ctr_info {
        gcov_unsigned_int num;
	u32 _padding;
        gcov_type *values;
}__attribute__((packed));

struct gcov_fn_info {
        const struct gcov_info *key;
        unsigned int ident;
        unsigned int lineno_checksum;
        unsigned int cfg_checksum;
	u32 _padding;
//        struct gcov_ctr_info ctrs[0];
} __attribute__((packed));


/* We have a list of all gcov info set up at startup */
struct gcov_info *gcov_info_list;

#define SKIBOOT_OFFSET 0x30000000

/* Endian of the machine producing the gcda. Which mean BE.
 * because skiboot is BE.
 * If skiboot is ever LE, go have fun.
 */
static size_t write_u32(int fd, u32 _v)
{
	u32 v = htobe32(_v);
	return write(fd, &v, sizeof(v));
}

static size_t write_u64(int fd, u64 v)
{
	u32 b[2];
	b[0] = htobe32(v & 0xffffffffUL);
	b[1] = htobe32(v >> 32);

	write(fd, &b[0], sizeof(u32));
	write(fd, &b[1], sizeof(u32));
	return sizeof(u64);
}

#define GCOV_DATA_MAGIC         ((unsigned int) 0x67636461)
#define GCOV_TAG_FUNCTION       ((unsigned int) 0x01000000)
#define GCOV_TAG_COUNTER_BASE   ((unsigned int) 0x01a10000)
#define GCOV_TAG_FOR_COUNTER(count)                                     \
        (GCOV_TAG_COUNTER_BASE + ((unsigned int) (count) << 17))

// gcc 4.7/4.8 specific
#define GCOV_TAG_FUNCTION_LENGTH        3

size_t skiboot_dump_size = 0x240000;

static inline const char* SKIBOOT_ADDR(const char* addr, const void* p)
{
	const char* r= (addr + (be64toh((const u64)p) - SKIBOOT_OFFSET));
	assert(r < (addr + skiboot_dump_size));
	return r;
}

static int counter_active(struct gcov_info *info, unsigned int type)
{
        return info->merge[type] ? 1 : 0;
}

static void write_gcda(char *addr, struct gcov_info* gi)
{
	const char* filename = SKIBOOT_ADDR(addr, gi->filename);
	int fd;
	u32 fn;
	struct gcov_fn_info *fn_info;
	struct gcov_fn_info **functions;
	struct gcov_ctr_info *ctr_info;
	u32 ctr;
	u32 cv;

	printf("Writing %s\n", filename);

	fd = open(filename, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
	if (fd < 0) {
		fprintf(stderr, "Error opening file %s: %d %s\n",
			filename, errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	write_u32(fd, GCOV_DATA_MAGIC);
	write_u32(fd, be32toh(gi->version));
	write_u32(fd, be32toh(gi->stamp));

	printf("version: %x\tstamp: %d\n", be32toh(gi->version), be32toh(gi->stamp));
	printf("nfunctions: %d \n", be32toh(gi->n_functions));

	for(fn = 0; fn < be32toh(gi->n_functions); fn++) {
		functions = (struct gcov_fn_info**)
			SKIBOOT_ADDR(addr, gi->functions);

		fn_info = (struct gcov_fn_info*)
			SKIBOOT_ADDR(addr, functions[fn]);

		printf("function: %p\n", (void*)be64toh((u64)functions[fn]));

		write_u32(fd, GCOV_TAG_FUNCTION);
		write_u32(fd, GCOV_TAG_FUNCTION_LENGTH);
		write_u32(fd, be32toh(fn_info->ident));
		write_u32(fd, be32toh(fn_info->lineno_checksum));
		write_u32(fd, be32toh(fn_info->cfg_checksum));

		ctr_info = (struct gcov_ctr_info*)
			((char*)fn_info + sizeof(struct gcov_fn_info));

		for(ctr = 0; ctr < GCOV_COUNTERS; ctr++) {
			if (!counter_active(gi, ctr))
				continue;

			write_u32(fd, (GCOV_TAG_FOR_COUNTER(ctr)));
			write_u32(fd, be32toh(ctr_info->num)*2);
			printf(" ctr %d gcov_ctr_info->num %u\n",
			    ctr, be32toh(ctr_info->num));

			for(cv = 0; cv < be32toh(ctr_info->num); cv++) {
				gcov_type *ctrv = (gcov_type *)
					SKIBOOT_ADDR(addr, ctr_info->values);
				//printf("%lx\n", be64toh(ctrv[cv]));
				write_u64(fd, be64toh(ctrv[cv]));
			}
			ctr_info++;
		}
	}

	close(fd);
}


int main(int argc, char *argv[])
{
	int r;
	int fd;
	struct stat sb;
	char *addr;
	u64 gcov_list_addr;

	printf("sizes: %zu %zu %zu %zu\n",
	       sizeof(gcov_unsigned_int),
	       sizeof(struct gcov_ctr_info),
	       sizeof(struct gcov_fn_info),
	       sizeof(struct gcov_info));
	printf("TARGET GNUC: %d.%d\n", TARGET__GNUC__, TARGET__GNUC_MINOR__);
	printf("GCOV_COUNTERS: %d\n", GCOV_COUNTERS);

	if (argc < 3) {
		fprintf(stderr, "Usage:\n"
			"\t%s skiboot.dump gcov_offset\n\n",
			argv[0]);
		return -1;
	}

	/* argv[1] = skiboot.dump */
	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Cannot open dump: %s (error %d %s)\n",
			argv[1], errno, strerror(errno));
		exit(-1);
	}

	r = fstat(fd, &sb);
	if (r < 0) {
		fprintf(stderr, "Cannot stat dump, %d %s\n",
			errno, strerror(errno));
		exit(-1);
	}

	addr = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	assert(addr != NULL);
	skiboot_dump_size = sb.st_size;

	printf("Skiboot memory dump %p - %p\n",
	       (void*)SKIBOOT_OFFSET, (void*)SKIBOOT_OFFSET+sb.st_size);

	gcov_list_addr = strtoll(argv[2], NULL, 0);
	gcov_list_addr = (u64)(addr + (gcov_list_addr - SKIBOOT_OFFSET));
	gcov_list_addr = be64toh(*(u64*)gcov_list_addr);

	printf("Skiboot gcov_info_list at %p\n", (void*)gcov_list_addr);

	do {
		gcov_info_list = (struct gcov_info *)(addr + (gcov_list_addr - SKIBOOT_OFFSET));
		write_gcda(addr, gcov_info_list);
		gcov_list_addr = be64toh((u64)gcov_info_list->next);

	} while(gcov_list_addr);

	munmap(addr, sb.st_size);
	close(fd);

	return 0;
}
