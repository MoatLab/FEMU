#ifndef _GNU_SOURCE 
	#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <assert.h>
#include <stdint.h>

#define BLOCK_SIZE 4096
#define END_BLOCK_MAGIC 99999

unsigned cycles_low, cycles_high, cycles_low1, cycles_high1;
uint64_t start, end;
uint64_t start_time, end_time;

static __inline__ unsigned long long rdtsc(void)
{
    __asm__ __volatile__ ("RDTSC\n\t"
            "mov %%edx, %0\n\t"
            "mov %%eax, %1\n\t": "=r" (cycles_high), "=r" (cycles_low)::
            "%rax", "rbx", "rcx", "rdx");
}

#define debug_print(fmt, ...) \
        do { if (DEBUG) fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
                                __LINE__, __func__, __VA_ARGS__); } while (0)

