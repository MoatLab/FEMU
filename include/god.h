#ifndef __GOD_H
#define __GOD_H

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>

extern char tsc_offset_fn[64];
extern int64_t tsc_offset;

int64_t ns2cyc(int64_t ns);
int64_t cyc2ns(int64_t cycles);
int64_t get_ts_in_ns(void);
uint64_t rdtscp(void);
void set_tsc_offset_fn(pid_t qemu_pid, int vmfd);
int read_tsc_offset(void);

#endif
