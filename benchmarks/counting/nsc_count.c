#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#define BLOCK_SIZE 4096

typedef unsigned long long ticks;

static __inline__ ticks getticks(void)
{
     unsigned a, d;
     asm("cpuid");
     asm volatile("rdtsc" : "=a" (a), "=d" (d));

     return (((ticks)a) | (((ticks)d) << 32));
}
/*
int count_bits(char *buf)
{
	int i, j;
	char c;
	int count =0;

	for (i = 0 ; i < BLOCK_SIZE ; i++) {
		c = buf[i];
		for (j = 0 ; j < 8 ; j++) {
			if (c & (1 << j)) {
				count +=  1;
			}
//			printf("j=%d res=%d\n", j , c & (1 << j));
		}
//	exit(1);
	}
	return count;
}
*/
int main(int argc, char *argv[])
{
	int fd = open(argv[1], O_RDONLY);
	char buf[4096];
	long unsigned c;

	if (fd < 0) {
		printf("Error opening %s\n", strerror(errno));
		exit(1);
	}

	int r = 0;
	ticks tick,tick1,tickh;
	unsigned long long time =0;
	
	tick = getticks();

//	while (read (fd, buf, BLOCK_SIZE) > 0) {
	for (i = 0 ; i < num_blocks ; i++) {
		read (fd, buf, BLOCK_SIZE);
	}

	tick1 = getticks();

	time = (unsigned long long)((tick1-tick)/2904595);
	printf("\ntime in MS  = %llu\n",time);

	printf("Count %lu\n", c);
}
