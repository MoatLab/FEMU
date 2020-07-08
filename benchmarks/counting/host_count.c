#include "common.h"

#define DEBUG 0

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
			debug_print("j=%d res=%d\n", j , c & (1 << j));
		}
	}
	return count;
}

int main(int argc, char *argv[])
{
	int fd;

	char buf[BLOCK_SIZE];
	long unsigned c;
	int i;

	if (argc != 2) {
		printf("Usage: ./host_count <dev_namme>");
		exit(0);
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		printf("Error opening %s\n", strerror(errno));
		exit(1);
	}

	int r = 0;
	int num_blocks=NUM_BLOCKS;
	unsigned long long start, end;

	start = rdtsc();
//	while (read (fd, buf, BLOCK_SIZE) > 0) {
	for (i = 0 ; i < num_blocks ; i++) {
		if (read(fd, buf, BLOCK_SIZE) == BLOCK_SIZE) {
			c += count_bits(buf);
		}else {
			printf("error during read %s\n", strerror(errno));
			exit (1);
		}
	}
	end = rdtsc();

        printf("cycles spent: %llu\n",end - start);

	printf("Count %lu\n", c);
}
