#include "common.h"
#define DEBUG 0

int main(int argc, char *argv[])
{
	int fd;
	if (argc != 2) {
		printf("Usage: ./nsc_count <dev_namme>");
		exit(0);
	}

	char buf[BLOCK_SIZE];
	long unsigned c;
	long long unsigned start, end;
	int r = 0;
	int i;
	int num_blocks = NUM_BLOCKS;
	
	fd = open(argv[1], O_RDONLY);
	start = rdtsc();

//	while (read (fd, buf, BLOCK_SIZE) > 0) {
	for (i = 0 ; i < num_blocks ; i++) {
		if (read (fd, buf, BLOCK_SIZE) != BLOCK_SIZE) {
			printf("Error during read %s\n", strerror(errno));
			exit (1);
		}
	}
	end = rdtsc();

        printf("cycles spent: %llu\n",end - start);
}
