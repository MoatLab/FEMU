// write_pointer_to_disk.c

#include "common.h"

#define DEBUG 0

int main(int argc, char *argv[])
{
	FILE* head_pointer_list_fptr;
	FILE* head_pointer_list_fd;
	int disk_fd_read;
	off_t disk_off;
	struct stat statbuf;

	uint64_t current_block, next_block;
	uint64_t head_pointer;

	int ret;
	char *data = aligned_alloc(4096, 4096);
	char *region;

	if (argc < 2) {
		printf("Usage ./nsc_pointer_reader <disk_name>\n");
		exit(0);
	}

	head_pointer_list_fptr = fopen("hp.dat", "r");
	if (head_pointer_list_fd == NULL) {
		printf("hp.dat open error: %s\n", strerror(errno));
		exit(1);
	}

	head_pointer_list_fd = fileno(head_pointer_list_fptr);
	if (fstat (head_pointer_list_fd, &statbuf) < 0)
	{
		printf ("fstat error\n");
		exit(1);
	}

	if ((region = mmap (0, statbuf.st_size, PROT_READ, MAP_SHARED,head_pointer_list_fd, 0)) == MAP_FAILED)
	{
		printf ("mmap error for input");
		return 0;
	}

	disk_fd_read = open(argv[1], O_RDONLY | O_DIRECT);
	if (disk_fd_read < 0) {
		printf("disk open error: %s\n", strerror(errno));
		exit(1);
	}

	start_time = rdtsc();
	while (fscanf(head_pointer_list_fd, "%lu", &head_pointer) != EOF) {
		debug_print("Parsing LL with head %lu\n", head_pointer);
		current_block = head_pointer;
		disk_off = lseek(disk_fd_read, current_block * BLOCK_SIZE, SEEK_SET);
		if (disk_off != current_block * BLOCK_SIZE) {
			printf("Error: could not seek %s\n", strerror(errno));
			exit (1);
		}
		ret = read(disk_fd_read, data, 4096);
		if( ret == -1) {
			printf("error reading from device %s\n",strerror(errno));
			exit(1);
		}
		memcpy(&next_block, data, sizeof(next_block));
		assert (next_block == END_BLOCK_MAGIC);
	}

	end_time = rdtsc1();

	free(data);
	munmap(region, statbuf.st_size);

	start = ( ((uint64_t)cycles_high << 32) | cycles_low );
        end = ( ((uint64_t)cycles_high1 << 32) | cycles_low1 );
        printf("cycles spent: %lu\n",end - start);

	close(disk_fd_read);
	fclose(head_pointer_list_fd);
}
