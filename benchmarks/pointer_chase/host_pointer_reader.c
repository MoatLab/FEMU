// write_pointer_to_disk.c

#include "common.h"

#define DEBUG 0

int main(int argc, char *argv[])
{
	FILE* head_pointer_list_fd;
	int disk_fd_read;
	off_t disk_off;

	uint64_t current_block, next_block;
	uint64_t head_pointer;

	int ret;
	char *data = aligned_alloc(4096, 4096);

	if (argc < 2) {
		printf("Usage ./host_pointer_reader <disk_name>\n");
		exit(0);
	}

	head_pointer_list_fd = fopen("hp.dat", "r");
	if (head_pointer_list_fd == NULL) {
		printf("hp.dat open error: %s\n", strerror(errno));
		exit(1);
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
		while(current_block != END_BLOCK_MAGIC && current_block !=0) {
			disk_off = current_block * BLOCK_SIZE;
			disk_off = lseek(disk_fd_read, disk_off, SEEK_SET);
			if (disk_off != current_block * BLOCK_SIZE || disk_off < 0) {
				printf("Error: could not seek %s\n", strerror(errno));
				exit (1);
			}
			//debug_print("disk offset = %ld\n", disk_off);
			ret = read(disk_fd_read, data, 4096);
			if( ret == -1) {
				printf("error reading from device %s\n",strerror(errno));
				exit(1);
			}
			memcpy(&next_block, data, sizeof(next_block));
			current_block = next_block;
			debug_print("Next PTR = %lu\n", current_block);
		}
	}

	end_time = rdtsc1();
	free(data);
	start = ( ((uint64_t)cycles_high << 32) | cycles_low );
        end = ( ((uint64_t)cycles_high1 << 32) | cycles_low1 );
        printf("cycles spent: %lu\n",end - start);

	close(disk_fd_read);
	fclose(head_pointer_list_fd);
}
