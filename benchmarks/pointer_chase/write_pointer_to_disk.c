// write_pointer_to_disk.c

#include "common.h"

int main(int argc, char *argv[])
{
	FILE* disk_pointer_list_fd;
	int disk_fd;
	char * line = NULL;
	size_t len = 0;
	ssize_t read;
	off_t disk_off;

	int first_block, second_block, list_length;
	int ret;

	if (argc < 2) {
		printf("Usage ./write_pointer_to_disk <disk_name>\n");
		exit(0);
	}

	disk_pointer_list_fd = fopen("dp.dat", "r");
	if (disk_pointer_list_fd == NULL) {
		printf("dp.dat open error: %s\n", strerror(errno));
		exit(1);
	}

	disk_fd = open(argv[1], O_WRONLY);
	if (disk_fd < 0) {
		printf("disk open error: %s\n", strerror(errno));
		exit(1);
	}

	while (fscanf(disk_pointer_list_fd, "%d %d %d", &first_block, &second_block, &list_length) != EOF) {
	//	printf("%d %d %d\n", first_block, second_block, list_length);
		disk_off = lseek(disk_fd, first_block * BLOCK_SIZE, SEEK_SET);
		if (disk_off != first_block * BLOCK_SIZE) {
			printf("Could Not seek to %d offset %s\n", first_block * BLOCK_SIZE , strerror(errno));
			exit(1);
		}
		ret = write(disk_fd, &second_block, sizeof(second_block));
		if (ret  == -1) {
			printf("Could not write to %d offset %s\n", first_block * BLOCK_SIZE , strerror(errno));
			exit(1);
		}
	}
	close(disk_fd);
	fclose(disk_pointer_list_fd);
}
