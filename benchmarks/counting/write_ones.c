#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <error.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#define BLOCK_SIZE 4096

int main(int argc, char *argv[])
{
	int fd = open(argv[1], O_WRONLY | O_CREAT);
	char buf[BLOCK_SIZE];
	int i;
	long unsigned c;
	int ret;

	int file_size = 10;

	if (fd < 0) {
		printf("Error opening %s\n", strerror(errno));
		exit(1);
	}
	
	for (i = 0 ; i < BLOCK_SIZE ; i++) {
		buf[i] = 1;
	}

	for (i = 0; i < file_size ; i++) {
		ret = write(fd, buf, BLOCK_SIZE);
		if (ret < 0) {
			printf("Error writing file \n");
			exit(1);
		}	
	}

	return 0;
}
