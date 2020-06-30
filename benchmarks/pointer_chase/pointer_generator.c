#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	int num_lists;
	int max_list_length;
	int min_list_length;
	int max_pointer_value;
	int i, j;
	time_t t;
	int list_length;
	int current_block, next_block;
	int outfile;

	if (argc < 5) {
		printf("Usage: ./pointer_generator <num_lists> <max_pointer_value> <min_list_length> <max_list_length>\n\n");
		printf("num_lists - total number of linked lists\n");
		printf("max_pointer_value - max pointer value\n");
		printf("min_list_length - min LL size (>= 1)\n");
		printf("max_list_length - max LL size\n");
		exit(0);
	}

	outfile = open("dp.dat", O_WRONLY | O_CREAT , 0644);
	if (outfile < 0 ) {
		printf("Error creating file %s\n", strerror(errno));
		exit(0);
	}

	srand((unsigned) time(&t));

	num_lists = atoi(argv[1]);
	max_pointer_value = atoi(argv[2]);
	min_list_length = atoi(argv[3]);
	max_list_length = atoi(argv[4]);

	if(min_list_length < 1) {
		printf("min_list_length %d, required > 0\n", min_list_length);
		exit(0);
	}


	for (i = 0 ; i < num_lists ; i++) {
		list_length = min_list_length + (rand() % (max_list_length - min_list_length + 1));
		current_block = rand() % (max_pointer_value + 1);
		next_block = 0;
		for (j = list_length ; j > 0 ; j--) {
			if (j > 1) {
				next_block = rand() % (max_pointer_value + 1);
			}
		//	printf("%d %d %d\n", current_block, next_block, j);
			dprintf(outfile, "%d %d %d\n", current_block, next_block, j);
			current_block = next_block;
			next_block = 0;
		}
	}
	close(outfile);
}
