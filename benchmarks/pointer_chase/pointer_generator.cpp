#include "common.h"

#include <map>
#include <algorithm>

#define DEBUG 0

using namespace std;
std::map <uint64_t, bool> pre_accessed_blocks;

int get_unvisited_pointer(uint64_t max_value)
{
	uint64_t bno = rand() % (max_value);
	while (pre_accessed_blocks.find(bno) != pre_accessed_blocks.end()) {
		debug_print("collision %lu exists\n", bno);
		bno = rand() % (max_value);
	}
	pre_accessed_blocks[bno]=true;
	return bno;
}

int main(int argc, char *argv[])
{
	int num_lists;
	int max_list_length;
	int min_list_length;
	uint64_t max_pointer_value;
	int i, j;
	time_t t;
	int list_length;
	uint64_t current_block, next_block;
	int outfile;
	int hpfile;

	if (argc < 5) {
		printf("Usage: ./pointer_generator <num_lists> <max_pointer_value> <min_list_length> <max_list_length>\n\n");
		printf("num_lists - total number of linked lists\n");
		printf("max_pointer_value - max pointer value\n");
		printf("min_list_length - min LL size (>= 1)\n");
		printf("max_list_length - max LL size\n");
		exit(0);
	}

	outfile = open("dp.dat", O_CREAT | O_TRUNC | O_WRONLY , 0644);
	if (outfile < 0 ) {
		printf("Error creating file %s\n", strerror(errno));
		exit(0);
	}

	hpfile = open("hp.dat", O_CREAT | O_TRUNC | O_WRONLY , 0644);
	if (hpfile < 0 ) {
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

	if(max_pointer_value <= max_list_length * num_lists) {
		printf("Please reduce max_list_length %d or num_lists %d\n\nOR\n\nincrease max_pointer_value %lu\n\n", max_list_length, num_lists, max_pointer_value);
		exit(0);
	}

	for (i = 0 ; i < num_lists ; i++) {
		list_length = min_list_length + (rand() % (max_list_length - min_list_length + 1));
		current_block = get_unvisited_pointer(max_pointer_value);
		next_block = END_BLOCK_MAGIC;
		for (j = list_length ; j > 0 ; j--) {
			if (j > 1) {
				next_block = get_unvisited_pointer(max_pointer_value);
			}
			if (j == list_length) {
				dprintf(hpfile, "%lu\n", current_block);
			}
		//	printf("%d %d %d\n", current_block, next_block, j);
			dprintf(outfile, "%lu %lu %d\n", current_block, next_block, j);
			current_block = next_block;
			next_block = END_BLOCK_MAGIC;
		}
	}
	close(outfile);
	close(hpfile);
}
