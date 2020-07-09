// Temporary file defining what to do in computation. This will be removed later
// when we add the compute operations in NVMe commands.

//#define COUNTING
#define POINTER_CHASING


// pointer chasing macros.
#define END_BLOCK_MAGIC 99999
#define BLOCK_SIZE 4096

uint64_t count_bits(char *buf);
uint64_t get_disk_pointer(char *buf);
