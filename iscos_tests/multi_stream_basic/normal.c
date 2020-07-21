#include "common.h"

/* RAND_MAX assumed to be 32767 */
unsigned char myrand(void) {
	return (unsigned char)(0xAA);
//    next = next * 1103515245 + 12345;
//    return((unsigned)(next/65536) % 32768) & 0xFF;
}

void normal_write(void *x)
{
	int fd;
	struct sdm *f = (struct sdm *)x;

	fd = open(f->fn, IO_OPEN_OPTIONS);
	if (fd < 0) {
		fprintf(stderr, "file %s open error\n", f->fn);
	}
	else {
		int err;
		off_t current_offset;
		printf("Opened fd from nw_thread: %d\n", fd);
		/* stream id is persistent in the kernel for an open fd.
		   If a normal write is intented while at a stream is open, it
		   is suggested to write a stream_id of 0 before the write */ 
		for (current_offset = IO_OFFSET_NW ; current_offset < MAX_FILE_OFFSET ; current_offset += IO_TRANSFER_SIZE) {
			err = pwrite(fd, f->data_in, IO_TRANSFER_SIZE, current_offset); 
			if (err<0) {
				fprintf(stderr, "nvme write from nw_thread status:%#x(%s) \n", errno, strerror(errno));
				break;
			}else if (err != IO_TRANSFER_SIZE) {
				printf("nvme size written from nw_thread: %d\n", err);
				break;
			}
		}
		printf("WRITE DONE: \n");
	}
	// this is just for completeness, since the disk is opened using O_DIRECT flag, we dont need this.
	fsync(fd);
	close(fd);
}

int main(int argc, char **argv)
{
	static const char *perrstr;
	struct sdm f;
	int err, fd, i;

	next = time(NULL); // random seed

	if (posix_memalign((void **)&f.data_in, getpagesize(), IO_SEGMENT_SIZE))
                goto perror;

	if (posix_memalign((void **)&f.data_out, getpagesize(), IO_SEGMENT_SIZE))
                goto perror;

	memset(f.data_in, 0, IO_SEGMENT_SIZE);
	memset(f.data_out, 0, IO_SEGMENT_SIZE);

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <device>\n", argv[0]);
		return 1;
	}

	perrstr = argv[1];
	f.fn = argv[1];		
	fd = open(argv[1], O_RDWR | O_DIRECT | O_LARGEFILE);
	if (fd < 0){
		goto perror;
	}
	printf("Opened fd from main: %d\n", fd);

	err = enable_stream_directive(fd);
	if (err<0){
		fprintf(stderr, "enable stream directive status:%#x(%s)\n", errno, strerror(errno));
	}else{
		printf("enable stream directive successful\n");
	}

	err = alloc_stream_resources(fd, 1);
	if (err<0){
		fprintf(stderr, "allocate stream resource status:%#x(%s)\n", errno, strerror(errno));
	}else{
		printf("allocate stream resource successful\n");
	}

	for (i=0; i<IO_SEGMENT_SIZE; i++)
		f.data_in[i] = (unsigned char)(i % 100);

	normal_write(&f);

	/* read */
	off_t current_offset;

	printf("READ COMPARISION BEGIN: \n");
	for (current_offset = IO_OFFSET_NW ; current_offset < MAX_FILE_OFFSET ; current_offset += IO_TRANSFER_SIZE) {
		err = pread(fd, f.data_out, IO_TRANSFER_SIZE, current_offset); 
		if (err<0){
			fprintf(stderr, "nvme read status:%#x(%s)\n", errno, strerror(errno));
			goto perror;
		}else if (err != IO_TRANSFER_SIZE){
			printf("nvme size read: %d\n", err);
			goto perror;
		}
		for (i = 0 ; i < IO_TRANSFER_SIZE ; i++) {
			if (f.data_out[i] != f.data_in[i]) {
				printf("data mismatch at offset %ld:%d\n", current_offset, i);
				goto perror;
			}
		}
	}
	printf("READ COMPARISION END: \n");
	printf("nvme read for normal write successful\n");

	for (i=0; i<(IO_TRANSFER_SIZE); i++) {
		if(f.data_out[i] != (unsigned char)(i % 100)) {
			printf("nvme rw compare failed at location %u\n", i);
			goto perror;
		}
	} 

   close(fd);
   free(f.data_in);
   free(f.data_out);
	return 0;

perror:
   close(fd);
   free(f.data_in);
   free(f.data_out);
	perror(perrstr);
	return 1;
}
