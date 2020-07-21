#include "common.h"

/* RAND_MAX assumed to be 32767 */
unsigned char myrand(void) {
	return (unsigned char)(0xAA);
//    next = next * 1103515245 + 12345;
//    return((unsigned)(next/65536) % 32768) & 0xFF;
}

void stream_write(void *x)
{
	int fd;
	struct sdm *f = (struct sdm *)x;

	fd = open(f->fn, IO_OPEN_OPTIONS);
	if (fd < 0) {
		fprintf(stderr, "file %s open error\n", f->fn);
	}
	else {
		int err;
		printf("Opened fd from st_thread: %d\n", fd);
		err = pwrite(fd, f->data_in, IO_ST_TRANSFER_SIZE, IO_OFFSET_ST); 
		if (err<0)
			fprintf(stderr, "nvme write from st_thread status:%#x(%s) \n", errno, strerror(errno));
		else if (err != IO_TRANSFER_SIZE)
			printf("nvme size written from st_thread: %d\n", err);
		else
			printf("nvme write from st_thread successful on fd %d\n", fd);

	}
	// this is just for completeness, since the disk is opened using O_DIRECT flag, we dont need this.
	fsync(fd);
	close(fd);
	return;

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

	err = alloc_stream_resources(fd, 4);
	if (err<0){
		fprintf(stderr, "allocate stream resource status:%#x(%s)\n", errno, strerror(errno));
	}else{
		printf("allocate stream resource successful\n");
	}

	for (i=0; i<IO_SEGMENT_SIZE; i++)
		f.data_in[i] = myrand();

	stream_write(&f);

	/* read */
	err = pread(fd, f.data_out, IO_TRANSFER_SIZE, IO_OFFSET_ST); 
	if (err<0)
		fprintf(stderr, "nvme read status:%#x(%s)\n", errno, strerror(errno));
	else if (err != IO_TRANSFER_SIZE)
		printf("nvme size read: %d\n", err);
	else
		printf("nvme read for stream write successful\n");

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
