#include "common.h"

/* RAND_MAX assumed to be 32767 */
unsigned char myrand(void) {
    next = next * 1103515245 + 12345;
    return((unsigned)(next/65536) % 32768) & 0xFF;
}

void *normal_write(void *x)
{
	int fd;
	struct sdm *f = (struct sdm *)x;

	fd = open(f->fn, IO_OPEN_OPTIONS);
	if (fd < 0) {
		fprintf(stderr, "file %s open error\n", f->fn);
	}
	else {
		int err;
		printf("Opened fd from nw_thread: %d\n", fd);
		/* stream id is persistent in the kernel for an open fd.
		   If a normal write is intented while at a stream is open, it
		   is suggested to write a stream_id of 0 before the write */ 
		posix_fadvise(fd, 0, 0, POSIX_FADV_STREAMID);
		err = pwrite(fd, f->data_in, IO_TRANSFER_SIZE, IO_OFFSET_NW); 
		if (err<0)
			fprintf(stderr, "nvme write from nw_thread status:%#x(%s) \n", errno, strerror(errno));
		else if (err != IO_TRANSFER_SIZE)
			printf("nvme size written from nw_thread: %d\n", err);
		else
			printf("nvme write from nw_thread successful on fd %d\n", fd);

	}
	close(fd);
	return NULL;
}

void *stream_write(void *x)
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
		posix_fadvise(fd, f->sid, 0, POSIX_FADV_STREAMID);
		err = pwrite(fd, f->data_in, IO_ST_TRANSFER_SIZE, IO_OFFSET_ST); 
		if (err<0)
			fprintf(stderr, "nvme write from st_thread status:%#x(%s) \n", errno, strerror(errno));
		else if (err != IO_TRANSFER_SIZE)
			printf("nvme size written from st_thread: %d\n", err);
		else
			printf("nvme write from st_thread successful on fd %d\n", fd);

	}
	close(fd);
	return NULL;

}

int nvme_dir_send(int fd, __u32 nsid, __u16 dspec, __u8 dtype, __u8 doper,
                  __u32 data_len, __u32 dw12, void *data, __u32 *result)
{
        struct nvme_admin_cmd cmd = {
                .opcode         = nvme_admin_directive_send,
                .addr           = (__u64)(uintptr_t) data,
                .data_len       = data_len,
                .nsid           = nsid,
                .cdw10          = data_len? (data_len >> 2) - 1 : 0,
                .cdw11          = dspec << 16 | dtype << 8 | doper,
                .cdw12          = dw12,
        };
        int err;

        err = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
        if (!err && result)
                *result = cmd.result;
        return err;
}

int nvme_dir_recv(int fd, __u32 nsid, __u16 dspec, __u8 dtype, __u8 doper,
                  __u32 data_len, __u32 dw12, void *data, __u32 *result)
{
        struct nvme_admin_cmd cmd = {
                .opcode         = nvme_admin_directive_recv,
                .addr           = (__u64)(uintptr_t) data,
                .data_len       = data_len,
                .nsid           = nsid,
                .cdw10          = data_len? (data_len >> 2) - 1 : 0,
                .cdw11          = dspec << 16 | dtype << 8 | doper,
                .cdw12          = dw12,
        };
        int err;

        err = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
        if (!err && result)
                *result = cmd.result;
        return err;
}

int nvme_get_nsid(int fd)
{
        static struct stat nvme_stat;
        int err = fstat(fd, &nvme_stat);

        if (err < 0)
                return err;

        if (!S_ISBLK(nvme_stat.st_mode)) {
                fprintf(stderr,
                        "Error: requesting namespace-id from non-block device\n");
                exit(ENOTBLK);
        }
        return ioctl(fd, NVME_IOCTL_ID);
}

int enable_stream_directive(int fd)
{
	__u32 result;
	int err;
	int nsid = nvme_get_nsid(fd);

	printf("Enable stream directive for nsid %d\n", nsid);
	err = nvme_dir_send(fd, nsid, 0, 0, 1, 0, 0x101, NULL, &result);
	return err;

}

int alloc_stream_resources(int fd, unsigned int rsc_cnt)
{
	__u32 result;
	int err;
	int nsid = nvme_get_nsid(fd);

	printf("Allocate stream resource for nsid %d\n", nsid);
	err = nvme_dir_recv(fd, nsid, 0, 1, 3, 0, rsc_cnt, NULL, &result);
	if (err==0)
		printf("  requested %d; returned %d\n", rsc_cnt, result & 0xffff);
	return err;
}

int main(int argc, char **argv)
{
	static const char *perrstr;
	struct sdm f;
	int err, fd, i;

	pthread_t nw_thread;
	pthread_t st_thread;

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
	if (fd < 0)
		goto perror;
	printf("Opened fd from main: %d\n", fd);

	err = enable_stream_directive(fd);
	if (err<0)
		fprintf(stderr, "enable stream directive status:%#x(%s)\n", errno, strerror(errno));
	else
		printf("enable stream directive successful\n");

	err = alloc_stream_resources(fd, 4);
	if (err<0)
		fprintf(stderr, "allocate stream resource status:%#x(%s)\n", errno, strerror(errno));
	else
		printf("allocate stream resource successful\n");

	for (i=0; i<IO_SEGMENT_SIZE; i++)
		f.data_in[i] = myrand();
	f.sid = 1;
	if(pthread_create(&st_thread, NULL, stream_write, &f)) {
		fprintf(stderr, "Error creating stream write thread\n");
		goto perror;
	}

	sleep(1); /* let the stream write to start first */

	if(pthread_create(&nw_thread, NULL, normal_write, &f)) {
		fprintf(stderr, "Error creating normal write thread\n");
		goto perror;
	}

	if(pthread_join(nw_thread, NULL)) {
		fprintf(stderr, "Error joining nw_thread\n");
	}

	/* read */
	err = pread(fd, f.data_out, IO_TRANSFER_SIZE, IO_OFFSET_NW); 
	if (err<0)
		fprintf(stderr, "nvme read status:%#x(%s)\n", errno, strerror(errno));
	else if (err != IO_TRANSFER_SIZE)
		printf("nvme size read: %d\n", err);
	else
		printf("nvme read for normal write successful\n");

	printf("Write Data: ");
	for (i=0; i<10; i++)
		printf("%4d", f.data_in[i]);
	printf("\n");

	printf("Read Data:  ");
	for (i=0; i<10; i++)
		printf("%4d", f.data_out[i]);
	printf("\n");

	for (i=0; i<(IO_TRANSFER_SIZE); i++) {
		if(f.data_out[i] != f.data_in[i]) {
			printf("nvme rw compare failed at location %u\n", i);
			break;
		}
	} 

	if(pthread_join(st_thread, NULL)) {
		fprintf(stderr, "Error joining st_thread\n");
	}

	/* read */
	err = pread(fd, f.data_out, IO_TRANSFER_SIZE, IO_OFFSET_ST); 
	if (err<0)
		fprintf(stderr, "nvme read status:%#x(%s)\n", errno, strerror(errno));
	else if (err != IO_TRANSFER_SIZE)
		printf("nvme size read: %d\n", err);
	else
		printf("nvme read for stream write successful\n");

	printf("Write Data: ");
	for (i=0; i<10; i++)
		printf("%4d", f.data_in[i]);
	printf("\n");

	printf("Read Data:  ");
	for (i=0; i<10; i++)
		printf("%4d", f.data_out[i]);
	printf("\n");

	for (i=0; i<(IO_TRANSFER_SIZE); i++) {
		if(f.data_out[i] != f.data_in[i]) {
			printf("nvme rw compare failed at location %u\n", i);
			break;
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
