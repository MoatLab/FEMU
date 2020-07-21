#ifndef COMMON_C_
#define COMMON_C_

#include "common.h"

#define COMPUTE_DW11(dspec, dtype, doper) (dspec << 16 | dtype << 8 | doper)

static int nvme_dir_send(int fd, __u32 nsid, __u16 dspec, __u8 dtype, __u8 doper,
                  __u32 data_len, __u32 dw12, void *data, __u32 *result)
{
        struct nvme_admin_cmd cmd = {
                .opcode         = nvme_admin_directive_send,
                .addr           = (__u64)(uintptr_t) data,
                .data_len       = data_len,
                .nsid           = nsid,
                .cdw10          = data_len? (data_len >> 2) - 1 : 0,
                .cdw11          = COMPUTE_DW11(dspec, dtype, doper),
                .cdw12          = dw12,
        };
        int err;

        err = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
        if (!err && result)
                *result = cmd.result;
        return err;
}

static int nvme_dir_recv(int fd, __u32 nsid, __u16 dspec, __u8 dtype, __u8 doper,
                  __u32 data_len, __u32 dw12, void *data, __u32 *result)
{
        struct nvme_admin_cmd cmd = {
                .opcode         = nvme_admin_directive_recv,
                .addr           = (__u64)(uintptr_t) data,
                .data_len       = data_len,
                .nsid           = nsid,
                .cdw10          = data_len? (data_len >> 2) - 1 : 0,
                .cdw11          = COMPUTE_DW11(dspec, dtype, doper),
                .cdw12          = dw12,
        };
        int err;

        err = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
        if (!err && result)
                *result = cmd.result;
        return err;
}

static int nvme_get_nsid(int fd)
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

// rsc_cnt is the resource count. it defines the number of 
// streams required for a particular file descriptor.
// the resultant number of streams are stored in result.
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

#endif
