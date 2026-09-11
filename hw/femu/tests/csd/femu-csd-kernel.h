#ifndef FEMU_CSD_KERNEL_H
#define FEMU_CSD_KERNEL_H

struct femu_csd_args {
    int numr;
    void **mr_addr;
    long long *mr_len;
    long long cparam1;
    long long cparam2;
    void *data_buffer;
    long long buffer_len;
} __attribute__((packed));

#endif
