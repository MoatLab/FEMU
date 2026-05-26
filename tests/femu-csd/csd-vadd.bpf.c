#include "femu-csd-kernel.h"

long long csd_vadd_bpf(struct femu_csd_args *args)
{
    int *in;
    int *out;
    long long count;

    if (args->numr < 2) {
        return -1;
    }

    in = args->mr_addr[1];
    out = args->mr_addr[0];
    count = args->cparam1;
    if (count <= 0) {
        return -1;
    }

    for (long long i = 0; i < count; i++) {
        out[i] = in[i * 2] + in[i * 2 + 1];
    }

    return count;
}
