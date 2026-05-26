#include <stdint.h>
#include "femu-csd-kernel.h"

int64_t csd_vadd(struct femu_csd_args *args)
{
    int *out = args->mr_addr[0];
    int *in = args->mr_addr[1];
    long long count = args->cparam1;

    if (count == 0 && args->numr >= 2) {
        long long out_count = args->mr_len[0] / (long long)sizeof(*out);
        long long in_count = args->mr_len[1] / (2 * (long long)sizeof(*in));

        count = out_count < in_count ? out_count : in_count;
    }

    if (args->numr < 2 || count < 0) {
        return -1;
    }

    for (long long i = 0; i < count; i++) {
        out[i] = in[i * 2] + in[i * 2 + 1];
    }

    return count;
}
