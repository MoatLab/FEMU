#include <stdint.h>
#include <string.h>
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

int64_t csd_vadd_indirect(struct femu_csd_args *args)
{
    int *output;
    int *input;
    int *global_mem;
    long long count = args->cparam1;
    int pos;
    int start_loc;

    if (args->numr < 3 || count < 0) {
        return -1;
    }

    output = args->mr_addr[0];
    input = args->mr_addr[1];
    global_mem = args->mr_addr[2];
    pos = global_mem[0];
    start_loc = global_mem[1];

    if (start_loc > 0 && pos > 0) {
        memmove(output, input + start_loc, (pos - start_loc) * sizeof(int));
        pos -= start_loc;
        start_loc = 0;
    }

    for (long long i = 0; i < count; i++) {
        output[pos++] = input[i * 2] + input[i * 2 + 1];
    }

    global_mem[1] = (pos / (512 / (int)sizeof(int))) * (512 / (int)sizeof(int));
    global_mem[0] = pos;

    return global_mem[1] / (512 / (int)sizeof(int));
}
