#include "god.h"
#include <time.h>

#define TSC_OFT_FN_LEN  64
/* Coperd: nanosecond to cycles ratio, need to be profiled first */
#define NS2CYC_RATIO    2.3 

char tsc_offset_fn[TSC_OFT_FN_LEN] = {'\0'};
int64_t tsc_offset;

int64_t blocking_to;

int64_t get_ts_in_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    return (ts.tv_sec * 1e9 + ts.tv_nsec);
}

/* Coperd: pre-measured cycle rate */
inline int64_t ns2cyc(int64_t ns)
{
    return (int64_t)(NS2CYC_RATIO * ns);
}

inline int64_t cyc2ns(int64_t cycles)
{
    return (int64_t)(cycles / NS2CYC_RATIO);
}

uint64_t rdtscp(void)
{
    uint32_t eax = 0, edx;

    __asm__ __volatile__("rdtscp"
            : "+a" (eax), "=d" (edx)
            :
            : "%ecx", "memory");

    return (((uint64_t)edx << 32) | eax);
}

void set_tsc_offset_fn(pid_t qemu_pid, int vmfd)
{
    assert(qemu_pid);
    assert(vmfd);
    sprintf(tsc_offset_fn, "%d-%d", qemu_pid, vmfd);
}

/*
 * Coperd: read tsc_offset, must be called after tsc_offset_fn is ready 
 * tsc_offset_fn: "<pid>-<vmfd>"
 */
int read_tsc_offset(void)
{
    char tn[TSC_OFT_FN_LEN] = {'\0'};
    const char *pn = "/sys/kernel/debug/kvm/";
    /* Coperd: assume all vcpus share the same TSC-OFFSET, TODO:fix */
    const char *sn = "/vcpu0/tsc-offset";

    assert(tsc_offset_fn);

    /* Coperd: need root privilege */
    if (getuid()) {
        return -1;
    }

    strncat(tn, pn, strlen(pn));
    strncat(tn, tsc_offset_fn, strlen(tsc_offset_fn));
    strncat(tn, sn, strlen(sn));
    FILE *fp = fopen(tn, "r");
    if (!fp) {
        printf("Coperd, failed to open tsc-offset file [%s]\n", tn);
        return -1;
    }

    /* Coperd: tsc_offset is negative number */
    int nr = fscanf(fp, "%" SCNd64 "\n", &tsc_offset);
    if (nr != 1) {
        printf("Error reading %s, expecting only one number, but read [%d]\n",
                tsc_offset_fn, nr);
        return -1;
    }

    printf("Coperd,tsc-offset=%" PRId64 "\n", tsc_offset);

    return 0;
}
