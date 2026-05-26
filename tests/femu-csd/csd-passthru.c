#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/nvme_ioctl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

enum {
    CSD_ADM_COMPUTE_LOAD     = 0x22,
    CSD_ADM_COMPUTE_LOAD_DATA = 0x25,
    CSD_ADM_COMPUTE_ACTIVATE = 0x23,
    CSD_CMD_ALLOC_FDM    = 0xb0,
    CSD_CMD_DEALLOC_AFDM = 0xc0,
    CSD_CMD_NVM_TO_AFDM  = 0xd0,
    CSD_CMD_EXEC         = 0xe1,
    CSD_CMD_READ_AFDM    = 0xf2,
    CSD_CMD_WRITE_AFDM   = 0xf5,
    CSD_CMD_CREATE_GROUP = 0xf6,
    CSD_CMD_SET_QOS      = 0xf7,
    CSD_CMD_DELETE_GROUP = 0xf8,
};

enum {
    CSD_CSF_TYPE_PHANTOM = 0,
    CSD_CSF_TYPE_EBPF = 1,
    CSD_CSF_TYPE_SHARED_LIB = 3,
};

enum {
    CSD_MR_AFDM_NSID = 0,
};

struct csd_memory_range {
    uint32_t nsid;
    uint32_t len;
    uint64_t sb;
    uint64_t rsvd[2];
} __attribute__((packed));

struct csd_program_execute_cmd {
    uint8_t opcode;
    uint8_t flags;
    uint16_t cid;
    uint32_t nsid;
    uint16_t pind;
    uint16_t rsid;
    uint32_t numr;
    uint32_t dlen;
    uint32_t rsvd;
    uint64_t prp1;
    uint64_t prp2;
    uint64_t cparam1;
    uint64_t cparam2;
    uint32_t group:8;
    uint32_t chunk_nlb:24;
    uint32_t runtime;
} __attribute__((packed));

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s /dev/nvmeXnY smoke\n"
            "  %s /dev/nvmeXnY alloc <bytes>\n"
            "  %s /dev/nvmeXnY dealloc <id>\n"
            "  %s /dev/nvmeXnY exec <pind> <in-afdm-id> <out-afdm-id> [runtime-ns] [group-id] [cparam1] [cparam2]\n"
            "  %s /dev/nvmeXnY smoke-so <host-visible-so-path>\n"
            "  %s /dev/nvmeXnY smoke-so-all <host-visible-kernels-so-path>\n"
            "  %s /dev/nvmeXnY bench <bytes> <iterations>\n"
            "  %s /dev/nvmeX admin-load-so <pind> <host-visible-so-path> <symbol> [runtime-ns]\n"
            "  %s /dev/nvmeX admin-load-ubpf <pind> <host-visible-elf-path> <symbol> [jit:0|1] [runtime-ns]\n"
            "  %s /dev/nvmeX admin-load-phantom <pind> <runtime-ns>\n"
            "  %s /dev/nvmeX admin-activate <pind>\n"
            "  %s /dev/nvmeX admin-deactivate <pind>\n"
            "  %s /dev/nvmeX admin-unload <pind>\n"
            "  %s /dev/nvmeXnY create-group <prio> <bandwidth-kb> <deadline-us>\n"
            "  %s /dev/nvmeXnY set-qos <group-id> <prio> <bandwidth-kb> <deadline-us>\n"
            "  %s /dev/nvmeXnY delete-group <group-id>\n"
            "  %s /dev/nvmeXnY write <id> <offset> <string>\n"
            "  %s /dev/nvmeXnY read <id> <offset> <bytes>\n"
            "  %s /dev/nvmeXnY nvm-to-afdm <id> <offset> <slba> <nlb>\n",
            prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog,
            prog, prog, prog, prog, prog, prog, prog, prog);
}

static uint64_t monotonic_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static uint64_t parse_u64(const char *s, const char *name)
{
    char *end = NULL;
    uint64_t v;

    errno = 0;
    v = strtoull(s, &end, 0);
    if (errno || !end || *end) {
        fprintf(stderr, "invalid %s: %s\n", name, s);
        exit(EXIT_FAILURE);
    }

    return v;
}

static int submit(int fd, struct nvme_passthru_cmd *cmd)
{
    int ret = ioctl(fd, NVME_IOCTL_IO_CMD, cmd);

    if (ret < 0) {
        perror("NVME_IOCTL_IO_CMD");
        return -1;
    }
    if (ret > 0) {
        fprintf(stderr, "NVME_IOCTL_IO_CMD status=0x%x result=0x%x\n",
                ret, cmd->result);
        return -1;
    }

    return 0;
}

static int submit_admin(int fd, struct nvme_passthru_cmd *cmd)
{
    int ret = ioctl(fd, NVME_IOCTL_ADMIN_CMD, cmd);

    if (ret < 0) {
        perror("NVME_IOCTL_ADMIN_CMD");
        return -1;
    }
    if (ret > 0) {
        fprintf(stderr, "NVME_IOCTL_ADMIN_CMD status=0x%x result=0x%x\n",
                ret, cmd->result);
        return -1;
    }

    return 0;
}

static int open_admin_from_namespace(const char *dev)
{
    char ctrl[PATH_MAX];
    char *base;
    char *name;
    char *ns;
    int fd;

    if (strlen(dev) >= sizeof(ctrl)) {
        fprintf(stderr, "device path too long: %s\n", dev);
        exit(EXIT_FAILURE);
    }

    strcpy(ctrl, dev);
    base = strrchr(ctrl, '/');
    name = base ? base + 1 : ctrl;
    ns = strstr(name, "nvme");
    if (ns) {
        ns = strchr(ns + strlen("nvme"), 'n');
        if (ns) {
            *ns = '\0';
        }
    }

    fd = open(ctrl, O_RDWR);
    if (fd < 0) {
        perror(ctrl);
        exit(EXIT_FAILURE);
    }

    return fd;
}

static void csd_admin_load_program(int fd, uint16_t pind, uint8_t type,
                                   const char *path, const char *symbol,
                                   uint8_t flags, uint32_t runtime)
{
    size_t path_len = path ? strlen(path) : 0;
    size_t symbol_len = symbol ? strlen(symbol) : 0;
    size_t size = path_len + symbol_len + (path ? 2 : 0);
    void *buf = NULL;
    uint32_t cdw10 = pind | ((uint32_t)type << 16);
    struct nvme_passthru_cmd cmd = {
        .opcode = size ? CSD_ADM_COMPUTE_LOAD_DATA : CSD_ADM_COMPUTE_LOAD,
        .nsid = 1,
        .data_len = size,
        .cdw2 = ((uint32_t)flags & 0x1),
        .cdw3 = runtime,
        .cdw10 = cdw10,
        .cdw11 = (uint32_t)size,
        .cdw14 = (uint32_t)size,
    };

    if (size) {
        if (posix_memalign(&buf, 4096, (size + 4095) & ~4095ULL)) {
            perror("posix_memalign");
            exit(EXIT_FAILURE);
        }
        memset(buf, 0, (size + 4095) & ~4095ULL);
        memcpy(buf, path, path_len);
        memcpy((char *)buf + path_len + 1, symbol, symbol_len);
        cmd.addr = (uintptr_t)buf;
    }

    if (submit_admin(fd, &cmd)) {
        free(buf);
        exit(EXIT_FAILURE);
    }

    free(buf);
}

static void csd_admin_unload_program(int fd, uint16_t pind)
{
    struct nvme_passthru_cmd cmd = {
        .opcode = CSD_ADM_COMPUTE_LOAD,
        .nsid = 1,
        .cdw10 = pind | (1U << 24),
    };

    if (submit_admin(fd, &cmd)) {
        exit(EXIT_FAILURE);
    }
}

static void csd_admin_activation(int fd, uint16_t pind, uint8_t sel)
{
    struct nvme_passthru_cmd cmd = {
        .opcode = CSD_ADM_COMPUTE_ACTIVATE,
        .nsid = 1,
        .cdw10 = pind | ((uint32_t)sel << 16),
    };

    if (submit_admin(fd, &cmd)) {
        exit(EXIT_FAILURE);
    }
}

static uint32_t csd_exec_ranges(int fd, uint32_t pind, uint32_t mr0_afdm_id,
                                uint32_t mr1_afdm_id, uint32_t runtime,
                                uint32_t group_id, uint64_t cparam1,
                                uint64_t cparam2)
{
    struct nvme_passthru_cmd cmd = { 0 };
    struct csd_program_execute_cmd *exec =
        (struct csd_program_execute_cmd *)&cmd;
    struct csd_memory_range ranges[2] = {
        {
            .nsid = CSD_MR_AFDM_NSID,
            .len = 0,
            .sb = mr0_afdm_id,
        },
        {
            .nsid = CSD_MR_AFDM_NSID,
            .len = 0,
            .sb = mr1_afdm_id,
        },
    };

    exec->opcode = CSD_CMD_EXEC;
    exec->nsid = 1;
    exec->pind = pind;
    exec->numr = 2;
    exec->cparam1 = cparam1;
    exec->cparam2 = cparam2;
    exec->group = group_id;
    exec->runtime = runtime;

    cmd.addr = (uintptr_t)ranges;
    cmd.data_len = sizeof(ranges);

    if (submit(fd, &cmd)) {
        exit(EXIT_FAILURE);
    }

    return cmd.result;
}

static uint32_t csd_exec(int fd, uint32_t pind, uint32_t in_afdm_id,
                         uint32_t out_afdm_id, uint32_t runtime,
                         uint32_t group_id, uint64_t cparam1,
                         uint64_t cparam2)
{
    return csd_exec_ranges(fd, pind, out_afdm_id, in_afdm_id, runtime,
                           group_id, cparam1, cparam2);
}

static uint32_t csd_create_group(int fd, int8_t prio, uint32_t bandwidth,
                                 uint32_t deadline)
{
    struct nvme_passthru_cmd cmd = {
        .opcode = CSD_CMD_CREATE_GROUP,
        .nsid = 1,
        .cdw10 = (uint8_t)prio,
        .cdw11 = bandwidth,
        .cdw12 = deadline,
    };

    if (submit(fd, &cmd)) {
        exit(EXIT_FAILURE);
    }

    return cmd.result;
}

static void csd_set_qos(int fd, uint32_t group_id, int8_t prio,
                        uint32_t bandwidth, uint32_t deadline)
{
    struct nvme_passthru_cmd cmd = {
        .opcode = CSD_CMD_SET_QOS,
        .nsid = 1,
        .cdw10 = (uint8_t)prio,
        .cdw11 = bandwidth,
        .cdw12 = deadline,
        .cdw13 = group_id,
    };

    if (submit(fd, &cmd)) {
        exit(EXIT_FAILURE);
    }
}

static void csd_delete_group(int fd, uint32_t group_id)
{
    struct nvme_passthru_cmd cmd = {
        .opcode = CSD_CMD_DELETE_GROUP,
        .nsid = 1,
        .cdw10 = group_id,
    };

    if (submit(fd, &cmd)) {
        exit(EXIT_FAILURE);
    }
}

static uint32_t csd_alloc(int fd, uint64_t size)
{
    struct nvme_passthru_cmd cmd = {
        .opcode = CSD_CMD_ALLOC_FDM,
        .nsid = 1,
        .cdw10 = (uint32_t)size,
        .cdw11 = (uint32_t)(size >> 32),
        .cdw12 = 0,
    };

    if (submit(fd, &cmd)) {
        exit(EXIT_FAILURE);
    }

    return cmd.result;
}

static void csd_dealloc(int fd, uint32_t id)
{
    struct nvme_passthru_cmd cmd = {
        .opcode = CSD_CMD_DEALLOC_AFDM,
        .nsid = 1,
        .cdw10 = id,
    };

    if (submit(fd, &cmd)) {
        exit(EXIT_FAILURE);
    }
}

static void csd_write(int fd, uint32_t id, uint64_t offset, const void *buf,
                      uint32_t size)
{
    struct nvme_passthru_cmd cmd = {
        .opcode = CSD_CMD_WRITE_AFDM,
        .nsid = 1,
        .addr = (uintptr_t)buf,
        .data_len = size,
        .cdw10 = (uint32_t)offset,
        .cdw11 = (uint32_t)(offset >> 32),
        .cdw12 = size,
        .cdw13 = 0,
        .cdw14 = id,
    };

    if (submit(fd, &cmd)) {
        exit(EXIT_FAILURE);
    }
}

static void csd_read(int fd, uint32_t id, uint64_t offset, void *buf,
                     uint32_t size)
{
    struct nvme_passthru_cmd cmd = {
        .opcode = CSD_CMD_READ_AFDM,
        .nsid = 1,
        .addr = (uintptr_t)buf,
        .data_len = size,
        .cdw10 = (uint32_t)offset,
        .cdw11 = (uint32_t)(offset >> 32),
        .cdw12 = size,
        .cdw13 = 0,
        .cdw14 = id,
    };

    if (submit(fd, &cmd)) {
        exit(EXIT_FAILURE);
    }
}

static void csd_nvm_to_afdm(int fd, uint32_t id, uint64_t offset,
                            uint64_t slba, uint16_t nlb)
{
    struct nvme_passthru_cmd cmd = {
        .opcode = CSD_CMD_NVM_TO_AFDM,
        .nsid = 1,
        .cdw10 = (uint32_t)slba,
        .cdw11 = (uint32_t)(slba >> 32),
        .cdw12 = nlb,
        .cdw13 = id,
        .cdw14 = (uint32_t)offset,
        .cdw15 = (uint32_t)(offset >> 32),
    };

    if (submit(fd, &cmd)) {
        exit(EXIT_FAILURE);
    }
}

static void dump_hex(const uint8_t *buf, size_t size)
{
    for (size_t i = 0; i < size; i++) {
        printf("%02x%s", buf[i], (i + 1) % 16 == 0 ? "\n" : " ");
    }
    if (size % 16) {
        printf("\n");
    }
}

static void run_smoke(const char *dev, int fd)
{
    const char *msg = "femu-csd-afdm-smoke";
    size_t msg_len = strlen(msg) + 1;
    uint8_t *write_buf = NULL;
    uint8_t *read_buf = NULL;
    uint32_t id;
    uint16_t csf_id = 1;
    int admin_fd;

    if (posix_memalign((void **)&write_buf, 4096, 4096) ||
        posix_memalign((void **)&read_buf, 4096, 4096)) {
        perror("posix_memalign");
        exit(EXIT_FAILURE);
    }

    memset(write_buf, 0, 4096);
    memset(read_buf, 0, 4096);
    memcpy(write_buf, msg, msg_len);

    id = csd_alloc(fd, 4096);
    printf("allocated AFDM id=%" PRIu32 "\n", id);

    csd_write(fd, id, 0, write_buf, 4096);
    csd_read(fd, id, 0, read_buf, 4096);

    if (memcmp(write_buf, read_buf, 4096)) {
        fprintf(stderr, "AFDM smoke mismatch\n");
        exit(EXIT_FAILURE);
    }

    admin_fd = open_admin_from_namespace(dev);
    csd_admin_load_program(admin_fd, csf_id, CSD_CSF_TYPE_PHANTOM,
                           NULL, NULL, 0, 1000);
    csd_admin_activation(admin_fd, csf_id, 1);
    printf("loaded phantom CSF id=%" PRIu16 "\n", csf_id);
    csd_exec(fd, csf_id, id, id, 0, 0, 0, 0);
    csd_admin_activation(admin_fd, csf_id, 0);
    csd_admin_unload_program(admin_fd, csf_id);
    close(admin_fd);
    printf("phantom exec passed\n");

    csd_dealloc(fd, id);
    printf("AFDM smoke passed\n");

    free(write_buf);
    free(read_buf);
}

static void run_so_smoke(const char *dev, int fd, const char *so_path)
{
    enum { COUNT = 1024 };
    int *input = NULL;
    int *output = NULL;
    uint32_t in_id;
    uint32_t out_id;
    uint16_t csf_id = 1;
    int admin_fd;

    if (posix_memalign((void **)&input, 4096, 8192) ||
        posix_memalign((void **)&output, 4096, 4096)) {
        perror("posix_memalign");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < COUNT; i++) {
        input[i * 2] = i;
        input[i * 2 + 1] = i * 2;
        output[i] = 0;
    }

    in_id = csd_alloc(fd, 8192);
    out_id = csd_alloc(fd, 4096);
    csd_write(fd, in_id, 0, input, 8192);
    csd_write(fd, out_id, 0, output, 4096);

    admin_fd = open_admin_from_namespace(dev);
    csd_admin_load_program(admin_fd, csf_id, CSD_CSF_TYPE_SHARED_LIB,
                           so_path, "csd_vadd", 0, 0);
    csd_admin_activation(admin_fd, csf_id, 1);
    printf("loaded shared-library CSF id=%" PRIu16 "\n", csf_id);
    csd_exec(fd, csf_id, in_id, out_id, 0, 0, COUNT, 0);
    csd_read(fd, out_id, 0, output, 4096);

    for (int i = 0; i < COUNT; i++) {
        int expected = i + i * 2;

        if (output[i] != expected) {
            fprintf(stderr, "shared-library smoke mismatch at %d: got %d expected %d\n",
                    i, output[i], expected);
            exit(EXIT_FAILURE);
        }
    }

    csd_dealloc(fd, in_id);
    csd_dealloc(fd, out_id);
    csd_admin_activation(admin_fd, csf_id, 0);
    csd_admin_unload_program(admin_fd, csf_id);
    close(admin_fd);
    printf("shared-library smoke passed\n");

    free(input);
    free(output);
}

static void run_original_so_smoke(const char *dev, int fd, const char *so_path)
{
    int admin_fd = open_admin_from_namespace(dev);
    uint32_t in_id;
    uint32_t out_id;
    uint8_t *input = NULL;
    uint8_t *output = NULL;
    uint32_t pattern_id;
    uint8_t *pattern = NULL;

    if (posix_memalign((void **)&input, 4096, 65536) ||
        posix_memalign((void **)&output, 4096, 65536) ||
        posix_memalign((void **)&pattern, 4096, 4096)) {
        perror("posix_memalign");
        exit(EXIT_FAILURE);
    }

    memset(input, 0, 65536);
    memset(output, 0, 65536);
    memset(pattern, 0, 4096);

    enum { KNN_NODES = 4, KNN_NODE_SIZE = 4160 };
    for (int n = 0; n < KNN_NODES; n++) {
        uint8_t *node = input + n * KNN_NODE_SIZE;

        memset(node, 'A' + n, 64);
        memset(node + 64, '0' + n, 4096);
    }
    in_id = csd_alloc(fd, KNN_NODES * KNN_NODE_SIZE);
    out_id = csd_alloc(fd, 4096);
    csd_write(fd, in_id, 0, input, KNN_NODES * KNN_NODE_SIZE);
    csd_admin_load_program(admin_fd, 2, CSD_CSF_TYPE_SHARED_LIB,
                           so_path, "csd_knn", 0, 0);
    csd_admin_activation(admin_fd, 2, 1);
    csd_exec_ranges(fd, 2, in_id, out_id, 0, 0, 0, 0);
    csd_read(fd, out_id, 0, output, 4096);
    for (int i = 0; i < KNN_NODES; i++) {
        if (((int *)output)[i] < 0) {
            fprintf(stderr, "knn smoke invalid distance at %d\n", i);
            exit(EXIT_FAILURE);
        }
    }
    csd_admin_activation(admin_fd, 2, 0);
    csd_admin_unload_program(admin_fd, 2);
    csd_dealloc(fd, in_id);
    csd_dealloc(fd, out_id);
    printf("knn shared-library smoke passed\n");

    memset(input, 'x', 65536);
    memset(output, 0, 65536);
    for (int r = 0; r < 8; r++) {
        char *record = (char *)input + r * 32;

        memset(record, 'A' + r, 32);
        record[30] = '0';
        record[31] = (r % 2) ? ('0' + 55) : ('0' + 70);
    }
    in_id = csd_alloc(fd, 4096);
    out_id = csd_alloc(fd, 4096);
    csd_write(fd, in_id, 0, input, 4096);
    csd_write(fd, out_id, 0, output, 4096);
    csd_admin_load_program(admin_fd, 3, CSD_CSF_TYPE_SHARED_LIB,
                           so_path, "csd_sql", 0, 0);
    csd_admin_activation(admin_fd, 3, 1);
    if (csd_exec_ranges(fd, 3, in_id, out_id, 0, 0, 50, 60) != 4 * 32) {
        fprintf(stderr, "sql smoke unexpected result\n");
        exit(EXIT_FAILURE);
    }
    csd_admin_activation(admin_fd, 3, 0);
    csd_admin_unload_program(admin_fd, 3);
    csd_dealloc(fd, in_id);
    csd_dealloc(fd, out_id);
    printf("sql shared-library smoke passed\n");

    memset(input, 'Z', 65536);
    memcpy(input + 32, "needle", 6);
    memcpy(input + 96, "needle", 6);
    memcpy(pattern, "needle", 7);
    in_id = csd_alloc(fd, 4096);
    pattern_id = csd_alloc(fd, 4096);
    csd_write(fd, in_id, 0, input, 4096);
    csd_write(fd, pattern_id, 0, pattern, 4096);
    csd_admin_load_program(admin_fd, 4, CSD_CSF_TYPE_SHARED_LIB,
                           so_path, "csd_grep", 0, 0);
    csd_admin_activation(admin_fd, 4, 1);
    if (csd_exec_ranges(fd, 4, in_id, pattern_id, 0, 0, 4, 1024) != 16) {
        fprintf(stderr, "grep smoke unexpected result\n");
        exit(EXIT_FAILURE);
    }
    csd_admin_activation(admin_fd, 4, 0);
    csd_admin_unload_program(admin_fd, 4);
    csd_dealloc(fd, in_id);
    csd_dealloc(fd, pattern_id);
    printf("grep shared-library smoke passed\n");

    close(admin_fd);
    free(input);
    free(output);
    free(pattern);
}

static void run_bench(int fd, uint32_t size, uint32_t iterations)
{
    uint8_t *buf = NULL;
    uint8_t *read_buf = NULL;
    uint32_t id;
    uint64_t start;
    uint64_t end;

    if (size == 0 || iterations == 0) {
        fprintf(stderr, "bench requires non-zero bytes and iterations\n");
        exit(EXIT_FAILURE);
    }
    if (posix_memalign((void **)&buf, 4096, (size + 4095U) & ~4095U) ||
        posix_memalign((void **)&read_buf, 4096, (size + 4095U) & ~4095U)) {
        perror("posix_memalign");
        exit(EXIT_FAILURE);
    }
    memset(buf, 0x5a, (size + 4095U) & ~4095U);
    memset(read_buf, 0, (size + 4095U) & ~4095U);

    id = csd_alloc(fd, size);

    start = monotonic_ns();
    for (uint32_t i = 0; i < iterations; i++) {
        csd_write(fd, id, 0, buf, size);
    }
    end = monotonic_ns();
    printf("bench afdm_write bytes=%u iterations=%u avg_ns=%" PRIu64 "\n",
           size, iterations, (end - start) / iterations);

    start = monotonic_ns();
    for (uint32_t i = 0; i < iterations; i++) {
        csd_read(fd, id, 0, read_buf, size);
    }
    end = monotonic_ns();
    printf("bench afdm_read bytes=%u iterations=%u avg_ns=%" PRIu64 "\n",
           size, iterations, (end - start) / iterations);

    if (pwrite(fd, buf, size, 0) != size) {
        perror("pwrite nvm");
        exit(EXIT_FAILURE);
    }
    fsync(fd);
    start = monotonic_ns();
    for (uint32_t i = 0; i < iterations; i++) {
        csd_nvm_to_afdm(fd, id, 0, 0, (uint16_t)((size + 4095U) / 4096U - 1));
    }
    end = monotonic_ns();
    printf("bench nvm_to_afdm bytes=%u iterations=%u avg_ns=%" PRIu64 "\n",
           size, iterations, (end - start) / iterations);

    csd_dealloc(fd, id);
    free(buf);
    free(read_buf);
}

int main(int argc, char **argv)
{
    const char *dev;
    const char *op;
    int fd;

    if (argc < 3) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    dev = argv[1];
    op = argv[2];
    fd = open(dev, O_RDWR);
    if (fd < 0) {
        perror(dev);
        return EXIT_FAILURE;
    }

    if (!strcmp(op, "smoke")) {
        run_smoke(dev, fd);
    } else if (!strcmp(op, "smoke-so")) {
        if (argc != 4) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        run_so_smoke(dev, fd, argv[3]);
    } else if (!strcmp(op, "smoke-so-all")) {
        if (argc != 4) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        run_original_so_smoke(dev, fd, argv[3]);
    } else if (!strcmp(op, "bench")) {
        if (argc != 5) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        run_bench(fd, (uint32_t)parse_u64(argv[3], "bytes"),
                  (uint32_t)parse_u64(argv[4], "iterations"));
    } else if (!strcmp(op, "alloc")) {
        uint64_t size;
        uint32_t id;

        if (argc != 4) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        size = parse_u64(argv[3], "bytes");
        id = csd_alloc(fd, size);
        printf("%" PRIu32 "\n", id);
    } else if (!strcmp(op, "dealloc")) {
        if (argc != 4) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        csd_dealloc(fd, (uint32_t)parse_u64(argv[3], "id"));
    } else if (!strcmp(op, "admin-load-so")) {
        uint32_t runtime = 0;

        if (argc < 6 || argc > 7) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        if (argc == 7) {
            runtime = (uint32_t)parse_u64(argv[6], "runtime-ns");
        }
        csd_admin_load_program(fd, (uint16_t)parse_u64(argv[3], "pind"),
                               CSD_CSF_TYPE_SHARED_LIB, argv[4], argv[5],
                               0, runtime);
    } else if (!strcmp(op, "admin-load-ubpf")) {
        uint32_t runtime = 0;
        uint8_t jit = 0;

        if (argc < 6 || argc > 8) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        if (argc >= 7) {
            jit = (uint8_t)parse_u64(argv[6], "jit");
        }
        if (argc == 8) {
            runtime = (uint32_t)parse_u64(argv[7], "runtime-ns");
        }
        csd_admin_load_program(fd, (uint16_t)parse_u64(argv[3], "pind"),
                               CSD_CSF_TYPE_EBPF, argv[4], argv[5],
                               jit ? 1 : 0, runtime);
    } else if (!strcmp(op, "admin-load-phantom")) {
        if (argc != 5) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        csd_admin_load_program(fd, (uint16_t)parse_u64(argv[3], "pind"),
                               CSD_CSF_TYPE_PHANTOM, NULL, NULL, 0,
                               (uint32_t)parse_u64(argv[4], "runtime-ns"));
    } else if (!strcmp(op, "admin-activate")) {
        if (argc != 4) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        csd_admin_activation(fd, (uint16_t)parse_u64(argv[3], "pind"), 1);
    } else if (!strcmp(op, "admin-deactivate")) {
        if (argc != 4) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        csd_admin_activation(fd, (uint16_t)parse_u64(argv[3], "pind"), 0);
    } else if (!strcmp(op, "admin-unload")) {
        if (argc != 4) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        csd_admin_unload_program(fd, (uint16_t)parse_u64(argv[3], "pind"));
    } else if (!strcmp(op, "exec")) {
        uint32_t runtime = 0;
        uint32_t group_id = 0;
        uint64_t cparam1 = 0;
        uint64_t cparam2 = 0;

        if (argc < 6 || argc > 10) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        if (argc >= 7) {
            runtime = (uint32_t)parse_u64(argv[6], "runtime-ns");
        }
        if (argc >= 8) {
            group_id = (uint32_t)parse_u64(argv[7], "group-id");
        }
        if (argc >= 9) {
            cparam1 = parse_u64(argv[8], "cparam1");
        }
        if (argc == 10) {
            cparam2 = parse_u64(argv[9], "cparam2");
        }
        csd_exec(fd, (uint32_t)parse_u64(argv[3], "pind"),
                 (uint32_t)parse_u64(argv[4], "in-afdm-id"),
                 (uint32_t)parse_u64(argv[5], "out-afdm-id"),
                 runtime, group_id, cparam1, cparam2);
    } else if (!strcmp(op, "create-group")) {
        uint32_t id;

        if (argc != 6) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        id = csd_create_group(fd, (int8_t)parse_u64(argv[3], "prio"),
                              (uint32_t)parse_u64(argv[4], "bandwidth-kb"),
                              (uint32_t)parse_u64(argv[5], "deadline-us"));
        printf("%" PRIu32 "\n", id);
    } else if (!strcmp(op, "set-qos")) {
        if (argc != 7) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        csd_set_qos(fd, (uint32_t)parse_u64(argv[3], "group-id"),
                    (int8_t)parse_u64(argv[4], "prio"),
                    (uint32_t)parse_u64(argv[5], "bandwidth-kb"),
                    (uint32_t)parse_u64(argv[6], "deadline-us"));
    } else if (!strcmp(op, "delete-group")) {
        if (argc != 4) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        csd_delete_group(fd, (uint32_t)parse_u64(argv[3], "group-id"));
    } else if (!strcmp(op, "write")) {
        if (argc != 6) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        csd_write(fd, (uint32_t)parse_u64(argv[3], "id"),
                  parse_u64(argv[4], "offset"), argv[5],
                  (uint32_t)strlen(argv[5]) + 1);
    } else if (!strcmp(op, "read")) {
        uint64_t size64;
        uint32_t size;
        void *buf = NULL;

        if (argc != 6) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        size64 = parse_u64(argv[5], "bytes");
        if (size64 > UINT32_MAX) {
            fprintf(stderr, "read size exceeds UINT32_MAX\n");
            return EXIT_FAILURE;
        }
        size = (uint32_t)size64;
        if (posix_memalign(&buf, 4096, (size + 4095) & ~4095U)) {
            perror("posix_memalign");
            return EXIT_FAILURE;
        }
        memset(buf, 0, (size + 4095) & ~4095U);
        csd_read(fd, (uint32_t)parse_u64(argv[3], "id"),
                 parse_u64(argv[4], "offset"), buf, size);
        dump_hex(buf, size);
        free(buf);
    } else if (!strcmp(op, "nvm-to-afdm")) {
        if (argc != 7) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        csd_nvm_to_afdm(fd, (uint32_t)parse_u64(argv[3], "id"),
                        parse_u64(argv[4], "offset"),
                        parse_u64(argv[5], "slba"),
                        (uint16_t)parse_u64(argv[6], "nlb"));
    } else {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    close(fd);
    return EXIT_SUCCESS;
}
