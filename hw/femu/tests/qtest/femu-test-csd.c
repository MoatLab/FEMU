/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QTest testcases for the FEMU SSD emulator: the computational storage
 * tests (femu_mode=4).
 *
 * femu-test.c registers every test. This file holds the test bodies
 * and the helpers that only they use.
 */

#include "qemu/osdep.h"
#include "femu-test.h"

#define FEMU_CSD_ALLOC_FDM   0xb0
#define FEMU_CSD_DEALLOC     0xc0
#define FEMU_CSD_NVM_TO_AFDM 0xd0
#define FEMU_CSD_EXEC        0xe1
#define FEMU_CSD_READ_AFDM   0xf2
#define FEMU_CSD_WRITE_AFDM  0xf5
#define FEMU_CSD_NEW_GROUP   0xf6
#define FEMU_CSD_SET_QOS     0xf7
#define FEMU_CSD_DEL_GROUP   0xf8
#define FEMU_CSD_FUZZ_IDS    8

typedef struct FemuCsdFuzzMem {
    uint32_t id;
    uint32_t size;
} FemuCsdFuzzMem;

/*
 * Computational storage commands from a fixed seed. The run keeps a small
 * pool of device memory it has allocated, so reads, writes, copies from the
 * namespace and frees mostly name live allocations with in-range offsets;
 * one command in four has a field replaced: an ID that was freed or never
 * given, an offset or size at or past the end, one that wraps, a data
 * pointer from the random lists, or another opcode. Every command must
 * complete, and a fresh allocation must still round-trip data.
 */
void femu_test_csd_fuzz(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    const uint8_t ops[] = {
        FEMU_CSD_ALLOC_FDM, FEMU_CSD_DEALLOC, FEMU_CSD_NVM_TO_AFDM,
        FEMU_CSD_EXEC, FEMU_CSD_READ_AFDM, FEMU_CSD_WRITE_AFDM,
        FEMU_CSD_NEW_GROUP, FEMU_CSD_SET_QOS, FEMU_CSD_DEL_GROUP,
        NVME_CMD_WRITE, NVME_CMD_READ,
    };
    FemuCsdFuzzMem mem[FEMU_CSD_FUZZ_IDS];
    uint32_t freed[FEMU_CSD_FUZZ_IDS] = { 0 };
    int nmem = 0;
    bool succeeded[256] = { false };
    uint64_t raw = 0;
    uint64_t region = femu_alloc_64k(alloc, &raw);
    uint64_t lists = region + 4096ULL * (FEMU_FUZZ_PAGES - FEMU_FUZZ_LISTS);
    GRand *rng = g_rand_new_with_seed(femu_fuzz_seed(0x43534446));
    uint8_t wbuf[4096];
    uint8_t rbuf[4096];
    NvmeRwCmd rw;
    NvmeCmd *cmd = (NvmeCmd *)&rw;
    int distinct = 0;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);

    for (i = 0; i < femu_fuzz_rounds(FEMU_IO_FUZZ_ROUNDS); i++) {
        int pick = nmem ? g_rand_int_range(rng, 0, nmem) : -1;
        uint32_t id = pick >= 0 ? mem[pick].id : 0;
        uint32_t msize = pick >= 0 ? mem[pick].size : 0;
        uint32_t len = 0;
        uint64_t off = 0;
        uint16_t st, cid;
        uint32_t result = 0;

        femu_fuzz_lists(&c, rng, region);
        memset(&rw, 0, sizeof(rw));
        rw.opcode = ops[g_rand_int_range(rng, 0, G_N_ELEMENTS(ops))];
        rw.nsid = cpu_to_le32(1);

        switch (rw.opcode) {
        case FEMU_CSD_ALLOC_FDM:
            len = 512 * g_rand_int_range(rng, 1, 129);
            cmd->cdw10 = cpu_to_le32(len);
            break;
        case FEMU_CSD_DEALLOC:
            cmd->cdw10 = cpu_to_le32(id);
            break;
        case FEMU_CSD_READ_AFDM:
        case FEMU_CSD_WRITE_AFDM:
            if (msize) {
                len = g_rand_int_range(rng, 1,
                                       MIN(msize, 16 * 4096) + 1);
                off = g_rand_int_range(rng, 0, msize - len + 1);
            }
            cmd->cdw10 = cpu_to_le32((uint32_t)off);
            cmd->cdw12 = cpu_to_le32(len);
            cmd->cdw14 = cpu_to_le32(id);
            if (len) {
                femu_fuzz_valid_dptr(&c, rng, region, &rw, len, true);
            }
            break;
        case FEMU_CSD_NVM_TO_AFDM:
            len = g_rand_int_range(rng, 1, 9);
            rw.slba = cpu_to_le64(g_rand_int_range(rng, 0, 1024));
            cmd->cdw12 = cpu_to_le32(len - 1);
            cmd->cdw13 = cpu_to_le32(id);
            if (msize >= len * 512) {
                off = g_rand_int_range(rng, 0, msize - len * 512 + 1);
            }
            cmd->cdw14 = cpu_to_le32((uint32_t)off);
            break;
        case NVME_CMD_WRITE:
        case NVME_CMD_READ:
            len = g_rand_int_range(rng, 1, 9);
            rw.slba = cpu_to_le64(g_rand_int_range(rng, 0, 1024));
            rw.nlb = cpu_to_le16(len - 1);
            femu_fuzz_valid_dptr(&c, rng, region, &rw, len * 512, true);
            break;
        default:
            /* groups, QoS and execute: small values in every field */
            cmd->cdw10 = cpu_to_le32(g_rand_int_range(rng, 0, 16));
            cmd->cdw11 = cpu_to_le32(g_rand_int_range(rng, 0, 1024));
            cmd->cdw12 = cpu_to_le32(g_rand_int_range(rng, 0, 1024));
            break;
        }

        if (g_rand_int_range(rng, 0, 4) == 0) {
            switch (g_rand_int_range(rng, 0, 7)) {
            case 0:
                rw.opcode = g_rand_int_range(rng, 0, 0x100);
                break;
            case 1:
                /* an ID freed earlier, or one never given */
                cmd->cdw10 = cpu_to_le32(g_rand_boolean(rng) ?
                        freed[g_rand_int_range(rng, 0,
                                               FEMU_CSD_FUZZ_IDS)] :
                        g_rand_int(rng));
                cmd->cdw13 = cmd->cdw10;
                cmd->cdw14 = cmd->cdw10;
                break;
            case 2:
                /* an offset at the end, past it, or one that wraps */
                if (g_rand_boolean(rng)) {
                    cmd->cdw10 = cpu_to_le32(msize);
                    cmd->cdw14 = cpu_to_le32(msize);
                } else {
                    cmd->cdw10 = cpu_to_le32(g_rand_int(rng));
                    cmd->cdw11 = cpu_to_le32(0xffffffff);
                    cmd->cdw15 = cpu_to_le32(0xffffffff);
                }
                break;
            case 3:
                /* a size of zero, past the end, or near 2^64 */
                cmd->cdw12 = cpu_to_le32(g_rand_boolean(rng) ? 0 :
                                         g_rand_int(rng));
                cmd->cdw13 = cpu_to_le32(g_rand_boolean(rng) ? 0 :
                                         0xffffffff);
                break;
            case 4:
                rw.flags = 0;
                rw.dptr.prp1 = cpu_to_le64(femu_fuzz_ptr(rng, region));
                rw.dptr.prp2 = cpu_to_le64(g_rand_boolean(rng) ?
                        lists + 8 * g_rand_int_range(rng, 0,
                                            FEMU_FUZZ_PRP_LISTS * 512) :
                        femu_fuzz_ptr(rng, region));
                break;
            case 5:
                rw.flags = g_rand_int_range(rng, 1, 4) << 6;
                qtest_memread(qts, femu_fuzz_sgl_slot(rng, region),
                              &rw.dptr.sgl, sizeof(rw.dptr.sgl));
                break;
            default:
                cmd->cdw11 = cpu_to_le32(g_rand_int(rng));
                cmd->cdw12 = cpu_to_le32(g_rand_int(rng));
                cmd->cdw13 = cpu_to_le32(g_rand_int(rng));
                break;
            }
        }

        femu_submit(&c, &c.io, cmd);
        st = FEMU_SC(femu_complete(&c, &c.io, &cid, &result));
        if (st == NVME_SUCCESS && !succeeded[rw.opcode]) {
            succeeded[rw.opcode] = true;
            distinct++;
        }

        /* keep the pool in step with what the device holds */
        if (st == NVME_SUCCESS && rw.opcode == FEMU_CSD_ALLOC_FDM) {
            if (nmem == FEMU_CSD_FUZZ_IDS) {
                NvmeCmd free_cmd = { 0 };

                free_cmd.opcode = FEMU_CSD_DEALLOC;
                free_cmd.nsid = cpu_to_le32(1);
                free_cmd.cdw10 = cpu_to_le32(result);
                g_assert_cmpint(femu_io(&c, &free_cmd), ==, NVME_SUCCESS);
                freed[i % FEMU_CSD_FUZZ_IDS] = result;
            } else {
                mem[nmem].id = result;
                mem[nmem].size = le32_to_cpu(cmd->cdw10);
                nmem++;
            }
        } else if (st == NVME_SUCCESS && rw.opcode == FEMU_CSD_DEALLOC) {
            int k;

            for (k = 0; k < nmem; k++) {
                if (mem[k].id == le32_to_cpu(cmd->cdw10)) {
                    freed[i % FEMU_CSD_FUZZ_IDS] = mem[k].id;
                    mem[k] = mem[--nmem];
                    break;
                }
            }
        }
    }

    g_assert_cmpint(distinct, >=, 5);

    /* a fresh allocation takes data in and gives it back */
    memset(&rw, 0, sizeof(rw));
    rw.opcode = FEMU_CSD_ALLOC_FDM;
    rw.nsid = cpu_to_le32(1);
    cmd->cdw10 = cpu_to_le32(sizeof(wbuf));
    femu_submit(&c, &c.io, cmd);
    {
        uint16_t cid;
        uint32_t id = 0;

        g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, &cid, &id)), ==,
                        NVME_SUCCESS);
        for (i = 0; i < sizeof(wbuf); i++) {
            wbuf[i] = (uint8_t)(0x6f + i * 9);
        }
        qtest_memwrite(qts, region, wbuf, sizeof(wbuf));
        memset(&rw, 0, sizeof(rw));
        rw.opcode = FEMU_CSD_WRITE_AFDM;
        rw.nsid = cpu_to_le32(1);
        rw.dptr.prp1 = cpu_to_le64(region);
        cmd->cdw12 = cpu_to_le32(sizeof(wbuf));
        cmd->cdw14 = cpu_to_le32(id);
        g_assert_cmpint(femu_io(&c, cmd), ==, NVME_SUCCESS);
        qtest_memset(qts, region, 0, sizeof(rbuf));
        rw.opcode = FEMU_CSD_READ_AFDM;
        g_assert_cmpint(femu_io(&c, cmd), ==, NVME_SUCCESS);
        qtest_memread(qts, region, rbuf, sizeof(rbuf));
        g_assert_cmpint(memcmp(wbuf, rbuf, sizeof(rbuf)), ==, 0);
    }

    femu_disable(&c);
    g_rand_free(rng);
    guest_free(alloc, raw);
}

#define FEMU_CSD_COMPUTE_LOAD   0xc5
#define FEMU_CSD_TYPE_SHARED_LIB 0x03

static uint16_t femu_csd_load(FemuCtrlState *c, uint64_t buf,
                              const char *name, const char *symbol)
{
    QTestState *qts = c->pdev->bus->qts;
    size_t name_len = strlen(name) + 1;
    size_t size = name_len + strlen(symbol) + 1;
    NvmeCmd cmd;

    qtest_memset(qts, buf, 0, 4096);
    qtest_memwrite(qts, buf, name, name_len);
    qtest_memwrite(qts, buf + name_len, symbol, strlen(symbol) + 1);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_CSD_COMPUTE_LOAD;
    cmd.dptr.prp1 = cpu_to_le64(buf);
    /* program index 1, shared library, whole program in one piece */
    cmd.cdw10 = cpu_to_le32(1 | (FEMU_CSD_TYPE_SHARED_LIB << 16));
    cmd.cdw11 = cpu_to_le32(size);
    cmd.cdw14 = cpu_to_le32(size);

    return femu_admin(c, &cmd);
}

/*
 * A program name from the guest is resolved inside csd_program_dir. Each way
 * the lookup can end, a missing file, a link out of the directory, and a file
 * that is there but is no library, has to be refused and leave the controller
 * working.
 */
void femu_test_csd_program_dir(void *obj, void *data,
                               QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    g_autofree char *link = g_build_filename(femu_csd_dir, "escape", NULL);
    g_autofree char *file = g_build_filename(femu_csd_dir, "notalib", NULL);
    uint64_t buf;

    g_assert_cmpint(g_mkdir_with_parents(femu_csd_dir, 0700), ==, 0);
    g_assert_true(g_file_set_contents(file, "not an ELF", -1, NULL));
    g_assert_cmpint(symlink("/etc/hostname", link), ==, 0);

    femu_enable(&c, &femu->dev, alloc);
    buf = guest_alloc(alloc, 4096);

    g_assert_cmpint(femu_csd_load(&c, buf, "missing", "run"), ==,
                    NVME_INVALID_FIELD | NVME_DNR);
    g_assert_cmpint(femu_csd_load(&c, buf, "escape", "run"), ==,
                    NVME_INVALID_FIELD | NVME_DNR);
    g_assert_cmpint(femu_csd_load(&c, buf, "notalib", "run"), ==,
                    NVME_INVALID_FIELD | NVME_DNR);

    femu_create_io_queues(&c);
    femu_round_trip(&c, 3);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);

    unlink(link);
    unlink(file);
    rmdir(femu_csd_dir);
}

#define FEMU_CSD_ACTIVATE       0xc8
#define FEMU_CSD_SLOW_MS        1000

/*
 * A program that sleeps for cparam1 milliseconds and returns 7. The argument
 * layout is struct femu_csd_args from hw/femu/tests/csd/femu-csd-kernel.h.
 */
static const char femu_csd_slow_src[] =
    "#include <time.h>\n"
    "struct args { int numr; void **a; long long *l; long long p1, p2;\n"
    "              void *d; long long dl; } __attribute__((packed));\n"
    "long long run(struct args *a)\n"
    "{\n"
    "    struct timespec t = { a->p1 / 1000, (a->p1 % 1000) * 1000000L };\n"
    "    nanosleep(&t, 0);\n"
    "    return 7;\n"
    "}\n";

/* build the program with the host compiler; false when there is none */
static bool femu_csd_build_slow(void)
{
    g_autofree char *src = g_build_filename(femu_csd_slow_dir, "slow.c",
                                            NULL);
    g_autofree char *so = g_build_filename(femu_csd_slow_dir, "slow.so",
                                           NULL);
    const char *argv[] = { "cc", "-shared", "-fPIC", "-o", so, src, NULL };
    int wait_status = -1;

    g_assert_cmpint(g_mkdir_with_parents(femu_csd_slow_dir, 0700), ==, 0);
    g_assert_true(g_file_set_contents(src, femu_csd_slow_src, -1, NULL));
    if (!g_spawn_sync(NULL, (char **)argv, NULL, G_SPAWN_SEARCH_PATH |
                      G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL,
                      NULL, NULL, NULL, NULL, &wait_status, NULL)) {
        return false;
    }
    return WIFEXITED(wait_status) && WEXITSTATUS(wait_status) == 0;
}

static void femu_csd_remove_slow(void)
{
    g_autofree char *src = g_build_filename(femu_csd_slow_dir, "slow.c",
                                            NULL);
    g_autofree char *so = g_build_filename(femu_csd_slow_dir, "slow.so",
                                           NULL);

    unlink(so);
    unlink(src);
    rmdir(femu_csd_slow_dir);
}

static uint16_t femu_csd_activate(FemuCtrlState *c, uint16_t pind)
{
    NvmeCmd cmd = { 0 };

    cmd.opcode = FEMU_CSD_ACTIVATE;
    cmd.cdw10 = cpu_to_le32(pind | (1 << 16));
    return femu_admin(c, &cmd);
}

/* load name:symbol at pind; with more set, as a later piece of no bytes */
static uint16_t femu_csd_load_at(FemuCtrlState *c, uint64_t buf, uint16_t pind,
                                 const char *name, const char *symbol,
                                 bool more)
{
    QTestState *qts = c->pdev->bus->qts;
    size_t name_len = strlen(name) + 1;
    size_t size = name_len + strlen(symbol) + 1;
    NvmeCmd cmd;

    qtest_memset(qts, buf, 0, 4096);
    qtest_memwrite(qts, buf, name, name_len);
    qtest_memwrite(qts, buf + name_len, symbol, strlen(symbol) + 1);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_CSD_COMPUTE_LOAD;
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(pind | (FEMU_CSD_TYPE_SHARED_LIB << 16));
    cmd.cdw11 = cpu_to_le32(size);
    cmd.cdw14 = cpu_to_le32(more ? 0 : size);
    cmd.cdw15 = cpu_to_le32(more ? 1 : 0);

    return femu_admin(c, &cmd);
}

/* queue Execute of program pind on AFDM id, sleeping ms, without waiting */
static void femu_csd_submit_exec_at(FemuCtrlState *c, FemuQueue *q,
                                    uint64_t ranges, uint16_t pind,
                                    uint32_t id, uint32_t ms)
{
    uint32_t mr[8] = { 0 };
    uint32_t dw[16] = { 0 };

    /* one memory range: nsid 0 (device memory), whole AFDM, sb = its id */
    mr[2] = cpu_to_le32(id);
    qtest_memwrite(c->pdev->bus->qts, ranges, mr, sizeof(mr));

    dw[0] = FEMU_CSD_EXEC;
    dw[1] = cpu_to_le32(1);
    dw[2] = cpu_to_le32(pind);          /* rsid 0 */
    dw[3] = cpu_to_le32(1);             /* numr */
    dw[4] = cpu_to_le32(sizeof(mr));    /* dlen */
    dw[6] = cpu_to_le32((uint32_t)ranges);
    dw[7] = cpu_to_le32(ranges >> 32);
    dw[10] = cpu_to_le32(ms);           /* cparam1 */
    femu_submit(c, q, (NvmeCmd *)dw);
}

static void femu_csd_submit_exec(FemuCtrlState *c, FemuQueue *q,
                                 uint64_t ranges, uint32_t id, uint32_t ms)
{
    femu_csd_submit_exec_at(c, q, ranges, 1, id, ms);
}

static bool femu_csd_cq_ready(FemuCtrlState *c, FemuQueue *q)
{
    NvmeCqe cqe;

    qtest_memread(c->pdev->bus->qts, q->cq_addr + q->cq_head * sizeof(cqe),
                  &cqe, sizeof(cqe));
    return (le16_to_cpu(cqe.status) & 1) == q->phase;
}

static void femu_csd_expect_exec(FemuCtrlState *c, FemuQueue *q)
{
    uint32_t result = 0;

    g_assert_cmpint(FEMU_SC(femu_complete(c, q, NULL, &result)), ==,
                    NVME_SUCCESS);
    g_assert_cmpuint(result, ==, 7);
}

/* how often @needle occurs in what QEMU has written to stderr so far */
static int femu_csd_warn_count(const char *needle)
{
    g_autofree char *text = NULL;
    const char *p;
    int count = 0;

    g_assert_true(g_file_get_contents(femu_csd_warn_log, &text, NULL, NULL));
    for (p = strstr(text, needle); p; p = strstr(p + 1, needle)) {
        count++;
    }
    return count;
}

/*
 * A completion carries the program's result, so it cannot go out before the
 * host has run the program. A runtime shorter than that is not reached, and
 * QEMU says so once.
 */
void femu_test_csd_runtime_floor(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    static const char needle[] = "took longer on the host";
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint32_t runtime_ns[] = { 1000 * 1000 * 1000, 1000, 1000 };
    uint32_t mr[8] = { 0 };
    uint32_t dw[16] = { 0 };
    NvmeCmd cmd = { 0 };
    uint64_t buf, ranges;
    uint32_t id = 0;
    int i;

    if (!femu_csd_build_slow()) {
        femu_csd_remove_slow();
        g_test_skip("no host C compiler to build the test program");
        return;
    }

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    ranges = guest_alloc(alloc, 4096);
    g_assert_cmpint(femu_csd_load(&c, buf, "slow.so", "run"), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(femu_csd_activate(&c, 1), ==, NVME_SUCCESS);
    cmd.opcode = FEMU_CSD_ALLOC_FDM;
    cmd.nsid = cpu_to_le32(1);
    cmd.cdw10 = cpu_to_le32(4096);
    femu_submit(&c, &c.io, &cmd);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, NULL, &id)), ==,
                    NVME_SUCCESS);
    mr[2] = cpu_to_le32(id);
    qtest_memwrite(c.pdev->bus->qts, ranges, mr, sizeof(mr));

    /* 5 ms on the host: 1 s is reachable, 1 us twice is not */
    for (i = 0; i < ARRAY_SIZE(runtime_ns); i++) {
        dw[0] = FEMU_CSD_EXEC;
        dw[1] = cpu_to_le32(1);
        dw[2] = cpu_to_le32(1);
        dw[3] = cpu_to_le32(1);
        dw[4] = cpu_to_le32(sizeof(mr));
        dw[6] = cpu_to_le32((uint32_t)ranges);
        dw[7] = cpu_to_le32(ranges >> 32);
        dw[10] = cpu_to_le32(5);
        dw[15] = cpu_to_le32(runtime_ns[i]);
        femu_submit(&c, &c.io, (NvmeCmd *)dw);
        femu_csd_expect_exec(&c, &c.io);
        g_assert_cmpint(femu_csd_warn_count(needle), ==, i ? 1 : 0);
    }

    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    femu_csd_remove_slow();
    unlink(femu_csd_warn_log);
}

/* the counts of the csd_pause freeze service, from x-csd-pause-stats */
static void femu_csd_pause_stats(QTestState *qts, uint64_t *freezes,
                                 uint64_t *thaws, uint64_t *lost,
                                 uint64_t *users)
{
    QDict *rsp = qtest_qmp(qts, "{'execute':'qom-get','arguments':{"
                           "'path':'/machine/peripheral/csd-pause',"
                           "'property':'x-csd-pause-stats'}}");
    uint64_t skipped, expired;

    g_assert_true(qdict_haskey(rsp, "return"));
    g_assert_cmpint(sscanf(qdict_get_str(rsp, "return"),
                           "freezes=%" SCNu64 " thaws=%" SCNu64
                           " skipped=%" SCNu64 " lost=%" SCNu64
                           " expired=%" SCNu64 " users=%" SCNu64,
                           freezes, thaws, &skipped, lost, &expired, users),
                    ==, 6);
    qobject_unref(rsp);
}

/*
 * With csd_pause the device times a program on a clock that stops with the
 * guest. Under qtest that clock is the test clock, so the host run of the
 * program, here 20 ms, does not count. The completion is due exactly when
 * the test clock reaches the declared 300 ms. Without csd_pause (the
 * control) the device runs on the host clock, and the completion is there
 * once the host has run the program for 300 ms.
 */
#define FEMU_CSD_PAUSE_RUN_MS   300

void femu_test_csd_pause(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    bool pause = data != NULL;
    FemuCtrlState c = { 0 };
    uint64_t freezes, thaws, lost, users;
    int waited;
    uint32_t mr[8] = { 0 };
    uint32_t dw[16] = { 0 };
    NvmeCmd cmd = { 0 };
    uint64_t buf, ranges;
    uint32_t id = 0;

    if (!femu_csd_build_slow()) {
        femu_csd_remove_slow();
        g_test_skip("no host C compiler to build the test program");
        return;
    }

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    ranges = guest_alloc(alloc, 4096);
    g_assert_cmpint(femu_csd_load(&c, buf, "slow.so", "run"), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(femu_csd_activate(&c, 1), ==, NVME_SUCCESS);
    cmd.opcode = FEMU_CSD_ALLOC_FDM;
    cmd.nsid = cpu_to_le32(1);
    cmd.cdw10 = cpu_to_le32(4096);
    femu_submit(&c, &c.io, &cmd);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &c.io, NULL, &id)), ==,
                    NVME_SUCCESS);
    mr[2] = cpu_to_le32(id);
    qtest_memwrite(qts, ranges, mr, sizeof(mr));

    dw[0] = FEMU_CSD_EXEC;
    dw[1] = cpu_to_le32(1);
    dw[2] = cpu_to_le32(1);
    dw[3] = cpu_to_le32(1);
    dw[4] = cpu_to_le32(sizeof(mr));
    dw[6] = cpu_to_le32((uint32_t)ranges);
    dw[7] = cpu_to_le32(ranges >> 32);
    dw[10] = cpu_to_le32(20);
    dw[15] = cpu_to_le32(FEMU_CSD_PAUSE_RUN_MS * 1000 * 1000);
    femu_submit(&c, &c.io, (NvmeCmd *)dw);

    if (!pause) {
        /* the host clock alone brings the completion */
        femu_csd_expect_exec(&c, &c.io);
        goto out;
    }

    /*
     * Wait until the run is over: one stop and one restart for it, and
     * nobody left waiting. The command arrived before that, on a test clock
     * that has not moved since.
     */
    for (waited = 0;; waited++) {
        femu_csd_pause_stats(qts, &freezes, &thaws, &lost, &users);
        if (thaws) {
            break;
        }
        g_assert_cmpint(waited, <, FEMU_POLL_LIMIT_MS);
        g_usleep(1000);
    }
    g_assert_cmpuint(freezes, ==, 1);
    g_assert_cmpuint(thaws, ==, 1);
    g_assert_cmpuint(lost, ==, 0);
    g_assert_cmpuint(users, ==, 0);

    /* more than the declared run time on the host clock: not due */
    g_usleep(2 * FEMU_CSD_PAUSE_RUN_MS * 1000);
    g_assert_false(femu_csd_cq_ready(&c, &c.io));
    /* one ms short of the run time on the test clock: still not due */
    qtest_clock_step(qts, (FEMU_CSD_PAUSE_RUN_MS - 1) * SCALE_MS);
    g_usleep(100 * 1000);
    g_assert_false(femu_csd_cq_ready(&c, &c.io));
    qtest_clock_step(qts, SCALE_MS);
    femu_csd_expect_exec(&c, &c.io);

out:

    femu_queue_free(&c, &c.io);
    femu_disable(&c);
    femu_csd_remove_slow();
}

/* the CEMU admin opcodes of csd_legacy_opcodes=on */
#define FEMU_CSD_OLD_MRS        0x21
#define FEMU_CSD_OLD_LOAD       0x22
#define FEMU_CSD_OLD_ACTIVATE   0x23
#define FEMU_CSD_OLD_LOAD_DATA  0x25
#define FEMU_CSD_MRS            0xc9
#define FEMU_CSD_LOAD_DATA      0xcd

typedef struct FemuCsdLayout {
    uint8_t mrs, load, activate, load_data;
} FemuCsdLayout;

static const FemuCsdLayout femu_csd_layout_new = {
    FEMU_CSD_MRS, FEMU_CSD_COMPUTE_LOAD, FEMU_CSD_ACTIVATE, FEMU_CSD_LOAD_DATA,
};

static const FemuCsdLayout femu_csd_layout_old = {
    FEMU_CSD_OLD_MRS, FEMU_CSD_OLD_LOAD, FEMU_CSD_OLD_ACTIVATE,
    FEMU_CSD_OLD_LOAD_DATA,
};

/*
 * The data each vendor specific CEMU command moves: 1 host to controller,
 * 2 controller to host, 0 none. A command that moves no data may carry any
 * direction bits (Base 2.3 Figure 91); -1 is a command this table misses.
 */
static int femu_csd_data_dir(uint8_t opc)
{
    switch (opc) {
    case FEMU_CSD_ALLOC_FDM:
    case FEMU_CSD_DEALLOC:
    case FEMU_CSD_NVM_TO_AFDM:
    case FEMU_CSD_NEW_GROUP:
    case FEMU_CSD_SET_QOS:
    case FEMU_CSD_DEL_GROUP:
    case FEMU_CSD_ACTIVATE:
        return 0;
    case FEMU_CSD_EXEC:
    case FEMU_CSD_WRITE_AFDM:
    case FEMU_CSD_COMPUTE_LOAD:
    case FEMU_CSD_MRS:
    case FEMU_CSD_LOAD_DATA:
        return 1;
    case FEMU_CSD_READ_AFDM:
        return 2;
    default:
        return -1;
    }
}

static uint32_t femu_csd_io_result(FemuCtrlState *c, NvmeCmd *cmd,
                                   uint16_t want)
{
    uint32_t result = 0;

    femu_submit(c, &c->io, cmd);
    g_assert_cmphex(FEMU_SC(femu_complete(c, &c->io, NULL, &result)), ==,
                    want);
    return result;
}

/*
 * One admin opcode layout answers, and FEMU refuses the other with Invalid
 * Command Opcode. Base 2.3 prohibits 21h, 22h and 25h on a PCIe I/O
 * controller and reserves 23h. FEMU has no Lockdown, so it also refuses
 * 24h. Log 05h lists only the layout in use. In the default layout
 * every vendor specific command that moves data declares its direction.
 */
void femu_test_csd_opcodes(void *obj, void *data,
                           QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    bool legacy = data != NULL;
    const FemuCsdLayout *on = legacy ? &femu_csd_layout_old :
                                       &femu_csd_layout_new;
    const FemuCsdLayout *off = legacy ? &femu_csd_layout_new :
                                        &femu_csd_layout_old;
    const uint8_t on_ops[] = { on->mrs, on->load, on->activate,
                               on->load_data };
    const uint8_t off_ops[] = { off->mrs, off->load, off->activate,
                                off->load_data, 0x24 };
    FemuCtrlState c = { 0 };
    uint32_t mr[8] = { 0 };
    uint32_t eff[1024];
    uint32_t dw[16];
    NvmeCmd cmd;
    uint32_t afdm, rsid, group;
    uint64_t buf;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, 4096);

    /* the other layout, and Lockdown (24h), which FEMU does not offer */
    for (i = 0; i < ARRAY_SIZE(off_ops); i++) {
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = off_ops[i];
        cmd.dptr.prp1 = cpu_to_le64(buf);
        cmd.cdw10 = cpu_to_le32(1);
        g_assert_cmphex(FEMU_SC(femu_admin(&c, &cmd)), ==,
                        NVME_INVALID_OPCODE);
    }

    /* a phantom program: load, activate, and run it on a range set */
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = on->load;
    cmd.cdw10 = cpu_to_le32(1);
    g_assert_cmphex(FEMU_SC(femu_admin(&c, &cmd)), ==, NVME_SUCCESS);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = on->activate;
    cmd.cdw10 = cpu_to_le32(1 | (1 << 16));
    g_assert_cmphex(FEMU_SC(femu_admin(&c, &cmd)), ==, NVME_SUCCESS);
    /*
     * Program 2 comes in two pieces of 4 bytes: Load, then Load Data. It
     * cannot be activated until the second piece is in.
     */
    qtest_memset(qts, buf, 0x3c, 8);
    for (i = 0; i < 2; i++) {
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = i ? on->load_data : on->load;
        cmd.dptr.prp1 = cpu_to_le64(buf + 4 * i);
        cmd.cdw10 = cpu_to_le32(2);             /* pind 2, phantom */
        cmd.cdw11 = cpu_to_le32(8);             /* psize */
        cmd.cdw14 = cpu_to_le32(4);             /* numb */
        cmd.cdw15 = cpu_to_le32(4 * i);         /* loff */
        g_assert_cmphex(FEMU_SC(femu_admin(&c, &cmd)), ==, NVME_SUCCESS);
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = on->activate;
        cmd.cdw10 = cpu_to_le32(2 | (1 << 16));
        g_assert_cmphex(FEMU_SC(femu_admin(&c, &cmd)), ==,
                        i ? NVME_SUCCESS : NVME_INVALID_FIELD);
    }

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_CSD_ALLOC_FDM;
    cmd.nsid = cpu_to_le32(1);
    cmd.cdw10 = cpu_to_le32(4096);
    afdm = femu_csd_io_result(&c, &cmd, NVME_SUCCESS);
    mr[2] = cpu_to_le32(afdm);
    qtest_memwrite(qts, buf, mr, sizeof(mr));
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = on->mrs;
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw11 = cpu_to_le32(1);                 /* numr */
    g_assert_cmphex(FEMU_SC(femu_admin_result(&c, &cmd, &rsid)), ==,
                    NVME_SUCCESS);
    g_assert_cmpuint(rsid, !=, 0);

    for (i = 1; i <= 2; i++) {
        memset(dw, 0, sizeof(dw));
        dw[0] = FEMU_CSD_EXEC;
        dw[1] = cpu_to_le32(1);
        dw[2] = cpu_to_le32(i | (rsid << 16));  /* program i on the set */
        femu_csd_io_result(&c, (NvmeCmd *)dw, NVME_SUCCESS);
    }

    /* the group commands */
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_CSD_NEW_GROUP;
    cmd.nsid = cpu_to_le32(1);
    group = femu_csd_io_result(&c, &cmd, NVME_SUCCESS);
    g_assert_cmpuint(group, !=, 0);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_CSD_SET_QOS;
    cmd.nsid = cpu_to_le32(1);
    cmd.cdw13 = cpu_to_le32(group);
    femu_csd_io_result(&c, &cmd, NVME_SUCCESS);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_CSD_DEL_GROUP;
    cmd.nsid = cpu_to_le32(1);
    cmd.cdw10 = cpu_to_le32(group);
    femu_csd_io_result(&c, &cmd, NVME_SUCCESS);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = on->mrs;
    cmd.cdw10 = cpu_to_le32(1 | (rsid << 16));  /* sel 1: delete */
    g_assert_cmphex(FEMU_SC(femu_admin(&c, &cmd)), ==, NVME_SUCCESS);

    /* log 05h: this layout, not the other */
    g_assert_cmphex(femu_get_log(&c, FEMU_LOG_CMD_EFFECTS, buf, 4096, 0), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, buf, eff, sizeof(eff));
    for (i = 0; i < ARRAY_SIZE(on_ops); i++) {
        g_assert_cmphex(le32_to_cpu(eff[on_ops[i]]) & 1, ==, 1);
        g_assert_cmphex(le32_to_cpu(eff[off_ops[i]]) & 1, ==, 0);
    }
    g_assert_cmphex(le32_to_cpu(eff[0x24]) & 1, ==, 0);

    for (i = 0; !legacy && i < 256; i++) {
        bool adm = i >= 0xc0 && (le32_to_cpu(eff[i]) & 1);
        bool io = i >= 0x80 && (le32_to_cpu(eff[256 + i]) & 1);

        if (adm || io) {
            int dir = femu_csd_data_dir(i);

            g_assert_cmpint(dir, >=, 0);
            if (dir) {
                g_assert_cmpint(i & 3, ==, dir);
            }
        }
    }

    guest_free(alloc, buf);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);
}

/*
 * A CSD controller whose namespaces all run other modes has no CSD state.
 * Its CEMU admin commands are not supported, even with valid fields, and
 * log 05h does not list them.
 */
void femu_test_csd_no_namespace(void *obj, void *data,
                                QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    const uint8_t ops[] = { FEMU_CSD_MRS, FEMU_CSD_COMPUTE_LOAD,
                            FEMU_CSD_ACTIVATE, FEMU_CSD_LOAD_DATA };
    FemuCtrlState c = { 0 };
    uint32_t eff[256];
    NvmeCmd cmd;
    uint64_t buf;
    int i;

    femu_enable(&c, &femu->dev, alloc);
    buf = guest_alloc(alloc, 4096);
    for (i = 0; i < ARRAY_SIZE(ops); i++) {
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = ops[i];
        cmd.dptr.prp1 = cpu_to_le64(buf);
        /* activate pind 1, or delete range set 1: past every field check */
        cmd.cdw10 = cpu_to_le32(1 | (1 << 16));
        g_assert_cmphex(FEMU_SC(femu_admin(&c, &cmd)), ==,
                        NVME_INVALID_OPCODE);
    }
    g_assert_cmphex(femu_get_log(&c, FEMU_LOG_CMD_EFFECTS, buf, 1024, 0), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, buf, eff, sizeof(eff));
    for (i = 0; i < ARRAY_SIZE(ops); i++) {
        g_assert_cmphex(le32_to_cpu(eff[ops[i]]), ==, 0);
    }
    guest_free(alloc, buf);
    femu_disable(&c);
}

void femu_test_csd_exec_concurrency(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    FemuQueue qa, qb;
    NvmeCmd cmd = { 0 };
    uint64_t buf, ranges;
    uint32_t id = 0;
    int64_t start, read_us, admin_us, other_us;
    bool exec_done_first;

    if (!femu_csd_build_slow()) {
        femu_csd_remove_slow();
        g_test_skip("no host C compiler to build the test program");
        return;
    }

    femu_enable(&c, &femu->dev, alloc);
    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    ranges = guest_alloc(alloc, 4096);
    g_assert_cmpint(femu_csd_load(&c, buf, "slow.so", "run"), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(femu_csd_activate(&c, 1), ==, NVME_SUCCESS);
    /* a loaded program is immutable; a further piece of it is refused */
    g_assert_cmpint(femu_csd_load_at(&c, buf, 1, "slow.so", "run", true), ==,
                    NVME_INVALID_FIELD | NVME_DNR);
    g_assert_cmpint(femu_csd_load_at(&c, buf, 2, "slow.so", "run", false), ==,
                    NVME_SUCCESS);
    g_assert_cmpint(femu_csd_activate(&c, 2), ==, NVME_SUCCESS);
    femu_burst_queue(&c, &qa, 1);
    femu_burst_queue(&c, &qb, 2);

    cmd.opcode = FEMU_CSD_ALLOC_FDM;
    cmd.nsid = cpu_to_le32(1);
    cmd.cdw10 = cpu_to_le32(4096);
    femu_submit(&c, &qa, &cmd);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &qa, NULL, &id)), ==,
                    NVME_SUCCESS);

    /* a read on queue 2 while queue 1 runs the program */
    start = g_get_monotonic_time();
    femu_csd_submit_exec(&c, &qa, ranges, id, FEMU_CSD_SLOW_MS);
    g_usleep(50 * 1000);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_CMD_READ;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    femu_submit(&c, &qb, &cmd);
    g_assert_cmpint(FEMU_SC(femu_complete(&c, &qb, NULL, NULL)), ==,
                    NVME_SUCCESS);
    read_us = g_get_monotonic_time() - start;
    exec_done_first = femu_csd_cq_ready(&c, &qa);
    femu_csd_expect_exec(&c, &qa);

    /* an admin command while queue 1 runs the program */
    start = g_get_monotonic_time();
    femu_csd_submit_exec(&c, &qa, ranges, id, FEMU_CSD_SLOW_MS);
    g_usleep(50 * 1000);
    g_assert_cmpint(femu_csd_activate(&c, 1), ==, NVME_SUCCESS);
    admin_us = g_get_monotonic_time() - start;
    femu_csd_expect_exec(&c, &qa);

    /*
     * Two runs of program 1, then one of program 2, on two compute units:
     * the second run of 1 waits for the first, and must not keep program 2
     * from the other unit.
     */
    start = g_get_monotonic_time();
    femu_csd_submit_exec(&c, &qa, ranges, id, FEMU_CSD_SLOW_MS);
    femu_csd_submit_exec(&c, &qa, ranges, id, FEMU_CSD_SLOW_MS);
    g_usleep(50 * 1000);
    femu_csd_submit_exec_at(&c, &qb, ranges + 2048, 2, id,
                            FEMU_CSD_SLOW_MS / 10);
    femu_csd_expect_exec(&c, &qb);
    other_us = g_get_monotonic_time() - start;
    femu_csd_expect_exec(&c, &qa);
    femu_csd_expect_exec(&c, &qa);

    g_test_message("program %d ms: read on the other queue done at %" PRId64
                   " ms, admin command at %" PRId64 " ms, another program "
                   "at %" PRId64 " ms", FEMU_CSD_SLOW_MS, read_us / 1000,
                   admin_us / 1000, other_us / 1000);
    g_assert_false(exec_done_first);
    g_assert_cmpint(read_us, <, FEMU_CSD_SLOW_MS * 1000 / 2);
    g_assert_cmpint(admin_us, <, FEMU_CSD_SLOW_MS * 1000 / 2);
    g_assert_cmpint(other_us, <, FEMU_CSD_SLOW_MS * 1000 / 2);

    /*
     * Delete queue 1 under a running program and create it again at once.
     * The program's completion must not land in the new queue.
     */
    femu_csd_submit_exec(&c, &qa, ranges, id, FEMU_CSD_SLOW_MS / 4);
    g_usleep(50 * 1000);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_DELETE_SQ;
    cmd.cdw10 = cpu_to_le32(1);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);
    cmd.opcode = NVME_ADM_CMD_DELETE_CQ;
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);
    femu_queue_free(&c, &qa);
    femu_burst_queue(&c, &qa, 1);
    g_usleep(FEMU_CSD_SLOW_MS / 4 * 1000 + 200 * 1000);
    g_assert_false(femu_csd_cq_ready(&c, &qa));
    c.io = qa;
    femu_round_trip(&c, 5);
    qa = c.io;

    /* disable the controller under a running program */
    femu_csd_submit_exec(&c, &qb, ranges, id, FEMU_CSD_SLOW_MS / 4);
    g_usleep(50 * 1000);
    femu_disable(&c);
    g_usleep(FEMU_CSD_SLOW_MS / 4 * 1000 + 200 * 1000);
    femu_queue_free(&c, &qa);
    femu_queue_free(&c, &qb);

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    femu_round_trip(&c, 6);
    femu_queue_free(&c, &c.io);
    femu_disable(&c);

    guest_free(alloc, ranges);
    guest_free(alloc, buf);
    femu_csd_remove_slow();
}

/*
 * A format 2 range that names the command's own namespace is a format 0
 * range. The controller advertises format 2 wherever it accepts Copy, so a
 * CSD namespace has to take it too.
 */
void femu_test_copy_fmt2_own(void *obj, void *data,
                             QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t buf, list;
    uint8_t r[FEMU_DATA_SIZE];
    int i;

    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, FEMU_DATA_SIZE);
    list = guest_alloc(alloc, 4096);

    qtest_memset(qts, buf, 0, 512);
    qtest_writew(qts, buf + 4, 0x4);              /* enable format 2 */
    g_assert_cmpint(femu_hbs(&c, true, buf), ==, NVME_SUCCESS);
    qtest_memset(qts, buf, 0x3c, FEMU_DATA_SIZE);
    g_assert_cmphex(femu_oncs_cmd(&c, NVME_CMD_WRITE, 16, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(femu_copy_fmt2(&c, list, 64, 1, 16, 8), ==, NVME_SUCCESS);
    qtest_memset(qts, buf, 0, FEMU_DATA_SIZE);
    g_assert_cmphex(femu_oncs_cmd(&c, NVME_CMD_READ, 64, buf), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, buf, r, sizeof(r));
    for (i = 0; i < sizeof(r); i++) {
        g_assert_cmphex(r[i], ==, 0x3c);
    }
    /* another namespace is still refused: there is none here */
    g_assert_cmphex(femu_copy_fmt2(&c, list, 64, 2, 16, 8), ==,
                    NVME_INVALID_NSID);
    femu_disable(&c);
}

/*
 * Computational Programs (CP 1.2) and Subsystem Local Memory (SLM 1.2) on a
 * CSD controller. With csd_slm_size and csd_cp the controller has the block
 * namespace 1, the memory namespace 2 and the compute namespace 3, and every
 * command of both sets needs CC.CSS 110b.
 */
#define FEMU_CSI_SLM            0x03
#define FEMU_CSI_CP             0x04
#define FEMU_CPS_CC     ((6 << 16) | (4 << 20) | (FEMU_CC_CSS_CSI << 4) | 1)
#define FEMU_CPS_SLM            2
#define FEMU_CPS_CP             3
#define FEMU_CPS_SLM_SIZE       (4u << 20)
#define FEMU_CPS_COPY_MAX       (1u << 20)

/* status codes with their status code type, as FEMU_SC() returns them */
#define FEMU_SC_INVALID_OPCODE  0x001
#define FEMU_SC_INVALID_FIELD   0x002
#define FEMU_SC_DATA_XFER       0x004
#define FEMU_SC_INVALID_NS      0x00b
#define FEMU_SC_LBA_RANGE       0x080
#define FEMU_SC_INVALID_LOG     0x109
#define FEMU_SC_INVALID_FORMAT  0x10a
#define FEMU_SC_IOCS_NOT_SUPP   0x129
#define FEMU_SC_INVALID_IOCS    0x12c
#define FEMU_SC_SIZE_LIMIT      0x183
#define FEMU_SC_INCOMPATIBLE    0x185
#define FEMU_SC_NO_FAST_COPY    0x186
#define FEMU_SC_OVERLAP         0x187
#define FEMU_SC_INVALID_MEM_NS  0x18b
#define FEMU_SC_INVALID_MRS     0x18c
#define FEMU_SC_INVALID_RSID    0x18d
#define FEMU_SC_INVALID_PDATA   0x18e
#define FEMU_SC_INVALID_PIND    0x18f
#define FEMU_SC_INVALID_PTYPE   0x190
#define FEMU_SC_MAX_RANGES      0x191
#define FEMU_SC_MAX_MRS         0x192
#define FEMU_SC_MAX_ACTIVE      0x193
#define FEMU_SC_MAX_PBYTES      0x194
#define FEMU_SC_MRS_IN_USE      0x195
#define FEMU_SC_NO_PROGRAM      0x196
#define FEMU_SC_OVERLAP_RANGES  0x197
#define FEMU_SC_NOT_ACTIVE      0x198
#define FEMU_SC_PROGRAM_IN_USE  0x199
#define FEMU_SC_NOT_DOWNLOAD    0x19a
#define FEMU_SC_TOO_BIG         0x19b

#define FEMU_SLM_COPY           0x01
#define FEMU_SLM_READ           0x02
#define FEMU_SLM_FILL           0x04
#define FEMU_SLM_WRITE          0x05
#define FEMU_CP_LOAD            0x85
#define FEMU_CP_PAM             0x88
#define FEMU_CP_MRSM            0x89
#define FEMU_CP_SHLIB           0xc3

static void femu_cps_enable(FemuCtrlState *c, QFemu *femu,
                            QGuestAllocator *alloc)
{
    c->pdev = &femu->dev;
    c->alloc = alloc;
    femu_queue_init(c, &c->admin, 0);
    femu_enable_cc(c, &femu->dev, alloc, FEMU_CPS_CC);
    femu_create_io_queues(c);
}

static void femu_cps_disable(FemuCtrlState *c)
{
    femu_queue_free(c, &c->io);
    femu_disable(c);
}

/* Memory Read, Fill or Write of len bytes at sb, through one page at buf */
static uint16_t femu_cps_mem(FemuCtrlState *c, uint32_t nsid, uint8_t opc,
                             uint64_t sb, uint32_t len, uint64_t buf)
{
    NvmeCmd cmd = { 0 };

    cmd.opcode = opc;
    cmd.nsid = cpu_to_le32(nsid);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32((uint32_t)sb);
    cmd.cdw11 = cpu_to_le32(sb >> 32);
    cmd.cdw12 = cpu_to_le32(len);
    return femu_io(c, &cmd);
}

static void femu_cps_put(FemuCtrlState *c, uint64_t sb, const uint8_t *data,
                         uint32_t len, uint64_t buf)
{
    qtest_memwrite(c->pdev->bus->qts, buf, data, len);
    g_assert_cmphex(femu_cps_mem(c, FEMU_CPS_SLM, FEMU_SLM_WRITE, sb, len,
                                 buf), ==, NVME_SUCCESS);
}

static void femu_cps_get(FemuCtrlState *c, uint64_t sb, uint8_t *data,
                         uint32_t len, uint64_t buf)
{
    g_assert_cmphex(femu_cps_mem(c, FEMU_CPS_SLM, FEMU_SLM_READ, sb, len,
                                 buf), ==, NVME_SUCCESS);
    qtest_memread(c->pdev->bus->qts, buf, data, len);
}

/* a 32-byte source range of format 4h, or a Memory Range of CP */
static void femu_cps_range(FemuCtrlState *c, uint64_t list, int i,
                           uint32_t nsid, uint64_t addr, uint32_t len,
                           bool format4)
{
    uint8_t d[32] = { 0 };

    stl_le_p(d, nsid);
    if (format4) {
        stq_le_p(d + 8, addr);      /* SADDR */
        stl_le_p(d + 16, len);      /* NBYTE */
    } else {
        stl_le_p(d + 4, len);       /* LEN */
        stq_le_p(d + 8, addr);      /* SB */
    }
    qtest_memwrite(c->pdev->bus->qts, list + i * 32, d, sizeof(d));
}

/* a 32-byte source range of format 2h */
static void femu_cps_lba_range(FemuCtrlState *c, uint64_t list, int i,
                               uint32_t snsid, uint64_t slba, uint16_t nlb)
{
    uint8_t d[32] = { 0 };

    stl_le_p(d, snsid);
    stq_le_p(d + 8, slba);
    stw_le_p(d + 16, nlb - 1);
    qtest_memwrite(c->pdev->bus->qts, list + i * 32, d, sizeof(d));
}

static uint16_t femu_cps_mcopy(FemuCtrlState *c, uint8_t fmt, uint8_t nr,
                               uint64_t sdaddr, uint64_t len, uint64_t list)
{
    NvmeCmd cmd = { 0 };

    cmd.opcode = FEMU_SLM_COPY;
    cmd.nsid = cpu_to_le32(FEMU_CPS_SLM);
    cmd.res1 = cpu_to_le64(len);
    cmd.dptr.prp1 = cpu_to_le64(list);
    cmd.cdw10 = cpu_to_le32((uint32_t)sdaddr);
    cmd.cdw11 = cpu_to_le32(sdaddr >> 32);
    cmd.cdw12 = cpu_to_le32(nr | fmt << 8);
    return femu_io(c, &cmd);
}

/* enable Copy Descriptor Formats in Host Behavior Support (CDFE) */
static void femu_cps_cdfe(FemuCtrlState *c, uint8_t cdfe, uint64_t buf)
{
    qtest_memset(c->pdev->bus->qts, buf, 0, 512);
    qtest_writeb(c->pdev->bus->qts, buf + 4, cdfe);
    g_assert_cmphex(femu_hbs(c, true, buf), ==, NVME_SUCCESS);
}

static uint16_t femu_cps_admin(FemuCtrlState *c, uint8_t opc, uint32_t nsid,
                               uint32_t dw10, uint32_t dw11, uint32_t psize,
                               uint32_t numb, uint32_t loff, uint64_t buf,
                               uint32_t *result)
{
    NvmeCmd cmd = { 0 };

    cmd.opcode = opc;
    cmd.nsid = cpu_to_le32(nsid);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32(dw10);
    cmd.cdw11 = cpu_to_le32(opc == FEMU_CP_LOAD ? psize : dw11);
    cmd.cdw14 = cpu_to_le32(numb);
    cmd.cdw15 = cpu_to_le32(loff);
    return FEMU_SC(femu_admin_result(c, &cmd, result));
}

static uint16_t femu_cps_pam(FemuCtrlState *c, uint16_t pind, uint8_t sel)
{
    return femu_cps_admin(c, FEMU_CP_PAM, FEMU_CPS_CP, pind | sel << 16, 0, 0,
                          0, 0, 0, NULL);
}

static uint16_t femu_cps_mrs(FemuCtrlState *c, uint8_t sel, uint16_t rsid,
                             uint32_t numr, uint64_t list, uint32_t *result)
{
    return femu_cps_admin(c, FEMU_CP_MRSM, FEMU_CPS_CP, sel | rsid << 16, numr,
                          0, 0, 0, list, result);
}

static uint16_t femu_cps_load(FemuCtrlState *c, uint16_t pind, uint8_t ptype,
                              bool unload, uint32_t psize, uint32_t numb,
                              uint32_t loff, uint64_t buf)
{
    return femu_cps_admin(c, FEMU_CP_LOAD, FEMU_CPS_CP,
                          pind | ptype << 16 | (unload ? 1u << 24 : 0), 0,
                          psize, numb, loff, buf, NULL);
}

static void femu_cps_exec_submit(FemuCtrlState *c, FemuQueue *q, uint16_t pind,
                                 uint16_t rsid, uint32_t numr, uint32_t dlen,
                                 uint64_t buf, uint64_t p1, uint64_t p2)
{
    NvmeCmd cmd = { 0 };

    cmd.opcode = 0x01;
    cmd.nsid = cpu_to_le32(FEMU_CPS_CP);
    cmd.res1 = cpu_to_le64(pind | (uint64_t)rsid << 16 | (uint64_t)numr << 32);
    cmd.mptr = cpu_to_le64(dlen);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw10 = cpu_to_le32((uint32_t)p1);
    cmd.cdw11 = cpu_to_le32(p1 >> 32);
    cmd.cdw12 = cpu_to_le32((uint32_t)p2);
    cmd.cdw13 = cpu_to_le32(p2 >> 32);
    femu_submit(c, q, &cmd);
}

/* the next completion on q, with dword 0 and dword 1 as one value */
static uint16_t femu_cps_exec_wait(FemuCtrlState *c, FemuQueue *q,
                                   uint64_t *rval)
{
    uint16_t status = femu_complete(c, q, NULL, NULL);
    uint64_t slot = q->cq_addr +
                    ((q->cq_head + FEMU_QSIZE - 1) % FEMU_QSIZE) *
                    sizeof(NvmeCqe);
    NvmeCqe cqe;

    qtest_memread(c->pdev->bus->qts, slot, &cqe, sizeof(cqe));
    if (rval) {
        *rval = le32_to_cpu(cqe.result) |
                (uint64_t)le32_to_cpu(cqe.dw1) << 32;
    }
    return FEMU_SC(status);
}

static uint16_t femu_cps_exec(FemuCtrlState *c, uint16_t pind, uint16_t rsid,
                              uint32_t numr, uint32_t dlen, uint64_t buf,
                              uint64_t p1, uint64_t p2, uint64_t *rval)
{
    femu_cps_exec_submit(c, &c->io, pind, rsid, numr, dlen, buf, p1, p2);
    return femu_cps_exec_wait(c, &c->io, rval);
}

static uint64_t femu_cps_fnv(uint64_t h, const uint8_t *p, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        h = (h ^ p[i]) * 0x100000001b3ULL;
    }
    return h;
}

/*
 * Without csd_slm_size and csd_cp a CSD controller is the one it was: one
 * namespace, no memory or compute command set, no reachability, no CP
 * opcodes, and the CEMU commands still work.
 */
void femu_test_cps_default(void *obj, void *data,
                           QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint8_t id[4096];
    NvmeCmd cmd = { 0 };
    uint64_t buf;

    femu_cps_enable(&c, femu, alloc);
    buf = guest_alloc(alloc, 4096);

    g_assert_cmphex(femu_identify(&c, 0, NVME_ID_CNS_CTRL, 0, buf), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, buf, id, sizeof(id));
    g_assert_cmpuint(ldl_le_p(&id[516]), ==, 1);            /* NN */
    g_assert_cmphex(id[134], ==, 0);                        /* CRCAP */
    g_assert_cmphex(ldl_le_p(&id[92]) & (1 << 17), ==, 0);  /* OAES */
    g_assert_cmphex(lduw_le_p(&id[534]), ==, 0x5);          /* OCFS */
    g_assert_cmphex(femu_identify(&c, 0, FEMU_CNS_IO_CMD_SET, 0, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(qtest_readb(qts, buf) & 0x18, ==, 0);

    g_assert_cmphex(femu_log_cmd(&c, NVME_NSID_BROADCAST, 0x1a, 0, buf, 64),
                    ==, FEMU_SC_INVALID_LOG);
    g_assert_cmphex(femu_get_log_csi(&c, 0x82, FEMU_CSI_CP, buf, 512, 0), ==,
                    FEMU_SC_INVALID_LOG);
    g_assert_cmphex(femu_get_log_csi(&c, FEMU_LOG_SUPPORTED, FEMU_CSI_CP, buf,
                                     1024, 0), ==, FEMU_SC_IOCS_NOT_SUPP);
    g_assert_cmphex(femu_cps_admin(&c, FEMU_CP_LOAD, 1, 2, 0, 4, 4, 0, buf,
                                   NULL), ==, FEMU_SC_INVALID_OPCODE);
    g_assert_cmphex(femu_identify(&c, 0, NVME_ID_CNS_CS_NS_ACTIVE_LIST,
                                  FEMU_CSI_SLM << 24, buf), ==,
                    FEMU_SC_INVALID_FIELD);
    g_assert_cmphex(femu_identify(&c, 1, NVME_ID_CNS_CS_NS, FEMU_CSI_SLM << 24,
                                  buf), ==, FEMU_SC_INVALID_FIELD);

    /* CEMU Allocate Device Memory still answers on the block namespace */
    cmd.opcode = 0xb0;
    cmd.nsid = cpu_to_le32(1);
    cmd.cdw10 = cpu_to_le32(4096);
    g_assert_cmphex(femu_io(&c, &cmd), ==, NVME_SUCCESS);
    femu_round_trip(&c, 5);

    guest_free(alloc, buf);
    femu_cps_disable(&c);
}

/*
 * The memory and compute namespaces belong to no endurance group (SLM 1.2
 * 2.1.2, CP 1.2 2.1.1). In a subsystem they report ENDGID 0, and the
 * block namespace reports group 1. The Reachability Group stays 1. With
 * FDP on (data set), a Write placed through handle 1 uses that handle.
 */
void femu_test_cps_subsys(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    bool fdp = data != NULL;
    FemuCtrlState c = { 0 };
    uint64_t ruamw0 = 0, ruamw1 = 0;
    uint64_t buf, page, list;
    uint8_t r[8];

    femu_cps_enable(&c, femu, alloc);
    buf = guest_alloc(alloc, 4096);
    page = guest_alloc(alloc, 4096);
    list = guest_alloc(alloc, 4096);

    for (uint32_t nsid = 1; nsid <= 3; nsid++) {
        g_assert_cmphex(femu_identify(&c, nsid, 0x08, 0, buf), ==,
                        NVME_SUCCESS);
        g_assert_cmpuint(qtest_readw(qts, buf + 12), ==, nsid == 1);
        g_assert_cmpuint(qtest_readw(qts, buf + 16), ==, 0);   /* NVMSETID */
        g_assert_cmpuint(qtest_readl(qts, buf + 20), ==, 1);   /* RGRPID */
    }
    g_assert_cmphex(femu_identify(&c, 0, NVME_ID_CNS_CTRL, 0, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(qtest_readb(qts, buf + 134), ==, 0x3);      /* CRCAP */
    g_assert_cmpuint(qtest_readw(qts, buf + 340), ==, 1);      /* ENDGIDMAX */
    g_assert_cmphex(qtest_readl(qts, buf + 96) & (1 << 19), ==,
                    fdp ? 1 << 19 : 0);                         /* FDPS */

    /*
     * A placed Write lands in its own handle: handle 1 loses one page of
     * writable space and handle 0 keeps its own. The page reads back.
     */
    qtest_memset(qts, page, 0x5c, 4096);
    if (fdp) {
        ruamw0 = femu_ruh_ruamw(&c, buf, 0);
        ruamw1 = femu_ruh_ruamw(&c, buf, 1);
    }
    g_assert_cmphex(FEMU_SC(femu_write_pages_placed(&c, 3, 1, page, list,
                                                    fdp ? 1 : -1)), ==,
                    NVME_SUCCESS);
    if (fdp) {
        g_assert_cmpuint(femu_ruh_ruamw(&c, buf, 0), ==, ruamw0);
        g_assert_cmpuint(femu_ruh_ruamw(&c, buf, 1), ==, ruamw1 - 8);
    }
    qtest_memset(qts, page, 0, 4096);
    g_assert_cmphex(femu_read_pages(&c, 3, 1, page, list), ==, NVME_SUCCESS);
    g_assert_cmphex(qtest_readb(qts, page + 4095), ==, 0x5c);

    /* the memory namespace still works next to the endurance group */
    femu_cps_put(&c, 0x40, (const uint8_t *)"subsys!", 8, buf);
    femu_cps_get(&c, 0x40, r, 8, buf);
    g_assert_cmpmem(r, 8, "subsys!", 8);

    guest_free(alloc, list);
    guest_free(alloc, page);
    guest_free(alloc, buf);
    femu_cps_disable(&c);
}

/* Identify, the reachability logs and the per-set logs */
void femu_test_cps_identify(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint8_t id[4096];
    uint32_t lids[256];
    uint32_t eff[1024];
    uint64_t buf;

    femu_cps_enable(&c, femu, alloc);
    buf = guest_alloc(alloc, 4096);

    g_assert_cmphex(femu_identify(&c, 0, NVME_ID_CNS_CTRL, 0, buf), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, buf, id, sizeof(id));
    g_assert_cmpuint(ldl_le_p(&id[516]), ==, 3);
    g_assert_cmphex(id[134], ==, 0x3);
    g_assert_cmphex(ldl_le_p(&id[92]) & (1 << 17), ==, 1 << 17);
    g_assert_cmphex(lduw_le_p(&id[534]), ==, 0x15);

    g_assert_cmphex(femu_identify(&c, 0, FEMU_CNS_IO_CMD_SET, 0, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(qtest_readb(qts, buf) & 0x1f, ==, 0x1f);

    g_assert_cmphex(femu_identify(&c, 0, NVME_ID_CNS_NS_ACTIVE_LIST, 0, buf),
                    ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf), ==, 1);
    g_assert_cmpuint(qtest_readl(qts, buf + 4), ==, 2);
    g_assert_cmpuint(qtest_readl(qts, buf + 8), ==, 3);
    g_assert_cmpuint(qtest_readl(qts, buf + 12), ==, 0);
    for (int csi = FEMU_CSI_SLM; csi <= FEMU_CSI_CP; csi++) {
        uint32_t nsid = csi == FEMU_CSI_SLM ? FEMU_CPS_SLM : FEMU_CPS_CP;

        g_assert_cmphex(femu_identify(&c, 0, NVME_ID_CNS_CS_NS_ACTIVE_LIST,
                                      csi << 24, buf), ==, NVME_SUCCESS);
        g_assert_cmpuint(qtest_readl(qts, buf), ==, nsid);
        g_assert_cmpuint(qtest_readl(qts, buf + 4), ==, 0);
        /* the CSI descriptor follows the 16-byte UUID descriptor */
        g_assert_cmphex(femu_identify(&c, nsid, NVME_ID_CNS_NS_DESCR_LIST, 0,
                                      buf), ==, NVME_SUCCESS);
        g_assert_cmphex(qtest_readb(qts, buf + 20), ==, FEMU_NIDT_CSI);
        g_assert_cmphex(qtest_readb(qts, buf + 24), ==, csi);
        /* no NVM structure, and the other set's structure is refused */
        g_assert_cmphex(femu_identify(&c, nsid, NVME_ID_CNS_NS, 0, buf), ==,
                        FEMU_SC_INVALID_IOCS);
        g_assert_cmphex(femu_identify(&c, nsid, NVME_ID_CNS_CS_NS,
                                      (FEMU_CSI_SLM + FEMU_CSI_CP - csi) << 24,
                                      buf), ==, FEMU_SC_INVALID_FIELD);
        g_assert_cmphex(femu_identify(&c, 0, FEMU_CNS_CS_CTRL, csi << 24, buf),
                        ==, NVME_SUCCESS);
        g_assert_cmphex(qtest_readl(qts, buf), ==, 0x00010200);
    }

    /* SLM Figure 25 */
    g_assert_cmphex(femu_identify(&c, FEMU_CPS_SLM, NVME_ID_CNS_CS_NS,
                                  FEMU_CSI_SLM << 24, buf), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, id, sizeof(id));
    g_assert_cmpuint(ldq_le_p(&id[0]), ==, FEMU_CPS_SLM_SIZE);
    g_assert_cmpuint(id[8], ==, 0);
    g_assert_cmpuint(ldl_le_p(&id[9]), ==, 0);
    g_assert_cmpuint(ldq_le_p(&id[13]), ==, FEMU_CPS_COPY_MAX);
    g_assert_cmpuint(ldl_le_p(&id[21]), ==, FEMU_CPS_COPY_MAX);
    g_assert_cmpuint(id[25], ==, 127);
    g_assert_cmphex(id[527], ==, 0x80);
    g_assert_cmphex(id[543], ==, 0);
    /* CP Figure 36 */
    g_assert_cmphex(femu_identify(&c, FEMU_CPS_CP, NVME_ID_CNS_CS_NS,
                                  FEMU_CSI_CP << 24, buf), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, id, sizeof(id));
    g_assert_cmpuint(lduw_le_p(&id[0]), ==, 2);
    g_assert_cmpuint(lduw_le_p(&id[2]), ==, 64);
    g_assert_cmpuint(lduw_le_p(&id[4]), ==, 2);
    g_assert_cmpuint(id[6], ==, 128);
    g_assert_cmpuint(ldq_le_p(&id[8]), ==, 64);
    g_assert_cmpuint(id[16], ==, 2);
    g_assert_cmpuint(id[17], ==, 0);

    /* every namespace is in Reachability Group 1 */
    for (uint32_t nsid = 1; nsid <= 3; nsid++) {
        g_assert_cmphex(femu_identify(&c, nsid, FEMU_CNS_NS_CS_INDEP, 0, buf),
                        ==, NVME_SUCCESS);
        g_assert_cmpuint(qtest_readl(qts, buf + 20), ==, 1);
    }
    g_assert_cmphex(femu_log_cmd(&c, NVME_NSID_BROADCAST, 0x1a, 0, buf, 64),
                    ==, NVME_SUCCESS);
    qtest_memread(qts, buf, id, 64);
    g_assert_cmpuint(ldq_le_p(&id[0]), ==, 0);
    g_assert_cmpuint(lduw_le_p(&id[8]), ==, 1);
    g_assert_cmpuint(ldl_le_p(&id[16]), ==, 1);
    g_assert_cmpuint(ldl_le_p(&id[20]), ==, 3);
    g_assert_cmpuint(ldl_le_p(&id[48]), ==, 1);
    g_assert_cmpuint(ldl_le_p(&id[52]), ==, 2);
    g_assert_cmpuint(ldl_le_p(&id[56]), ==, 3);
    g_assert_cmphex(femu_log_cmd(&c, NVME_NSID_BROADCAST, 0x1a | 1 << 8, 0,
                                 buf, 64), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf + 20), ==, 0);
    g_assert_cmphex(femu_log_cmd(&c, NVME_NSID_BROADCAST, 0x1b, 0, buf, 64),
                    ==, NVME_SUCCESS);
    qtest_memread(qts, buf, id, 64);
    g_assert_cmpuint(lduw_le_p(&id[8]), ==, 1);
    g_assert_cmpuint(ldl_le_p(&id[16]), ==, 1);
    g_assert_cmpuint(ldl_le_p(&id[20]), ==, 1);
    g_assert_cmphex(id[32], ==, 0x01);
    g_assert_cmpuint(ldl_le_p(&id[48]), ==, 1);
    g_assert_cmphex(femu_log_cmd(&c, NVME_NSID_BROADCAST, 0x1b | 1 << 8, 0,
                                 buf, 64), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf + 20), ==, 0);

    /* the CP pages are listed for CP only */
    g_assert_cmphex(femu_get_log_csi(&c, FEMU_LOG_SUPPORTED, FEMU_CSI_CP, buf,
                                     1024, 0), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, lids, sizeof(lids));
    for (int lid = 0x82; lid <= 0x84; lid++) {
        g_assert_cmphex(lids[lid] & 1, ==, 1);
    }
    g_assert_cmphex(lids[0x1a] & 1, ==, 1);
    g_assert_cmphex(lids[0x1b] & 1, ==, 1);
    g_assert_cmphex(femu_get_log_csi(&c, FEMU_LOG_SUPPORTED, FEMU_CSI_SLM, buf,
                                     1024, 0), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, lids, sizeof(lids));
    g_assert_cmphex(lids[0x82] & 1, ==, 0);
    g_assert_cmphex(lids[0x1a] & 1, ==, 1);

    /* SLM Figure 5 and CP Figure 15: support, and no logical block change */
    g_assert_cmphex(femu_get_log_csi(&c, FEMU_LOG_CMD_EFFECTS, FEMU_CSI_SLM,
                                     buf, 4096, 0), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, eff, sizeof(eff));
    g_assert_cmphex(eff[256 + 0x00], ==, 1);
    g_assert_cmphex(eff[256 + 0x01], ==, 1);
    g_assert_cmphex(eff[256 + 0x02], ==, 1);
    g_assert_cmphex(eff[256 + 0x04], ==, 1);
    g_assert_cmphex(eff[256 + 0x05], ==, 1);
    g_assert_cmphex(eff[256 + 0x09], ==, 0);
    g_assert_cmphex(eff[256 + 0xb0], ==, 0);
    g_assert_cmphex(eff[FEMU_CP_LOAD] & 1, ==, 1);
    g_assert_cmphex(eff[FEMU_CP_PAM] & 1, ==, 1);
    g_assert_cmphex(eff[FEMU_CP_MRSM] & 1, ==, 1);
    g_assert_cmphex(femu_get_log_csi(&c, FEMU_LOG_CMD_EFFECTS, FEMU_CSI_CP,
                                     buf, 4096, 0), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, eff, sizeof(eff));
    g_assert_cmphex(eff[256 + 0x01], ==, 1);
    g_assert_cmphex(eff[256 + 0x02], ==, 0);

    guest_free(alloc, buf);
    femu_cps_disable(&c);
}

/* Memory Write, Read and Fill, and what each refuses */
void femu_test_cps_slm_rw(void *obj, void *data,
                          QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint8_t w[4096], r[4096];
    NvmeCmd cmd = { 0 };
    uint64_t buf;
    int i;

    femu_cps_enable(&c, femu, alloc);
    buf = guest_alloc(alloc, 4096);
    for (i = 0; i < sizeof(w); i++) {
        w[i] = (uint8_t)(i * 13 + 1);
    }
    femu_cps_put(&c, 0x100, w, sizeof(w), buf);
    femu_cps_get(&c, 0x100, r, sizeof(r), buf);
    g_assert_cmpint(memcmp(w, r, sizeof(w)), ==, 0);
    /* memory commands are not logical block commands in SMART (02h) */
    {
        uint64_t wr0, rd0;

        g_assert_cmphex(femu_get_log(&c, NVME_LOG_SMART_INFO, buf, 512, 0),
                        ==, NVME_SUCCESS);
        rd0 = qtest_readq(qts, buf + 64);       /* Host Read Commands */
        wr0 = qtest_readq(qts, buf + 80);       /* Host Write Commands */
        femu_cps_put(&c, 0x100, w, sizeof(w), buf);
        femu_cps_get(&c, 0x100, r, sizeof(r), buf);
        g_assert_cmphex(femu_get_log(&c, NVME_LOG_SMART_INFO, buf, 512, 0),
                        ==, NVME_SUCCESS);
        g_assert_cmpuint(qtest_readq(qts, buf + 64), ==, rd0);
        g_assert_cmpuint(qtest_readq(qts, buf + 80), ==, wr0);
        g_assert_cmphex(femu_rw(&c, NVME_CMD_WRITE, 0, buf), ==, NVME_SUCCESS);
        g_assert_cmphex(femu_get_log(&c, NVME_LOG_SMART_INFO, buf, 512, 0),
                        ==, NVME_SUCCESS);
        g_assert_cmpuint(qtest_readq(qts, buf + 80), ==, wr0 + 1);
    }
    /* the last dword of the namespace */
    femu_cps_put(&c, FEMU_CPS_SLM_SIZE - 4, w, 4, buf);
    femu_cps_get(&c, FEMU_CPS_SLM_SIZE - 4, r, 4, buf);
    g_assert_cmpint(memcmp(w, r, 4), ==, 0);

    g_assert_cmphex(femu_cps_mem(&c, FEMU_CPS_SLM, FEMU_SLM_FILL, 0x200, 8, 0),
                    ==, NVME_SUCCESS);
    femu_cps_get(&c, 0x100, r, sizeof(r), buf);
    for (i = 0; i < sizeof(w); i++) {
        g_assert_cmphex(r[i], ==, i >= 0x100 && i < 0x108 ? 0 : w[i]);
    }

    /* dword alignment, the end of the namespace, and the high address half */
    for (i = 0; i < 3; i++) {
        static const uint8_t opcs[] = { FEMU_SLM_READ, FEMU_SLM_WRITE,
                                        FEMU_SLM_FILL };
        uint8_t opc = opcs[i];

        g_assert_cmphex(femu_cps_mem(&c, FEMU_CPS_SLM, opc, 2, 4, buf), ==,
                        FEMU_SC_INVALID_FIELD);
        g_assert_cmphex(femu_cps_mem(&c, FEMU_CPS_SLM, opc, 0, 6, buf), ==,
                        FEMU_SC_INVALID_FIELD);
        g_assert_cmphex(femu_cps_mem(&c, FEMU_CPS_SLM, opc,
                                     FEMU_CPS_SLM_SIZE - 4, 8, buf), ==,
                        FEMU_SC_INVALID_FIELD);
        g_assert_cmphex(femu_cps_mem(&c, FEMU_CPS_SLM, opc, 1ULL << 32, 4,
                                     buf), ==, FEMU_SC_INVALID_FIELD);
        g_assert_cmphex(femu_cps_mem(&c, FEMU_CPS_SLM, opc, 0, 0, buf), ==,
                        NVME_SUCCESS);
    }

    /* Flush does nothing; NVM, CEMU and fused commands are refused */
    g_assert_cmphex(femu_cps_mem(&c, FEMU_CPS_SLM, NVME_CMD_FLUSH, 0, 0, 0),
                    ==, NVME_SUCCESS);
    g_assert_cmphex(femu_cps_mem(&c, FEMU_CPS_SLM, 0x09, 0, 0, buf), ==,
                    FEMU_SC_INVALID_OPCODE);
    g_assert_cmphex(femu_cps_mem(&c, FEMU_CPS_SLM, 0xb0, 0, 4096, buf), ==,
                    FEMU_SC_INVALID_OPCODE);
    g_assert_cmphex(femu_cps_mem(&c, FEMU_CPS_CP, FEMU_SLM_READ, 0, 4, buf),
                    ==, FEMU_SC_INVALID_OPCODE);
    cmd.opcode = FEMU_SLM_READ;
    cmd.flags = 1;
    cmd.nsid = cpu_to_le32(FEMU_CPS_SLM);
    cmd.dptr.prp1 = cpu_to_le64(buf);
    cmd.cdw12 = cpu_to_le32(4);
    g_assert_cmphex(femu_io(&c, &cmd), ==, FEMU_SC_INVALID_FIELD);
    /* the data the refusals passed over is untouched */
    femu_cps_get(&c, 0x100, r, 8, buf);
    g_assert_cmpint(memcmp(w, r, 8), ==, 0);

    /*
     * A write whose data pointer fails part of the way: four bytes from the
     * end of a good page, then a page that is not memory. The command fails
     * and leaves both dwords as they were.
     */
    cmd.flags = 0;
    cmd.opcode = FEMU_SLM_WRITE;
    cmd.dptr.prp1 = cpu_to_le64(buf + 4092);
    cmd.dptr.prp2 = cpu_to_le64(0xfffffffff000ULL);
    cmd.cdw10 = cpu_to_le32(0x100);
    cmd.cdw12 = cpu_to_le32(8);
    qtest_memset(qts, buf + 4092, 0xee, 4);
    g_assert_cmphex(femu_io(&c, &cmd), ==, FEMU_SC_DATA_XFER);
    femu_cps_get(&c, 0x100, r, 8, buf);
    g_assert_cmpint(memcmp(w, r, 8), ==, 0);
    /* the same through an SGL of a one-byte block and a bad three-byte one */
    {
        NvmeSglDescriptor d[2] = { { 0 } };
        NvmeSglDescriptor seg = { 0 };

        d[0].addr = cpu_to_le64(buf + 2048);
        d[0].len = cpu_to_le32(1);
        d[1].addr = cpu_to_le64(0xfffffffff000ULL);
        d[1].len = cpu_to_le32(3);
        qtest_memwrite(qts, buf + 1024, d, sizeof(d));
        seg.addr = cpu_to_le64(buf + 1024);
        seg.len = cpu_to_le32(sizeof(d));
        seg.type = NVME_SGL_DESCR_TYPE_LAST_SEGMENT << 4;
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = FEMU_SLM_WRITE;
        cmd.flags = 1 << 6;
        cmd.nsid = cpu_to_le32(FEMU_CPS_SLM);
        memcpy(&cmd.dptr.sgl, &seg, sizeof(seg));
        cmd.cdw10 = cpu_to_le32(0x100);
        cmd.cdw12 = cpu_to_le32(4);
        qtest_writeb(qts, buf + 2048, 0xee);
        g_assert_cmphex(femu_io(&c, &cmd), ==, FEMU_SC_DATA_XFER);
        femu_cps_get(&c, 0x100, r, 8, buf);
        g_assert_cmpint(memcmp(w, r, 8), ==, 0);
    }

    guest_free(alloc, buf);
    femu_cps_disable(&c);

    /* with CC.CSS 000b only the NVM command set runs */
    memset(&c, 0, sizeof(c));
    femu_enable(&c, &femu->dev, alloc);
    femu_create_io_queues(&c);
    buf = guest_alloc(alloc, 4096);
    g_assert_cmphex(femu_cps_mem(&c, FEMU_CPS_SLM, FEMU_SLM_READ, 0, 4, buf),
                    ==, FEMU_SC_INVALID_OPCODE);
    guest_free(alloc, buf);
    femu_cps_disable(&c);
    (void)qts;
}

/* Memory Copy from memory and from blocks, and Copy from memory to blocks */
void femu_test_cps_slm_copy(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint8_t w[4096], r[4096];
    NvmeCmd cmd = { 0 };
    uint64_t buf, list, pages;
    int i;

    femu_cps_enable(&c, femu, alloc);
    buf = guest_alloc(alloc, 4096);
    list = guest_alloc(alloc, 4096);
    for (i = 0; i < sizeof(w); i++) {
        w[i] = (uint8_t)(i * 7 + 3);
    }
    femu_cps_put(&c, 0, w, sizeof(w), buf);

    /* a format not enabled in Host Behavior Support is refused */
    femu_cps_range(&c, list, 0, FEMU_CPS_SLM, 0, 16, true);
    g_assert_cmphex(femu_cps_mcopy(&c, 4, 0, 0x10000, 16, list), ==,
                    FEMU_SC_INVALID_FIELD);
    femu_cps_cdfe(&c, 1 << 2 | 1 << 4, buf);

    /* two ranges gather into one run, in range order */
    femu_cps_range(&c, list, 0, FEMU_CPS_SLM, 0x40, 16, true);
    femu_cps_range(&c, list, 1, FEMU_CPS_SLM, 0x0, 8, true);
    g_assert_cmphex(femu_cps_mcopy(&c, 4, 1, 0x10000, 24, list), ==,
                    NVME_SUCCESS);
    femu_cps_get(&c, 0x10000, r, 24, buf);
    g_assert_cmpint(memcmp(r, w + 0x40, 16), ==, 0);
    g_assert_cmpint(memcmp(r + 16, w, 8), ==, 0);

    /* refusals; none of them writes the destination */
    g_assert_cmphex(femu_cps_mcopy(&c, 4, 1, 0x10000, 28, list), ==,
                    FEMU_SC_INVALID_FIELD);             /* LEN != sum */
    g_assert_cmphex(femu_cps_mcopy(&c, 4, 1, 0x10002, 24, list), ==,
                    FEMU_SC_INVALID_FIELD);             /* SDADDR */
    g_assert_cmphex(femu_cps_mcopy(&c, 4, 1, 0x30, 24, list), ==,
                    FEMU_SC_OVERLAP);
    g_assert_cmphex(femu_cps_mcopy(&c, 4, 128, 0x10000, 24, list), ==,
                    FEMU_SC_SIZE_LIMIT);                /* NR 128 is 129 */
    g_assert_cmphex(femu_cps_mcopy(&c, 3, 1, 0x10000, 24, list), ==,
                    FEMU_SC_INVALID_FIELD);
    g_assert_cmphex(femu_cps_mcopy(&c, 4, 1, FEMU_CPS_SLM_SIZE - 20, 24,
                                   list), ==, FEMU_SC_INVALID_FIELD);
    femu_cps_range(&c, list, 1, 0, 0x0, 8, true);
    g_assert_cmphex(femu_cps_mcopy(&c, 4, 1, 0x20000, 24, list), ==,
                    FEMU_SC_INVALID_FIELD);             /* SNSID 0 */
    femu_cps_range(&c, list, 1, 1, 0x0, 8, true);
    g_assert_cmphex(femu_cps_mcopy(&c, 4, 1, 0x20000, 24, list), ==,
                    FEMU_SC_INVALID_NS);                /* not memory */
    femu_cps_range(&c, list, 1, FEMU_CPS_SLM, 0x0, FEMU_CPS_COPY_MAX + 4,
                   true);
    g_assert_cmphex(femu_cps_mcopy(&c, 4, 1, 0x20000, FEMU_CPS_COPY_MAX + 20,
                                   list), ==, FEMU_SC_SIZE_LIMIT);
    femu_cps_range(&c, list, 1, FEMU_CPS_SLM, 0x0, 8, true);
    qtest_writeb(qts, list + 32 + 23, 0x80);            /* FCO */
    g_assert_cmphex(femu_cps_mcopy(&c, 4, 1, 0x20000, 24, list), ==,
                    FEMU_SC_NO_FAST_COPY);
    femu_cps_get(&c, 0x20000, r, 32, buf);
    for (i = 0; i < 32; i++) {
        g_assert_cmphex(r[i], ==, 0);
    }

    /* format 2h: blocks of namespace 1 into memory */
    qtest_memwrite(qts, buf, w, sizeof(w));
    g_assert_cmphex(femu_rw(&c, NVME_CMD_WRITE, 16, buf), ==, NVME_SUCCESS);
    femu_cps_lba_range(&c, list, 0, 1, 17, 2);
    femu_cps_lba_range(&c, list, 1, 1, 16, 1);
    g_assert_cmphex(femu_cps_mcopy(&c, 2, 1, 0x30000, 3 * 512, list), ==,
                    NVME_SUCCESS);
    femu_cps_get(&c, 0x30000, r, 3 * 512, buf);
    g_assert_cmpint(memcmp(r, w + 512, 1024), ==, 0);
    g_assert_cmpint(memcmp(r + 1024, w, 512), ==, 0);
    femu_cps_lba_range(&c, list, 0, FEMU_CPS_SLM, 0, 1);
    g_assert_cmphex(femu_cps_mcopy(&c, 2, 0, 0x30000, 512, list), ==,
                    FEMU_SC_INCOMPATIBLE);              /* SNSID == NSID */
    femu_cps_lba_range(&c, list, 0, FEMU_CPS_CP, 0, 1);
    g_assert_cmphex(femu_cps_mcopy(&c, 2, 0, 0x30000, 512, list), ==,
                    FEMU_SC_INVALID_NS);
    femu_cps_lba_range(&c, list, 0, 9, 0, 1);
    g_assert_cmphex(femu_cps_mcopy(&c, 2, 0, 0x30000, 512, list), ==,
                    FEMU_SC_INVALID_FIELD);             /* invalid NSID */
    femu_cps_lba_range(&c, list, 0, 1, 1ULL << 40, 1);
    g_assert_cmphex(femu_cps_mcopy(&c, 2, 0, 0x30000, 512, list), ==,
                    FEMU_SC_LBA_RANGE);
    femu_cps_lba_range(&c, list, 0, 1, 16, 1);
    g_assert_cmphex(femu_cps_mcopy(&c, 2, 0, 0x30000, 1024, list), ==,
                    FEMU_SC_INVALID_FIELD);             /* LEN != blocks */

    /* Copy format 4h: memory into blocks 64 to 71 of namespace 1 */
    femu_cps_range(&c, list, 0, FEMU_CPS_SLM, 0x800, 2048, true);
    femu_cps_range(&c, list, 1, FEMU_CPS_SLM, 0x0, 2048, true);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_CMD_COPY;
    cmd.nsid = cpu_to_le32(1);
    cmd.dptr.prp1 = cpu_to_le64(list);
    cmd.cdw10 = cpu_to_le32(64);
    cmd.cdw12 = cpu_to_le32(1 | 4 << 8);
    g_assert_cmphex(femu_io(&c, &cmd), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_rw(&c, NVME_CMD_READ, 64, buf), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, r, sizeof(r));
    g_assert_cmpint(memcmp(r, w + 2048, 2048), ==, 0);
    g_assert_cmpint(memcmp(r + 2048, w, 2048), ==, 0);
    /* not whole blocks, a source that is not memory, FCO, CDF4E clear */
    femu_cps_range(&c, list, 1, FEMU_CPS_SLM, 0x0, 2044, true);
    g_assert_cmphex(femu_io(&c, &cmd), ==, FEMU_SC_INVALID_FIELD);
    femu_cps_range(&c, list, 1, 0, 0x0, 2048, true);
    g_assert_cmphex(femu_io(&c, &cmd), ==, FEMU_SC_INVALID_NS);
    femu_cps_range(&c, list, 1, 1, 0x0, 2048, true);
    g_assert_cmphex(femu_io(&c, &cmd), ==, FEMU_SC_INVALID_NS);
    femu_cps_range(&c, list, 1, FEMU_CPS_SLM, 0x0, 2048, true);
    qtest_writeb(qts, list + 32 + 23, 0x80);
    g_assert_cmphex(femu_io(&c, &cmd), ==, FEMU_SC_NO_FAST_COPY);
    /* no bytes: success, and blocks 0 and 1 keep their data */
    qtest_memwrite(qts, buf, w, sizeof(w));
    g_assert_cmphex(femu_rw(&c, NVME_CMD_WRITE, 0, buf), ==, NVME_SUCCESS);
    femu_cps_range(&c, list, 0, FEMU_CPS_SLM, 0x0, 0, true);
    femu_cps_range(&c, list, 1, FEMU_CPS_SLM, 0x0, 0, true);
    /* and no page is programmed for them (C0h offset 8, host pages) */
    g_assert_cmphex(femu_log_cmd(&c, 1, 0xc0, 0, list + 2048, 512), ==,
                    NVME_SUCCESS);
    pages = qtest_readq(qts, list + 2048 + 8);
    for (i = 0; i < 2; i++) {
        cmd.cdw10 = cpu_to_le32(i);
        g_assert_cmphex(femu_io(&c, &cmd), ==, NVME_SUCCESS);
    }
    g_assert_cmphex(femu_log_cmd(&c, 1, 0xc0, 0, list + 2048, 512), ==,
                    NVME_SUCCESS);
    g_assert_cmpuint(qtest_readq(qts, list + 2048 + 8), ==, pages);
    g_assert_cmphex(femu_rw(&c, NVME_CMD_READ, 0, buf), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, r, sizeof(r));
    g_assert_cmpint(memcmp(r, w, sizeof(w)), ==, 0);
    cmd.cdw10 = cpu_to_le32(64);
    femu_cps_cdfe(&c, 1 << 2, buf);
    femu_cps_range(&c, list, 1, FEMU_CPS_SLM, 0x0, 2048, true);
    g_assert_cmphex(femu_io(&c, &cmd), ==, FEMU_SC_INVALID_FIELD);

    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_cps_disable(&c);
}

/* the admin side of CP: logs, activation, range sets and program loads */
void femu_test_cps_admin(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint8_t log[64 + 16 * 64];
    uint32_t rsid[2];
    uint64_t buf, list;
    int i;

    femu_cps_enable(&c, femu, alloc);
    buf = guest_alloc(alloc, 4096);
    list = guest_alloc(alloc, 4096);

    /* Program List: two device-defined programs, then empty indexes */
    g_assert_cmphex(femu_log_cmd(&c, FEMU_CPS_CP, 0x82, FEMU_CSI_CP << 24,
                                 buf, sizeof(log)), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, log, sizeof(log));
    g_assert_cmpuint(ldl_le_p(log), ==, 16);
    g_assert_cmphex(log[64], ==, 0x2);
    g_assert_cmphex(log[128], ==, 0x2);
    for (i = 2; i < 16; i++) {
        g_assert_cmphex(log[64 + i * 64], ==, 0);
    }
    g_assert_cmphex(femu_log_cmd(&c, FEMU_CPS_SLM, 0x82, FEMU_CSI_CP << 24,
                                 buf, 64), ==, FEMU_SC_INVALID_FIELD);
    g_assert_cmphex(femu_log_cmd(&c, NVME_NSID_BROADCAST, 0x82,
                                 FEMU_CSI_CP << 24, buf, 64), ==,
                    FEMU_SC_INVALID_FIELD);
    /* no program directory, so no downloadable type */
    g_assert_cmphex(femu_log_cmd(&c, FEMU_CPS_CP, 0x83, FEMU_CSI_CP << 24,
                                 buf, 64), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf), ==, 0);

    /* activation, up to MAXACT (nr_cu=2) */
    g_assert_cmphex(femu_cps_pam(&c, 0, 1), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_cps_pam(&c, 0, 1), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_cps_pam(&c, 2, 1), ==, FEMU_SC_NO_PROGRAM);
    g_assert_cmphex(femu_cps_pam(&c, 16, 1), ==, FEMU_SC_INVALID_PIND);
    g_assert_cmphex(femu_cps_pam(&c, 0xffff, 1), ==, FEMU_SC_INVALID_PIND);
    g_assert_cmphex(femu_cps_pam(&c, 0, 2), ==, FEMU_SC_INVALID_FIELD);
    g_assert_cmphex(femu_cps_pam(&c, 1, 1), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_log_cmd(&c, FEMU_CPS_CP, 0x82, FEMU_CSI_CP << 24,
                                 buf, sizeof(log)), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, log, sizeof(log));
    g_assert_cmphex(log[64], ==, 0x6);
    g_assert_cmphex(log[128], ==, 0x6);
    g_assert_cmphex(femu_cps_pam(&c, 0xffff, 0), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_cps_pam(&c, 1, 0), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_cps_pam(&c, 2, 0), ==, FEMU_SC_NO_PROGRAM);

    /* Memory Range Sets */
    femu_cps_range(&c, list, 0, FEMU_CPS_SLM, 0x1000, 0x100, false);
    femu_cps_range(&c, list, 1, FEMU_CPS_SLM, 0x0, 0x100, false);
    g_assert_cmphex(femu_cps_mrs(&c, 0, 0, 2, list, &rsid[0]), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(femu_cps_mrs(&c, 0, 0, 1, list, &rsid[1]), ==,
                    NVME_SUCCESS);
    g_assert_cmpuint(rsid[0], !=, 0);
    g_assert_cmpuint(rsid[1], !=, rsid[0]);
    g_assert_cmphex(femu_cps_mrs(&c, 0, 5, 1, list, NULL), ==,
                    FEMU_SC_INVALID_FIELD);             /* RSID set */
    g_assert_cmphex(femu_cps_mrs(&c, 0, 0, 0, list, NULL), ==,
                    FEMU_SC_INVALID_FIELD);
    g_assert_cmphex(femu_cps_mrs(&c, 0, 0, 129, list, NULL), ==,
                    FEMU_SC_INVALID_FIELD);
    g_assert_cmphex(femu_cps_mrs(&c, 2, 0, 1, list, NULL), ==,
                    FEMU_SC_INVALID_FIELD);
    femu_cps_range(&c, list, 1, FEMU_CPS_SLM, 0x10f0, 0x20, false);
    g_assert_cmphex(femu_cps_mrs(&c, 0, 0, 2, list, NULL), ==,
                    FEMU_SC_OVERLAP_RANGES);
    femu_cps_range(&c, list, 1, 1, 0x0, 0x20, false);
    g_assert_cmphex(femu_cps_mrs(&c, 0, 0, 2, list, NULL), ==,
                    FEMU_SC_INVALID_MEM_NS);
    femu_cps_range(&c, list, 1, FEMU_CPS_SLM, 0x0, 0x22, false);
    g_assert_cmphex(femu_cps_mrs(&c, 0, 0, 2, list, NULL), ==,
                    FEMU_SC_INVALID_MRS);
    femu_cps_range(&c, list, 1, FEMU_CPS_SLM, FEMU_CPS_SLM_SIZE - 4, 8, false);
    g_assert_cmphex(femu_cps_mrs(&c, 0, 0, 2, list, NULL), ==,
                    FEMU_SC_INVALID_MRS);
    /* the list: RSID 0h first, then each set by RSID */
    g_assert_cmphex(femu_log_cmd(&c, FEMU_CPS_CP, 0x84, FEMU_CSI_CP << 24,
                                 buf, 4096), ==, NVME_SUCCESS);
    qtest_memread(qts, buf, log, sizeof(log));
    g_assert_cmpuint(ldl_le_p(log), ==, 3);
    g_assert_cmpuint(lduw_le_p(log + 4), ==, 0);
    g_assert_cmpuint(lduw_le_p(log + 36), ==, rsid[0]);
    g_assert_cmpuint(ldl_le_p(log + 38), ==, 2);
    g_assert_cmpuint(ldl_le_p(log + 68), ==, FEMU_CPS_SLM);
    g_assert_cmpuint(ldl_le_p(log + 72), ==, 0x100);
    g_assert_cmpuint(ldq_le_p(log + 76), ==, 0x1000);
    g_assert_cmpuint(lduw_le_p(log + 132), ==, rsid[1]);
    g_assert_cmphex(femu_log_cmd(&c, FEMU_CPS_CP, 0x84 | 1 << 8,
                                 FEMU_CSI_CP << 24, buf, 4096), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, buf, log, 128);
    g_assert_cmpuint(lduw_le_p(log + 36), ==, rsid[0]);
    g_assert_cmpuint(ldl_le_p(log + 38), ==, 0);
    g_assert_cmpuint(lduw_le_p(log + 68), ==, rsid[1]);

    g_assert_cmphex(femu_cps_mrs(&c, 1, 0, 0, 0, NULL), ==,
                    FEMU_SC_INVALID_RSID);
    g_assert_cmphex(femu_cps_mrs(&c, 1, rsid[1], 0, 0, NULL), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(femu_cps_mrs(&c, 1, rsid[1], 0, 0, NULL), ==,
                    FEMU_SC_INVALID_RSID);
    g_assert_cmphex(femu_cps_mrs(&c, 1, 0xffff, 0, 0, NULL), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(femu_cps_mrs(&c, 1, 0xffff, 0, 0, NULL), ==,
                    NVME_SUCCESS);
    /* MAXMEMRS */
    femu_cps_range(&c, list, 0, FEMU_CPS_SLM, 0x0, 0x100, false);
    for (i = 0; i < 64; i++) {
        g_assert_cmphex(femu_cps_mrs(&c, 0, 0, 1, list, NULL), ==,
                        NVME_SUCCESS);
    }
    g_assert_cmphex(femu_cps_mrs(&c, 0, 0, 1, list, NULL), ==,
                    FEMU_SC_MAX_MRS);
    g_assert_cmphex(femu_cps_mrs(&c, 1, 0xffff, 0, 0, NULL), ==,
                    NVME_SUCCESS);

    /* loads: no downloadable type, device-defined and invalid indexes */
    g_assert_cmphex(femu_cps_load(&c, 2, FEMU_CP_SHLIB, false, 8, 8, 0, buf),
                    ==, FEMU_SC_INVALID_PTYPE);
    g_assert_cmphex(femu_cps_load(&c, 0, FEMU_CP_SHLIB, false, 8, 8, 0, buf),
                    ==, FEMU_SC_NOT_DOWNLOAD);
    g_assert_cmphex(femu_cps_load(&c, 1, 0, true, 0, 0, 0, 0), ==,
                    FEMU_SC_NOT_DOWNLOAD);
    g_assert_cmphex(femu_cps_load(&c, 0xffff, FEMU_CP_SHLIB, false, 8, 8, 0,
                                  buf), ==, FEMU_SC_INVALID_PIND);
    g_assert_cmphex(femu_cps_load(&c, 16, 0, true, 0, 0, 0, 0), ==,
                    FEMU_SC_INVALID_PIND);
    g_assert_cmphex(femu_cps_load(&c, 2, 0, true, 0, 0, 0, 0), ==,
                    FEMU_SC_NO_PROGRAM);
    g_assert_cmphex(femu_cps_load(&c, 2, 0, false, 8, 8, 4, buf), ==,
                    FEMU_SC_NO_PROGRAM);
    g_assert_cmphex(femu_cps_load(&c, 0xffff, 0, true, 0, 0, 0, 0), ==,
                    NVME_SUCCESS);
    /* any other namespace */
    g_assert_cmphex(femu_cps_admin(&c, FEMU_CP_PAM, FEMU_CPS_SLM, 1 << 16, 0,
                                   0, 0, 0, 0, NULL), ==, FEMU_SC_INVALID_NS);
    g_assert_cmphex(femu_cps_admin(&c, FEMU_CP_MRSM, NVME_NSID_BROADCAST, 1,
                                   0, 0, 0, 0, 0, NULL), ==,
                    FEMU_SC_INVALID_NS);

    /* Format: refused on the compute namespace; it clears the memory */
    femu_cps_put(&c, 0x40, (const uint8_t *)"abcdefgh", 8, buf);
    g_assert_cmphex(femu_cps_admin(&c, NVME_ADM_CMD_FORMAT_NVM, FEMU_CPS_CP,
                                   0, 0, 0, 0, 0, 0, NULL), ==,
                    FEMU_SC_INVALID_NS);
    g_assert_cmphex(femu_cps_admin(&c, NVME_ADM_CMD_FORMAT_NVM, FEMU_CPS_SLM,
                                   1, 0, 0, 0, 0, 0, NULL), ==,
                    FEMU_SC_INVALID_FORMAT);
    /* a broadcast Format fails on the block namespace and changes nothing */
    g_assert_cmphex(femu_cps_admin(&c, NVME_ADM_CMD_FORMAT_NVM,
                                   NVME_NSID_BROADCAST, 0, 0, 0, 0, 0, 0,
                                   NULL), ==, FEMU_SC_INVALID_FORMAT);
    femu_cps_get(&c, 0x40, log, 8, buf);
    g_assert_cmpint(memcmp(log, "abcdefgh", 8), ==, 0);
    g_assert_cmphex(femu_cps_admin(&c, NVME_ADM_CMD_FORMAT_NVM, FEMU_CPS_SLM,
                                   0, 0, 0, 0, 0, 0, NULL), ==, NVME_SUCCESS);
    femu_cps_get(&c, 0x40, log, 8, buf);
    for (i = 0; i < 8; i++) {
        g_assert_cmphex(log[i], ==, 0);
    }

    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_cps_disable(&c);
}

/* Execute Program with the device-defined programs */
void femu_test_cps_exec(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint8_t w[512], r[512], pdata[24];
    uint32_t rsid;
    uint64_t buf, list, rval, h;
    int i;

    femu_cps_enable(&c, femu, alloc);
    buf = guest_alloc(alloc, 4096);
    list = guest_alloc(alloc, 4096);
    for (i = 0; i < sizeof(w); i++) {
        w[i] = (uint8_t)(i * 31 + 5);
    }
    femu_cps_put(&c, 0x1000, w, sizeof(w), buf);

    /* not activated, then copy range 1 to range 2 through a range set */
    femu_cps_range(&c, list, 0, FEMU_CPS_SLM, 0x1000, 256, false);
    femu_cps_range(&c, list, 1, FEMU_CPS_SLM, 0x8000, 512, false);
    g_assert_cmphex(femu_cps_mrs(&c, 0, 0, 2, list, &rsid), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_cps_exec(&c, 0, rsid, 0, 0, 0, 0, 0, NULL), ==,
                    FEMU_SC_NOT_ACTIVE);
    g_assert_cmphex(femu_cps_pam(&c, 0, 1), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_cps_pam(&c, 1, 1), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_cps_exec(&c, 0, rsid, 0, 0, 0, 0, 0, &rval), ==,
                    NVME_SUCCESS);
    g_assert_cmpuint(rval, ==, 256);
    femu_cps_get(&c, 0x8000, r, sizeof(r), buf);
    g_assert_cmpint(memcmp(r, w, 256), ==, 0);
    for (i = 256; i < sizeof(r); i++) {
        g_assert_cmphex(r[i], ==, 0);
    }

    /* inline ranges in the data buffer, and the program data after them */
    femu_cps_range(&c, list, 0, FEMU_CPS_SLM, 0x1000, 512, false);
    for (i = 0; i < sizeof(pdata); i++) {
        pdata[i] = (uint8_t)(0xa0 + i);
    }
    qtest_memwrite(qts, list + 32, pdata, sizeof(pdata));
    g_assert_cmphex(femu_cps_exec(&c, 1, 0, 1, 32 + sizeof(pdata), list, 0, 0,
                                  &rval), ==, NVME_SUCCESS);
    h = femu_cps_fnv(0xcbf29ce484222325ULL, w, sizeof(w));
    h = femu_cps_fnv(h, pdata, sizeof(pdata));
    /* both halves of the 64-bit return value */
    g_assert_cmphex(rval, ==, h);
    g_assert_cmphex(rval >> 32, !=, 0);
    /* program data only */
    g_assert_cmphex(femu_cps_exec(&c, 1, 0, 0, sizeof(pdata), list + 32, 0, 0,
                                  &rval), ==, NVME_SUCCESS);
    g_assert_cmphex(rval, ==, femu_cps_fnv(0xcbf29ce484222325ULL, pdata,
                                           sizeof(pdata)));

    /* refusals */
    g_assert_cmphex(femu_cps_exec(&c, 16, 0, 0, 0, 0, 0, 0, NULL), ==,
                    FEMU_SC_INVALID_PIND);
    g_assert_cmphex(femu_cps_exec(&c, 5, 0, 0, 0, 0, 0, 0, NULL), ==,
                    FEMU_SC_NO_PROGRAM);
    g_assert_cmphex(femu_cps_exec(&c, 0, rsid + 7, 0, 0, 0, 0, 0, NULL), ==,
                    FEMU_SC_INVALID_RSID);
    g_assert_cmphex(femu_cps_exec(&c, 0, rsid, 1, 32, list, 0, 0, NULL), ==,
                    FEMU_SC_INVALID_FIELD);
    g_assert_cmphex(femu_cps_exec(&c, 0, 0, 1, 31, list, 0, 0, NULL), ==,
                    FEMU_SC_INVALID_FIELD);
    g_assert_cmphex(femu_cps_exec(&c, 0, 0, 129, 129 * 32, list, 0, 0, NULL),
                    ==, FEMU_SC_MAX_RANGES);
    femu_cps_range(&c, list, 0, 1, 0x1000, 512, false);
    g_assert_cmphex(femu_cps_exec(&c, 1, 0, 1, 32, list, 0, 0, NULL), ==,
                    FEMU_SC_INVALID_MEM_NS);
    femu_cps_range(&c, list, 0, FEMU_CPS_SLM, 0x1000, 512, false);
    femu_cps_range(&c, list, 1, FEMU_CPS_SLM, 0x11fc, 8, false);
    g_assert_cmphex(femu_cps_exec(&c, 1, 0, 2, 64, list, 0, 0, NULL), ==,
                    FEMU_SC_OVERLAP_RANGES);
    femu_cps_range(&c, list, 1, FEMU_CPS_SLM, FEMU_CPS_SLM_SIZE - 4, 8, false);
    g_assert_cmphex(femu_cps_exec(&c, 1, 0, 2, 64, list, 0, 0, NULL), ==,
                    FEMU_SC_INVALID_FIELD);
    /* copy needs two ranges; a run refused by the program */
    g_assert_cmphex(femu_cps_exec(&c, 0, 0, 1, 32, list, 0, 0, NULL), ==,
                    FEMU_SC_INVALID_FIELD);

    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_cps_disable(&c);
}

/*
 * Marks its start, sleeps cparam1 milliseconds, fills Memory Range 1 with the
 * low byte of cparam2, marks its end, and returns a value with bit 63 set.
 * The marks are files in femu_cps_dir, so a test knows the program runs.
 */
static const char femu_cps_prog_src[] =
    "#include <stdio.h>\n"
    "#include <time.h>\n"
    "struct args { int numr; void **a; long long *l; long long p1, p2;\n"
    "              void *d; long long dl; } __attribute__((packed));\n"
    "long long run(struct args *a)\n"
    "{\n"
    "    struct timespec t = { a->p1 / 1000, (a->p1 % 1000) * 1000000L };\n"
    "    fclose(fopen(DIR \"/started\", \"w\"));\n"
    "    nanosleep(&t, 0);\n"
    "    if (a->numr > 0) {\n"
    "        unsigned char *p = a->a[0];\n"
    "        for (long long i = 0; i < a->l[0]; i++) {\n"
    "            p[i] = (unsigned char)a->p2;\n"
    "        }\n"
    "    }\n"
    "    fclose(fopen(DIR \"/done\", \"w\"));\n"
    "    return (long long)0x8000000000000011ULL;\n"
    "}\n";

static bool femu_cps_build(void)
{
    g_autofree char *src = g_build_filename(femu_cps_dir, "fill.c", NULL);
    g_autofree char *so = g_build_filename(femu_cps_dir, "fill.so", NULL);
    const char *argv[] = { "cc", "-shared", "-fPIC", "-o", so, src, NULL };
    int wait_status = -1;

    g_autofree char *text = g_strdup_printf("#define DIR \"%s\"\n%s",
                                            femu_cps_dir, femu_cps_prog_src);

    g_assert_cmpint(g_mkdir_with_parents(femu_cps_dir, 0700), ==, 0);
    g_assert_true(g_file_set_contents(src, text, -1, NULL));
    if (!g_spawn_sync(NULL, (char **)argv, NULL, G_SPAWN_SEARCH_PATH |
                      G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL,
                      NULL, NULL, NULL, NULL, &wait_status, NULL)) {
        return false;
    }
    return WIFEXITED(wait_status) && WEXITSTATUS(wait_status) == 0;
}

/* forget the marks of an earlier run */
static void femu_cps_unmark(void)
{
    g_autofree char *s = g_build_filename(femu_cps_dir, "started", NULL);
    g_autofree char *d = g_build_filename(femu_cps_dir, "done", NULL);

    unlink(s);
    unlink(d);
}

/* wait until the program has written its mark @name */
static void femu_cps_wait_mark(const char *name)
{
    g_autofree char *path = g_build_filename(femu_cps_dir, name, NULL);
    int waited = 0;

    while (!g_file_test(path, G_FILE_TEST_EXISTS)) {
        g_assert_cmpint(waited, <, FEMU_POLL_LIMIT_MS);
        g_usleep(1000);
        waited++;
    }
}

static void femu_cps_remove(void)
{
    g_autofree char *src = g_build_filename(femu_cps_dir, "fill.c", NULL);
    g_autofree char *so = g_build_filename(femu_cps_dir, "fill.so", NULL);

    femu_cps_unmark();
    unlink(so);
    unlink(src);
    rmdir(femu_cps_dir);
}

/* load "fill.so\0run\0" at pind in two pieces, the second one first */
static void femu_cps_load_fill(FemuCtrlState *c, uint16_t pind, uint64_t buf)
{
    static const char prog[] = "fill.so\0run";   /* 12 bytes with the NUL */

    qtest_memwrite(c->pdev->bus->qts, buf, prog, sizeof(prog));
    qtest_memwrite(c->pdev->bus->qts, buf + 1024, prog + 8, 4);
    g_assert_cmphex(femu_cps_load(c, pind, FEMU_CP_SHLIB, false,
                                  sizeof(prog), 4, 0, buf), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_cps_load(c, pind, 0, false, 0, 4, 8, buf + 1024), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(femu_cps_load(c, pind, 0, false, 0, 4, 4, buf + 4), ==,
                    NVME_SUCCESS);
}

static void femu_cps_wait_ms(int ms)
{
    g_usleep(ms * 1000);
}

/*
 * Downloaded programs, and what "in use" means: until the completion of an
 * Execute is posted, its program and range set stay in use, even after the
 * program has returned. A program whose command is dropped (queue deleted,
 * controller disabled) writes nothing to the memory namespace.
 */
void femu_test_cps_download(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    FemuQueue q2;
    uint8_t r[256];
    uint32_t rsid;
    uint64_t buf, list, rval;
    NvmeCmd cmd;
    int i;

    if (!femu_cps_build()) {
        femu_cps_remove();
        g_test_skip("no host compiler");
        return;
    }
    femu_cps_enable(&c, femu, alloc);
    buf = guest_alloc(alloc, 4096);
    list = guest_alloc(alloc, 4096);

    g_assert_cmphex(femu_log_cmd(&c, FEMU_CPS_CP, 0x83, FEMU_CSI_CP << 24,
                                 buf, 64), ==, NVME_SUCCESS);
    g_assert_cmpuint(qtest_readl(qts, buf), >=, 1);
    g_assert_cmphex(qtest_readb(qts, buf + 32 +
                                32 * (qtest_readl(qts, buf) - 1)), ==,
                    FEMU_CP_SHLIB);

    /* limits of a first piece */
    g_assert_cmphex(femu_cps_load(&c, 2, FEMU_CP_SHLIB, false, 17 << 20, 4, 0,
                                  buf), ==, FEMU_SC_TOO_BIG);
    g_assert_cmphex(femu_cps_load(&c, 2, FEMU_CP_SHLIB, false, 12, 6, 0, buf),
                    ==, FEMU_SC_INVALID_FIELD);
    g_assert_cmphex(femu_cps_load(&c, 2, FEMU_CP_SHLIB, false, 12, 16, 0, buf),
                    ==, FEMU_SC_INVALID_FIELD);
    /* four programs of 16 MiB fill the 64 MiB; a replacement still loads */
    for (i = 2; i < 6; i++) {
        g_assert_cmphex(femu_cps_load(&c, i, FEMU_CP_SHLIB, false, 16 << 20,
                                      0, 0, buf), ==, NVME_SUCCESS);
    }
    g_assert_cmphex(femu_cps_load(&c, 6, FEMU_CP_SHLIB, false, 4, 0, 0, buf),
                    ==, FEMU_SC_MAX_PBYTES);
    g_assert_cmphex(femu_cps_load(&c, 5, FEMU_CP_SHLIB, false, 16 << 20, 0,
                                  0, buf), ==, NVME_SUCCESS);
    /* a loading program is not a program yet */
    g_assert_cmphex(femu_cps_pam(&c, 2, 1), ==, FEMU_SC_NO_PROGRAM);
    g_assert_cmphex(femu_cps_load(&c, 0xffff, 0, true, 0, 0, 0, 0), ==,
                    NVME_SUCCESS);

    /* invalid program data empties the index */
    qtest_memwrite(qts, buf, "nofile\0run\0\0", 12);
    g_assert_cmphex(femu_cps_load(&c, 2, FEMU_CP_SHLIB, false, 12, 12, 0, buf),
                    ==, FEMU_SC_INVALID_PDATA);
    g_assert_cmphex(femu_cps_load(&c, 2, 0, true, 0, 0, 0, 0), ==,
                    FEMU_SC_NO_PROGRAM);

    femu_cps_load_fill(&c, 2, buf);
    g_assert_cmphex(femu_log_cmd(&c, FEMU_CPS_CP, 0x82, FEMU_CSI_CP << 24,
                                 buf, 256), ==, NVME_SUCCESS);
    g_assert_cmphex(qtest_readb(qts, buf + 64 + 2 * 64), ==, 0x1);
    g_assert_cmphex(qtest_readb(qts, buf + 64 + 2 * 64 + 1), ==,
                    FEMU_CP_SHLIB);
    /* MAXACT is nr_cu, 2 */
    g_assert_cmphex(femu_cps_pam(&c, 0, 1), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_cps_pam(&c, 1, 1), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_cps_pam(&c, 2, 1), ==, FEMU_SC_MAX_ACTIVE);
    g_assert_cmphex(femu_cps_pam(&c, 0xffff, 0), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_cps_pam(&c, 2, 1), ==, NVME_SUCCESS);

    /* runs on a range set; all 64 bits of the return value */
    femu_cps_range(&c, list, 0, FEMU_CPS_SLM, 0x2000, 64, false);
    g_assert_cmphex(femu_cps_mrs(&c, 0, 0, 1, list, &rsid), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_cps_exec(&c, 2, rsid, 0, 0, 0, 0, 0x5a, &rval), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(rval, ==, 0x8000000000000011ULL);
    femu_cps_get(&c, 0x2000, r, 68, buf);
    for (i = 0; i < 64; i++) {
        g_assert_cmphex(r[i], ==, 0x5a);
    }
    g_assert_cmphex(r[64], ==, 0);

    /* in use while running */
    femu_cps_unmark();
    femu_cps_exec_submit(&c, &c.io, 2, rsid, 0, 0, 0, 1500, 0x11);
    femu_cps_wait_mark("started");
    g_assert_cmphex(femu_cps_mrs(&c, 1, rsid, 0, 0, NULL), ==,
                    FEMU_SC_MRS_IN_USE);
    g_assert_cmphex(femu_cps_mrs(&c, 1, 0xffff, 0, 0, NULL), ==,
                    FEMU_SC_MRS_IN_USE);
    g_assert_cmphex(femu_cps_pam(&c, 2, 0), ==, FEMU_SC_PROGRAM_IN_USE);
    g_assert_cmphex(femu_cps_pam(&c, 0xffff, 0), ==, FEMU_SC_PROGRAM_IN_USE);
    g_assert_cmphex(femu_cps_load(&c, 2, 0, true, 0, 0, 0, 0), ==,
                    FEMU_SC_PROGRAM_IN_USE);
    g_assert_cmphex(femu_cps_load(&c, 0xffff, 0, true, 0, 0, 0, 0), ==,
                    FEMU_SC_PROGRAM_IN_USE);
    g_assert_cmphex(femu_cps_load(&c, 2, FEMU_CP_SHLIB, false, 12, 0, 0, buf),
                    ==, FEMU_SC_PROGRAM_IN_USE);
    g_assert_cmphex(femu_cps_exec_wait(&c, &c.io, NULL), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_cps_pam(&c, 2, 0), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_cps_pam(&c, 2, 1), ==, NVME_SUCCESS);

    /*
     * Dropped while it runs: delete the queue, create it again, and let the
     * program end. It wrote nothing, its completion is gone, and the program
     * and set are free at once.
     */
    femu_burst_queue(&c, &q2, 2);
    femu_cps_unmark();
    femu_cps_exec_submit(&c, &q2, 2, rsid, 0, 0, 0, 1500, 0x77);
    femu_cps_wait_mark("started");
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_DELETE_SQ;
    cmd.cdw10 = cpu_to_le32(2);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);
    cmd.opcode = NVME_ADM_CMD_DELETE_CQ;
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);
    femu_queue_free(&c, &q2);
    femu_burst_queue(&c, &q2, 2);
    g_assert_cmphex(femu_cps_pam(&c, 2, 0), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_cps_load(&c, 2, 0, true, 0, 0, 0, 0), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(femu_cps_mrs(&c, 1, rsid, 0, 0, NULL), ==, NVME_SUCCESS);
    /* all of that happened while the program still ran */
    {
        g_autofree char *done = g_build_filename(femu_cps_dir, "done", NULL);

        g_assert_false(g_file_test(done, G_FILE_TEST_EXISTS));
    }
    femu_cps_wait_mark("done");
    femu_cps_wait_ms(500);
    g_assert_false(femu_csd_cq_ready(&c, &q2));
    femu_cps_get(&c, 0x2000, r, 64, buf);
    for (i = 0; i < 64; i++) {
        g_assert_cmphex(r[i], ==, 0x11);
    }

    /*
     * A program a dropped command still runs keeps its bytes counted: with
     * the 64 MiB full, its index cannot take a new program until it returns.
     */
    femu_cps_load_fill(&c, 2, buf);
    for (i = 3; i < 6; i++) {
        g_assert_cmphex(femu_cps_load(&c, i, FEMU_CP_SHLIB, false, 16 << 20,
                                      0, 0, buf), ==, NVME_SUCCESS);
    }
    g_assert_cmphex(femu_cps_load(&c, 6, FEMU_CP_SHLIB, false,
                                  (16 << 20) - 12, 0, 0, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(femu_cps_pam(&c, 2, 1), ==, NVME_SUCCESS);
    femu_cps_range(&c, list, 0, FEMU_CPS_SLM, 0x3000, 64, false);
    femu_cps_unmark();
    femu_cps_exec_submit(&c, &q2, 2, 0, 1, 32, list, 1500, 0x44);
    femu_cps_wait_mark("started");
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = NVME_ADM_CMD_DELETE_SQ;
    cmd.cdw10 = cpu_to_le32(2);
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);
    cmd.opcode = NVME_ADM_CMD_DELETE_CQ;
    g_assert_cmpint(femu_admin(&c, &cmd), ==, NVME_SUCCESS);
    femu_queue_free(&c, &q2);
    femu_burst_queue(&c, &q2, 2);
    g_assert_cmphex(femu_cps_load(&c, 2, FEMU_CP_SHLIB, false, 12, 0, 0, buf),
                    ==, FEMU_SC_MAX_PBYTES);
    femu_cps_wait_mark("done");
    femu_cps_wait_ms(500);
    g_assert_cmphex(femu_cps_load(&c, 2, FEMU_CP_SHLIB, false, 12, 0, 0, buf),
                    ==, NVME_SUCCESS);
    g_assert_cmphex(femu_cps_load(&c, 0xffff, 0, true, 0, 0, 0, 0), ==,
                    NVME_SUCCESS);

    /* and the same across a controller reset */
    femu_cps_load_fill(&c, 3, buf);
    g_assert_cmphex(femu_cps_pam(&c, 3, 1), ==, NVME_SUCCESS);
    femu_cps_range(&c, list, 0, FEMU_CPS_SLM, 0x2000, 64, false);
    femu_cps_unmark();
    femu_cps_exec_submit(&c, &c.io, 3, 0, 1, 32, list, 1500, 0x99);
    femu_cps_wait_mark("started");
    femu_queue_free(&c, &q2);
    femu_cps_disable(&c);
    femu_cps_wait_mark("done");
    femu_cps_wait_ms(500);
    memset(&c, 0, sizeof(c));
    femu_cps_enable(&c, femu, alloc);
    femu_cps_get(&c, 0x2000, r, 64, buf);
    for (i = 0; i < 64; i++) {
        g_assert_cmphex(r[i], ==, 0x11);
    }
    /* the reset retired the command, so the program is free */
    g_assert_cmphex(femu_cps_pam(&c, 3, 0), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_cps_load(&c, 0xffff, 0, true, 0, 0, 0, 0), ==,
                    NVME_SUCCESS);

    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_cps_disable(&c);
    femu_cps_remove();
}

/*
 * In use until the completion is posted: with a large run time scale the
 * program returns long before its modeled end, and the set and program
 * stay in use until the completion arrives.
 */
void femu_test_cps_modeled(void *obj, void *data,
                           QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    FemuCtrlState c = { 0 };
    uint32_t rsid;
    uint64_t buf, list;
    int64_t start;

    if (!femu_cps_build()) {
        femu_cps_remove();
        g_test_skip("no host compiler");
        return;
    }
    femu_cps_enable(&c, femu, alloc);
    buf = guest_alloc(alloc, 4096);
    list = guest_alloc(alloc, 4096);
    femu_cps_load_fill(&c, 2, buf);
    g_assert_cmphex(femu_cps_pam(&c, 2, 1), ==, NVME_SUCCESS);
    femu_cps_range(&c, list, 0, FEMU_CPS_SLM, 0x0, 64, false);
    g_assert_cmphex(femu_cps_mrs(&c, 0, 0, 1, list, &rsid), ==, NVME_SUCCESS);

    /* 20 ms on the host, at least 20 * 100 ms modeled */
    femu_cps_unmark();
    start = g_get_monotonic_time();
    femu_cps_exec_submit(&c, &c.io, 2, rsid, 0, 0, 0, 20, 0x3c);
    /* the program has returned; its completion waits for the modeled end */
    femu_cps_wait_mark("done");
    femu_cps_wait_ms(100);
    g_assert_false(femu_csd_cq_ready(&c, &c.io));
    g_assert_cmphex(femu_cps_mrs(&c, 1, rsid, 0, 0, NULL), ==,
                    FEMU_SC_MRS_IN_USE);
    g_assert_cmphex(femu_cps_pam(&c, 2, 0), ==, FEMU_SC_PROGRAM_IN_USE);
    g_assert_cmphex(femu_cps_exec_wait(&c, &c.io, NULL), ==, NVME_SUCCESS);
    g_assert_cmpint(g_get_monotonic_time() - start, >=, 2 * G_USEC_PER_SEC);
    g_assert_cmphex(femu_cps_mrs(&c, 1, rsid, 0, 0, NULL), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_cps_pam(&c, 2, 0), ==, NVME_SUCCESS);

    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_cps_disable(&c);
    femu_cps_remove();
}

/*
 * MDTS (mdts=1: 8 KiB) bounds what moves to or from the host: Memory Read,
 * Execute data and a Load Program piece. Memory Fill moves no data, so it
 * is not bounded.
 */
void femu_test_cps_mdts(void *obj, void *data, QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint64_t pages, prpl;
    NvmeCmd cmd = { 0 };

    femu_cps_enable(&c, femu, alloc);
    pages = guest_alloc(alloc, 3 * 4096);
    prpl = guest_alloc(alloc, 4096);
    qtest_writeq(qts, prpl, pages + 4096);
    qtest_writeq(qts, prpl + 8, pages + 8192);

    cmd.opcode = FEMU_SLM_READ;
    cmd.nsid = cpu_to_le32(FEMU_CPS_SLM);
    cmd.dptr.prp1 = cpu_to_le64(pages);
    cmd.dptr.prp2 = cpu_to_le64(prpl);
    cmd.cdw12 = cpu_to_le32(12288);
    g_assert_cmphex(femu_io(&c, &cmd), ==, FEMU_SC_INVALID_FIELD);
    cmd.cdw12 = cpu_to_le32(8192);
    cmd.dptr.prp2 = cpu_to_le64(pages + 4096);
    g_assert_cmphex(femu_io(&c, &cmd), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_cps_mem(&c, FEMU_CPS_SLM, FEMU_SLM_FILL, 0, 1 << 16,
                                 0), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_cps_pam(&c, 1, 1), ==, NVME_SUCCESS);
    g_assert_cmphex(femu_cps_exec(&c, 1, 0, 0, 12288, pages, 0, 0, NULL), ==,
                    FEMU_SC_INVALID_FIELD);

    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = FEMU_CP_LOAD;
    cmd.nsid = cpu_to_le32(FEMU_CPS_CP);
    cmd.dptr.prp1 = cpu_to_le64(pages);
    cmd.dptr.prp2 = cpu_to_le64(prpl);
    cmd.cdw10 = cpu_to_le32(2 | FEMU_CP_SHLIB << 16);
    cmd.cdw11 = cpu_to_le32(16384);
    cmd.cdw14 = cpu_to_le32(12288);
    g_assert_cmphex(FEMU_SC(femu_admin(&c, &cmd)), ==, FEMU_SC_INVALID_FIELD);

    guest_free(alloc, prpl);
    guest_free(alloc, pages);
    femu_cps_disable(&c);
}

/*
 * Each SLM command is atomic as a whole. Two queues write a page of 0xaa and
 * a page of 0x55 to the same place while a third reads it, each queue on a
 * poller of its own; every read returns one pattern, never a mix.
 */
void femu_test_cps_slm_atomic(void *obj, void *data,
                              QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    FemuQueue q2, q3;
    uint8_t r[4096];
    uint64_t a, b, rd;
    NvmeCmd cmd;

    femu_cps_enable(&c, femu, alloc);
    femu_burst_queue(&c, &q2, 2);
    femu_burst_queue(&c, &q3, 3);
    a = guest_alloc(alloc, 4096);
    b = guest_alloc(alloc, 4096);
    rd = guest_alloc(alloc, 4096);
    qtest_memset(qts, a, 0xaa, 4096);
    qtest_memset(qts, b, 0x55, 4096);
    for (int i = 0; i < 300; i++) {
        memset(&cmd, 0, sizeof(cmd));
        cmd.nsid = cpu_to_le32(FEMU_CPS_SLM);
        cmd.cdw12 = cpu_to_le32(4096);
        cmd.opcode = FEMU_SLM_WRITE;
        cmd.dptr.prp1 = cpu_to_le64(a);
        femu_submit(&c, &c.io, &cmd);
        cmd.dptr.prp1 = cpu_to_le64(b);
        femu_submit(&c, &q2, &cmd);
        cmd.opcode = FEMU_SLM_READ;
        cmd.dptr.prp1 = cpu_to_le64(rd);
        femu_submit(&c, &q3, &cmd);
        g_assert_cmphex(FEMU_SC(femu_complete(&c, &c.io, NULL, NULL)), ==, 0);
        g_assert_cmphex(FEMU_SC(femu_complete(&c, &q2, NULL, NULL)), ==, 0);
        g_assert_cmphex(FEMU_SC(femu_complete(&c, &q3, NULL, NULL)), ==, 0);
        qtest_memread(qts, rd, r, sizeof(r));
        g_assert_true(r[0] == 0 || r[0] == 0xaa || r[0] == 0x55);
        for (int j = 1; j < sizeof(r); j++) {
            g_assert_cmphex(r[j], ==, r[0]);
        }
    }
    guest_free(alloc, rd);
    guest_free(alloc, b);
    guest_free(alloc, a);
    femu_queue_free(&c, &q3);
    femu_queue_free(&c, &q2);
    femu_cps_disable(&c);
}

/*
 * A memory namespace without a compute namespace, on a controller whose CSD
 * namespace is not the first: Memory Copy reads a NoSSD namespace, and the
 * CP commands are not there.
 */
void femu_test_cps_slm_only(void *obj, void *data,
                            QGuestAllocator *alloc)
{
    QFemu *femu = obj;
    QTestState *qts = femu->dev.bus->qts;
    FemuCtrlState c = { 0 };
    uint8_t w[4096], r[4096];
    NvmeRwCmd rw = { 0 };
    uint64_t buf, list;
    int i;

    femu_cps_enable(&c, femu, alloc);
    buf = guest_alloc(alloc, 4096);
    list = guest_alloc(alloc, 4096);
    g_assert_cmphex(femu_identify(&c, 0, FEMU_CNS_IO_CMD_SET, 0, buf), ==,
                    NVME_SUCCESS);
    g_assert_cmphex(qtest_readb(qts, buf) & 0x18, ==, 0x08);
    g_assert_cmphex(femu_cps_admin(&c, FEMU_CP_PAM, 3, 1 << 16, 0, 0, 0, 0, 0,
                                   NULL), ==, FEMU_SC_INVALID_OPCODE);
    g_assert_cmphex(femu_identify(&c, 0, FEMU_CNS_CS_CTRL, FEMU_CSI_CP << 24,
                                  buf), ==, FEMU_SC_INVALID_FIELD);

    for (i = 0; i < sizeof(w); i++) {
        w[i] = (uint8_t)(i * 3 + 9);
    }
    qtest_memwrite(qts, buf, w, sizeof(w));
    rw.opcode = NVME_CMD_WRITE;
    rw.nsid = cpu_to_le32(1);
    rw.dptr.prp1 = cpu_to_le64(buf);
    rw.slba = cpu_to_le64(8);
    rw.nlb = cpu_to_le16(7);
    g_assert_cmphex(femu_io(&c, (NvmeCmd *)&rw), ==, NVME_SUCCESS);
    femu_cps_cdfe(&c, 1 << 2, buf);
    femu_cps_lba_range(&c, list, 0, 1, 8, 8);
    {
        NvmeCmd cmd = { 0 };

        cmd.opcode = FEMU_SLM_COPY;
        cmd.nsid = cpu_to_le32(3);
        cmd.res1 = cpu_to_le64(4096);
        cmd.dptr.prp1 = cpu_to_le64(list);
        cmd.cdw12 = cpu_to_le32(2 << 8);
        g_assert_cmphex(femu_io(&c, &cmd), ==, NVME_SUCCESS);
    }
    g_assert_cmphex(femu_cps_mem(&c, 3, FEMU_SLM_READ, 0, 4096, buf), ==,
                    NVME_SUCCESS);
    qtest_memread(qts, buf, r, sizeof(r));
    g_assert_cmpint(memcmp(w, r, sizeof(w)), ==, 0);

    guest_free(alloc, list);
    guest_free(alloc, buf);
    femu_cps_disable(&c);
}
