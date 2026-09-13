/* Replay a compiled routed-MoE trace against a preconditioned FEMU namespace.
 *
 * Groups are strict barriers.  Within a group, variable-size O_DIRECT reads are
 * kept at a rolling queue depth.  The program does not fill the device: use the
 * QLC layout materializer and a fresh sequential fill before running it.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/aio_abi.h>
#include <linux/fs.h>
#include <linux/nvme_ioctl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define VERSION 1u
#define FEMU_ADM_FLIP  0xef
#define FEMU_RESET_QLC 8
#define FEMU_SNAP_QLC  9
#define FEMU_ACCUM_QLC_PREFILL 10
#define FEMU_ACCUM_QLC_DECODE 11
#define FEMU_ACCUM_QLC_TEACHER_FORCED 12

static const unsigned char MAGIC[8] = {'M','B','Q','R','P','L','1','\0'};

struct __attribute__((packed)) trace_header {
    unsigned char magic[8];
    uint32_t version, header_bytes, sector_bytes, direct_alignment;
    uint32_t default_qd, max_command_bytes, group_record_bytes, command_record_bytes;
    uint64_t group_count, command_count, total_bytes, max_end_byte;
    unsigned char extent_map_sha256[32], mapped_reads_sha256[32];
};

struct __attribute__((packed)) group_record {
    uint64_t group_id;
    int64_t release_after_group_id;
    uint64_t forward_id;
    int32_t layer;
    uint8_t phase, cache_reset;
    uint16_t reserved;
    uint32_t command_count, request_index;
};

struct __attribute__((packed)) command_record {
    uint64_t lba_start;
    uint32_t sector_count;
    uint8_t page_class;
    uint8_t reserved[3];
};

_Static_assert(sizeof(struct trace_header) == 136, "trace header size");
_Static_assert(sizeof(struct group_record) == 40, "group record size");
_Static_assert(sizeof(struct command_record) == 16, "command record size");

struct slot {
    struct iocb cb;
    void *buffer;
    struct command_record command;
    uint32_t local_index;
    uint64_t submit_ns;
    bool active;
};

static void usage(const char *program)
{
    fprintf(stderr,
        "usage:\n"
        "  %s --trace TRACE --dry-run\n"
        "  %s --trace TRACE --device /dev/nvme0n1 --controller /dev/nvme0\n"
        "     --group-log GROUPS.jsonl --summary RUN.json [--io-log IOS.jsonl]\n"
        "     [--qd 32] [--skip-qlc-counters] [--buffered]\n",
        program, program);
}

static void fail(const char *message)
{
    if (errno) fprintf(stderr, "fatal: %s: %s\n", message, strerror(errno));
    else fprintf(stderr, "fatal: %s\n", message);
    exit(1);
}

static void read_exact(FILE *stream, void *buffer, size_t size, const char *what)
{
    if (fread(buffer, 1, size, stream) != size) {
        errno = 0;
        fprintf(stderr, "fatal: truncated %s\n", what);
        exit(1);
    }
}

static uint64_t now_ns(void)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &value)) fail("clock_gettime");
    return (uint64_t)value.tv_sec * 1000000000ull + (uint64_t)value.tv_nsec;
}

static const char *phase_name(uint8_t phase)
{
    static const char *names[] = {"prefill", "decode", "teacher_forced"};
    return phase < 3 ? names[phase] : "invalid";
}

static int qlc_accum_command(uint8_t phase)
{
    static const int commands[] = {
        FEMU_ACCUM_QLC_PREFILL,
        FEMU_ACCUM_QLC_DECODE,
        FEMU_ACCUM_QLC_TEACHER_FORCED,
    };
    if (phase >= sizeof commands / sizeof commands[0]) {
        errno = 0;
        fail("invalid phase for QLC accounting");
    }
    return commands[phase];
}

static FILE *open_exclusive(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0) fail(path);
    FILE *stream = fdopen(fd, "w");
    if (!stream) fail("fdopen");
    return stream;
}

static int aio_setup_sys(unsigned entries, aio_context_t *context)
{
    return (int)syscall(__NR_io_setup, entries, context);
}
static int aio_submit_sys(aio_context_t context, long nr, struct iocb **iocbs)
{
    return (int)syscall(__NR_io_submit, context, nr, iocbs);
}
static int aio_getevents_sys(aio_context_t context, long min_nr, long nr,
                             struct io_event *events)
{
    return (int)syscall(__NR_io_getevents, context, min_nr, nr, events, NULL);
}
static int aio_destroy_sys(aio_context_t context)
{
    return (int)syscall(__NR_io_destroy, context);
}

static void hash_hex(const unsigned char hash[32], char output[65])
{
    static const char digits[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        output[2*i] = digits[hash[i] >> 4];
        output[2*i+1] = digits[hash[i] & 15];
    }
    output[64] = 0;
}

static int femu_flip(const char *controller, uint32_t selector)
{
    int fd = open(controller, O_RDONLY);
    if (fd < 0) return -1;
    struct nvme_admin_cmd command;
    memset(&command, 0, sizeof command);
    command.opcode = FEMU_ADM_FLIP;
    command.cdw10 = selector;
    int result = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &command);
    int saved = errno;
    close(fd);
    errno = saved;
    return result;
}

static struct trace_header read_header(FILE *trace)
{
    struct trace_header header;
    read_exact(trace, &header, sizeof header, "trace header");
    uint16_t endian = 1;
    if (*(unsigned char *)&endian != 1) { errno = 0; fail("little-endian host required"); }
    if (memcmp(header.magic, MAGIC, 8) || header.version != VERSION
        || header.header_bytes != sizeof header
        || header.group_record_bytes != sizeof(struct group_record)
        || header.command_record_bytes != sizeof(struct command_record)
        || header.sector_bytes != 512 || header.direct_alignment < 512
        || !header.default_qd || !header.max_command_bytes) {
        errno = 0; fail("binary trace header mismatch");
    }
    return header;
}

static uint32_t preflight(FILE *trace, const struct trace_header *header)
{
    uint64_t commands = 0, bytes = 0, max_end = 0;
    int64_t previous = -1;
    uint32_t max_group = 0;
    for (uint64_t expected = 0; expected < header->group_count; expected++) {
        struct group_record group;
        read_exact(trace, &group, sizeof group, "group record");
        if (group.group_id != expected || group.phase > 2 || group.reserved
            || (group.cache_reset && group.release_after_group_id != -1)
            || (!group.cache_reset && group.release_after_group_id != previous)) {
            errno = 0; fail("group ordering/dependency mismatch");
        }
        if (group.command_count > max_group) max_group = group.command_count;
        for (uint32_t index = 0; index < group.command_count; index++) {
            struct command_record command;
            read_exact(trace, &command, sizeof command, "command record");
            if (command.lba_start > UINT64_MAX / header->sector_bytes) {
                errno = 0; fail("command offset overflow");
            }
            uint64_t size = (uint64_t)command.sector_count * header->sector_bytes;
            uint64_t offset = command.lba_start * header->sector_bytes;
            if (!command.sector_count || command.page_class > 3
                || size > header->max_command_bytes
                || offset % header->direct_alignment || size % header->direct_alignment
                || command.reserved[0] || command.reserved[1] || command.reserved[2]) {
                errno = 0; fail("invalid command record");
            }
            if (offset > UINT64_MAX - size || bytes > UINT64_MAX - size) {
                errno = 0; fail("command total overflow");
            }
            commands++;
            bytes += size;
            if (offset + size > max_end) max_end = offset + size;
        }
        previous = (int64_t)group.group_id;
    }
    if (fgetc(trace) != EOF || commands != header->command_count
        || bytes != header->total_bytes || max_end != header->max_end_byte) {
        errno = 0; fail("trace length/totals mismatch");
    }
    return max_group;
}

static int free_slot(struct slot *slots, uint32_t qd)
{
    for (uint32_t i = 0; i < qd; i++) if (!slots[i].active) return (int)i;
    return -1;
}

int main(int argc, char **argv)
{
    const char *trace_path = NULL, *device = NULL, *controller = NULL;
    const char *group_path = NULL, *io_path = NULL, *summary_path = NULL;
    uint32_t qd_override = 0;
    bool dry_run = false, skip_counters = false, buffered = false;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--trace") && ++i < argc) trace_path = argv[i];
        else if (!strcmp(argv[i], "--device") && ++i < argc) device = argv[i];
        else if (!strcmp(argv[i], "--controller") && ++i < argc) controller = argv[i];
        else if (!strcmp(argv[i], "--group-log") && ++i < argc) group_path = argv[i];
        else if (!strcmp(argv[i], "--io-log") && ++i < argc) io_path = argv[i];
        else if (!strcmp(argv[i], "--summary") && ++i < argc) summary_path = argv[i];
        else if (!strcmp(argv[i], "--qd") && ++i < argc) qd_override = (uint32_t)strtoul(argv[i], NULL, 10);
        else if (!strcmp(argv[i], "--dry-run")) dry_run = true;
        else if (!strcmp(argv[i], "--skip-qlc-counters")) skip_counters = true;
        else if (!strcmp(argv[i], "--buffered")) buffered = true;
        else { usage(argv[0]); return 2; }
    }
    if (!trace_path || (!dry_run && (!device || !group_path || !summary_path
                                     || (!skip_counters && !controller)))) {
        usage(argv[0]); return 2;
    }
    FILE *trace = fopen(trace_path, "rb");
    if (!trace) fail(trace_path);
    struct trace_header header = read_header(trace);
    uint32_t max_group = preflight(trace, &header);
    uint32_t qd = qd_override ? qd_override : header.default_qd;
    if (!qd || qd > 4096) { errno = 0; fail("queue depth must be in [1, 4096]"); }
    char layout_hash[65], mapped_hash[65];
    hash_hex(header.extent_map_sha256, layout_hash);
    hash_hex(header.mapped_reads_sha256, mapped_hash);
    if (dry_run) {
        printf("trace valid: groups=%" PRIu64 " commands=%" PRIu64
               " bytes=%" PRIu64 " max_group=%u qd=%u max_end=%" PRIu64 "\n",
               header.group_count, header.command_count, header.total_bytes,
               max_group, qd, header.max_end_byte);
        fclose(trace); return 0;
    }

    int flags = O_RDONLY | (buffered ? 0 : O_DIRECT);
    int device_fd = open(device, flags);
    if (device_fd < 0) fail(device);
    uint64_t device_bytes = 0;
    if (ioctl(device_fd, BLKGETSIZE64, &device_bytes)) {
        struct stat st;
        if (fstat(device_fd, &st) || !S_ISREG(st.st_mode)) fail("BLKGETSIZE64/fstat");
        device_bytes = (uint64_t)st.st_size;
    }
    if (header.max_end_byte > device_bytes) { errno = 0; fail("trace exceeds device size"); }

    struct slot *slots = calloc(qd, sizeof *slots);
    struct io_event *events = calloc(qd, sizeof *events);
    if (!slots || !events) fail("allocate queue state");
    for (uint32_t i = 0; i < qd; i++) {
        int rc = posix_memalign(&slots[i].buffer, header.direct_alignment,
                                header.max_command_bytes);
        if (rc) { errno = rc; fail("posix_memalign"); }
    }
    aio_context_t context = 0;
    if (aio_setup_sys(qd, &context)) fail("io_setup");
    FILE *group_log = open_exclusive(group_path);
    FILE *io_log = io_path ? open_exclusive(io_path) : NULL;
    FILE *run_summary = open_exclusive(summary_path);
    /* The complete group log is below 1 MiB for the supplied traces.  Keep it
     * out of the timed groups and flush after replay.  Per-I/O logging remains
     * a diagnostic mode whose overhead is explicitly visible. */
    if (setvbuf(group_log, NULL, _IOFBF, 4u << 20)) fail("setvbuf group log");
    if (setvbuf(run_summary, NULL, _IOFBF, 4096)) fail("setvbuf summary");

    if (!skip_counters) {
        if (!controller || femu_flip(controller, FEMU_RESET_QLC))
            fail("FEMU QLC counter reset");
    }
    rewind(trace);
    (void)read_header(trace);
    uint64_t origin = now_ns(), sum_group_io = 0;
    uint64_t observed_commands = 0, observed_bytes = 0;
    uint8_t counter_phase = UINT8_MAX;
    for (uint64_t expected = 0; expected < header.group_count; expected++) {
        struct group_record group;
        read_exact(trace, &group, sizeof group, "group record during replay");
        /* Every preceding group is complete here. Attribute its physical NAND
         * counter delta before the next phase starts; requests may alternate
         * prefill/decode multiple times in one compiled trace. */
        if (!skip_counters && counter_phase != UINT8_MAX
                && group.phase != counter_phase) {
            if (femu_flip(controller, qlc_accum_command(counter_phase)))
                fail("FEMU QLC phase accumulation");
        }
        counter_phase = group.phase;
        struct command_record *commands = NULL;
        if (group.command_count) {
            commands = malloc((size_t)group.command_count * sizeof *commands);
            if (!commands) fail("allocate group commands");
            read_exact(trace, commands, (size_t)group.command_count * sizeof *commands,
                       "group commands during replay");
        }
        uint64_t ready = now_ns(), first_submit = 0, last_submit = 0, last_complete = ready;
        uint64_t group_requested_bytes = 0;
        for (uint32_t index = 0; index < group.command_count; index++)
            group_requested_bytes +=
                (uint64_t)commands[index].sector_count * header.sector_bytes;
        uint32_t next = 0, completed = 0, in_flight = 0, peak = 0;
        while (completed < group.command_count) {
            while (next < group.command_count && in_flight < qd) {
                int index = free_slot(slots, qd);
                if (index < 0) { errno = 0; fail("queue bookkeeping"); }
                struct slot *slot = &slots[index];
                slot->command = commands[next];
                slot->local_index = next;
                memset(&slot->cb, 0, sizeof slot->cb);
                slot->cb.aio_data = (uint64_t)index + 1;
                slot->cb.aio_lio_opcode = IOCB_CMD_PREAD;
                slot->cb.aio_fildes = (uint32_t)device_fd;
                slot->cb.aio_buf = (uint64_t)(uintptr_t)slot->buffer;
                slot->cb.aio_nbytes = (uint64_t)slot->command.sector_count * header.sector_bytes;
                slot->cb.aio_offset = (int64_t)(slot->command.lba_start * header.sector_bytes);
                struct iocb *pointer = &slot->cb;
                slot->submit_ns = now_ns();
                int submitted;
                do submitted = aio_submit_sys(context, 1, &pointer); while (submitted < 0 && errno == EINTR);
                if (submitted != 1) fail("io_submit");
                slot->active = true;
                if (!first_submit) first_submit = slot->submit_ns;
                last_submit = now_ns();
                next++; in_flight++;
                if (in_flight > peak) peak = in_flight;
            }
            int count;
            do count = aio_getevents_sys(context, 1, qd, events); while (count < 0 && errno == EINTR);
            if (count <= 0) fail("io_getevents");
            uint64_t observed = now_ns();
            for (int i = 0; i < count; i++) {
                if (!events[i].data || events[i].data > qd) { errno = 0; fail("invalid AIO user data"); }
                struct slot *slot = &slots[events[i].data - 1];
                uint64_t expected_bytes = (uint64_t)slot->command.sector_count * header.sector_bytes;
                if (!slot->active || events[i].res != (int64_t)expected_bytes || events[i].res2) {
                    errno = events[i].res < 0 ? (int)-events[i].res : 0;
                    fail("asynchronous read completion");
                }
                if (io_log) fprintf(io_log,
                    "{\"group_id\":%" PRIu64 ",\"command_index\":%u,"
                    "\"lba_start\":%" PRIu64 ",\"sector_count\":%u,\"page_class\":%u,"
                    "\"submit_ns\":%" PRIu64 ",\"completion_observed_ns\":%" PRIu64 ","
                    "\"observed_latency_ns\":%" PRIu64 "}\n",
                    group.group_id, slot->local_index, slot->command.lba_start,
                    slot->command.sector_count, slot->command.page_class,
                    slot->submit_ns-origin, observed-origin, observed-slot->submit_ns);
                slot->active = false;
                in_flight--; completed++;
                observed_commands++;
                observed_bytes += expected_bytes;
            }
            last_complete = observed;
        }
        uint64_t group_io = first_submit ? last_complete - first_submit : 0;
        sum_group_io += group_io;
        if (group.command_count) {
            fprintf(group_log,
                "{\"group_id\":%" PRIu64 ",\"request_index\":%u,\"forward_id\":%" PRIu64
                ",\"layer\":%d,\"phase\":\"%s\",\"cache_reset\":%s,"
                "\"release_after_group_id\":%" PRId64 ",\"command_count\":%u,"
                "\"requested_bytes\":%" PRIu64 ",\"peak_outstanding\":%u,"
                "\"group_ready_ns\":%" PRIu64 ",\"first_submit_ns\":%" PRIu64 ","
                "\"last_submit_ns\":%" PRIu64 ",\"last_complete_ns\":%" PRIu64 ","
                "\"group_io_ns\":%" PRIu64 "}\n",
                group.group_id, group.request_index, group.forward_id, group.layer,
                phase_name(group.phase), group.cache_reset ? "true" : "false",
                group.release_after_group_id, group.command_count,
                group_requested_bytes,
                peak, ready-origin, first_submit-origin, last_submit-origin,
                last_complete-origin, group_io);
        } else {
            fprintf(group_log,
                "{\"group_id\":%" PRIu64 ",\"request_index\":%u,\"forward_id\":%" PRIu64
                ",\"layer\":%d,\"phase\":\"%s\",\"cache_reset\":%s,"
                "\"release_after_group_id\":%" PRId64 ",\"command_count\":0,"
                "\"requested_bytes\":0,\"peak_outstanding\":0,"
                "\"group_ready_ns\":%" PRIu64 ",\"first_submit_ns\":null,"
                "\"last_submit_ns\":null,\"last_complete_ns\":%" PRIu64 ","
                "\"group_io_ns\":0}\n",
                group.group_id, group.request_index, group.forward_id, group.layer,
                phase_name(group.phase), group.cache_reset ? "true" : "false",
                group.release_after_group_id, ready-origin, ready-origin);
        }
        free(commands);
    }
    uint64_t wall = now_ns() - origin;
    if (observed_commands != header.command_count || observed_bytes != header.total_bytes) {
        errno = 0; fail("replay totals mismatch");
    }
    fflush(group_log); if (io_log) fflush(io_log);
    if (!skip_counters) {
        if (counter_phase != UINT8_MAX
                && femu_flip(controller, qlc_accum_command(counter_phase)))
            fail("FEMU final QLC phase accumulation");
        if (femu_flip(controller, FEMU_SNAP_QLC))
            fail("FEMU QLC counter snapshot");
    }
    fprintf(run_summary,
        "{\n  \"schema\": \"moe-bcq-replay-result-v1\",\n"
        "  \"queue_depth\": %u,\n  \"direct_io\": %s,\n"
        "  \"qlc_counters\": \"%s\",\n"
        "  \"groups\": %" PRIu64 ",\n  \"commands\": %" PRIu64 ",\n"
        "  \"requested_bytes\": %" PRIu64 ",\n"
        "  \"wall_ns_including_log_overhead\": %" PRIu64 ",\n"
        "  \"sum_group_io_ns\": %" PRIu64 ",\n"
        "  \"extent_map_sha256\": \"%s\",\n"
        "  \"mapped_reads_sha256\": \"%s\"\n}\n",
        qd, buffered ? "false" : "true",
        skip_counters ? "skipped" : "reset_phase_accumulated_and_snapshotted",
        header.group_count,
        observed_commands, observed_bytes, wall, sum_group_io, layout_hash, mapped_hash);
    fflush(run_summary);

    fclose(run_summary); if (io_log) fclose(io_log); fclose(group_log);
    if (aio_destroy_sys(context)) fail("io_destroy");
    for (uint32_t i = 0; i < qd; i++) free(slots[i].buffer);
    free(events); free(slots); close(device_fd); fclose(trace);
    return 0;
}
