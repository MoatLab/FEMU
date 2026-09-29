/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * ccactl: drive the femu-cxl-ssd caching API from a guest shell.
 *
 *   ccactl [-d DEV] [-f] [-t MS] info
 *   ccactl [-d DEV] [-f] [-t MS] nop
 *   ccactl [-d DEV] [-f] [-t MS] pin|unpin|invalidate|disable|enable|query
 *          LPN COUNT | all
 *   ccactl [-d DEV] reset [all]
 */
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "cca.h"

static void usage(void)
{
    fprintf(stderr,
            "usage: ccactl [-d DEV] [-f] [-t MS] COMMAND [LPN COUNT | all]\n"
            "  DEV       mem0, a PCI address, or a resource5 path\n"
            "  -f        force: unpin pinned pages (invalidate, disable)\n"
            "  -t MS     command timeout, negative waits forever\n"
            "  COMMAND   info nop pin unpin invalidate disable enable query\n"
            "            reset [all]\n"
            "  LPN COUNT a range of 4 KiB device pages; 'all' is the media\n");
    exit(2);
}

/* Decimal or 0x-prefixed page numbers; they never reach 2^63. */
static int parse_u64(const char *s, uint64_t *v)
{
    int64_t value;
    int used = 0;

    if (sscanf(s, "%" SCNi64 "%n", &value, &used) != 1 || s[used] ||
        value < 0) {
        return -EINVAL;
    }
    *v = value;
    return 0;
}

int main(int argc, char **argv)
{
    static const struct {
        const char *name;
        uint32_t cmd;
    } cmds[] = {
        { "pin", CCA_CTRL_PIN },
        { "unpin", CCA_CTRL_UNPIN },
        { "invalidate", CCA_CTRL_INVALIDATE },
        { "disable", CCA_CTRL_CACHE_DISABLE },
        { "enable", CCA_CTRL_CACHE_ENABLE },
        { "query", CCA_CTRL_QUERY },
    };
    const char *dev = NULL;
    struct cca_result r;
    struct cca_dev *d;
    unsigned flags = 0;
    uint64_t lpn = 0;
    uint64_t count = CCA_WHOLE;
    int timeout = -2;
    unsigned i;
    int opt;
    int rc;

    while ((opt = getopt(argc, argv, "d:ft:h")) != -1) {
        switch (opt) {
        case 'd':
            dev = optarg;
            break;
        case 'f':
            flags |= CCA_FLAG_FORCE;
            break;
        case 't':
            timeout = atoi(optarg);
            break;
        default:
            usage();
        }
    }
    if (optind >= argc) {
        usage();
    }
    rc = cca_open(dev, &d);
    if (rc) {
        fprintf(stderr, "ccactl: open %s: %s\n", dev ? dev : "(auto)",
                strerror(-rc));
        return 1;
    }
    if (timeout != -2) {
        cca_set_timeout(d, timeout);
    }
    if (!strcmp(argv[optind], "info")) {
        struct cca_info info;

        cca_info(d, &info);
        printf("version %u\nmedia_pages %" PRIu64 "\ncache_pages %u\n"
               "cache_ways %u\npin_limit %u\ncompleted %" PRIu64 "\n",
               info.version, info.media_pages, info.cache_pages,
               info.cache_ways, info.pin_limit, info.completed);
        cca_close(d);
        return 0;
    }
    if (!strcmp(argv[optind], "nop")) {
        rc = cca_nop(d);
        printf("status %d (%s)\n", rc, cca_strerror(rc));
        cca_close(d);
        return rc ? 1 : 0;
    }
    if (!strcmp(argv[optind], "reset")) {
        int all = optind + 1 < argc && !strcmp(argv[optind + 1], "all");

        rc = cca_reset(d, all);
        printf("reset %s: %s\n", all ? "all" : "rings", cca_strerror(rc));
        cca_close(d);
        return rc ? 1 : 0;
    }
    for (i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++) {
        if (!strcmp(argv[optind], cmds[i].name)) {
            break;
        }
    }
    if (i == sizeof(cmds) / sizeof(cmds[0])) {
        cca_close(d);
        usage();
    }
    if (optind + 1 < argc && strcmp(argv[optind + 1], "all")) {
        if (optind + 2 >= argc || parse_u64(argv[optind + 1], &lpn) ||
            parse_u64(argv[optind + 2], &count)) {
            cca_close(d);
            usage();
        }
    } else if (optind + 1 >= argc) {
        cca_close(d);
        usage();
    }
    switch (cmds[i].cmd) {
    case CCA_CTRL_PIN:
        rc = cca_pin(d, lpn, count, &r);
        break;
    case CCA_CTRL_UNPIN:
        rc = cca_unpin(d, lpn, count, &r);
        break;
    case CCA_CTRL_INVALIDATE:
        rc = cca_invalidate(d, lpn, count, flags, &r);
        break;
    case CCA_CTRL_CACHE_DISABLE:
        rc = cca_cache_disable(d, lpn, count, flags, &r);
        break;
    case CCA_CTRL_CACHE_ENABLE:
        rc = cca_cache_enable(d, lpn, count, &r);
        break;
    default:
        rc = cca_query(d, lpn, count, &r);
        break;
    }
    printf("status %d (%s)\npages %" PRIu64 "\n", rc, cca_strerror(rc),
           r.pages);
    if (cmds[i].cmd == CCA_CTRL_QUERY && !rc) {
        printf("resident %" PRIu64 "\ndirty %" PRIu64 "\npinned %" PRIu64
               "\nuncached %" PRIu64 "\n", r.resident, r.dirty, r.pinned,
               r.uncached);
    }
    cca_close(d);
    return rc ? 1 : 0;
}
