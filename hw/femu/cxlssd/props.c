/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Property help text for femu-cxl-ssd. The properties it inherits from
 * cxl-type3 are described in the generated reference instead, so that this
 * device does not change the help text of the parent type.
 */
#include "qemu/osdep.h"
#include "../femu-props.h"

static const FemuPropDesc cxl_descs[] = {
    /* cache */
    { "cache-pages",
      "Number of 4 KiB pages the device cache holds; 0 sends every access "
      "to the media, otherwise at most the media page count and divisible "
      "by cache-ways" },
    { "cache-policy",
      "Cache replacement policy, one of fifo, lifo, clock or s3-fifo; "
      "unset is fifo" },
    /* media */
    { "ftl",
      "Charge cache misses and write-backs to the FTL and NAND model; off "
      "keeps memory behaviour with no media timing and cannot be linked to "
      "an NVMe controller" },
    { "channels",
      "Number of NAND channels, 1 to 4096" },
    { "luns-per-channel",
      "NAND LUNs per channel, 1 to 128, with one plane per LUN" },
    { "pages-per-block",
      "4 KiB pages per NAND block, 1 to 65536" },
    { "blocks-per-plane",
      "NAND blocks per plane, 2 to 65536 and enough to cover the media; 0 "
      "sizes it to 5/4 of the media plus 4 blocks per plane" },
    { "gc-threshold",
      "Percent of lines in use at which background garbage collection "
      "starts, 1 to 100" },
    { "gc-threshold-high",
      "Percent of lines in use at which garbage collection is forced, from "
      "gc-threshold to 100" },
    { "read-ns",
      "NAND page read time in ns, at most one second" },
    { "program-ns",
      "NAND page program time in ns, at most one second" },
    { "erase-ns",
      "NAND block erase time in ns, at most one second" },
    { "channel-ns",
      "NAND channel transfer time per page in ns, at most one second" },
    { "cylon-first-touch-program",
      "Charge a NAND program instead of a free read when a read reaches a "
      "page the FTL has never mapped, as the Cylon experiments do" },
    { "cylon-free-writeback",
      "Write dirty pages back on eviction and flush with no NAND program "
      "and no media time, as the Cylon experiments do" },

    /* direct endpoint remapping */
    { "der",
      "Direct mapping of cached pages into the guest: off (MMIO only, the "
      "default), memslot (KVM memory slot aliases, not under TCG) or "
      "cylon (a Cylon host kernel)" },
    { "der-replace-rate",
      "With der=memslot and no free alias (1024 shared by all devices, "
      "fewer if KVM has fewer free slots), the most aliases per second a "
      "repeatedly missing page may displace; 0 disables replacement" },
    { "cylon-kernel-ack",
      "Must be on with der=cylon to state that the host runs a Cylon kernel "
      "with the dual-slot fixes; the device does not check it" },
    { "cylon-never-emulate",
      "With der=cylon and cylon-emul-exit on, ask the host kernel for version "
      "2 of the Cylon fault exit: an access to a cold page exits with its "
      "type and FEMU maps the page, so KVM emulates only pages FEMU cannot "
      "map; per VM, set by the first Cylon device that installs its slot" },
    { "cylon-emul-exit",
      "With der=cylon, ask the host kernel to return accesses it cannot "
      "decode on unmapped pages to FEMU, which maps the page; off keeps "
      "stock KVM behaviour (a guest #UD or an internal error) only if no "
      "other device of the VM turned the VM-wide capability on" },
    { "concurrent-misses",
      "Let misses to different pages wait for the media together; auto "
      "does so only while direct mapping is active" },

    /* caching API, control and logs */
    { "cca",
      "Expose the caching API on BAR 5 (pin, unpin, invalidate, uncached "
      "ranges, query) and start its worker thread" },
    { "lsa-control",
      "Accept experiment control commands through Get LSA on an internal "
      "128 MiB label area; trusted guests only, and not with an lsa "
      "backend" },
    { "log-dir",
      "Host directory for cxlssd-stats.log, cxlssd-io-N.log and "
      "cxlssd-spt.log; unset is the working directory" },
    { "tracefs-dir",
      "Host tracefs directory whose tracing control commands 91 and 81 "
      "write; unset, those commands change nothing on the host" },
    { "log-limit",
      "Size limit in bytes for each log file the device writes; 0 opens no "
      "I/O log and takes no statistics appends" },
    { NULL, NULL }
};

static const FemuPropDesc cxl_runtime_descs[] = {
    /* cache tunables, also accepted on -device */
    { "cache-ways",
      "Entries per cache set, non-zero and dividing cache-pages (1 is direct "
      "mapped); default 16, and a qom-set at run time writes back and "
      "rebuilds the cache" },
    { "prefetch-degree",
      "Up to this many pages inserted into the cache after each demand "
      "miss, at most the media page count, with no NAND read; default 0, "
      "changeable with qom-set" },
    { "prefetch-stride",
      "Distance in pages from a missed page to the first prefetched page, "
      "at most the media page count; default 1, changeable with qom-set" },

    /* actions and control */
    { "der-ratio",
      "Run time only: direct-map this fraction of pages, one of 0, 50, "
      "75, 90, 95, 97, 98, 99, 995 (99.5%), 999 (99.9%) or 100 percent; "
      "needs der other than off and no uncached ranges, and der=memslot "
      "refuses a ratio whose unmapped gaps outnumber the free aliases" },
    { "control-command",
      "Run time only: writing runs that experiment control command with "
      "control-argument before qom-set returns; reading gives the last "
      "command" },
    { "control-argument",
      "Argument for the next control-command write; reading gives the "
      "last argument used, which a Get LSA control command also sets" },
    { "control-status",
      "Read-only result of the last control command: 0 success, 1 error, "
      "2 a Get LSA command still queued" },
    { "flush-cache",
      "Write-only: true revokes direct mappings, writes dirty pages back, "
      "drops unpinned pages and waits for the modelled media time" },
    { "stats-reset",
      "Write-only: true copies the counters to the last-* properties, then "
      "clears the event counters" },
    { "fast-load",
      "Accesses skip only their wait for the modelled media time; the FTL, "
      "cache and counters still run. For warmup and loading, not for "
      "measurement. Setting false waits for the queued NAND work first; "
      "default off, changeable with qom-set" },
    { "fast-load-drain-ns",
      "Read-only: ns the last fast-load switch to false waited for queued "
      "NAND work" },

    /* cache counters */
    { "cache-entries",
      "Read-only gauge: pages resident in the cache, pinned ones included" },
    { "cache-hits",
      "Read-only event counter: MMIO page lookups that found a resident "
      "page" },
    { "cache-misses",
      "Read-only event counter: MMIO page lookups that missed, including "
      "accesses with no cache" },
    { "read-hits",
      "Read-only event counter: cache-hits caused by reads" },
    { "read-misses",
      "Read-only event counter: cache-misses caused by reads" },
    { "write-hits",
      "Read-only event counter: cache-hits caused by writes" },
    { "write-misses",
      "Read-only event counter: cache-misses caused by writes" },
    { "cache-inserts",
      "Read-only event counter: pages admitted by demand misses, prefetch "
      "and PIN fills" },
    { "cache-evictions",
      "Read-only event counter: pages the replacement policy removed, "
      "including those a flush or a cache-ways change drops" },
    { "prefetch-inserts",
      "Read-only event counter: pages inserted by prefetch" },
    { "last-read-hits",
      "Read-only: read-hits at the last stats-reset or control command 1" },
    { "last-read-misses",
      "Read-only: read-misses at the last stats-reset or control command 1" },
    { "last-write-hits",
      "Read-only: write-hits at the last stats-reset or control command 1" },
    { "last-write-misses",
      "Read-only: write-misses at the last stats-reset or control command "
      "1" },
    { "last-inserts",
      "Read-only: cache-inserts at the last stats-reset or control command "
      "1" },
    { "last-evictions",
      "Read-only: cache-evictions at the last stats-reset or control "
      "command 1" },
    { "last-entries",
      "Read-only: cache-entries at the last stats-reset or control command "
      "1" },
    { "last-prefetch-inserts",
      "Read-only: prefetch-inserts at the last stats-reset or control "
      "command 1" },

    /* media counters */
    { "media-time-ns",
      "Read-only: total modelled media time in ns returned by FTL requests, "
      "including contention" },
    { "media-reads",
      "Read-only: page reads the FTL performed for cache fills, uncached "
      "reads and PIN fills, not counting reads that "
      "cylon-first-touch-program turned into programs; stays 0 with "
      "ftl=off" },
    { "media-writes",
      "Read-only: user page programs counted by the FTL, garbage "
      "collection copies excluded, refreshed at each media request of "
      "this device, so writes from a linked NVMe controller appear after "
      "the next one" },
    { "media-full",
      "Read-only: accesses whose NAND program found no free page; that "
      "program is not timed and the access completes uncached, though a "
      "fill read already issued is charged; stats-reset keeps it, and a "
      "measurement is valid only while it is 0" },

    /* direct mapping counters */
    { "der-active",
      "Read-only: whether direct mapping is available on this device" },
    { "der-probes",
      "Read-only: probe attempts, one per realize with der=cylon" },
    { "der-mapped",
      "Read-only gauge: pages currently mapped for direct guest access" },
    { "der-remaps",
      "Read-only: direct page mappings installed" },
    { "der-revocations",
      "Read-only: direct page mappings removed" },
    { "der-quiet-revocations",
      "Read-only: Cylon revocations of entries whose accessed bit was "
      "clear, done without a TLB flush" },
    { "der-replacements",
      "Read-only: memslot aliases displaced by a hotter page" },
    { "der-fallbacks",
      "Read-only: refused direct mapping attempts and device "
      "disablements" },
    { "der-emul-exit",
      "Read-only: whether the host kernel returns Cylon accesses it cannot "
      "emulate to FEMU (KVM_CAP_CYLON_FAULT_EXIT)" },
    { "der-emul-fills",
      "Read-only: exits for an access KVM could not decode that FEMU served "
      "by a fill and a mapping, repeats and cache hits included; not "
      "instructions or unique pages; stats-reset keeps it" },
    { "der-emul-v2",
      "Read-only: whether version 2 of the Cylon fault exit is on for the "
      "VM (cylon-never-emulate)" },
    { "der-fault-reads",
      "Read-only: version 2 exits for a data read of a cold page; "
      "stats-reset keeps it" },
    { "der-fault-writes",
      "Read-only: version 2 exits for a data write to a cold page; "
      "stats-reset keeps it" },
    { "der-fault-fetches",
      "Read-only: version 2 exits for an instruction fetch from a cold "
      "page; stats-reset keeps it" },
    { "der-fault-page-walks",
      "Read-only: version 2 exits for a guest page walk that read a cold "
      "page-table page; stats-reset keeps it" },
    { "der-fault-unprotected",
      "Read-only: version 2 fills left unprotected because the instruction "
      "already held 16 pages; stats-reset keeps it" },
    { "der-fault-emulated",
      "Read-only: pages handed back to KVM's emulator because FEMU could "
      "not map them (uncached range, pinned set, full medium); "
      "stats-reset keeps it" },
    { "der-emul-fetch-fills",
      "Read-only: the der-emul-fills exits for code the guest executed from "
      "an unmapped page; stats-reset keeps it" },
    { "der-emul-failures",
      "Read-only: such exits FEMU could not serve (unmappable page or no "
      "progress); each one stops the VM; stats-reset keeps it" },

    /* caching API counters */
    { "cca-commands",
      "Read-only event counter: caching API commands completed, whatever "
      "their status" },
    { "cca-errors",
      "Read-only event counter: caching API commands completed with a "
      "non-zero status" },
    { "cca-pinned",
      "Read-only gauge: pages currently pinned in the cache" },
    { "cca-uncached",
      "Read-only gauge: pages currently in caching API uncached ranges" },
    { "cca-pin-fills",
      "Read-only event counter: pages PIN read from the media" },
    { "cca-writebacks",
      "Read-only event counter: dirty pages programmed by caching API "
      "commands" },
    { "cca-dropped",
      "Read-only event counter: resident pages dropped by INVALIDATE and "
      "CACHE_DISABLE" },
    { "cca-pinned-set-misses",
      "Read-only event counter: misses served from the media because every "
      "way of the set is pinned" },

    /* other */
    { "invalidations",
      "Read-only: generation count bumped by PCI configuration writes, "
      "component register writes, every mailbox command other than a "
      "control Get LSA, and reset; each revokes all direct mappings" },
    { "nvme-drops",
      "Read-only: resident pages a linked NVMe write, copy or deallocate "
      "dropped or cleaned" },
    { "log-dropped",
      "Read-only: statistics appends refused, I/O logs closed at log-limit "
      "and SPT dumps truncated" },
    { NULL, NULL }
};

void femu_cxl_describe_props(ObjectClass *oc)
{
    femu_describe_class(oc, cxl_descs);
}

void femu_cxl_describe_runtime(Object *obj)
{
    femu_describe_object(obj, cxl_runtime_descs);
}
