<!--
SPDX-License-Identifier: GPL-2.0-or-later
-->

# CXL SSD design

The opt-in `femu-cxl-ssd` device subclasses QEMU's CXL Type-3 device. It takes
an ordinary volatile memory backend, preserving standard decoder translation,
capacity reporting, CDAT construction, and media-disable checks. It introduces
no additional NVMe controller and changes no existing FEMU mode. Migration is
explicitly blocked because the FTL and cache do not have migration state.

## QEMU integration

`cxlssd/qemu-adapter.c` owns the QOM subclass and all dependencies on QEMU's
CXL device layout, fixed windows, routing, decoders, CCI state and KVM ioctls.
`cxlssd.c` owns the media worker and cache/FTL access through the FEMU interface
in `qemu-adapter.h`; the cache and SPTE helpers remain independent libraries.

Each fixed window has one shared FEMU I/O overlay while FEMU endpoints exist.
Installation runs at machine-init-done, or immediately for later realization.
The overlay remains installed through reset and decoder changes. Routing uses
the host bridge's live decoder state before endpoint translation. A selected
non-FEMU endpoint is forwarded by direct dispatch to the original window.
Only the FEMU overlay disables its reentrancy guard. FEMU realization rejects
multi-target windows and endpoints behind switches. Endpoint translation
accepts non-interleaved volatile decoders, including DPA skip and decoder
ordering; unsupported live decoder settings return a transaction error.
Disabled-media reads return random bytes and writes are discarded successfully.

Only two generic hooks remain outside `hw/femu/`: an opaque KVM memslot
reservation, protected by the slot lock and excluded from listener allocation
and free capacity; and a per-CCI pre-command callback. The CCI callback runs
for every transport without replacing command handlers or changing the
handler-identity checks. PCI configuration writes chain the inherited method,
component writes forward through an overlay, and reset chains the parent's
Resettable hold phase while preserving the legacy-reset trampoline.

FEMU drains and revokes before these parent operations. It frees all three
CCI background timers and pending sanitize state before reset or unplug,
leaving the primary mutex to the parent's exit method. Restricted volatile
backend validation and explicit ownership let failed realization release its
mapped flag without repeating the parent's address-space destruction. The
upstream Type-3 timer and general realize-unwind fixes are not retained;
these protections apply to FEMU only.

## Media and cache

The payload resides in the supplied host memory backend. The cache holds
page numbers, dirty state and eviction metadata. A miss reads the corresponding
page through `bb_ftl_process_req()`. An unmapped page has no read cost, but
its contents come from the backend and are not cleared: they read as zero only
when the backend is zero-filled, as a fresh `memory-backend-ram` is. Writes to
resident pages become dirty. Dirty eviction or `flush-cache=true` issues a
real FTL write; without a cache, each write goes straight to the FTL. The guest
access waits for the returned media completion cost by spinning on the realtime clock with the BQL released. This is volatile memory, not a persistence contract for guest CPU cache
flush instructions.

`ssd_init()`, `bb_ftl_process_req()`, `ssd_free()` and the shared NAND media are
reused directly. There is no renamed copy of the old FTL. Master supplies
mapping, allocation, GC, media accounting, and its current timing fixes. The
private controller context has no PCI queues or enabled optional NVMe features.
The CXL cache replaces the need for a second enabled bbssd write buffer. NAND
geometry is 512-byte sectors, eight sectors per page, 256 pages per block, four
channels, four LUNs per channel and one plane per LUN. Blocks per plane are
`(size / 16 MiB) * 5 / 4 + 4`; the extra space reserves room for GC. Timings are
configurable. Current bbssd request processing supplies background and forced
GC. NAND type-specific and advanced NVMe experiment properties are not exposed
through this device.

FIFO removes the oldest entry; LIFO removes the newest. CLOCK rotates entries
until it finds an entry without a reference. S3-FIFO has small, main and bounded
ghost queues, promotes reused small entries, and decrements main-entry
frequency during eviction. All policies use initialized queues even at WAY_1.
Keys use full 64-bit equality rather than a truncating comparator. The cache
library can be built independently of QEMU.

## Thread ownership

CXL MMIO arrives on vCPU threads under the BQL; qtest and management operations
also hold it. The BQL protects payload copies, cache membership, counters and
DER mappings. A per-device operation gate serializes accesses, cache flushes
and teardown across waits. Gate waiters release the BQL using a condition
variable. Invalidation never waits: configuration writes, component writes and
CCI commands run inside another owner's re-entrancy guard, and blocking there
would refuse unrelated accesses from other vCPUs. It revokes DER mappings at
once and bumps the read-only `invalidations` generation; an access in flight
does not install a mapping when the generation moved during its media delay. An access holds an object reference until completion;
teardown marks the device closing, waits for the gate, and prevents new work.
A waiter re-routes and re-translates after entering the gate and completes at
the current DPA, or with random data when media became disabled, as the parent
Type-3 device would; only an address that no longer decodes fails.

The requesting thread drops the BQL both while handing work to the FTL worker
and during the remaining media delay, while retaining the operation gate.
Other vCPUs can run and access other devices; accesses to this device queue
behind the current operation. The worker mutex protects the single stack-owned
request and completion, and is released before reacquiring the BQL. The worker
alone modifies FTL/NAND state. Cache iterators, entries, payload and access
latency accounting stay stable because flush and teardown wait for the gate
and invalidation touches only DER mappings. The FEMU-owned fixed-window overlay disables its own I/O recursion guard.
It dispatches FEMU media directly, so no parent window guard remains engaged
across a BQL wait. The component-register overlay revokes and then enters the
parent register callback without waiting. Plain Type-3 callbacks retain their normal guard.
Read-only QOM counters may show an operation in progress.
The worker is joined before its state is destroyed.

The worker receives only page numbers, operation types and timestamps. It
never reads or writes guest memory. Payload copies remain on the vCPU thread.
Any future worker-side guest-memory operation must use `femu_dma_rw()`; the
existing NVMe poller DMA rules are unchanged.

## Direct Endpoint Remapping

The `der` string selects `off` (the default), `memslot`, or `cylon`. Other
values, including the former boolean spelling `on`, fail property validation.
`der=cylon` additionally requires `cylon-kernel-ack=on` (default off), including
on hosts where activation would fall back. It states that the host runs a Cylon
kernel with the dual-slot fixes described under "Host kernel" below; the device
cannot verify that, and the published kernel is unsafe without them.
`off` performs no probe and prints no DER message. `memslot` uses QEMU RAM
aliases and the ordinary KVM listener without any Cylon ioctl dependency; qtest
can exercise these mappings directly. All modes expose read-only QOM
`der-active`, `der-probes`, `der-mapped`, `der-remaps`, `der-revocations` and
`der-fallbacks`. Mapped is a current gauge; remaps and revocations count completed
page operations; fallbacks count rejected mapping attempts or device disablement.
For Cylon, active becomes true only after installing and validating the slot.

Both direct modes require non-interleaved pages in a single-target CXL window,
with the endpoint directly below a root port on a host bridge without HDM
decoding. Memslot pressure leaves additional pages on MMIO without reducing
cache capacity. Every memslot-mapped entry is conservatively dirty because
alias writes cannot notify cache metadata. Direct hits in either mode do not
update CLOCK/S3-FIFO reference metadata or MMIO hit counters.

### Cylon interface and memory ownership

Realize probes the published `KVM_GET_LINEAR_SPT` (0xde, VM ioctl) and
`KVM_SET_SPTE_FLAG` (0xdd, vCPU ioctl). GET uses an absent GFN, which returns
EINVAL before dereferencing `slot->aux`; SET uses flag zero, the kernel's
remote TLB flush operation. No KVM, stock KVM and qtest all retain MMIO and
emit exactly one warning. Intel EPT, EPT A/D, TDP MMU and MMIO caching must be
enabled. No private full-SPTE ioctl is used.

The payload backend must be hugetlbfs (including hugetlb memfd), shared and
preallocated, with huge-page-aligned address and size. The device locks it
with `mlock()` and resolves each huge page through `/proc/self/pagemap`.
Nonpresent or zero PFNs, missing CAP_SYS_ADMIN, invalid alignment or addresses,
and locking failure refuse activation with a reason. There is no contiguous
`hpa_base`: each 4 KiB payload address uses its own huge page's resolved base
plus its offset within that page. The backend remains locked until teardown.

The first eligible decoded access schedules a main-loop callback to register
a dual-mode slot with `KVM_SET_USER_MEMORY_REGION`. FEMU reserves its slot ID
through the generic KVM reservation API. The slot's host address is the payload
backend itself; no separate faulting allocation exists. Its flag is
CylonLinux's `KVM_MEMSLOT_DUAL_MODE` (bit 17). The fixed host kernel must enforce
4 KiB leaves even though the payload uses huge pages.

Before registration, FEMU checks complete writable I/O coverage of the window,
the selected endpoint, and linear translation across every decoder boundary.
The slot covers exactly the window and backend size. Reservation ownership and
registered state are checked before SPT access. Cylon and ordinary RAM-alias
DER are mutually exclusive. A FEMU memory listener deletes the external slot
in `begin()` before any map update can expose overlapping RAM; re-admission
requires fresh coverage and routing checks after commit. Dirty-ring logging
refuses activation, and global dirty-log start revokes and disables Cylon.

Installation pauses vCPUs before registration because the published kernel
publishes a slot before allocating its SPT storage. Pending installation holds
a window reference and a generation; invalidation or teardown cancels stale
work even while the callback waits for vCPUs. Detached state is freed after
pending installation and RCU readers finish. Slot deletion precedes SPT unmap,
backing unlock and reservation release. Failed deletion terminates QEMU rather
than releasing an ID or payload that the kernel might still use.

GET receives one untouched `MAP_SHARED | MAP_ANONYMOUS` VMA per used chunk,
sized exactly to `min(remaining SPT bytes, 4 MiB)`. This matches the published
x86 Cylon kernel and prototype (`MAX_ORDER=10`, 4 KiB pages); a differently
configured ABI is unsupported and must be reviewed before acknowledging it.
A 256 MiB window needs 512 KiB of SPT; a 64 GiB window needs 32 chunks.
Installation explicitly checks the sixty-entry ioctl limit before slot creation.
Returned count, pointers, offsets and lengths must describe a contiguous,
nonoverlapping SPT covering exactly the slot. `/proc/self/smaps` must report
`pf` for each exact VMA; there is no sentinel write or pre-ioctl page fault.
This detects absent remaps. SPT areas are unmapped after successful slot deletion.

#### Host kernel

The published CylonLinux 6.4.6 corrupts host memory with this interface: slot
tables were freed with their shadow pages and again by the slot destructor,
allocation failures were ignored, and the ioctl could remap over live PTEs.
The fixes are on MoatLab/Cylon `master`. Besides
ownership (one shadow page per slot table under a per-slot lock, headers freed
after RCU, 4 KiB leaves only, tables allocated while the slot is prepared),
two fixes are needed for DER to work at all: the first access to a page is
treated as MMIO (otherwise KVM's emulator writes the slot's backing instead of
exiting), and existing tables are dropped when the slot is created (otherwise
ordinary tables from before the slot stay linked and direct entries are never
used). Nonzero `KVM_SET_SPTE_FLAG` operations are refused; only the flush
remains.

The fixed kernel still requires, and does not check: SMM disabled
(`-machine smm=off`), identical CPUID on every vCPU (one TDP root role), and
no move or flag change of the dual slot. Tables that were mapped to userspace
are never freed: about 8 bytes per 4 KiB page of the window per slot.

### SPTE encoding, dirty tracking and revocation

The formats come from CylonLinux `arch/x86/kvm/mmu/spte.h`, `spte.c`, `mmu.c`
and `tdp_mmu.c`, and the Intel EPT definitions used there. Direct entries have
RWX permissions, WB memory type, ignore-PAT, accessed, MMU-present and the
host/MMU-writable software bits (57 and 58). Dirty (bit 9) starts clear. The
address mask covers bits 12 through 51. All fields have named constants.

EPT MMIO has W/X without R (binary 110), the guest page address and split
memslot-generation fields (bits 3..10 and 52..62). The prototype's `0x586`
contains generation 0xb0; it is not a timeless MMIO mask. For a populated leaf, the implementation saves the exact kernel-created
MMIO entry, including runtime generation and host reserved-address mitigation
bits. It restores that entry on revocation; the kernel refreshes a stale MMIO
generation itself. Empty leaves are admitted by CAS and restored to zero. Unit tests check the fixed encodings, the full generation
range, noncontiguous huge-page arithmetic and boundary/overflow rejection.

Each admission checks the window offset, SPT index and resolved physical
address, rechecks that the corresponding huge-page PFN has not changed, then
compare-and-swaps the observed empty or MMIO entry to a direct entry and invokes SET
to flush. A lost exchange leaves the page on MMIO. Zero, MMIO and frozen
`REMOVED_SPTE` entries are KVM revocations: mark the cache entry dirty and drop
the tracking record without disabling Cylon or overwriting KVM's entry.
Flush before retiring that record because a kernel zap may precede completion
of its remote TLB invalidation. An
unexpected existing mapping, invalid layout or ioctl failure restores saved
MMIO entries, attempts flushes, deletes the external slot to invalidate
all remaining translations, conservatively dirties affected cache entries,
disables Cylon for the device and logs once. Failed registration remains MMIO
instead of aborting realize. Fatal handling of a failed KVM
slot deletion is retained because execution cannot safely continue with stale
translations.

Revocation first clears both EPT W and MMU-writable atomically and flushes writable TLB
entries. It then samples the hardware dirty bit while compare-and-swapping the saved
MMIO SPTE and flushes again. Exchanges retry hardware dirty-bit changes and
leave concurrent KVM revocations intact. A concurrent kernel replacement makes the page
conservatively dirty. Thus clean direct reads need no program, while writes
and uncertain transitions do. This requires EPT A/D; hosts without it stay
MMIO rather than guessing that a page is clean.

Both modes revoke before eviction programming, explicit cache flush,
decoder/configuration writes, reset, CCI commands and device removal. Warm
reset retains volatile payload and cache/FTL contents but revokes mappings.
Cylon deletes its slot on every invalidation and cache-page revocation,
sampling tracked dirty state first. Later eligible accesses can reinstall it.
Failure and teardown also delete the slot and release its mapped SPT VMAs. The FTL worker is joined
before its state is destroyed. Payload backing belongs to the host memory
backend. Direct hits do not enter QEMU or read pagemap.

### Host and guest restrictions

`mlock()` prevents ordinary reclaim; it does **not** pin a hugetlb PFN against
migration. Memory offline, soft-offline and explicit migration can move it.
The admission-time pagemap recheck detects movement that already happened and
falls back, but cannot close the check/use race or detect movement while a
guest uses an existing direct mapping. Runs must exclude these migration
operations for their lifetime. A host-side pinning and invalidation protocol
is needed to remove that restriction; the two Cylon ioctls do not provide one.

KVM's own guest-memory reads/writes use the payload backing, so emulator
page walks, instruction fetch and paravirtual structures see the same bytes
as direct EPT accesses. These KVM-internal accesses do not enter FEMU's cache
or timing model and may not update its dirty metadata. The payload correction
removes the separate-backing data-consistency restriction on system RAM;
system-RAM guest operation still needs end-to-end validation. Direct hits also
remain outside the per-access timing model.

The direct encoding assumes coherent DMA (WB plus ignore-PAT). Non-coherent
assigned devices are unsupported: KVM otherwise derives the memory type from
guest MTRRs. Configuration/CCI invalidation remains deliberately conservative;
every message/write can revoke all cached mappings and incur VM-wide flushes.
SET's published implementation uses a full-VM flush, even for one page.
CAS avoids overwriting an already changed entry; it does not serialize with
all KVM write-lock paths. Kernel-side coordination is still required for a
complete SPTE concurrency contract.

## Earlier defects

The nine items in the earlier summary are covered as follows:

1. Full-width hash keys avoid the old GTree comparator overflow, including the
   second defective comparator in the old FTL initialization path.
2. FEMU owns external slot deletion and reservation release; ordinary DER
   aliases continue to use QEMU listener allocation and deletion.
3. Clearing frees entries and ghost history; destruction frees the hash and
   every queue. No tree is abandoned or recreated.
4. Admission and eviction counters are centralized for every policy.
5. There is no unresolved eviction declaration.
6. S3-FIFO WAY_1 uses the same initialized queue representation as other ways.
7. CLOCK WAY_1 also uses that queue representation.
8. Every new source is tracked and wired into the build.
9. No unused alternate cache implementation is imported.

The old `pqueue_peek()` loop is a real concurrency hazard; it is replaced by
per-request completion. The old no-op `flush_pg()` preserved payload bytes but
omitted NAND programs and timing; dirty eviction now charges both. The tests
include a mutation restoring the no-op and demonstrate the missing program.

## Scope and validation limits

The Cylon Caching API, its ivshmem device and control ring are omitted.
Concurrent NVMe access to the same medium, persistent CXL storage,
dynamic capacity and migration are outside this implementation. Guest kernel
boot/enumeration and long-running workloads require separate system testing.

Qtests program actual PCI bridges and HDM registers, then access the CXL fixed
memory window. They cover all four policies at one and sixteen ways, data
readback, dirty programming, media timing, invalid configuration, no-FTL mode,
qtest fallback, mapping revocation, mixed-window forwarding, topology
refusal, overlay ownership and teardown. A stock-KVM qtest exercises reserved
slot exclusion, capacity accounting and reuse after release. Standalone tests cover
policy ordering, S3-FIFO promotion and ghost admission, full-width keys,
repeated clearing and dirty accounting over all policies at one through
thirty-two ways. The memslot qtests validate QEMU mappings. Cylon is deliberately inert under
qtest, so they cannot validate custom-kernel compatibility.

The FEMU lifecycle tests, including background reset followed by unplug,
exercise the local protections. Plain Type-3 lifecycle fixes remain outside
this implementation. Stock-KVM reservation testing does not validate Cylon's custom
slot flag, SPT mappings, memory-map revocation or guest system-RAM operation;
those still require a fixed Cylon host and guest runs.

With the fixed kernel, a nested run under KASAN (18 guest lifetimes, region
teardown and re-creation, 1 and 4 vCPUs) reported nothing, and a bare-metal run
on a Xeon Gold 6548Y+ with a 256 MiB window and a 1024-page cache passed
page-stride write/readback across two eviction cycles in every mode. Median
load latency on a cached page was about 3.0 us with `der=off`, 105 ns with
`memslot` and 105 ns with `cylon`; sequential reads of cached data ran at
2.5 MiB/s, 345 MiB/s and 2.4 GiB/s. With `cylon`, EPT dirty bits kept media
writes to the pages actually written. Not covered: long workloads, hugetlb
migration during a run, and guests that online the range as system RAM.

## Experiment controls

`lsa-control=on` enables the Cylon guest command convention:
`cxl read-labels mem0 -s COMMAND -O ARGUMENT`. It defaults off. With it on,
FEMU supplies a zero-initialized internal 128 MiB LSA; no label memdev is
needed or accepted. This accommodates every supported page-count argument
at the maximum capacity. The buffer is volatile and loses its contents at
unplug. With control off, an optional ordinary `lsa` memory backend uses the
parent's normal label semantics. Reads with control on return the requested
length, with byte zero reporting success (0) or an invalid command/argument
(1); `control-status` reports the same result over QOM. Mailbox bounds errors
still use the standard CXL status. Reads exceeding the active transport's
payload capacity return no data and set `control-status=1`, protecting the
mailbox output buffer. Get-LSA on the primary mailbox leaves DER
intact so inspecting statistics does not destroy experiment mappings; other
CCI commands/transports retain conservative invalidation.

Every command is also available through QOM: set `control-argument`, then
set `control-command`. QOM errors report invalid arguments directly. These
host controls work with `lsa-control=off` too.

| Size/command | Argument and effect |
| --- | --- |
| 1 | Append a statistics snapshot tagged with the argument, then reset cache counters |
| 2 | Revoke mappings and flush/clear cached pages |
| 3 | Cylon ways selector: 0..4 means 1, 2, 4, 8, 16 ways; 5 means fully associative |
| 5 | Set prefetch degree |
| 7 | Set prefetch stride |
| 9, 11 | Flush/clear the cache, as in Cylon; keep the configured DER mode |
| 13, 15 | Start a new per-access log / close it |
| 17 | Dump current tracked direct mappings and Cylon SPTE values |
| 90, 80 | Set direct ratio / revoke and reset it |
| 91, 81 | Enable / disable QEMU memory-region read/write trace events |

The trace command numbering follows Cylon's implementation (91 starts,
81 stops). The QEMU events are global and use the configured trace backend;
`-D FILE` selects the log-backend destination. If `tracefs-dir` is set,
commands also write its `tracing_on` file without invoking a shell.
`log-dir` selects the directory for `cxlssd-stats.log`, `cxlssd-io-N.log` and
`cxlssd-spt.log`; it defaults to the working directory. An unavailable output
warns once per device and the device continues. I/O logs contain realtime
start timestamp, R/W, byte DPA, byte length and modeled media nanoseconds.
Direct CPU hits do not enter QEMU and cannot appear in these logs.

QOM exposes `read-hits`, `read-misses`, `write-hits`, `write-misses`,
`cache-entries` and `prefetch-inserts`, alongside existing aggregate/cache,
media and DER counters. `stats-reset=true` resets cache and prefetch event
counters, preserving membership, media totals and DER totals. The previous
snapshot remains in `last-read-hits`, `last-read-misses`, `last-write-hits`,
`last-write-misses`, `last-inserts`, `last-evictions`, `last-entries` and
`last-prefetch-inserts`. Runtime way changes preserve event totals.

`prefetch-degree` defaults to zero and `prefetch-stride` to one. Both are
runtime QOM properties bounded by media page count. Only a miss triggers
prefetch, after inserting the demanded page: insert the interval
`[lpn + stride, lpn + stride + degree)`, skipping resident and out-of-range
pages. Prefetch performs no NAND read. Dirty victims still follow the chosen
writeback policy. Prefetched pages are eligible for DER. A small cache may
evict the demanded page during prefetch, matching the insertion order.

`cache-ways` is a runtime QOM property with no 1024-way cap. It must divide
`cache-pages`; set it equal to `cache-pages` for fully associative operation.
Changing it drains accesses, revokes mappings, flushes dirty pages and rebuilds
the cache. All policies support one way. Resident and ghost membership use
hash tables, queue-end removal is constant time, and CLOCK/S3-FIFO eviction
is amortized constant time rather than a scan proportional to associativity
on every operation. The large standalone test uses 1,258,291 entries.

## Geometry and timing compatibility

Capacity may be 256 MiB through 120 GiB in 256 MiB increments. The upper limit
comes from sixty 4 MiB SPT chunks at eight bytes per 4 KiB media page, and
includes Cylon's 48/96 GiB configurations. `ftl=off` avoids allocating an
unused NAND model. With the FTL on, payload and NAND metadata both consume
host memory; capacity acceptance is not a claim of tested sustained operation
at those sizes.

The following realize-time properties feed the existing bbssd FTL:
`channels` (4), `luns-per-channel` (4), `pages-per-block` (256),
`blocks-per-plane` (0 = automatic overprovisioning), `channel-ns` (0),
`gc-threshold` (75) and `gc-threshold-high` (95). Sectors remain 512 bytes,
eight per page, with one plane per LUN. Axis limits follow the FTL's PPA
fields; aggregate sectors must fit its signed integer totals. Explicit NAND
capacity must cover media capacity. Thresholds must lie in 1..100, with the
high threshold at least the low threshold. Geometry without spare space can
run out of writable pages; automatic geometry reserves extra space.

`cylon-first-touch-program=on` charges a NAND program instead of a read on
first access to an unmapped page. `cylon-free-writeback=on` suppresses NAND
programming on dirty cache eviction/flush. Both default off and exist to
reproduce Cylon paper experiments; enabling them changes the media model.
The default continues to program dirty eviction and reads unmapped pages
without a NAND operation. Media waits spin on the realtime clock outside
the BQL and retain the device operation gate. This removes sleep timer slack
but consumes a host CPU while waiting. The virtual clock cannot measure this
host wait; qtests validate modeled timing and BQL release independently.

## Direct ratios

`der-ratio` is a runtime QOM property equivalent to commands 90/80. Zero resets
it. Values 50, 75, 90, 95, 97, 98, 99, 995 and 999 match Cylon's periodic
selection (exclude each 2nd, 4th, 10th, 20th, 33rd, 50th, 100th, 200th or
1000th page, starting with page zero); 100 selects every page. In particular,
97 means 32/33, and 995/999 mean 99.5/99.9 percent. Other values are rejected.
This selection spans the entire device independently of cache membership.
Memslot mode coalesces adjacent selected pages into aliases; slot pressure
can leave part of the selection on MMIO, reflected in `der-mapped` and
`der-fallbacks`. Cylon mode installs the dual slot asynchronously if necessary
and applies the selection to its leaves. An empty leaf can be installed with
CAS and restored to zero on revocation without inventing an MMIO generation;
existing MMIO leaves retain their exact kernel encoding. The fixed kernel's
preallocated 4 KiB leaf ownership is required for this operation.

Ratio mappings are independent of cache residency; cache eviction does not
remove a selected ratio mapping. Direct accesses have no NAND timing and
uncached direct writes have no modeled NAND writeback, matching this Cylon
experiment mode. Reset, decoder changes, flush and teardown revoke mappings;
reapply a ratio after those operations to restore its entire selection.
With DER off or unavailable, the ratio remains queryable but mappings stay
inactive. `der-mapped`, not the requested ratio, is the activation evidence.
Custom-kernel ratio installation, zero-leaf restoration and dirty revocation
still require guest validation.

`hw/femu/scripts/run-cxlssd.sh` exposes size, a default five-percent cache,
fully associative or explicit ways, policy, prefetch, geometry, timings,
GC, control/logging and compatibility switches through environment variables.
For example, use `CXL_SIZE=96G CHANNELS=8 LUNS_PER_CHANNEL=8
BLOCKS_PER_PLANE=1536 CACHE_POLICY=clock PREFETCH_DEGREE=3` and supply guest
boot arguments. `DRY_RUN=1` prints the command. `CXL_BACKEND` can supply a
shared/preallocated hugetlb backend configuration for Cylon; explicitly set
`CYLON_KERNEL_ACK=on` only on the fixed host kernel. The script changes no
host tuning, allocates no huge pages itself and never invokes sudo.
