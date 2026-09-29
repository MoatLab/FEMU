<!--
SPDX-License-Identifier: GPL-2.0-or-later
-->

# CXL SSD design

The opt-in `femu-cxl-ssd` device subclasses QEMU's CXL Type-3 device. It takes
an ordinary volatile memory backend, preserving standard decoder translation,
capacity reporting, CDAT construction, and media-disable checks. It introduces
no additional NVMe controller and changes no existing FEMU mode. Migration is
explicitly blocked because the FTL and cache do not have migration state.

## Media and cache

The payload resides in the supplied host memory backend. The cache holds
page numbers, dirty state and eviction metadata. A miss reads the corresponding
page through `bb_ftl_process_req()`. An unmapped page has no read cost, but
its contents come from the backend and are not cleared: they read as zero only
when the backend is zero-filled, as a fresh `memory-backend-ram` is. Writes to
resident pages become dirty. Dirty eviction or `flush-cache=true` issues a
real FTL write; without a cache, each write goes straight to the FTL. The guest
access waits for the returned media completion cost using a sleep, not a busy
loop. This is volatile memory, not a persistence contract for guest CPU cache
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
DER mappings. A per-device operation gate serializes accesses, cache flushes,
invalidation and teardown across waits. Gate waiters release the BQL using a
condition variable. An access holds an object reference until completion;
teardown marks the device closing, waits for the gate, and prevents new work.
A waiter rechecks decoder translation and media state before using its DPA.

The requesting thread drops the BQL both while handing work to the FTL worker
and during the remaining media delay, while retaining the operation gate.
Other vCPUs can run and access other devices; accesses to this device queue
behind the current operation. The worker mutex protects the single stack-owned
request and completion, and is released before reacquiring the BQL. The worker
alone modifies FTL/NAND state. Cache iterators, entries, payload and access
latency accounting stay stable because invalidation, flush and teardown wait
for the gate. The fixed-window dispatcher temporarily releases its I/O recursion guard only
for a managed memory callback, which owns this serialization and performs no
recursive guest DMA. The Cylon forwarding region uses the same contract.
Without this, simultaneous accesses would be rejected before reaching the
gate. Plain Type-3 callbacks retain their normal guard.
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

The first decoded access installs a dedicated trapping I/O region over the
whole window. QEMU's existing KVM listener assigns and owns its slot, including
zero-size removal and TLB invalidation. Its flag is CylonLinux's
`KVM_MEMSLOT_DUAL_MODE` (bit 17). The I/O region forwards QEMU accesses to the
original CXL window, preserving decoder/media checks. A separate anonymous
non-THP backing keeps KVM's leaf level at 4 KiB; direct SPTEs point exclusively
to the verified hugetlb payload, never this faulting backing. The slot must
cover exactly the window and backend size, and its listener record must match
both range and backing before GET or any mapping update. The first access
schedules a main-loop callback; it does not pause vCPUs inside MMIO. That
callback pauses vCPUs before registration, because the published kernel
publishes a slot before allocating its SPT storage. Teardown can
cancel a pending install even while the callback waits for vCPUs. The callback
retains its window reference, and detached Cylon state is freed after pending
installation and RCU flatview readers have finished.

GET receives one untouched `MAP_SHARED | MAP_ANONYMOUS` VMA per used chunk,
sized exactly to `min(remaining SPT bytes, 4 MiB)`. This matches the published
x86 Cylon kernel and prototype (`MAX_ORDER=10`, 4 KiB pages); a differently
configured ABI is unsupported and must be reviewed before acknowledging it.
A 256 MiB window needs 512 KiB of SPT; a 64 GiB window needs 32 chunks.
Installation explicitly checks the sixty-entry ioctl limit before slot creation.
Returned count, pointers, offsets and lengths must describe a contiguous,
nonoverlapping SPT covering exactly the slot. `/proc/self/smaps` must report
`pf` for each exact VMA; there is no sentinel write or pre-ioctl page fault.
This detects absent remaps. SPT areas are unmapped before slot deletion.

#### Host kernel

The published CylonLinux 6.4.6 corrupts host memory with this interface: slot
tables were freed with their shadow pages and again by the slot destructor,
allocation failures were ignored, and the ioctl could remap over live PTEs.
The fixes are on the `fix/dualslot-lifetime` branch of MoatLab/Cylon. Besides
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
contains generation 0xb0; it is not a timeless MMIO mask. The implementation
waits for a KVM fault to populate a leaf and saves that exact kernel-created
MMIO entry, including runtime generation and host reserved-address mitigation
bits. It restores that entry on revocation; the kernel refreshes a stale MMIO
generation itself. Unit tests check the fixed encodings, the full generation
range, noncontiguous huge-page arithmetic and boundary/overflow rejection.

Each admission checks the window offset, SPT index and resolved physical
address, rechecks that the corresponding huge-page PFN has not changed, then
compare-and-swaps the observed MMIO entry to a direct entry. That entry is
not present, so no TLB holds a translation from it and nothing is flushed, as
KVM does not flush when a fault fills a non-present entry. A lost exchange
leaves the page on MMIO. Zero, MMIO and frozen
`REMOVED_SPTE` entries are KVM revocations: mark the cache entry dirty and drop
the tracking record without disabling Cylon or overwriting KVM's entry.
Flush before retiring that record because a kernel zap may precede completion
of its remote TLB invalidation. An
unexpected existing mapping, invalid layout or ioctl failure restores saved
MMIO entries, attempts flushes, removes the listener-owned slot to invalidate
all remaining translations, conservatively dirties affected cache entries,
disables Cylon for the device and logs once. Failed registration remains MMIO
instead of aborting realize. QEMU's existing fatal handling of a failed KVM
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
The Cylon slot remains trapping across ordinary invalidation; removal frees
its mapped SPT VMAs and private faulting backing. The FTL worker is joined
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

KVM's own guest-memory reads/writes use the dual slot's anonymous faulting
backing, not the payload selected by the direct EPT entry. Emulator page
walks, instruction fetch and paravirtual structures can therefore see different
bytes. Do not online this CXL range as general System RAM or put page tables,
code or PV structures there. Restrict Cylon to controlled data mappings; the
acknowledgement is not a guarantee that arbitrary guest software is safe.
Faulting backing can gain RSS up to the window size as KVM resolves faults.

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
2. QEMU owns KVM slot deletion, including zero-size deletion and invalidation.
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
Prefetching, concurrent NVMe access to the same medium, persistent CXL storage,
dynamic capacity and migration are outside this implementation. Guest kernel
boot/enumeration and long-running workloads require separate system testing.

Qtests program actual PCI bridges and HDM registers, then access the CXL fixed
memory window. They cover all four policies at one and sixteen ways, data
readback, dirty programming, media timing, invalid configuration, no-FTL mode,
qtest fallback, mapping revocation and teardown. Standalone tests cover
policy ordering, S3-FIFO promotion and ghost admission, full-width keys,
repeated clearing and dirty accounting over all policies at one through
thirty-two ways. The memslot qtests validate QEMU mappings. Cylon is deliberately inert under
qtest, so they cannot validate custom-kernel compatibility.

With the fixed kernel, a nested run under KASAN (18 guest lifetimes, region
teardown and re-creation, 1 and 4 vCPUs) reported nothing, and a bare-metal run
on a Xeon Gold 6548Y+ with a 256 MiB window and a 1024-page cache passed
page-stride write/readback across two eviction cycles in every mode. Median
load latency on a cached page was about 3.0 us with `der=off`, 105 ns with
`memslot` and 105 ns with `cylon`; sequential reads of cached data ran at
2.5 MiB/s, 345 MiB/s and 2.4 GiB/s. With `cylon`, EPT dirty bits kept media
writes to the pages actually written. Not covered: long workloads, hugetlb
migration during a run, and guests that online the range as system RAM.
