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
page through `bb_ftl_process_req()`. An unmapped page initially contains zeros
and has no read cost. Writes to resident pages become dirty. Dirty eviction or
`flush-cache=true` issues a real FTL write; without a cache, each write goes
straight to the FTL. The guest access waits for the returned media completion
cost using a sleep, not a busy loop. This is volatile memory, not a persistence
contract for guest CPU cache flush instructions.

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
DER mappings. Each device owns one FTL worker without the BQL. A mutex and
condition variable protect a single request handoff and its completion; the
worker alone modifies FTL/NAND state after initialization. The requesting vCPU
waits for its own stack-resident request. There is no response priority queue
and no shared-head polling loop. The worker is stopped and joined before its
state is destroyed.

The worker receives only page numbers, operation types and timestamps. It
never reads or writes guest memory. Payload copies remain on the vCPU thread.
Any future worker-side guest-memory operation must use `femu_dma_rw()`; the
existing NVMe poller DMA rules are unchanged.

## Direct Endpoint Remapping

Realize probes the public Cylon `KVM_GET_LINEAR_SPT` (0xde) and
`KVM_SET_SPTE_FLAG` (0xdd) interfaces. The GET probe uses an absent GFN: the
public kernel returns EINVAL before touching a slot's auxiliary pointer. The
SET probe uses flag zero, the public TLB-invalidation operation. No private
full-SPTE ioctl is defined or called. Without support, or without KVM, realize
succeeds, logs one informational message, and keeps MMIO for the device's
lifetime. `der=off` avoids the probe and message.

This implementation deliberately uses QEMU memory-region aliases and its KVM
listener for direct mappings instead of writing userspace-mapped shadow page
tables. The listener allocates slots, revokes mappings and invalidates TLBs;
there are no hard-coded slot IDs, guessed host physical addresses, or physical
contiguity requirements. This retains direct guest access to cached pages but
makes mapping changes more expensive than Cylon's direct SPTE updates. Memslot
pressure leaves additional pages on MMIO. It does not reduce cache capacity.

Remapping is restricted to non-interleaved pages in a single-target CXL window,
with the endpoint directly below a root port on a host bridge without HDM
decoding. Other topologies retain the MMIO path. Every directly mapped entry
is conservatively dirty, since direct writes cannot notify cache metadata.
Such entries therefore incur a program on eviction even if only read. Direct
hits do not update CLOCK/S3-FIFO reference metadata or MMIO hit counters.

Mappings are removed before eviction programming, flush, decoder/configuration
writes, reset, CCI commands and device removal. Warm reset retains volatile
payload and cache/FTL contents but revokes direct mappings. Normal device exit
joins the worker and frees all private state; backing memory belongs to the
host memory backend.

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
stock-host fallback, mapping revocation and teardown. Standalone tests cover
policy ordering, S3-FIFO promotion and ghost admission, full-width keys,
repeated clearing and dirty accounting over all policies at one through
thirty-two ways. The forced qtest remapping path validates QEMU mappings, not
custom-kernel compatibility.

Bare-metal validation is still required on the public Cylon host kernel for
ioctl compatibility, direct multi-vCPU traffic, TLB revocation, memslot
pressure and performance. The mapping approach and conservative dirty policy
must be considered when comparing against the published implementation.
