<!--
SPDX-License-Identifier: GPL-2.0-or-later
-->

# CXL SSD (`femu-cxl-ssd`)

The device comes from Cylon (FAST '26); the user guide has its
[citation](../modes/cxl-ssd.md#citation).

This chapter describes the CXL SSD as a component: where it sits, what state
it keeps, how an access moves through it, which thread charges which cost,
and which parameters and counters belong to it. It ties together three
existing pages:

- The [design note](../cxlssd.md) is the detailed reference. It records every
  locking rule, every KVM corner case and every validation result. This
  chapter links to it for depth instead of repeating it.
- The [CXL SSD guide](../modes/cxl-ssd.md) shows how to run the device.
- The [caching API guide](../features/cxl-cca.md) and the
  [CXL NVMe link guide](../features/cxl-nvme-link.md) cover the two optional
  features.

## Purpose

`femu-cxl-ssd` is a CXL Type-3 memory device whose capacity is backed by
emulated NAND flash. The guest sees ordinary volatile CXL memory: it creates
a region and uses it as a DAX device or as system RAM. Behind the memory
interface the device keeps a DRAM page cache in front of a private instance
of the BBSSD FTL and NAND timing model. A cache hit costs no media time; a
miss costs a NAND page read; evicting a dirty page costs a NAND page program.

The device is a subclass of QEMU's `cxl-type3`. It keeps the parent's
decoder translation, capacity reporting, CDAT and media-disable behaviour,
and adds the cache, the media timing, optional direct mapping of cached
pages into the guest, a guest-controlled caching API and an optional NVMe
front end over the same medium. It changes no other FEMU mode.

Three properties set it apart from the NVMe modes:

1. The data path is a load or store, not a command. Each access that is not
   direct-mapped is an MMIO exit on a vCPU thread, and that vCPU waits out
   the modelled media time before the load or store completes.
2. The payload is a QEMU host memory backend (`volatile-memdev`), not FEMU's
   own DRAM backend. The cache holds metadata only: page numbers, dirty
   state and replacement state.
3. The FTL never touches payload bytes. It receives page numbers, opcodes
   and timestamps, and returns a latency.

## Place in the CXL topology

The guest reaches the device through a CXL fixed memory window (CFMW), a
host physical address range that the machine routes to one or more CXL host
bridges. Below a host bridge sit root ports, optionally a CXL switch, and the
Type-3 endpoint. Each level has HDM decoders that the guest's CXL driver
programs when it creates a region.

```text
  guest physical address space
  +---------------------------------------------------------------+
  | system RAM | ... | CXL fixed memory window cxl-fmw.0 (HPA)    |
  +---------------------------------------------------------------+
                                  |
                 FEMU overlay "femu-cxl-media" (priority 0, I/O)
                 installed over every window that can reach a
                 femu-cxl-ssd; routes like QEMU's own window router
                                  |
         window interleave: pick the target host bridge
                                  |
                   +------------------------------+
                   | pxb-cxl host bridge          |  HB HDM decoders, or
                   |  (cxl.0)                     |  passthrough to its one
                   +------------------------------+  root port when it has none
                                  |
                   +------------------------------+
                   | cxl-rp root port             |
                   +------------------------------+
                                  |
                   (optional CXL switch: one level of switch decoders)
                                  |
   +--------------------------------------------------------------------+
   | femu-cxl-ssd  (subclass of cxl-type3)                              |
   |   endpoint HDM decoders: HPA -> DPA (interleave, DPA skip)         |
   |   BAR0/1, BAR2/3: parent registers    BAR4: MSI-X                  |
   |   BAR5: caching API (cca=on only)                                  |
   |   mailbox / CCI: Get LSA control channel (lsa-control=on only)     |
   |                                                                    |
   |   DRAM page cache -> femu-cxl-ftl worker -> BBSSD FTL + NAND model |
   |   payload: host memory backend named by volatile-memdev            |
   +--------------------------------------------------------------------+
```

`run-cxlssd.sh` builds the simplest form: one `pxb-cxl`, one `cxl-rp`, the
device, and a single-target window. The device realizes in any topology a
plain `cxl-type3` accepts: interleaved windows, host bridges with HDM
decoders and several root ports, and below a CXL switch. Address routing
follows the window interleave, the host bridge decoders (or its single root
port when it has none), one level of switch decoders, then endpoint
translation, the same order QEMU's own window router uses. A selected
endpoint that is not a `femu-cxl-ssd` is forwarded to the window's original
dispatch, so a plain `cxl-type3` in the same window keeps working. An address
that no decoder claims reads as zero with a transaction error, and a write to
it is dropped.

Only the direct mapping modes are tied to one topology: a single endpoint
directly below the only root port of a host bridge without HDM decoders, in
a single-target window, with no committed interleaved endpoint decoder
(`der_windows_scan()`). Elsewhere the device works, accesses stay on MMIO and
refused mappings count in `der-fallbacks`.

Where it lives: `adapter_route()`, `adapter_translate()`,
`adapter_access()` and `adapter_machine_done()` in
`hw/femu/cxlssd/qemu-adapter.c`.

## The adapter boundary

All dependencies on QEMU's CXL device layout, fixed windows, decoders, CCI
state and KVM ioctls are in one file, `hw/femu/cxlssd/qemu-adapter.c`. The
rest of the component talks to it through `hw/femu/cxlssd/qemu-adapter.h`.

```text
  QEMU CXL core (hw/cxl, hw/mem/cxl_type3.c)      accel/kvm
        |  QOM subclass, overlays, decoders,          |  KVM memslot
        |  CCI pre-command hook, reset chain          |  reservation, ioctls
        v                                             v
  +----------------------------------------------------------------+
  | qemu-adapter.c                                                 |
  |   QOM type, realize/exit, window overlay and routing,          |
  |   invalidation, LSA control channel, QOM properties,           |
  |   DER: memslot aliases and Cylon slot/SPTE handling,           |
  |   femu_cxl_nvme_ops for a linked NVMe controller               |
  +----------------------------------------------------------------+
        |  qemu-adapter.h: FemuCxlMedia, FemuCxlOp, gate, access
        v
  +----------------+   +-----------+   +--------------------------+
  | cxlssd.c       |   | cache.c   |   | cca.c, cca-ring.c        |
  | access path,   |   | sets and  |   | BAR5 caching API, thread |
  | gate, worker,  |   | policies  |   +--------------------------+
  | media delay,   |   +-----------+   spte.h, spt.h: SPTE and SPT
  | NVMe link side |                   helpers (no QEMU state)
  +----------------+
        |  bb_ftl_process_req(), ssd_init(), ssd_free()
        v
  hw/femu/bbssd (FTL) and the NAND media layer
```

Two generic hooks live outside `hw/femu/`, and both are inert unless a
`femu-cxl-ssd` uses them:

| Hook | Where | What it does |
| --- | --- | --- |
| KVM memslot reservation | `kvm_reserve_memslot()`, `kvm_reserved_memslot_id()` and `kvm_release_memslot()` in `accel/kvm/kvm-all.c`, declared in `include/system/kvm.h` | Reserves a slot ID that the KVM memory listener never allocates and that does not count as free capacity. `der=cylon` registers its dual-mode slot under that ID |
| CCI command callbacks | `pre_command`, `post_command` and `pre_command_opaque` in `CXLCCI` (`include/hw/cxl/cxl_device.h`), called from `hw/cxl/cxl-mailbox-utils.c` | Run before and after every CCI command on every transport, without replacing any command handler. FEMU uses them to revoke direct mappings and to hold its CXL lock across the command |

Everything else is done by chaining parent methods: PCI configuration writes
call the inherited method after FEMU revokes, component register writes go
through a FEMU overlay on the component register block, reset chains the
parent's hold phase, and the LSA class methods are always overridden but
pass through to the parent's unless `lsa-control=on`.

The NVMe side never includes CXL headers. `hw/femu/femu.c`, and
`hw/femu/bbssd/bb.c` for flips, call the medium through `femu_cxl_nvme_ops`, a table of five functions
(`prepare`, `attach`, `detach`, `ftl`, `flip`) that `qemu-adapter.c`
registers. The CXL files are built only when both `CONFIG_FEMU_PCI` and
`CONFIG_CXL_MEM_DEVICE` are on (`hw/femu/meson.build`); without them the
table stays empty and `cxl_ssd=` is refused.

## Data structures

| Structure | File | Fields that matter |
| --- | --- | --- |
| `FemuCxlSsd` | `qemu-adapter.c` | `parent_obj` (the `CXLType3Dev`), `media`, `component_overlay`, `lsa_queue` (queued control commands) |
| `FemuCxlWindow` | `qemu-adapter.c` | One per fixed window that can reach a FEMU endpoint: the window and its `io` overlay region. Shared by all FEMU devices; removed when the last one leaves |
| `FemuCxlMedia` | `qemu-adapter.h` | `backend` (payload pointer and size), `cache`, `direct` (DER state), `cca`; the gate (`busy`, `accesses`, `exclusive_waiters`, `idle` condition variable); `pages` (pages held by accesses in progress); `invalidations` (generation); `lock`, `worker_cond`, `work`, `worker` (the FTL worker); `ns.ssd` (the private FTL); NVMe link fields `nvme`, `nvme_ranges`, `nvme_taken`, `nvme_done`, `nvme_bh`; counters |
| `FemuCxlOp` | `qemu-adapter.h` | One access, flush or eviction chain: the media time `ns` it has accumulated and the pages it holds itself |
| `FemuCxlWork` | `qemu-adapter.h` | One FTL request on the worker queue: an `NvmeRequest`, the returned `latency`, `done`, and `done_cond`, the waiter's condition variable |
| `FemuCxlCache`, `FemuCxlSet`, `FemuCxlEntry` | `cache.h` | `nsets`, `ways`, `policy`, `entries` and `ghosts` hash tables; per set the `small`, `main`, `ghost` and `pinned` queues; per entry `lpn`, `dirty`, `freq`, `queue`, `der_hits`, `der_displaced` |
| `FemuCxlDer` | `der.h` | `maps` (mapped pages), `available`, `cylon`, `fast` (Cylon state), `ratio`, `installed` (memslot aliases, oldest first), replacement state, DER counters |
| `FemuCxlMap` | `qemu-adapter.c` | One memslot alias: first page, page count, alias region, queue link |
| `FemuCylon`, `CylonPage` | `qemu-adapter.c` | Slot reservation, memory listener, SPT chunk areas, resolved huge page frames; per mapped page the SPTE pointer and the saved MMIO SPTE |
| `FemuCxlCca` | `cca.h` | BAR5 regions, host ring cursors, `status`, `epoch`, `uncached_map` (one bit per media page), thread, `kick`, `stop`, counters |

Keys in the cache and DER tables are full 64-bit page numbers (LPN = DPA /
4096). The cache library (`cache.c`) has no QEMU dependency and builds
standalone for its unit test.

## The media path

### From a guest access to the cache

The overlay callback `adapter_access()` runs on the vCPU thread that took
the MMIO exit, holding the BQL. A Cylon fault exit reaches it on the vCPU
thread without the BQL (see [Locking](../cxlssd.md#locking)). It routes the address,
takes the CXL lock, translates, takes the device's operation gate, routes
again (decoders may have changed while it waited), and calls
`femu_cxl_access()` in `cxlssd.c`. If media is
disabled (the parent's media-disable state), reads return random bytes and
writes are discarded, as the parent Type-3 device does.

`femu_cxl_access()` handles an access of 1 to 8 bytes, which may cross one
page boundary:

1. Hold each page it touches, in ascending order, in `s->pages`. A second
   access to a held page waits. This keeps accesses to one page ordered and
   makes a second miss wait for the first fill instead of repeating it.
2. Look up each page in the cache. On a miss, ask the FTL worker for a page
   read (or a program, when the page is not cacheable and the access is a
   write), then insert the page. Insertion may evict a victim; a dirty
   victim costs a program. A write marks the entry dirty.
3. On a demand miss, prefetch (see [Prefetch](#prefetch)).
4. Wait out the accumulated media time with the locks released. A fill
   without prefetch waits it out inside its media read instead, so it takes
   the locks once less.
5. Copy the bytes between the guest and the host memory backend.
6. For a single-page access to a cached (or ratio-selected) page, try to map
   the page directly into the guest (see [Direct mapping](#direct-mapping)).

A page is not cacheable when the cache is off (`cache-pages=0`), when the
caching API marked it uncached, or when every way of its set is pinned.
Such an access goes to the media every time: a read is a NAND read, a write
a NAND program. An access also goes uncached when the only victim its insert
could evict is held by another access in progress.

The write miss is write-allocate with fill: a store to a page that is not
resident first reads the page from NAND, then dirties it. An unmapped page
(one the FTL has never programmed) costs no media time on a read, though it
still counts in `media-reads`; its bytes come from the backend, which reads
as zeros for a fresh `memory-backend-ram`.

### Access path under each `der` mode

```text
                         guest load/store to the CXL window
                                        |
             +--------------------------+---------------------------+
             | page directly mapped?                                |
             | (memslot alias or Cylon direct SPTE)                 |
             +--------------------------+---------------------------+
                yes |                                   | no
                    v                                   v
   +---------------------------------+      EPT violation / MMIO exit
   | DIRECT HIT                      |      vCPU thread, CXL lock
   | CPU reads/writes host memory    |                  |
   | no exit, no counter, no timing, |      adapter_access(): route,
   | no CLOCK/S3-FIFO reference      |      translate, enter the gate
   | memslot: page stays dirty       |                  |
   | cylon: EPT D bit sampled later  |      femu_cxl_access(): hold page
   +---------------------------------+                  |
                                            +-----------+-----------+
                                            | resident in cache?    |
                                            +-----------+-----------+
                                         hit |                      | miss
                                             v                      v
                                   cache-hits +1          cache-misses +1
                                   no media time          FTL read (fill),
                                                          insert, maybe evict
                                                          (dirty victim:
                                                          FTL program),
                                                          prefetch
                                             |                      |
                                             +----------+-----------+
                                                        v
                                    wait media time (locks dropped)
                                    memcpy to/from host backend
                                                        |
                    +-------------------+---------------+---------------+
                    | der=off           | der=memslot                   | der=cylon
                    v                   v                               v
              nothing more        add a one-page RAM          CAS the page's EPT
              (every access       alias (budget 1024,         leaf from its MMIO
              exits again)        shared); entry marked       SPTE to a direct
                                  dirty                       SPTE; dirty taken
                                                              from the D bit
```

With `der=off` the same page exits on every access, so every hit is counted
and timed. In the direct modes the first access after a miss completes in
QEMU and installs a mapping; the guest's later accesses to that page are
direct hits until the page is evicted or an invalidation revokes it.

### The operation gate

The gate (`femu_cxl_enter()`, `femu_cxl_enter_access()` and their
`leave` pairs in `cxlssd.c`) is a reader/writer style lock built on the CXL
lock and the `idle` condition variable:

| Holder | Mode |
| --- | --- |
| Guest access, `concurrent-misses` in effect | Shared (`femu_cxl_enter_access()`) |
| Guest access otherwise | Exclusive (`femu_cxl_enter()`) |
| `flush-cache`, `stats-reset`, `fast-load`, `cache-ways`, prefetch and `der-ratio` changes, every control command | Exclusive |
| Each caching API chunk | Exclusive |
| The NVMe link bottom half that drops cache entries | Exclusive |

An exclusive waiter blocks new shared holders, so a flush is not starved by
a stream of accesses. Waiters release the locks while they wait. Invalidation
and teardown never wait for the gate (see [Invalidation](#invalidation)).

`concurrent-misses` decides whether accesses share the gate. With `auto`,
they share it only while a direct mode is available
(`femu_cxl_concurrent()`). Sharing lets misses to different pages wait for
the media together, so their NAND reads overlap where they reach different
LUNs.

**Atomicity caveat.** With `der=off`, a guest's `lock`-prefixed
read-modify-write reaches the device as a read and a separate write. It is
never atomic. One access at a time keeps other vCPUs out from between the
two most of the time; overlapping misses make lost updates common. FEMU's
tests with four vCPUs lost 0.6% to 0.9% of `lock add` increments with
serialized accesses and 51% to 52.5% with overlapping misses. In the direct
modes the write lands on the page the read mapped, where KVM's emulator
exchanges and retries, and no increments were lost. Do not rely on atomic
operations to `der=off` memory, and keep `concurrent-misses` at `auto` or
`off` there.

## The DRAM page cache

The cache (`hw/femu/cxlssd/cache.c`) is set-associative over LPNs. It holds
`cache-pages` entries in `nsets = cache-pages / cache-ways` sets; page `lpn`
belongs to set `lpn % nsets`. One way is direct mapped; `cache-ways` equal
to `cache-pages` is fully associative.

```text
  FemuCxlCache
  +----------------------------------------------------------------+
  | entries: hash LPN -> FemuCxlEntry   ghosts: hash LPN -> node   |
  | nsets = cache-pages / cache-ways    policy                     |
  +----------------------------------------------------------------+
        set index = lpn % nsets
        |
        v
  sets[0] ... sets[i] ... sets[nsets-1]
              |
              v   FemuCxlSet (ways = cache-ways)
  +----------------------------------------------------------------+
  | small : [head: next victim] e e e e [tail: newest]            |
  | main  : [head] e e e [tail]               (S3-FIFO only)       |
  | ghost : LPNs recently evicted from small, at most `ways`       |
  | pinned: e e        (caching API; never evicted)                |
  +----------------------------------------------------------------+
     small + main + pinned <= ways

  FemuCxlEntry: lpn | dirty | freq (0..3) | queue | der_hits | link
```

### Replacement policies

`cache-policy` selects one policy for all sets. Every policy evicts only
from `small` and `main`; pinned entries have left those queues.

| Policy | Insert | Victim |
| --- | --- | --- |
| `fifo` | Tail of `small` | Head of `small` (oldest) |
| `lifo` | Tail of `small` | Tail of `small` (newest) |
| `clock` | Tail of `small` with its reference set | Rotate from the head, clearing references, until an entry has none |
| `s3-fifo` | Tail of `small`, or of `main` when the LPN is in the set's ghost queue | Evict from `small` while it holds at least a tenth of the unpinned ways (minimum one) or `main` is empty. An entry leaving `small` with more than one hit moves to `main`; otherwise it is evicted and its LPN joins the ghost queue. In `main`, an entry with hits loses one and rotates |

Hits increment `freq` up to 3. With one way, S3-FIFO uses only `small`.
Removal of a known entry is constant time because each entry keeps its own
queue node. The design note's [media and cache](../cxlssd.md#media-and-cache)
section has the remaining details.

### Prefetch

Only a demand miss triggers prefetch, after the demanded page is inserted.
The device inserts pages `[lpn + prefetch-stride, lpn + prefetch-stride +
degree)`, where the degree is `prefetch-degree` capped at `cache-pages`.
Resident, out-of-range and uncached pages, and pages whose set is fully
pinned, are skipped. A prefetch performs no NAND read and adds no media
time, but a dirty page it evicts is still programmed. If an insert cannot
evict, prefetching stops for that access without failing it. Prefetched
pages may be mapped directly. A small cache may evict the demanded page
itself while prefetching, following insertion order.

### Run-time changes

`cache-ways`, `prefetch-degree` and `prefetch-stride` can change while the
guest runs (`qom-set`, or control commands 3, 5 and 7). A `cache-ways`
change takes the gate exclusively, refuses before touching anything if the
pinned pages do not fit the new geometry, then revokes mappings, writes
dirty pages back, rebuilds the cache with the pinned pages still resident,
and maps a direct ratio again.

## Dirty data and write-back to the FTL

The cache is write-back. A dirty page is programmed to NAND when:

| Event | Who pays |
| --- | --- |
| Eviction of a dirty victim by an insert | The access that caused the insert, or the `femu-cxl-cca` thread for a PIN fill |
| `flush-cache=true`, control commands 2, 9, 11 | The caller (the main loop, waiting with the locks dropped) |
| `cache-ways` change | The caller |
| Caching API INVALIDATE and CACHE_DISABLE | The `femu-cxl-cca` thread, per chunk |

`cylon-free-writeback=on` skips the program on eviction and flush, as the
published Cylon experiments do.

What counts as dirty depends on the `der` mode, because a direct store never
reaches QEMU:

- `der=off`: a store through MMIO sets `dirty`.
- `der=memslot`: QEMU cannot see stores through an alias, so every page that
  gets an alias is marked dirty when it is mapped. Its eviction always costs
  a program.
- `der=cylon`: revocation samples the EPT dirty bit. A page read but never
  written through the direct entry is evicted clean, with no program.

The FTL worker (`cxl_worker()` in `cxlssd.c`, thread `femu-cxl-ftl`) is the
only thread of the device itself that changes FTL and NAND state; with a
linked NVMe controller, that controller's FTL thread is the other one, and
both run under `s->lock`. Callers queue a
`FemuCxlWork` on `s->work` under `s->lock`, wake the worker on
`s->worker_cond` and wait for `done` on the request's own `done_cond`, which
lives on the caller's stack. The worker signals only that condition, so each
request is woken individually and no waiter wakes for another request. The
worker
calls `bb_ftl_process_req()` with an 8-sector request (one 4 KiB page of
512-byte sectors) and returns its latency. Requests are served in arrival
order, and the NAND model overlaps them where they reach different LUNs.
`cylon-first-touch-program=on` turns a read of an unmapped page into a
program.

The FTL is a private BBSSD instance built in `femu_cxl_start()`: 512-byte
sectors, eight per page, one plane per LUN, and the geometry, timing and GC
thresholds of the device properties. It has no PCI queues and none of the
optional NVMe features. With `ftl=off` there is no FTL and no worker:
accesses have no media time and write-back is metadata only. GC, mapping and
NAND timing are those of the BBSSD FTL, which the
[timing model](../concepts/timing-model.md) and the architecture page's
[BBSSD section](../concepts/architecture.md#bbssd) describe.

Realize refuses NAND whose spare lines do not exceed the forced collection
reserve by two, so collection always frees a line. A write that finds the
free lines at the forced threshold waits until the collection erases end on
every LUN; `gc-stalls` and `gc-stall-ns` count the waits. `media-full`
counts programs that still find no page. Such a program is not timed, and
it does not stop an eviction or an insert. A full NAND never sends a
cacheable access uncached. See
[Full NAND](../cxlssd.md#full-nand).

## Direct mapping

`der` selects how cached pages may be served without an exit. The design
note's [Direct Endpoint Remapping](../cxlssd.md#direct-endpoint-remapping)
section is the full reference.

| Mode | Mechanism | Host needs | Mapping limit |
| --- | --- | --- | --- |
| `off` | None: every access is MMIO | Nothing | n/a |
| `memslot` | One-page `memory_region_init_alias()` RAM aliases over the window; KVM makes each one an ordinary memslot | KVM; refused under TCG at realize | 1024 aliases shared by all devices, and never more than KVM's free slots minus 8 |
| `cylon` | A dual-mode KVM slot over the window, and direct leaves written into KVM's EPT through the Cylon kernel's linear SPT | The fixed Cylon host kernel, Intel EPT with A/D bits, TDP MMU, MMIO caching, a shared preallocated hugetlbfs backend, root (for `mlock()` and `/proc/self/pagemap`), `cylon-kernel-ack=on`, `smm=off`, identical CPUID on all vCPUs | No per-page alias cost; the window is at most 120 GiB (60 SPT chunks of 4 MiB at 8 bytes per page) |

Every mapping's HPA is checked against the endpoint decoders before it is
installed (`femu_cxl_der_map()`), so a prefetched page whose derived HPA
decodes to another DPA, or to none, is not mapped. Pages in caching API
uncached ranges are never mapped. `der-ratio` maps a fixed fraction of all
pages, cached or not, to reproduce Cylon's direct ratio experiments; see
[direct ratios](../cxlssd.md#direct-ratios).

### `der=memslot`: the alias budget and replacement

Each alias, and the MMIO gap beside it, is a separate section of the system
address space, and QEMU aborts once an address space needs 4096 sections.
So all `femu-cxl-ssd` devices share one budget of 1024 one-page aliases
(`FEMU_CXL_DER_ALIASES`), further capped at KVM's free slots minus 8
(`der_alias_budget()`). Ratio runs use the same budget. A cached page that
finds the budget full stays on MMIO and counts in `der-fallbacks`.

When the hot set moves, the aliases may hold cold pages. Replacement
(`der_replace_due()`, `der_replace_victim()`, `der_displace()`):

```text
  MMIO access to a cached page, budget full
        |
        v
  der-replace-rate == 0 ? ---- yes ------------------------> stay on MMIO
        | no                                                 (no counting)
        v
  entry->der_hits += 1  ---- < 256 (FEMU_CXL_DER_HOT) ---->  stay on MMIO
        | >= 256           (the miss that inserted the page counts too)
        v
  first replacement, or time since the last one
  >= (1 s / rate) << backoff ? ---------------- no -------> stay on MMIO
        | yes
        v
  victim = oldest alias of this device whose page is not pinned
        | none -------------------------------------------> stay on MMIO
        v
  one memory transaction: remove victim alias, add this page's alias
  der-replacements +1, der-remaps +1, der-revocations +1
        |
        v
  backoff: this page was displaced before -> backoff + 1 (max 8, so the
           interval grows up to 256x); 8 consecutive promotions of pages
           not displaced before -> backoff - 1
```

Accesses through an alias never reach QEMU, so installation order is the
only recency the device can see. Pinned pages keep their aliases.

### `der=cylon`: dual-mode slot and SPTE protocol

At realize, `femu_cylon_prepare()` probes the two Cylon ioctls
(`KVM_GET_LINEAR_SPT`, VM ioctl 0xde; `KVM_SET_SPTE_FLAG`, vCPU ioctl 0xdd),
checks the KVM module parameters, the hugetlbfs backend, `mlock()` and the
pagemap frames. Any failure prints one warning,
`FEMU CXL DER unavailable: <reason>; using MMIO`, and the device continues
as with `der=off`. `cylon-kernel-ack=on` is required even then, because the
device cannot tell the fixed kernel from the published one.

The first eligible decoded access schedules `cylon_install_bh()`, which
pauses all vCPUs, reserves a slot ID through the generic reservation hook,
and registers a slot over the window with flag `KVM_CYLON_DUAL_MODE` (bit
17). Its host address is the payload backend itself. The kernel then hands
back the slot's linear SPT in at most 60 chunks of 4 MiB. Installation needs
at least 8 free memslots.

Per page, the SPTE moves through these states:

```text
            KVM's first fault on the page
   (empty) -----------------------------> MMIO SPTE (kernel-created,
      |                                    generation bits saved by FEMU)
      | ratio only: CAS empty -> direct                |
      v                                                | access completes in QEMU:
   DIRECT SPTE  <--------------------------------------+ CAS MMIO -> direct
   RWX, WB, A=0, D=0                                     (der-remaps +1)
      |
      | revoke (eviction, invalidation, teardown)
      v
   A bit clear? -- yes --> CAS direct -> saved MMIO, no TLB flush
      |                    (der-quiet-revocations +1, der-revocations +1,
      |                    page clean)
      | no (or the CAS lost to the CPU setting A)
      v
   CAS clear W and MMU-writable; flush this GFN
   read D; CAS -> saved MMIO; flush this GFN
   D set -> cache entry dirty      (der-revocations +1)

   KVM replaced the entry itself (zero, MMIO, frozen): treated as a KVM
   revocation: entry made dirty, record dropped after a flush.
   Unexpected entry or ioctl failure: restore saved MMIO entries, delete
   the slot, disable Cylon until the next device reset.
```

An entry whose accessed bit is still clear has not been used by any page
walk since it was installed, so no TLB holds it: that is the quiet path. The
full path costs two single-GFN flushes per page. `der-revocations` counts
every revocation, quiet or not. A whole-slot invalidation still samples each
page (one flush per accessed page) but skips the final flush, because the
slot deletion that follows flushes everything; later accesses reinstall the
slot and pages map again lazily. Global dirty logging (migration)
revokes everything and disables Cylon. A failed slot deletion aborts QEMU,
because continuing could leave the kernel using a slot whose backing FEMU
has released.

**The Cylon host kernel.** The published CylonLinux 6.4.6 corrupts host
memory with this interface. The fixes are on MoatLab/Cylon `master`; the
design note's [host kernel](../cxlssd.md#host-kernel) section lists them and
the requirements the kernel still does not check (SMM off, identical CPUID,
no move or flag change of the dual slot). Its
[host and guest restrictions](../cxlssd.md#host-and-guest-restrictions)
section explains why hugetlb migration, memory offline, `page_idle` and
DAMON must not touch the QEMU process during a run.

**Known kernel-side limitation: first touch per 2 MiB under a ratio.** A
direct ratio installs direct leaves into empty SPT entries, including pages
in 2 MiB guest regions the guest has never touched. For such a region the
level above the leaf is still empty. The first guest access in the region
faults, KVM links the page table, and in doing so replaces FEMU's direct
leaf with an MMIO SPTE. FEMU sees a KVM revocation (`der-revocations` +1),
serves that access by MMIO and maps the page again (`der-remaps` +1); the
rest of the region stays direct. Expect one exit per untouched 2 MiB region
under a `der=cylon` ratio. This is kernel behaviour, not a device bug; the
fix belongs in the kernel (keep a present direct leaf when a fault only
links its parent table). Ordinary cache mappings are not affected, because
they are installed only over MMIO SPTEs KVM has already created.

## Invalidation

Direct mappings are revoked whenever the guest could change what an address
means, and whenever the device needs to observe a page again.
`cxl_invalidate()` revokes all mappings and bumps the `invalidations`
generation; an access in flight that sees the generation move during its
media delay does not install the mapping it translated before.

| Trigger | Where | Effect |
| --- | --- | --- |
| PCI configuration write | `adapter_config_write()` | Revoke all, the parent's method, revoke all again |
| Component register write (HDM decoders) | `adapter_component_write()` through `component_overlay` | Revoke all, then the parent's registers, under the CXL lock |
| Any CCI command on any transport | `adapter_pre_command()`, `adapter_post_command()` | Revoke all, then the command, under the CXL lock; except Get LSA on the primary mailbox with `lsa-control=on`, which carries a control command and revokes nothing |
| Device reset | `adapter_reset_hold()` | Revoke all, let a failed Cylon retry, caching API reset (unpin all, end uncached ranges), free CCI background state, then the parent's hold phase |
| Unplug | `cxl_exit()` | Tell the caching API thread to stop, mark the device closing, disable DER, and free the media now or leave that to the last gate holder |
| Eviction | `femu_cxl_evict()` | Revoke that page only (a ratio-selected page keeps its mapping; its dirty bit is sampled) |
| Flush, way change, commands 2, 3, 9, 11 | `cxl_flush()`, `cxl_runtime_set()` | Revoke all, write dirty pages back, drop unpinned entries, map a ratio again |
| Caching API INVALIDATE, CACHE_DISABLE | `cca.c` | Revoke the chunk's pages, or all mappings once for more than 64 candidates |
| Linked NVMe write, zeroes, copy, deallocate | `femu_cxl_nvme_bh()` | Revoke and drop the pages without write-back; pinned pages stay, made clean; ratio-selected pages keep their mapping; a range over 64 pages revokes all mappings at once when no ratio is set |
| Global dirty logging (Cylon) | `cylon_log_start()` | Revoke all, disable Cylon |
| Memory map change overlapping the window (Cylon) | `cylon_region_change()` | Delete the dual slot; re-admit after fresh checks |

Invalidation never waits for the gate. Configuration writes, component
writes and CCI commands run inside another owner's re-entrancy guard, and
waiting there would refuse other vCPUs' accesses. Revocation therefore
touches only DER state, which is safe under the CXL lock alone. Warm reset keeps
the volatile payload and the cache and FTL contents; only mappings, pins and
uncached ranges go. Pages map again on their next access.

## The LSA control channel

With `lsa-control=on` the device serves an internal, zero-filled 128 MiB
label storage area (`FEMU_CXL_LSA_SIZE`) instead of an `lsa` backend, and a
guest `Get LSA` mailbox command (opcode 0x4102) carries an experiment
command: the read length is the command and the read offset its argument.
This is the convention of Cylon's scripts:
`cxl read-labels mem0 -s COMMAND -O ARGUMENT`. Byte 0 of the returned data
is the status: 0 success, 1 error, 2 queued.

```text
  guest: cxl read-labels mem0 -s CMD -O ARG
        |
        v  mailbox Get LSA (0x4102), vCPU thread, device re-entrancy guard held
  cxl_get_lsa()
        |
        +-- CMD in {1,5,7,13,15,17,80,81,90,91}, gate free, queue empty
        |        -> run inline (cxl_command()), byte 0 = 0 or 1
        |
        +-- otherwise (2, 3, 9, 11, unknown, or device busy)
                 -> append to lsa_queue, byte 0 = 2
                    main-loop BH cxl_lsa_bh() runs the queue in order;
                    control-status reads 2 until it drains
```

The command table is in the
[guide](../modes/cxl-ssd.md#control-channel-through-the-label-area) and the
[design note](../cxlssd.md#experiment-controls). The same commands are
available from the host through `control-argument` and `control-command`,
whatever `lsa-control` says.

**Trust.** The channel lets the guest act on the host. Commands 1, 3, 5, 7,
13 and 17 create or write files (`cxlssd-stats.log`, `cxlssd-io-N.log`,
`cxlssd-spt.log`) in `log-dir`, QEMU's working directory by default. When
`tracefs-dir` is set, command 91 truncates the host's tracefs `trace` file
and writes `tracing_on`, and 81 writes `tracing_on`. The device bounds this: each file stops at
`log-limit`, statistics appends pass a token bucket (a burst of 64, then 100
per second), I/O log names cycle through 64 files, and `log-dropped` counts
what was refused. It does not authenticate the guest. Keep `lsa-control`
off for guests you do not trust; it is off by default on the device and on
in `run-cxlssd.sh`. The
[security page](../concepts/security-and-limits.md#cxl-ssd-control-channel)
says more.

## The caching API (CCA)

`cca=on` gives the guest control of the cache through PCI BAR5: pin and
unpin pages, write back and drop ranges, mark ranges uncached, and query
residency. The device side is `hw/femu/cxlssd/cca.c` and `cca-ring.c`; the
ABI is one header, `hw/femu/cxlssd/cca-abi.h`, compiled by both the device
and the guest library in `hw/femu/tools/cca/`.

### BAR5 layout

```text
  BAR5, 512 KiB, 32-bit memory BAR
  offset
  0x00000 +--------------------------------------------------+
          | registers, 4 KiB, trapped (4- and 8-byte access) |
          |  0x00 MAGIC 0x43434131 "CCA1"   0x04 VERSION 2   |
          |  0x08 STATUS  READY|FATAL|CACHE|BUSY             |
          |  0x0c DOORBELL (any write)  0x10 RESET (1, 2)    |
          |  0x14 FATAL_REASON  0x18 MEDIA_PAGES (64-bit)    |
          |  0x20 CACHE_PAGES  0x24 CACHE_WAYS               |
          |  0x28 PIN_LIMIT  0x30 COMPLETED (64)  0x38 EPOCH |
  0x01000 +--------------------------------------------------+
          | RAM "femu-cxl-cca-shm" (offsets below are BAR5)  |
          |  0x01000 header (magic, version, ring offsets;   |
          |          data ring fields stay 0)                |
          |  0x01100 request ring:  head | tail | 2048 u32   |
          |  0x03200 response ring: head | tail | 2048 u32   |
          |  0x06000 slot pool: 2048 slots x 128 B           |
          |          slot = 64 B command + 64 B response     |
  0x46000 |  (unused to the end of the BAR)                  |
  0x80000 +--------------------------------------------------+

  command  (64 B): cmd | flags | lpn_start | lpn_count | tag | rsvd[4] = 0
  response (64 B): status (0 or -errno) | lpn_start | lpn_count (pages acted
                   on) | tag | resident | dirty | pinned | uncached
```

The rings are single producer, single consumer, with free-running 32-bit
head and tail; their size is a constant, never read from shared memory. The
device keeps its own cursors, reads each shared index once, and copies a
command out of its slot before validating it. A head too far ahead, a slot
index out of range, or a response ring the guest never drains sets
STATUS.FATAL with a reason and stops the device side until RESET.

### Commands

| Command | Effect |
| --- | --- |
| NOP | Status 0 |
| PIN | Room is checked for the whole range first (`-ENOSPC`). Resident pages are pinned; others are filled by a NAND read, then pinned. A later fill failure (`-EIO`) or a way change between chunks (`-EAGAIN`) leaves the pages already pinned. `-EBUSY` on an uncached page, `-EOPNOTSUPP` without a cache |
| UNPIN | Returns pinned pages to `main` under S3-FIFO with more than one way, else to the tail of `small`; dirty state is kept |
| INVALIDATE | Revoke mappings, write dirty pages back, drop them; pinned pages need `CCA_F_FORCE` |
| CACHE_DISABLE | Mark pages uncached, then drop resident ones as INVALIDATE does |
| CACHE_ENABLE | End the uncached marking |
| QUERY | Count resident, dirty, pinned and uncached pages |

Ranges are 4 KiB device pages; `CCA_F_ALL` selects the whole medium. Every
way of a set may be pinned; a miss to such a set is served uncached and
counted in `cca-pinned-set-misses`. `der-ratio` and uncached ranges exclude
each other.

### Thread and chunking

A doorbell write signals the detached `femu-cxl-cca` thread and never
waits. The thread takes the BQL and the CXL lock, runs up to 64 commands in
submission order, then gives them up and wakes itself again, so a guest that
keeps the ring full cannot hold them. Each command runs in chunks of at most 256 pages of
work and 4096 lookups. A chunk holds the gate exclusively, then waits out its
media time with the locks released; before each chunk the thread lets one
waiting access take the gate first. Guest accesses therefore run between
chunks, and the worst stall a chunk adds to an access is about 256 programs.
Device reset reformats the rings, bumps EPOCH and drops a command in flight
without a completion. The [caching API section](../cxlssd.md#caching-api-cca)
of the design note covers the reset and unplug races.

## The NVMe front end

`-device femu,femu_mode=1,cxl_ssd=<id>` puts a BBSSD NVMe controller in front
of the same medium. Its one namespace uses the device's memory backend as
payload and the device's FTL as its own, so both front ends see one set of
bytes and one mapping table.

```text
        guest CXL driver (devdax / system RAM)     guest NVMe driver
                    |                                     |
         loads/stores (MMIO or direct)          SQ/CQ, poller thread
                    |                                     |
   +----------------v------------------+     +------------v-------------+
   | femu-cxl-ssd                       |     | femu (bbssd, cxl_ssd=)   |
   | cache metadata, DER mappings       |     | DMA copies payload at    |
   +----------------+------------------+     | submission               |
                    |                         +------------+-------------+
                    |   payload: one host memory backend   |
                    +----------------+---------------------+
                                     |
     femu-cxl-ftl worker             |        NVMe FTL thread
     (CXL fills, write-backs)        |        (femu_cxl_nvme_ftl())
                    \                |               /
                     +--- s->lock (worker mutex) ---+
                                     |
                       one BBSSD FTL + NAND model
                                     |
   NVMe Write / Write Zeroes / Copy dst / Deallocate:
     FTL thread appends page ranges to nvme_ranges, tags request cxl_seq
                                     |
                                     v
     main-loop BH femu_cxl_nvme_bh(): takes the gate (or sets nvme_kick
     and lets the holder reschedule it), revokes mappings, drops the
     pages WITHOUT write-back (pinned pages stay, made clean),
     publishes nvme_done
                                     |
                                     v
     poller posts the completion only when nvme_done >= cxl_seq
```

Consistency rules (the full list is in the design note's
[coherence](../cxlssd.md#coherence) section):

1. Payload needs no code: CXL accesses, direct mappings and NVMe DMA all
   touch the same host memory. An NVMe read returns the latest CXL store
   whether the page is clean, dirty in the cache or direct-mapped.
2. Write, Write Zeroes, Copy (destination) and Deallocate make each page
   they cover non-resident before the command completes. The entry is
   dropped without write-back, because the command already programmed or
   unmapped the page.
3. NVMe reads leave the cache alone and charge a NAND read even for
   resident pages.
4. A CXL store, and every direct mapping, marks the namespace's
   written-block bitmap, so DULBE and Get LBA Status see CXL writes.
5. NVMe Flush does not flush the cache; the medium is volatile memory.
6. Flips 1 to 4 change the shared timings and so affect CXL misses too;
   flip 3 restores the device's own `read-ns`, `program-ns`, `erase-ns` and
   `channel-ns`.

Lock order is BQL, CXL lock (the gate is a condition under it), worker
mutex. The NVMe FTL thread never takes the BQL or the CXL lock. The
controller must be BBSSD with one namespace and none of namespace
management, a subsystem, streams, `power_loss`, `buffer_size`, `op_pcent`,
metadata or protection information (`femu_cxl_link_check()` in `femu.c`).
Format NVM is not advertised and Sanitize is refused, since both would
rewrite the medium behind the cache. While linked, `device_del` of the
medium fails with an unplug blocker; the
[NVMe link guide](../features/cxl-nvme-link.md) covers the slot power-off
case and the realize messages.

## Threads, locks and where latency is charged

| Thread | Runs | Takes |
| --- | --- | --- |
| vCPU, MMIO exit | MMIO overlay callback, the whole access path, Get LSA | BQL, CXL lock, gate, page holds; drops both locks to wait for the worker and for the media delay |
| vCPU, Cylon fault exit | The fault service and its fill | CXL lock, gate, page holds; drops it to wait; takes the BQL first only when a step needs it (`der-fault-bql`) |
| `femu-cxl-ftl` | `cxl_worker()`: every FTL request of the medium, device DMA work queued before the last `fast-load=false` first | `s->lock`, then `post_lock` briefly; never the BQL or the CXL lock, never guest memory |
| `femu-cxl-cca` | Caching API commands | BQL, CXL lock, gate per chunk, `cca->lock` for the doorbell flag |
| QEMU main loop | QMP `qom-set` (flush, way change, control commands), queued LSA commands, NVMe drop BH, Cylon install BH, teardown and reference BHs left by fault exits | BQL, CXL lock; the gate, except the Cylon install BH, which pauses all vCPUs before it takes the CXL lock |
| QEMU main loop, device DMA | Copies of other devices into the window, guarded or not (block layer completions), except qtest commands; identified by the thread that realized the device, so an IOThread's or another non-vCPU thread's copy, which also holds the BQL, keeps the full model | BQL, CXL lock, `post_lock`; never the gate or `s->lock`, never waits (`femu_cxl_access_nowait()`) |
| NVMe FTL thread (linked controller) | NVMe I/O on the shared FTL (`femu_cxl_nvme_ftl()`), after the device DMA work before the last `fast-load=false` is booked | `s->lock`, waits on `posted_cond` under `post_lock` with `s->lock` dropped; never the BQL or the CXL lock |
| NVMe pollers (linked controller) | Hold a completion until its cache drop is published | Read `nvme_done` only |

Latency model (`femu_cxl_media()`, `femu_cxl_delay()` in `cxlssd.c`):

- Each FTL request is stamped `now + op.ns`, so the media operations of one
  access (a fill, then the write-back of the victim its insert evicts) are
  serialized in modelled time, and the returned latencies accumulate in `op.ns` and in `media-time-ns`.
- After its media work, the access waits `op.ns` minus the time already
  spent, with the locks released. The wait sleeps until 100 us before the
  deadline and spins on the realtime clock for the last 100 us
  (`FEMU_CXL_SPIN_NS`), which absorbs timer slack without holding a host CPU
  for long waits such as a flush.
- The stall is charged to the vCPU inside the MMIO exit: the guest's load
  or store does not complete until the media time has passed.
- Direct hits never enter QEMU and have no modelled time. `flush-cache` and
  way changes wait on the main loop. Caching API chunks wait on the CCA
  thread.

The [timing model](../concepts/timing-model.md#cxl-ssd) lists what each kind
of access costs, and the architecture page's
[CXL load walkthrough](../concepts/architecture.md#cxl-load-walkthrough)
follows one load end to end.

## Parameters

The [property reference](../reference/properties.md#femu-cxl-ssd-cxl-type-3-ssd)
lists every property with its type, default and range; it is generated from
the binary. This table explains how they interact.

| Group | Properties | Interactions |
| --- | --- | --- |
| [Backend](../reference/properties.md#inherited-from-cxl-type3) | `volatile-memdev` | Required and the only backend accepted: `memdev`, `persistent-memdev`, `volatile-dc-memdev` and `num-dc-regions` are refused, and `lsa` only with `lsa-control=off`. Size a nonzero multiple of 256 MiB, at most 120 GiB. `der=cylon` needs it hugetlbfs, `share=on`, `prealloc=on` |
| [Cache](../reference/properties.md#cache) | `cache-pages`, `cache-policy` | `cache-pages=0` disables the cache. Otherwise at most the media page count and divisible by `cache-ways` |
| [Cache tunables](../reference/runtime-properties.md#cache-tunables-also-accepted-on--device) | `cache-ways`, `prefetch-degree`, `prefetch-stride` | Accepted on `-device` and changeable with `qom-set`. Ways must be nonzero and divide `cache-pages`. Prefetch values are bounded by the media page count; the effective degree is capped at `cache-pages` |
| [NAND geometry and timing](../reference/properties.md#nand-geometry-and-timing) | `ftl`, `channels`, `luns-per-channel`, `pages-per-block`, `blocks-per-plane`, `gc-threshold`, `gc-threshold-high`, `read-ns`, `program-ns`, `erase-ns`, `channel-ns` | Feed the private BBSSD FTL. `blocks-per-plane=0` sizes the NAND to 5/4 of the media plus 4 blocks per plane; an explicit value must leave spare lines beyond the forced collection reserve. `ftl=off` drops all media timing and forbids an NVMe link. When linked, these also apply to the NVMe namespace and the controller's own geometry and timing properties are ignored |
| Cylon media switches (same table) | `cylon-first-touch-program`, `cylon-free-writeback` | Change the media model to match published Cylon experiments; off for normal use |
| [Direct mapping](../reference/properties.md#direct-mapping-der) | `der`, `der-replace-rate`, `cylon-kernel-ack`, `concurrent-misses` | `der=memslot` is refused under TCG. `der=cylon` without `cylon-kernel-ack=on` is refused. `der-replace-rate` matters only for `memslot`. `concurrent-misses=auto` follows whether DER is available |
| [Caching API, control channel and logs](../reference/properties.md#caching-api-control-channel-and-logs) | `cca`, `lsa-control`, `log-dir`, `tracefs-dir`, `log-limit` | `cca=off` registers no BAR5. `lsa-control=on` refuses an `lsa` backend. `log-limit=0` opens no I/O log and takes no statistics appends. `tracefs-dir` unset makes commands 91 and 81 no-ops on the host |
| [Actions and control](../reference/runtime-properties.md#actions-and-control) | `der-ratio`, `control-command`, `control-argument`, `control-status`, `flush-cache`, `stats-reset`, `fast-load`, `fast-load-drain-ns`, `fast-load-switch-ns`, `nand-idle-ns` | Run time only, except `fast-load`, which `-device` also accepts. `der-ratio` needs a direct mode and no uncached ranges; `memslot` refuses a ratio that needs more aliases than are free. `fast-load=false` holds the gate alone while it sets the `post_barrier` and waits at most 100 ms for the worker to book the device DMA work before it and then tries `lock` to read the NAND horizon, with the BQL and the CXL lock dropped; it never waits for `lock` or for the horizon. `nand-idle-ns` only tries `lock` |

`run-cxlssd.sh` uses defaults that follow Cylon's launch script and differ
from the device's (a cache of 1/20 of the media, direct mapped, 8 by 8
channels and LUNs, `lsa-control=on`, and no spare NAND blocks for the `48G`
and `96G` presets); the [guide](../modes/cxl-ssd.md#with-run-cxlssdsh) has
the table.

## Counters

All counters are read-only QOM properties on the device
(`/machine/peripheral/<id>`). The
[runtime property reference](../reference/runtime-properties.md#femu-cxl-ssd-cxl-type-3-ssd)
describes each one; this table says where each family comes from.

| Family | Counted where | Notes |
| --- | --- | --- |
| [Cache](../reference/runtime-properties.md#cache-counters): `cache-hits`, `cache-misses`, `read-*`, `write-*`, `cache-inserts`, `cache-evictions`, `cache-entries`, `prefetch-inserts` | `femu_cxl_access()` and the cache library | Trapped lookups only; direct hits are invisible |
| [Snapshots](../reference/runtime-properties.md#snapshot-counters): `last-*` | `stats-reset`, control command 1 | Copies taken before the event counters are cleared |
| [Media](../reference/runtime-properties.md#media-counters): `media-reads`, `media-writes`, `media-time-ns`, `media-full`, `gc-stalls`, `gc-stall-ns` | `femu_cxl_media()` | Never cleared by `stats-reset`; take differences. `media-writes` comes from the FTL and includes linked NVMe programs |
| [Direct mapping](../reference/runtime-properties.md#direct-mapping-counters): `der-active`, `der-probes`, `der-mapped`, `der-remaps`, `der-revocations`, `der-quiet-revocations`, `der-replacements`, `der-fallbacks`, `der-emul-exit`, `der-emul-fills`, `der-emul-failures` | DER code in `qemu-adapter.c` | `der-mapped` is a gauge and the evidence that mapping is active |
| [Caching API](../reference/runtime-properties.md#caching-api-counters): `cca-*` | `cca.c` | `cca-pinned` and `cca-uncached` are gauges |
| [Other](../reference/runtime-properties.md#other-counters): `invalidations`, `nvme-drops`, `log-dropped` | Invalidation sites, NVMe drop BH, log writers | `invalidations` is a generation, not an error count |

Host-side files, all bounded by `log-limit` and written in `log-dir`:
`cxlssd-stats.log` (command 1 snapshots, ways and prefetch changes),
`cxlssd-io-N.log` (one line per trapped access: realtime start, R/W, DPA,
length, modelled ns) and `cxlssd-spt.log` (command 17 dump of tracked direct
mappings and Cylon SPTE values).

## Validation

| Layer | What runs | What it covers |
| --- | --- | --- |
| Unit tests (`hw/femu/tests/unit/`) | `test-cxl-cache.c`, `test-cxl-spte.c`, `test-cxl-cca-ring.c`, built by `hw/femu/tests/Makefile` | Policy ordering, S3-FIFO promotion and ghost admission, full-width keys, dirty accounting at 1 to 32 ways and a large fully associative cache; SPTE encodings, MMIO generation range and huge-page address arithmetic; the guest ring library against the device ring consumer, with every guest-writable index fuzzed |
| qtests (`hw/femu/tests/qtest/femu-test.c`) | About a hundred `cxl-*` cases under `qos-test` | Real PCI bridges and HDM registers programmed, then accesses through the window: all policies, readback, dirty programming, media timing, invalid configuration, `ftl=off`, mixed-window forwarding, interleaved, switched and multi-root-port topologies, memslot mappings, budget and replacement, ratios, invalidation, unplug during a wait, concurrency stress, LSA and QOM control, every caching API command, and the NVMe link (`cxl-nvme-*`) |
| Doc examples | `hw/femu/scripts/check-doc-examples.py` | Each tagged command line in the guides starts under qtest; `der=cylon` is checked to fall back with its warning |
| Guest runs on real hosts | `hw/femu/tools/cca/run-guest-tests.sh` in the guest, plus the runs recorded in the design note | A bare-metal Intel host on the fixed Cylon kernel, and a nested run under KASAN, passed write/readback across eviction cycles in all three `der` modes; caching API self-test; fio on a linked NVMe namespace next to devdax traffic with checksums on both paths |

Under qtest Cylon is deliberately inert (no KVM), so qtests cannot validate
the custom kernel: dual-slot registration, SPT mapping, SPTE revocation and
the quiet path are covered only by guest runs on a Cylon host. Long
workloads, sustained traffic past the GC threshold in a guest, hugetlb
migration during a run, and guests that online the range as system RAM for
long periods are not covered. The design note's
[scope and validation limits](../cxlssd.md#scope-and-validation-limits)
has the exact list.

## Limits

- No migration or snapshot: the device's vmstate is `unmigratable`, because
  the FTL and cache have no migration state. `migrate` fails with "State
  blocked by non-migratable device".
- Volatile only: no persistent memory, no dynamic capacity. Data is lost when
  QEMU exits.
- TCG: `der=memslot` is refused at realize (other vCPUs could keep TLB
  entries for a revoked alias). `der=cylon` needs KVM and falls back to MMIO
  under TCG and qtest. `der=off` works everywhere.
- Direct mapping only in the single-endpoint topology described above.
- `der=off` costs an exit per access: a hit takes microseconds, so large
  workloads are slow.
- With `der=off`, `lock`-prefixed operations to the window are not atomic.
- Direct hits are untimed and uncounted, and do not update CLOCK or S3-FIFO
  reference state.
- `der=memslot` holds at most 1024 aliases at once across all devices: one
  page each for cache mappings, while a ratio run counts as one alias.
- `der=cylon` needs the fixed host kernel and has the host restrictions and
  the 2 MiB first-touch effect described above.
- The caching API data rings are not implemented; their header fields are 0.

## Extending the component

| To add | Change | Check |
| --- | --- | --- |
| A cache policy | `FemuCxlPolicy` in `cache.h`, the name table in `femu_cxl_policy()`, insert and victim rules in `femu_cxl_cache_insert()` and `cache_evict()` and the requeue rule in `femu_cxl_cache_unpin()` in `cache.c`, the name table in `cxl_policy_name()` and the realize error message in `qemu-adapter.c`, the `cache-policy` description in `props.c` | `test-cxl-cache.c` builds `cache.c` without QEMU; add ordering cases there first |
| A counter | A QOM property in `cxl_init()` in `qemu-adapter.c` and its description in `cxl_runtime_descs` in `props.c` | `gen-property-docs.py --check` fails until the description exists and `reference/runtime-properties.md` is regenerated |
| A control command | `cxl_command()` in `qemu-adapter.c`; add it to `cxl_lsa_inline()` only if it never drops the locks (no media wait, flush or way change) | qtests `cxl-control-qom` and `cxl-control-lsa` run the same table both ways |
| A caching API command | The command enum in `cca-abi.h` (raise `CCA_LAYOUT_VERSION` if the layout changes), `cca_validate()`, `cca_prepare()` and the per-page handler table in `cca_exec()` in `cca.c`, the guest library in `hw/femu/tools/cca/` | `test-cxl-cca-ring.c` and the `cxl-cca-*` qtests |
| A direct mapping mode | The `der` check in `cxl_realize()`, `femu_cxl_der_init()`, and the map, remove, sample and clear entry points in `qemu-adapter.c` | Every invalidation trigger in the table above must reach it |
| Another media model | `cxl_worker()` calls `bb_ftl_process_req()`; replace the call and the FTL construction in `femu_cxl_start()` | Keep the worker free of guest memory: payload copies stay on the vCPU thread, and any future worker-side copy must use `femu_dma_rw()` |

Keep new QEMU or KVM dependencies in `qemu-adapter.c`, so `cache.c`,
`cca-ring.c`, `spte.h` and `spt.h` stay testable without QEMU and
`cxlssd.c` stays free of CXL and KVM details.

## Source map

| File | Contents |
| --- | --- |
| `hw/femu/cxlssd/qemu-adapter.c` | QOM type `femu-cxl-ssd`, realize and exit, window overlay and routing, invalidation hooks, reset chain, LSA control channel and logs, QOM properties, DER (memslot aliases, budget, replacement, ratios; Cylon prepare, install, SPTE map and revoke, listener), NVMe link ops |
| `hw/femu/cxlssd/qemu-adapter.h` | `FemuCxlMedia`, `FemuCxlOp`, `FemuCxlWork`, gate and access API |
| `hw/femu/cxlssd/cxlssd.c` | Gate, media delay, FTL worker, `femu_cxl_access()`, eviction callback, geometry checks, FTL start and stop, NVMe link side (`femu_cxl_nvme_ftl()`, drop BH, flips) |
| `hw/femu/cxlssd/cache.c`, `cache.h` | Set-associative cache and the four policies, pinning |
| `hw/femu/cxlssd/der.h` | `FemuCxlDer` and the ratio selection helpers |
| `hw/femu/cxlssd/spte.h`, `spt.h` | Cylon EPT SPTE encodings and SPT chunk limits |
| `hw/femu/cxlssd/cca.c`, `cca.h` | Caching API device side: BAR5, thread, commands |
| `hw/femu/cxlssd/cca-ring.c`, `cca-ring.h`, `cca-abi.h` | Ring consumer and the shared ABI |
| `hw/femu/cxlssd/props.c` | Property help text used by the generated reference |
| `hw/femu/tools/cca/` | Guest library, `ccactl`, `cca-test`, `run-guest-tests.sh` |
| `hw/femu/scripts/run-cxlssd.sh` | One-device launcher |
| `hw/femu/femu.c` | `cxl_ssd` link property, `femu_cxl_link_check()`, calls through `femu_cxl_nvme_ops` |
| `accel/kvm/kvm-all.c`, `include/system/kvm.h` | Generic memslot reservation hook |
| `hw/cxl/cxl-mailbox-utils.c`, `include/hw/cxl/cxl_device.h` | Generic CCI pre-command hook |

## Related pages

- [CXL SSD design note](../cxlssd.md)
- [CXL SSD guide](../modes/cxl-ssd.md)
- [CXL caching API](../features/cxl-cca.md)
- [CXL NVMe link](../features/cxl-nvme-link.md)
- [Timing model](../concepts/timing-model.md#cxl-ssd)
- [Architecture](../concepts/architecture.md)
- [Security and limits](../concepts/security-and-limits.md)
