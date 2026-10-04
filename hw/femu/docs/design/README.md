# FEMU design

This is the design document for FEMU's emulated storage devices. It explains
how FEMU is built, one component per chapter, so you can predict what a
configuration will do, read the numbers it reports, and change the code.

Read this page first. It says what FEMU models and what it leaves out, shows
how the components fit together, follows one request from the guest to the
memory backend and back, and gives the reasons for the main design choices.
Each component then has its own chapter (see [Design pages](#design-pages)).
Every chapter has the same parts: purpose, place in the hierarchy, data
structures, algorithms, threads and where time is charged, parameters,
counters, validation, limits, how to extend it, and a source map.

For a shorter tour, read [Architecture](../concepts/architecture.md). For the
property list, read the generated [property reference](../reference/properties.md).
Where this document and the code disagree, the code is right; please report
it.

## What FEMU models

FEMU is QEMU with extra device models under `hw/femu/`. A guest operating
system runs unmodified on KVM and sees a storage device built from these
models. FEMU models:

- **The host interface.** A PCIe NVMe controller (`-device femu`) with admin
  and I/O queues, doorbells, shadow doorbells, MSI-X, MSI and pin interrupts,
  Identify, features, log pages and asynchronous events. A CXL Type-3 memory
  device (`-device femu-cxl-ssd`) whose loads and stores reach an SSD model.
- **Several kinds of SSD.** `femu_mode` selects one: a conventional SSD with
  a device FTL (BBSSD), a Zoned Namespace SSD (ZNS), an Open-Channel SSD
  (OCSSD), a key-value SSD (KV), computational storage (CSD), or a plain
  memory-backed drive with no media timing (NoSSD). Namespaces of one
  controller can run different modes.
- **The FTL.** Address mapping (page-level, DFTL, two log-block schemes),
  a write buffer, a read cache, garbage collection with several victim
  policies, wear, read and retention reclaim, Flexible Data Placement.
- **NAND timing.** Channels, LUNs, planes, blocks and pages; per-cell-type
  read, program and erase times; a channel bus; program and erase suspend;
  ECC read retries as extra time.
- **Optional host-side costs.** A host link with a bandwidth and a
  propagation delay, and a single controller CPU with a fixed cost per
  command.

## What FEMU does not model

- **Cycles.** Nothing is simulated instruction by instruction or clock by
  clock. Each operation has a cost in nanoseconds, and FEMU holds the
  completion until that much host time has passed (see
  [Design choices](#design-choices)).
- **Persistent data.** Device data lives in host memory. A guest reboot or a
  controller reset keeps it; QEMU exiting loses it. Migration and snapshots
  are refused ([Security and limits](../concepts/security-and-limits.md#migration-and-snapshots)).
- **Data errors from the medium.** The media model never changes a byte.
  ECC shows up as extra read time (`ecc_step_ns`). The medium never fails a
  command on its own: failures come from the injection properties
  (`err_read_unc_ppm`, `err_write_fail_ppm`) or from rules the host sees
  (Write Uncorrectable, protection information, Open-Channel chunk state).
- **The PCIe protocol.** There are no TLPs, credits or link training. The
  optional host-link model is a bandwidth plus a fixed delay.
- **Controller firmware internals.** The optional firmware-CPU model is one
  fixed cost per Read, Write and Zone Append on one modelled core.
- **Power and heat.** The controller reports one power state, and the
  temperature is the value of the `temperature` property. Interrupt
  coalescing settings are reported but not applied.
- **Firmware update and security commands.** Firmware Download and Commit,
  Security Send and Security Receive are refused.
- **Exact guest-visible latency.** FEMU enforces a lower bound. A completion
  is posted on the first poller sweep after it is due, so a poller that does
  not get a host core adds time ([Timing model](../concepts/timing-model.md)).

## Component hierarchy

Everything FEMU adds sits inside the QEMU process. The guest reaches it in
two ways: NVMe through PCIe registers and DMA, and CXL through loads and
stores to host-managed device memory. Below the interface the two paths share
the same FTL and NAND timing code, each device with its own instance.

<!-- femu-untested: a component diagram, not a command line -->
```text
 GUEST VM
 +-------------------------------------------+  +--------------------------------------+
 | fio, databases, nvme-cli, your program    |  | programs using CXL memory            |
 | Linux NVMe driver (or SPDK, xNVMe, ...)   |  | Linux CXL driver: region, dax, NUMA  |
 +---------------------+---------------------+  +------------------+-------------------+
                       | MMIO: registers, doorbells                | loads and stores to
                       | DMA: queue entries, PRP/SGL data          | the device's range
 ======================|=========== KVM exit or guest memory ======|=====================
 QEMU PROCESS          v                                           v
 +-------------------------------------------+  +--------------------------------------+
 | 1. INTERFACE   -device femu               |  | 1. INTERFACE   -device femu-cxl-ssd  |
 |    PCIe NVMe controller, NVMe 2.1         |  |    CXL Type-3 volatile memory,       |
 |    BAR0 registers + doorbells             |  |    subclass of cxl-type3             |
 |    BAR4 MSI-X, MSI, pin; BAR2 CMB         |  |    I/O overlay "femu-cxl-media" on   |
 |  -device femu-subsys (optional)           |  |    each reachable CXL window         |
 |    CNTLID space, FDP endurance group,     |  |    BAR5 cache control (cca=on)       |
 |    namespaces shared between controllers  |  |    label area channel (lsa-control)  |
 +---------------------+---------------------+  +------------------+-------------------+
                       |                                           |
 +---------------------v---------------------+  +------------------v-------------------+
 | 2. NVMe FRONTEND                          |  | 2. CXL ACCESS PATH                   |
 |    admin queue: vCPU thread               |  |    HDM decode, page cache model      |
 |    I/O queues: femu-poller threads        |  |    (fifo, lifo, clock, s3-fifo),     |
 |    rings to_ftl[i], to_poller[i]          |  |    direct mapping (der=memslot,      |
 |    completion heap pq[i] per poller       |  |    der=cylon); vCPU waits media time |
 +---------------------+---------------------+  +------------------+-------------------+
                       | ns->ext_ops.io_cmd (per namespace)        | cache misses,
 +---------------------v---------------------+                     | write-backs
 | 3. MODE EXTENSIONS (FemuExtCtrlOps)       |                     |
 |    NoSSD  BBSSD  ZNS  OCSSD  KV  CSD      |                     |
 +---------------------+---------------------+                     |
                       |                                           |
 +---------------------v-------------------------------------------v-------------------+
 | 4. FTL     BBSSD: page | dftl | hybrid | fast mapping, write buffer, read cache,     |
 |            GC policies, wear, reclaim, FDP placement (also used by CSD, CXL SSD)    |
 |            ZNS: zone FTL and write caches      KV: hash index over NAND lines       |
 |            OCSSD: none, the host is the FTL                                         |
 +---------------------+---------------------------------------------------------------+
                       |
 +---------------------v---------------------------------------------------------------+
 | 5. NAND TIMING  nand-media.c: busy-until time per LUN or plane, channel bus,       |
 |                 cell-type tables, suspend, ECC     oc-timing.c: OCSSD 0xEE times    |
 +-------------------------------------------------------------------------------------+

 6. MEMORY BACKEND (data only; layers 4 and 5 never touch it)
    femu:         one host buffer of devsz_mb MiB (backend/dram.c), namespaces packed in it;
                  BBSSD with op_pcent: the NAND capacity; shared subsystem or cxl_ssd:
                  borrowed from the subsystem or the medium
    femu-cxl-ssd: the memory-backend object named by volatile-memdev
    KV:           a value store of its own
    NVMe: layers 2 and 3 copy data before any time is charged (power_loss=on:
    the FTL thread does). CXL: the vCPU copies after the media wait.
```

| Layer | What it does | Chapter |
| --- | --- | --- |
| 1. Interface | PCI function, registers, CXL decode, subsystem | [nvme-frontend.md](nvme-frontend.md), [cxl-ssd.md](cxl-ssd.md), [namespaces.md](namespaces.md) |
| 2. Frontend | queues, pollers, dispatch, completion timing, interrupts | [nvme-frontend.md](nvme-frontend.md) |
| 3. Mode extensions | the command set and behaviour of each kind of SSD | [ocssd.md](ocssd.md), [zns.md](zns.md), [kvssd.md](kvssd.md), [csd.md](csd.md), [nossd.md](nossd.md), [fdp.md](fdp.md) |
| 4. FTL | mapping, buffering, GC, wear | [ftl.md](ftl.md) |
| 5. NAND timing | how long each NAND operation takes | [nand-timing.md](nand-timing.md) |
| 6. Memory backend | where the bytes live | this page, [namespaces.md](namespaces.md) |

### Device types

| QOM type | Parent | On the command line | Role |
| --- | --- | --- | --- |
| `femu` | `TYPE_PCI_DEVICE`, PCIe endpoint | `-device femu,...` | the NVMe controller and all its namespaces |
| `femu-subsys` | `TYPE_DEVICE`, on no bus | `-device femu-subsys,id=s0,...` before the controllers | joins controllers (`subsys=s0`), holds FDP and shared namespaces |
| `femu-cxl-ssd` | `cxl-type3` | `-device femu-cxl-ssd,volatile-memdev=...` on a CXL root port | a CXL memory device backed by an SSD model |

There is no namespace device: a controller builds its namespaces from
`namespaces`, `namespace_sizes` and `namespace_modes`, and Namespace
Management adds more at run time. `femu-subsys` creates an `nvme-bus`
(a type FEMU borrows from QEMU's own NVMe controller) but no FEMU device
plugs into it. A `femu` controller can also serve a `femu-cxl-ssd` medium as
its one namespace with `cxl_ssd=<id>`; it then uses the medium's memory and
FTL instead of its own.

## How a request flows

### One NVMe write on a BBSSD namespace

The data moves first; the time is computed afterwards and enforced at
completion. Time runs downward.

```text
 guest driver        vCPU thread          femu-poller i                FEMU-FTL-Thread         backend
      |                   |                    |                              |                    |
  1   | SQE into SQ ring  |                    |                              |                    |
      | tail doorbell --->| nvme_process_db_io |                              |                    |
      | (or shadow entry) | stores sq->tail    |                              |                    |
      |                   | (nothing else)     |                              |                    |
  2   |                   |                    | sweep: nvme_process_sq_io    |                    |
      |                   |                    | copy SQE, stime = now,       |                    |
      |                   |                    | expire_time = now            |                    |
  3   |                   |                    | nvme_io_cmd -> ns ext_ops    |                    |
      |                   |                    | -> nvme_rw: check, map PRP   |                    |
      |                   |                    |    backend_rw copies data ---+------------------->|
  4   |                   |                    | to_ftl[i] enqueue ---------->|                    |
  5   |                   |                    |                              | femu_ftl_process_req
      |                   |                    |                              | FTL: map, GC, ...  |
      |                   |                    |                              | NAND: program time |
      |                   |                    |                              | expire_time += lat |
      |                   |                    |<------------ to_poller[i] ---|                    |
  6   |                   |                    | nvme_process_cq_cpl:         |                    |
      |                   |                    | + host link, + firmware CPU, |                    |
      |                   |                    | insert into heap pq[i]       |                    |
      |                   |                    | next sweeps: is now >=       |                    |
      |                   |                    | expire_time? not yet: keep   |                    |
  7   |<---------------------- CQE written ----| yes: post CQE, then one      |                    |
      |<---------------------- interrupt ------| interrupt per CQ per sweep   |                    |
  8   | CQ head doorbell->| head stored        |                              |                    |
```

1. The guest writes a submission queue entry and rings the tail doorbell. The
   vCPU exits to QEMU, which stores the new tail and returns. With shadow
   doorbells the guest also writes the value to its own memory and rings the
   register only when the EventIdx protocol asks for it.
2. The poller that owns the queue finds the new entry on its next sweep and
   stamps the request with the host time.
3. The command is checked and dispatched to the namespace's mode. For a block
   Read or Write the data is copied between guest memory and the backend now,
   on the poller thread. (With `power_loss=on` the FTL thread executes the
   command, data copy included, in step 5.)
4. The request goes to the FTL thread through a lock-free ring.
5. The FTL decides where the page goes, runs GC if needed, and asks the NAND
   model when the program would end. The difference is added to the request's
   completion time.
6. Back on the poller, optional host-link and firmware-CPU time is added, and
   the request waits in a min-heap ordered by completion time.
7. Once the host clock passes that time, the poller writes the completion
   entry and raises the queue's interrupt.
8. The guest consumes the entry and moves the completion queue head.

Modes differ only in steps 3 to 5. NoSSD charges nothing and, on a NoSSD
controller with the default settings, posts the completion inside step 3's
sweep. OCSSD and KV compute
their time on the poller in step 3 and skip the FTL thread. ZNS and CSD use
the FTL thread like BBSSD. [nvme-frontend.md](nvme-frontend.md) has the full
command lifecycle.

### One CXL load that misses

```text
 guest vCPU           vCPU thread in QEMU (BQL)               femu-cxl-ftl worker    memory backend
     |                         |                                      |                    |
     | load from device range  |                                      |                    |
     |------------------------>| femu-cxl-media overlay: decode HDM   |                    |
     |                         | femu_cxl_access: cache lookup, miss  |                    |
     |                         | drop BQL, queue NAND read ---------->| FTL + NAND model   |
     |                         |<------------------- media time ------|                    |
     |                         | evict victim (dirty: write-back cost)|                    |
     |                         | femu_cxl_delay: sleep, then spin     |                    |
     |                         | until the media time has passed      |                    |
     |                         | copy bytes from the backend ---------+------------------->|
     |<------------------------| load completes                       |                    |
```

A hit skips the worker and the wait. With direct mapping (`der`), subsequent
accesses to a cached page do not leave the guest at all.
[cxl-ssd.md](cxl-ssd.md) covers the cache, the decoders and direct mapping.

## Threads and where time is charged

```text
  vCPU threads ----- MMIO: registers, doorbells, admin queue, AER, CXL accesses (+ wait)
  main loop -------- QMP, interrupt bottom halves without irqfd, AER posting, CXL BHs
  femu-poller x N -- I/O fetch, command execution and data copy (not with power_loss=on),
                     OCSSD/KV/CSD-compute time,
                     host-link and firmware-CPU time, completion posting, interrupts
  FEMU-FTL-Thread -- BBSSD, CSD and ZNS FTL and NAND time (0 or 1 per controller);
                     with power_loss=on it also executes each I/O command; for a
                     cxl_ssd link it calls into the medium's FTL
  femu-cxl-ftl ----- FTL and NAND time for CXL misses and write-backs (1 per medium)
  femu-cxl-cca ----- cache control commands from BAR5 (only with cca=on)
```

| Device or mode | Time computed in | Time enforced by |
| --- | --- | --- |
| NoSSD | nothing to compute | poller heap, usually in the same sweep |
| BBSSD, ZNS, CSD NAND time | `FEMU-FTL-Thread` | poller heap |
| OCSSD, KV, CSD compute units and CSD memory-copy reads | the poller, while executing the command | poller heap |
| Host link, firmware CPU | the poller, before the heap | poller heap |
| `femu-cxl-ssd` | `femu-cxl-ftl` | the vCPU waits before the access completes |

## Design pages

| Page | Component |
| --- | --- |
| [nvme-frontend.md](nvme-frontend.md) | The NVMe controller: PCI and BAR layout, doorbells and shadow doorbells, queues, pollers, dispatch, completion timing, interrupts, reset and teardown |
| [ftl.md](ftl.md) | The BBSSD FTL: mapping schemes, write buffer, read cache, lines, GC and victim policies, wear and reclaim |
| [nand-timing.md](nand-timing.md) | The NAND media layer: geometry, cell types, per-LUN and per-plane busy time, channel bus, suspend, ECC |
| [zns.md](zns.md) | Zoned Namespaces: zone state machine, zone FTL, write caches, Zone Append, ZRWA |
| [fdp.md](fdp.md) | Flexible Data Placement: endurance group, reclaim units and handles, placement and GC |
| [namespaces.md](namespaces.md) | Namespaces and the subsystem: sizing, per-namespace modes, Namespace Management, shared namespaces |
| [ocssd.md](ocssd.md) | Open-Channel SSD 1.2 and 2.0: the host-managed interface and its timing |
| [kvssd.md](kvssd.md) | The NVMe Key Value command set and its FTL |
| [csd.md](csd.md) | Computational storage: compute units, device memory, programs |
| [nossd.md](nossd.md) | NoSSD: memory-backed NVMe with no media timing |
| [cxl-ssd.md](cxl-ssd.md) | The CXL SSD: address decoding, page cache, direct mapping, cache control, NVMe link |

## Design choices

Each choice below says what FEMU does and why.

**Charge latency, then hold the completion.** FEMU does not simulate
hardware cycles. A command's data is moved at memory speed, a model computes
how long the command would take, and the completion is withheld until the
host clock passes that time. The guest therefore runs at native speed with
its real driver and file system, and still sees device-like latencies. The
price is that FEMU sets a lower bound: if the poller does not run, the
completion is posted after it is due. Give pollers and the FTL thread their
own cores when you measure ([performance tuning](../guides/performance-tuning.md#threads-and-cores)).

**Host wall-clock time.** Requests are stamped with `QEMU_CLOCK_REALTIME`,
the clock the guest also observes. A 200 us program makes the guest wait
200 us. There is no virtual time that could diverge from what the guest
measures.

**Data in host memory, separate from timing.** The FTL and NAND model keep
metadata only: mappings, valid bits, busy-until times. The bytes go straight
to one host buffer at the namespace's offset. This keeps the models simple
and fast, makes a read return the last write no matter what the FTL did, and
lets a mapping bug change timing but never corrupt data. The cost is that
capacity is bounded by host RAM and data does not survive QEMU. The
power-loss model (`power_loss=on`) is the one place the FTL thread applies
data, because it has to roll back unflushed writes.

**Polling threads instead of trapping each I/O.** A doorbell write only
stores a number. Dedicated `femu-poller` threads fetch commands and post
completions. Doing the work on the vCPU would make every command pay a VM
exit and stall the guest CPU, and a trap-driven design cannot post a
completion at a chosen microsecond. The cost is host cores that spin while the controller is
enabled.

**One owner per queue.** A poller fetches from a submission queue without a
lock, so each queue has exactly one poller. `multipoller_enabled` accepts only
0 (one poller, all queues) or 1 (queues split round-robin). An older value
greater than 1 started several pollers that each swept every queue, and two
of them then executed and completed the same command; realize now refuses it.

**A separate FTL thread with single-threaded state.** One `FEMU-FTL-Thread`
per controller owns the FTL and NAND state of every BBSSD, ZNS and CSD
namespace, so that state needs no locks. Pollers hand requests over through
single-consumer rings and keep fetching while the FTL computes.

**Modes as handler tables.** A mode is a `FemuExtCtrlOps` table: init, exit,
start, admin, I/O and log hooks. The frontend handles everything shared
(queues, Identify, features, common NVM commands) and passes the rest to the
table of the namespace a command addresses. Adding a kind of SSD means adding
a table, and one controller can serve namespaces of different modes.

**Refuse, do not guess.** Settings that cannot work together fail realize
with a message that names the property, with a few exceptions the property
reference states (for example `ns_mgmt`, which stays off without an error on
a controller that cannot support it), and properties that are accepted but
have no effect print a warning. A configuration that starts is one FEMU can
serve as described.

**CXL accesses wait on the vCPU.** A load or store cannot complete out of
order the way an NVMe command can, so the `femu-cxl-ssd` path charges media
time on the vCPU thread that made the access, with the BQL released so other
vCPUs keep running.

## Glossary

| Term | Meaning |
| --- | --- |
| BAR | PCI Base Address Register: a window of device registers or memory. `femu` uses BAR0 (registers, doorbells), BAR2 (CMB), BAR4 (MSI-X) |
| BBSSD | black-box SSD, `femu_mode=1`: a conventional SSD with a device FTL |
| BQL | QEMU's big lock. vCPU MMIO handlers and the main loop hold it; pollers and FTL threads do not |
| CC, CSTS | Controller Configuration and Controller Status registers; `CC.EN` enables the controller, `CSTS.RDY` says it is ready |
| CMB | Controller Memory Buffer, device memory the host can place queues or data in (`cmbsz`, `cmbloc`) |
| CNTLID | controller identifier, unique within a subsystem |
| CQ, SQ, CQE, SQE | completion and submission queues and their entries |
| CSD | computational storage device, `femu_mode=4` |
| DER | direct mapping of cached CXL SSD pages into the guest (`der=memslot` or `der=cylon`) |
| DFTL | a demand-loaded page mapping table with a cached mapping table (`mapping=dftl`) |
| Doorbell | a BAR0 register the host writes a queue's new tail (SQ) or head (CQ) to |
| EventIdx | in the Doorbell Buffer Config scheme, the value the controller publishes so the host knows when it must still ring the real doorbell |
| `expire_time` | a request's completion time in host nanoseconds; the poller posts it no earlier |
| `ext_ops` | a mode's `FemuExtCtrlOps` handler table, per controller and per namespace |
| FDP | Flexible Data Placement: reclaim units and placement handles on `femu-subsys` |
| FTL | flash translation layer: maps logical pages to NAND pages and reclaims space |
| GC | garbage collection: copying valid pages out of a line so it can be erased |
| HDM | host-managed device memory, the address range a CXL Type-3 device decodes |
| irqfd | a KVM mechanism that lets a thread inject an MSI-X interrupt without the BQL |
| KV | key-value SSD, `femu_mode=5`, the NVMe Key Value command set |
| Line | a superblock: the same block index on every plane of every LUN; the unit of GC |
| LUN | a NAND die that runs one operation at a time; channels hold LUNs |
| NoSSD | `femu_mode=2`, the default: NVMe backed by memory with no media timing |
| OCSSD | Open-Channel SSD, `femu_mode=0`: the host addresses NAND directly |
| `pq[i]` | poller `i`'s min-heap of timed requests, ordered by `expire_time` |
| PRP, SGL | the two ways an NVMe command describes its data buffers |
| Poller | a `femu-poller` thread that fetches I/O commands and posts completions |
| Realize | QEMU's device construction step; property checks happen here |
| Shadow doorbell | a host-memory copy of the doorbells set up with Doorbell Buffer Config; FEMU polls it |
| Sweep | one pass of a poller over its queues and its completion heap |
| `to_ftl[i]`, `to_poller[i]` | the rings between poller `i` and the FTL thread |
| WAF | write amplification factor: NAND pages programmed per host page written |
| ZNS | Zoned Namespace SSD, `femu_mode=3` |

## Source map

| Path | Contents |
| --- | --- |
| `hw/femu/femu.c` | QOM types `femu` and `femu-subsys`, realize and exit, property checks, registers and doorbells, the FTL thread, mode registration |
| `hw/femu/femu-props.c` | property help text |
| `hw/femu/nvme-admin.c`, `nvme-io.c`, `nvme-util.c`, `dma.c`, `intr.c` | the NVMe frontend |
| `hw/femu/nvme-pel.c`, `nvme-pi.c`, `nvme-streams.c` | Persistent Event Log, protection information, Streams |
| `hw/femu/nossd/`, `bbssd/`, `zns/`, `ocssd/`, `kvssd/`, `csd/` | the modes; `bbssd/` also holds the FTL |
| `hw/femu/nand/`, `hw/femu/ocssd/oc-timing.c` | NAND timing |
| `hw/femu/backend/dram.c` | the memory backend |
| `hw/femu/cxlssd/` | the CXL SSD |
| `hw/femu/lib/` | rings and the priority queue |
| `hw/femu/nvme.h` | shared structures, constants and the mode enum |

[Code structure](../development/code-structure.md) lists every file.

## Related pages

- [Architecture](../concepts/architecture.md)
- [Timing model](../concepts/timing-model.md)
- [Choosing a mode](../concepts/choosing-a-mode.md)
- [Security and limits](../concepts/security-and-limits.md)
- [Device property reference](../reference/properties.md)
- [Log pages and counters](../reference/log-pages-and-counters.md)
