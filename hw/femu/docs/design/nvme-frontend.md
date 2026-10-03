# NVMe frontend

The NVMe frontend is the part of `-device femu` that a guest driver talks to:
the PCI function, the controller registers, the admin and I/O queues, the
poller threads that fetch and complete commands, and the interrupts. It turns
NVMe commands into calls to a mode (BBSSD, ZNS, KV and the others) and holds
each completion until the time the mode charged has passed.

This chapter describes the frontend as the code in this tree implements it.
The [design overview](README.md) shows where it sits among the other
components.

## Place in the hierarchy

```text
              guest NVMe driver
                 |          ^
   MMIO writes   |          | CQEs and interrupts
   DMA reads     v          |
 +-------------------------------------------------------------------+
 | NVMe FRONTEND (this chapter)                                      |
 |   PCI function, BAR0 registers, doorbells, shadow doorbells       |
 |   admin queue (vCPU thread)   I/O queues (femu-poller threads)    |
 |   dispatch, completion heap, interrupts, reset, teardown          |
 +-------------------------------------------------------------------+
        | ns->ext_ops.io_cmd         | to_ftl[i]      ^ to_poller[i]
        v                            v                |
   mode extensions             FEMU-FTL-Thread (BBSSD, ZNS, CSD)
   (zns.md, kvssd.md, ...)     (ftl.md, nand-timing.md)
        |
        v
   memory backend (data copies happen here, on the poller)
```

## PCI function and BAR layout

The controller is a PCIe endpoint with class code 01 08 02 (NVMe). Its vendor
and device IDs come from `vid` and `did` (by default `1d1d:1f1f`), and it
reports NVMe version 1.4. It has INTA, an MSI capability with up to 32
vectors at config offset 0x50, a PCIe capability at 0x80, and MSI-X with
`queues` + 1 vectors in a BAR of its own. `nvme_init_pci()` sets this up.

| BAR | Contents | When |
| --- | --- | --- |
| 0-1 | controller registers and doorbells (64-bit) | always |
| 2-3 | Controller Memory Buffer (64-bit) | `cmbsz` non-zero; `cmbloc` must select BAR 2 |
| 4-5 | MSI-X table and pending bits | always |

```text
 BAR0, reg_size bytes
 offset   register   FEMU behaviour
 0x0000   CAP        MQES = entries, CQR = cqr, AMS = 1, TO = 0xf, DSTRD = stride,
                     NSSRS = 0, CSS = NVM + I/O command sets by CSI,
                     MPSMIN = mpsmin, MPSMAX = mpsmax                      read only
 0x0008   VS         0x00010400 (1.4)                                      read only
 0x000c   INTMS      set interrupt mask bits (MSI and pin; ignored with MSI-X)
 0x0010   INTMC      clear interrupt mask bits; a held MSI is sent when unmasked
 0x0014   CC         EN, SHN, MPS, IOSQES, IOCQES; see the state machine below
 0x001c   CSTS       RDY, CFS, SHST                                        read only
 0x0020   NSSR       reads 0; writes ignored (no subsystem reset)
 0x0024   AQA        admin ASQS and ACQS, 1..4095 (0's based): 2..4096 entries
 0x0028   ASQ        admin SQ base, 64 bits, may be written as two dwords
 0x0030   ACQ        admin CQ base, 64 bits, may be written as two dwords
 0x0038   CMBLOC     cmbloc                                                read only
 0x003c   CMBSZ      cmbsz                                                 read only
 0x1000   doorbells: DB = 4 << stride bytes
          0x1000 + (2 * qid)     * DB   SQ qid tail
          0x1000 + (2 * qid + 1) * DB   CQ qid head
          qid 0 is the admin pair, 1 .. queues are I/O queues

 reg_size = max(16 KiB, pow2ceil(0x1000 + 2 * (queues + 1) * DB))
```

BAR0 is at least 16 KiB because the PCIe transport makes bits 13:4 of the BAR
read only. Writes go to `nvme_mmio_write()`: offsets inside the register block
go to `nvme_write_bar()`, the admin doorbell pair to `nvme_process_db_admin()`,
and everything else to `nvme_process_db_io()`. All of them run on the vCPU
thread that made the access, holding the BQL.

The CMB is an I/O memory region (`nvme_cmb_ops`) backed by a host buffer of
the size `cmbsz` describes. PRP and SGL data pointers, and the entries of
PRP-list queues, that fall inside it are served from that buffer
(`nvme_addr_is_cmb()` in `hw/femu/dma.c`). A physically contiguous queue is
mapped directly and has no CMB case.

## Controller states

```text
                 realize
                    |
                    v
        +-----------------------+   the host programs AQA, ASQ, ACQ
        | DISABLED              |   and the CC fields while EN = 0
        | CC.EN=0  CSTS.RDY=0   |<------------------------------------------+
        +-----------+-----------+                                          |
                    | CC.EN 0 -> 1                                         |
                    v                                                      |
        nvme_start_ctrl():                                                 |
          check MPS against CAP, IOSQES/IOCQES, AQA, ASQ/ACQ alignment      |
          map the admin CQ and SQ                                          |
          run each distinct mode's start_ctrl hook                         |
          nvme_start_dataplane(): create pollers on the first enable,      |
          set dataplane_started                                            |
             | all ok                       | any check fails              |
             v                              v                              |
   +-------------------+          +-------------------+                    |
   | READY  RDY=1      |          | FAILED  CFS=1     |---- CC.EN 1 -> 0 --+
   +----+---------+----+          +-------------------+                    |
        |         | CC.SHN set (EN still 1)                                |
        |         v                                                        |
        |   nvme_clear_ctrl(shutdown), CSTS.SHST = complete                |
        | CC.EN 1 -> 0                                                     |
        v                                                                  |
   nvme_write_bar(), CC.EN 1 -> 0:                                         |
     nvme_clear_ctrl(): pause pollers and FTL thread; drop held AERs and   |
       queued events; drain and free every SQ and CQ; deassert the pin;    |
       reset features; unmap the shadow doorbell buffers                   |
     then clear RDY, CFS and SHST, reset the Timestamp, and record a       |
     reset in the Persistent Event Log ------------------------------------+
```

A shutdown with CC.EN still 1 runs `nvme_clear_ctrl()` but leaves RDY set
and resets neither the Timestamp nor the Persistent Event Log context.

Pollers are created once and survive a reset; a reset only clears
`dataplane_started` until the next enable. With `power_loss=on`, a normal
shutdown (CC.SHN = 01b) first flushes the BBSSD write buffer, and a failed
flush sets CSTS.CFS.

## Queues

### Data structures

| Structure | Fields that matter |
| --- | --- |
| `NvmeSQueue` | `sqid`, `cqid` (the CQ it reports to), `head`, `tail`, `size`; `dma_addr` and `dma_addr_hva` (contiguous ring) or `prp_list`; `io_req` (one `NvmeRequest` per slot) and `req_list` (the free ones); `db_addr`/`db_addr_hva` and `eventidx_addr`/`eventidx_addr_hva` (shadow doorbell); `is_active` |
| `NvmeCQueue` | `cqid`, `head`, `tail`, `size`, `phase`; `vector`, `irq_enabled`, `virq` and `guest_notifier` (irqfd route), `irq_bh` (fallback); `sq_list`; `post_lock`; the same four shadow doorbell fields; `is_active` |
| `NvmeRequest` | `cmd`, `cqe`, `sq`, `ns`, `status`; `slba`, `nlb`, `is_write`, `xfer_bytes`; `stime`, `expire_time`, `reqlat` (ns); `cxl_seq` |
| `FemuCtrl` | `sq[]`, `cq[]` (index 0 is admin); `nr_pollers`, `poller[]`; `to_ftl[]`, `to_poller[]`, `pq[]`, `cpl_backlog[]`, `should_isr`, `poller_in_sweep[]`, `poller_ctr[]` (all indexed by poller, 1-based); `dataplane_started`, `ftl_in_sweep`, `use_ftl_thread` |

A submission queue owns one request per slot, so it can have at most `size`
commands outstanding; when its free list is empty the poller leaves the rest
of the queue for a following sweep.

### Admin queue

The admin queue pair is created from AQA, ASQ and ACQ when the controller is
enabled. It is processed synchronously: a write to the admin SQ tail doorbell
calls `nvme_process_sq_admin()` on the vCPU thread, which fetches each new
entry, runs `nvme_admin_cmd()`, writes the completion and notifies the admin
CQ's interrupt. It fetches only while the admin CQ has a free slot; a CQ head
doorbell write resumes it. The admin queue always uses its doorbell registers,
even after Doorbell Buffer Config.

Admin commands that free or replace state the I/O path reads (Delete SQ and
CQ, Format NVM, Namespace Management and Attachment, Sanitize, Streams, some
Set Features) first stop the pollers and the FTL thread with
`nvme_pause_pollers()` and restart them after (see
[Quiescing the data plane](#quiescing-the-data-plane)).

### I/O queues

The host creates I/O queues with Create I/O CQ and Create I/O SQ. Queue ids run
from 1 to `queues`, sizes from 2 to `entries` + 1. With `cqr=1` (the default)
queues must be physically contiguous; with `cqr=0` a queue may be a PRP list.
A completion queue's interrupt vector must be at most `queues`, and below the
number of MSI vectors the guest enabled when MSI is in use. Several SQs may
share one CQ.

A new SQ is published with a write barrier before `is_active` is set, and the
poller reads `is_active` with a read barrier before using the queue, so a
poller never sees a half-built queue. Delete I/O SQ pauses the data plane,
returns the queue's requests to it, and frees it. Delete I/O CQ is refused
while an SQ still reports to it.

Set Features Number of Queues reports `queues` for both SQs and CQs and is
accepted only before any I/O queue exists.

## Doorbells and shadow doorbells

### Doorbell registers

A doorbell write records the new value and returns. For an I/O SQ the vCPU
stores `sq->tail`; the poller notices it on its next sweep. For an I/O CQ it
stores `cq->head`, notifies the CQ again if entries remain, and on the pin
updates the interrupt level. A write to a doorbell that does not exist, or of
a value past the end of its queue, is ignored and, while the controller is
ready, raises an Error asynchronous event (event information 00h, write to an
invalid doorbell register, or 01h, invalid doorbell write value). An I/O
doorbell write that is not aligned to DB, and a register write to a queue
that has a shadow doorbell, are dropped without an event (for a shadowed CQ
the write only updates the pin level).

### Doorbell Buffer Config

The controller always advertises Doorbell Buffer Config (OACS bit 8). The host
gives two page-aligned pages of its memory with this admin command: a shadow
doorbell page, where it writes tails and heads instead of the registers, and
an EventIdx page, where the controller writes back hints.
`nvme_set_db_memory()` maps both pages and points every existing I/O queue at
its two entries:

```text
 shadow doorbell page (host writes)              EventIdx page (controller writes)
 entry size DB = 4 << stride bytes               same layout
 offset          +------------------+            +------------------+
 0 * DB          | SQ0 tail (unused)|            | SQ0 EventIdx     | admin pair: kept
 1 * DB          | CQ0 head (unused)|            | CQ0 EventIdx     | equal to the value
 2 * DB          | SQ1 tail         |            | SQ1 EventIdx     | just written
 3 * DB          | CQ1 head         |            | CQ1 EventIdx     |
 ...             | ...              |            | ...              |
 2q * DB         | SQq tail         |            | SQq EventIdx     |
 (2q + 1) * DB   | CQq head         |            | CQq EventIdx     |
                 +------------------+            +------------------+
```

Rules the code enforces:

- Both addresses must be non-zero and page aligned, and both pages must map
  completely; otherwise the command fails with Invalid Field and nothing is
  recorded.
- The pages are set once per enable. A second command before a reset fails.
- All entries must fit in one page: (2 x `queues` + 1) x DB bytes at most.
  With a 4 KiB page and `stride=0` that is 511 I/O queues.
- Each queue that already exists is seeded with its current tail or head
  before it is switched to its entry, so a poller never reads a stale zero.
  A queue created afterwards starts at 0 and points at its entry at once,
  relying on the host's zeroed entry.
- A controller reset unmaps both pages and forgets them.

Once a queue has a shadow doorbell, its register doorbell no longer moves it.
The poller reads the SQ tail from the shadow at the start of every sweep
(`nvme_update_sq_tail()`) and the CQ head whenever it checks for space or
posts an interrupt (`nvme_update_cq_head()`). A value past the end of the
queue is ignored.

### EventIdx

With shadow doorbells the host rings the real doorbell only when its new
value passes the EventIdx the controller published. FEMU's pollers read the
shadow values of every active I/O queue on every sweep, so I/O queues do not
depend on doorbell writes. Two queues are handled differently:

- **The admin pair** keeps its EventIdx equal to the value just written, so a
  host that follows the EventIdx protocol still rings it (the admin queue is
  driven only by its registers).
- **Pin interrupts.** With neither MSI-X nor MSI enabled, the CQ EventIdx is
  the head itself. The pin is level triggered and can only drop after the host
  reports its new head, so the host must ring the CQ head doorbell after every
  batch; the register write then updates the pin level.

## Pollers

### How many and who owns what

`nvme_init_poller()` creates the pollers the first time the host enables the
controller. Their number depends on two properties:

| `multipoller_enabled` | Pollers | Poller `i` of `N` owns |
| --- | --- | --- |
| `0` (default) | 1 | every I/O SQ |
| `1` | ceil(`queues` / `poller_ratio`); `poller_ratio=0` counts as 1 | SQs `i`, `i + N`, `i + 2N`, ... |
| anything else | realize fails | |

```text
 multipoller_enabled=0                 multipoller_enabled=1, queues=8, poller_ratio=3
                                       N = ceil(8 / 3) = 3

 femu-poller 1: SQ1 SQ2 ... SQ8        femu-poller 1: SQ1 SQ4 SQ7
                                       femu-poller 2: SQ2 SQ5 SQ8
                                       femu-poller 3: SQ3 SQ6

 per poller i:  to_ftl[i]    ring, poller i -> FTL thread, holds 65535
                to_poller[i] ring, FTL thread -> poller i, holds 65535
                pq[i]        min-heap on expire_time, starts at 65536, grows
                cpl_backlog[i]  completions waiting for CQ space
                should_isr row  which CQs to interrupt after this sweep
                poller_in_sweep[i], poller_ctr[i]
```

<!-- femu-example: frontend-sharded-pollers -->
```text
-device femu,femu_mode=2,queues=8,multipoller_enabled=1,poller_ratio=3
```

Every SQ has exactly one owner because a poller fetches from it without a
lock. Values of `multipoller_enabled` greater than 1 used to start one poller
per shard but had each of them sweep every queue; two pollers then fetched,
executed and completed the same command. Realize now refuses them.

A CQ is not owned. Its SQs may belong to different pollers, so with more than
one poller a completion is posted under the CQ's `post_lock`, and each poller
keeps its own row of `should_isr` flags.

### The sweep

```text
 nvme_poller(i), forever until poller_stopping:
   if !dataplane_started: in_sweep = false, sleep 1 ms, retry
   in_sweep = true; smp_mb; recheck dataplane_started
   for each SQ this poller owns, active and with an active CQ:
       nvme_process_sq_io(sq, i)          fetch and execute new commands
   nvme_process_cq_cpl(i)                 time and post completions
   smp_mb; in_sweep = false
```

A poller never sleeps while the data plane runs: it spins on a host core.
Plan one core per poller and one for the FTL thread
([performance tuning](../guides/performance-tuning.md#threads-and-cores)).

## Command lifecycle

```text
 SQ slot in guest memory (or the CMB)
   |  nvme_process_sq_io(): copy the 64-byte SQE, take a free NvmeRequest,
   |  stime = expire_time = now (QEMU_CLOCK_REALTIME)
   v
 nvme_io_cmd()
   |  nsid -> nvme_ns(): allocated and attached, else Invalid Namespace
   |  Flush, Dataset Management, Compare, Write Zeroes, Copy, Verify,
   |  Write Uncorrectable, I/O Management Send/Receive: handled here
   |  any other opcode -> ns->ext_ops.io_cmd() of the namespace's mode
   |     NoSSD, BBSSD, CSD Read/Write: nvme_rw() maps PRP/SGL, copies data
   |     ZNS, OCSSD, KV: their own paths; OCSSD and KV add NAND time now
   |  status stored; on success the SMART host counters are updated
   v
 to_ftl[i] (every request, failed ones included)
   |
   +-- controller has an FTL thread: it dequeues, calls
   |   femu_ftl_process_req(), adds the latency to expire_time,
   |   enqueues on to_poller[i]
   +-- no FTL thread: the poller reads to_ftl[i] itself
   v
 nvme_process_cq_cpl(i)
   |  add host-link time (Read, Write) and firmware-CPU time
   |  (Read, Write, Zone Append), insert into pq[i]
   |  retry cpl_backlog[i]
   |  while the heap's earliest request is due (now >= expire_time)
   |  and, for a CXL-linked request, the medium has dropped stale pages:
   |      CQ inactive -> request back to the free list
   |      CQ full     -> cpl_backlog[i]
   |      otherwise   -> post CQE
   v
 request back on sq->req_list; should_isr[cqid] = true
 end of sweep: for each flagged CQ, raise its interrupt
```

Things to note:

- **Data moves before time is charged.** By the time a request reaches
  `to_ftl[i]`, a Read's data is already in guest memory and a Write's data is
  already in the backend. The FTL thread only computes time. (With
  `power_loss=on` the poller skips `nvme_io_cmd()` and the FTL thread
  executes every I/O command, data copy included, through `nvme_power_io()`.)
- **Failed commands take the same path.** A request with an error status is
  still enqueued; the mode charges it nothing, and it completes as soon as the
  poller sees it again (in the same sweep when there is no FTL thread), plus
  any host-link or firmware-CPU time, which is charged regardless of status.
  Skipping the ring would leak the request.
- **Order.** Completions are posted in `expire_time` order per poller, not in
  submission order.
- **Full completion queues.** A due completion whose CQ has no free slot waits
  in the poller's backlog, and the poller retries it every sweep.
- **Abort** looks for the command in the SQ between head and tail with the
  pollers paused. If it is there, the controller records it in its own state
  (the SQ itself is never written) and the Abort completes with dword 0 bit 0
  clear; the command then completes with Command Abort Requested when it is
  fetched, without running. A command already fetched is not aborted, and the
  Abort completes with bit 0 set. Admin commands run one at a time, so the
  Aborts outstanding together are the one running and those still in the
  admin SQ; with more than `acl` of them waiting, the running one fails with
  Abort Command Limit Exceeded. A command queued behind an Abort on the admin
  queue can be aborted too.

## Completion timing

`nvme_process_cq_cpl()` is where FEMU enforces latency. A request's
`expire_time` starts at its fetch time and grows as each model adds to it:

| Added by | When | Property |
| --- | --- | --- |
| OCSSD, KV, CSD compute units | while the command executes on the poller | mode properties |
| FTL thread (BBSSD, ZNS, CSD NAND time) | before `to_poller[i]` | FTL and NAND properties |
| host link | in `nvme_process_cq_cpl()`; a per-direction next-free time | `pcie_bandwidth_mbps`, `pcie_prop_delay_ns` |
| firmware CPU | in `nvme_process_cq_cpl()`; one next-free time for the controller | `fw_cpu_ns` |

The heap `pq[i]` is a binary heap (`hw/femu/lib/pqueue.c`) keyed on
`expire_time`. Each sweep pops every request that is due and stops at the
first that is not. Nothing sleeps: a request simply stays in the heap until a
sweep finds it due. The guest therefore sees at least the charged time, plus
however long the poller takes to come round.

The clock is `QEMU_CLOCK_REALTIME`. Only the qtest-only property
`x-oc12-clock` switches it to the virtual clock, for deterministic tests.

## Interrupts

Each I/O CQ created with interrupts enabled gets its vector. After a sweep
that posted to a CQ through the heap, the poller calls `nvme_isr_notify_io()`
once for that CQ:

```text
 nvme_isr_notify_io(cq)                      (poller thread, no BQL)
   |
   +-- cq->virq > 0 (MSI-X under KVM, route added at Create I/O CQ):
   |      event_notifier_set() -> KVM irqfd injects the MSI-X vector
   |
   +-- otherwise: qemu_bh_schedule(cq->irq_bh)      (main loop, BQL)
          nvme_isr_notify_legacy():
            MSI-X enabled  -> msix_notify(vector)
            MSI enabled    -> msi_notify(vector), or hold the bit in
                              irq_status while INTMS masks it
            neither (pin)  -> nvme_irq_update(): assert INTA while any
                              enabled CQ has head != tail and INTMS allows
```

The admin CQ is notified on the vCPU thread through the same legacy path.
MSI-X mask, unmask and pending-bit polling are handled by vector notifiers
(`nvme_vector_mask()`, `nvme_vector_unmask()`, `nvme_vector_poll()`) that move
the irqfd routes.

There is no interrupt coalescing. `intc`, `intc_thresh` and `intc_time` set
the values the Interrupt Coalescing and Interrupt Vector Configuration
features report, and nothing else. On the heap path a poller raises at most
one interrupt per CQ per sweep.

## Quiescing the data plane

Admin commands, controller reset and some features must change state the
pollers and the FTL thread read without locks. `nvme_pause_pollers()` waits
until neither is inside a sweep:

```text
 caller (vCPU, BQL)                    poller i                       FTL thread
 dataplane_started = false             in_sweep[i] = true             ftl_in_sweep = true
 smp_mb                                smp_mb                         smp_mb
 wait while any in_sweep[i]            dataplane_started? no:         dataplane_started? no:
   or ftl_in_sweep is true               in_sweep[i] = false, back off  ftl_in_sweep = false, skip
 ... change queues or namespaces ...   ... sweep ...                  ... one request ...
 nvme_resume_pollers():                smp_mb                         ftl_in_sweep = false
   dataplane_started = true            in_sweep[i] = false
```

Either the caller sees a sweep in progress and waits for it, or the thread
sees the cleared flag and backs off. With shared namespaces
(`femu-subsys,ns_mgmt=on`) the pause covers every controller in the
subsystem, and a nested pause does not resume its caller's work.

## Teardown

`femu_exit()` runs when the device is unplugged (`device_del`). QEMU does not
call it when the process exits. It stops the threads before freeing anything
they read:

1. Set `poller_stopping` and join every poller. Pollers go first because they
   feed the FTL thread.
2. Set `ftl_stopping` and join the FTL thread.
3. Close the Persistent Event Log, detach a linked CXL medium.
4. Run each distinct mode's `exit` hook once (not for a controller on a
   shared subsystem's storage).
5. `nvme_clear_ctrl(shutdown)`, then free the rings, heaps and per-poller
   arrays, the AER bottom half and the memory backend (unless it is shared or
   lent by a CXL medium).

## Commands, namespaces and modes

### Dispatch into modes

A mode is a `FemuExtCtrlOps` table (`hw/femu/nvme.h`):

| Hook | Called from | For |
| --- | --- | --- |
| `init` | realize, once per namespace of that mode, and Namespace Management create | build the mode's state for the namespace |
| `init_ctrl_name` | realize, only with `ns_mgmt` (otherwise each mode's `init` sets the name); only a namespace of the controller's `femu_mode` names it, and the controller's own table names it when no namespace does | Identify model number and serial |
| `start_ctrl` | controller enable, once per distinct mode | refuse settings the mode cannot serve; derive values from CC |
| `io_cmd` | poller, for opcodes the frontend does not handle | the mode's I/O commands |
| `admin_cmd`, `admin_cmd_cqe` | vCPU, for admin opcodes the frontend does not handle | mode admin commands, such as the Open-Channel commands, BBSSD 0xEF and the CSD commands |
| `get_log` | vCPU, for log ids the frontend does not handle | OC 2.0 chunk information, the ZNS Changed Zone List |
| `rw_check_req` | not called through the table | OC 2.0 sets it and calls its checker directly |
| `exit`, `ns_exit` | teardown, namespace deletion | free the mode's state |

`nvme_register_extensions()` installs the table for the controller's
`femu_mode`, and `nvme_register_extensions_ns()` gives each namespace the table
of its own mode, so I/O dispatches on the namespace, not the controller.
Admin commands go to the controller's table; Get Log Page tries the named
namespace's table first, then the controller's.

### Namespace routing

`nvme_ns()` maps an NSID to a namespace that is both allocated and attached
to this controller. NSIDs run from 1 to `namespaces` (or to 256 with
Namespace Management). An unknown NSID fails with Invalid Namespace, and with
Namespace Management an unallocated or detached NSID within range fails with
Invalid Field. A Flush to every namespace (NSID FFFFFFFFh) is refused, which
Identify reports as Flush Behavior 10b.

The FTL thread routes each request by its namespace: a namespace borrowed
from a linked CXL medium goes to the medium's FTL; with `power_loss=on` the
command is first executed; then ZNS namespaces go to `zns_ftl_process_req()`,
BBSSD and CSD namespaces to `bb_ftl_process_req()`, and others charge
nothing. One FTL thread serves all of them, and it exists only
when a namespace needs it. With shared namespaces, the subsystem's `ns_lock`
is held around command execution and FTL processing.
[namespaces.md](namespaces.md) covers sizing, per-namespace modes and
Namespace Management.

### Log pages and features at a glance

| Log page | Id | Notes |
| --- | --- | --- |
| Supported Log Pages | 00h | lists the ids the controller advertises (04h only with Namespace Management) |
| Error Information | 01h | newest `elpe` + 1 entries |
| SMART / Health | 02h | host totals from the pollers, media wear, `temperature` |
| Firmware Slot | 03h | |
| Changed Namespace List | 04h | namespaces whose attributes changed |
| Commands Supported and Effects | 05h | per command set (NVM, zoned, KV) |
| Device Self-test | 06h | tests complete at once |
| Telemetry Host / Controller | 07h, 08h | 07h: header plus the C0h counters captured by the last Create; 08h: header only |
| Endurance Group | 09h | with `femu-subsys` |
| Persistent Event | 0Dh | kept in `pel_file` if set |
| LBA Status | 0Eh | |
| FDP Configurations, RUH Usage, Statistics, Events | 20h-23h | with FDP |
| Sanitize Status | 81h | |
| Changed Zone List | BFh | ZNS, from the mode |
| FEMU media counters | C0h | WAF and FTL counters |

Get and Set Features answer Arbitration (01h), Power Management (02h, one
power state), LBA Range Type (03h), Temperature Threshold (04h), Error
Recovery (05h), Volatile Write Cache (06h, only with `vwc=1`), Number of
Queues (07h), Interrupt Coalescing (08h), Interrupt Vector Configuration
(09h), Write Atomicity (0Ah), Asynchronous Event Configuration (0Bh),
Timestamp (0Eh), Host Behavior Support (16h), Command Set Profile (19h), FDP
(1Dh, 1Eh), Key Value Configuration (20h) and Software Progress Marker (80h).
Only the FDP features report a saved value: FDP Mode is fixed at realize,
FDP Events can be changed at run time. A controller reset
(`nvme_reset_features()`) restores Arbitration, Power Management, the
temperature thresholds, Volatile Write Cache, Number of Queues, Interrupt
Coalescing, Interrupt Vector Configuration, Write Atomicity, Asynchronous
Event Configuration, Host Behavior Support and each namespace's Error
Recovery; the Software Progress Marker, LBA Range Type data, Key Value
Configuration and FDP event filters keep their values.

### Asynchronous events

The controller holds up to `aerl` + 1 Asynchronous Event Requests; one more
fails with Asynchronous Event Request Limit Exceeded. An event is queued (at
most 16; more are dropped) and posted by `nvme_process_aers()` from a
main-loop bottom half, because a poller may raise it and must not touch the
admin CQ. A request that arrives while events are queued is matched at once
on the vCPU thread. The
event types and their log pages are listed in
[log pages and counters](../reference/log-pages-and-counters.md#asynchronous-events).

## Parameters

The frontend reads these `-device femu` properties. Their defaults and
ranges are in the generated reference; follow the link of each group.

| Property | Effect on the frontend | Reference |
| --- | --- | --- |
| `queues` | number of I/O queue pairs; sizes BAR0, MSI-X vectors, `sq[]`, `cq[]` and the shadow doorbell page | [queues, pollers and interrupts](../reference/properties.md#queues-pollers-and-interrupts) |
| `entries` | CAP.MQES; the largest queue is `entries` + 1 | same |
| `max_sqes`, `max_cqes` | Identify SQES and CQES; only 64-byte SQEs and 16-byte CQEs are accepted | same |
| `stride` | doorbell spacing, 4 << `stride` bytes; also the shadow doorbell entry size | same |
| `multipoller_enabled`, `poller_ratio` | number of pollers and queue ownership | same |
| `hiops_inline` | NoSSD only: performance option, on by default; set off only when debugging | same |
| `aerl`, `elpe` | held AER limit, Error log length | same |
| `mdts` | largest data transfer per command | same |
| `intc`, `intc_thresh`, `intc_time` | values reported by the coalescing features only | same |
| `vid`, `did` | PCI IDs | [controller identity and capabilities](../reference/properties.md#controller-identity-and-capabilities) |
| `cqr` | whether queues must be physically contiguous | same |
| `mpsmin`, `mpsmax` | memory page sizes CC.MPS may choose | same |
| `oacs`, `oncs`, `vwc` | which optional admin and NVM commands are answered | same |
| `sgl` | accept SGL data pointers | same |
| `cmbsz`, `cmbloc` | Controller Memory Buffer on BAR 2 | same |
| `femu_mode`, `namespaces`, `namespace_modes` | which mode tables are installed, NSID range | [mode, capacity and namespaces](../reference/properties.md#mode-capacity-and-namespaces) |
| `ns_mgmt`, `streams`, `power_loss` | admin commands answered; FTL thread applies data with `power_loss` | [namespace management, streams and power loss](../reference/properties.md#namespace-management-streams-and-power-loss) |
| `pcie_bandwidth_mbps`, `pcie_prop_delay_ns`, `fw_cpu_ns` | time added in `nvme_process_cq_cpl()` | [host link and controller firmware](../reference/properties.md#host-link-and-controller-firmware) |
| `subsys` | CNTLID, FDP, shared namespaces | [femu-subsys](../reference/properties.md#femu-subsys-nvme-subsystem) |

Interactions:

- With the defaults (`queues=8`, `stride=0`) BAR0 is 16 KiB. Large `queues`
  or `stride` values grow it; `queues` above 511 with `stride=0` and 4 KiB
  pages leaves Doorbell Buffer Config unusable (the host then rings the
  registers).
- `multipoller_enabled=1` with `poller_ratio=1` starts one poller per queue,
  which needs that many spare host cores.
- The host's CC.MPS must fall within `mpsmin`..`mpsmax`, or enabling the
  controller sets CSTS.CFS.

## Counters

| Counter | Where kept | How to read it |
| --- | --- | --- |
| Host read and write commands and bytes | `poller_ctr[i]`, counted on the poller after execution, successful commands only, for every mode (the FTL thread counts them with `power_loss`) | SMART log: Host Read/Write Commands, Data Units Read/Written |
| Completions, and completions posted 20 us or more past their due time | `poller_ctr[i]` | BBSSD vendor command 0xEF, CDW10=5, prints both and resets them ([timing model](../concepts/timing-model.md#changing-timing-at-run-time)) |
| Error log entries | `num_errors` | SMART log, Error Information log |

The per-poller counters are padded to separate cache lines so pollers never
share one; readers sum them. Media counters (WAF, GC pages, buffer hits) come
from the FTL, not the frontend; see
[log pages and counters](../reference/log-pages-and-counters.md#vendor-log-page-c0h).

## Validation

The frontend is covered by the qtest suite in
`hw/femu/tests/qtest/femu-test.c`, which drives the controller through its
registers with no guest. Cases that target this chapter include:

| Case | Checks |
| --- | --- |
| `bar0-size` | BAR0 size for the queue count and stride |
| `cc-states` | enable, disable, shutdown and failure transitions of CC and CSTS |
| `doorbell-errors` | invalid doorbell writes raise Error events |
| `io-by-doorbell`, `io-by-shadow-doorbell` | I/O through registers and through Doorbell Buffer Config |
| `dbbuf-too-many-queues` | Doorbell Buffer Config refused when the entries do not fit |
| `intx-shadow-doorbell` | the pin drops with shadow doorbells |
| `queue-mapping` | Create I/O queue refused when the ring cannot be mapped |
| `shared-cq`, `shared-cq-pollers` | SQs that share one CQ, with one and several pollers |
| `poller-burst`, `poller-burst-per-queue`, `poller-burst-sharded` | full-queue bursts complete exactly once, in their own queue, under each poller layout |
| `cq-full` | completions wait for CQ space |
| `delete-sq-in-flight`, `ns-retire-pollers` | queue and namespace removal with I/O in flight |
| `aer-limit` | the AER limit |
| `abort` | Abort leaves the SQ unwritten, aborts queued admin and I/O commands, and enforces ACL |
| `features-reset`, `features-reset-vwc` | features return to defaults on reset |
| `admin-fuzz`, `io-fuzz` and its variants | structured fuzzing of admin and I/O commands |

Run them all, or one by name, from a build directory
([testing](../guides/testing.md)):

```sh
QTEST_QEMU_BINARY=./qemu-system-x86_64 ./tests/qtest/qos-test -m quick \
    -p /x86_64/pc/i440FX-pcihost/pci-bus-pc/pci-bus/femu/femu-tests/io-by-shadow-doorbell
```

The documentation example above (`frontend-sharded-pollers`) is started by
`check-docs`, which enables the controller and moves one block.

## Limits

- At most 2047 I/O queue pairs (the MSI-X table size), at most 65535 entries
  per queue.
- SQEs are 64 bytes and CQEs 16 bytes; other sizes are refused at realize.
- One controller per PCI function. No SR-IOV, no NVM Subsystem Reset, no
  controller memory for PMR.
- No interrupt coalescing; the coalescing features only store values.
- Weighted round robin arbitration is not implemented: CAP.AMS advertises it,
  but each poller sweeps its queues in id order.
- A queue can have at most `size` commands outstanding, and a poller's rings
  hold 65535 requests each.
- Abort only reaches commands not yet fetched.
- Latency is a lower bound that depends on poller scheduling.
- The controller is not migratable.

## Extension points

- **A new mode**: write a `FemuExtCtrlOps` table and a `nvme_register_*()`
  function, add the mode to the enum in `hw/femu/nvme.h`, to the
  `femu_mode` bound in `nvme_check_constraints()`, to
  `nvme_mode_from_token()` for `namespace_modes`, to
  `nvme_register_extensions()`, and to `femu_needs_ftl_thread()` and
  `femu_ftl_process_req()` if it charges time on the FTL thread. A mode that
  charges time on the poller adds it to `req->expire_time` in its `io_cmd`.
- **A new I/O command shared by all block modes**: add it to `nvme_io_cmd()`
  and to the Commands Supported and Effects tables at the top of
  `hw/femu/nvme-admin.c`.
- **A new admin command, feature or log page**: `nvme_admin_cmd()`,
  `nvme_set_feature()`, `nvme_get_feature()` and the support tables
  `nvme_feature_support[]` and `nvme_feature_cap[]`, `nvme_get_log()` and
  `nvme_supported_log_pages()`.
- **A new host-side cost**: add it next to the host-link and firmware-CPU
  models in `nvme_process_cq_cpl()`.
- **Anything that changes state the I/O path reads**: wrap it in
  `nvme_pause_pollers()` and `nvme_resume_pollers()`.
- **A new property**: define it in `femu_props[]` in `hw/femu/femu.c`,
  describe it in `hw/femu/femu-props.c`, check it in
  `nvme_check_constraints()`, and regenerate the property reference
  ([docs maintenance](../development/docs-maintenance.md)).

## Source map

| File | Functions |
| --- | --- |
| `hw/femu/femu.c` | `nvme_init_pci()`, `nvme_init_cmb()`, `nvme_init_ctrl()` (Identify Controller, CAP), `nvme_check_constraints()`, `nvme_mmio_write()`, `nvme_write_bar()`, `nvme_process_db_admin()`, `nvme_process_db_io()`, `nvme_start_ctrl()`, `nvme_clear_ctrl()`, `nvme_reset_features()`, `femu_ftl_thread()`, `femu_ftl_process_req()`, `femu_needs_ftl_thread()`, `nvme_register_extensions()`, `nvme_register_extensions_ns()`, `femu_realize()`, `femu_exit()` |
| `hw/femu/nvme-admin.c` | `nvme_create_sq()`, `nvme_create_cq()`, `nvme_del_sq()`, `nvme_del_cq()`, `nvme_init_poller()`, `nvme_start_dataplane()`, `nvme_set_db_memory()`, `nvme_identify()`, `nvme_get_feature()`, `nvme_set_feature()`, `nvme_get_log()`, `nvme_abort_req()`, `nvme_admin_cmd()`, `nvme_process_aers()`, `nvme_process_sq_admin()` |
| `hw/femu/nvme-io.c` | `nvme_poller()`, `nvme_process_sq_io()`, `nvme_update_sq_eventidx()`, `nvme_process_cq_cpl()`, `nvme_post_cqe()`, `nvme_rw()`, `nvme_io_cmd()` |
| `hw/femu/nvme-util.c` | `nvme_pause_pollers()`, `nvme_resume_pollers()`, `nvme_update_sq_tail()`, `nvme_update_cq_head()`, `nvme_update_cq_eventidx()`, `nvme_init_sq()`, `nvme_init_cq()` |
| `hw/femu/intr.c` | `nvme_isr_notify_io()`, `nvme_isr_notify_admin()`, `nvme_irq_update()`, `nvme_irq_mask_changed()`, `nvme_setup_virq()`, vector notifiers |
| `hw/femu/dma.c` | PRP and SGL mapping, `femu_dma_rw` |
| `hw/femu/lib/rte_ring.c`, `hw/femu/lib/pqueue.c` | the rings and the completion heap |
| `hw/femu/nvme.h` | `NvmeSQueue`, `NvmeCQueue`, `NvmeRequest`, `FemuCtrl`, `FemuExtCtrlOps`, `FemuPollerCtr`, register layout |

## Related pages

- [Design overview](README.md)
- [Architecture](../concepts/architecture.md)
- [Timing model](../concepts/timing-model.md)
- [Device property reference](../reference/properties.md)
- [Log pages and counters](../reference/log-pages-and-counters.md)
- [Performance tuning](../guides/performance-tuning.md)
