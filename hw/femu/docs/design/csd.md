# CSD: the computational storage extension

This chapter describes how FEMU emulates a computational storage drive
(`femu_mode=4`): the device memory, how programs are loaded and run, how
compute time is charged, and what the guest is trusted with. To run the
mode, see the [CSD guide](../modes/csd.md).

## Origin and credit

CSD mode is derived from CEMU, by Qiuyang Zhang, Jiapin Wang, You Zhou, Peng
Xu, Kai Lu, Jiguang Wan, Fei Wu and Tao Lu (ASPLOS '26), and was ported to
FEMU by Emilio ([@Emilio597](https://github.com/Emilio597)) in
[#188](https://github.com/MoatLab/FEMU/pull/188). The command layouts follow
CEMU's. The port keeps CEMU's device-side model and leaves out its modified
guest kernel, its FDMFS file system, and its VM freezing and virtual clock
changes. If you use this mode, cite CEMU as well as FEMU; the BibTeX entry is
in the [CSD guide's citation section](../modes/csd.md#citation).

## Purpose

A computational storage drive runs programs next to the data. The host
allocates memory on the device, copies namespace data into it without a trip
through host memory, runs a program on that memory, and reads back only the
result. FEMU emulates the control path of such a device with NVMe commands,
and runs each program inside the QEMU process on the host. The program's
time on the device is modelled with a small set of compute units.

The namespace under the device memory is an ordinary block namespace on the
black-box FTL, so plain reads and writes have SSD timing and garbage
collection.

## Place in the hierarchy

```text
            guest: csd-passthru, or own tool, via NVMe passthrough
                 |                                  |
          I/O queue commands                 admin queue commands
                 |                                  |
   +-------------v---------------+    +-------------v-------------+
   | poller thread               |    | vCPU thread               |
   | nvme_io_cmd() -> csd_io_cmd |    | nvme_admin_cmd()          |
   +----+-------------+----------+    |  -> csd_admin_cmd()       |
        |             |               |  memory range sets 0x21   |
   Read, Write   CSD commands         |  program load 0x22, 0x25  |
        |        0xb0 .. 0xf8         |  activate 0x23            |
        |             |               +-------------+-------------+
   nvme_rw()     +----v-----------------------------v----+
   copy data     | FemuCsdState (one per controller)     |
        |        |  FDM pool, AFDM table, programs,      |
        |        |  memory range sets, groups,           |
        |        |  compute unit busy-until times,       |
        |        |  queue of Execute jobs                |
        |        +----+------------------+---------------+
        |             | Execute job      | copy namespace data
        |             v                  v into an AFDM
        |   +-------------------+    memory backend
        |   | femu-csd-cu x     |
        |   | nr_cu: run the    |--> completion ring of the poller
        |   | program, charge a |    that fetched the command
        |   | compute unit      |
        |   +-------------------+
   +----v------------------------+
   | FTL thread: black-box FTL   |   timing for Read and Write; CSD
   +-----------------------------+   commands other than Execute pass
                                     through it and are charged nothing
                                     there, though the FTL may run GC
```

`csd_init()` runs the black-box geometry and capacity checks, builds a full
black-box FTL for the namespace (`ns->ssd`), and allocates `FemuCsdState`.
The state is controller-wide (`n->csd_ctrl_state`), which is why a controller
may have only one CSD namespace. Its other namespaces may run other modes,
but the CSD admin commands (0x21, 0x22, 0x23, 0x25) reach `csd_admin_cmd()`
only through the controller's own handler table. On a controller whose
`femu_mode` is not 4, for example `femu_mode=2` with
`namespace_modes=nossd,,csd`, those commands fail with Invalid Opcode, so
programs cannot be loaded. Set `femu_mode=4` on a controller that should run
programs. A CSD namespace makes the controller start its FTL thread.

## Data structures

`FemuCsdState` in `hw/femu/csd/csd.c`, guarded by one mutex. No program
runs under it:

```text
  FemuCsdState
  +----------------------------------------------------------------+
  | fdm_capacity = fdm_size MiB       fdm_used                     |
  | afdms     id   -> FemuCsdAfdm { id, size, data }               |
  | programs  pind -> FemuCsdProgram { type, active, loading,      |
  |                     runtime, runtime_scale, size, data,        |
  |                     module + function, or uBPF VM + JIT }      |
  | mrs       rsid -> FemuCsdMrs { numr, ranges[] }                |
  | groups    id   -> FemuCsdGroup { prio, qos_flags, bandwidth,   |
  |                     deadline }                                 |
  | cu_next_avail[nr_cu]   when each compute unit is free again    |
  | prog_used              bytes held by loaded programs           |
  | workers[nr_cu]         femu-csd-cu threads                     |
  | pending, running       FemuCsdJob { req, poller, program,      |
  |                          AFDMs, args, runtime }                |
  +----------------------------------------------------------------+
```

AFDMs and programs are reference counted. The table holds one reference,
and each Execute that is queued or running holds one on its program and on
each AFDM it names. Deallocating an AFDM or unloading or replacing a program
takes it out of its table at once, but its memory, and its share of the
`fdm_size` quota or of the program limits, is given back only when the last
Execute using it has finished. A program whose last reference goes is
closed by a compute unit thread without the CSD lock, since closing a
library runs its destructors.

- **FDM and AFDM.** Function data memory (FDM) is the device memory pool,
  `fdm_size` MiB. An allocation from it (AFDM) is a buffer in host memory
  with an id. `fdm_size` is a quota: FEMU allocates each AFDM when the guest
  asks for it, and refuses an allocation that would pass the quota with
  Capacity Exceeded. Only the host-visible type (0) is supported.
- **Memory range.** A 32-byte descriptor `{nsid, len, sb}`. FEMU accepts only
  `nsid` 0, meaning device memory, where `sb` is an AFDM id and `len` is the
  bytes to use (0 for the whole AFDM).
- **Memory range set.** A stored list of up to 255 memory ranges with an id
  (`rsid`), so a program can be run many times without sending its ranges
  again. The ranges are checked only when a program runs.
- **Program.** Indexed by `pind` (1 to 65535). One program may be up to
  16 MiB and all loaded programs together up to 64 MiB.
- **Group.** A priority (1 to 9, 0 means 5), QoS flags, bandwidth and
  deadline, kept as CEMU defines them. An execute command may name a group,
  which must exist, but groups do not change scheduling. The group field of
  Execute is 8 bits wide, so only groups 1 to 255 can be named.

## Commands

I/O commands, on the CSD namespace (`csd_io_cmd()`):

| Opcode | Command | Effect | Time charged |
| --- | --- | --- | --- |
| 0x01, 0x02 | Write, Read | `nvme_rw()` then the black-box FTL | black-box FTL timing |
| 0xb0 | Allocate FDM | new AFDM of `size` bytes; Dword 0 = id | none |
| 0xc0 | Deallocate AFDM | frees it, returns its bytes to the quota | none |
| 0xd0 | NVM to AFDM | copy `nlb + 1` blocks (`nlb` is 0-based) from `slba` into an AFDM at `offset` | one `pg_rd_lat` if any page of the range is mapped in the FTL, else none |
| 0xe1 | Execute | run a program on memory ranges; Dword 0 = its return value | compute unit time, below |
| 0xf2 | Read AFDM | AFDM bytes to the host | none |
| 0xf5 | Write AFDM | host bytes into an AFDM | none |
| 0xf6, 0xf7, 0xf8 | Create group, Set QoS, Delete group | group bookkeeping | none |

Admin commands (`csd_admin_cmd()`):

| Opcode | Command |
| --- | --- |
| 0x21 | Memory range set management: `sel` 0 creates a set from `numr` ranges in the data buffer (Dword 0 = `rsid`), `sel` 1 deletes one |
| 0x22, 0x25 | Load program, or load more of its bytes; `sel` 1 unloads |
| 0x23 | Activate (`sel` 1) or deactivate (`sel` 0) a program |

`hw/femu/tests/csd/csd-passthru.c` builds every one of these commands and is
the reference for their layouts; `hw/femu/csd/csd.h` declares them.

NVM to AFDM reads the namespace's slice of the memory backend directly and
checks the black-box mapping table only to decide whether to charge the
read. It does not go through the FTL's LUN queues. Pages still held in the
write buffer and deallocated pages are not mapped, so a range of only those
costs nothing.

When `oncs` turns them on, the generic NVM commands (Dataset Management,
Compare, Write Zeroes and the others) are handled by the common layer in
`nvme_io_cmd()` before `csd_io_cmd()` is consulted.

## Loading a program

```text
   (no program at pind)
          |
          | load, loff = 0: size psize, type, runtime, runtime_scale
          v
     +---------+   load, loff > 0: more bytes (same size, type, pid)
     | LOADING |<--+
     +----+----+---+
          | all psize bytes received: resolve and open by type
          v
     +----------+   activate sel=1   +--------+
     | INACTIVE |------------------->| ACTIVE |
     |          |<-------------------|        |
     +----+-----+   activate sel=0   +--------+
          | load sel=1 (only when inactive)
          v
     (no program at pind)
```

The diagram simplifies a few edges. A load with `loff = 0` replaces
whatever the index held, even an active program; an Execute already queued
or running keeps the old one. A further chunk (`loff > 0`) is accepted only
while the program is still loading, so a loaded program never changes. A load with `sel=1` also
unloads a program that is still loading. A further chunk must repeat the size
and type, and the `pid` only when the command's `pit` field is 1. Every
chunk adds its byte count toward the size, so a chunk sent twice counts
twice. When the byte count reaches the size, `csd_load_program_data()` prepares the
program by type, without the CSD lock held: opening a library runs its
constructors, and the pollers must not wait for them. The program is still
loading then, so nothing can run it, and admin commands, the only ones that
change programs, run one at a time under QEMU's global lock:

| Type | Value | Payload | Prepared by |
| --- | --- | --- | --- |
| Phantom | 0 | none needed | nothing; runs built-in code |
| eBPF | 1 | `name\0symbol\0` | read the ELF file, load the section into a uBPF VM, JIT-compile it when the command's `jit` bit is set |
| Shared library | 3 | `name\0symbol\0` | `g_module_open()` the file and look up the symbol |

Bitstream programs (type 2) and any other type fail with Invalid Field, but
only when the last byte arrives. If
preparing fails, the load command fails and the program stays at that index
in the loading state until a new load replaces it.

### Program files and the trust model

`csd_program_path()` turns the guest's `name` into a host path:

- With [`csd_program_dir`](../reference/properties.md#csd-computational-storage)
  unset, every shared-library and eBPF load fails; only phantom programs
  load.
- The name must be a plain file name: not empty, no `/`, not `.` or `..`.
- The joined path is resolved with `realpath()`, symbolic links included, and
  must still lie inside the resolved directory.

This keeps the guest from naming any other file on the host. It does not
make the programs safe. A shared library runs as native code in the QEMU
process, with QEMU's privileges and access to all of its memory, and the
launchers start QEMU with `sudo`. A uBPF program runs in uBPF's interpreter,
or as native code when JIT-compiled, also inside QEMU; FEMU adds no checks of
its own to what uBPF does. So the directory must hold only programs you
built and trust, and must not be writable by anyone else. FEMU does not
check the directory at realize; a missing one makes every load fail.

eBPF needs a build with uBPF (`./femu-compile.sh --enable-csd-ubpf`, meson
option `femu_csd_ubpf`). Without it, an eBPF load fails with Invalid Field.

## Running a program

```text
  Execute (0xe1), on the poller thread (csd_exec):
   1. read numr inline ranges (+ optional extra data, dlen <= 1 MiB)
      from the data buffer, or take the stored set named by rsid
   2. lock; check the program exists and is active, and the group exists
   3. map each range to its AFDM buffer (nsid 0, sb = AFDM id), and take
      a reference on each AFDM and on the program
   4. runtime = command runtime, else program runtime; if there is one,
      take the compute unit now (see below); unlock
   5. hand the request to the CSD as a job (req->defer); the poller
      moves on without sending it to the FTL thread

  on one of nr_cu femu-csd-cu threads (csd_worker):
   6. take the oldest job whose program is not running already, mark the
      program running, and call it without the CSD lock, timing it with
      the host clock:
        phantom    copy range 1 into range 0
        shared lib fn(&args)
        eBPF       JIT function or ubpf_exec(&args)
   7. lock; Dword 0 = return value (above 2^32 - 1 clamped to that; a
      negative value keeps its low 32 bits)
   8. with no runtime from step 4: runtime = measured host time x scale,
      and take the compute unit now
   9. put the request on the completion ring of the poller that fetched
      it, retrying while the ring is full; drop the references; unlock
```

Taking the compute unit means: pick the unit that is free first, hold it
for the runtime from the command's arrival, and set `expire_time` to the end
of that hold. A known runtime takes its unit on the poller, in arrival
order, so the order in which the host happens to finish programs does not
change it; a failed run still holds it. A measured runtime is known only
after the run, so those take their unit in the order runs end.

The poller then posts the completion once `expire_time` has passed, as for
any other command. A long program therefore holds one `femu-csd-cu` thread
and nothing else: the pollers keep serving every queue, CSD admin commands
and other CSD I/O commands take the CSD lock only briefly, and the vCPU
that sends an admin command never waits for a program.

When a submission queue is deleted, or the controller is reset, while one of
its Execute commands is queued or running, `nvme_drain_sq()` first calls
`femu_csd_drain_sq()`, which frees its queued jobs and detaches the
request from a running one. A running program still runs to the end, but
its result is dropped, as the specification
allows for commands on a deleted queue, and nothing touches the freed
request.

The program sees one argument, `struct femu_csd_args`
(`hw/femu/tests/csd/femu-csd-kernel.h`):

```text
  int        numr          number of memory ranges
  void     **mr_addr       one pointer per range; by convention
                           mr_addr[0] is output, mr_addr[1] input
  long long *mr_len        bytes per range
  long long  cparam1, cparam2   from the command
  void      *data_buffer   extra bytes after the ranges, or NULL
  long long  buffer_len
```

### Compute units and runtime scaling

The program runs to completion on the host as soon as a `femu-csd-cu`
thread is free; the compute units' busy-until times then decide when the
guest sees the completion. This is the same
"compute, then hold" approach the rest of FEMU uses
([timing model](../concepts/timing-model.md#compute-then-hold)).

```text
  runtime (ns), first that applies:
    1. the runtime field of the Execute command
    2. the runtime given when the program was loaded
    3. measured host time x program runtime_scale / 10
    4. measured host time x csf_runtime_scale

  compute units (nr_cu = 3):
    cu0  |==== A ====|
    cu1  |== B ==|    |===== D =====|
    cu2  |====== C ======|
                      ^ D arrives: cu1 is already free, D starts at once

    cu   = the unit with the smallest cu_next_avail
    start = max(arrival, cu_next_avail[cu])
    cu_next_avail[cu] = start + runtime
    expire_time = cu_next_avail[cu]
```

[`nr_cu`](../reference/properties.md#csd-computational-storage) bounds how
many programs run at once in device time;
[`csf_runtime_scale`](../reference/properties.md#csd-computational-storage)
stands for how much slower the device's cores are than the host's.

## Parameters

Properties: [CSD](../reference/properties.md#csd-computational-storage). The
[NAND geometry](../reference/properties.md#nand-geometry-bbssd-csd-kv),
[NAND timing](../reference/properties.md#nand-timing-bbssd-csd-kv) and
[garbage collection](../reference/properties.md#garbage-collection-mapping-and-caches)
properties apply to the namespace as in the black-box mode.

| Property | Role |
| --- | --- |
| `fdm_size` | device memory quota in MiB; required |
| `nr_cu` | compute units, 1 to 64 |
| `csf_runtime_scale` | host-to-device time factor for programs that give no runtime; not 0 |
| `csd_program_dir` | where shared-library and eBPF programs load from |
| `pg_rd_lat` | the cost of an NVM to AFDM copy |
| `nr_thread`, `time_slice`, `context_switch_time` | accepted for CEMU configurations; no effect, and a non-default value warns at realize (`nr_thread` must still not be 0) |

The smallest device line that loads programs:

<!-- femu-example: design-csd -->
```text
-device femu,devsz_mb=4096,femu_mode=4,fdm_size=64,nr_cu=2,csd_program_dir=/home/you/csd-programs
```

## Counters

- The vendor log page C0h counts the namespace's NAND traffic as for the
  black-box mode
  ([log pages and counters](../reference/log-pages-and-counters.md#vendor-log-page-c0h)).
  NVM to AFDM copies do not appear there, because they do not go through
  the FTL.
- The SMART log counts plain Read and Write. CSD commands are not counted.
- FEMU keeps no counter of programs run or compute unit use. Time the
  Execute commands from the guest; `csd-passthru benchmark-kernels` times
  whole program runs, and `csd-passthru bench` times the device memory and
  NVM to AFDM transfers.

## Validation status

- qtest cases in CI: `csd-program-dir`, run with the property set, checks
  that a missing file, a symbolic link out of the directory and a file that
  is not a library are refused; `csd-fuzz` fuzzes the fields of the CSD I/O
  commands; `csd-exec-concurrency` builds a shared-library program that
  sleeps (it skips when the host has no C compiler), loads and runs it, and
  checks that a read on another queue, an admin command and another
  program complete while it runs, that a loaded program refuses a further
  load piece, and that deleting the program's queue or disabling the
  controller under it leaves the controller working. No qtest covers the
  case where `csd_program_dir` is unset, or the `/`, `.` and `..` name
  rules. Phantom and eBPF programs and compute unit timing are tested only
  in a guest.
- The documentation check starts each CSD example and writes and reads one
  block of the namespace.
- Shared-library and eBPF programs run only in a guest, with
  `hw/femu/tests/csd/csd-passthru` and the example programs in
  `hw/femu/tests/csd/`. When `femu-test.sh` finds a CSD namespace, it runs a
  smoke check that allocates device memory, copies into it and reads it back;
  it runs no program. CI does not build uBPF, so the eBPF path is not tested
  there.

## Limits

- Programs run on `nr_cu` host threads, one per compute unit, so at most
  `nr_cu` run at once on the host; further Execute commands queue for a
  thread. Two runs of the same program never overlap; different programs
  do. A program that never returns keeps its thread and, at device removal
  (`device_del`), keeps QEMU waiting for it; FEMU cannot stop native code
  it has called.
- A program runs on the AFDMs it was given while other commands may read
  or write the same AFDMs; FEMU does not order them. Device memory freed
  while a program uses it counts against `fdm_size` until the program
  returns.
- The guest's program runs in the QEMU process. Treat `csd_program_dir` as
  code you are choosing to run on the host.
- NVM to AFDM charges one page read whatever its size, and does not queue on
  LUNs or channels.
- Groups and their QoS settings are stored but do not affect scheduling.
- Device memory transfers (Read and Write AFDM) take no device time.
- One CSD namespace per controller. No `meta` and no namespace management.

Refusal messages are listed in the
[CSD guide](../modes/csd.md#limits-and-refusals).

## Extending the mode

- **A new program type.** Add a case to `csd_load_program_data()` to prepare
  it, and one to the switch in `csd_run_program()` to run it.
- **Group scheduling.** `csd_exec()` already looks up the group. Choosing the
  compute unit by group priority or deadline would happen in
  `csd_finish_locked()`, where it picks the unit with the smallest
  `cu_next_avail`, and the order jobs leave the queue in `csd_worker()`.
- **Copy cost from the FTL.** `csd_nvm_to_afdm()` has the mapped page count
  from `csd_check_nvm_ftl_range()`; charging each mapped page through the
  media model (`ssd_advance_status()`) instead of one `pg_rd_lat` would add
  LUN and channel contention.
- **Preemption.** A compute unit thread runs a program to the end. A time
  slice, which CEMU's `time_slice` and `context_switch_time` describe, would
  need programs that yield.

## Source map

| File | Contents |
| --- | --- |
| [`hw/femu/csd/csd.c`](../../csd/csd.c) | state, every CSD command, program loading, compute unit threads, execution |
| [`hw/femu/csd/csd.h`](../../csd/csd.h) | command layouts, opcodes, program types |
| [`hw/femu/tests/csd/`](../../tests/csd/README.md) | guest tool, example programs, program ABI |
| [`hw/femu/bbssd/`](../../bbssd/ftl.c) | the black-box FTL under the namespace |
| [`hw/femu/femu.c`](../../femu.c) | the one-CSD-namespace check, FTL thread start |

## Related pages

- [CSD guide](../modes/csd.md): launching, guest tool, citation
- [Timing model: KV and CSD](../concepts/timing-model.md#kv-and-csd)
- [BlackBox SSD guide](../modes/blackbox.md): the FTL under the namespace
