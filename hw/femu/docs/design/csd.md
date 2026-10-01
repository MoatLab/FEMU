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
        |        |  compute unit busy-until times        |
        |        +----+------------------+---------------+
        |             | run program      | copy namespace data
        |             v (on the poller)  v into an AFDM
        |        host code in QEMU   memory backend
        |
   +----v------------------------+
   | FTL thread: black-box FTL   |   timing for Read and Write; CSD
   +-----------------------------+   commands pass through it too and
                                     are charged nothing there, though
                                     the FTL may run GC meanwhile
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

`FemuCsdState` in `hw/femu/csd/csd.c`, guarded by one mutex:

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
  +----------------------------------------------------------------+
```

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
whatever the index held, even an active program. A load with `sel=1` also
unloads a program that is still loading. A further chunk must repeat the size
and type, and the `pid` only when the command's `pit` field is 1. Every
chunk adds its byte count toward the size, so a chunk sent twice counts
twice. When the byte count reaches the size, `csd_load_program_data()` prepares the program by type:

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
  Execute (0xe1) on the poller thread:
   1. read numr inline ranges (+ optional extra data, dlen <= 1 MiB)
      from the data buffer, or take the stored set named by rsid
   2. lock; check the program exists and is active, and the group exists
   3. map each range to its AFDM buffer (nsid 0, sb = AFDM id)
   4. call the program, timing it with the host clock:
        phantom    copy range 1 into range 0
        shared lib fn(&args)
        eBPF       JIT function or ubpf_exec(&args)
   5. Dword 0 = return value (above 2^32 - 1 clamped to that; a negative
      value keeps its low 32 bits)
   6. runtime = command runtime, else program runtime,
                else measured host time x scale
   7. pick the compute unit that is free first, hold it for runtime,
      set expire_time to the end of that hold; unlock
```

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

The program runs to completion on the host at once; the compute units only
decide when the guest sees the completion. This is the same
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
  commands. No qtest covers the case where `csd_program_dir` is unset, or the
  `/`, `.` and `..` name rules. No qtest loads, activates or runs a program.
  Program execution, phantom programs included, and compute unit timing are
  tested only in a guest.
- The documentation check starts each CSD example and writes and reads one
  block of the namespace.
- Shared-library and eBPF programs run only in a guest, with
  `hw/femu/tests/csd/csd-passthru` and the example programs in
  `hw/femu/tests/csd/`. When `femu-test.sh` finds a CSD namespace, it runs a
  smoke check that allocates device memory, copies into it and reads it back;
  it runs no program. CI does not build uBPF, so the eBPF path is not tested
  there.

## Limits

- A program runs on the poller thread that fetched the Execute command,
  holding the CSD lock. While it runs, that poller serves no other queue and
  other CSD commands wait. A long program stalls I/O. A CSD admin command
  sent meanwhile waits for the CSD lock while holding QEMU's global lock,
  which stalls that vCPU as well; so does a slow program load.
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
  it, and one to the switch in `csd_exec()` to run it.
- **Group scheduling.** `csd_exec()` already looks up the group. Choosing the
  compute unit by group priority or deadline would happen where it picks the
  unit with the smallest `cu_next_avail`.
- **Copy cost from the FTL.** `csd_nvm_to_afdm()` has the mapped page count
  from `csd_check_nvm_ftl_range()`; charging each mapped page through the
  media model (`ssd_advance_status()`) instead of one `pg_rd_lat` would add
  LUN and channel contention.
- **Running programs off the poller.** Moving step 4 of Execute to a worker
  thread, completing the request when it returns, would stop long programs
  from stalling the poller.

## Source map

| File | Contents |
| --- | --- |
| [`hw/femu/csd/csd.c`](../../csd/csd.c) | state, every CSD command, program loading, execution, compute units |
| [`hw/femu/csd/csd.h`](../../csd/csd.h) | command layouts, opcodes, program types |
| [`hw/femu/tests/csd/`](../../tests/csd/README.md) | guest tool, example programs, program ABI |
| [`hw/femu/bbssd/`](../../bbssd/ftl.c) | the black-box FTL under the namespace |
| [`hw/femu/femu.c`](../../femu.c) | the one-CSD-namespace check, FTL thread start |

## Related pages

- [CSD guide](../modes/csd.md): launching, guest tool, citation
- [Timing model: KV and CSD](../concepts/timing-model.md#kv-and-csd)
- [BlackBox SSD guide](../modes/blackbox.md): the FTL under the namespace
