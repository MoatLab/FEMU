# KV: the key-value extension

This chapter describes how FEMU emulates a key-value SSD (`femu_mode=5`): the
NVMe Key Value command set as implemented, the device-side index and value
store, and what each command is charged. To run the mode, see the
[KV guide](../modes/kvssd.md).

## Purpose

A key-value SSD stores values under keys instead of blocks at addresses. The
device owns the mapping from a key to where its value lives, so the host
needs no file system or block map to find it. FEMU implements the NVM Express
Key Value Command Set, revision 1.3, on top of the same NAND model the
black-box mode uses. Values are placed on emulated channels, LUNs and planes,
so key-value latency follows flash parallelism and space reclaim rather
than a fixed number.

**Guest requirement.** Linux has no key-value driver. The guest reaches a KV
namespace through NVMe passthrough on the generic character device
`/dev/ngXnY`, which Linux creates for command sets it does not know since
6.0. Older kernels skip the namespace. See
[Requirements: kernel per mode](../getting-started/requirements.md#kernel-per-mode).

## Place in the hierarchy

```text
  guest: nvme io-passthru / kv-probe / own program on /dev/ngXnY
                         |
                 NVMe submission queue
                         |
          +--------------v---------------+
          | poller thread                |
          |   nvme_io_cmd()              |   nvme-io.c
          |     default: ns io_cmd hook  |
          +--------------+---------------+
                         |
          +--------------v---------------+
          | kvssd_io_cmd()   kvssd.c     |   parse key, lengths, options
          +--------------+---------------+
                         |
          +--------------v---------------+
          | KV FTL           kvssd-ftl.c |   under the namespace's lock
          |  index: key -> value         |
          |  value arena (DRAM, data)    |
          |  struct ssd (timing only)    |---> NAND media model
          +--------------+---------------+     (channels, LUNs, planes)
                         |
                expire_time on the request
                         |
          poller priority queue -> completion
```

KV needs no FTL thread. The command, the data copy and the timing all run on
the poller thread inside `nvme_io_cmd()`. If another namespace of the same
controller starts the FTL thread (a black-box, ZNS or CSD namespace), KV
requests pass through it without further charge.

Each KV namespace owns its own state: key space, value store and NAND
model. `kvssd_init()` sets the namespace's command set identifier to KV
(`NVME_CSI_KV`, 1h) and allocates the state with `kvssd_ftl_alloc()`. The
first KV namespace also answers controller-wide admin paths that name no
namespace. A controller can mix KV namespaces with block namespaces
([multi-namespace guide](../features/multi-namespace.md)), but not with FDP.

## Data structures

`FemuKvssdState` (`hw/femu/kvssd/kvssd.h`), one per KV namespace:

```text
  FemuKvssdState
  +------------------------------------------------------------------+
  | table[hash_slots]   open-addressing index (DRAM)                 |
  |   FemuKvssdMappingEntry:                                         |
  |   +----------+---------+-----------+--------+---------+--------+ |
  |   | key[16]  | key_len | value_off | length | ppas[]  | nr_ppas| |
  |   +----------+---------+-----------+--------+---------+--------+ |
  |     key_len == 0 marks an empty slot                             |
  +------------------------------------------------------------------+
  | values[value_capacity]   byte arena holding the value bytes      |
  |   [ live | dead | live | live | dead | ... | free ............ ] |
  |                                              ^ value_next        |
  |   value_used, key_used, value_reclaimable (dead bytes)           |
  +------------------------------------------------------------------+
  | ssd    a black-box struct ssd built from the NAND properties:    |
  |        lines, write pointer, page states, LUN busy times.        |
  |        Used for placement and timing only; it holds no data.     |
  +------------------------------------------------------------------+
  | ednek   Key Value Configuration feature (20h), bit 0             |
  | lock    one mutex for all of the above                           |
  +------------------------------------------------------------------+
```

- **Index.** A hash table with linear probing on a 32-bit FNV-1a hash of the
  key bytes. Deletion shifts following entries back so probe runs stay
  intact. It has `min(2^22, 2 * (value_capacity / 4096 + 1))` slots, at
  least 1024, and holds at most `hash_slots - 1` keys; that limit is what the
  namespace reports as its maximum number of keys. The index lives in host
  memory and costs no flash reads.
- **Value arena.** The value bytes the host stores, appended at
  `value_next`. An overwrite or delete leaves the old bytes behind as dead
  space (`value_reclaimable`).
- **Value pages.** Each entry also records the NAND pages that hold its
  value (`ppas`), `ceil(length / page size)` of them, where the page size is
  `secsz * secs_per_pg`. Those pages exist only in the timing model.

The two views are kept in step: the arena decides where the bytes are, and
the NAND model decides what storing and reading them costs.

## Capacity

`kvssd_ftl_alloc()` sizes the store from two limits and takes the smaller:

```text
  value_capacity = min( namespace size,
                        NAND pages * page size * gc_thres_pcent / 100 )
```

The share of NAND set aside by
[`gc_thres_pcent`](../reference/properties.md#garbage-collection-mapping-and-caches)
is free space for reclaim, the over-provisioning a real KV-SSD keeps. The
NAND size comes from the
[geometry properties](../reference/properties.md#nand-geometry-bbssd-csd-kv).
Identify reports the result as the namespace size (NSZE) in bytes and the
live key and value bytes as NUSE.

A store is refused with Capacity Exceeded when live keys and values would
pass `value_capacity`, when the index is full, or when the NAND model has
too few free pages for the value.

## Commands

Commands use the common command format. `kvssd.c` reads these fields:

| Field | Meaning |
| --- | --- |
| CDW2, CDW3 | key bytes 0 to 7 |
| CDW14, CDW15 | key bytes 8 to 15 |
| CDW11 bits 7:0 | key length, 1 to 16 (List also accepts 0) |
| CDW11 bits 15:8 | Store options: bit 8 store only if the key exists, bit 9 store only if it does not |
| CDW10 | value size (Store) or host buffer size (Retrieve, List) |
| data pointer | the value or the list, PRP or SGL |

| Opcode | Command | FTL function | Result |
| --- | --- | --- | --- |
| 01h | Store | `kvssd_ftl_store()` | appends the value, programs its pages, updates the index |
| 02h | Retrieve | `kvssd_ftl_retrieve()` | returns `min(host buffer, value)` bytes; Dword 0 of the completion holds the full value size |
| 10h | Delete | `kvssd_ftl_delete()` | removes the key; a missing key succeeds unless EDNEK is set |
| 14h | Exist | `kvssd_ftl_exist()` | success or Key Does Not Exist |
| 06h | List | `kvssd_ftl_list()` | key count, then one entry per key: 2-byte length and key, padded to 4 bytes |

Store and Retrieve share their opcodes with Write and Read, so the generic
code counts them in the SMART host command totals, using the bytes really
moved.

Limits on the command fields:

- Key length above 16: Invalid Field. Key length 0: Invalid Key Size (86h),
  except for List, where 0 means "from the start".
- Value above 2 MiB: Invalid Value Size (85h).
- A value, retrieved span or list larger than MDTS allows: Invalid Field.
  Store checks the value before the FTL runs; Retrieve checks the span inside
  the FTL, and only when the key exists; List checks its buffer size inside
  the FTL.
- A List buffer smaller than 4 bytes: Invalid Field.
- The broadcast namespace ID: Invalid Field.

List walks the index in slot order, starting at the start key's slot when
the key exists and at slot 0 otherwise. The order is stable while the
namespace does not change, which is what the specification asks.

Admin side (`hw/femu/kvssd/kvssd-admin.c`): Identify with CSI 01h answers the
I/O command set specific Namespace and Controller structures and the format
query (CNS 0Ah); there is one KV format with a 16-byte key, a 2 MiB value
and the key limit above. Set and Get Features 20h (Key Value Configuration)
read and write EDNEK.

## Store, step by step

```text
  kvssd_ftl_store(key, vsize)                    lock held throughout
   1. find key in index
   2. option or capacity check fails?  -> charge base cost, return error
   3. kv_value_alloc(vsize)
        frontier fits?          -> take [value_next, value_next + vsize)
        else dead bytes exist?  -> kv_compact(), then retry
        else                    -> Capacity Exceeded
   4. copy the value from the host into the arena
   5. kv_program_ppas(): for each value page
        kv_ensure_write_pointer()   (may erase empty lines first)
        get_new_page(); mark valid; charge a NAND program
        kv_advance_write_pointer()  (channel, LUN, plane, then page)
   6. index upsert; invalidate the old value's pages, count its bytes dead
   7. latency: a compaction in step 3 has already added its own time;
      then max(base cost, page programs + reclaim erases)
```

The write pointer walks a line the way the black-box FTL does: across
channels, then LUNs, then planes, then down the pages of the block. When a
line fills, it goes to the full list if all its pages are still valid, or to
the victim queue if some were invalidated.

**Reclaim.** `kv_reclaim_empty_lines()` takes lines from the victim queue
whose valid page count is zero and erases them, one multi-plane erase per
LUN. It runs when a line closes, when the write pointer needs a new line,
and when the FTL checks how much space is left. KV never moves valid pages out of a partly valid
line.

**Compaction.** Compaction runs only when the value arena's frontier cannot
fit a new value and there are dead bytes. `kv_compact()` then rewrites every
live value to the front of the arena, in offset order, and programs new NAND
pages for each as garbage collection writes. This charges the whole live set
to the store that triggered it. If the NAND model has too few free pages for
the whole live set, compaction is not attempted and the Store fails with
Capacity Exceeded. A Store that finds too few free NAND pages for its own
value also fails with Capacity Exceeded; that case does not try compaction
either.

## Timing

KV charges NAND operations through the black-box media model
(`ssd_advance_status()`), so every operation queues on its LUN and channel
like a black-box I/O. The NAND timing properties
([`pg_rd_lat`, `pg_wr_lat`, `blk_er_lat`, the channel properties](../reference/properties.md#nand-timing-bbssd-csd-kv))
set the costs.

Every command that reaches the index pays a **base cost**: one NAND page
read, charged at physical address 0 as a mapping read. It stands for the
controller's index work, so that commands that touch no value are not free.
The index itself adds no reads. Commands refused for their fields, and most
error paths after the index lookup, are charged nothing.

| Command | Charged |
| --- | --- |
| Store | the time of any compaction it triggers, plus the longer of the base cost and its page programs (with any reclaim erases added in) |
| Retrieve | the reads of the value pages that are transferred, and the base cost; the longest of them |
| Exist | the base cost |
| Delete, List | the base cost plus the index cost, which is 0 for the hash index |
| a missing key, a conditional Store that does not apply, a full index or a full value space | the base cost |

All costs are measured from the command's arrival time, so a chip that is
already busy makes the command wait. The result is added to the request's
`expire_time` (`kv_apply_lat()`). Both compaction and the Store's own cost
are measured from the arrival time, so a Store that triggers compaction may
count part of the same wait twice. The host-link and firmware models
([host link and controller firmware](../reference/properties.md#host-link-and-controller-firmware))
also charge Store and Retrieve as they charge Write and Read. The
[timing model page](../concepts/timing-model.md#kv-and-csd) gives the same
rules in short.

## Parameters

KV reads only part of the black-box properties:

| Group | Properties | Use in KV |
| --- | --- | --- |
| [NAND geometry](../reference/properties.md#nand-geometry-bbssd-csd-kv) | `nchs`, `luns_per_ch`, `pls_per_lun`, `blks_per_pl`, `pgs_per_blk`, `secs_per_pg`, `secsz` | layout of the value pages; NAND size |
| [NAND timing](../reference/properties.md#nand-timing-bbssd-csd-kv) | `pg_rd_lat`, `pg_wr_lat`, `blk_er_lat`, cell type and channel properties | cost of each operation |
| [Garbage collection](../reference/properties.md#garbage-collection-mapping-and-caches) | `gc_thres_pcent` | usable share of the NAND |
| [Mode, capacity and namespaces](../reference/properties.md#mode-capacity-and-namespaces) | `devsz_mb`, `namespaces`, `namespace_sizes`, `namespace_modes` | namespace size, KV next to other modes |
| [Queues, pollers and interrupts](../reference/properties.md#queues-pollers-and-interrupts) | `mdts` | largest value, retrieve or list one command moves |

The mapping, cache, write buffer and background GC properties do not apply.
KV runs the black-box geometry check, but not its capacity check: a
namespace larger than the NAND still starts, and its value space is clamped
as above. `meta` and FDP are refused for a KV namespace.

A KV namespace with a block namespace beside it on one controller (on the QEMU
command line, the comma inside the value is written `,,`):

<!-- femu-example: design-kv-mixed -->
```text
-device femu,devsz_mb=2048,femu_mode=5,namespaces=2,namespace_modes=kvssd,,bbssd
```

## Counters

KV keeps its NAND page counts on its `struct ssd`, split the way the
black-box mode splits them, and the vendor log page C0h sums them over the
controller's black-box, CSD and KV namespaces
([log pages and counters](../reference/log-pages-and-counters.md#vendor-log-page-c0h)):

- pages the host asked to program: value pages written by Store;
- pages relocated by garbage collection: value pages rewritten by
  compaction;
- pages programmed: the same as the first, since KV has no write buffer;
- reads of the most-read block: value page reads count against their block.

The SMART log counts Store and Retrieve as host writes and reads, with the
bytes actually moved.

## Validation status

- qtest cases in `hw/femu/tests/qtest/femu-test.c`, run in CI:
  `kv-discovery` (the command set list and its command effects log),
  `kv-namespaces` (separate key spaces), `kv-accounting` (SMART bytes and
  the most-read block figure), `namespace-kv-byte-capacity`, `kv-mdts` and
  `kv-list-mdts0` (transfer limits), `kv-identify-reserved` (Identify
  layout), `sgl-kv`, and `kv-fuzz`, a fuzzer over the command fields.
- The documentation check stores and retrieves one value in each example
  whose namespace 1 is a KV namespace.
- `FEMU_KV_SELFTEST`, set in the environment, runs a self-test of the FTL at
  realize and logs the result
  ([environment variables](../reference/properties.md#environment-variables)).
- In a guest, `hw/femu/scripts/kv-probe.c` and the KV checks of
  `femu-test.sh` run the full command set; they need Linux 6.0 or newer and
  are not run in CI.

## Limits

- One key-value format: keys up to 16 bytes, values up to 2 MiB.
- Values are held in host memory as well as in the timing model's page
  states, so a KV namespace costs host memory equal to its value capacity.
- Reclaim only erases lines with no valid pages, and compaction rewrites the
  whole live set at once, only when the value arena is full. A workload
  that leaves every line partly valid pays compaction in one command instead
  of steady background GC, or gets Capacity Exceeded when the NAND runs out
  first.
- The base cost is charged on the LUN at physical address 0, so under load
  every command queues on that one LUN for it.
- List order follows the hash table, not key order.
- Not with FDP or `meta`. A controller with a KV namespace offers no
  namespace management: it needs a NoSSD or black-box controller whose
  namespaces all share its mode.

Refusal messages are listed in the
[KV guide](../modes/kvssd.md#limits-and-refusals).

## Extending the mode

- **Another index.** `FemuKvIndexOps` in `kvssd.h` is a small table of
  `find`, `upsert`, `remove` and `probe_reads`. An index kept on flash, such
  as an LSM tree, returns the number of page reads one lookup costs from
  `probe_reads`, and `kv_charge_index()` charges them. It charges them as
  user reads of physical address 0, so they also raise the most-read block
  counter; give them real addresses. Set `s->index` to the
  new table in `kvssd_ftl_alloc()`.
- **Background reclaim.** Valid-page relocation from partly valid lines would
  replace whole-arena compaction; the black-box GC in `hw/femu/bbssd/` shows
  the line and victim bookkeeping it would reuse.
- **More KV formats.** `kvssd_fill_id_ns()` reports one format; additional
  formats need a Format NVM path that changes `kv_key_max` and
  `kv_value_max`.

## Source map

| File | Contents |
| --- | --- |
| [`hw/femu/kvssd/kvssd.c`](../../kvssd/kvssd.c) | command parsing, registration, init and exit |
| [`hw/femu/kvssd/kvssd-ftl.c`](../../kvssd/kvssd-ftl.c) | index, value arena, NAND placement, reclaim, compaction, timing, self-test |
| [`hw/femu/kvssd/kvssd-admin.c`](../../kvssd/kvssd-admin.c) | Identify structures, Key Value Configuration feature |
| [`hw/femu/kvssd/kvssd.h`](../../kvssd/kvssd.h) | `FemuKvssdState`, `FemuKvssdMappingEntry`, `FemuKvIndexOps` |
| [`hw/femu/bbssd/ftl-media.c`](../../bbssd/ftl-media.c) | `ssd_advance_status()`, the media model KV charges through |
| [`hw/femu/nvme-admin.c`](../../nvme-admin.c) | Identify and feature routing to the KV handlers |

## Related pages

- [KV guide](../modes/kvssd.md): command examples, status codes, troubleshooting
- [Timing model: KV and CSD](../concepts/timing-model.md#kv-and-csd)
- [Multiple namespaces](../features/multi-namespace.md)
