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
  intact. The table lives in host memory, 64 bytes a slot, and costs no
  flash reads.
- **Key limit.** `kv_index_size()` sets `kv_max_keys`, which the
  namespace reports as MNK. The property `kv_max_keys` sets it, or else
  the flash does ([KV mode](../modes/kvssd.md#key-limit-kv_max_keys)).
  With `kv_pack` it is the number of 1-byte values the usable flash holds,
  from 1023 to 2^22 - 1. Without `kv_pack` it is the old limit:
  `hash_slots - 1` of `min(2^22, 2 * (value_capacity / 4096 + 1))` slots,
  at least 1024. Otherwise a limit of K keys gets `K + K/3 + 1` slots, so
  a probe always ends at an empty slot.
- **Value arena.** The value bytes the host stores, appended at
  `value_next`. An overwrite or delete leaves the old bytes behind as dead
  space (`value_reclaimable`).
- **Value pages.** Each entry also records the NAND pages that hold its
  value (`ppas`), `ceil(length / page size)` of them, where the page size is
  `secsz * secs_per_pg`. Those pages exist only in the timing model.
  `ssd->rmap` names the owner of each programmed page: the table slot of
  its value, or the LSM tree for a meta page. A page is released only
  through its owner.

The two views are separate. The arena is the emulator's store of the host
bytes: when its frontier is full, `kv_arena_pack()` moves the live bytes
to the front, with no NAND time. The NAND model is the device: value GC
collects its lines one victim at a time ([value GC](#value-gc)).

## Value packing

With `kv_pack=on` (the default), a value whose record fits a page shares
the page with other values. A record is the value and a 32 byte header
(`KV_PACK_HDR`): the key, the length, a version and the offset. The user
view is in [KV value packing](../features/kv-value-packing.md).

```text
  s->open (KvPackPage, DRAM)             s->packed: ppa -> KvPackPage
  +-------------------------------+      +-------------------------------+
  | items: owner slot, off, len,  |      | the same header, for a page   |
  |        live                   |      | on NAND; rmap = KV_OWNER_PACK |
  | fill, live, live_bytes        |      +-------------------------------+
  +-------------------------------+
  entry of a packed value: packed = true, nr_ppas = 1,
    ppas[0] = KV_PPA_OPEN (in DRAM) or the page, pack_off = record offset
  s->line_live[line]: live bytes; a page for a whole or meta page,
    the live records of a packed page
```

- `kv_place_value()` puts a value in the open page. A value whose record
  does not fit a page goes to whole pages, as before. When the record
  does not fit the open page, the dead records go first
  (`kv_pack_compact()`, DRAM only). Then `kv_pack_program()` programs the
  page. A page full of live records is programmed with the value that
  fills it. `kv-pack.c` holds the page header; the unit test
  `test-femu-kv-pack` checks it.
- `kv_pack_hold()` says whether the open page may stay in DRAM: not with
  `vwc=1` and WCE cleared. Then the page is programmed with the value in
  it, before the index takes the value, so a failed program changes
  nothing.
- The owner of a packed value is its item, found by the offset. Owner
  moves (`kv_move_owner()`) and releases (`kv_release_value()`) take the
  entry, so a hash backshift and an LSM reinsertion move the item too.
- `kv_pack_kill()` ends a record. A programmed page with no live record
  goes invalid and its header is freed.
- `kvssd_ftl_flush()` programs the open page and waits for
  `pack_persist`, the end of the last packed program. Flush with WCE set,
  Set Features 06h that clears WCE and CC.SHN call it
  (`kvssd_flush()`, `kvssd_flush_all()`).
- `kv_room()` keeps one page for the open page while it holds a live
  record, so that a Flush finds its page.

## Key index

`FemuKvIndexOps` (`kvssd.h`) is the index of a namespace: `find`,
`upsert`, `remove` and `probe`. The `kv_index` property picks one of two
tables in `kvssd_ftl_alloc()`:

| `kv_index` | Index | `probe` |
| --- | --- | --- |
| `hash` (default) | the open-addressing table above, in DRAM | none: no flash read |
| `lsm` | an LSM tree after PinK (`kv-lsm.c`) | one meta page read per unpinned level, in sequence |

With `lsm`, `table[]` becomes a pool of versions. Each Store takes a new
slot from a free stack, and the pool grows when the stack is empty. The
tree maps the key to the slot of its newest version:

```text
  memtable (sorted, DRAM) ---flush---> L1 ---merge---> L2 ---> ... L24
  record { key, key_len, tombstone, slot } --------+
                                                    v
  table[slot] { key, value_off, length, ppas, stale }   one version
```

- `kv-lsm.c` holds the tree and needs nothing from QEMU. The unit test
  `tests/unit/test-kv-lsm.c` builds it alone. It calls the FTL through
  `KvLsmOps`:
  - `io`: a meta page read or program;
  - `alloc`: a new meta page;
  - `free_page`: a page the tree no longer names;
  - `drop`: a record that leaves the tree.
- A meta page is a real NAND page on its own write pointer (`meta_wp`),
  in lines that hold no value. Its id is its `ppa`. Probes and scans
  charge it as `USER_IO`, merges and GC as `GC_IO`. Thus read counts,
  wear and ECC see its real block.
- Each slot has one record. An overwrite or a Delete makes the old version
  stale: it gives back its arena bytes and NUSE at once, but it keeps its
  pages. The pages go when `drop` reports its record, from a merge that
  shadows it or from a memtable put that replaces it.
- `alloc` takes only a free line, and does not program: the program
  comes as `KV_LSM_IO_COMPACT_PROGRAM` when the merge commits. GC runs
  only at the start of a command, never inside a merge. GC itself runs
  the merges of the keys it reinserts, between two victims.
- `room` refuses a merge before it takes a page. Every merge leaves one
  free line for value GC. A Delete whose flush fails keeps its tombstone
  in the memtable over its capacity (`kv_lsm_put_tombstone()`), so a full
  device still takes a Delete.
- `kv_lsm_compact_all()` merges every run into the deepest level in one
  pass, so its output holds only the live keys. A Store that still has no
  room after GC runs it, and then GC again.
- The timing rules, from the request arrival time `t0`:

```text
  lookup (probe)   each meta read starts when the one before ends
  Retrieve         value reads start at t0 + probe
  List             per level: serial reads; levels side by side
  merge I/O        queued during the command, issued at unlock:
                   reads from t0, programs after the last read,
                   the next merge after the last program; not in the latency
  value GC         check reads level by level from t0, each move after
                   its read, reinserted keys' merges after the moves
```

The hash table leaves `probe` NULL and takes none of these paths, so its
call order and times are unchanged. The user view is in
[LSM-tree key index](../features/kv-lsm-index.md).

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
too few free pages for the value and a reserve. The reserve is the room
that value GC needs to move a victim. It is one line with the hash index.
The LSM index also needs a line for its open meta page, and the pages of
its largest merge: one that rewrites every record, with a part page for
each level.

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
- A controller enabled with CC.CSS other than 110b: Invalid Command Opcode
  for every I/O command to a KV namespace (`nvme_io_cmd()`). CC.CSS 000b
  selects only the NVM command set (Base 2.3, Figure 41).

List walks the index in slot order, starting at the start key's slot when
the key exists and at slot 0 otherwise. The order is stable while the
namespace does not change, which is what the specification asks.

Admin side (`hw/femu/kvssd/kvssd-admin.c`): Identify with CSI 01h answers the
I/O command set specific Namespace and Controller structures and the format
query (CNS 0Ah); there is one KV format with a 16-byte key, a 2 MiB value
and the key limit above. Identify CNS 00h belongs to the NVM Command Set, so
for a KV namespace it fails with Invalid I/O Command Set. A host reads the
common attributes and readiness from CNS 08h, as Linux does, and the size
and format from the KV structure above, which reports the same NMIC and
ENDGID. Set and Get Features 20h (Key Value Configuration)
read and write EDNEK.

## Store, step by step

```text
  kvssd_ftl_store(key, vsize)                    lock held throughout
   1. find key in index
   2. option or capacity check fails?  -> charge the index cost, return error
   3. kv_gc_run(): value GC while free lines <= threshold or room < need
      lsm, still no room, old records: kv_lsm_compact_all(), GC again
   4. room < value pages + reserve?    -> Capacity Exceeded
   5. kv_value_alloc(vsize)
        frontier fits?          -> take [value_next, value_next + vsize)
        else dead bytes exist?  -> kv_arena_pack() (memory only), retry
        else                    -> Capacity Exceeded
   6. copy the value from the host into the arena
   7. kv_place_value()
        record fits a page (kv_pack=on): the open page
          no room: drop dead records, then program the open page
          WCE cleared: program the page with the value in it
        else kv_program_ppas(): for each value page
          kv_wp_line()   (a free line when the pointer has none)
          mark valid; charge a NAND program
          kv_wp_step()   (channel, LUN, plane, then page)
   8. index upsert; the new pages or item take the slot as owner
        hash: release the old value's pages or record now
        lsm:  the old version goes stale; its flash waits for the tree
   9. latency: whichever ends last of the GC in step 3, the index cost,
      the page programs, the reclaim erases, and the DRAM time of a
      record that stays in the open page
```

The write pointer walks a line the way the black-box FTL does: across
channels, then LUNs, then planes, then down the pages of the block. When a
line fills, it goes to the full list if all its pages are still valid, or to
the victim queue if some were invalidated.

**Reclaim.** `kv_reclaim_empty_lines()` takes lines from the victim queue
whose valid page count is zero and erases them, one multi-plane erase per
LUN. It runs at the start of GC and before a Store programs its value.

### Value GC

`kv_gc_run()` runs at the start of a Store, and with the LSM index at the
start of a Delete. It collects victims while the free lines are at or
below `gc_thres_lines`, or while a Store has too little room:

```text
  victim = the line with the fewest valid pages (victim queue)
           kv_pack: the closed line with the fewest live bytes, from the
           victim queue and the full list, each once per run
           lsm, no such line, a Store with no room:
           the next full value line of the run, oldest first
  value line:
     hash   every valid page is live: read it, program a copy
     lsm    look up each version's key (meta reads, level by level)
              the newest record names it -> move; record on flash -> reinsert
              else                       -> release the page, no move
     packed page: read it once; each live record goes to the GC page
              (lsm: a stale version is released); the GC page is
              programmed when full and before the erase
  meta line: read and program each valid meta page; the level list follows
  reinsert the keys (lsm), then erase the victim, one erase per LUN
```

- A victim from the queue that gives no usable page ends the run, unless
  a Store needs room. GC then tries the victims queued at the start of the
  run, and the full lines. A run takes only the full lines that existed at
  its start, so it never moves a line in a loop.
- The victim is marked `reclaiming` before any page changes. When a move
  finds no free page, the victim goes back to its list by its counts.
- Each move reads its source page, then programs the copy. The erase waits
  for the last program. The next victim starts when the erase ends. The
  Store waits for all of it.

## Timing

KV charges NAND operations through the black-box media model
(`ssd_advance_status()`), so every operation queues on its LUN and channel
like a black-box I/O. The NAND timing properties
([`pg_rd_lat`, `pg_wr_lat`, `blk_er_lat`, the channel properties](../reference/properties.md#nand-timing-bbssd-csd-kv))
set the costs.

With the hash index, every command that reaches the index pays a **base
cost**: one NAND page read, charged as a mapping read on the LUN that holds
the key's part of the index (`kv_index_ppa()`). The index is spread over every LUN by the key's
FNV-1a hash, LUN `hash % (nchs * luns_per_ch)`, so lookups of different keys
run in parallel; a List uses its start key. The cost stands for the
controller's index work, so that commands that touch no value are not free.
The index itself adds no reads. Commands refused for their fields, and most
error paths after the index lookup, are charged nothing.

| Command | Charged |
| --- | --- |
| Store | whichever ends last of any value GC it runs, the base cost, its page programs and any reclaim erases; a packed value costs the DRAM time, or the program of the open page it forces |
| Flush (`vwc=1`, WCE set) | the program of the open page, and every earlier program of packed values |
| Retrieve | the reads of the value pages that are transferred, and the base cost; the longest of them; a packed value reads its one page, or costs the DRAM time while it is in the open page |
| Exist | the base cost |
| Delete, List | the longer of the base cost and the index cost, which is 0 for the hash index |
| any command with `kv_index=lsm` | the meta page reads of the [key index](#key-index) in place of the base cost |
| a missing key, a conditional Store that does not apply, a full index or a full value space | the base cost |

All costs are measured from the command's arrival time on the LUN
timelines, so a LUN that is already busy makes the command wait, and a
stage that queues behind an earlier stage of the same command already
contains that wait. The command therefore ends with its last stage, and
costs never add up: a Store whose own programs follow its value GC on a LUN
completes when they do. The result is added to the request's
`expire_time` (`kv_apply_lat()`). The host-link and firmware models
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
| [KV timing](../reference/properties.md#kv-timing) | `kv_pack` | small values share pages (default on) |
| [Controller identity and capabilities](../reference/properties.md#controller-identity-and-capabilities) | `vwc` | with WCE set, the open page waits for Flush |
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

- pages the host asked to program: value pages written by Store; with
  `kv_pack=on`, the value bytes of the Stores in whole pages, rounded down;
- pages relocated by garbage collection: value pages and meta pages that
  value GC moved;
- pages programmed: the value pages of the first item, each packed page,
  and the meta pages that merges program (LSM index only);
- reads of the most-read block: value page reads count against their block.

The SMART log counts Store and Retrieve as host writes and reads, with the
bytes actually moved.

## Validation status

- qtest cases in `hw/femu/tests/qtest/femu-test.c`, run in CI:
  `kv-discovery` (the command set list and its command effects log),
  `kv-namespaces` (separate key spaces), `kv-accounting` (SMART bytes and
  the most-read block figure), `kv-base-spread` (timing), `kv-gc-victim`
  (one victim per GC), `kv-hash-backshift` (page owners after a Delete
  shifts entries), `kv-css-nvm` and `kv-css-all` (CC.CSS),
  `namespace-kv-byte-capacity`, `kv-mdts` and
  `kv-list-mdts0` (transfer limits), `kv-identify-reserved` (Identify
  layout), `sgl-kv`, and `kv-fuzz`, a fuzzer over the command fields.
- The `kv-pack-*` qtests cover value packing. They check pages and host
  bytes, the old model and overwrites in the open page. They also check
  Flush and WCE, a Flush beside a program, the read time, and GC with
  both indexes.
- The `kv-lsm-*` qtests cover `kv_index=lsm`: data, List order, probe
  time, background merges, query output, refusals, value GC (also with
  two planes and two-page values), old values on flash, meta page
  programs, Delete, a full device, table growth and random overwrites. The
  unit test `test-femu-kv-lsm` checks the tree against a reference, and
  each page and record callback.
- The unit test `test-femu-kv-pack` checks the packed page header: fit,
  exact fill, offsets, drops, compaction and allocation failures.
- The qtests set `FEMU_KV_CHECK`. After each value GC and every 64
  commands, the FTL checks the owner that `rmap` names for each valid
  page. A broken owner stops QEMU.
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
- Value GC runs in the Store that needs room, not in the background.
- With `kv_pack=off`, a value takes whole pages. Small values then use
  more NAND than their bytes. A Store can get Capacity Exceeded before
  NUSE reaches NSZE. With packing, a record still takes a 32 byte header,
  and a value whose record does not fit a page takes whole pages.
- One open page per namespace. Admin commands and the shutdown status do
  not wait for the program of the open page. FEMU models no power loss
  for KV, so the index in device DRAM needs no journal.
- The base cost of a key always falls on the same LUN, so a workload that
  hammers one key queues on that LUN.
- With the hash index, List order follows the hash table, not key order.
  The LSM index returns byte order.
- Not with FDP or `meta`. A controller with a KV namespace offers no
  namespace management: it needs a NoSSD or black-box controller whose
  namespaces all share its mode.

Refusal messages are listed in the
[KV guide](../modes/kvssd.md#limits-and-refusals).

## Extending the mode

- **Another index.** `FemuKvIndexOps` in `kvssd.h` is a small table of
  `find`, `upsert`, `remove` and `probe`. An index kept on flash returns
  from `probe` the time of its lookup reads, as the LSM tree does. Add a
  `kv_index` value and set `s->index` to the new table in
  `kvssd_ftl_alloc()`.
- **Background GC.** `kv_gc_run()` runs in the command; a timer could run
  it between commands, as the black-box GC in `hw/femu/bbssd/` does.
- **More KV formats.** `kvssd_fill_id_ns()` reports one format; additional
  formats need a Format NVM path that changes `kv_key_max` and
  `kv_value_max`.

## Source map

| File | Contents |
| --- | --- |
| [`hw/femu/kvssd/kvssd.c`](../../kvssd/kvssd.c) | command parsing, registration, init and exit |
| [`hw/femu/kvssd/kvssd-ftl.c`](../../kvssd/kvssd-ftl.c) | index, value arena, NAND placement, value packing, page owners, value GC, timing, owner check, self-test |
| [`hw/femu/kvssd/kv-lsm.c`](../../kvssd/kv-lsm.c) | the LSM tree of `kv_index=lsm`: memtable, levels, merges, scan |
| [`hw/femu/kvssd/kv-pack.c`](../../kvssd/kv-pack.c) | the packed page header of `kv_pack=on`: records, fit, compaction |
| [`hw/femu/kvssd/kvssd-admin.c`](../../kvssd/kvssd-admin.c) | Identify structures, Key Value Configuration feature |
| [`hw/femu/kvssd/kvssd.h`](../../kvssd/kvssd.h) | `FemuKvssdState`, `FemuKvssdMappingEntry`, `FemuKvIndexOps` |
| [`hw/femu/bbssd/ftl-media.c`](../../bbssd/ftl-media.c) | `ssd_advance_status()`, the media model KV charges through |
| [`hw/femu/nvme-admin.c`](../../nvme-admin.c) | Identify and feature routing to the KV handlers |

## Related pages

- [KV guide](../modes/kvssd.md): command examples, status codes, troubleshooting
- [Timing model: KV and CSD](../concepts/timing-model.md#kv-and-csd)
- [Multiple namespaces](../features/multi-namespace.md)
- [KV value packing](../features/kv-value-packing.md)
