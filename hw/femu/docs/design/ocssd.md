# OCSSD: the Open-Channel extension

This chapter describes how FEMU emulates an Open-Channel SSD (`femu_mode=0`).
It covers the internals: the two protocol versions, their address formats,
the per-chunk state that 2.0 keeps, and how each command is timed. To run the
mode, see the [OCSSD guide](../modes/ocssd.md).

## Purpose

An Open-Channel SSD has no device FTL. The host sees the NAND geometry and
addresses physical sectors directly. Mapping, garbage collection, wear
levelling and bad-block handling all run in the host: LightNVM and pblk in
Linux before 5.15, or SPDK in user space. FEMU's job in this mode is to
check the addresses the host sends, store the data, and charge NAND time per
chip and per channel.

FEMU implements two versions, selected by
[`lver`](../reference/properties.md#ocssd-open-channel):

| | Open-Channel 1.2 (`lver=1`) | Open-Channel 2.0 (`lver=2`, the default) |
| --- | --- | --- |
| Address | physical page address (PPA): channel, LUN, block, page, plane, sector | logical block address: group, parallel unit, chunk, sector |
| Unit of erase | a block on one plane, named by a PPA | a chunk: one block on every plane of a parallel unit |
| Write rule | none enforced | sequential within a chunk, at the chunk's write pointer |
| Per-unit state | sector state and out-of-band bytes | chunk descriptor: state, type, wear index, write pointer |
| Plain NVMe Read and Write | refused | accepted (SPDK uses them) |
| Channel transfer time | optional (`oc12_channel_timing`) | none |
| Page-type timing | yes (lower, center, upper page) | no (every access is charged as a lower page) |
| Log page | none | chunk information, CAh |
| Model string | `FEMU OpenChannel-SSD Controller (v1.2)` | `FEMU OpenChannel-SSD Controller (v2.0)` |

**Guest requirement.** Linux removed LightNVM in 5.15, so a guest that uses
the kernel's Open-Channel stack must run an older kernel.
[Requirements: kernel per mode](../getting-started/requirements.md#kernel-per-mode)
gives the range for each version. On a newer kernel the controller still
appears, and SPDK can drive it from user space.

## Place in the hierarchy

```text
  guest: pblk / LightNVM (Linux < 5.15)  or  SPDK
                         |
                 NVMe submission queue
                         |
          +--------------v---------------+
          | poller thread                |   nvme_process_sq_io()
          |   nvme_io_cmd()              |   nvme-io.c
          |     default: ns io_cmd hook  |
          +--------------+---------------+
                         |
            +------------+-------------+
            |                          |
   +--------v--------+        +--------v--------+
   | oc12_io_cmd()   |        | oc20_io_cmd()   |
   | ocssd/oc12.c    |        | ocssd/oc20.c    |
   |  check PPAs     |        |  check chunks   |
   |  OOB metadata   |        |  write pointer  |
   +--------+--------+        +--------+--------+
            |  data                    |  data
            v                          v
   +---------------------------------------------+
   | memory backend: backend_rw()  backend/dram.c|
   +---------------------------------------------+
            |  timing                  |  timing
            v                          v
   +---------------------------------------------+
   | per-chip and per-channel busy-until times   |
   | timing-model/timing.c                       |
   +---------------------------------------------+
                         |
                expire_time on the request
                         |
          poller priority queue -> completion
```

There is no FTL thread in this mode. The whole command, data copy and timing
included, runs on the poller thread inside `nvme_io_cmd()`. The request then
goes to the poller's own priority queue and is completed when the host clock
passes its `expire_time`. The
[architecture page](../concepts/architecture.md#completion) describes that
completion step.

Registration happens in `nvme_register_extensions()` in `hw/femu/femu.c`: with
`femu_mode=0`, `lver=1` installs `nvme_register_ocssd12()` and `lver=2`
installs `nvme_register_ocssd20()`. Each fills the controller's
`FemuExtCtrlOps` table: `init`, `exit`, `io_cmd` and `admin_cmd`, plus
`get_log` for 2.0.

## Open-Channel 1.2

### Address format

A 1.2 address is a 64-bit PPA. Each field gets just enough bits for its
count, rounded up to a power of two, packed from the sector upward
(`oc12_init_id_ctrl()`):

```text
 63                                                              0
 +--------+--------+----------+---------+---------+-------------+
 | unused | channel|   LUN    |  block  |  page   | plane | sec |
 +--------+--------+----------+---------+---------+-------------+
            ch_len   lun_len    blk_len   pg_len   pln_len sect_len

 field width = ceil(log2(count)); for example lsecs_per_pg=4 -> 2 bits
```

`oc12_ppa_in_geometry()` checks every field against the real count. Because
the fields are rounded up to powers of two, a value can fit in its field and
still name a unit the device does not have; such an address is refused.

### Data structures

`Oc12Ctrl` (`hw/femu/ocssd/oc12.h`) holds the controller state:

- `id_ctrl`: the 1.2 identity structure the host reads with admin command
  0xE2. One configuration group: channel, LUN, plane, block, page and sector
  counts, sector size (`lsec_size`), out-of-band size (`lmetasize`), the
  multi-plane mask (`mpos`) for 1, 2 or 4 planes, fixed timing hints, and
  capability bit 0 (bad block table management).
- `params`: the geometry from the properties plus derived strides
  (`sec_per_pl`, `sec_per_blk`, `pl_units`, `pg_units`, ...).
- `ppaf`: the masks and offsets for each address field.
- `meta_buf`: one entry per sector, `4 + lmetasize` bytes. The first 4 bytes
  are a sector state (`OC12_SEC_WRITTEN`, `OC12_SEC_ERASED`); the rest are
  the out-of-band bytes the host passes through the command's metadata
  pointer. `ppa2secidx()` flattens a PPA to the entry index.

Per namespace (`NvmeNamespace`):

- `bbtbl`: one bad block table per LUN, `blocks * planes` bytes. The host
  reads it with admin command 0xF2 and marks blocks with 0xF1, which indexes
  by block number only and ignores the plane.
- `tbl`: a table the host can read with admin command 0xEA (Get L2P Table).
  FEMU fills it with "unmapped" at start-up and never updates it.

### Commands

| Opcode | Kind | Handler | What it does |
| --- | --- | --- | --- |
| 0x92 | I/O | `oc12_read()` | vector read of up to `lmax_sec_per_rq` sectors |
| 0x91 | I/O | `oc12_write()` | vector write; at least `lsecs_per_pg * lnum_pln` sectors |
| 0x90 | I/O | `oc12_erase_async()` | vector erase of the listed blocks |
| 0x01, 0x02 | I/O | | plain Write and Read are refused with Invalid Opcode |
| 0xE2 | admin | `oc12_identity()` | identity structure |
| 0xEA | admin | `oc12_get_l2p_tbl()` | the `tbl` described above |
| 0xF2 | admin | `oc12_bbt_get()` | bad block table of one LUN |
| 0xF1 | admin | `oc12_bbt_set()` | mark one or more blocks |

A vector command carries either one PPA in the command or a list of PPAs in
host memory. Read and write accept only PRP data pointers, check the list
against the geometry and MDTS, move the out-of-band bytes, and then copy the
data. Each PPA must pair with one sector of the data transfer; a data
pointer that does not split into exactly one segment per address is refused
with Invalid Field.

The backend stores 1.2 data at the PPA value itself, used as a sector
number: `start_block + (ppa << lbads)`. Because the PPA fields are padded to
powers of two, this address space can be larger than the device. An address
that lands past the end of the memory backend fails with LBA Out of Range.

Other refusals: a PPA value above the namespace size fails with LBA Out of
Range before the backend is reached; an LBA format with metadata (`meta`)
makes read and write fail with Invalid Field; and an address outside the
geometry on erase or on a bad block command fails with Invalid Field.

In both versions the generic NVM commands (Flush, Dataset Management,
Compare, Write Zeroes, Copy, Verify, Write Uncorrectable) are handled by
`nvme_io_cmd()` on raw LBAs before the Open-Channel handler is consulted,
when `oncs` turns them on. They do not follow the Open-Channel rules.

### What 1.2 does not enforce

1.2 keeps the sector state but does not act on it:

- A write to a sector that was already written succeeds and replaces the
  data. Real NAND would refuse it.
- Erase does not reset the sector states: the state update is disabled in
  `oc12_meta_blk_set_erased()`, which returns at its first line.
- Reads do not check the state, so an unwritten sector returns whatever the
  backend holds.
- Blocks marked bad in `bbtbl` are still read, written and erased; the table
  is only storage for the host.

Write the host FTL as if these rules applied, because real devices apply
them.

## Open-Channel 2.0

### Address format and geometry

A 2.0 address is a logical block address split into four fields
(`femu_oc20_init_id_ctrl()`, macros in `hw/femu/ocssd/oc20.h`):

```text
 63                                                    0
 +--------+---------+------------------+--------+-------+
 | unused |  group  | parallel unit    | chunk  |sector |
 +--------+---------+------------------+--------+-------+
            grp_len   lun_len            chk_len sec_len

 group           = channel                 (NUM_GRP = lnum_ch)
 parallel unit   = LUN                     (NUM_PU  = lnum_lun)
 chunk           = one block on every plane of the LUN
 sector          = index inside the chunk  (CLBA = lsecs_per_pg
                                            * lpgs_per_blk * lnum_pln)
 NUM_CHK = namespace blocks / (lsecs_per_pg * lpgs_per_blk
                               * lnum_ch * lnum_lun * lnum_pln)
```

`NUM_CHK` is computed from the namespace's block count in the LBA format
selected by `lba_index`, before 2.0 switches the namespace to 4096-byte
sectors. With the default `lba_index=0` (512-byte blocks), the geometry
therefore describes 8 times the memory that `devsz_mb` provides, and valid
addresses past the first eighth fail with LBA Out of Range. Set
`nlbaf=5,lba_index=3` (4096-byte blocks), as `run-whitebox.sh` does, so the
two agree.

The namespace reports its size as `2^(grp_len + lun_len + chk_len +
sec_len)` sectors, the whole address space including the padding. The
sector size is always 4096 bytes. Unlike 1.2, the data path turns the
address into a dense sector index (`oc20_lba_to_sector_index()`) before it
touches the backend, so the padding costs no memory.

The geometry structure returned by admin command 0xE2 also carries fixed
values: minimum write size 4 sectors, optimal write size 8, cache minimum
write size units (`mw_cunits`) 24, no limit on open chunks, and typical and
maximum read, write and reset times. Those times are hints for the host;
the timing model below does not use them.

### Data structures

`Oc20Namespace` (`ns->state`) holds:

- `id_ctrl`: the 4096-byte geometry structure.
- `lbaf`: masks and offsets for the four address fields.
- `chunk_info`: one 32-byte descriptor (`Oc20CS`) per chunk, the same layout
  the chunk information log page returns:

```text
  Oc20CS (32 bytes)
  +-------+------+------------+---------+---------+---------+---------+
  | state | type | wear_index | rsvd[5] |  slba   |  cnlb   |   wp    |
  |  u8   |  u8  |     u8     |         |  u64    |  u64    |  u64    |
  +-------+------+------------+---------+---------+---------+---------+
   state: FREE 0x1, CLOSED 0x2, OPEN 0x4, OFFLINE 0x8
   type : SEQ 0x1 (all chunks at start-up), RAN 0x2
```

`Oc20Ctrl` (`n->ext_ops.state`) holds a header with the sector size (4096)
and metadata size (16) the namespace reports.

### Chunk state machine

```text
                  write at wp
        +------+  (first)      +------+   write that reaches cnlb   +--------+
        | FREE |-------------->| OPEN |--------------------------->| CLOSED |
        +------+               +------+                            +--------+
          ^  ^                    | ^ |                                 |
          |  |  reset (only with  | | | write at wp                     |
          |  |  learly_reset)     | | +--- (wp advances)                |
          |  +--------------------+ |                                  |
          |                                       reset                |
          +------------------------------------------------------------+

   reset of a FREE chunk  : refused (multiple resets are not offered)
   write to an OFFLINE one: Write Fault
   reset of an OFFLINE one: Offline Chunk (0x2C0)
   read of an OFFLINE one : succeeds and returns zeros
   OFFLINE is only set through Set Log Page
   each reset             : wear_index + 1, wp = 0
```

The rules, from `oc20_rw_check_chunk_write()` and `oc20_chunk_set_free()`:

- A write is split into runs, one per chunk it touches. In each run the
  sectors must be consecutive and the first must equal the chunk's write
  pointer. Otherwise the command fails with Out of Order Write (0x2F2).
- A write to a closed or offline chunk, or one that would pass the chunk's
  capacity, fails with Write Fault.
- After the data is stored, `oc20_advance_wp_all()` moves each chunk's write
  pointer by its run. A free chunk becomes open; a chunk whose write pointer
  reaches `cnlb` becomes closed.
- Vector erase (0x90) resets each listed chunk. Resetting a closed chunk is
  always allowed. Resetting an open chunk needs
  [`learly_reset`](../reference/properties.md#ocssd-open-channel). Resetting
  a free chunk is refused, because FEMU does not advertise multiple resets.
  When the command has a metadata pointer, FEMU writes the new descriptor of
  each chunk there.
- A read of a sector that is not yet readable succeeds and returns zeros. A
  sector is readable when it is below the write pointer of a closed chunk, or
  more than `mw_cunits` (24) sectors below the write pointer of an open one.
  The 24-sector window models data still held in the device's write cache.
- Random chunks (type RAN) skip the write pointer: a write run may start at
  any sector of an open random chunk, though its sectors must still be
  consecutive, and it moves neither the write pointer nor the state. Any
  sector of an open random chunk can be read. Chunks only become random
  through Set Log Page.

The minimum write size (4 sectors) is reported but not checked, so that SPDK
works.

### Commands

| Opcode | Kind | Handler | What it does |
| --- | --- | --- | --- |
| 0x92 | I/O | `oc20_rw(vector=true)` | vector read, list of up to 64 addresses |
| 0x91 | I/O | `oc20_rw(vector=true)` | vector write |
| 0x90 | I/O | `oc20_erase()` | vector chunk reset |
| 0x02, 0x01 | I/O | `oc20_rw(vector=false)` | plain Read and Write over consecutive addresses, with the same chunk rules |
| 0xE2 | admin | `oc20_identify()` | geometry |
| 0x02 (Get Log Page), LID CAh | admin | `oc20_get_log()` | chunk descriptors |
| 0xC1 | admin | `oc20_set_log()` | write chunk descriptors (FEMU extension) |

Read and write accept only PRP data pointers. A command with more than 64
addresses fails with Invalid Field.

Set Log Page (0xC1) with LID CAh lets the host put chunks into a given state,
type, wear index and write pointer, for example to start a test from a
partly used device. FEMU checks every descriptor before it changes any:
`slba` and `cnlb` must match the controller's, the type must be SEQ or RAN,
and the write pointer must suit the state (0 for FREE, below `cnlb` for
OPEN, at most `cnlb` for CLOSED). It pauses the pollers while it copies the
descriptors in.

The 2.0 data path does not transfer the metadata buffer, even though the
namespace reports 16 metadata bytes per sector.

## Timing

Both versions use the same busy-until model in
`hw/femu/timing-model/timing.c`. The controller keeps one time per chip
(LUN) and one per channel:

- `chip_next_avail_time[ch * num_lun + lun]`, at most 128 chips.
- `chnl_next_avail_time[ch]` and a list of reserved intervals per channel,
  at most 32 channels.

`advance_chip_timestamp()` starts an operation at the larger of "now" and the
chip's busy-until time, adds the operation's latency, and returns the new
busy-until time. Latencies come from the built-in table for
[`flash_type`](../reference/properties.md#ocssd-open-channel) (1 SLC, 2 MLC,
3 TLC, 4 QLC) in `hw/femu/nand/nand.h`, by operation and page type. The
NAND timing properties of the black-box mode (`pg_rd_lat` and the others)
do not apply.

A read or write is first grouped into buckets, one per NAND page touched, by
`parse_ppa_list()` (1.2) or `oc20_parse_lba_list()` (2.0). Each bucket is
then charged on its chip and channel:

```text
  write bucket:  [ channel transfer ][ program on chip ........ ]
                 ^ the channel's first free time at or after now,
                   fitted around reserved read transfers     ^ done

  read bucket:   [ read on chip ....... ][ channel transfer ]
                 ^ now                                      ^ done
                 (the transfer is fitted into a free gap of the
                  channel's reservation list)

  command done = now + max over buckets of (done - now)
  erase       = one block erase on the chip of each listed address;
                command done = the latest of them
```

Version differences:

- **1.2.** A bucket is one page across all planes of a LUN. Its page type
  (lower, center and upper; QLC has two center types) comes from the page number, so MLC, TLC and QLC
  pages cost different times. With
  [`oc12_channel_timing`](../reference/properties.md#ocssd-open-channel)
  on, each bucket also pays channel time: `ch_xfer_lat` per page, or the
  `flash_type` table's transfer time when `ch_xfer_lat` is 0, scaled by the
  sectors it carries out of `lsecs_per_pg`.
- **2.0.** A bucket is one run of addresses inside one chunk, so a command
  that writes 16 consecutive sectors of a chunk is charged one program. Every
  operation is charged as page type 0 (the lower page). No channel time is
  charged.

The time is computed on the poller when the command arrives, and stored as
the request's `expire_time`. Chip and channel times are protected by one spin
lock each, so several pollers can time commands at once.

## Parameters

All OCSSD properties are listed in the
[OCSSD section of the property reference](../reference/properties.md#ocssd-open-channel).
How they interact:

| Property | 1.2 | 2.0 | Notes |
| --- | --- | --- | --- |
| `lver` | 1 | 2 | Any other value fails realize. |
| `lnum_ch` | channels | groups | `lnum_ch * lnum_lun` at most 128, `lnum_ch` at most 32: the chip and channel arrays are that size. |
| `lnum_lun` | LUNs per channel | parallel units per group | |
| `lnum_pln` | 1, 2 or 4 | any value above 0 | 2.0 folds the planes into the chunk size. |
| `lpgs_per_blk` | at most 512 | any value above 0 | 1.2 looks up the page type in a 512-entry table. |
| `lsecs_per_pg` | sectors per page | sectors per page | |
| `lsec_size` | reported sector size | must be above 0, otherwise ignored | |
| `lmetasize` | out-of-band bytes per sector | ignored (16) | |
| `lmax_sec_per_rq` | addresses per command | ignored (64) | |
| `flash_type` | timing table | timing table | 1 to 4; others fail realize. |
| `oc12_channel_timing`, `ch_xfer_lat` | channel time | ignored | `ch_xfer_lat` must not be negative when channel timing is on. |
| `learly_reset` | ignored | early reset capability | |
| `devsz_mb` | sets blocks per LUN | sets chunks per parallel unit | 1.2 needs 1 to 65535 blocks per LUN. |

`ms_max` has no effect; a value other than the default prints a warning. An Open-Channel
controller has exactly one namespace, and `namespace_modes`, if given, must
say `ocssd`.

A minimal 2.0 device with the geometry of `run-whitebox.sh`:

<!-- femu-example: design-ocssd20 -->
```text
-device femu,devsz_mb=4096,namespaces=1,lver=2,nlbaf=5,lba_index=3,lnum_ch=2,lnum_lun=4,lnum_pln=2,lsecs_per_pg=4,lpgs_per_blk=512,femu_mode=0
```

## Counters

OCSSD has no device FTL, so the vendor log page C0h stays zero. What the
mode does report:

- The SMART log's host read and write counts. The poller counts only the
  plain NVMe Read and Write opcodes (0x02 and 0x01), so vector commands are
  not counted: on 1.2 the counts stay at zero, and on 2.0 they move only for
  plain Read and Write.
- In 2.0, the chunk information log (CAh): each chunk's state, write pointer
  and wear index. The wear index counts resets.

## Validation status

- The qtest suite in `hw/femu/tests/qtest/femu-test.c`, run in CI, has
  command-level cases for both versions. For 1.2: `oc12-opcodes`,
  `oc12-capabilities`, `oc12-small-sectors`, `oc12-ppa-timing`,
  `oc12-flash-type`, `oc12-page-count`, `oc12-transfer-cost` and the
  `oc12-channel-*` cases for channel time. For 2.0: `oc20-vector-io`,
  `oc20-set-chunks`, `oc20-log-length`, `oc20-sgl-refused` and `oc20-fuzz`,
  a fuzzer over the command fields.
- The documentation check starts each OCSSD example in this guide and in
  the mode guide, and sends Identify; it does not move data in this mode.
- No guest test runs in CI: LightNVM needs a guest kernel older than 5.15,
  and the guest image FEMU builds runs Linux 6.8.

## Limits

- One namespace per controller.
- 1.2 does not enforce erase-before-write, does not reset sector state on
  erase, and does not act on its bad block table (see above).
- 2.0 does not model page types or channel transfer, and charges one page
  time per chunk run regardless of how many pages the run covers.
- 2.0 does not store per-sector metadata.
- The vendor admin command 0xEE can change the read, program and erase
  times of the lower and upper pages and the channel time at run time, but
  not those of the centre pages of TLC and QLC
  ([0xEE](nand-timing.md#runtime-switches)).
- The Get L2P Table command of 1.2 always returns unmapped entries.
- Data lives only in host memory and is lost when QEMU exits.

Refusals at realize are listed in the
[mode guide](../modes/ocssd.md#limits-and-refusals).

## Extending the mode

- **A new cell type.** Add its latencies and page-type table in
  `hw/femu/nand/nand.h` and `hw/femu/nand/nand.c`, then widen the
  `flash_type` checks in `nvme_check_constraints()` (`hw/femu/femu.c`) and
  `oc12_init()`.
- **Page types or channel time in 2.0.** `oc20_advance_status()` passes page
  type 0 and a transfer time of 0. Look up the page from the sector index
  and pass a transfer time, as `oc12_advance_status()` does.
- **Enforcing 1.2 write-once.** `oc12_meta_state_set_written()` already reads
  the sector state; refuse a write when it is `OC12_SEC_WRITTEN`, and make
  `oc12_meta_blk_set_erased()` reset the states instead of returning early.
- **Another log page.** Add a case to `oc20_get_log()`; the generic Get Log
  Page handler offers unknown log IDs to the namespace's `get_log` hook.

## Source map

| File | Contents |
| --- | --- |
| [`hw/femu/ocssd/oc12.c`](../../ocssd/oc12.c), [`oc12.h`](../../ocssd/oc12.h) | 1.2 commands, PPA format, sector metadata, bad block tables, init and exit |
| [`hw/femu/ocssd/oc20.c`](../../ocssd/oc20.c), [`oc20.h`](../../ocssd/oc20.h) | 2.0 commands, chunk descriptors, write pointer rules, geometry, log page |
| [`hw/femu/timing-model/timing.c`](../../timing-model/timing.c) | chip and channel busy-until times, geometry bound check |
| [`hw/femu/nand/nand.h`](../../nand/nand.h), [`nand.c`](../../nand/nand.c) | per-cell-type latency tables and page-type tables |
| [`hw/femu/femu.c`](../../femu.c) | `nvme_register_extensions()`, realize-time checks |
| [`hw/femu/nvme-io.c`](../../nvme-io.c) | `nvme_io_cmd()` dispatch, completion queue |

## Related pages

- [OCSSD guide](../modes/ocssd.md): launching, guest tools, troubleshooting
- [Timing model: OCSSD](../concepts/timing-model.md#ocssd)
- [Property reference: OCSSD](../reference/properties.md#ocssd-open-channel)
