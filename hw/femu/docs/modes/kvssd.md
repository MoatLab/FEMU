# Key-value SSD (KV)

KV mode (`femu_mode=5`) emulates an SSD with the NVMe Key Value command set.
The namespace stores values under keys instead of blocks at addresses: the
host sends Store, Retrieve, Delete, Exist and List commands with a key of up
to 16 bytes. Values live on emulated NAND laid out with the BlackBox
geometry, and each command is charged NAND read and program time.

Use it to develop or measure key-value stores and host software written for
key-value devices, without key-value hardware.

## Requirements

- Host and guest: see [the mode table](../concepts/choosing-a-mode.md#every-mode-at-a-glance)
  and [requirements.md](../getting-started/requirements.md#kernel-per-mode).
- Linux has no key-value command set driver. The namespace gets no block
  device (`/dev/nvme0n1` does not exist for it). You drive it with NVMe
  passthrough commands, from nvme-cli or your own program. On a controller
  with one namespace, send them to the controller node `/dev/nvme0`. Linux
  refuses I/O passthrough on the controller node when the controller has
  more than one namespace; then use the namespace's generic node
  `/dev/ngXnY`.
- Guest kernel: 6.0 or newer. Linux 6.0 started to attach namespaces of a
  command set it has no driver for, with only the generic node (commit
  eb867ee995bd, "nvme: enable generic interface (/dev/ngXnY) for unknown
  command sets"). Linux 5.10 to 5.19 log `unknown csi 1 for nsid N` (5.9:
  `unknown csi:1 ns:N`) and skip the namespace, so passthrough on
  `/dev/nvme0` fails too.
- The host must enable the controller with CC.CSS set to 110b (all
  supported I/O command sets). Under 000b (NVM only), every I/O command
  to a KV namespace fails with Invalid Command Opcode (Base 2.3, Figure
  41). Linux sets 110b when CAP.CSS bit 6 is set, and FEMU sets that bit.
- Guest tools: `nvme-cli` (`io-passthru`), and a C compiler to build
  `kv-probe.c`. The image from `make-guest-image.sh` has no compiler; add one
  with `./make-guest-image.sh --packages build-essential`, or run
  `sudo apt install build-essential` in the guest.

## Launch

From `build-femu/`:

<!-- femu-example: kvssd-launcher -->
```bash
./run-kvssd.sh
```

The FEMU device in that script is:

<!-- femu-example: kvssd-launcher-device -->
```
-device femu,devsz_mb=4096,namespaces=1,femu_mode=5,secsz=512,secs_per_pg=8,pgs_per_blk=256,blks_per_pl=256,pls_per_lun=1,luns_per_ch=8,nchs=8,pg_rd_lat=40000,pg_wr_lat=200000,blk_er_lat=2000000,gc_thres_pcent=75
```

The geometry and timing above are the defaults, so the shortest KV device
is:

<!-- femu-example: kvssd-device -->
```
-device femu,devsz_mb=4096,namespaces=1,femu_mode=5
```

The preset `hw/femu/scripts/configs/kvssd.conf` describes the launcher's
device; [`ssd-config.sh`](../tutorials/09-ssd-config-files.md) expands it to:

<!-- femu-example: kvssd-preset -->
```
-device femu,id=nvme0,devsz_mb=4096,namespaces=1,secsz=512,secs_per_pg=8,pgs_per_blk=256,blks_per_pl=256,pls_per_lun=1,luns_per_ch=8,nchs=8,pg_rd_lat=40000,pg_wr_lat=200000,blk_er_lat=2000000,gc_thres_pcent=75,femu_mode=5
```

## Configuration

KV uses only part of the BlackBox properties:

- [NAND geometry](../reference/properties.md#nand-geometry-bbssd-csd-kv)
  (`nchs`, `luns_per_ch`, `pls_per_lun`, `blks_per_pl`, `pgs_per_blk`,
  `secs_per_pg`, `secsz`) lays out the value store.
- [NAND timing](../reference/properties.md#nand-timing-bbssd-csd-kv)
  (`pg_rd_lat`, `pg_wr_lat`, `blk_er_lat`, `nand_cell_type` and the channel
  bus properties) sets the cost of each command.
- `gc_thres_pcent` is the share of the NAND usable for values. The usable
  value space is the namespace size or that share of the NAND, whichever is
  smaller.

The FTL, mapping, cache and write buffer properties do not apply. Each
command pays one page read for the index lookup, overlapped with the NAND
reads or programs of its value; reclaiming space charges erases to the command that
triggers it ([timing model](../concepts/timing-model.md#kv-and-csd)).

### Key index (kv_index)

The device index from key to value is an open-addressed hash in DRAM by
default. `kv_index=lsm` makes it an LSM tree after PinK. Lookups then
read meta pages of the unpinned levels, merges load the NAND in the
background, and List returns keys in byte order. See
[LSM-tree key index](../features/kv-lsm-index.md) for the knobs and the
cost model.

<!-- femu-example: kvssd-lsm -->
```
-device femu,femu_mode=5,devsz_mb=64,kv_index=lsm,kv_lsm_pinned_levels=2
```

### Value packing (kv_pack)

Values whose record (the value and a 32 byte header) fits a NAND page
share pages, as real KV-SSDs pack small values. A Store goes to an open
page in controller DRAM; the page is programmed when the next record does
not fit. With `vwc=1`, Flush programs the open page. `kv_pack=off` gives
each value whole pages, the model before packing. See
[KV value packing](../features/kv-value-packing.md).

<!-- femu-example: kvssd-pack-off -->
```
-device femu,femu_mode=5,devsz_mb=64,kv_pack=off
```

### Key limit (kv_max_keys)

Each KV namespace has a key limit. Identify reports it as MNK, the maximum
number of keys of KV format 0 (KV 1.3, Figure 42). A Store of a new key
past the limit fails with Capacity Exceeded. An overwrite of a key that
exists passes the key check.

With `kv_max_keys=0` (the default), FEMU sizes the limit from the flash:

```
 kv_pack=on   MNK = usable pages * floor(page size / 33)
              (one 33-byte record per 1-byte value), 1023 to 4194303
              (a page below 33 bytes holds one value)
 kv_pack=off  MNK = 2 * (value space / 4 KiB + 1) - 1, 1023 to 4194303
              (the old limit: a value takes whole pages)
 usable pages = NAND pages * gc_thres_pcent / 100
```

So with packing, small values are no longer held to the old two keys
for each 4 KiB of value space. MNK is an estimate that sizes the index.
The value space, the flash or the limit can stop new keys first. A
namespace with more than about 130 MiB of usable flash gets the top of
4194303 keys. Real KV-SSDs also limit the key count by the device DRAM
that holds the index. In FEMU the index is a table in host DRAM:

```
 hash index: K keys --> K + K/3 + 1 slots * 64 bytes  (about 85 B a key)
             K = 4194303 (the automatic top) --> about 341.3 MiB
 kv_pack=off without kv_max_keys: the old table, K + 1 slots
 a page of the table costs host memory only when a key lands in it
```

`kv_max_keys=N` (1 to 1610612735) sets the limit of each KV namespace.
With the hash index, a small value saves host DRAM, and a large value
gives more keys than the automatic top. Realize fails when the host
cannot allocate the table. With `kv_index=lsm` the limit counts live
keys only. The LSM table holds versions, starts small and grows with the
Stores.

<!-- femu-example: kvssd-max-keys -->
```
-device femu,femu_mode=5,devsz_mb=64,kv_max_keys=100000
```

### Workload-mix timing (kv_timing=model)

With `kv_timing=model`, Store and Retrieve take their time from a fitted
model, not from the NAND model. The fit and its coefficients come from the
Samsung KVSSD PDK emulator (BSD-3). Delete, Exist, List and a Retrieve of
a missing key keep the NAND model time, as in the PDK.

```
 Store / Retrieve hit
        |
        v
 window of the last 16 timed commands  (per namespace)
   insert share, read share, update share, mean value size
        |
        v
 kIOPS = cubic polynomial (35 terms + intercept)
        |
        v
 latency = 1e6 / kIOPS ns   (x size / 16 KiB when the mean is above 16 KiB)
```

- An insert is a Store of a new key. An update is a Store over an existing
  key. A read is a Retrieve that finds the key, with the bytes it returns.
- Each command gets its own latency. Commands do not queue behind each
  other, so throughput grows with queue depth, as in the PDK.
- The NAND model still runs, so wear, space and the counters move as in
  media mode. Only the time of the command changes.
- The fit is not used above a mean value size of 16 KiB, where it grows
  without bound. The time then scales with the size.
- A result below 0.01 kIOPS, or one that is not finite, becomes 0.01 kIOPS.
  QEMU then warns once for each namespace.
- The PDK computes the size terms x0^2 and x0^3 in 32-bit integers.
  x0^3 wraps above 1625 bytes, and x0^2 above 65535 bytes. FEMU computes
  every term in double. At 4 KiB FEMU gives 0.24 kIOPS more than the PDK.

`kv_model_coeffs` replaces the fit: 36 comma-separated numbers, the
intercept first. On a `-device` line, write each comma twice. The 35
coefficients follow the PDK term order:

```
 x0 = mean value size, x1 = insert share, x2 = read share, x3 = update share
 1, x0, x1, x2, x3,
 x0^2, x0 x1, x0 x2, x0 x3, x1^2, x1 x2, x1 x3, x2^2, x2 x3, x3^2,
 x0^3, x0^2 x1, ... (every product of three, in the same order), x3^3
```

What the fit does not tell:

- the device and the firmware that produced it;
- the queue depth and the key size at training time;
- the training data, so the fit cannot be checked or trained again here.

Use it to compare workload mixes against one fixed device curve, not as a
calibrated device.

<!-- femu-example: kvssd-model -->
```
-device femu,femu_mode=5,devsz_mb=4096,kv_timing=model
```

Limits built into the mode:

- Keys are 1 to 16 bytes.
- Values are at most 2 MiB, and one command also cannot move more than
  `mdts` allows (4 MiB by default).
- Each KV namespace has its own key space. A controller can have several KV
  namespaces, or KV next to block namespaces
  ([multi-namespace guide](../features/multi-namespace.md)); see the
  requirements above for which device node to use then.
- KV checks the BlackBox geometry properties, but not the GC capacity rule
  BlackBox applies: a namespace larger than the NAND allows still starts,
  and its usable value space is clamped to the NAND.

## Use it from the guest

### Command format

| Command | Opcode |
| --- | --- |
| Store | 0x01 |
| Retrieve | 0x02 |
| List | 0x06 |
| Delete | 0x10 |
| Exist | 0x14 |

- Key: the low 8 bytes in CDW2 and CDW3, the high 8 bytes in CDW14 and
  CDW15, little-endian.
- CDW11 bits 7:0: key length in bytes.
- CDW11 bits 15:8, Store only: bit 8 stores only if the key exists, bit 9
  stores only if it does not.
- CDW10: the value size for Store, the host buffer size for Retrieve and
  List.
- The value moves through the normal data pointer.
- The namespace ID must be given. nvme-cli sends 0 by default, which the
  Linux driver refuses with Invalid argument before the command reaches the
  device. FEMU answers the broadcast ID (`0xffffffff`) with Invalid Field.

### With nvme-cli

Check the controller:

```sh
sudo nvme id-ctrl /dev/nvme0 | grep -E '^(mn|sn) '
```

The model is `FEMU KV-SSD Controller` and the serial number starts with
`vKVSSD`.

Store a 64-byte value under the 4-byte key `BBBB` (0x42424242), read it
back, check that it exists, then delete it:

```sh
head -c 64 /dev/urandom > value.bin
sudo nvme io-passthru /dev/nvme0 -O 0x01 -n 1 --cdw10=64 --cdw11=4 \
    --cdw2=0x42424242 -l 64 -w -i value.bin
sudo nvme io-passthru /dev/nvme0 -O 0x02 -n 1 --cdw10=64 --cdw11=4 \
    --cdw2=0x42424242 -l 64 -r -b > out.bin
cmp value.bin out.bin
sudo nvme io-passthru /dev/nvme0 -O 0x14 -n 1 --cdw11=4 --cdw2=0x42424242
sudo nvme io-passthru /dev/nvme0 -O 0x10 -n 1 --cdw11=4 --cdw2=0x42424242
```

Retrieve reports the full value size in the completion's result (Dword 0).
If the host buffer is smaller, the device returns the first bytes and the
host can retry with a larger buffer.

List up to 4096 bytes of keys from the start of the key space:

```sh
sudo nvme io-passthru /dev/nvme0 -O 0x06 -n 1 --cdw10=4096 --cdw11=0 \
    -l 4096 -r
```

The returned buffer starts with a 4-byte key count, followed by one entry
per key: a 2-byte key length and the key, each entry padded to 4 bytes.

### Walk all keys

The Key Value command set (revision 1.3) has no iterator and no command
that deletes a group of keys. A host walks the key space with List. The
order of the keys stays the same while no Store, Delete, Format or Sanitize
runs. A start key that exists comes back as the first entry.

```
 List(no key)        --> page 1: k1 k2 ... k8
 List(start = k8)    --> page 2: k8 k9 ... k15   (drop k8, it repeats)
 List(start = k15)   --> page 3: k15 k16 ...     (drop k15)
 ...                 --> stop when k1 comes back
```

FEMU returns the keys in the order of its index slots, from the slot of the
start key. After the last slot the walk continues from slot 0, so a walk
stops when its first key comes back. A start key that is not stored gives
the same first key as a List without a key. To delete all keys, walk them
and send one Delete for each key. The qtest `kv-list-walk` checks that a
walk returns each stored key once.

### With kv-probe

`hw/femu/scripts/kv-probe.c` runs the whole lifecycle: store, exist,
retrieve (full and short), the conditional stores, delete, the retrieve
that must then miss, and a key longer than 16 bytes. It checks status and
data. It takes the node to use as its argument (default `/dev/nvme0`) and
always addresses namespace 1. From `build-femu/` on the host, copy it to
the guest and run it:

```sh
scp -P 8080 -i ~/images/femu-guest-key ../femu-scripts/kv-probe.c femu@localhost:
./run-guest-ssh.sh gcc -O2 -o kv-probe kv-probe.c
./run-guest-ssh.sh sudo ./kv-probe /dev/nvme0
```

### With kv-bench

`hw/femu/scripts/kv-bench.c` is a key-value workload with the knobs of
Samsung's kvbench. It checks each Retrieve, Exist and List answer against
a model of the keys, and prints the rate and latency of each command. It
needs the generic node and an empty namespace:

```sh
scp -P 8080 -i ~/images/femu-guest-key ../femu-scripts/kv-bench.c femu@localhost:
./run-guest-ssh.sh gcc -O2 -pthread -o kv-bench kv-bench.c
./run-guest-ssh.sh sudo ./kv-bench --keys 20000 /dev/ng0n1
```

The `kv-bench` suite of `guest-conformance.sh` runs `kv-probe` and two
`kv-bench` runs in a fresh guest. See
[KV benchmark](../guides/testing.md#kv-benchmark).

### Status codes

| Status | Meaning |
| --- | --- |
| 0x85 | Invalid Value Size: the value is larger than 2 MiB. |
| 0x86 | Invalid Key Size: a key length of 0 on Store, Retrieve, Delete or Exist. For List, length 0 means "from the start". |
| 0x87 | Key Does Not Exist: Retrieve or Exist of a missing key, a Store with bit 8 (only if the key exists) for a missing key, or Delete of a missing key when EDNEK is set. It comes with Do Not Retry set. |
| 0x89 | Key Exists: a Store with bit 9 (only if the key is absent) found the key. |
| Capacity Exceeded | The value space is full, or a new key is past the key limit (MNK). |
| Invalid Field | A key longer than 16 bytes, a List buffer smaller than 4 bytes, or the broadcast namespace ID. |
| Invalid Command Opcode | The controller runs with CC.CSS 000b, which selects only the NVM command set. Enable it with 110b. |

By default, Delete of a missing key succeeds. Setting the EDNEK bit (bit 0)
of the Key Value Configuration feature (20h) makes it fail with 0x87:

```sh
sudo nvme set-feature /dev/nvme0 -n 1 -f 0x20 -V 1
```

### Counters

The vendor log page C0h sums its counters over the controller's BlackBox,
CSD and KV namespaces. This reads the host pages written, pages moved and
pages programmed ([log pages and counters](../reference/log-pages-and-counters.md#vendor-log-page-c0h)):

```sh
sudo nvme get-log /dev/nvme0 --log-id=0xc0 --log-len=512 -b | od -An -t u8 -j 8 -N 24 -w24
```

## Limits and refusals

| Message | Cause and fix |
| --- | --- |
| `the key-value command set and FDP cannot share a controller: placement owns every reclaim unit and the key-value store is left with no write pointer` | A KV namespace on a controller in an FDP subsystem. |
| `FEMU bbssd: nchs must be greater than 0, got 0` | KV checks the BlackBox geometry properties with the same messages, but not the GC capacity rule. |
| `meta: namespace 1 runs a mode without metadata support (block or no-SSD only)` | `meta` with a KV namespace. |
| `FEMU kvssd: kv_timing=X is not media or model` | Use `media` or `model`. |
| `FEMU kvssd: kv_model_coeffs: ...; give the intercept and 35 coefficients` | Give 36 finite numbers, separated by commas. |
| `kv_timing=model and kv_model_coeffs need a key-value namespace (femu_mode=5 or kvssd in namespace_modes)` | The device has no KV namespace, so the knobs would do nothing. |
| `kv_timing=model and kv_model_coeffs need a key-value namespace; shared namespaces are NoSSD or bbssd` | A controller on shared namespaces (`ns_mgmt=on` subsystem) has no KV namespace. |
| `kv_index=X is not hash or lsm` | Use `hash` or `lsm`. |
| `kv_lsm_memtable_keys, kv_lsm_size_ratio and kv_lsm_pinned_levels need kv_index=lsm` | An LSM knob other than its default with the hash index. |
| `kv_lsm_size_ratio=N is not 2 to 64` (and the other knob ranges) | See the [LSM index properties](../features/kv-lsm-index.md#properties). |
| `kv_index=lsm and the kv_lsm_* knobs need a key-value namespace ...` | The device has no KV namespace, or its namespaces are shared. |
| `FEMU kvssd: kv_index=lsm needs a page of at least 32 bytes; the page is N` | A meta page must hold one 32-byte record. |
| `kv_pack=off needs a key-value namespace ...` | The device has no KV namespace, or its namespaces are shared. |
| `kv_max_keys needs a key-value namespace ...` | The device has no KV namespace, or its namespaces are shared. |
| `kv_max_keys=N is not 0 to 1610612735` | Use 0 (automatic) or a limit in that range. |
| `FEMU kvssd: no host memory for an index table of N slots (M MiB); set a smaller kv_max_keys` | The host cannot allocate the hash index table. With `kv_index=lsm` the message has no hint: the first LSM table size comes from the value space. |

## Verify

1. `sudo nvme id-ctrl /dev/nvme0` reports the model `FEMU KV-SSD Controller`.
2. The store, retrieve and `cmp` above succeed, and Exist after Delete
   returns 0x87.
3. `kv-probe` prints no failures.
4. `kv-bench` prints `KVBENCH_RESULT=PASS`.

## Troubleshooting

- **There is no `/dev/nvme0n1`.** Expected: Linux attaches no block driver to
  a key-value namespace. Send commands to `/dev/nvme0`, or to `/dev/ngXnY`
  when the controller has several namespaces.
- **nvme-cli says `Invalid argument`.** Add `-n 1` (or the namespace you
  mean). nvme-cli sends namespace ID 0 by default, and the Linux driver
  refuses it. On a controller with several namespaces, the controller node
  refuses I/O passthrough altogether; use the generic node.
- **Retrieve returns 0x87 right after Store.** Check that the key bytes and
  the key length (CDW11) match exactly; `BBBB` with length 4 is a different
  key from `BBBB` with length 8.
- **`FEMU_KV_SELFTEST`**: set this environment variable to run the KV FTL
  self-test once at realize and log the result
  ([environment variables](../reference/properties.md#environment-variables)).
  A key limit below 128 skips it, with a `KVSELFTEST SKIP` line.

Related issues: #68.

## Related pages

- [Timing model: KV and CSD](../concepts/timing-model.md#kv-and-csd)
- [Architecture: other FTLs](../concepts/architecture.md#other-ftls)
- [Multiple namespaces](../features/multi-namespace.md)
- [LSM-tree key index](../features/kv-lsm-index.md)
- [KV value packing](../features/kv-value-packing.md)
