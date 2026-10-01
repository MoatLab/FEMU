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
- Guest tools: `nvme-cli` (`io-passthru`), and a C compiler to build
  `kv-probe.c`. The image from `make-guest-image.sh` has no compiler; add one
  with `./make-guest-image.sh --packages build-essential`, or run
  `sudo apt install build-essential` in the guest.

## Launch

There is no KV launcher. Start from `run-nossd.sh` or `run-blackbox.sh` and
replace the FEMU device with:

<!-- femu-example: kvssd-device -->
```
-device femu,devsz_mb=4096,namespaces=1,femu_mode=5
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

### With kv-probe

`hw/femu/scripts/kv-probe.c` runs the whole lifecycle: store, exist,
retrieve (full and short), the conditional stores, delete, and the retrieve
that must then miss. It checks status and data. From `build-femu/` on the
host, copy it to the guest and run it:

```sh
scp -P 8080 -i ~/images/femu-guest-key ../femu-scripts/kv-probe.c femu@localhost:
./run-guest-ssh.sh gcc -O2 -o kv-probe kv-probe.c
./run-guest-ssh.sh sudo ./kv-probe /dev/nvme0
```

### Status codes

| Status | Meaning |
| --- | --- |
| 0x85 | Invalid Value Size: the value is larger than 2 MiB. |
| 0x86 | Invalid Key Size: a key length of 0 on Store, Retrieve, Delete or Exist. For List, length 0 means "from the start". |
| 0x87 | Key Does Not Exist: Retrieve or Exist of a missing key, a Store with bit 8 (only if the key exists) for a missing key, or Delete of a missing key when EDNEK is set. It comes with Do Not Retry set. |
| 0x89 | Key Exists: a Store with bit 9 (only if the key is absent) found the key. |
| Capacity Exceeded | The value space or the key index is full. |
| Invalid Field | A key longer than 16 bytes, a List buffer smaller than 4 bytes, or the broadcast namespace ID. |

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

## Verify

1. `sudo nvme id-ctrl /dev/nvme0` reports the model `FEMU KV-SSD Controller`.
2. The store, retrieve and `cmp` above succeed, and Exist after Delete
   returns 0x87.
3. `kv-probe` prints no failures.

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

Related issues: #68.

## Related pages

- [Timing model: KV and CSD](../concepts/timing-model.md#kv-and-csd)
- [Architecture: other FTLs](../concepts/architecture.md#other-ftls)
- [Multiple namespaces](../features/multi-namespace.md)
