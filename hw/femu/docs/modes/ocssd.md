# Open-Channel SSD (OCSSD)

OCSSD mode (`femu_mode=0`) emulates an Open-Channel SSD, also called a
"white-box" SSD. The device has no FTL. The host sees the NAND geometry
(channels or groups, LUNs or parallel units, blocks or chunks, pages) and
addresses physical pages directly with vector read, write and erase
commands. Mapping, garbage collection and wear levelling run in the host.
`lver=2` (the default) selects Open-Channel 2.0, `lver=1` selects 1.2.

Use it for host-side FTL research: LightNVM and pblk in older Linux kernels,
or SPDK.

**The guest kernel must be older than 5.15.** Linux removed LightNVM, its
Open-Channel driver, in 5.15. A newer guest kernel, including the Linux 6.8
image from `make-guest-image.sh`, sees the controller but has no driver for
the Open-Channel interface. On a newer kernel, drive the device from user
space with SPDK.

## Requirements

- Guest kernel: older than 5.15, with LightNVM (`CONFIG_NVM`) and pblk
  (`CONFIG_NVM_PBLK`) built. The minimum version for each Open-Channel
  release is in [the mode table](../concepts/choosing-a-mode.md#every-mode-at-a-glance)
  and [requirements.md](../getting-started/requirements.md#kernel-per-mode).
  [guest-image.md](../getting-started/guest-image.md#kernel-per-mode) says
  how to get such a guest.
- Guest tools: nvme-cli 1.x for `nvme lnvm`. nvme-cli 2.x no longer has the
  `lnvm` commands.
- Host: nothing beyond the common requirements. `run-whitebox.sh` uses a
  4 GiB device and a 4 GiB guest.

## Launch

From `build-femu/`:

<!-- femu-example: ocssd-launcher -->
```bash
./run-whitebox.sh
```

The FEMU device in that script, for Open-Channel 2.0, is:

<!-- femu-example: ocssd20-device -->
```
-device femu,devsz_mb=4096,namespaces=1,lver=2,lmetasize=16,nlbaf=5,lba_index=3,mdts=10,lnum_ch=2,lnum_lun=4,lnum_pln=2,lsec_size=4096,lsecs_per_pg=4,lpgs_per_blk=512,femu_mode=0
```

For Open-Channel 1.2, set `OCVER=1` at the top of `run-whitebox.sh`, which
changes `lver`:

<!-- femu-example: ocssd12-device -->
```
-device femu,devsz_mb=4096,namespaces=1,lver=1,lmetasize=16,nlbaf=5,lba_index=3,mdts=10,lnum_ch=2,lnum_lun=4,lnum_pln=2,lsec_size=4096,lsecs_per_pg=4,lpgs_per_blk=512,femu_mode=0
```

`run-whitebox.sh` lets you change `ssd_size`, `num_channels` and
`num_chips_per_channel`. Keep the other values unless you have a reason to
change them.

## Configuration

Properties: [OCSSD](../reference/properties.md#ocssd-open-channel). The
BlackBox geometry and timing properties do not apply, except `ch_xfer_lat`
with `oc12_channel_timing`.

### Geometry

- `lnum_ch`: channels (groups in 2.0), 1 to 32.
- `lnum_lun`: LUNs (parallel units in 2.0) per channel. `lnum_ch * lnum_lun`
  is at most 128.
- `lnum_pln`: planes per LUN. Open-Channel 1.2 accepts 1, 2 or 4.
- `lpgs_per_blk`: pages per block, at most 512 for 1.2. A 2.0 chunk is one
  block on every plane of a parallel unit.
- `lsecs_per_pg`: sectors per page.
- `lsec_size` and `lmetasize`: sector and out-of-band metadata size for 1.2.
  2.0 always uses 4096-byte sectors with 16 bytes of metadata.
- `devsz_mb` sets the capacity, and with it the number of blocks per LUN.

### Timing

Read, program and erase times come from the `flash_type` table: 1 SLC,
2 MLC (the default), 3 TLC or 4 QLC. Open-Channel 1.2 also charges channel
transfer time when `oc12_channel_timing=on`, using `ch_xfer_lat` per page or
the table value when it is 0. Open-Channel 2.0 charges no channel time.
Vendor admin command 0xEE changes these times at run time
([NAND timing](../design/nand-timing.md#runtime-switches)). See
the [timing model](../concepts/timing-model.md#ocssd).

### Other

- `learly_reset` (2.0): report that the host may reset a chunk it has not
  filled.
- OCSSD supports one namespace, does not take `namespace_modes` other than
  `ocssd`, and ignores `sgl`.

## Use it from the guest

These commands assume a guest kernel with LightNVM and nvme-cli 1.x.

Check the device:

```sh
sudo nvme list
sudo nvme id-ctrl /dev/nvme0 | grep -E '^(mn|sn) '
sudo nvme lnvm list
```

The model is `FEMU OpenChannel-SSD Controller (v2.0)` (or `(v1.2)`), and the
serial number starts with `vOCSSD`.

Open-Channel 1.2 accepts only its vector commands on `/dev/nvme0n1`;
Open-Channel 2.0 also accepts plain Read and Write. Either way the host has
to follow the NAND rules below. To get a normal block device, create a pblk target over a range of LUNs. With
`run-whitebox.sh` there are 2 x 4 = 8 LUNs, numbered 0 to 7:

```sh
sudo nvme lnvm create --device-name=nvme0n1 --target-name=mydev \
    --target-type=pblk --lun-begin=0 --lun-end=7
```

`/dev/mydev` is then a block device with pblk as its host FTL. Use it like
any disk:

```sh
sudo fio --name=oc --filename=/dev/mydev --direct=1 --ioengine=libaio \
    --rw=randwrite --bs=4k --iodepth=16 --size=1G
sudo mkfs.ext4 /dev/mydev
```

With SPDK, bind the controller to SPDK's user-space driver and use its
Open-Channel support. FEMU's Open-Channel 2.0 controller also accepts the
plain NVMe Read and Write commands that SPDK sends.

The 2.0 chunk information log page (CAh) reports each chunk's state, write
pointer and wear, 32 bytes per chunk. It needs an explicit namespace, and
`--log-len` must not exceed 32 times the chunk count. This reads the first
128 chunks:

```sh
sudo nvme get-log /dev/nvme0 --log-id=0xca --log-len=4096 --namespace-id=1
```

The vendor log page C0h stays zero in OCSSD mode: there is no device FTL to
count.

## Limits and refusals

| Message | Cause and fix |
| --- | --- |
| `lver must be 1 (Open-Channel 1.2) or 2 (Open-Channel 2.0)` | Another `lver`. |
| `flash_type must be 1 (SLC), 2 (MLC), 3 (TLC) or 4 (QLC)` | A cell type without a timing table. |
| `ocssd supports a single namespace` | `namespaces` above 1. |
| `ocssd is a controller mode: femu_mode and namespace_modes must both select it, or neither` | `namespace_modes=ocssd` on a controller of another mode, or the reverse. |
| `FEMU ocssd: lnum_ch must not exceed 32 and lnum_ch * lnum_lun must not exceed 128, got 64 and 8` | The geometry is too large. |
| `FEMU ocssd: lnum_ch, lnum_lun, lnum_pln, lsecs_per_pg, lpgs_per_blk and lsec_size must all be greater than zero` | A geometry property is 0. |
| `FEMU ocssd: lnum_pln must be 1, 2 or 4, got 3` | Open-Channel 1.2 plane count. |
| `OC 1.2 requires SLC, MLC, TLC or QLC and at most 512 pages per block` | `lpgs_per_blk` above 512 with `lver=1`. |

At run time, Open-Channel 2.0 enforces the chunk rules: a write must start
at the chunk's write pointer, so a chunk must be reset before it is written
again. Open-Channel 1.2 does not check; a rewrite of a written page silently
replaces its data, which real flash would not allow. A write outside the
geometry fails in both.

## Verify

1. `sudo nvme list` shows the model `FEMU OpenChannel-SSD Controller`.
2. On a LightNVM guest, `sudo nvme lnvm list` lists `nvme0n1` with the
   geometry you set, and `nvme lnvm create` gives a `/dev/mydev` that fio can
   write and read.

## Troubleshooting

- **The device shows up but nothing can use it.** The guest kernel is 5.15 or
  newer, so there is no LightNVM. Boot an older kernel, or use SPDK.
- **`nvme lnvm`: invalid sub-command.** nvme-cli 2.x dropped it. Build
  nvme-cli 1.x in the guest.
- **Writes fail after rewriting an address (Open-Channel 2.0).** A write
  must start at the chunk's write pointer; reset the chunk first. Run normal
  workloads on a pblk target, not on `/dev/nvme0n1`.
- **`dmesg` shows `corrupted read LBA` from pblk.** Users reported this
  warning on reads of pages that were never written; the maintainers found
  the data intact.
- **`mkfs` hangs on a pblk target.** Users reported that keeping
  `lnum_pln=2`, changing only `lnum_ch`, `lnum_lun` and the size, and using a
  power-of-two size avoided it.
- **SPDK cannot write the device.** Older FEMU accepted only vector commands
  on Open-Channel 2.0. Current FEMU also accepts NVMe Read and Write.

Related issues: #3, #4, #48, #49, #118.

## Related pages

- [Timing model: OCSSD](../concepts/timing-model.md#ocssd)
- [Requirements: kernel per mode](../getting-started/requirements.md#kernel-per-mode)
- [Device property reference: OCSSD](../reference/properties.md#ocssd-open-channel)
