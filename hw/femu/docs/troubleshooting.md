# Troubleshooting and FAQ

Answers to the questions that come up most often in FEMU's issue tracker.
Each one gives a short answer, the fix or workaround, and the issues where
it came up. For build errors, see
[build.md](getting-started/build.md#common-build-errors). For crashes and
debug output, see [debugging](guides/debugging.md).

1. [Which device and mode do I want?](#which-device-and-mode-do-i-want)
2. [Which guest kernel does each mode need?](#which-guest-kernel-does-each-mode-need)
3. [Where do I get a guest image?](#where-do-i-get-a-guest-image)
4. [The build fails](#the-build-fails)
5. [How large an SSD can I emulate?](#how-large-an-ssd-can-i-emulate)
6. [How do I change the geometry or latency without recompiling?](#how-do-i-change-the-geometry-or-latency-without-recompiling)
7. [How do I set the ZNS zone size, zone count and limits?](#how-do-i-set-the-zns-zone-size-zone-count-and-limits)
8. [How do I choose the NAND cell type?](#how-do-i-choose-the-nand-cell-type)
9. [Why are reads impossibly fast?](#why-are-reads-impossibly-fast)
10. [How do I see garbage collection and write amplification?](#how-do-i-see-garbage-collection-and-write-amplification)
11. [What does FEMU model, and what not?](#what-does-femu-model-and-what-not)
12. [How do I run several SSDs or namespaces?](#how-do-i-run-several-ssds-or-namespaces)
13. [How do I run FDP?](#how-do-i-run-fdp)
14. [Can I still use OCSSD after LightNVM was removed?](#can-i-still-use-ocssd-after-lightnvm-was-removed)
15. [How do I get debug output?](#how-do-i-get-debug-output)
16. [How do I tune for performance?](#how-do-i-tune-for-performance)
17. [Where is the code for X, and how do I add a command?](#where-is-the-code-for-x-and-how-do-i-add-a-command)
18. [Does data survive a reboot?](#does-data-survive-a-reboot)

## Which device and mode do I want?

`-device femu` is an NVMe SSD; `femu_mode` picks what is inside it. With no
`femu_mode`, you get NoSSD (`femu_mode=2`): an NVMe drive with no media
timing. For a conventional SSD with an FTL, garbage collection and write
amplification, use BlackBox (`femu_mode=1`, `run-blackbox.sh`). ZNS is
`femu_mode=3`, Open-Channel `0`, computational storage `4`, key-value `5`.
FDP is not a mode: it is BlackBox with a `femu-subsys,fdp=on`. A CXL
memory-semantic SSD is a different device, `femu-cxl-ssd`.

**Fix:** pick from the decision table in
[choosing a mode](concepts/choosing-a-mode.md), then follow that mode's
guide.

Related issues: #21, #36, #60, #68, #153.

## Which guest kernel does each mode need?

| Mode | Guest kernel |
| --- | --- |
| NoSSD, BlackBox, CSD, FDP | any with the NVMe driver |
| ZNS | 5.9 or newer, with `CONFIG_BLK_DEV_ZONED=y` |
| KV | 6.0 or newer; the namespace appears only as `/dev/ngXnY` |
| OCSSD | older than 5.15, with LightNVM; 1.2 needs 4.16, 2.0 needs 4.17 |
| CXL SSD | CXL region support (`CONFIG_CXL_REGION` and related options) |

The image from `make-guest-image.sh` runs Linux 6.8 and covers every mode
except OCSSD.

**Fix:** if `nvme list` shows the controller but no usable namespace, check
`uname -r` in the guest against this table and `dmesg | grep nvme`.
[requirements.md](getting-started/requirements.md#kernel-per-mode) has the
details.

Related issues: #20, #57, #64, #112, #115, #161.

## Where do I get a guest image?

Build one. `make-guest-image.sh` makes an Ubuntu 24.04 image from the
official cloud image, with a `femu` user, an SSH key, `nvme-cli` and `fio`,
and writes it where the launchers look for it, `$HOME/images/u20s.qcow2`:

```sh
cd build-femu
./make-guest-image.sh
```

**Fixes for older instructions:**

- `qemu-system-x86_64: -localtime: invalid option`: QEMU removed
  `-localtime` in version 3.1. Use `-rtc base=localtime`.
- A launcher says `VM disk image couldn't be found`: set `OSIMGF` to your
  image, or `IMGDIR` to its directory.
- WSL is not supported, and in WSL the guest may use only one or two
  cores. Use a Linux host.

See [guest-image.md](getting-started/guest-image.md).

Related issues: #1, #36, #88, #89, #93.

## The build fails

FEMU is based on QEMU 10.1, which needs Python 3.9 and GLib 2.66 or newer,
so Ubuntu 20.04 and older cannot build it with their own packages.

**Fixes for the common errors:**

- `-Werror` stops the build on a new compiler warning: add
  `--disable-werror` to the `configure` line, and report the warning.
- Errors around `nfs_pread_async`: libnfs 6 changed its API. `femu-compile.sh`
  passes `--disable-libnfs`; pass it yourself if you run `configure` by hand.
- `Cannot find Ninja` or `python venv creation failed`: install
  `ninja-build` and `python3-venv`.
- Errors such as `memfd_create` declared twice, or syntax errors in the ZNS
  code, were reported against older FEMU versions. Build current `master`.

The full table is in [build.md](getting-started/build.md#common-build-errors).

Related issues: #2, #56, #136, #150, #168.

## How large an SSD can I emulate?

As large as the host's free memory. FEMU keeps the whole device in host
DRAM, so a 256 GiB device needs 256 GiB of free host RAM, plus the guest's
RAM and the FTL tables. A BlackBox, CSD or KV namespace can address at most
2^31 - 1 sectors, just under 1 TiB with 512-byte sectors.

Under `sudo`, FEMU locks the device memory at start-up, so all of it must be
free when QEMU starts. When the host cannot allocate it, QEMU aborts with
`failed to allocate N bytes`.

**Fix:** set `devsz_mb` (or, for BlackBox, the geometry and `op_pcent`) to
fit. [Host sizing](concepts/security-and-limits.md#host-sizing) explains the
memory a device takes.

Related issues: #19, #33, #52, #73, #144; discussion #119.

## How do I change the geometry or latency without recompiling?

Every setting is a device property on the QEMU command line. Nothing needs
a code change, and the old `vssd1.conf` file is gone.

**Fix:**

- Edit the variables at the top of the launcher (`run-blackbox.sh` and
  others), or write the `-device femu,...` line yourself.
- Or describe the device in a config file and expand it with
  `ssd-config.sh` ([scripts reference](reference/scripts.md#configuration-files)).
- BlackBox: `pg_rd_lat`, `pg_wr_lat`, `blk_er_lat` (ns) and the geometry
  properties. ZNS: `zns_pg_rd_lat`, `zns_pg_wr_lat`, `zns_blk_er_lat` and
  `zns_num_ch`, `zns_num_lun`, `zns_num_plane`, `zns_num_blk`.
- `qemu-system-x86_64 -device femu,help` lists every property, and
  [the property reference](reference/properties.md) explains each one.

This example sets a 4 GiB BlackBox device with 50 us reads:

<!-- femu-example: faq-latency -->
```
-device femu,devsz_mb=4096,femu_mode=1,pg_rd_lat=50000,pg_wr_lat=500000,blk_er_lat=3000000
```

Related issues: #19, #21, #73, #193.

## How do I set the ZNS zone size, zone count and limits?

There is no zone size property. The zone size follows from the namespace
size and `zns_num_ch`, `zns_num_lun`, `zns_num_plane`, `zns_num_blk` and
`zns_chnls_per_zone`. Raising `zns_num_blk` gives more, smaller zones.
Linux needs a power-of-two zone size.

**Fix:**

- Use the formula and table in
  [the ZNS guide](modes/zns.md#zone-size-and-zone-count).
- For 4 KiB logical blocks, set `lba_index=3`; no code change is needed.
- `zns_max_open` and `zns_max_active` set the open and active zone limits
  (0 means no limit).

<!-- femu-example: faq-zns -->
```
-device femu,devsz_mb=4096,femu_mode=3,lba_index=3,zns_num_ch=8,zns_num_lun=4,zns_num_plane=2,zns_num_blk=128,zns_max_active=16,zns_max_open=8
```

Related issues: #76, #126, #144, #177, #182.

## How do I choose the NAND cell type?

Each mode has its own numeric property. Names such as `tlc` are not
accepted:

| Mode | Property | Values |
| --- | --- | --- |
| BlackBox, CSD, KV | `nand_cell_type` | 0 flat times (default), 1 SLC, 2 MLC, 3 TLC, 4 QLC |
| ZNS | `zns_flash_type` | 1 SLC, 3 TLC, 4 QLC; 2 MLC and 5 PLC only with explicit `zns_pg_rd_lat`, `zns_pg_wr_lat` and `zns_blk_er_lat` |
| OCSSD | `flash_type` | 1 SLC, 2 MLC, 3 TLC, 4 QLC |

`Property 'femu.cell_type' not found` means the name is wrong: use
`nand_cell_type`. FEMU has no mode that mixes cell types, such as an SLC
cache in front of TLC.

<!-- femu-example: faq-qlc -->
```
-device femu,devsz_mb=1024,femu_mode=1,nand_cell_type=4
```

Related issues: #50, #113, #132.

## Why are reads impossibly fast?

In BlackBox and CSD, a read of a page that was never written has no
mapping, so it costs no NAND time and returns zeroes. A read benchmark on a
fresh device therefore measures only FEMU's overhead. Old versions printed
`ppn[-1] not mapped` for such reads; current versions print nothing.

**Fix:** write the range before you read it, for example with a sequential
fio write job, as in [measuring](guides/measuring.md#blackbox-and-csd).

Related issues: #16, #92.

## How do I see garbage collection and write amplification?

Read the vendor log page C0h in the guest. Its first 4 bytes are the write
amplification factor times 1000, followed by the host, GC and NAND page
counts:

```sh
sudo nvme get-log /dev/nvme0 --log-id=0xc0 --log-len=512 -b | od -An -t u4 -N 4
```

The old SMART vendor bytes no longer hold these counters. GC starts when
75% of the lines are in use (`gc_thres_pcent`), so on a fresh device you
must write more than the free space before the WAF rises above 1.000.
Random overwrites leave valid pages in every line, which GC must move;
sequential overwrites free whole lines, so the WAF stays near 1.

**Fix:** see [measuring](guides/measuring.md#write-amplification-and-media-counters-c0h)
for per-run WAF and the [BlackBox guide](modes/blackbox.md#use-it-from-the-guest)
for a workload that makes GC run.

Related issues: #130, #137.

## What does FEMU model, and what not?

FEMU models:

- NAND read, program and erase times per LUN (per plane for ZNS), with
  optional channel bus, program and erase suspend, and ECC retry time;
- the BlackBox FTL: page or cached mapping, GC, write buffer, read cache,
  wear and errors;
- optional PCIe bandwidth, propagation delay and controller firmware time
  (`pcie_bandwidth_mbps`, `pcie_prop_delay_ns`, `fw_cpu_ns`).

It does not model:

- the time to copy data between guest memory and the device; the copy
  happens at once, and the model only delays the completion;
- persistence: the device lives in host memory;
- power, heat or temperature changes (the reported temperature is the
  `temperature` property);
- interrupt coalescing (the features are reported but not applied).

The latency is a lower bound. A completion is posted on the first poller
pass after it is due, so a poller without a host core adds delay. The
guest's own driver and block layer add time that the model does not
include.

**Fix:** read the [timing model](concepts/timing-model.md), and measure
FEMU's own overhead on a NoSSD device before you compare against the model.

Related issues: #7, #15, #69, #151.

## How do I run several SSDs or namespaces?

For several SSDs, add one `-device femu` per SSD, each with its own `id`
and `devsz_mb`. For several namespaces on one controller, set `namespaces`.
`namespace_sizes` and `namespace_modes` give each namespace its own size
and mode; double the commas inside them on the QEMU command line:

<!-- femu-example: faq-multi -->
```
-device femu,id=nvme0,devsz_mb=4096,femu_mode=1,namespaces=2,namespace_sizes=3G,,1G -device femu,id=nvme1,devsz_mb=1024,femu_mode=3
```

The `serial` property has no effect: each controller reports a serial
number made of a mode prefix and a counter, in the order the controllers
are created. Names under `/dev/disk/by-id` therefore depend on the order of
the `-device` options.

**Fix:** see [several namespaces and devices](features/multi-namespace.md).
OCSSD and FDP controllers have one namespace each.

Related issues: #26, #121.

## How do I run FDP?

FDP is configured on an NVMe subsystem, not on the controller. Create a
`femu-subsys` with `fdp=on` first, then a BlackBox controller that joins
it. `run-blackbox-fdp.sh` does both.

<!-- femu-example: faq-fdp -->
```
-device femu-subsys,id=subsys0,nqn=subsys0,fdp=on,fdp.nruh=4 -device femu,devsz_mb=4096,femu_mode=1,subsys=subsys0
```

In the guest, `sudo nvme fdp configs /dev/nvme0 -e 1` shows the
configuration. See the [FDP guide](features/fdp.md).

Related issues: #153.

## Can I still use OCSSD after LightNVM was removed?

Linux removed LightNVM, its Open-Channel driver, in 5.15. On a newer guest
kernel the OCSSD controller appears, but nothing in the kernel can use it.

**Fix:** use a guest kernel older than 5.15 with `CONFIG_NVM` and pblk, or
drive the device from user space with SPDK. Open-Channel 2.0 in current FEMU
also accepts plain NVMe Read and Write, which SPDK uses. nvme-cli 2.x
dropped `nvme lnvm`; build nvme-cli 1.x in the guest for it. See the
[OCSSD guide](modes/ocssd.md).

Related issues: #4, #48, #139.

## How do I get debug output?

FEMU prints `[FEMU] Log:` and `[FEMU] Err:` lines on QEMU's console.
`run-blackbox.sh`, `run-zns.sh` and `run-csd.sh` save the console in
`build-femu/log`. There is no `FEMU_DEBUG` environment variable, and FEMU
defines no QEMU trace events.

**Fix:** compile the debug messages in with
`--extra-cflags="-DFEMU_DEBUG_NVME -DFEMU_DEBUG_FTL"`, or use the run-time
variables such as `FEMU_FDP_DEBUG`. See [debugging](guides/debugging.md).

Related issues: #18, #105; discussion #133.

## How do I tune for performance?

Give every FEMU thread a core. The `femu-poller` threads and the
`FEMU-FTL-Thread` spin while the guest has the controller enabled, so each
needs a host core of its own, on top of the vCPUs. One poller serves every
queue by default; `multipoller_enabled=1` starts one per queue, or one per
`poller_ratio` queues.

**Fix:** follow [performance tuning](guides/performance-tuning.md): pin
the vCPUs, the pollers and the FTL thread, set the CPU frequency policy to
performance, and keep the threads on one NUMA node. `pin.sh` pins only the
vCPUs and the main thread.

Related issues: #69, #77, #101.

## Where is the code for X, and how do I add a command?

All FEMU code is under `hw/femu/`.
[Architecture](concepts/architecture.md) maps each layer to its files:
`femu.c` creates the device, `nvme-admin.c` and `nvme-io.c` handle NVMe
commands, and each mode has its own directory (`bbssd/`, `zns/`, `ocssd/`,
`nossd/`, `kvssd/`, `csd/`, `cxlssd/`).

**To add a command:**

- An I/O command for every mode: add a `case` to `nvme_io_cmd()` in
  `nvme-io.c`. Opcodes it does not handle go to the namespace's mode, for
  example `bb_io_cmd()` in `bbssd/bb.c`.
- An admin command: add it to `nvme_admin_cmd()` in `nvme-admin.c`, or to
  the mode's `admin_cmd` hook, as `bb_admin_cmd()` does for the vendor
  command 0xEF.
- To fail a command, return an NVMe status from the handler, for example
  `return NVME_INVALID_FIELD | NVME_DNR;`. A status found later, in the FTL,
  goes in `req->status`.

Add a qtest for it ([testing](guides/testing.md#adding-a-test)).

Related issues: #72, #114, #162.

## Does data survive a reboot?

A guest reboot keeps the data. Stopping QEMU loses it. FEMU keeps every
namespace in host memory and never writes it to a file; there is no option
to make it persistent. Snapshots and migration are refused
([security and limits](concepts/security-and-limits.md#migration-and-snapshots)).

**Workaround:** keep data you need on the guest's boot disk or copy it out
before you stop QEMU, and recreate the device contents after each start.

Related issues: #52.
