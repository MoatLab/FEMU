# FEMU - Fast, Accurate, and Extensible NVMe SSD Emulator

**Join the FEMU community on [Discord](https://discord.gg/AgPTUJCw7)** for FEMU-related discussions, questions, and ideas. Everyone is welcome!

[![FEMU Version](https://img.shields.io/badge/FEMU-v10.1-brightgreen)](https://github.com/MoatLab/FEMU/releases)
[![Build Status](https://github.com/MoatLab/FEMU/workflows/CI/badge.svg)](https://github.com/MoatLab/FEMU/actions)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![Platform](https://img.shields.io/badge/Platform-x86--64-brightgreen)](https://shields.io/)

```
  ______ ______ __  __ _    _
 |  ____|  ____|  \/  | |  | |
 | |__  | |__  | \  / | |  | |
 |  __| |  __| | |\/| | |  | |
 | |    | |____| |  | | |__| |
 |_|    |______|_|  |_|\____/  -- A fast, accurate, scalable, and extensible NVMe SSD Emulator
```

**FEMU** is a fast, accurate, scalable, and extensible NVMe SSD emulator based on QEMU/KVM. It enables full-system evaluation of storage systems and supports multiple SSD architectures for systems research.

FEMU is supported by the U.S. National Science Foundation through [NSF POSE award #2550145](https://www.nsf.gov/awardsearch/showAward?AWD_ID=2550145),
*Toward a Community-Driven Fast Emulator (FEMU) Ecosystem for Next-Generation Storage Systems
Research and Innovation*.

> **Consolidation in progress (2026).** Features that were previously maintained in separate
> FEMU-based repositories are being ported into this repository; CXL SSD emulation is already
> merged as the `femu-cxl-ssd` device. FEMU is also being made easier to configure, script,
> and drive with AI coding agents. Much of this work is AI-assisted. We believe that careful use of AI-assisted coding,
> with every change built and regression-tested in CI and reviewed by the maintainers, will
> help FEMU reach a more organized code structure and better efficiency. A more thorough
> review is under way in parallel; in the meantime, some existing behavior may change or
> regress. Please report bugs, regressions, and feature requests through
> [GitHub Issues](https://github.com/MoatLab/FEMU/issues) or
> [Discord](https://discord.gg/AgPTUJCw7). Contributions made with your own coding agents are
> welcome too: feel free to submit pull requests.

---

## Table of Contents

The full documentation starts at the [doc map](hw/femu/docs/README.md).

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [System Requirements](#system-requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [BlackBox SSD Mode (BBSSD)](#blackbox-ssd-mode-bbssd)
  - [WhiteBox SSD Mode (OCSSD)](#whitebox-ssd-mode-ocssd)
  - [Zoned Namespace SSD Mode (ZNSSD)](#zoned-namespace-ssd-mode-znssd)
  - [NoSSD Mode](#nossd-mode)
  - [Computational Storage Mode (CSD)](#computational-storage-mode-csd)
  - [Key-Value SSD Mode (KVSSD)](#key-value-ssd-mode-kvssd)
- [Configuration](#configuration)
  - [Config Files](#config-files)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Research & Citation](#research--citation)
- [Contributing](#contributing)
- [Support](#support)
- [License](#license)
- [Acknowledgments](#acknowledgments)

---

## Overview

FEMU bridges the gap between SSD hardware platforms and SSD simulators by providing:

- **Full system stack support** (Applications + OS + NVMe interface)
- **Multiple SSD architectures** with configurable parameters
- **High performance** suitable for systems research and development
- **Extensible design** for exploring new SSD algorithms, architectures, interfaces, and software stacks.

### Key Benefits

- ✅ **Fast**: Sub-10μs latency emulation for performance-critical research
- ✅ **Accurate**: Realistic SSD behavior modeling based on real hardware characteristics
- ✅ **Scalable**: Support for large-capacity SSDs and multi-device configurations
- ✅ **Extensible**: Modular architecture for easy customization and new feature development

---

## Features

<!-- modes-table:start -->
<!-- Generated from hw/femu/docs/modes.py by hw/femu/scripts/gen-mode-table.py; edit modes.py, not this table. -->

| Mode or feature | Use it for | Turn it on with | Guest kernel | Guest tools | Host needs | Launcher | Checked |
| --- | --- | --- | --- | --- | --- | --- | --- |
| [NoSSD](#nossd-mode) | fast NVMe device in DRAM, no flash timing | `femu_mode=2` (the default) | any with the NVMe driver | nvme-cli, fio | none beyond the common ones | `run-nossd.sh` | CI: realize, Identify, write and read back |
| [BlackBox SSD (BBSSD)](#blackbox-ssd-mode-bbssd) | a commercial SSD: device FTL, GC, NAND timing | `femu_mode=1` | any with the NVMe driver | nvme-cli, fio | about 17 GiB free RAM for the launcher's 12 GiB device | `run-blackbox.sh` | CI: realize, Identify, write and read back; guest: [quick start, run end to end](hw/femu/docs/getting-started/quick-start.md) |
| [Zoned Namespace (ZNS)](#zoned-namespace-ssd-mode-znssd) | zoned storage research | `femu_mode=3` | 5.9 or newer with `CONFIG_BLK_DEV_ZONED=y`; 4 KiB guest pages | nvme-cli 1.12 or newer for `nvme zns` | none beyond the common ones | `run-zns.sh` | CI: realize, Identify, write and read back |
| [Open-Channel SSD 1.2](#whitebox-ssd-mode-ocssd) | host-managed FTL research | `femu_mode=0,lver=1` | 4.16 to 5.14 (LightNVM was removed in 5.15) | LightNVM tools, or SPDK on newer kernels | none beyond the common ones | `run-whitebox.sh` | CI: realize, Identify |
| [Open-Channel SSD 2.0](#whitebox-ssd-mode-ocssd) | host-managed FTL research | `femu_mode=0` (`lver=2` is the default) | 4.17 to 5.14 (LightNVM was removed in 5.15) | LightNVM tools, or SPDK on newer kernels | none beyond the common ones | `run-whitebox.sh` | CI: realize, Identify |
| [Key-value SSD (KV)](#key-value-ssd-mode-kvssd) | key-value store research | `femu_mode=5` | 5.13 or newer; no block device, the namespace is `/dev/ngXnY` | nvme-cli `io-passthru`, `hw/femu/scripts/kv-probe.c` | none beyond the common ones | none | CI: realize, Identify, store and retrieve |
| [Computational storage (CSD)](#computational-storage-mode-csd) | running programs next to the data | `femu_mode=4,fdm_size=<MiB>` | any with the NVMe driver | `hw/femu/tests/csd` tools | `csd_program_dir` for shared-library programs; `--enable-csd-ubpf` build for eBPF programs | `run-csd.sh` | CI: realize, Identify, write and read back |
| [Flexible Data Placement (FDP)](#features) | placement hints on a BBSSD | `femu-subsys,fdp=on,fdp.nruh=<n>` and `femu,femu_mode=1,subsys=<id>` | any with the NVMe driver; placement hints need passthrough or io_uring commands | nvme-cli with `nvme fdp` | none beyond the common ones | `run-blackbox-fdp.sh` | CI: realize, Identify, write and read back |
| [Multiple namespaces](#multiple-namespaces) | several namespaces, each with its own mode | `namespaces=<n>`, optionally `namespace_sizes` and `namespace_modes` | any with the NVMe driver (ZNS namespaces need what ZNS needs) | nvme-cli | none beyond the common ones | none | CI: realize, Identify, write and read back |
| [Namespace management](hw/femu/docs/CONFIGURATION-CHANGES.md) | create, delete and attach namespaces at run time | `ns_mgmt=on` on a NoSSD or BBSSD controller; `femu-subsys,ns_mgmt=on` to share namespaces | any with the NVMe driver | nvme-cli `create-ns`, `attach-ns` | none beyond the common ones | none | CI: realize, Identify, write and read back |
| [Metadata and protection information](hw/femu/docs/reference/properties.md) | per-block metadata, PI types 1 to 3 | `meta=<bytes>,mc=<mask>`, plus `pi=on` with `meta` of 8 or more | `CONFIG_BLK_DEV_INTEGRITY=y` to use metadata formats through the block layer | nvme-cli `format` | none beyond the common ones | none | CI: realize, Identify, write and read back |
| [CXL SSD, `der=off`](hw/femu/docs/cxlssd.md) | CXL memory backed by flash, all accesses trapped | `femu-cxl-ssd` below `pxb-cxl` and `cxl-rp` on `-machine q35,cxl=on` | `CONFIG_CXL_BUS`, `CXL_PCI`, `CXL_ACPI`, `CXL_MEM`, `CXL_PORT`, `CXL_REGION`, `DEV_DAX`, `DEV_DAX_KMEM` | `cxl-cli`, `daxctl`, `ndctl` | a build with `CONFIG_CXL_MEM_DEVICE` | `run-cxlssd.sh` | CI: realize |
| [CXL SSD, `der=memslot`](hw/femu/docs/cxlssd.md) | cached pages mapped into the guest as KVM memory slots | `der=memslot` on `femu-cxl-ssd` | as for `der=off` | as for `der=off` | KVM (TCG is refused) | `run-cxlssd.sh` | CI: realize |
| [CXL SSD, `der=cylon`](hw/femu/docs/cxlssd.md) | cached pages mapped by a Cylon host kernel | `der=cylon,cylon-kernel-ack=on` on `femu-cxl-ssd` | as for `der=off` | as for `der=off` | Cylon host kernel; KVM with EPT A/D bits and the TDP MMU; 4 KiB host pages; a shared, preallocated hugetlb backend. Without them the device warns and uses MMIO | `run-cxlssd.sh` | CI: realize |
| [CXL caching API (CCA)](hw/femu/tools/cca/README.md) | guest pins, unpins and invalidates cached pages | `cca=on` on `femu-cxl-ssd` | as for `der=off`; a devdax region | `hw/femu/tools/cca` (`ccactl`, `cca-test`), run as root | as for `der=off` | `run-cxlssd.sh` | CI: realize |
| [NVMe front end on a CXL SSD](hw/femu/docs/cxlssd.md) | the same media as CXL memory and as an NVMe namespace | `femu,bus=pcie.0,femu_mode=1,cxl_ssd=<id>` after the `femu-cxl-ssd` | as for `der=off`, plus the NVMe driver | as for `der=off`, plus nvme-cli | as for `der=off` | none | CI: realize, Identify, write and read back |
<!-- modes-table:end -->

When `femu_mode` is not set, the device runs in NoSSD mode (2).

Flexible Data Placement is not a separate mode: it is BlackBox with `fdp=on`
set on the subsystem. See `run-blackbox-fdp.sh`.

The CXL SSD is not an NVMe mode either: `femu-cxl-ssd` is a CXL Type-3 memory
device whose DRAM page cache sits in front of the BlackBox FTL. See
`hw/femu/docs/cxlssd.md`.

OpenChannel needs a host that speaks it. LightNVM was removed from Linux in
5.15, so this mode has no in-tree driver on a current kernel.

---

## Architecture

```
         +----------------------------------------------------------+
         |                      VM / Guest OS                       |
         |      NVMe block device             CXL memory            |
         |      (nvme-cli, fio, ...)          (devdax / kmem)       |
         +------------^^-----------------------------^^-------------+
                      ||                             ||
                  PCIe / NVMe                  CXL.mem (Type 3)
                      ||                             ||
  +-------------------vv--------------------+ +------vv-------------+
  |        FEMU NVMe SSD controller         | |    femu-cxl-ssd     |
  | +------------+ +----------+ +---------+ | |                     |
  | |  BlackBox  | | WhiteBox | |   ZNS   | | |  DRAM page cache    |
  | |  (BBSSD)   | | (OCSSD)  | | (ZNSSD) | | |  (FIFO/LIFO/CLOCK/  |
  | |  + FDP     | |          | |         | | |   S3-FIFO)          |
  | +------------+ +----------+ +---------+ | |  + direct mapping   |
  | +------------+ +----------+ +---------+ | |    into the guest   |
  | |   NoSSD    | |   CSD    | |  KVSSD  | | |                     |
  | | (ultra-low | | (compute | |  (key-  | | |  misses and dirty   |
  | |  latency)  | |  storage)| |  value) | | |  evictions go to    |
  | +------------+ +----------+ +---------+ | |  the BlackBox FTL   |
  +-----------------------------------------+ +---------------------+
  |     FTL and NAND flash timing model (all modes except NoSSD)    |
  +-----------------------------------------------------------------+
  |                             QEMU/KVM                            |
  +-----------------------------------------------------------------+
  |                            Host Linux                           |
  +-----------------------------------------------------------------+
```

### Core Components

- **NVMe Controller**: NVMe 1.4 controller, reported as version 1.4.0
- **SSD Modes**: Pluggable backends for different SSD architectures
- **Timing Model**: Configurable latency simulation for realistic performance
- **Memory Backend**: DRAM-based storage emulation

---

## System Requirements

An x86_64 Linux host with KVM, Python >= 3.9 and GLib >= 2.66 (Ubuntu 22.04 or
24.04; CI builds on both). The emulated SSD lives in host DRAM, so the default
BBSSD launcher needs about 17 GiB of free RAM. Full details, including the
guest kernel each mode needs:
[requirements.md](hw/femu/docs/getting-started/requirements.md).

### Host Environment Compatibility

See [Operating system and CPU](hw/femu/docs/getting-started/requirements.md#operating-system-and-cpu).

### Guest Environment Compatibility

See [Kernel per mode](hw/femu/docs/getting-started/requirements.md#kernel-per-mode).
OCSSD needs a guest kernel older than 5.15 and ZNS needs 5.9 or newer.

---

## Installation

```bash
git clone https://github.com/MoatLab/FEMU.git
cd FEMU && mkdir build-femu && cd build-femu
cp ../femu-scripts/femu-copy-scripts.sh . && ./femu-copy-scripts.sh
sudo ./pkgdep.sh      # Debian/Ubuntu dependencies
./femu-compile.sh     # builds build-femu/qemu-system-x86_64
```

Dependencies, optional features (CSD uBPF, CXL SSD), debug builds and common
build errors: [build.md](hw/femu/docs/getting-started/build.md).

### Build FEMU

See [build.md](hw/femu/docs/getting-started/build.md).

---

## Quick Start

From `build-femu/`:

```bash
./make-guest-image.sh               # Ubuntu 24.04 guest in ~/images/u20s.qcow2
./run-blackbox.sh                   # terminal 1: boot the guest with a BBSSD
./run-guest-ssh.sh sudo nvme list   # terminal 2: the emulated SSD is /dev/nvme0n1
./run-guest-ssh.sh sudo poweroff
```

The full walk-through, with fio and the write amplification factor, is in
[quick-start.md](hw/femu/docs/getting-started/quick-start.md). Other ways to
get a guest image are in
[guest-image.md](hw/femu/docs/getting-started/guest-image.md).

The emulated SSD lives in memory: nothing written to it survives shutting the
VM down.

### 1. VM Image Setup

See [guest-image.md](hw/femu/docs/getting-started/guest-image.md).

### 3. Run Your First FEMU Instance

See [quick-start.md](hw/femu/docs/getting-started/quick-start.md#3-boot-the-guest-with-a-bbssd-terminal-1).

### 4. Access the VM

See [Log in with SSH](hw/femu/docs/getting-started/guest-image.md#log-in-with-ssh).

---

## Usage

FEMU supports multiple SSD emulation modes, each optimized for different research scenarios.

### BlackBox SSD Mode (BBSSD)

Emulates commercial SSDs with device-managed FTL.

```bash
./run-blackbox.sh
```

**Key Parameters:**
```bash
# SSD Layout Configuration
secsz=512              # Sector size (bytes)
secs_per_pg=8          # Sectors per page
pgs_per_blk=256        # Pages per block
blks_per_pl=256        # Blocks per plane
luns_per_ch=8          # LUNs per channel
nchs=8                 # Number of channels

# Performance Configuration
pg_rd_lat=40000        # Page read latency (ns)
pg_wr_lat=200000       # Page write latency (ns)
blk_er_lat=2000000     # Block erase latency (ns)
cmd_addr_lat=0         # Channel bus phases (ns): command/address cycle,
pg_xfer_lat=0          #   page data transfer, status read. Any non-zero
status_lat=0           #   value adds a shared per-channel bus to the model

# Garbage Collection
gc_thres_pcent=75      # GC trigger threshold (percent of lines in use)
gc_policy=greedy       # Victim selection: greedy (default), random,
                       #   cost-benefit, fifo, d-choice

# L2P Mapping (optional; default is a full DRAM page-mapping table)
mapping=page           # page (default), dftl, hybrid, or fast
mapping_cache_mb=0     # DFTL translation-cache size in MiB (used only for dftl)

# Write amplification / debugging
debug_ftl=false        # print page-state violations on the GC path to stderr

# Fault insertion (0 = off)
err_read_unc_ppm=0     # uncorrectable reads per million reads
err_write_fail_ppm=0   # write faults per million writes

# Host link and controller CPU (0 = off)
pcie_bandwidth_mbps=0  # host link bandwidth, MB/s
pcie_prop_delay_ns=0   # host link propagation delay, ns
fw_cpu_ns=0            # controller CPU time charged per command, ns

# DRAM Read Cache (optional; default off)
read_cache_mb=0        # Read-cache size in MiB (0 disables it)
cache_evict=clock      # Eviction policy: clock (default), random, lru, arc

# Write buffer (optional; default off)
buffer_size=0          # Device write-buffer size in flash pages (0 disables it)
buffer_thres_pcent=90  # Occupancy at which the buffer starts flushing

# NAND media (optional)
nand_cell_type=0       # 0 flat timing (pg_rd_lat etc.); 1 SLC, 2 MLC, 3 TLC, 4 QLC
                       #   use built-in per-cell-type latency tables
op_pcent=0             # Over-provisioning withheld from the host, percent
pls_per_lun=1          # Planes per LUN; above one, a line erases across planes
nand_bad_blocks=0      # Blocks marked bad at init, reflected in available spare
trim_lat_ns=0          # Latency charged per TRIM range
pe_suspend=0           # Reads preempt a program or erase in flight on their LUN
tsusp_ns=0             #   (program/erase suspend); overhead each such read pays, ns

# Wear, disturb and retention (optional; all default off)
read_reclaim_limit=0   # Reads a block may take before its line is refreshed
retention_limit_sec=0  # Seconds data may sit programmed before a read refreshes it
ecc_step_ns=0          # Extra read latency per correction tier as a block ages
ecc_retention_sec=0    # Seconds of data age per correction tier

# Placement (optional)
hot_cold_sep=false     # Keep frequently and rarely rewritten data on separate lines
```

The wear and retention knobs are all off by default and are read-triggered: a
line is queued for refresh when something reads it, so a region nothing ever
reads is never refreshed. That is a deliberate limitation, not an oversight --
modelling a background media scan would need a timer the emulator does not run.

**Mapping schemes.** `mapping=` selects how the FTL translates logical to
physical pages:

| Scheme | Model |
|--------|-------|
| `page` | Full DRAM page-level table (default) |
| `dftl` | Page-level, with the translation table charged as a demand cache |
| `hybrid` | BAST log-block mapping (Kim 2002): one log block per data block, merged when the pool runs out |
| `fast` | FAST log-block mapping (Lee et al. 2007): a sequential log block plus a shared fully-associative random-write pool |

The log-block schemes are workload-shaped: sequential overwrites merge cheaply,
random overwrites force full merges. Their cost is charged to the NAND timeline
and counted as relocated pages, so it appears in latency and in write
amplification.

**Fault insertion.** `err_read_unc_ppm` and `err_write_fail_ppm` return a media
error on a fixed fraction of reads or writes. The device counts commands rather
than drawing at random, so a run reproduces exactly.

**Host link and controller CPU.** `pcie_bandwidth_mbps` and `pcie_prop_delay_ns`
charge each transfer against a link of finite bandwidth, serialized per
direction; `fw_cpu_ns` charges a fixed cost per command against a single
firmware core, which caps command rate the way a real controller's CPU does.
Both sit after the media latency, so they compose with it, and both are off by
default. They apply to the modes that model timing; NoSSD completes inline and
is unaffected.

**Asynchronous events.** The controller reports events to a host that has
Async Event Requests outstanding, rather than leaving them pending forever. The
one it raises today is the SMART temperature warning: `temperature` sets the
reported value in Kelvin (default 0x143, 50 C), and a host that enables the
warning through Async Event Configuration and then sets a temperature threshold
at or below it gets an event naming the health log.

An event of a given type is reported once and then withheld until the host
reads the log page it pointed at with Retain Asynchronous Event clear, so the
same condition is not reported repeatedly before the host has looked. A
controller reset drops anything outstanding.

```bash
gcc -O2 -o aer-probe femu-scripts/aer-probe.c   # inside the guest
sudo ./aer-probe /dev/nvme0
```

**Host I/O counters.** The SMART log reports the standard host totals -- data
units read and written, and read and write command counts -- so a workload's
volume can be read back the way it would be from a real drive. They are counted
where every I/O command passes before reaching whichever mode owns the
namespace, so they are the same in every mode, including the ones with no FTL.
Data units follow the spec's unit of a thousand 512 byte units, rounded up.

```bash
sudo nvme smart-log /dev/nvme0        # Data Units Written, host_write_commands, ...
```

**DRAM write buffer.** `buffer_size` holds that many pages in DRAM instead of
programming them, the way a real drive absorbs host writes; `buffer_thres_pcent`
is the fill level at which a write starts evicting the least recently written
pages, and it is those evictions that reach the media and are charged for. A
read of a page still held is served without touching the media. Deallocating a
held page drops it rather than writing it out later.

It defaults to 0, which programs every write directly and leaves timing as it
was. Note that with a buffer configured a write that is absorbed costs nothing
and the cost appears later on whichever write evicts it, so per-request latency
is redistributed rather than reduced.

**Write amplification and wear.** The device reports these in its vendor log
page C0h (512 bytes, little-endian), not in the SMART log:

| byte | width | meaning |
|---|---|---|
| 0 | 4 | write amplification, scaled by 1000 |
| 8 | 8 | pages the host wrote (the denominator) |
| 16 | 8 | pages garbage collection relocated |
| 24 | 8 | user pages programmed into NAND |
| 32 | 8 | reads taken by the most-read block since its erase |
| 40 | 8 | lines rewritten because of read stress |
| 48 | 8 | lines rewritten because of retention age |

```bash
sudo nvme get-log /dev/nvme0 --log-id=0xc0 --log-len=512 -b | od -An -tu4 -j0 -N4   # WAF x1000
sudo nvme get-log /dev/nvme0 --log-id=0xc0 --log-len=512 -b | od -An -tu8 -j8 -N8   # host pages
```

Amplification is `(programmed + relocated) / host`, so a write buffer that
absorbs repeated writes to the same page shows up as a factor below 1. Bytes 8
and 24 are equal when no buffer is configured. The read count at byte 32 is the
stress a real device watches to decide when data must be rewritten. The full
layout, including the write buffer and `mapping=hybrid` merge counters, is in
[`hw/femu/docs/reference/log-pages-and-counters.md`](hw/femu/docs/reference/log-pages-and-counters.md#vendor-log-page-c0h).

**Read stress.** Reading a page disturbs the others in its block, so a block read
many times without being rewritten drifts towards errors. Set
`read_reclaim_limit` to the number of reads a block may take before its line is
refreshed:

```
-device femu,...,femu_mode=1,read_reclaim_limit=100000
```

The line is chosen on the read but rewritten on a following write, where
relocation already costs something, rather than stalling a read behind a whole
line of it; one line is refreshed per write at most. The cost shows up as write
amplification, which is how a read-heavy workload comes to have a write cost at
all. Measured on a 512 MiB region read six times over with a low limit: 5 lines
refreshed, 77824 pages relocated, amplification 1.000 -> 1.542. Off by default.

The rate is bounded by how often the host writes, not by how hard it reads: one
line is queued at a time and at most one is refreshed per write. That keeps an
aggressive setting from running away -- dropping the limit from 500 to 10 moves
amplification only 1.542 to 1.628 -- but it also means a workload that never
writes never refreshes anything, where a real device would do this in the
background. Model reads-only ageing some other way.

These are summed across the bbssd, CSD and KV namespaces of the controller (the
most-read block count is the maximum), and are populated in FDP mode as well as
plain block mode.

**Use Cases:**
- Commercial SSD simulation research
- FTL algorithm development and testing
- Storage system performance evaluation

### Multiple Namespaces

BBSSD, NoSSD, ZNS and KV can expose more than one namespace, and
`namespace_modes` can give each namespace its own mode. The namespaces share the
device's capacity, each getting its own slice, so they are independent block
devices (`/dev/nvme0n1`, `/dev/nvme0n2`, ...) that cannot overwrite each other.

```bash
# two namespaces, splitting the capacity evenly
-device femu,devsz_mb=4096,namespaces=2,femu_mode=1,...

# two namespaces with explicit sizes (3 GiB and 1 GiB)
-device femu,devsz_mb=4096,namespaces=2,namespace_sizes=3G,,1G,femu_mode=1,...
```

**Key Parameters:**
```bash
namespaces=1           # Number of namespaces (default 1)
namespace_sizes=       # Optional per-namespace sizes, e.g. "8G,,4G".
                       #   Unset splits the capacity evenly. One entry per
                       #   namespace, and the sum must fit the device.
```

Note the doubled comma in `namespace_sizes`: QEMU treats a comma as an option
separator, so a comma inside a value has to be escaped by doubling it.

Open-Channel (OCSSD) keeps its geometry on the controller and supports a single
namespace; so does FDP, whose reclaim groups are shared device-wide. A
controller can also hold at most one CSD namespace, although its other
namespaces may use other modes. FEMU refuses to start with more than that.

### WhiteBox SSD Mode (OCSSD)

Emulates OpenChannel SSDs with host-managed FTL.

```bash
./run-whitebox.sh
```

**Supported Specifications:**
- OpenChannel SSD 1.2
- OpenChannel SSD 2.0 (default)

**Configuration:**
```bash
# Set OCSSD version in run-whitebox.sh
OCVER=2    # For OCSSD 2.0 (default)
OCVER=1    # For OCSSD 1.2
```

**Use Cases:**
- Host-side FTL research (LightNVM, SPDK)
- Storage disaggregation studies
- Custom wear leveling algorithms

### Zoned Namespace SSD Mode (ZNSSD)

Emulates NVMe ZNS SSDs with zone-based interface.

```bash
./run-zns.sh
```

**Zone Configuration:**
- Configurable zone size and count
- Support for zone management commands
- Zone state tracking and validation

**Key Parameters:**
```bash
zns_max_active=0       # Max active zones (0 = unlimited)
zns_max_open=0         # Max open zones (0 = unlimited)
zns_num_wc=0           # Write caches, one per zone being written
                       #   (0 = zns_max_open, or 3 when that is unlimited)
zns_zd_ext_size=0      # Zone-descriptor extension bytes (0 = none)
zns_num_conv_zones=0   # Leading conventional zones (0 = all sequential)
zns_zone_cap=0         # Usable bytes per zone (0 = the whole zone)
zns_chnls_per_zone=0   # Channels a zone spans (0 = all of them)
zns_pg_rd_lat=0        # NAND read / program / erase time (ns) for the
zns_pg_wr_lat=0        #   configured cell type; 0 keeps the built-in value
zns_blk_er_lat=0
zns_cmd_addr_lat=0     # Channel bus phases (ns): command/address cycle,
zns_pg_xfer_lat=0      #   page data transfer, status read. Any non-zero
zns_status_lat=0       #   value adds a shared per-channel bus to the model
zns_pe_suspend=0       # Reads preempt a program or erase in flight on their plane
zns_tsusp_ns=0         #   (program/erase suspend); overhead each such read pays, ns
zns_zrwa_size=0        # ZRWA window in LBAs (0 = ZRWA disabled)
zns_zrwafg_size=0      # ZRWA flush granularity in LBAs
zns_zrwa_num=0         # Zones that may hold a ZRWA at once
zns_cross_zone_read=false # Allow reads to span zone boundaries (OZCS bit 0)
zns_zasl_bs=131072     # Max Zone Append transfer in bytes (0 = follow MDTS)
```

**Zone Random Write Area (ZRWA).** Setting all three of `zns_zrwa_size`,
`zns_zrwafg_size` and `zns_zrwa_num` advertises ZRWA support. A zone opened with
the ZRWA-allocate flag (`nvme zns open-zone --zrwaa`) then accepts writes
anywhere in a sliding window instead of strictly at the write pointer, which
only advances — in whole flush-granularity units — when a write crosses the end
of the window, or when the host flushes explicitly
(`nvme zns zrwa-flush-zone`). Finishing or resetting the zone returns the ZRWA
resource. With all three left at 0 the namespace advertises no ZRWA and behaves
exactly as before.

Note that Linux issues writes to a zoned block device at the write pointer, so
the random-write freedom is visible through the NVMe passthrough commands rather
than through ordinary buffered or direct writes to the block device.

**Zone Append size limit.** ZASL caps how much one Zone Append may transfer,
and the host reads it from Identify to size its appends. `zns_zasl_bs` sets it
in bytes, defaulting to the 128 KiB that used to be fixed; 0 makes it follow
MDTS instead. Because the limit is reported as a power-of-two count of 4 KiB
controller pages, the value must be such a multiple -- anything else is rejected
at startup rather than quietly rounded down to a smaller limit than asked for.
An append larger than the limit is refused with Invalid Field in Command.

**Reads across zone boundaries.** A zoned namespace normally rejects a read that
runs past the end of its zone with a zone-boundary error, since consecutive
zones need not hold related data. `zns_cross_zone_read=true` allows such a read
and advertises it through OZCS bit 0, which is how the host knows it may issue
one; the controller still checks that every zone the read spans is in a readable
state. It defaults to false, which is the stricter and more common behavior.

**Changed Zone List log page.** Log page BFh reports zone descriptor changes the
host did not cause. Read it with `nvme get-log <dev> --log-id=0xbf
--log-len=4096 --namespace-id=N`; the page carries an 8-byte count followed by
up to 511 zone start LBAs. The list is per namespace, so the command needs a
specific namespace identifier rather than the broadcast value nvme-cli sends by
default.

The specification excludes most changes from this list: anything following a
Zone Management Send command, a write that opens or fills a zone, and the
controller closing a zone to free a resource. What is left is a change the host
did not ask for, and reading the log without `--rae` clears both the list and
the event behind it.

`err_write_fail_ppm` produces such a change on a zoned namespace: one write in
every million/ppm fails and takes its zone read only, the way a controller does
when it can no longer program the zone. The failing write is reported as a write
fault, later writes to that zone are refused as read only, the zone is added to
this log, and a Zone Descriptor Changed notice is raised for a host with an
Async Event Request outstanding. The counter makes a run repeat rather than
drawing at random. With the knob unset nothing does this, and the list stays
empty.

```bash
gcc -O2 -o zone-aen-probe femu-scripts/zone-aen-probe.c   # inside the guest
sudo ./zone-aen-probe /dev/nvme0 /dev/nvme0n1
```

**Zone width.** By default a zone spans every channel, so it is as wide as the
device and there are relatively few of them. `zns_chnls_per_zone=N` narrows a
zone to N channels, which divides the zone size and multiplies the zone count by
`zns_num_ch / N` while leaving the device capacity alone — useful for studying
how zone size and zone-level parallelism affect a zoned workload. N must divide
`zns_num_ch`; anything else warns and falls back to full width.

With `zns_num_ch=8`, a 4 GiB device gives:

| `zns_chnls_per_zone` | zones | zone size |
|---|---|---|
| 0 (default) or 8 | 16 | 256 MiB |
| 4 | 32 | 128 MiB |
| 2 | 64 | 64 MiB |

**Conventional zones.** `zns_num_conv_zones=N` makes the first N zones
conventional: they take writes anywhere inside the zone, keep no write pointer
(reported as all ones), and reject zone management and zone append. The
remaining zones stay sequential-write-required.

This is off by default, and it should stay off for a Linux guest. The NVMe ZNS
command set only defines the sequential-write-required zone type, so Linux's
NVMe driver rejects a conventional zone and fails the *whole* zone report with
`EINVAL` — the namespace then reports `nr_zones=0` and is unusable for zoned
btrfs, f2fs, zonefs or dm-zoned. Enable it only for host software that accepts
the conventional zone type, or to exercise FEMU's own zone handling.

To combine randomly-writable and zoned capacity on a Linux guest, give the
controller one namespace of each mode instead (see Multiple Namespaces):

```bash
-device femu,devsz_mb=8192,namespaces=2,namespace_modes=znssd,,bbssd,...
```

**Use Cases:**
- ZNS filesystem development (F2FS, Btrfs)
- Zone-aware applications
- Log-structured storage research

### Key-Value SSD Mode (KVSSD)

Emulates a key-value SSD: the namespace stores values against keys rather than
blocks against addresses.

```bash
-device femu,devsz_mb=4096,namespaces=1,femu_mode=5,...
```

Keys of up to 16 bytes travel inline in the command: the low eight bytes in
CDW2 and CDW3, the high eight in CDW14 and CDW15. The key length in bytes goes
in CDW11 bits 7:0, and CDW10 carries the value size in bytes for a store, or the
host buffer size for a retrieve; the value itself uses the normal data pointer.
The commands are:

| Command | Opcode |
|---------|--------|
| Store | 0x01 |
| Retrieve | 0x02 |
| List | 0x06 |
| Delete | 0x10 |
| Exist | 0x14 |

Linux has no key-value command set, so the namespace appears without a block
device and is driven by passthrough:

```bash
# store a 64 byte value under the 4 byte key "BBBB"
nvme io-passthru /dev/nvme0 -O 0x01 -n 1 --cdw10=64 --cdw11=4 \
    --cdw2=0x42424242 -l 64 -w -i value.bin

# read it back
nvme io-passthru /dev/nvme0 -O 0x02 -n 1 --cdw10=64 --cdw11=4 \
    --cdw2=0x42424242 -l 64 -r -b
```

Note that the namespace identifier has to be given explicitly: nvme-cli sends
the broadcast value by default, which a per-namespace command rejects. Because
the namespace has no block device, the command goes to the controller node.

Retrieving or checking a key that is not stored returns 0x87, key does not
exist, with Do Not Retry set alongside it.

`femu-scripts/kv-probe.c` drives the whole lifecycle -- store, exist, retrieve
in full and short form, the conditional stores, delete, and the miss afterwards
-- and checks both status and data:

```bash
gcc -O2 -o kv-probe femu-scripts/kv-probe.c   # inside the guest
sudo ./kv-probe /dev/nvme0
```

**Use Cases:**
- Key-value store research without key-value hardware
- Host software that targets a key-value device

### NoSSD Mode

Ultra-fast NVMe emulation without storage logic.

```bash
./run-nossd.sh
```

**Characteristics:**
- Sub-10 microsecond latency
- No FTL or wear simulation
- Maximum I/O performance

**Use Cases:**
- Storage-class memory (SCM) emulation
- Performance upper-bound testing
- Fast storage prototyping

**High-IOPS path.** NoSSD mode carries a set of optimizations (shadow-doorbell
MMIO suppression, per-poller counter sharding, M:N poller↔queue decoupling via
`poller_ratio`, inline completion, a single-PRP fast path, and NUMA placement of
the emulated backend). With SPDK driven inside the guest and strict socket
isolation on a 2-socket host, a single VM sustains tens of millions of 512B
random-read IOPS. See `hw/femu/docs/HIOPS.md` and the reproduction harness in
`hw/femu/scripts/hiops/` for the configuration and measured results.

### Computational Storage Mode (CSD)

Experimental computational storage support derived from
[CEMU](https://github.com/cs-qyzhang/CEMU). CSD is selected with `femu_mode=4`
and keeps CSD-specific code under `hw/femu/csd/`. We thank the CEMU authors,
Qiuyang Zhang, Jiapin Wang, You Zhou, Peng Xu, Kai Lu, Jiguang Wan, Fei Wu and
Tao Lu, and Emilio ([@Emilio597](https://github.com/Emilio597)), who ported it to
FEMU in [#188](https://github.com/MoatLab/FEMU/pull/188). If you use the CSD mode,
please also cite:

```bibtex
@inproceedings{Zhang+26-CEMU,
  author    = {Qiuyang Zhang and Jiapin Wang and You Zhou and Peng Xu and
               Kai Lu and Jiguang Wan and Fei Wu and Tao Lu},
  title     = {{CEMU: Enabling Full-System Emulation of Computational Storage
               Beyond Hardware Limits}},
  booktitle = {Proceedings of the 31st ACM International Conference on
               Architectural Support for Programming Languages and Operating
               Systems (ASPLOS '26), Volume 2},
  pages     = {323--341},
  year      = {2026},
  doi       = {10.1145/3779212.3790137},
}
```

```bash
./run-csd.sh
```

**Key Parameters:**
```bash
fdm_size=64            # Functional data memory size (MB), required
csd_program_dir=       # Host directory programs load from; the guest names a
                       #   file in it. Unset, only phantom programs load. Not
                       #   set by run-csd.sh; see hw/femu/tests/csd/README.md
nr_cu=4                # Compute units; programs queue for the first free one
csf_runtime_scale=3    # A program that names no runtime is charged its host
                       #   run time times this (a load's own scale, in tenths,
                       #   takes precedence)
nr_thread=4            # Accepted for CEMU config compatibility only: the
time_slice=200000      #   threaded scheduler they configure is not part of
context_switch_time=200 #  this port, so they have no effect
```

**Current Scope:**
- Normal NVMe read/write through the device-side BBSSD FTL path in CSD mode
- Vendor commands for AFDM allocation, read/write, NVM-to-AFDM copy
- Phantom and shared-library CSF load/execute path using the original CEMU
  lifecycle, `path\0symbol\0` program descriptor format, and program execute
  fields (`pind`, `numr`, `dlen`, `cparam1`, `cparam2`, `group`, `runtime`)
- CEMU-style admin commands for CSF load/unload and activate/deactivate
- Optional uBPF CSF support via `./femu-compile.sh --enable-csd-ubpf`
  or `./femu-compile.sh --enable-csd-ubpf=/path/to/ubpf-cemu`
- Group/QoS command metadata
- Guest-side passthrough tests in `hw/femu/tests/csd/`

The initial CSD path does not require a CEMU-specific Linux kernel, FDMFS, or a
fixed VM image. Advanced CEMU features such as VM freezing, virtual clock
changes, and FDMFS are intentionally kept out of the default path while the base
mode is upstreamed.

---

## Configuration

### Persistent Event log retention

Add `pel_file=/absolute/path/events.pel` to a FEMU device to retain its
Persistent Event log across QEMU runs. An unset property keeps the in-memory
behavior. A missing file starts an empty history; a corrupt or incompatible
file refuses device creation without changing that file.

The file stores encoded events, generation, and power cycles. Each realize adds
one power cycle and a new power-on event and SMART snapshot. PEL PWRCC,
Controller Power Cycle, and SMART Power Cycles use the retained count. Reporting
contexts, other SMART counters, namespace contents, and power-on hours are not
retained.

Writes run on the main loop after events and generation changes, with additional
saves at controller reset, device removal, and normal process exit. Updates use
a temporary file in the same directory, file fsync, rename, and directory fsync.
At normal process exit, event collection closes under the log mutex before the
final snapshot. Events appended before that cutoff are saved; later appends
are dropped by design, including completions of outstanding I/O. Exit saving
does not wait for pollers, whose MMIO DMA may need the main thread's lock.
An abrupt process termination can lose changes still queued for the main loop.
Runtime write errors are reported to stderr; subsequent events and lifecycle
saves retry. Use one file per device and only one QEMU writer per file; the file
is not a shared storage or migration mechanism.

Device properties are listed in
[`hw/femu/docs/reference/properties.md`](hw/femu/docs/reference/properties.md),
with their type, default and meaning, and the QOM counters in
[`hw/femu/docs/reference/runtime-properties.md`](hw/femu/docs/reference/runtime-properties.md).
Both are generated from the binary, and CI fails when they fall out of date.
`./qemu-system-x86_64 -device femu,help` prints the same descriptions.

### Config Files

FEMU has well over a hundred device properties, so writing them out as a single
`-device femu,a=,b=,c=,...` line makes a run script that nobody can read.
`hw/femu/scripts/ssd-config.sh` expands a config file into those arguments
instead:

```bash
./hw/femu/scripts/ssd-config.sh hw/femu/scripts/configs/bbssd.conf
# -device femu,id=nvme0,devsz_mb=4096,namespaces=1,secsz=512,...,femu_mode=1
```

so a run script can say:

```bash
QEMU_ARGS=$(./hw/femu/scripts/ssd-config.sh my-ssd.conf)
qemu-system-x86_64 -enable-kvm -cpu host -smp 8 -m 8G $QEMU_ARGS ...
```

The format is INI-ish. Keys are FEMU device properties and mean exactly what
they mean in `qemu-system-x86_64 -device femu,help`; `#` and `;` start comments,
section headers are labels for the reader, and a key with an empty value is
ignored:

```ini
[device]
mode        = bbssd        # friendly name for femu_mode
devsz_mb    = 4096

[geometry]
secs_per_pg = 8            # 4 KiB pages
luns_per_ch = 8
nchs        = 8

[timing]
pg_rd_lat   = 40000        # ns
pg_wr_lat   = 200000
```

Two things it handles that are easy to get wrong by hand:

- **`[subsys]`** properties are emitted as a separate `-device femu-subsys,...`
  and wired to the SSD. FDP lives on the subsystem object rather than on the
  `femu` device, which is the usual stumbling block when setting it up.
- **List values** such as `namespace_modes = bbssd,znssd,nossd` get their commas
  escaped for QEMU automatically.

Keys are checked against the emulator itself, so a typo is reported rather than
silently dropped, and the checking cannot fall behind the properties
FEMU actually has:

```
$ ./hw/femu/scripts/ssd-config.sh my-ssd.conf
ssd-config: unknown property 'gc_polcy' -- not one FEMU accepts
ssd-config: config rejected; see the warnings above
```

### Checking a Device

`hw/femu/scripts/femu-test.sh` runs inside the guest and checks that the
emulated device still behaves: data survives the FTL, deallocate works, the
counters move, and the mode-specific surface answers. `max_block_reads` is the
reads taken by the most-read block since it was last erased -- the read stress a
real device watches to decide when data must be rewritten. What it runs depends on
what the device reports itself to be, so the same script covers a block, zoned
or key-value namespace. A key-value namespace is not block addressable, so it
has no block node at all and is driven through the controller instead.

```bash
# inside the guest -- this OVERWRITES the device, hence --yes
sudo ./femu-test.sh --yes /dev/nvme0n1
```

```
== data survives the FTL ==
  PASS  random write then verify (crc32c)
== deallocate ==
  PASS  deallocate accepted
  PASS  mapping still sound after deallocate
== counters ==
  waf_x1000=935 host_pages=40960 nand_pages=38335 max_block_reads=807
  PASS  host writes counted

FEMU_TEST pass=7 fail=0 skip=0
```

It refuses to run on a mounted device, and exits non-zero if anything failed, so
it can gate a build. A read that fails counts as a failure just as a bad
checksum does -- both mean the device did not return what was written.

Worked examples live in `hw/femu/scripts/configs/` (block SSD, over-provisioned
for GC studies, ZNS, FDP, heterogeneous namespaces, QLC, write buffer).
`hw/femu/scripts/ssd-config-test.sh` expands every one of them and checks FEMU
accepts the result.

### SSD Layout Parameters

FEMU uses a hierarchical storage organization:

```
Channels → LUNs → Planes → Blocks → Pages → Sectors
```

**Key Relationships:**
```bash
# Total capacity calculation
total_pages = nchs × luns_per_ch × pls_per_lun × blks_per_pl × pgs_per_blk
total_capacity = total_pages × secs_per_pg × secsz

# Example:
# 8 × 8 × 1 × 256 × 256 × 8 × 512 = 68,719,476,736 bytes (~64GB raw)
```

`pls_per_lun` above 1 is addressed: a line spans one block index across every
channel, LUN and plane, so the planes add capacity and are collected together.
Garbage collection erases a line's planes on one LUN in a single multi-plane
operation. Reads and programs are not batched across planes and share their
LUN's timing gate, so planes do not add read or program parallelism. FDP places
its reclaim units across the planes too.

### Performance Tuning

**For Realistic Simulation:**
```bash
# Production SSD-like settings
pg_rd_lat=40000        # 40μs read
pg_wr_lat=200000       # 200μs write
blk_er_lat=2000000     # 2ms erase
```

### Advanced Configuration

**Memory Configuration:**
```bash
# In run scripts, adjust VM memory and SSD size
-m 8G                  # Guest RAM
devsz_mb=16384         # 16GB SSD capacity
```

**Multi-Device Setup:**
```bash
# Add multiple FEMU devices
-device femu,devsz_mb=4096,femu_mode=1,serial=femu1 \
-device femu,devsz_mb=4096,femu_mode=1,serial=femu2
```

### FTL Policies and Caches (BlackBox)

The BlackBox FTL exposes several pluggable, opt-in models. Each defaults to the
original behavior, so a device that sets none of them keeps the classic timing.

**Garbage-collection victim policy (`gc_policy`).** Chooses which line the FTL
reclaims first: `greedy` (fewest valid pages, the default), `random`,
`cost-benefit` (age-weighted), `fifo` (oldest closed line first), or `d-choice`
(sample d candidates and take the fewest valid pages).

**L2P mapping scheme (`mapping`).** `page` (default) keeps the whole
logical-to-physical table in DRAM. `dftl` demand-caches translation pages and
charges a translation-page read on a cache miss, modeling a DRAM-constrained
controller. Size its cache with `mapping_cache_mb`; a `dftl` device with no
explicit size gets 4 MiB.

**DRAM read cache (`read_cache_mb`).** A timing-only read cache: a hit returns
at DRAM latency and skips the NAND read. It holds no data, so NAND stays the
source of truth. `cache_evict` selects the replacement policy: `clock`
(default), `random`, `lru`, or a scan-resistant `arc`.

---

## Development

### Building from Source

For development work, use the debug build:

```bash
# Configure with debugging enabled (femu-compile.sh's options plus debug)
../configure --enable-kvm --target-list=x86_64-softmmu --enable-slirp \
    --disable-libnfs --disable-libiscsi --disable-curl \
    --enable-debug --enable-debug-info

# Compile with debug symbols
make -j$(nproc)
```

### Code Structure

```
hw/femu/                    # Main FEMU implementation
├── femu.c                  # NVMe controller core
├── nvme-admin.c            # Admin command handling
├── nvme-io.c               # I/O command handling
├── nvme-util.c             # Utility functions
├── bbssd/                  # BlackBox SSD implementation
│   ├── ftl.c               # Flash Translation Layer
│   └── bb.c                # BlackBox logic
├── ocssd/                  # OpenChannel SSD implementation
│   ├── oc12.c              # OCSSD 1.2 support
│   └── oc20.c              # OCSSD 2.0 support
├── zns/                    # ZNS implementation
│   ├── zns.c               # ZNS logic
│   └── zftl.c              # Zone-based FTL
├── nossd/                  # NoSSD mode
│   └── nop.c               # Minimal processing
├── csd/                    # Computational Storage mode
│   ├── csd.c               # CSD command handling
│   └── csd.h               # CSD private command definitions
├── nand/                   # NAND flash model
├── timing-model/           # Performance modeling
├── backend/                # Storage backends (emulated medium / mbe)
├── lib/                    # Utility libraries
├── inc/                    # Shared headers (rings, pqueue, ...)
├── scripts/                # Build + run scripts (see below)
├── tests/                  # FEMU's own tests (unit, qtest, guest-side CSD)
└── docs/                   # FEMU documentation
```

All FEMU-specific code, scripts, and docs live under `hw/femu/` to keep the
project self-contained and easy to maintain long term. For backward
compatibility, a top-level `femu-scripts` symlink points to `hw/femu/scripts/`,
so the historical `cd build-femu && ../femu-scripts/...` workflow still works.

Docs under `hw/femu/docs/`:
- `reference/properties.md`: every device property and the environment
  variables FEMU reads, generated by `hw/femu/scripts/gen-property-docs.py`.
- `reference/runtime-properties.md`: QOM properties and counters, generated.
- `reference/log-pages-and-counters.md`: the vendor log page C0h.
- `cxlssd.md`: CXL SSD (`femu-cxl-ssd`) design notes.
- `HIOPS.md` — NoSSD high-IOPS optimizations, results, and reproduction.
- `CONFIGURATION-CHANGES.md` — configuration changes that affect existing runs.

Scripts under `hw/femu/scripts/` (run from your `build-femu/` dir):
- `femu-compile.sh`, `femu-copy-scripts.sh` — build and stage the run scripts.
- `run-{blackbox,whitebox,zns,nossd,csd}.sh` — per-mode launchers.
- `run-blackbox-fdp.sh` — BlackBox with Flexible Data Placement enabled.
- `hiops/` — the socket-isolation high-IOPS benchmark harness.

### Adding New Features

1. **Create feature branch:**
   ```bash
   git checkout -b feature/new-ssd-mode
   ```

2. **Implement changes** following existing patterns

3. **Add configuration options** in run scripts

4. **Test thoroughly** across supported platforms

5. **Submit pull request** with comprehensive description

### Debugging

**GDB Debugging:** do not use `gdb-run.sh`; it is an old script that starts
QEMU's stock `nvme` device, not FEMU. Run a launcher's own command line under
gdb instead. From `build-femu/`, make a copy of the launcher that starts QEMU
through gdb:

```bash
sed -e 's|\./qemu-system-x86_64|gdb -ex "handle SIGUSR1 nostop noprint pass" --args ./qemu-system-x86_64|' \
    -e 's/ 2>&1 | tee .*$//' run-blackbox.sh > gdb-blackbox.sh
bash gdb-blackbox.sh

# In GDB session
(gdb) break femu_realize
(gdb) run
```

KVM uses SIGUSR1 to kick vCPU threads, which is why gdb is told to pass it.

**Debug output:** FEMU has no runtime switch for debug output and defines no
QEMU trace events. Its debug messages are compiled in with extra flags:

```bash
# FEMU_DEBUG_FTL: FTL debug messages, and arms the FTL assertions
# FEMU_DEBUG_NVME: controller debug messages
../configure --enable-kvm --target-list=x86_64-softmmu --enable-slirp \
    --disable-libnfs --disable-libiscsi --disable-curl \
    --extra-cflags="-DFEMU_DEBUG_FTL -DFEMU_DEBUG_NVME"
make -j$(nproc)
```

`-DFEMU_FTL_ASSERT` arms the FTL assertions without the messages; the CI
sanitizer build uses it. For FDP, setting `FEMU_FDP_DEBUG=1` in QEMU's
environment traces placement to stderr. The launchers start QEMU through
`sudo`, which drops the caller's environment, so put the variable on that line:
`sudo FEMU_FDP_DEBUG=1 ./qemu-system-x86_64 ...`.

---

## Troubleshooting

### Common Issues

**Issue: "femu device not found"**
```bash
# Solution: Ensure using FEMU-compiled binary
./qemu-system-x86_64 -device help | grep femu
# Should show FEMU device. If not, rebuild FEMU.
```

**Issue: VM fails to boot**
```bash
# Check KVM support
lsmod | grep kvm
# Enable if needed:
sudo modprobe kvm-intel  # Intel CPUs
sudo modprobe kvm-amd    # AMD CPUs
```

**Issue: Poor performance**
```bash
# Check host CPU governor
cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
# Set to performance:
sudo cpupower frequency-set -g performance
```

**Issue: Build failures**

See [common build errors](hw/femu/docs/getting-started/build.md#common-build-errors).

### Performance Optimization

**Host Optimization:**
```bash
# Disable CPU frequency scaling
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Increase VM priority
sudo nice -n -10 ./run-blackbox.sh

# Pin QEMU threads to specific cores
taskset -c 0-7 ./run-blackbox.sh
```

**Guest Optimization:**
```bash
# In VM, disable unnecessary services
sudo systemctl disable cups bluetooth
sudo systemctl mask sleep.target suspend.target

# Use deadline scheduler for better SSD simulation
echo mq-deadline | sudo tee /sys/block/nvme*/queue/scheduler
```

### Logging and Monitoring

**Enable detailed logging:** QEMU system emulation reads no logging
environment variables. Add these options to the QEMU command line in the run
script instead:

```bash
-d guest_errors,unimp -D femu-debug.log
```

**Monitor performance:**
```bash
# In guest VM
sudo iostat -x 1           # I/O statistics
sudo iotop                 # I/O by process
sudo dstat -cdn            # System-wide stats
```

### Getting Help

1. **Check [`hw/femu/docs/`](hw/femu/docs/)** for the property reference and design notes
2. **Search [Issues](https://github.com/MoatLab/FEMU/issues)** for similar problems
3. **Join discussions** in GitHub Discussions
4. **Contact maintainers** for research collaboration

---

## Research & Citation

FEMU has been used in numerous systems research projects across top-tier venues including ASPLOS, OSDI, SOSP, FAST, SIGCOMM, HPCA, DAC, DATE, etc.

**Please check the growing list of research papers using FEMU [here](https://github.com/MoatLab/FEMU/wiki/Research-Papers-using-FEMU), including papers at ASPLOS, OSDI, SOSP and FAST, etc.**

### Primary Citation

If you use FEMU in your research, please cite our FAST 2018 paper:

```bibtex
@inproceedings{Li+18-FEMU,
  author    = {Huaicheng Li and Mingzhe Hao and Michael Hao Tong and
               Swaminathan Sundararaman and Matias Bj{\o}rling and Haryadi S. Gunawi},
  title     = {{The CASE of FEMU: Cheap, Accurate, Scalable and Extensible Flash Emulator}},
  booktitle = {16th USENIX Conference on File and Storage Technologies (FAST 18)},
  year      = {2018},
}
```

### Related Publications

**FEMU-based Research:**
- See our growing list of [research papers using FEMU](https://github.com/MoatLab/FEMU/wiki/Research-Papers-using-FEMU)
- Papers span storage systems, operating systems, and computer architecture

**Technical Reports:**
- FEMU technical details and validation studies
- Performance characterization and accuracy analysis

---

## Contributing

We welcome contributions from the community! FEMU is actively used in systems research worldwide.

### How to Contribute

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Contribution Guidelines

**Code Style:**
- Follow existing QEMU coding standards
- Use consistent indentation (4 spaces)
- Add comprehensive comments for new features
- Include error handling and validation

**Testing:**
- Test on multiple host distributions
- Validate all SSD modes still function
- Include performance regression tests
- Document any new configuration options

**Documentation:**
- Update relevant README sections
- Add inline code documentation
- Document new features in this README or under `hw/femu/docs/`
- Include usage examples

### Research Collaborations

**Academic Partnerships:**
- We welcome research collaborations
- Joint paper development opportunities
- Access to advanced FEMU features
- Performance optimization consulting

**Contact for Research:**
- Email: [huaicheng@cs.vt.edu](mailto:huaicheng@cs.vt.edu)
- Include: research area, institution, timeline

---

## Support

### Community Support

- **GitHub Issues**: [Report bugs and request features](https://github.com/MoatLab/FEMU/issues)
- **GitHub Discussions**: [Community Q&A and discussions](https://github.com/MoatLab/FEMU/discussions)
- **Documentation**: this README and [`hw/femu/docs/`](hw/femu/docs/)

### Professional Support

For research institutions and industry partners:
- Custom FEMU development and consulting
- Performance optimization services
- Training workshops and tutorials
- Priority technical support

**Contact**: [Huaicheng Li](mailto:huaicheng@cs.vt.edu), Virginia Tech

### Reporting Issues

**Bug Reports:**
Include the following information:
- Host OS and kernel version
- FEMU version and commit hash
- Complete error messages or logs
- Steps to reproduce the issue
- Expected vs actual behavior

**Feature Requests:**
- Describe the use case and motivation
- Provide technical requirements
- Suggest implementation approach if available
- Consider contributing implementation

---

## License

FEMU is released under the **GNU General Public License v2.0**.

```
Copyright (C) 2018-2024 Virginia Tech and Contributors

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
```

Full license text: [GPL-2.0](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)

### Third-Party Components

FEMU incorporates code from several projects:

- **QEMU**: Machine emulator and virtualizer (GPL v2.0)
- **NVMe QEMU**: NVMe controller implementation
- **LightNVM**: OpenChannel SSD support
- **Linux Kernel**: Headers and interface definitions (GPL v2.0)

See individual file headers for specific attribution details.

---

## Acknowledgments

### Research Community

FEMU development is supported by:
- **U.S. National Science Foundation** - [NSF POSE award #2550145](https://www.nsf.gov/awardsearch/showAward?AWD_ID=2550145)
- **Virginia Tech** - Primary development and maintenance
- **Research collaborators** - Algorithm contributions and validation
- **Systems community** - Feedback, bug reports, and improvements

Any opinions, findings, and conclusions or recommendations expressed in this material are
those of the authors and do not necessarily reflect the views of the National Science Foundation.

### Technical Foundation

FEMU builds upon several pioneering projects:
- **QEMU/KVM** - Virtualization infrastructure
- **SSD Simulators** - SSDSim, FlashSim, VSSIM concepts
- **Hardware Platforms** - OpenSSD, DFC design insights
- **Standards Bodies** - NVMe, OpenChannel, ZNS specifications

### Contributors

We thank all contributors who have helped improve FEMU:
- Algorithm developers and performance optimizers
- Platform porting and compatibility testing
- Documentation improvements and examples
- Bug reports and feature suggestions


---

**For more detailed information, see [`hw/femu/docs/`](hw/femu/docs/).**

---

<p align="center">
  <strong>FEMU</strong> - Advancing Next-Generation Storage Systems Research<br>
  <em>Fast • Accurate • Scalable • Extensible</em>
</p>
