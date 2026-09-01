# FEMU - Fast, Accurate, and Extensible NVMe SSD Emulator

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

---

## Table of Contents

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

| Feature | BlackBox | WhiteBox | ZNS | NoSSD | CSD |
|---------|----------|----------|-----|--------|-----|
| **FTL Management** | Device-side | Host-side | Zone-based | None | Device-side |
| **Use Cases** | Commercial SSD simulation | OpenChannel SSD research | ZNS research | SCM emulation | Computational storage research |
| **Latency Model** | Realistic NAND | Realistic NAND | Zone-optimized | Ultra-low (sub-10μs) | Realistic NAND + compute runtime |
| **Guest Support** | Full NVMe | OpenChannel 1.2/2.0 | NVMe ZNS | NVMe basic | Full NVMe + CSD commands |

---

## Architecture

```
                        +--------------------+
                        |    VM / Guest OS   |
                        |                    |
                        |                    |
                        |  NVMe Block Device |
                        +--------^^----------+
                                 ||
                              PCIe/NVMe
                                 ||
  +------------------------------vv----------------------------+
  |  +---------+ +---------+ +---------+ +-----------+ +------+|
  |  | BlackBox| | WhiteBox| | ZNS-SSD | |  NoSSD    | | ...  ||
  |  |  (BBSSD)| | (OCSSD) | |(ZNSSD)  | |(Ultra-low)| |      ||
  |  +---------+ +---------+ +---------+ +-----------+ +------+|
  |                    FEMU NVMe SSD Controller                |
  +------------------------------------------------------------+
  |                          QEMU/KVM                          |
  +------------------------------------------------------------+
  |                        Host Linux                          |
  +------------------------------------------------------------+
```

### Core Components

- **NVMe Controller**: Standards-compliant NVMe 1.3+ implementation
- **SSD Modes**: Pluggable backends for different SSD architectures
- **Timing Model**: Configurable latency simulation for realistic performance
- **Memory Backend**: DRAM-based storage emulation

---

## System Requirements

### Minimum Requirements

- **Physical Machine**: Run FEMU on a physical machine, not inside a VM (nested virtualization is not recommended due to performance impact)
- **OS**: Linux (Ubuntu 18.04+, CentOS 7+, or equivalent)
- **CPU**: x86_64 with hardware virtualization (Intel VT-x/AMD-V)
- **Memory**: At least 12GB DRAM to enable seamless run of default FEMU scripts emulating a 4GB SSD
- **CPU Cores**: At least 8 cores for 4 vCPUs and 4GB DRAM VM
- **Storage**: 20GB free disk space

### Recommended Configuration
- **CPU**: 16+ cores (Intel Xeon or AMD EPYC)
- **Memory**: 32GB+ RAM
- **Storage**: NVMe SSD with 100GB+ free space
- **Network**: For distributed testing scenarios

### Host Environment Compatibility

| Linux Distribution | Kernel | GCC    | Ninja  | Python | Status |
|:-------------------|:-------|:-------|:-------|:-------|:-------|
| Ubuntu 24.04 LTS   | 6.8.0  | 13.2.0 | 1.12.1 | 3.12.3 | ✅ Tested |
| Ubuntu 22.04 LTS   | 5.15.0 | 11.3.0 | 1.10.1 | 3.10.6 | ✅ Tested |
| Ubuntu 20.04 LTS   | 5.4.0  | 9.3.0  | 1.10.0 | 3.8.2  | ✅ Tested |
| Ubuntu 18.04 LTS   | 4.15.0 | 7.5.0  | 1.8.2  | 3.6.7  | ✅ Tested |
| Ubuntu 16.04.5     | 4.15.0 | 5.4.0  | 1.8.2  | 3.6.0  | ⚠️ Legacy |
| Gentoo             | 5.10   | 9.3.0  | 1.10.1 | 3.7.9  | ⚠️ Community |

### Guest Environment Compatibility

| Mode \ Guest Kernel       | 4.16    | 4.20    | 5.4     | 5.10    | 6.1     | 6.9     |
| :---                      | :---:   | :---:   | :---:   | :---:   | :---:   | :---:   |
| NoSSD                     | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| BlackBox SSD              | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| OpenChannel-SSD v1.2      | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| OpenChannel-SSD v2.0      | ❌ | ✅ | ✅ | ✅ | ❌ | ❌ |
| Zoned-Namespace (ZNS) SSD | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ |

**Continuous Integration**: FEMU uses GitHub Actions for automated testing across multiple Ubuntu versions. The CI pipeline:

- Tests compilation on Ubuntu 20.04, 22.04, and 24.04 LTS
- Verifies FEMU device registration and all SSD modes (BlackBox, WhiteBox, ZNS, NoSSD)
- Validates code quality and build system integration
- Runs compatibility tests for configuration parameters and run scripts
- Build status is shown in the badge at the top of this README

---

## Installation

### Build FEMU

1. **Clone the repository:**
   ```bash
   git clone https://github.com/MoatLab/FEMU.git
   cd FEMU
   ```

2. **Create build directory:**
   ```bash
   mkdir build-femu
   cd build-femu
   ```

3. **Setup build environment and install dependencies:**
   ```bash
   # Copy FEMU helper scripts
   cp ../femu-scripts/femu-copy-scripts.sh .
   ./femu-copy-scripts.sh .

   # Install all build dependencies automatically (Ubuntu/Debian only)
   sudo ./pkgdep.sh
   ```

4. **Compile FEMU:**
   ```bash
   ./femu-compile.sh
   ```

   The FEMU binary will be created as: `x86_64-softmmu/qemu-system-x86_64`

5. **Verify installation:**
   ```bash
   ./qemu-system-x86_64 -device help | grep femu
   # Should output: name "femu", bus PCI, desc "FEMU Non-Volatile Memory Express"
   ```

### Build Verification

To ensure your build is successful, run the basic device check:

```bash
# Check if FEMU device is properly registered
./qemu-system-x86_64 -device femu,help

# Check version information
./qemu-system-x86_64 --version
```

---

## Quick Start

### 1. VM Image Setup

**Option A: Use Pre-built Image (Recommended)**
1. Download VM image from [FEMU VM Image Portal](https://forms.gle/nEZaEe2fkj5B1bxt9)
2. Extract to `~/images/` directory
3. Rename to match script expectations: `u20s.qcow2`

**Option B: Build Custom Image**
```bash
# Create image directory
mkdir -p ~/images
cd ~/images

# Download Ubuntu Server ISO
# If the link no longer works, visit http://releases.ubuntu.com to download the correct version of ISO image
wget http://releases.ubuntu.com/24.04/ubuntu-24.04.3-live-server-amd64.iso

# Create VM disk image
qemu-img create -f qcow2 femu.qcow2 80G

# Install OS (requires GUI environment)
qemu-system-x86_64 -cdrom ubuntu-24.04.3-live-server-amd64.iso \
    -hda femu.qcow2 -boot d -net nic -net user -m 8192 -localtime -smp 8 -cpu host -enable-kvm
```

### 2. Configure VM for Serial Console

Inside the VM, edit `/etc/default/grub`:

```bash
sudo nano /etc/default/grub
```

Add these lines:
```
GRUB_CMDLINE_LINUX="ip=dhcp console=ttyS0,115200 console=tty console=ttyS0"
GRUB_TERMINAL=serial
GRUB_SERIAL_COMMAND="serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1"
```

Update GRUB and reboot:
```bash
sudo update-grub
sudo reboot
```

### 3. Run Your First FEMU Instance

```bash
# From the build-femu directory
./run-blackbox.sh
```

### 4. Access the VM

The VM will start in text mode. You can also SSH into the VM:
```bash
# From host machine
ssh -p 8080 username@localhost
```

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

# Garbage Collection
gc_thres_pcent=75      # GC trigger threshold (percent of lines in use)
gc_policy=greedy       # Victim selection: greedy (default), random,
                       #   cost-benefit, fifo, d-choice

# L2P Mapping (optional; default is a full DRAM page-mapping table)
mapping=page           # page (default), dftl, hybrid, or fast
mapping_cache_mb=0     # DFTL translation-cache size in MiB (used only for dftl)

# Write amplification / debugging
debug_ftl=false        # report FTL invariant violations instead of aborting

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
```

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

**Write amplification.** The device reports amplification in the vendor area of
the SMART log: the factor scaled by 1000 at byte 192, host-programmed pages at
200, and relocated pages at 208.

```bash
sudo nvme smart-log /dev/nvme0n1 -o binary | od -An -tu4 -j192 -N4   # WAF x1000
```

**Use Cases:**
- Commercial SSD simulation research
- FTL algorithm development and testing
- Storage system performance evaluation

### Multiple Namespaces

BBSSD and NoSSD can expose more than one namespace. The namespaces share the
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

Zoned (ZNSSD), Open-Channel (OCSSD), and CSD modes keep their geometry on the
controller and support a single namespace; so does FDP, whose reclaim groups are
shared device-wide. Requesting more than one namespace in those configurations
is rejected at startup.

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
zns_zd_ext_size=0      # Zone-descriptor extension bytes (0 = none)
zns_num_conv_zones=0   # Leading conventional zones (0 = all sequential)
zns_zone_cap=0         # Usable bytes per zone (0 = the whole zone)
zns_chnls_per_zone=0   # Channels a zone spans (0 = all of them)
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

Experimental computational storage support derived from CEMU. CSD is selected
with `femu_mode=4` and keeps CSD-specific code under `hw/femu/csd/`.

```bash
./run-csd.sh
```

**Key Parameters:**
```bash
fdm_size=64            # Functional data memory size (MB), required
nr_cu=4                # Number of compute units
nr_thread=4            # Number of functional simulation threads
time_slice=200000      # Scheduler time slice (ns)
context_switch_time=200 # Context switch time (ns)
csf_runtime_scale=3    # Runtime scaling factor
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
- Guest-side passthrough tests in `tests/femu-csd/`

The initial CSD path does not require a CEMU-specific Linux kernel, FDMFS, or a
fixed VM image. Advanced CEMU features such as VM freezing, virtual clock
changes, and FDMFS are intentionally kept out of the default path while the base
mode is upstreamed.

---

## Configuration

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
counters move, and the mode-specific surface answers. What it runs depends on
what the device reports itself to be, so the same script covers a block, zoned
or key-value namespace.

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
  waf_x1000=935 host_pages=40960 nand_pages=38335
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
# Configure with debugging enabled
../configure --enable-kvm --target-list=x86_64-softmmu \
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
└── docs/                   # FEMU documentation
```

All FEMU-specific code, scripts, and docs live under `hw/femu/` to keep the
project self-contained and easy to maintain long term. For backward
compatibility, a top-level `femu-scripts` symlink points to `hw/femu/scripts/`,
so the historical `cd build-femu && ../femu-scripts/...` workflow still works.

Docs under `hw/femu/docs/`:
- `HIOPS.md` — NoSSD high-IOPS optimizations, results, and reproduction.
- `FEMU-Master-Roadmap.md` — design roadmap.

Scripts under `hw/femu/scripts/` (run from your `build-femu/` dir):
- `femu-compile.sh`, `femu-copy-scripts.sh` — build and stage the run scripts.
- `run-{blackbox,whitebox,zns,nossd,csd}.sh` — per-mode launchers.
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

**GDB Debugging:**
```bash
# Use provided GDB script
./gdb-run.sh

# In GDB session
(gdb) break femu_realize
(gdb) continue
```

**Logging:**
```bash
# Enable FEMU debug output
export FEMU_DEBUG=1
./run-blackbox.sh
```

**Trace Events:**
```bash
# Enable QEMU tracing
./qemu-system-x86_64 -trace events=/path/to/trace-events
```

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
```bash
# Update build dependencies
sudo apt update && sudo apt upgrade
# Clean rebuild:
make clean && ./femu-compile.sh
```

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
echo deadline | sudo tee /sys/block/nvme*/queue/scheduler
```

### Logging and Monitoring

**Enable detailed logging:**
```bash
# Set environment variables before running
export QEMU_LOG=guest_errors,unimp
export QEMU_LOG_FILENAME=femu-debug.log
./run-blackbox.sh
```

**Monitor performance:**
```bash
# In guest VM
sudo iostat -x 1           # I/O statistics
sudo iotop                 # I/O by process
sudo dstat -cdn            # System-wide stats
```

### Getting Help

1. **Check [Wiki](https://github.com/MoatLab/FEMU/wiki)** for detailed documentation
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
- Create wiki pages for major features
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
- **Wiki**: [Comprehensive documentation](https://github.com/MoatLab/FEMU/wiki)

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
- **Virginia Tech** - Primary development and maintenance
- **Research collaborators** - Algorithm contributions and validation
- **Systems community** - Feedback, bug reports, and improvements

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

**For more detailed information, visit the [FEMU Wiki](https://github.com/MoatLab/FEMU/wiki).**

---

<p align="center">
  <strong>FEMU</strong> - Advancing Next-Generation Storage Systems Research<br>
  <em>Fast • Accurate • Scalable • Extensible</em>
</p>
