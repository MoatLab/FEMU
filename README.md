# FEMU - Fast, Accurate, and Extensible NVMe SSD Emulator

**Website: [femu-ose.github.io](https://femu-ose.github.io/)** · **Join the FEMU community on [Discord](https://discord.gg/AgPTUJCw7)** for FEMU-related discussions, questions, and ideas. Everyone is welcome!

[![FEMU Version](https://img.shields.io/badge/FEMU-v10.1-brightgreen)](https://github.com/MoatLab/FEMU/releases)
[![Build Status](https://github.com/MoatLab/FEMU/workflows/CI/badge.svg)](https://github.com/MoatLab/FEMU/actions)
[![License: GPL v2+](https://img.shields.io/badge/License-GPL%20v2%2B-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![Platform](https://img.shields.io/badge/Platform-x86--64-brightgreen)](https://shields.io/)
[![Website](https://img.shields.io/badge/Website-femu--ose.github.io-blue)](https://femu-ose.github.io/)
[![Manual](https://img.shields.io/badge/Manual-PDF-red)](https://femu-ose.github.io/pdf/femu-manual.pdf)

```
  ______ ______ __  __ _    _
 |  ____|  ____|  \/  | |  | |
 | |__  | |__  | \  / | |  | |
 |  __| |  __| | |\/| | |  | |
 | |    | |____| |  | | |__| |
 |_|    |______|_|  |_|\____/  -- A fast, accurate, scalable, and extensible NVMe SSD Emulator
```

**FEMU** is a fast, accurate, scalable, and extensible NVMe SSD emulator based on QEMU/KVM. It enables full-system evaluation of storage systems and supports multiple SSD architectures for systems research.

> **New to FEMU? Start with [The FEMU Manual (PDF)](https://femu-ose.github.io/pdf/femu-manual.pdf).** One
> document covers building and running FEMU, its architecture and the design of each
> component, every mode and feature, every parameter, measuring, troubleshooting and
> contributing, with diagrams throughout.

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
> welcome too: feel free to submit pull requests. Please read the
> [AI policy](hw/femu/docs/ai-policy.md) first; AI-assisted commits carry an `Assisted-by:` line.

## Table of Contents

[Overview](#overview) · [Features](#features) · [Architecture](#architecture) ·
[Requirements](#system-requirements) · [Installation](#installation) ·
[Quick Start](#quick-start) · [Where to Go Next](#where-to-go-next) ·
[Usage](#usage) · [Configuration](#configuration) · [Development](#development) ·
[Troubleshooting](#troubleshooting) · [Citation](#research--citation) ·
[Contributing](#contributing) · [Support](#support) · [License](#license) ·
[Acknowledgments](#acknowledgments)

The full documentation starts at the [doc map](hw/femu/docs/README.md), and the
same pages are collected in [the FEMU Manual (PDF)](https://femu-ose.github.io/pdf/femu-manual.pdf). What
changed since the last release is in the [changelog](hw/femu/docs/CHANGELOG.md).

## Overview

FEMU bridges the gap between SSD hardware platforms and SSD simulators. It
runs the full system stack (applications, OS and the NVMe interface) on
emulated SSDs of several architectures, each with configurable parameters.

### Key Benefits

- **Fast**: NoSSD mode completes I/O in a few microseconds to tens of
  microseconds, depending on the host ([NoSSD](hw/femu/docs/modes/nossd.md)).
- **Accurate**: the SSD modes charge NAND, channel and garbage collection time
  from a configurable [timing model](hw/femu/docs/concepts/timing-model.md).
- **Scalable**: several devices and namespaces per VM, within the
  [host sizing limits](hw/femu/docs/concepts/security-and-limits.md).
- **Extensible**: each mode is a separate backend under `hw/femu/`
  ([code structure](hw/femu/docs/development/code-structure.md)).

## Features

<!-- modes-table:start -->
<!-- Generated from hw/femu/docs/modes.py by hw/femu/scripts/gen-mode-table.py; edit modes.py, not this table. -->

| Mode or feature | Use it for | Turn it on with | Guest kernel | Guest tools | Host needs | Launcher | Checked |
| --- | --- | --- | --- | --- | --- | --- | --- |
| [NoSSD](hw/femu/docs/modes/nossd.md) | fast NVMe device in DRAM, no flash timing | `femu_mode=2` (the default) | any with the NVMe driver | nvme-cli, fio | none beyond the common ones | `run-nossd.sh` | CI: realize, Identify, write and read back |
| [BlackBox SSD (BBSSD)](hw/femu/docs/modes/blackbox.md) | a commercial SSD: device FTL, GC, NAND timing | `femu_mode=1` | any with the NVMe driver | nvme-cli, fio | about 17 GiB free RAM for the launcher's 12 GiB device | `run-blackbox.sh` | CI: realize, Identify, write and read back; guest: [quick start, run end to end](hw/femu/docs/getting-started/quick-start.md) |
| [Zoned Namespace (ZNS)](hw/femu/docs/modes/zns.md) | zoned storage research | `femu_mode=3` | 5.9 or newer with `CONFIG_BLK_DEV_ZONED=y`; 4 KiB guest pages | nvme-cli 1.12 or newer for `nvme zns` | none beyond the common ones | `run-zns.sh` | CI: realize, Identify, write and read back |
| [Open-Channel SSD 1.2](hw/femu/docs/modes/ocssd.md) | host-managed FTL research | `femu_mode=0,lver=1` | 4.16 to 5.14 (LightNVM was removed in 5.15) | LightNVM tools, or SPDK on newer kernels | none beyond the common ones | `run-whitebox.sh` | CI: realize, Identify |
| [Open-Channel SSD 2.0](hw/femu/docs/modes/ocssd.md) | host-managed FTL research | `femu_mode=0` (`lver=2` is the default) | 4.17 to 5.14 (LightNVM was removed in 5.15) | LightNVM tools, or SPDK on newer kernels | none beyond the common ones | `run-whitebox.sh` | CI: realize, Identify |
| [Key-value SSD (KV)](hw/femu/docs/modes/kvssd.md) | key-value store research | `femu_mode=5` | 6.0 or newer; no block device, the namespace is `/dev/ngXnY` | nvme-cli `io-passthru`, `hw/femu/scripts/kv-probe.c` | none beyond the common ones | `run-kvssd.sh` | CI: realize, Identify, store and retrieve |
| [Computational storage (CSD)](hw/femu/docs/modes/csd.md) | running programs next to the data | `femu_mode=4,fdm_size=<MiB>` | any with the NVMe driver | `hw/femu/tests/csd` tools | `csd_program_dir` for shared-library programs; `--enable-csd-ubpf` build for eBPF programs | `run-csd.sh` | CI: realize, Identify, write and read back |
| [Flexible Data Placement (FDP)](hw/femu/docs/features/fdp.md) | placement hints on a BBSSD | `femu-subsys,fdp=on,fdp.nruh=<n>` and `femu,femu_mode=1,subsys=<id>` | any with the NVMe driver; placement hints need passthrough or io_uring commands | nvme-cli with `nvme fdp` | none beyond the common ones | `run-blackbox-fdp.sh` | CI: realize, Identify, write and read back |
| [Multiple namespaces](hw/femu/docs/features/multi-namespace.md) | several namespaces, each with its own mode | `namespaces=<n>`, optionally `namespace_sizes` and `namespace_modes` | any with the NVMe driver (ZNS namespaces need what ZNS needs) | nvme-cli | none beyond the common ones | none | CI: realize, Identify, write and read back |
| [Namespace management](hw/femu/docs/features/ns-management-and-pi.md#namespace-management) | create, delete and attach namespaces at run time | `ns_mgmt=on` on a NoSSD or BBSSD controller; `femu-subsys,ns_mgmt=on` to share namespaces | any with the NVMe driver | nvme-cli `create-ns`, `attach-ns` | none beyond the common ones | none | CI: realize, Identify, write and read back |
| [Metadata and protection information](hw/femu/docs/features/ns-management-and-pi.md#metadata-and-protection-information) | per-block metadata, PI types 1 to 3 | `meta=<bytes>,mc=<mask>`, plus `pi=on` with `meta` of 8 or more | `CONFIG_BLK_DEV_INTEGRITY=y` to use metadata formats through the block layer | nvme-cli `format` | none beyond the common ones | none | CI: realize, Identify, write and read back |
| [CXL SSD, `der=off`](hw/femu/docs/modes/cxl-ssd.md) | CXL memory backed by flash, all accesses trapped | `femu-cxl-ssd` below `pxb-cxl` and `cxl-rp` on `-machine q35,cxl=on` | `CONFIG_CXL_BUS`, `CXL_PCI`, `CXL_ACPI`, `CXL_MEM`, `CXL_PORT`, `CXL_REGION`, `CXL_REGION_INVALIDATION_TEST` (in a VM), `DEV_DAX`, `DEV_DAX_CXL`, `DEV_DAX_KMEM` | `cxl-cli`, `daxctl`, `ndctl` | a build with `CONFIG_CXL_MEM_DEVICE` | `run-cxlssd.sh` | CI: realize |
| [CXL SSD, `der=memslot`](hw/femu/docs/modes/cxl-ssd.md#dermemslot) | cached pages mapped into the guest as KVM memory slots | `der=memslot` on `femu-cxl-ssd` | as for `der=off` | as for `der=off` | KVM (TCG is refused) | `run-cxlssd.sh` | CI: realize |
| [CXL SSD, `der=cylon`](hw/femu/docs/modes/cxl-ssd.md#dercylon) | cached pages mapped by a Cylon host kernel | `der=cylon,cylon-kernel-ack=on` on `femu-cxl-ssd` | as for `der=off` | as for `der=off` | Cylon host kernel; KVM with EPT A/D bits and the TDP MMU; 4 KiB host pages; a shared, preallocated hugetlb backend. Without them the device warns and uses MMIO | `run-cxlssd.sh` | CI: realize |
| [CXL caching API (CCA)](hw/femu/docs/features/cxl-cca.md) | guest pins, unpins and invalidates cached pages | `cca=on` on `femu-cxl-ssd` | as for `der=off`; a devdax region | `hw/femu/tools/cca` (`ccactl`, `cca-test`), run as root | as for `der=off` | `run-cxlssd.sh` | CI: realize |
| [NVMe front end on a CXL SSD](hw/femu/docs/features/cxl-nvme-link.md) | the same media as CXL memory and as an NVMe namespace | `femu,bus=pcie.0,femu_mode=1,cxl_ssd=<id>` after the `femu-cxl-ssd` | as for `der=off`, plus the NVMe driver | as for `der=off`, plus nvme-cli | as for `der=off` | none | CI: realize, Identify, write and read back |
<!-- modes-table:end -->

When `femu_mode` is not set, the device runs in NoSSD mode (2). Flexible Data
Placement is not a separate mode: it is BlackBox with `fdp=on` set on the
subsystem. The CXL SSD is not an NVMe mode either: `femu-cxl-ssd` is a CXL
Type-3 memory device whose DRAM page cache sits in front of the BlackBox FTL.
OpenChannel needs a host that speaks it; LightNVM was removed from Linux in
5.15. [Choosing a mode](hw/femu/docs/concepts/choosing-a-mode.md) has the full
decision table.

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

The NVMe controller (NVMe 1.4, reported as version 1.4.0) hands each command
to the mode backend that owns the namespace. The modes with flash share the
FTL and NAND timing model, and the emulated medium lives in host DRAM.
[Architecture](hw/femu/docs/concepts/architecture.md) walks through each
layer, its source files and its threads.

## System Requirements

An x86_64 Linux host with KVM, Python >= 3.9 and GLib >= 2.66 (Ubuntu 22.04 or
24.04; CI builds on both). The emulated SSD lives in host DRAM, so the default
BBSSD launcher needs about 17 GiB of free RAM. Full details, including the
guest kernel each mode needs:
[requirements.md](hw/femu/docs/getting-started/requirements.md).

### [Host Environment Compatibility](hw/femu/docs/getting-started/requirements.md#operating-system-and-cpu)

### [Guest Environment Compatibility](hw/femu/docs/getting-started/requirements.md#kernel-per-mode)

OCSSD needs a guest kernel older than 5.15 and ZNS needs 5.9 or newer.

## Installation

```sh
git clone https://github.com/MoatLab/FEMU.git
cd FEMU && mkdir build-femu && cd build-femu
cp ../femu-scripts/femu-copy-scripts.sh . && ./femu-copy-scripts.sh
sudo ./pkgdep.sh      # Debian/Ubuntu dependencies
./femu-compile.sh     # builds build-femu/qemu-system-x86_64
```

Dependencies, optional features (CSD uBPF, CXL SSD), debug builds and common
build errors: [build.md](hw/femu/docs/getting-started/build.md).

### [Build FEMU](hw/femu/docs/getting-started/build.md)

## Quick Start

From `build-femu/`:

<!-- femu-untested: needs a guest image and KVM; run-blackbox.sh itself is tested by blackbox-launcher -->
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

### [1. VM Image Setup](hw/femu/docs/getting-started/guest-image.md)

### [3. Run Your First FEMU Instance](hw/femu/docs/getting-started/quick-start.md#3-boot-the-guest-with-a-bbssd-terminal-1)

### [4. Access the VM](hw/femu/docs/getting-started/guest-image.md#log-in-with-ssh)

## Where to Go Next

| I want to | Read |
| --- | --- |
| Read everything in one document | [The FEMU Manual (PDF)](https://femu-ose.github.io/pdf/femu-manual.pdf) |
| Pick a mode for my experiment | [Choosing a mode](hw/femu/docs/concepts/choosing-a-mode.md) |
| Set up one mode or feature | the guide linked from the [Features](#features) table |
| Look up a property, counter or script | [properties](hw/femu/docs/reference/properties.md), [runtime properties](hw/femu/docs/reference/runtime-properties.md), [log pages and counters](hw/femu/docs/reference/log-pages-and-counters.md), [scripts](hw/femu/docs/reference/scripts.md) |
| Understand how FEMU works | [architecture](hw/femu/docs/concepts/architecture.md), [timing model](hw/femu/docs/concepts/timing-model.md), [security and limits](hw/femu/docs/concepts/security-and-limits.md) |
| Measure or tune | [measuring](hw/femu/docs/guides/measuring.md), [performance tuning](hw/femu/docs/guides/performance-tuning.md) |
| Fix a problem | [troubleshooting and FAQ](hw/femu/docs/troubleshooting.md), [debugging](hw/femu/docs/guides/debugging.md) |
| Change FEMU | [code structure](hw/femu/docs/development/code-structure.md), [testing](hw/femu/docs/guides/testing.md), [CONTRIBUTING.md](CONTRIBUTING.md) |
| See what changed | [changelog](hw/femu/docs/CHANGELOG.md) |

Everything else is in the [doc map](hw/femu/docs/README.md).

## Usage

Each mode has its own guide, linked from the [Features](#features) table and below.

### [BlackBox SSD Mode (BBSSD)](hw/femu/docs/modes/blackbox.md)

### [Multiple Namespaces](hw/femu/docs/features/multi-namespace.md)

### [WhiteBox SSD Mode (OCSSD)](hw/femu/docs/modes/ocssd.md)

### [Zoned Namespace SSD Mode (ZNSSD)](hw/femu/docs/modes/zns.md)

### [Key-Value SSD Mode (KVSSD)](hw/femu/docs/modes/kvssd.md)

### [NoSSD Mode](hw/femu/docs/modes/nossd.md)

### [Computational Storage Mode (CSD)](hw/femu/docs/modes/csd.md)

CSD mode is derived from [CEMU](https://github.com/cs-qyzhang/CEMU). We thank
the CEMU authors, Qiuyang Zhang, Jiapin Wang, You Zhou, Peng Xu, Kai Lu,
Jiguang Wan, Fei Wu and Tao Lu, and Emilio
([@Emilio597](https://github.com/Emilio597)), who ported it to FEMU in
[#188](https://github.com/MoatLab/FEMU/pull/188). If you use the CSD mode,
please also cite CEMU ([BibTeX](hw/femu/docs/modes/csd.md#citation)).

## Configuration

Every device property, with its type, default and meaning, is in
[properties.md](hw/femu/docs/reference/properties.md), and the QOM counters in
[runtime-properties.md](hw/femu/docs/reference/runtime-properties.md). Both
are generated from the binary, and CI fails when they fall out of date.
`./qemu-system-x86_64 -device femu,help` prints the same descriptions.

### [Persistent Event log retention](hw/femu/docs/reference/log-pages-and-counters.md#persistent-event-log-retention)

### [Config Files](hw/femu/docs/reference/scripts.md#configuration-files)

### [Checking a Device](hw/femu/docs/guides/testing.md#guest-side-tests)

### [SSD Layout Parameters](hw/femu/docs/modes/blackbox.md#capacity-and-geometry)

### [Performance Tuning](hw/femu/docs/guides/performance-tuning.md)

### [Advanced Configuration](hw/femu/docs/getting-started/requirements.md#memory)

### [FTL Policies and Caches (BlackBox)](hw/femu/docs/modes/blackbox.md#garbage-collection)

## Development

All FEMU code, scripts and docs live under `hw/femu/`. A top-level
`femu-scripts` link points to `hw/femu/scripts/`.

### [Building from Source](hw/femu/docs/getting-started/build.md#debug-build)

### [Code Structure](hw/femu/docs/development/code-structure.md)

### [Adding New Features](hw/femu/docs/development/code-structure.md#making-a-change)

### [Debugging](hw/femu/docs/guides/debugging.md)

## Troubleshooting

The [troubleshooting and FAQ page](hw/femu/docs/troubleshooting.md) answers
the questions asked most often in the issue tracker;
[build.md](hw/femu/docs/getting-started/build.md#common-build-errors) covers
build errors.

### [Common Issues](hw/femu/docs/troubleshooting.md)

### [Performance Optimization](hw/femu/docs/guides/performance-tuning.md)

### [Logging and Monitoring](hw/femu/docs/guides/debugging.md#where-messages-go)

### Getting Help

1. Check the [doc map](hw/femu/docs/README.md) and the [FAQ](hw/femu/docs/troubleshooting.md).
2. Search [Issues](https://github.com/MoatLab/FEMU/issues) for similar problems.
3. Ask in [GitHub Discussions](https://github.com/MoatLab/FEMU/discussions) or on [Discord](https://discord.gg/AgPTUJCw7).
4. Contact the maintainers for research collaboration.

## Research & Citation

FEMU has been used in systems research published at ASPLOS, OSDI, SOSP, FAST,
SIGCOMM, HPCA, DAC, DATE and other venues. **See the growing
[list of research papers using FEMU](https://github.com/MoatLab/FEMU/wiki/Research-Papers-using-FEMU).**

### Primary Citation

If you use FEMU in your research, please cite our FAST 2018 paper. The same
entry is in [CITATION.cff](CITATION.cff), which GitHub shows as "Cite this
repository":

```bibtex
@inproceedings{Li+18-FEMU,
  author    = {Huaicheng Li and Mingzhe Hao and Michael Hao Tong and
               Swaminathan Sundararaman and Matias Bj{\o}rling and Haryadi S. Gunawi},
  title     = {{The CASE of FEMU: Cheap, Accurate, Scalable and Extensible Flash Emulator}},
  booktitle = {16th USENIX Conference on File and Storage Technologies (FAST 18)},
  year      = {2018},
}
```

If you use one of these modes, also cite the paper it comes from:

- FDP: [WARP](hw/femu/docs/features/fdp.md#citation), *Characterizing and Emulating FDP SSDs with WARP* (FAST '26).
- CXL SSD (`femu-cxl-ssd`): [Cylon](hw/femu/docs/modes/cxl-ssd.md#citation), *Cylon: Fast and Accurate Full-System Emulation of CXL-SSDs* (FAST '26).
- CSD: [CEMU](hw/femu/docs/modes/csd.md#citation), *CEMU: Enabling Full-System Emulation of Computational Storage Beyond Hardware Limits* (ASPLOS '26).

### [Related Publications](https://github.com/MoatLab/FEMU/wiki/Research-Papers-using-FEMU)

## Contributing

We welcome contributions from the community! FEMU is actively used in systems research worldwide.

### [How to Contribute](CONTRIBUTING.md)

### Contribution Guidelines

[CONTRIBUTING.md](CONTRIBUTING.md) covers style (`scripts/checkpatch.pl`),
tests, sign-off and pull requests. Document new properties and features under
[`hw/femu/docs/`](hw/femu/docs/README.md), with usage examples, and add an
entry to the [changelog](hw/femu/docs/CHANGELOG.md).

### Research Collaborations

We welcome research collaborations: joint paper development, access to
advanced FEMU features, and performance optimization consulting. Email
[huaicheng@cs.vt.edu](mailto:huaicheng@cs.vt.edu) with your research area,
institution and timeline.

## Support

### Community Support

[GitHub Issues](https://github.com/MoatLab/FEMU/issues) for bugs and feature
requests, [GitHub Discussions](https://github.com/MoatLab/FEMU/discussions) and
[Discord](https://discord.gg/AgPTUJCw7) for questions, and the
[doc map](hw/femu/docs/README.md).

### Professional Support

For research institutions and industry partners: custom FEMU development and
consulting, performance optimization services, training workshops and
tutorials, and priority technical support. Contact
[Huaicheng Li](mailto:huaicheng@cs.vt.edu), Virginia Tech.

### Reporting Issues

For a bug, include the host OS and kernel version, the FEMU commit, the full
QEMU command line, the complete error messages or logs, the steps to
reproduce, and what you expected; [reporting a bug](hw/femu/docs/guides/debugging.md#reporting-a-bug)
has the full list. For a feature request, describe the use case and
motivation, the technical requirements, and an implementation approach if you
have one; consider contributing it.

## License

FEMU is released under the **GNU General Public License v2.0 or later**.

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

FEMU incorporates code from QEMU (machine emulator and virtualizer, GPL
v2.0), the QEMU NVMe controller, LightNVM (OpenChannel SSD support) and Linux
kernel headers and interface definitions (GPL v2.0). See individual file
headers for specific attribution details.

## Acknowledgments

### Research Community

FEMU development is supported by the U.S. National Science Foundation
([NSF POSE award #2550145](https://www.nsf.gov/awardsearch/showAward?AWD_ID=2550145)),
Virginia Tech (primary development and maintenance), research collaborators
(algorithm contributions and validation) and the systems community (feedback,
bug reports and improvements).

Any opinions, findings, and conclusions or recommendations expressed in this material are
those of the authors and do not necessarily reflect the views of the National Science Foundation.

### Technical Foundation

FEMU builds upon QEMU/KVM (virtualization infrastructure), ideas from SSD
simulators (SSDSim, FlashSim, VSSIM), hardware platforms (OpenSSD, DFC), and
the NVMe, OpenChannel and ZNS specifications.

### Contributors

We thank all contributors who have helped improve FEMU: algorithm developers
and performance optimizers, platform porting and compatibility testing,
documentation improvements and examples, bug reports and feature suggestions.
