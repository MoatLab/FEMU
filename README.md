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
- [Configuration](#configuration)
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

| Feature | BlackBox | WhiteBox | ZNS | NoSSD |
|---------|----------|----------|-----|--------|
| **FTL Management** | Device-side | Host-side | Zone-based | None |
| **Use Cases** | Commercial SSD simulation | OpenChannel SSD research | ZNS research | SCM emulation |
| **Latency Model** | Realistic NAND | Realistic NAND | Zone-optimized | Ultra-low (sub-10μs) |
| **Guest Support** | Full NVMe | OpenChannel 1.2/2.0 | NVMe ZNS | NVMe basic |

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
gc_thres_pcent=75      # GC trigger threshold
```

**Use Cases:**
- Commercial SSD simulation research
- FTL algorithm development and testing
- Storage system performance evaluation

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

**Use Cases:**
- ZNS filesystem development (F2FS, Btrfs)
- Zone-aware applications
- Log-structured storage research

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

---

## Configuration

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
├── timing-model/           # Performance modeling
├── backend/                # Storage backends
└── lib/                    # Utility libraries
```

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
