# Requirements

What the host and the guest need before you build and run FEMU. The
[quick start](quick-start.md) assumes everything on this page.

## Host

### Operating system and CPU

FEMU runs on an x86_64 Linux host with hardware virtualization (Intel VT-x or
AMD-V). Run it on a physical machine. Nested virtualization works but distorts
the emulated latency, and WSL is not supported.

FEMU is based on QEMU 10.1, which needs Python 3.9 or newer and GLib 2.66 or
newer. Check yours:

```sh
python3 --version
pkg-config --modversion glib-2.0
```

| Distribution | Python | GLib | Status |
| --- | --- | --- | --- |
| Ubuntu 24.04 LTS | 3.12 | 2.80 | Built in CI |
| Ubuntu 22.04 LTS | 3.10 | 2.72 | Built in CI |
| Ubuntu 20.04 and older | 3.8 | 2.64 | Cannot build with stock packages |

Other distributions with new enough Python and GLib should build FEMU, but CI
does not test them. `pkgdep.sh` installs dependencies on Debian and Ubuntu
only; on other distributions install the equivalents of the packages listed in
[build.md](build.md#dependencies).

CI builds FEMU with `femu-compile.sh` on Ubuntu 22.04 and 24.04
(`.github/workflows/ci.yml`). It runs the unit tests and qtests and starts every
mode without a guest. It does not boot a guest. The guest-level
[quick start](quick-start.md) was last run end to end on a Pop!_OS 24.04 host
(Ubuntu 24.04 base) with Linux 6.18.

### KVM access

The run scripts start QEMU with `-enable-kvm`. Check that KVM is loaded and
that you can open it:

```sh
ls -l /dev/kvm
id -nG | grep -w kvm
```

If `/dev/kvm` is missing, enable virtualization in the BIOS and load the module
(`sudo modprobe kvm_intel` or `sudo modprobe kvm_amd`). If you are not in the
`kvm` group, add yourself and log in again:

```sh
sudo usermod -aG kvm "$USER"
```

The `run-*.sh` launchers run QEMU with `sudo`, so they work without the group.
`make-guest-image.sh` runs without root and needs the group.

### Memory

The emulated SSD lives in host DRAM. Nothing is stored in a file, and nothing
written to it survives a shutdown. Plan host memory as:

```
host RAM needed = devsz_mb (the emulated SSD) + guest RAM (-m) + about 1 GiB for QEMU
```

| Launcher | `devsz_mb` | Guest `-m` | Free host RAM needed |
| --- | --- | --- | --- |
| `run-blackbox.sh` (BBSSD) | 12288 | 4G | about 17 GiB |
| `run-nossd.sh`, `run-zns.sh`, `run-whitebox.sh`, `run-csd.sh` | 4096 | 4G | about 9 GiB |

To fit a smaller host, lower `ssd_size` in `run-blackbox.sh` and the geometry
with it (see [the property reference](../reference/properties.md)).

FEMU locks the device memory (`mlock`) so page faults do not distort latency.
Under `sudo` the limit does not apply. If you run QEMU as a normal user, raise
the limit with `ulimit -l unlimited` (or `/etc/security/limits.conf`). Without
it the device still starts and prints a warning, and latency is less precise.

### Hugepages

The standard `run-*.sh` launchers do not need hugepages. `femu-cxl-ssd` with
`der=cylon` needs a shared, preallocated hugetlb memory backend and a modified
host kernel (see [cxlssd.md](../cxlssd.md)).

### Disk

The source tree and one build take about 3 GiB. The guest image built by
`make-guest-image.sh` uses about 2.5 GiB on disk (32 GiB virtual), plus a
0.6 GiB download cache.

### CPU cores

The launchers give the guest 4 vCPUs (`-smp 4`). FEMU adds its own polling
threads. 8 host cores is a comfortable minimum.

## Guest

### Kernel per mode

| Mode | `femu_mode` | Guest kernel | Notes |
| --- | --- | --- | --- |
| NoSSD | 2 (default) | any with NVMe | |
| BlackBox SSD (BBSSD) | 1 | any with NVMe | |
| OpenChannel SSD 1.2 / 2.0 | 0 | 4.16 to 5.14 (2.0 needs 4.17 or newer) | LightNVM was removed in Linux 5.15. On newer kernels use SPDK. |
| Zoned Namespace (ZNS) | 3 | 5.9 or newer, `CONFIG_BLK_DEV_ZONED=y` | |
| Key-value (KV) | 5 | 6.0 or newer | No block device. The namespace appears as the generic character device `/dev/ngXnY`. Older kernels do not attach the namespace at all. |
| Computational storage (CSD) | 4 | any with NVMe | Guest tools in `hw/femu/tests/csd/`. |
| Flexible Data Placement (FDP) | 1, with `femu-subsys,fdp=on` | any with NVMe | Use passthrough commands or io_uring to send placement hints. |
| CXL SSD (`femu-cxl-ssd`) | not a `femu_mode` | CXL region support: `CONFIG_CXL_BUS`, `CXL_PCI`, `CXL_ACPI`, `CXL_MEM`, `CXL_PORT`, `CXL_REGION`, `DEV_DAX`, `DEV_DAX_KMEM` | Needs `cxl-cli` and `daxctl` in the guest. |

The image from `make-guest-image.sh` runs Ubuntu 24.04 with Linux 6.8. It covers
every mode except OCSSD.

### Guest tools

- `nvme-cli` and `fio` for every NVMe mode. `make-guest-image.sh` installs both.
- ZNS needs nvme-cli 1.12 or newer for `nvme zns`.
- nvme-cli 2.8, the version in Ubuntu 24.04, double-frees and crashes after
  every successful Persistent Event Log read (`nvme persistent-event-log`).
  Build nvme-cli 3.x from source in the guest if you need that log. Other
  commands work.
- CXL: `cxl-cli`, `daxctl` and `ndctl` (`make-guest-image.sh --cxl`).
