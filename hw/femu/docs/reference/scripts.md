# Scripts and tools

Every script and tool shipped under `hw/femu/scripts/` and `hw/femu/tools/`:
what it does, its arguments and the environment variables it reads. The
top-level `femu-scripts` link points to `hw/femu/scripts/`, so from
`build-femu/` you can also run them as `../femu-scripts/NAME`.

Scripts marked **legacy** do not start FEMU. They start QEMU's stock `nvme`
device or another disk on the old `x86_64-softmmu/` binary path, set thread
affinity by hand, or prepare a specific lab machine. They are kept for
reference. Do not use them.

## Build and setup

| Script | Run from | What it does |
| --- | --- | --- |
| `pkgdep.sh` | anywhere, as root | Installs the build dependencies with `apt-get` on Debian and Ubuntu. Exits with `pkgdep: unsupported system type` elsewhere. CI does not run it. |
| `femu-compile.sh` | `build-femu/` | Runs `make clean`, then `../configure --enable-kvm --target-list=x86_64-softmmu --enable-slirp --disable-libnfs --disable-libiscsi --disable-curl`, then `make` with one job per CPU. `--enable-csd-ubpf` adds uBPF CSD programs, `--enable-csd-ubpf=PATH` uses the uBPF tree at `PATH`. Any other argument is an error. See [build.md](../getting-started/build.md). |
| `femu-copy-scripts.sh` | `build-femu/` | Copies `pkgdep.sh`, `femu-compile.sh`, `make-guest-image.sh`, `run-guest-ssh.sh`, the `run-blackbox.sh`, `run-blackbox-fdp.sh`, `run-whitebox.sh`, `run-nossd.sh`, `run-zns.sh` and `run-csd.sh` launchers, `pin.sh` and `ftk/` into the current directory, overwriting earlier copies. It does not copy `run-cxlssd.sh`, `ssd-config.sh`, `configs/` or the guest tools; run those from `../femu-scripts/`. |

## Guest image and access

| Script | What it does | Arguments and environment |
| --- | --- | --- |
| `make-guest-image.sh` | Builds an Ubuntu 24.04 guest image from the official cloud image. It checks the download's SHA256 sum, and its signature when `gpgv` and the Ubuntu keyring are installed, with user `femu`, an SSH key, a serial console, `nvme-cli` and `fio`. Needs no root, but needs access to `/dev/kvm` unless you pass `--no-kvm`. See [guest-image.md](../getting-started/guest-image.md). | `-o DIR` output directory, `-n FILE` image name (default `u20s.qcow2`, the name the launchers expect), `-s SIZE` (default `32G`), `-k FILE` public key, `-p PW` console password, `--cxl` adds `ndctl`, `daxctl` and `cxl-cli`, `--packages LIST` extra packages, `--qemu PATH`, `--qemu-img PATH`, `--no-kvm`, `--timeout SEC` (default 1800), `-f` replace an existing image. Reads `IMGDIR` (default output directory `$HOME/images`), `QEMU` and `QEMU_IMG`. |
| `run-guest-ssh.sh` | Logs in to a running guest built by `make-guest-image.sh`, or runs one command in it: `./run-guest-ssh.sh sudo nvme list`. | `IMGDIR` (default `$HOME/images`), `SSH_KEY` (default `$IMGDIR/femu-guest-key`), `SSH_PORT` (default 8080), `GUEST_USER` (default `femu`). |

## Launchers

Run each NVMe launcher from `build-femu/` after `femu-copy-scripts.sh`. They
start `./qemu-system-x86_64` with `sudo`, KVM, `-cpu host`, `-nographic`,
`-name NAME,debug-threads=on` (so the host shows FEMU's thread names),
a virtio-scsi boot disk and user networking that forwards host port
`SSH_PORT` to the guest's port 22. `run-cxlssd.sh` is different: it is not
copied, so run it as `../femu-scripts/run-cxlssd.sh`, and it adds no disk,
no network and no `sudo` (see below). All except `run-cxlssd.sh` read:

| Variable | Default | Meaning |
| --- | --- | --- |
| `IMGDIR` | `$HOME/images` | Directory of the guest image |
| `OSIMGF` | `$IMGDIR/u20s.qcow2` | Guest image file; the script exits with status 1 if it does not exist |
| `SSH_PORT` | `8080` | Host port forwarded to the guest's SSH port; use a different one for each VM you run at the same time |

The device geometry, size and timing are shell variables at the top of each
script. Edit them there; they are not read from the environment.

| Launcher | Device | Guest | Output files |
| --- | --- | --- | --- |
| `run-blackbox.sh` | BlackBox SSD, 12 GiB namespace on 16 GiB of NAND ([BlackBox](../modes/blackbox.md)) | 4 vCPUs, 4 GiB | `log`, `qmp-sock` |
| `run-blackbox-fdp.sh` | BlackBox with a `femu-subsys` that has FDP on, 4 handles, 1 reclaim group ([FDP](../features/fdp.md)) | 4 vCPUs, 4 GiB | `/tmp/femu-fdp.log`, `qmp-sock` |
| `run-nossd.sh` | NoSSD, 4 GiB ([NoSSD](../modes/nossd.md)) | 4 vCPUs, 4 GiB | `qmp-sock` |
| `run-zns.sh` | ZNS, 4 GiB, QLC timing, 16 zones of 256 MiB ([ZNS](../modes/zns.md)) | 4 vCPUs, 4 GiB | `log`, `qmp-sock` |
| `run-whitebox.sh` | Open-Channel 2.0 (`OCVER=2` in the script; 1 selects 1.2), 4 GiB ([OCSSD](../modes/ocssd.md)) | 4 vCPUs, 4 GiB | `qmp-sock` |
| `run-csd.sh` | Computational storage, 4 GiB, 4 compute units ([CSD](../modes/csd.md)). It does not set `csd_program_dir`, so only the built-in program type loads | 4 vCPUs, 4 GiB | `log`, `qmp-sock` |
| `run-cxlssd.sh` | One `femu-cxl-ssd` below a CXL host bridge ([CXL SSD](../modes/cxl-ssd.md)) | 4 vCPUs, 4 GiB, no disk and no network unless you add them | `cxlssd-stats.log`, `cxlssd-io-N.log` and `cxlssd-spt.log` in `LOG_DIR` when the guest asks for them through `lsa-control` |

`run-blackbox.sh` also passes `FEMU_EXP_LOG`, `FEMU_SECRET` and
`FEMU_DUMP_LPN` through `sudo` to QEMU
([environment variables](properties.md#environment-variables)). The other
launchers pass no variables to QEMU.

`qmp-sock` is created by root in the current directory; `log` is written
by `tee` as you. Two launchers started from the same directory share them,
so start a second VM from another directory.

`run-cxlssd.sh` runs QEMU without `sudo` and adds its own arguments after
the ones it builds, so you append a boot disk, a network and a QMP socket on
its command line. Its settings are environment variables:

| Variable | Default | Sets |
| --- | --- | --- |
| `QEMU` | `./qemu-system-x86_64` | the QEMU binary |
| `CXL_SIZE` | `256M` | media size, a number followed by `M` or `G` |
| `CACHE_PAGES` | size in MiB / 20 x 256 | `cache-pages` |
| `CACHE_WAYS` | `1` | `cache-ways`; `full` means `CACHE_PAGES` |
| `BLOCKS_PER_PLANE` | 768 for 48G, 1536 for 96G, else 0 | `blocks-per-plane` |
| `CACHE_POLICY` | `fifo` | `cache-policy` |
| `DER` | `off` | `der` |
| `CYLON_KERNEL_ACK` | `off` | `cylon-kernel-ack` |
| `PREFETCH_DEGREE`, `PREFETCH_STRIDE` | `0`, `1` | `prefetch-degree`, `prefetch-stride` |
| `CHANNELS`, `LUNS_PER_CHANNEL`, `PAGES_PER_BLOCK` | `8`, `8`, `256` | NAND geometry |
| `READ_NS`, `PROGRAM_NS`, `ERASE_NS`, `CHANNEL_NS` | `40000`, `200000`, `2000000`, `0` | NAND timing |
| `GC_THRESHOLD`, `GC_THRESHOLD_HIGH` | `75`, `95` | GC thresholds |
| `FTL` | `on` | `ftl` |
| `LSA_CONTROL` | `on` | `lsa-control`; see [security](../concepts/security-and-limits.md#cxl-ssd-control-channel) |
| `CYLON_FIRST_TOUCH_PROGRAM`, `CYLON_FREE_WRITEBACK` | `off` | the matching properties |
| `LOG_DIR`, `LOG_LIMIT` | `.`, `64M` | `log-dir`, `log-limit` |
| `TRACEFS_DIR` | unset | `tracefs-dir`, only when set |
| `CXL_BACKEND` | `memory-backend-ram` | memory backend type and options |
| `ACCEL`, `CPU`, `CPUS`, `RAM` | `kvm`, `host`, `4`, `4G` | accelerator, CPU model, vCPUs, guest RAM |
| `DRY_RUN` | `0` | `1` prints the command instead of running it |

These defaults follow Cylon's launch script and differ from the device's
own defaults: one cache way instead of 16, a cache of size / 20 (3072 pages
for 256 MiB) instead of 1024 pages, 8x8 channels and LUNs instead of 4x4,
fixed `blocks-per-plane` for the 48G and 96G sizes, and `lsa-control` on
instead of off.

## Configuration files

| Script | What it does |
| --- | --- |
| `ssd-config.sh CONFIG [--device-only \| --check]` | Expands an INI-style file into `-device femu,...` arguments (and a `-device femu-subsys,...` for a `[subsys]` section). Keys are device property names; `mode = bbssd` and the like stand for `femu_mode`. With `--device-only` it omits the `-device` words; with `--check` it only validates. It checks keys against `-device femu,help` of the binary in `FEMU_BIN`, or of `build-femu/`, `build/` or `build-official/` under the source tree. |
| `ssd-config-test.sh [QEMU]` | Expands every file in `configs/`, starts QEMU with each and requires the device to come up, and checks that the parser rejects bad input. The binary is the argument, `FEMU_BIN`, or the first one found as above. CI runs it. |

The files in `configs/`:

| File | Device |
| --- | --- |
| `bbssd.conf` | BlackBox, 4 GiB, 8 channels of 8 LUNs |
| `bbssd-overprovisioned.conf` | BlackBox sized with `op_pcent=10` |
| `fdp.conf` | BlackBox with FDP on a `[subsys]` section |
| `heterogeneous.conf` | One controller with a BlackBox, a ZNS and a NoSSD namespace |
| `qlc.conf` | BlackBox with QLC per-page-type timing |
| `write-buffer.conf` | BlackBox with a 2048-page write buffer, `vwc=1` and Write Zeroes |
| `zns.conf` | ZNS, 16 zones of 256 MiB, at most 16 active and 8 open |

Run it from `build-femu/` with `FEMU_BIN` set. Through the
`../femu-scripts` link the script cannot find the binary on its own, and
then it skips the key check:

```sh
FEMU_BIN=./qemu-system-x86_64 ../femu-scripts/ssd-config.sh ../femu-scripts/configs/zns.conf
```

The launchers take no arguments. To boot a config, copy a launcher and put
the output in place of its `-device femu` option, or call QEMU yourself:

<!-- femu-untested: the options come from ssd-config.sh, which ssd-config-test.sh checks in CI -->
```bash
QEMU_ARGS=$(FEMU_BIN=./qemu-system-x86_64 ../femu-scripts/ssd-config.sh my-ssd.conf)
./qemu-system-x86_64 -enable-kvm -cpu host -smp 4 -m 4G $QEMU_ARGS ...
```

The file format: keys are `femu` device properties and mean what
`-device femu,help` says. `#` and `;` start comments, section headers are
labels for the reader (except `[subsys]`), and a key with an empty value is
ignored. List values such as `namespace_modes = bbssd,znssd,nossd` get
their commas doubled for QEMU automatically.

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

A misspelled key stops the expansion when the binary is found:

```text
ssd-config: unknown property 'gc_polcy' -- not one FEMU accepts
ssd-config: config rejected; see the warnings above
```

## Guest-side test tools

Copy these into the guest and run them there. The C programs build with
`gcc -O2 -o NAME NAME.c` and need no headers beyond libc.

| Tool | Arguments | What it checks |
| --- | --- | --- |
| `femu-test.sh` | `--yes [DEVICE]`, default `/dev/nvme0n1` | Data integrity, counters, deallocate, and zone or key-value commands, chosen by what the namespace reports. **It overwrites the whole namespace**, so `--yes` is required, and it refuses a mounted device. See [testing](../guides/testing.md#guest-side-tests). |
| `kv-probe.c` | `[CONTROLLER]`, default `/dev/nvme0` | A key-value Store, Exist, Retrieve, Delete and a Retrieve of the deleted key ([KV](../modes/kvssd.md)) |
| `aer-probe.c` | `[CONTROLLER]`, default `/dev/nvme0` | That crossing the temperature threshold completes an Asynchronous Event Request, and that the event is re-armed after the log is read |
| `zone-aen-probe.c` | `[CONTROLLER] [NAMESPACE]`, defaults `/dev/nvme0` `/dev/nvme0n1` | That a zone taken read only raises the Zone Descriptor Changed notice; needs a ZNS device with `err_write_fail_ppm` set ([ZNS](../modes/zns.md)) |
| `fdp-test-nvme-admin.sh` | none; uses `/dev/nvme0`, `/dev/nvme0n1` and `/dev/ng0n1` | The FDP admin commands of nvme-cli against the configuration `run-blackbox-fdp.sh` creates (4 handles, 1 reclaim group); written for a Linux 6.12 guest |

## Host tuning helpers

| Script | What it does |
| --- | --- |
| `ftk/qmp-vcpu-pin -s SOCKET CPU...` | Pins each vCPU thread to a host CPU with `taskset`, using QMP `query-cpus-fast` on `SOCKET`; vCPU i goes to the i-th CPU in the list, wrapping around. It imports `ftk/qmp.py`. Run it with `sudo` when QEMU runs as root. A Unix socket path longer than about 107 bytes fails with `AF_UNIX path too long`. |
| `pin.sh [FIRST_CPU]` | Pins each vCPU thread, then each `femu-poller`, `FEMU-FTL-Thread`, `femu-cxl-ftl` and `femu-cxl-cca`, to its own host CPU, starting at `FIRST_CPU` (default 0), and moves the other QEMU threads, `femu-csd-cu` included, to the CPUs after those. It finds the threads by name, so QEMU must run with `-name NAME,debug-threads=on` (the launchers pass it), and it finds QEMU with `pgrep -x qemu-system-x86`; set `QEMU_PID` when several run. Run it after the guest has booted: the pollers start when the guest enables the controller. It stops if the host has too few CPUs. See [performance tuning](../guides/performance-tuning.md#pin-the-threads). |
| `set_cpu_perf_mode.sh` | Sets every CPU's cpufreq scaling policy to `performance` through sysfs. Run it as root. |

## Documentation tooling

These run in CI. [docs-maintenance.md](../development/docs-maintenance.md)
explains each.

| Script | Arguments |
| --- | --- |
| `gen-property-docs.py` | `--qemu BINARY` regenerates `reference/properties.md` and `runtime-properties.md` from the binary; `--check` compares instead of writing (`--qemu` is still required) |
| `gen-mode-table.py` | rewrites the mode tables from `docs/modes.py`; `--check` compares and checks `modes.py` against the code |
| `check-doc-links.py` | `[--root DIR] [PATH...]`; checks every relative link and anchor |
| `check-doc-examples.py` | `--lint`, `--list`, `--self-test`, `--qemu BINARY`, `--qos-test BINARY`, `--only NAME`, `--timeout SEC`, `[PATH...]`; checks every code block's tag and runs the tagged examples |

## CXL caching API tools: `hw/femu/tools/cca/`

Guest code for `femu-cxl-ssd,cca=on`. `make -C hw/femu/tools/cca` in the
guest builds `libcca.a`, the `ccactl` command and the `cca-test` self-test.
`run-guest-tests.sh [-d MEMDEV] [-x DAX] [-o LOG] [CASE...]` builds them and
runs the self-test as root, logging to `cca-guest-YYYYMMDD-HHMMSS.log` by
default.
See [the caching API guide](../features/cxl-cca.md) and the
[tool README](../../tools/cca/README.md).

## Legacy scripts

None of these start FEMU. Several hard-code paths on one lab machine
(`/home/huaicheng/images`), the old `x86_64-softmmu/qemu-system-x86_64`
binary, or a `u14s.qcow2` image.

| Script | What it was for |
| --- | --- |
| `femu-run.sh`, `m.sh`, `s1.sh`, `s2.sh` | Start a VM with QEMU's stock `-device nvme` |
| `f.sh`, `dp.sh`, `dp-run.sh`, `ide-run.sh`, `virtio-run.sh`, `null-run.sh` | Start a VM with a raw, tmpfs-backed, IDE, virtio-blk or null data disk instead of FEMU, for comparison runs |
| `gdb-run.sh` | Start the stock `nvme` device under gdb; see [debugging](../guides/debugging.md#run-femu-under-gdb) for a version that runs FEMU |
| `valgrind-run.sh` | Start the stock `nvme` device under valgrind, with properties that no longer exist |
| `aff.sh PID` | Pin 20 consecutive thread IDs starting at `PID` to CPUs 5 to 24 |
| `getaff.sh` | Print the CPU affinity of every thread of every `qemu` process |
| `pre.sh` | Turn off address space randomization, format `/dev/nvme0n1` with ext4 and mount it for one lab user. **Destroys data** |
| `pre-all.sh` | Run `pre.sh` and network setup over SSH on three named lab hosts |
| `tuning.sh` | Stop a list of services on one lab machine |

One more NoSSD launcher, and a benchmark harness in a subdirectory of
`hw/femu/scripts/` with its own README, are not covered here.

## Related pages

- [Build](../getting-started/build.md)
- [Guest image](../getting-started/guest-image.md)
- [Performance tuning](../guides/performance-tuning.md)
- [Testing](../guides/testing.md)
