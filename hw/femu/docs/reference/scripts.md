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
| `femu-compile.sh` | `build-femu/` | Runs `make clean`, then `../configure --enable-kvm --target-list=x86_64-softmmu --enable-slirp --disable-libnfs --disable-libiscsi --disable-curl`, then `make` with one job per CPU. `--enable-csd-ubpf` adds uBPF CSD programs, `--enable-csd-ubpf=PATH` uses the uBPF tree at `PATH`, and `--werror` makes a compiler warning fail the build. Without that flag the script disables warnings as errors, since a newer compiler can warn in QEMU code. Any other argument is an error. See [build.md](../getting-started/build.md). |
| `build-guest-kernel.sh` | the FEMU tree, `OUTDIR` | Downloads Linux 6.12.117, checks its SHA-256, merges `tests/functional/guest.config` into `tinyconfig` and builds `OUTDIR/bzImage`. It fails when an option of the fragment does not stay `=y`. Needs `libelf-dev`, `flex`, `bison` and `bc`. See [guest boot test](../guides/testing.md#guest-boot-test). |
| `build-guest-initramfs.sh` | the FEMU tree, `OUTDIR` | Builds `OUTDIR/initramfs.cpio.gz` from a static busybox (`BUSYBOX=`, default `/usr/bin/busybox`), the static `femu-guest-check` helper and `tests/functional/init`. |
| `femu-copy-scripts.sh` | `build-femu/` | Copies `pkgdep.sh`, `femu-compile.sh`, `make-guest-image.sh`, `run-guest-ssh.sh`, the `run-blackbox.sh`, `run-blackbox-fdp.sh`, `run-whitebox.sh`, `run-nossd.sh`, `run-zns.sh`, `run-csd.sh` and `run-kvssd.sh` launchers, `pin.sh` and `ftk/` into the current directory, overwriting earlier copies. It does not copy `run-cxlssd.sh`, `ssd-config.sh`, `configs/` or the guest tools; run those from `../femu-scripts/`. |

## Guest image and access

| Script | What it does | Arguments and environment |
| --- | --- | --- |
| `make-guest-image.sh` | Builds an Ubuntu 24.04 guest image from a pinned cloud image serial. It checks the download against a pinned SHA-256 and Ubuntu's SHA256 sums, and their signature when `gpgv` and the Ubuntu keyring are installed, with user `femu`, an SSH key, a serial console, `nvme-cli`, `fio` and the kernel you ask for. A second boot checks the kernel and the tools. It writes a standalone qcow2 with a `.sha256` and a `.manifest`. Needs no root, but needs access to `/dev/kvm` unless you pass `--no-kvm`. See [guest-image.md](../getting-started/guest-image.md). | `-o DIR` output directory, `-n FILE` image name (default `u20s.qcow2`, the name the launchers expect), `-s SIZE` (default `32G`), `-k FILE` public key, `-p PW` console password, `--kernel VERSION` (`distro`, an Ubuntu ABI such as `6.8.0-31`, or a mainline version such as `6.12.40`; mainline needs `genisoimage`, `xorriso` or `mkisofs`), `--base-serial S` (`YYYYMMDD[.N]` or `latest`), `--base-sha256 HEX`, `--cache DIR`, `--compress`, `--cxl` adds `ndctl`, `daxctl` and `cxl-cli`, `--packages LIST` extra packages, `--qemu PATH`, `--qemu-img PATH`, `--no-kvm`, `--timeout SEC` per boot (default 1800), `-f` replace an existing image, `--self-test` checks the parsers and exits. Reads `IMGDIR` (default output directory `$HOME/images`), `QEMU` and `QEMU_IMG`. |
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
| `FEMU_MACHINE` | `pc-i440fx-10.1` | Machine type; a versioned name keeps the guest view the same on a new QEMU base |

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
| `run-kvssd.sh` | Key-value SSD, 4 GiB of value space on the BlackBox geometry ([KV](../modes/kvssd.md)); the guest needs Linux 6.0 or newer | 4 vCPUs, 4 GiB | `log`, `qmp-sock` |
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
| `BLOCKS_PER_PLANE` | 867 for 48G, 1732 for 96G, else 0 | `blocks-per-plane` |
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
| `FEMU_MACHINE` | `pc-q35-10.1` | machine type; `cxl=on,smm=off` is added |
| `DRY_RUN` | `0` | `1` prints the command instead of running it |

These defaults follow Cylon's launch script and differ from the device's
own defaults: one cache way instead of 16, a cache of size / 20 (3072 pages
for 256 MiB) instead of 1024 pages, 8x8 channels and LUNs instead of 4x4,
fixed `blocks-per-plane` for the 48G and 96G sizes (the least the device
accepts; Cylon's sizes have no spare blocks), and `lsa-control` on
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
| `csd.conf` | Computational storage, the device of `run-csd.sh` without its no-effect scheduler properties |
| `fdp.conf` | BlackBox with FDP on a `[subsys]` section |
| `heterogeneous.conf` | One controller with a BlackBox, a ZNS and a NoSSD namespace |
| `kvssd.conf` | Key-value SSD, the device of `run-kvssd.sh` |
| `nossd.conf` | NoSSD with link and firmware time from the NVMeCHA controller ([NoSSD](../modes/nossd.md#host-link-and-controller-firmware)) |
| `ocssd.conf` | Open-Channel 2.0, the device of `run-whitebox.sh`; `lver = 1` selects 1.2 |
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
| `kv-bench.c` | `[OPTIONS] NODE`, the generic node such as `/dev/ng0n1`; build with `gcc -O2 -pthread` | A key-value workload of Store, Retrieve, Delete, Exist and List with the kvbench knobs (`--keys`, `--key-len`, `--values`, `--ratio`, `--mix`, `--threads`). It checks each answer against a model of the keys and prints the rate and latency of each command. `--control legacy-opcodes` or `corrupt-model` makes it fail on purpose. Needs an empty namespace and deletes its keys at the end. Exits 1 on an error or a mismatch. See [KV benchmark](../guides/testing.md#kv-benchmark). |
| `aer-probe.c` | `[CONTROLLER]`, default `/dev/nvme0` | That crossing the temperature threshold completes an Asynchronous Event Request, and that the event is re-armed after the log is read |
| `zone-aen-probe.c` | `[CONTROLLER] [NAMESPACE]`, defaults `/dev/nvme0` `/dev/nvme0n1` | That a zone taken read only raises the Zone Descriptor Changed notice; needs a ZNS device with `err_write_fail_ppm` set ([ZNS](../modes/zns.md)) |
| `fdp-test-nvme-admin.sh` | none; uses `/dev/nvme0`, `/dev/nvme0n1` and `/dev/ng0n1` | The FDP admin commands of nvme-cli against the configuration `run-blackbox-fdp.sh` creates (4 handles, 1 reclaim group); written for a Linux 6.12 guest |
| `blktests-guest.sh` | `GROUP [DEVICE]`, default device `/dev/nvme0n1`; reads `BLKTESTS_REPO`, `BLKTESTS_REF` and `WORKDIR` (parent of a new scratch directory, default `/tmp`) | Clones, builds and runs one blktests group against the namespace, and prints the counts of passed, failed and not run tests. Exits 1 when a test that ran on the namespace failed or the run stopped early, and 2 when the setup failed. Needs network access and writes to the namespace. See [conformance suites](../guides/testing.md#conformance-suites). |
| `nvme-cli-e2e-guest.sh` | `[CONTROLLER [NAMESPACE]]`, defaults `/dev/nvme0` `/dev/nvme0n1`; reads `NVMECLI_REPO`, `NVMECLI_REF` (default `v3.1`), `E2E_TIMEOUT` and `WORKDIR` (parent of a new scratch directory, default `/tmp`) | Builds nvme-cli and runs its end-to-end suite. Exits 1 when a test failed or the suite ended abnormally, and 2 when the setup failed. A failure of `test_get_lba_status` counts as a known nvme-cli defect only when the same command passes with the numeric namespace ID. Needs network access, writes to the namespace and can format it. |
| `zenfs-crash-guest.sh` | `[NAMESPACE]`, default the first host-managed zoned namespace; reads `ROCKSDB_REPO`, `ROCKSDB_REF` (default `v9.10.0`), `ZENFS_REPO`, `ZENFS_REF` (default `919c2eb`), `ZENFS_PREFIX`, `ZENFS_JOBS`, `ZENFS_ROUNDS`, `ZENFS_INTERVAL`, `ZENFS_THREADS`, `ZENFS_KEYS`, `ZENFS_CONTROL` and `WORKDIR` | Builds RocksDB with ZenFS and runs the RocksDB blackbox crash test on the namespace: rounds of `db_stress` killed with SIGKILL, then a final check of every key. Exits 1 when a round or the final check failed, and 2 when the setup failed. `ZENFS_CONTROL=reset-zones` makes it fail on purpose. Needs network access and formats the namespace with ZenFS. See [ZenFS crash test](../guides/testing.md#zenfs-crash-test). |
| `kv-bench-guest.sh` | `[NODE]`, default the one `/dev/ngXnY` without a block device; reads `KVBENCH_KEYS`, `KVBENCH_OPS`, `KVBENCH_THREADS`, `KVBENCH_SEED`, `KVBENCH_CONTROL` and `WORKDIR` | Builds `kv-probe.c` and `kv-bench.c` from its own directory, runs `kv-probe`, then a small-value and a large-value `kv-bench` run. Exits 1 when a check failed and 2 when the setup failed. See [KV benchmark](../guides/testing.md#kv-benchmark). |
| `recipe-dlio-guest.sh` | `--yes [NAMESPACE]`, default `nvme0n1`; reads `DLIO_REPO`, `DLIO_REF` (default `v2.0.1`), `DLIO_PREFIX`, `DLIO_FILES`, `DLIO_RECORD_BYTES`, `DLIO_EPOCHS`, `DLIO_BATCH`, `DLIO_COMPUTE_SEC`, `DLIO_MODEL_BYTES`, `DLIO_TIMEOUT`, `DLIO_INSTALL_TIMEOUT`, `DLIO_CONTROL` and `WORKDIR` | Installs the DLIO benchmark, makes an ext4 file system on the namespace, writes a dataset, then reads it with `O_DIRECT` and writes checkpoints. It checks that the block layer counts and the C0h counters moved by the size of each phase. The last line is `DLIO_RESULT=PASS`, `FAIL` or `SETUP-ERROR`; the exit status is 0, 1 or 2. Needs network access and `recipe-guest-lib.sh` in its directory. Not yet validated on a host. See [the DLIO recipe](../recipes/dlio.md). |
| `recipe-diskann-guest.sh` | `--yes [NAMESPACE]`, default `nvme0n1`; reads `DISKANN_REPO`, `DISKANN_REF` (default `0.7.0`), `DISKANN_PREFIX`, `DISKANN_JOBS`, `DISKANN_POINTS`, `DISKANN_DIM`, `DISKANN_QUERIES`, `DISKANN_LISTS`, `DISKANN_THREADS`, `DISKANN_SEARCH_GB`, `DISKANN_BUILD_GB`, `DISKANN_TIMEOUT`, `DISKANN_INSTALL_TIMEOUT`, `DISKANN_CONTROL` and `WORKDIR` | Builds DiskANN, makes an ext4 file system on the namespace, builds a disk index of random vectors on it and runs queries. It checks that the index writes and the query reads reached the device. The last line is `DISKANN_RESULT=PASS`, `FAIL` or `SETUP-ERROR`; the exit status is 0, 1 or 2. Needs network access and `recipe-guest-lib.sh` in its directory. Not yet validated on a host. See [the DiskANN recipe](../recipes/diskann.md). |
| `recipe-kv-offload-guest.sh` | `--yes [NAMESPACE]`, default `nvme0n1`; reads `KVO_FDP`, `KVO_RUNTIME`, `KVO_CONTROL` and `WORKDIR` | Fills the raw namespace, runs `fio/gpu-kv-offload-fdp.fio` with or without FDP placement, and reads log page C0h and the FDP statistics around the run. It checks that the stores reached the FTL. The last line is `KVO_RESULT=PASS`, `FAIL` or `SETUP-ERROR`; the exit status is 0, 1 or 2. Needs fio 3.34 or newer, `fio/gpu-kv-offload-fdp.fio` and `recipe-guest-lib.sh` next to it. It installs nothing. Not yet validated on a host. See [the KV-cache offload recipe](../recipes/kv-cache-offload.md). |
| `recipe-guest-lib.sh` | none; the three recipe scripts source it | The shared functions of the recipe scripts: the verdict line, the namespace checks, and the samples of log page C0h and of the block layer counts. |

Run this one on the host:

| Script | What it does | Arguments and environment |
| --- | --- | --- |
| `guest-conformance.sh` | Boots a guest for each suite with a fresh overlay of the guest image, runs the suite's guest script in it over SSH, stops the guest and prints `RESULT SUITE PASS`, `FAIL` or `SETUP-ERROR`. An SMBIOS string checks that the SSH port reaches this guest. It refuses an overlay or PID file that an earlier run left in the result directory. CI does not run it. See [conformance suites](../guides/testing.md#conformance-suites). | Suites `blktests-block`, `blktests-zbd`, `nvme-cli`, `zenfs-crash`, `kv-bench` or `all`. Options `--qemu PATH` (default `./qemu-system-x86_64`), `--image FILE`, `--key FILE`, `--port N` (default 8090), `--outdir DIR`, `--timeout SEC` (default 7200 for `zenfs-crash`, else 3600), `--boot-timeout SEC` (default 300), `--device PROPS` (the FEMU properties for a control run), `--smp N` and `--mem SIZE` (default 16 and `16G` for `zenfs-crash`, else 4 and `4G`), `--sudo`, `--keep`. Reads `QEMU`, `IMGDIR`, `OSIMGF`, `SSH_KEY`, `SSH_PORT` and `FEMU_MACHINE` (default `pc-i440fx-10.1`), and passes the `BLKTESTS_*`, `NVMECLI_*`, `ROCKSDB_*`, `ZENFS_*` and `KVBENCH_*` variables that `--help` lists to the guest. Exits 0 when every suite passed, 1 when a suite failed, and 2 when a suite could not run and no suite failed. |
| `csd-pause-check/run.sh` | Boots a small KVM guest from a kernel and a busybox initramfs twice, with `csd_pause` off and on. In the guest, `csdlat.c` times Execute of a program that sleeps on the host, and `clockcheck.c` counts clock steps back on each vCPU, sleeps that end early, and the gap between the TSC and the kvmclock. Prints both results; it checks nothing itself. See [CSD](../modes/csd.md#hide-the-host-run-time-csd_pause). | `QEMU KERNEL MODDIR OUTDIR [VCPUS]`: a FEMU binary, a guest bzImage, its `/lib/modules/<version>` for `nvme.ko` or `none`, an output directory, and the vCPU count (default 4). Needs `gcc` with static glibc, a static `busybox`, `cpio` and `gzip`. |

## Host monitoring tools

Run these on the host, against a running or a dry-run QEMU. They need
Python 3 and no other package.

| Script | What it does | Arguments |
| --- | --- | --- |
| `femu-config-check.py` | Starts QEMU under qtest with the given options and no guest, then reports either FEMU's refusal or the configuration it builds: capacity, geometry, over-provisioning, line or reclaim unit size, zones, mode and NAND timing per namespace, and QEMU's warnings. `--manifest FILE` also writes the host, the build and the source of each property value. See [check a configuration](../guides/debugging.md#check-a-configuration-without-a-guest). | `[--json] [--manifest FILE] [--qemu BINARY] [--timeout SEC] [--] QEMU-OPTIONS`, or the value of one `-device` option; `--self-test` checks the tool. Exits 0 accepted, 1 refused, 2 when the check failed. It loads `femu-stat.py` from its own directory. |
| `femu-steady-state.py` | Reports the first round where a series of per-round results is at steady state, by the SNIA PTS rule: over the last 5 rounds, the spread is at most 20% and the least-squares trend at most 10% of the average. See [repeatable numbers](../guides/measuring.md#repeatable-numbers). | `[--window W] [--excursion P] [--slope P] [--column N] [--metric iops\|bw\|lat_mean] [--json] [FILE...]`: fio JSON outputs, one per round, or one value per line; `--self-test` checks the tool. Exits 0 steady, 1 not steady, 2 on an input error. |
| `femu-trace2csv.py` | Turns the `femu_cqe` lines of a QEMU trace log (`-trace femu_cqe -D femu.log`) into a CSV I/O trace: ISO 8601 time (`-msg timestamp=on`), completion queue, command ID, opcode, starting LBA, blocks, status and modelled time. | `[LOG]` (stdin when absent); `--self-test` checks the parser. |
| `femu-trace2fio.py` | Checks an `io_trace` CSV file line by line, prints a shape report (command mix, request sizes, queues, depth between fetch and CQE, gaps between fetches, bursts, sequential share) and writes an fio version 3 I/O log for `fio --read_iolog`. A wrong line stops it with the line number. It counts each command that it cannot replay. See [trace replay and I/O shapes](../guides/trace-replay.md). | `--block-size BYTES [--nsid N] [--device-size BYTES] [--iolog OUT --filename PATH] [--time-scale F] [--lba-scale F] [--strict] [--buckets N] [--burst-gap NS] TRACE` (`-` is stdin); `--self-test` plants faults and compares the output of a built-in trace. Exit status 1 for a trace that fails a check. |
| `femu-trace-import.py` | Turns a public trace into an `io_trace` file for `femu-trace2fio.py`: MSR Cambridge and Tencent CBS (SNIA IOTTA), Alibaba block traces 2020, and Meta CacheLib key-value traces through a FIFO flash cache model. It selects one volume, rounds byte ranges to whole blocks, splits ranges above 65536 blocks and folds a large volume onto the device. A bad line stops it with the line number. See [import a public trace](../guides/trace-replay.md#import-a-public-trace). | `--format msr\|alibaba\|tencent\|cachelib --block-size BYTES --device-size BYTES --out OUT [--volume ID] [--fold none\|wrap\|scale] [--volume-size BYTES \| --volume-sizes FILE] [--time-unit U] [--spread] [--rate N] [--duration SEC] [--limit N] [--max-bad N] TRACE` (`--time-unit` is necessary for tencent and for a cachelib `op_time` column) (`-` is stdin, `.gz` is read as gzip); `--list-volumes`; `--self-test` converts the fixtures in `trace-fixtures/`. Exit status 1 for a trace that fails a check. |
| `femu-prom.py` | Serves the `query-femu` counters of every `femu` device of a running VM at `/metrics` in the Prometheus text format: page and erase counters, WAF and line counts, labelled by device and namespace. Each scrape reads the device again. It loads `femu-stat.py` from its own directory. | `SOCKET`, `--port PORT` (9813), `--bind ADDR` (127.0.0.1), `--once` prints one exposition; `--source query-stats` reads every device with one [`query-stats`](query-stats.md) call instead, which does not wait for the FTL thread; `--self-test` renders canned replies without QEMU. |
| `femu-stat.py` | Shows the FTL counters of each `femu` device of a running VM, like `top`: pages, WAF since start and over the interval, rates, line, reclaim unit and zone counts, and I/O stage times. It polls QMP `query-femu` and `query-femu-stages` and never resets the counts. See [live counters](../guides/measuring.md#live-counters-on-the-host-femu-stat). | `SOCKET` (a Unix socket path or `HOST:PORT`), `--interval SEC`, `--count N`, `--once`, `--json`, `--ns LIST`, `--path QOMPATH`; `--self-test --qemu BINARY` checks the tool under qtest. Exits 2 on a connection error. |

## Workload shapes: `hw/femu/scripts/fio/`

fio job files for the I/O shapes of an accelerator workload. Run them in
the guest with `FEMU_DEV` set to the NVMe generic character device, for
example `FEMU_DEV=/dev/ng0n1 fio gpu-model-load.fio`. Each job has a
fixed rate limit. See
[trace replay and I/O shapes](../guides/trace-replay.md#io-shapes-of-an-accelerator-workload).

| File | Shape | Limit per job |
| --- | --- | --- |
| `fio/gpu-model-load.fio` | model and dataset load: 4 jobs, sequential 1 MiB reads | `rate=16m` |
| `fio/gpu-small-random-read.fio` | vector search and graph sampling: 8 jobs, random 512 B and 4 KiB reads in bursts of 64 | `rate_iops=300` |
| `fio/gpu-checkpoint-burst.fio` | checkpoint: 1 MiB sequential writes for 2 s, then a pause of 8 s | `rate=32m` |
| `fio/gpu-kv-offload.fio` | KV-cache offload: entries of 4 MiB, one store job and one load job | `rate=16m` (store), `rate=32m` (load) |
| `fio/gpu-kv-offload-fdp.fio` | KV-cache offload of two tenants, with placement (`FEMU_FDP=1`) or with none (`FEMU_FDP=0`); also needs `FEMU_RUNTIME` in seconds | `rate=24m` and `rate=8m` (stores), `rate=32m` (load) |

| Script | What it does | Arguments |
| --- | --- | --- |
| `check-fio-jobs.py` | Checks that each job of each file has a `rate` or `rate_iops` value above zero for each direction that its `rw` option uses. It also fails a limit that is not a plain number, `rate` with `rate_iops`, `rate_iops` as the only limit of a job with mixed request sizes, `include` and the replay options. It reads files only, not the fio command line. CI runs it. | `[FILE...]` (default: `fio/*.fio`); `--self-test` plants faults. |

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
| `gen-property-docs.py` | `--qemu BINARY` regenerates `reference/properties.md`, `runtime-properties.md` and the `properties.snapshot` snapshot from the binary; `--check` compares instead of writing (`--qemu` is still required); `--schema FILE` also writes a JSON Schema (draft 2020-12) of each device's own properties: JSON type, integer range, default, description, QOM type and topic |
| `gen-combinations.py` | rewrites `reference/combinations.md` from the refusal messages in `hw/femu`; `--check` compares instead of writing; `--self-test` checks the parser |
| `gen-mode-table.py` | rewrites the mode tables from `docs/modes.py`; `--check` compares and checks `modes.py` against the code |
| `check-doc-links.py` | `[--root DIR] [PATH...]`; checks every relative link and anchor |
| `check-changelog-hashes.py` | `[--head COMMIT] [FILE]`; checks that every commit the CHANGELOG names is in the history of `--head` (needs a full clone) |
| `check-c-style.py` | `[DIR]` (default `hw/femu`) or `--self-test`; finds C99 comments and trailing whitespace in `.c` and `.h` files, and fails on a tree with no source file |
| `check-patches.sh` | `BASE HEAD` or `--self-test`; runs QEMU's `scripts/checkpatch.pl` on each commit in `BASE..HEAD`, merges left out: an ERROR or a git or checker failure fails, a WARNING is printed in full. A base of all zeros (a new branch) checks HEAD alone; binary or mode-only commits are skipped. A commit titled `Rebase FEMU onto QEMU X.Y.Z` is checked under `hw/femu/` only, since the rest is upstream QEMU code. Its `VERSION` file must hold `X.Y.Z`. CI runs it on the commits of each push and pull request |
| `qemu-canary.py` | `FEMU_REV QEMU_REV OUTDIR`, `--base REV` or `--self-test`; merges FEMU with a newer QEMU (a three-way merge on the QEMU base that `VERSION` names) and writes `OUTDIR/report.txt` and the merged tree in `OUTDIR/src`. Two lists in the script hold the FEMU policy: QEMU files that FEMU does not ship, and QEMU submodules that FEMU ships as directories. A conflict on any other path makes the result red (exit 1). It uses no network |
| `check-property-tests.py` | no argument or `--self-test`; checks that a file under `tests/` or `scripts/` names each property in `reference/properties.md`, or that `tests/untested-properties.list` lists it with a reason |
| `check-property-compat.py` | `OLD NEW`, `--release TAG --published FILE` or `--self-test`; compares `reference/properties.snapshot` at two commits, and fails on a removed property or a new type, default or kind that `reference/interface-changes.list` does not record; `--release` compares a tag with the newest published release before it (FILE lists the published tags) and checks the deprecation period; CI and the release check run it |
| `femu-symbol-map.py` | `OLD NEW [--kind K,K] [--all] [--json] [--summary] [--touched A..B]` or `--self-test`; reads two git revisions and prints what became of each old file, function, struct, field, enum constant, macro and property: moved, split, redefined (other parameter types), a renamed candidate with the commit that removed the old name, removed, or a changed default or enum value; `--touched` keeps the names a fork's diff uses ([porting an old fork](../guides/porting-old-forks.md)); CI runs the self-test |
| `release-notes.py` | `TAG`, `--check` or `--self-test`; prints the changelog section of a release tag, or checks the changelog layout (an Unreleased section first, then releases newest first); CI and the release check run it |
| `check-container.py` | no argument, `--root DIR` or `--self-test`; checks that `hw/femu/container/Containerfile` pins its base image by digest and `UBUNTU_SNAPSHOT` by a fixed default, installs the CI build list plus a fixed set of extras, and that `.devcontainer/devcontainer.json` and `.dockerignore` match it. See [container.md](../getting-started/container.md) |
| `check-unit-tests.py` | no argument, `--meson-names`, `--listed FILE` or `--self-test`; checks that each `tests/unit/test-*.c` is in `tests/meson.build` or `tests/Makefile`, and that the `femu-unit` suite lists every meson unit test |
| `check-doc-examples.py` | `--lint`, `--list`, `--self-test`, `--qemu BINARY`, `--qos-test BINARY`, `--only NAME`, `--timeout SEC`, `[PATH...]`; checks every code block's tag and runs the tagged examples |

## Teaching labs: `hw/femu/scripts/labs/`

The scripts of the [teaching labs](../labs/README.md). The `lab-*.sh`
scripts run in the guest, as root, on a fresh device. Each one prints a
last line that starts with `LAB` and the lab number. They need fio,
nvme-cli and Python 3.

| Script | Arguments and environment | What it does |
| --- | --- | --- |
| `lab-common.sh` | sourced by the others; `LAB_CTRL` (default `/dev/nvme0`), `LAB_NS` (default `/dev/nvme0n1`), `LAB_DIR` (default `./lab-out`) | Reads the C0h counters, prints their differences and the WAF of an interval, switches the NAND time off with vendor command 0xEF, and checks the host page count against the bytes fio wrote |
| `lab-gc-waf.sh` | `[fio options]`; `LAB_TIME=on` keeps the NAND time, `LAB_IO` (default `4G`) | Lab 1: fill, age, then measure one run of random 4 KiB writes |
| `lab-hot-cold.sh` | `uniform`, `zipf` or `hot80` | Lab 2: the method of lab 1 with one of three write distributions |
| `lab-dftl.sh` | `LAB_WS` (default `256 768 1024`), `LAB_WARM_MB` (32), `LAB_READ_MB` (128), `LAB_WRITE_MB` (256) | Lab 3: fill, then random reads over each working set, then random writes; prints the translation page reads and programs, the miss ratio and the read latency |
| `lab-fdp.sh` | `fdp` or `untagged`, then `all`, `prefill` or `run`; `LAB_NG` (default `/dev/ng0n1`) | Lab 4: the two-region job of tutorial 04, with or without placement |
| `lab-waf-model.py` | `uniform`, `classes`, `dftl` or `--self-test`; runs on the host | The paper models of the labs: the FIFO log with the FEMU GC thresholds, the classes model, and the CMT miss ratio |

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
