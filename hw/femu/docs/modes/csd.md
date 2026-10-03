# Computational storage (CSD)

CSD mode (`femu_mode=4`) emulates a computational storage drive. On top of a
normal NVMe namespace, the device has its own memory (function data memory,
FDM) and compute units that run programs next to the data. The guest
allocates device memory, copies namespace data into it, loads and runs a
program, and reads the result back, all with NVMe commands. Ordinary reads
and writes go through the [BlackBox](blackbox.md) FTL, so they have SSD
timing.

The mode is a port of [CEMU](https://github.com/cs-qyzhang/CEMU); if you use
it, cite CEMU as well as FEMU ([citation](#citation)). It does not need
CEMU's modified guest kernel, FDMFS or a fixed VM image. CEMU's VM freezing
and virtual clock changes are left out of this port.

Use it to study offloading filters, scans, compression or other kernels to
the drive, and what that does to latency and host CPU use.

## Requirements

- Host and guest: see [the mode table](../concepts/choosing-a-mode.md#every-mode-at-a-glance)
  and [requirements.md](../getting-started/requirements.md#kernel-per-mode).
  Any guest kernel with the NVMe driver works.
- Guest tools: `hw/femu/tests/csd`, built in the guest with a C compiler.
  The image from `make-guest-image.sh` has none; add one with
  `./make-guest-image.sh --packages build-essential`, or run
  `sudo apt install build-essential` in the guest.
- Programs: shared-library programs are built on the host and placed in the
  directory named by `csd_program_dir`. eBPF programs also need a FEMU build
  with uBPF (`./femu-compile.sh --enable-csd-ubpf`, see
  [build.md](../getting-started/build.md#csd-with-ubpf-programs)) and clang
  with the BPF target on the host.

## Security: programs run inside QEMU on the host

A program load names a file. QEMU, on the host, opens that file and runs
code from it inside the QEMU process. The `run-*.sh` launchers start QEMU
with `sudo`, so that code runs as root on the host.

FEMU limits what the guest can name:

- With `csd_program_dir` unset, only the built-in phantom program type
  loads. Shared-library and eBPF loads fail.
- With it set, the guest may name only a file in that directory: no `/`, no
  `..`, and the path must still resolve inside the directory after symbolic
  links are followed.

That protects the rest of the host file system. It does not make the
programs in the directory safe: they run on QEMU's compute unit threads with
all of QEMU's privileges and memory. Use CSD only with guests you trust, put only
programs you built and trust in the directory, and make sure no one else can
write to it.

## Launch

From `build-femu/`:

<!-- femu-example: csd-launcher -->
```bash
./run-csd.sh
```

The FEMU device in that script is:

<!-- femu-example: csd-device -->
```
-device femu,devsz_mb=4096,namespaces=1,femu_mode=4,secsz=512,secs_per_pg=8,pgs_per_blk=256,blks_per_pl=256,pls_per_lun=1,luns_per_ch=8,nchs=8,pg_rd_lat=40000,pg_wr_lat=200000,blk_er_lat=2000000,ch_xfer_lat=0,gc_thres_pcent=75,gc_thres_pcent_high=95,fdm_size=64,nr_cu=4,nr_thread=4,time_slice=200000,context_switch_time=200,csf_runtime_scale=3
```

The preset `hw/femu/scripts/configs/csd.conf` describes the same device
without the three scheduler properties that have no effect.
[`ssd-config.sh`](../tutorials/09-ssd-config-files.md) expands it to:

<!-- femu-example: csd-preset -->
```
-device femu,id=nvme0,devsz_mb=4096,namespaces=1,secsz=512,secs_per_pg=8,pgs_per_blk=256,blks_per_pl=256,pls_per_lun=1,luns_per_ch=8,nchs=8,pg_rd_lat=40000,pg_wr_lat=200000,blk_er_lat=2000000,gc_thres_pcent=75,gc_thres_pcent_high=95,fdm_size=64,nr_cu=4,csf_runtime_scale=3,femu_mode=4
```

`run-csd.sh` does not set `csd_program_dir`, so it runs phantom programs
only. To load your own programs, add the directory after the other
`FEMU_OPTIONS` lines in `run-csd.sh`:

```sh
FEMU_OPTIONS=${FEMU_OPTIONS}",csd_program_dir=$HOME/csd-programs"
```

The shortest device line with programs enabled is:

<!-- femu-example: csd-programs -->
```
-device femu,devsz_mb=4096,femu_mode=4,fdm_size=64,csd_program_dir=/home/you/csd-programs
```

FEMU does not check the directory at start-up. A directory that does not
exist makes every program load fail.

## Configuration

Properties: [CSD](../reference/properties.md#csd-computational-storage).
The BlackBox geometry, timing, GC and FTL properties also apply to the
namespace; see the [BlackBox guide](blackbox.md#configuration).

- `fdm_size`: device memory in MiB. Required.
- `nr_cu`: compute units, 1 to 64. Each is a host thread, `femu-csd-cu`,
  that runs programs. A program waits for the first free unit.
- `csf_runtime_scale`: a program that declares no run time and no scale of
  its own holds its unit for its measured host run time times this value
  (default 3).
  A completion carries the program's result, so it never arrives before the
  host has run the program: a run time, declared or scaled, shorter than the
  host's own is not reached. QEMU warns once when that happens.
- `csd_program_dir`: the host directory programs load from.
- `nr_thread`, `time_slice` and `context_switch_time` are accepted so CEMU
  configurations still start. They have no effect, and a value other than
  the default prints a warning at realize.

A copy from the namespace into device memory costs one `pg_rd_lat`,
whatever its size, when any page of the range has been written, and nothing
otherwise. See the
[timing model](../concepts/timing-model.md#kv-and-csd).

### Program types

| Type | What runs | Needs |
| --- | --- | --- |
| Phantom | Built in: copies the input memory range to the output range. Useful to test the command flow and timing. | nothing |
| Shared library | A function with the signature `int64_t fn(struct femu_csd_args *args)` from a `.so` file, named in the load command. | `csd_program_dir` |
| uBPF | An eBPF ELF object, interpreted or JIT-compiled. | `csd_program_dir` and a build with `--enable-csd-ubpf` |

### How programs run

An Execute command is checked on the poller and then handed to one of the
`nr_cu` compute unit threads, which runs the program and posts the
completion. While a program runs, I/O on every queue, other CSD commands
and admin commands go on as usual; only that compute unit is busy.

- At most `nr_cu` programs run at once. Runs of one program take turns, so
  a shared library needs no locking of its own; different programs run
  side by side, and a run waiting for its own program leaves the compute
  unit free for another.
- A program that never returns keeps its compute unit for good, and QEMU
  waits for it when the device is removed. FEMU cannot stop native code it
  has called.
- Device memory a program is using stays allocated, and counted against
  `fdm_size`, until the program returns, even after Free device memory.
- Deleting the I/O queue an Execute came from, or resetting the controller,
  while the program runs drops its result; the program still runs to the
  end.

### Commands

I/O commands on the namespace:

| Opcode | Command |
| --- | --- |
| 0xb0 | Allocate device memory |
| 0xc0 | Free device memory |
| 0xd0 | Copy namespace data into device memory |
| 0xe1 | Execute a program |
| 0xf2 | Read device memory |
| 0xf5 | Write device memory |
| 0xf6, 0xf7, 0xf8 | Create a group, set its QoS, delete it |

Admin commands: 0x21 memory range set management, 0x22 program load and
unload, 0x23 program activate and deactivate, 0x25 load program data. The
command layouts follow CEMU; `hw/femu/tests/csd/csd-passthru.c` builds each
one.

## Use it from the guest

Check the device:

```sh
sudo nvme list
sudo nvme id-ctrl /dev/nvme0 | grep -E '^(mn|sn) '
```

The model is `FEMU Computational Storage Controller` and the serial number
starts with `vCSD`.

### Build the guest tool

From `build-femu/` on the host, copy the tools into the guest and build the
passthrough helper:

```sh
scp -P 8080 -i ~/images/femu-guest-key -r ../hw/femu/tests/csd femu@localhost:
./run-guest-ssh.sh make -C csd csd-passthru
```

### Run the phantom smoke test

This needs no program directory. It allocates, writes and reads device
memory, loads and runs a phantom program, and frees everything:

```sh
./run-guest-ssh.sh sudo ./csd/csd-passthru /dev/nvme0n1 smoke
```

### Run a shared-library program

On the host, build the example programs and put them in the program
directory (`csd-original-kernels.so` needs the lz4 development package):

```sh
cd hw/femu/tests/csd          # in the FEMU source tree
make csd-vadd.so csd-original-kernels.so
mkdir -p ~/csd-programs
cp csd-vadd.so csd-original-kernels.so ~/csd-programs/
```

Start FEMU with `csd_program_dir` set to that directory, then name the file
alone in the guest:

```sh
sudo ./csd/csd-passthru /dev/nvme0n1 smoke-so csd-vadd.so
sudo ./csd/csd-passthru /dev/nvme0n1 smoke-so-all csd-original-kernels.so
sudo ./csd/csd-passthru /dev/nvme0n1 bench 4096 32
```

`bench` reports the average latency of device memory writes, reads and
namespace-to-memory copies. [hw/femu/tests/csd/README.md](../../tests/csd/README.md)
lists every subcommand, the eBPF steps and the program ABI.

The vendor log page C0h counts the namespace's NAND traffic as for
BlackBox ([log pages and counters](../reference/log-pages-and-counters.md#vendor-log-page-c0h)).

## Limits and refusals

| Message | Cause and fix |
| --- | --- |
| `CSD mode requires fdm_size to be non-zero` | Set `fdm_size`. |
| `CSD nr_cu must be in range [1, 64]` | `nr_cu` out of range. |
| `CSD nr_thread must be non-zero` | `nr_thread=0`. |
| `CSD csf_runtime_scale must be non-zero` | `csf_runtime_scale=0`. |
| `csd supports at most one namespace per controller` | Two CSD namespaces, from `namespace_modes` or from `femu_mode=4` with `namespaces` above 1. Other namespaces of the controller may use other modes. |
| `FEMU bbssd: namespace 1 exposes ...` | The namespace does not fit the NAND geometry; see the [BlackBox limits](blackbox.md#limits-and-refusals). |
| `FEMU csd: buffer_size has no effect under FDP` | A knob the FDP write path ignores, on a controller in an FDP subsystem; the same list as for BlackBox ([FDP](../features/fdp.md)). |

A program load that fails returns Invalid Field to the guest, or Capacity
Exceeded when the program table is full. For a missing or bad program file,
QEMU prints the reason on its console after `[FEMU] Err:`, for example:

- `CSD: loading a program needs csd_program_dir to be set`
- `CSD: a program name must be a file in csd_program_dir, got "..."`
- `CSD: <path> does not resolve inside csd_program_dir`
- `CSD: failed to load shared library <path>: <reason>`

An eBPF load on a build without uBPF, a malformed load descriptor, or an
unknown program type fails with Invalid Field and prints nothing.

## Verify

1. `sudo nvme id-ctrl /dev/nvme0` reports `FEMU Computational Storage
   Controller`.
2. `csd-passthru /dev/nvme0n1 smoke` completes without errors.
3. With `csd_program_dir` set, `smoke-so csd-vadd.so` completes; without it,
   the same command fails and the QEMU console says why.

## Troubleshooting

- **A program load fails with Invalid Field.** Read the QEMU console (or
  `build-femu/log`). Usually `csd_program_dir` is unset, the name contains a
  path, or the file is not in the directory. No message means an eBPF load
  on a build without uBPF, or a malformed load command.
- **An eBPF load fails.** The FEMU build has no uBPF support. Rebuild with
  `./femu-compile.sh --enable-csd-ubpf`.
- **`make` in the guest fails on `csd-original-kernels.so`.** It needs the lz4
  development package and is meant to be built on the host. Build only
  `csd-passthru` in the guest.

Related issues: #60, #143, #188.

## Citation

CSD mode is derived from [CEMU](https://github.com/cs-qyzhang/CEMU). We thank
the CEMU authors, Qiuyang Zhang, Jiapin Wang, You Zhou, Peng Xu, Kai Lu,
Jiguang Wan, Fei Wu and Tao Lu, and Emilio
([@Emilio597](https://github.com/Emilio597)), who ported it to FEMU in
[#188](https://github.com/MoatLab/FEMU/pull/188). If you use the CSD mode,
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

## Related pages

- [hw/femu/tests/csd/README.md](../../tests/csd/README.md): the guest tool
  and program ABI
- [BlackBox SSD](blackbox.md): the FTL under the namespace
- [Timing model: KV and CSD](../concepts/timing-model.md#kv-and-csd)
