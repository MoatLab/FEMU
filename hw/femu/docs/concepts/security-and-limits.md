# Security and limits

What a guest can do to the host through FEMU, what QEMU features FEMU does
not support, how device properties change between versions, and how much
host memory a device takes. To report a vulnerability, follow
[SECURITY.md](../../../../SECURITY.md).

## Security model

FEMU runs inside the QEMU process on the host. Everything a FEMU device
does, it does with QEMU's privileges. The NVMe `run-*.sh` launchers start
QEMU with `sudo`, so by default that means root; `run-cxlssd.sh` runs QEMU
as you.

Treat the guest as trusted unless you have turned off every feature below.
For a guest you do not trust:

- Run QEMU as a normal user in the `kvm` group, not with `sudo`. FEMU then
  cannot pin the device memory unless you raise the memory lock limit
  ([requirements](../getting-started/requirements.md#memory)). It starts
  anyway and prints `[FEMU] Err: cannot pin the N MiB memory backend`,
  which is a warning, not a failure.
- Do not use CSD mode with `csd_program_dir`.
- Keep `lsa-control` off on `femu-cxl-ssd`.

### CSD programs

In CSD mode (`femu_mode=4`), the guest can ask the device to load a program
by file name. For a shared-library program, QEMU opens that file with
`g_module_open()` and runs its code inside the QEMU process. An eBPF program
is read from the same directory and run by the uBPF library, when FEMU is
built with it.

FEMU limits which files the guest can name:

- With `csd_program_dir` unset (the default, and what `run-csd.sh` does),
  only the built-in program type loads.
- With it set, a name must be a file in that directory. FEMU refuses an
  empty name, a name containing `/`, the names `.` and `..`, and a name
  whose path leaves the directory after symbolic links are resolved.

This keeps the guest away from the rest of the host file system. It does
not make the programs in the directory safe: any shared object there runs
as QEMU, which is root under the launchers. Put only programs you built in
the directory, and make sure no other user can write to it. See the
[CSD guide](../modes/csd.md#security-programs-run-inside-qemu-on-the-host).

### CXL SSD control channel

`femu-cxl-ssd,lsa-control=on` lets the guest send experiment commands
through the CXL Get LSA mailbox command
([CXL SSD guide](../modes/cxl-ssd.md#control-channel-through-the-label-area)).
With it on, the guest can:

- create and write `cxlssd-stats.log`, `cxlssd-io-N.log` and
  `cxlssd-spt.log` in `log-dir`, which is QEMU's working directory when
  unset;
- write the host's `trace` and `tracing_on` files in `tracefs-dir`, which
  clears the host trace buffer and turns host tracing on or off, when
  `tracefs-dir` is set;
- flush and reconfigure the device cache, reset the statistics, and set or
  remove a direct-mapping ratio.

Each file is capped at `log-limit` (64 MiB by default) and FEMU reuses a
fixed set of 64 I/O log names. With the statistics and mapping dump files,
a guest can therefore make FEMU write about 66 times `log-limit` (about
4.1 GiB with the default) in `log-dir`, and no more.

`lsa-control` is off by default on the device. `run-cxlssd.sh` turns it on,
because Cylon's scripts use it. Turn it off for a guest you do not trust:

<!-- femu-example: security-cxl-no-lsa -->
```bash
LSA_CONTROL=off ../femu-scripts/run-cxlssd.sh
```

The same commands stay available from the host through QMP
(`control-command`), whatever `lsa-control` says.

### Other host-side files and output

These are chosen on the host, not by the guest:

- `pel_file` keeps the Persistent Event Log in a host file that QEMU
  creates if it is missing.
- `FEMU_DUMP_LPN` (BlackBox) hex-dumps the contents of one logical page to
  QEMU's standard error on every read, which `run-blackbox.sh` copies into
  its log file. `FEMU_EXP_LOG` traces only the addresses of pages that
  contain the `FEMU_SECRET` marker. Leave `FEMU_DUMP_LPN` unset when the
  guest's data is private.

## Migration and snapshots

FEMU devices cannot be migrated or saved. Both `femu` and `femu-cxl-ssd`
mark their state unmigratable, so QEMU refuses these operations and the
guest keeps running:

| Operation | What QEMU reports |
| --- | --- |
| QMP `migrate` | `State blocked by non-migratable device '0000:00:04.0/femu'` |
| HMP `savevm NAME` | `Error: State blocked by non-migratable device '0000:00:04.0/femu'` |
| Either, with a CXL SSD | `State blocked by non-migratable device '<path>/femu-cxl-ssd'` |
| `-only-migratable` with a FEMU device | `Device femu is not migratable, but --only-migratable was specified`, and QEMU does not start |

The part before `/femu` is the device's PCI address, so it changes with
your command line.

Device data lives only in host memory:

- A guest reboot or a controller reset keeps the data.
- QEMU exiting, for any reason, loses it. FEMU never writes an NVMe
  namespace to a file, and there is no option to do so. (`femu-cxl-ssd`
  keeps its data in the memory backend you give it; a file-backed
  `memory-backend-file` leaves the bytes in that file.)
- A snapshot of the guest's boot disk (for example with `qemu-img`) does not
  include the FEMU device.

To start every run from the same state, write the data again after boot, or
run a fixed preconditioning workload. Related issue: #52.

## Property compatibility

FEMU's device properties are its configuration interface, but they are not
versioned: FEMU has no machine-type compatibility settings for them, so a
command line means what the current code says it means.

### Values refused at realize

Recent versions check more property values when the device is created and
stop QEMU with a message, where older versions accepted the value and then
misbehaved. A command line that used to start may therefore stop. The most
recent additions:

| Property | Now refused |
| --- | --- |
| `femu_mode` | above 5 |
| `multipoller_enabled` | other than 0 or 1 |
| `lver` (OCSSD) | other than 1 or 2 |
| `flash_type` (OCSSD) | outside 1 to 4 |
| `zns_chnls_per_zone` | a value that does not divide `zns_num_ch` |

The message names the property, for example:

<!-- femu-untested: QEMU output for a refused value, not a command -->
```text
qemu-system-x86_64: -device femu,devsz_mb=64,femu_mode=7: femu_mode must be 0 (OpenChannel), 1 (black-box), 2 (no-SSD), 3 (zoned), 4 (computational storage) or 5 (key-value)
```

[CONFIGURATION-CHANGES.md](../CONFIGURATION-CHANGES.md) lists these and
other refusals, and the changes that move numbers without stopping a run.
Most mode guides list their own refusals under "Limits and refusals"; the
CXL SSD guide has them under "Limits".

### Properties that are accepted but do nothing

These are kept so that old command lines still start. Setting them changes
nothing the guest can observe:

| Property | Why |
| --- | --- |
| `serial` | Identify Controller reports a serial number FEMU generates |
| `ms` | the metadata size comes from `meta` |
| `dlfeat` | Identify Namespace always reports 0x9 |
| `ms_max` (OCSSD 2.0) | the controller reports a single LBA format (NLBAF 0) |
| `tplpbsy`, `tplrbsy`, `trcbsy` | programs and reads are issued one plane at a time, and the cache read model is not enabled |
| `nr_thread`, `time_slice`, `context_switch_time` (CSD) | accepted for CEMU configurations; `nr_thread` must still be non-zero |
| `intc`, `intc_thresh`, `intc_time` | `intc_thresh` and `intc_time` are reported in Interrupt Coalescing (feature 08h) and `intc` (0 or 1) in Interrupt Vector Configuration (09h); interrupts are not coalesced |

The [property reference](../reference/properties.md) says this in each
description, and `-device femu,help` prints the same text.

## Host sizing

### Memory

A FEMU device keeps its whole capacity in host DRAM. For each device, plan
for:

- **The backend**: `devsz_mb` MiB, or the raw NAND capacity with
  `op_pcent`. Under `sudo`, FEMU locks it in memory at start-up, so all of
  it is resident from the first second. Without the lock (a normal user
  with the default limit), pages become resident as the guest first touches
  them.
- **FTL tables**: allocated and filled at start-up. With the default
  BlackBox geometry (16 GiB of NAND in 4 KiB pages), QEMU's resident size
  was 116 MiB against 35 MiB for a NoSSD device of the same size, so the
  FTL took about 80 MiB. It grows with the number of NAND pages.
- **The guest**: its `-m` size.
- **QEMU itself**: the requirements page budgets about 1 GiB.

The [requirements page](../getting-started/requirements.md#memory) gives
the totals for each launcher. If the allocation is more than the kernel
will commit, QEMU aborts at start with `failed to allocate N bytes`.

In BlackBox, CSD and KV mode the NAND geometry as a whole (every namespace
plus spare space) may hold at most 2^31 - 1 sectors of `secsz` bytes, just
under 1 TiB with the default 512-byte sectors.

### Hugepages

FEMU allocates its backend from ordinary anonymous memory, not hugetlbfs, so
the NVMe modes need no hugepages. You can back the guest's RAM with
hugepages to reduce TLB misses in the guest; see
[performance tuning](../guides/performance-tuning.md#hugepages).
`femu-cxl-ssd` with `der=cylon` is the exception: it needs a shared,
preallocated hugetlb memory backend
([CXL SSD guide](../modes/cxl-ssd.md#dercylon)).

### CPU

Each `femu-poller` thread, and the `FEMU-FTL-Thread` of a controller with a
BlackBox, ZNS or CSD namespace, spin on a host core
while the guest has the controller enabled. Plan one core for each of them
on top of the guest's vCPUs
([performance tuning](../guides/performance-tuning.md#threads-and-cores)).

## Related pages

- [Architecture](architecture.md)
- [Performance tuning](../guides/performance-tuning.md)
- [Troubleshooting](../troubleshooting.md)
- [CONFIGURATION-CHANGES.md](../CONFIGURATION-CHANGES.md)
