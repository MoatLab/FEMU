# Debugging

Where FEMU reports problems, how to get more output, and how to run it under
a debugger. For answers to common problems, see
[troubleshooting](../troubleshooting.md).

## Where messages go

FEMU prints its messages on QEMU's console:

| Prefix | Stream | Meaning |
| --- | --- | --- |
| `[FEMU] Log:` | stdout | information, such as a vendor command taking effect |
| `[FEMU] Err:` | stderr | an error FEMU recovered from, such as a CSD program that failed to load |
| `[FEMU] FTL-Log:`, `[FEMU] FTL-Err:` | stdout, stderr | the BlackBox FTL |
| `[Misao] ZFTL-Log:`, `[Misao] ZFTL-Err:` | stdout, stderr | the ZNS FTL |
| `[FEMU] FDP-Log:`, `[FEMU] FDP-Trace:` | stderr | FDP setup; placement and reclaim traces with `FEMU_FDP_DEBUG` |
| `qemu-system-x86_64: -device femu,...: MESSAGE` | stderr | the device refused its options and QEMU did not start |

`run-blackbox.sh`, `run-zns.sh` and `run-csd.sh` copy the console to
`build-femu/log`, and `run-blackbox-fdp.sh` to `/tmp/femu-fdp.log`.
`run-nossd.sh`, `run-whitebox.sh` and `run-cxlssd.sh` print only to the
terminal.
Through the `tee` pipe, standard output is buffered, so stdout lines can
reach the log later than stderr lines. Put `stdbuf -oL` in front of
`./qemu-system-x86_64` on the launcher's `sudo` line to write them at once.

Check the guest's side too. A guest that gives up on the device logs it in
`dmesg`:

```sh
sudo dmesg | grep -i nvme
```

FEMU defines no QEMU trace events and does not use QEMU's `-d` log
categories, so `-d` and `-trace` show nothing from FEMU itself. They still
help with the QEMU code around it. `-d guest_errors,unimp -D qemu.log` logs
bad register accesses that QEMU's MSI-X and CXL code detect. Add them
to the QEMU command line in the launcher:

<!-- femu-untested: QEMU logging options added to a launcher; they create no device -->
```bash
-d guest_errors,unimp -D qemu.log
```

## Run FEMU under gdb

Do not use `gdb-run.sh`; it starts QEMU's stock `nvme` device, not FEMU.
Instead, run a launcher's own command line under gdb. From `build-femu/`,
make a copy of the launcher that starts QEMU through gdb, and run it:

<!-- femu-untested: starts QEMU under gdb, which needs an interactive terminal -->
```bash
sed -e 's|\./qemu-system-x86_64|gdb -ex "handle SIGUSR1 nostop noprint pass" --args ./qemu-system-x86_64|' \
    -e 's/ 2>&1 | tee .*$//' run-blackbox.sh > gdb-blackbox.sh
bash gdb-blackbox.sh
```

At the gdb prompt, set breakpoints and start QEMU:

```text
(gdb) break femu_realize
(gdb) run
```

KVM uses SIGUSR1 to kick vCPU threads, which is why gdb is told to pass it
on. The guest's serial console shares the terminal with gdb; press Ctrl-C
to get back to the gdb prompt.

To attach to a QEMU that is already running instead, on the host:

```sh
sudo gdb -p "$(pgrep -x qemu-system-x86)" -ex "handle SIGUSR1 nostop noprint pass"
```

When QEMU crashes, `thread apply all bt` in gdb prints every thread's
stack. Add `,debug-threads=on` to the launcher's `-name` option first, so
that `info threads` shows the `femu-poller` and `FEMU-FTL-Thread` names
([performance tuning](performance-tuning.md#threads-and-cores)).

## Debug builds and compile-time switches

`femu-compile.sh` builds with `-O2 -g`. gdb works on that build, but many
variables are optimized out. To single-step, configure an unoptimized build
yourself from `build-femu/`:

```sh
../configure --enable-kvm --target-list=x86_64-softmmu --enable-slirp \
    --disable-libnfs --disable-libiscsi --disable-curl \
    --enable-debug --enable-debug-info
make -j"$(nproc)"
```

The debug messages (`Dbg:`) have no run-time switch. These macros, passed with
`--extra-cflags`, compile them in:

| Macro | Effect |
| --- | --- |
| `FEMU_DEBUG_NVME` | controller debug messages (`[FEMU] Dbg:`), and the per-command log that vendor command 0xEF with CDW10 6 and 7 turns on and off |
| `FEMU_DEBUG_FTL` | BlackBox FTL debug messages (`[FEMU] FTL-Dbg:`), and the FTL invariant checks of BlackBox and ZNS |
| `FEMU_DEBUG_ZFTL` | ZNS FTL debug messages (`[Misao] ZFTL-Dbg:`) |
| `FEMU_FTL_ASSERT` | the FTL invariant checks only, without the messages |

For example:

```sh
../configure --enable-kvm --target-list=x86_64-softmmu --enable-slirp \
    --disable-libnfs --disable-libiscsi --disable-curl \
    --extra-cflags="-DFEMU_DEBUG_FTL -DFEMU_DEBUG_NVME"
make -j"$(nproc)"
```

The invariant checks (`ftl_assert`) are compiled out of a normal build. A
mapping or bound error there corrupts FTL state quietly instead of
stopping QEMU. When a BlackBox or ZNS run produces wrong data or impossible
counters, rebuild with `-DFEMU_FTL_ASSERT` first. The debug messages print
on the I/O path, so use them with small workloads.

The [sanitizer build](testing.md#sanitizer-build) adds AddressSanitizer and
UndefinedBehaviorSanitizer on top of the FTL checks. Run the failing
workload on it to find memory errors.

## Run-time switches

FEMU reads a few environment variables
([environment variables](../reference/properties.md#environment-variables)):

| Variable | Prints to stderr |
| --- | --- |
| `FEMU_FDP_DEBUG` (any value) | FDP placement and reclaim traces |
| `FEMU_EXP_LOG=1` with `FEMU_SECRET=TEXT` | writes, overwrites, deallocations, GC moves and erases of pages whose data contains `TEXT` |
| `FEMU_DUMP_LPN=N` | a hex dump of logical page N on every read not served from the write buffer |
| `FEMU_KV_SELFTEST` (any value) | the result of a KV FTL self-test run once at start |

The launchers other than `run-cxlssd.sh` start QEMU with `sudo`, which drops
your environment.
`run-blackbox.sh` passes `FEMU_EXP_LOG`, `FEMU_SECRET` and `FEMU_DUMP_LPN`
through, so this works:

<!-- femu-example: debugging-exp-log -->
```bash
FEMU_EXP_LOG=1 FEMU_SECRET=MARKER ./run-blackbox.sh
```

For the others, add the variable to the launcher's `sudo` line, for example
`sudo FEMU_FDP_DEBUG=1 ./qemu-system-x86_64 \` in `run-blackbox-fdp.sh`.

On a running BlackBox controller, the vendor admin command 0xEF switches
GC time and NAND time on and off and prints poller counts
([timing model](../concepts/timing-model.md#changing-timing-at-run-time)).

## Inspect a running device

QEMU's monitor shows what QEMU built. With the QMP socket the launchers
other than `run-cxlssd.sh` create (`build-femu/qmp-sock`), on the host:

```sh
printf '%s\n' '{"execute":"qmp_capabilities"}' '{"execute":"query-pci"}' |
    sudo socat - UNIX-CONNECT:./qmp-sock
```

`qom-list` and `qom-get` on `/machine/peripheral/<id>` read a device's
properties and counters ([runtime properties](../reference/runtime-properties.md)).
`run-nossd.sh` names its controller `nvme0` and `run-cxlssd.sh` names its
device `cxlssd`. The other launchers give the controller no `id=`, so add one
to address it by name.

## Common crash reports

| Symptom | What it means | What to do |
| --- | --- | --- |
| `qemu-system-x86_64: -device femu,...: MESSAGE` and QEMU exits | A property value was refused at start | Read the message; the mode guide's "Limits and refusals" table explains it |
| `[FEMU] Err: cannot pin the N MiB memory backend` | Not a crash. QEMU runs without `sudo` and the memory lock limit is too low | Ignore it, or raise `ulimit -l` ([requirements](../getting-started/requirements.md#memory)) |
| `failed to allocate N bytes`, then QEMU stops with a trap or abort and may dump core | The host has less free memory than the device needs | Lower `devsz_mb` or free memory ([host sizing](../concepts/security-and-limits.md#host-sizing)) |
| Guest `dmesg` shows `nvme nvme0: I/O ... timeout`, then a controller reset | The guest's NVMe driver waited too long for a completion and reset the controller | Check the QEMU console for an error at the same time. If there is none, check that the pollers have cores ([performance tuning](performance-tuning.md)). If it repeats on an idle host, report it |
| The device is missing in the guest, and the console shows `[FEMU] Err:` lines | FEMU refused a command or a configuration the guest used | Read the console; for ZNS, see the [ZNS troubleshooting](../modes/zns.md#troubleshooting) |
| QEMU exits with a segmentation fault or an assertion | A FEMU bug | Run it under gdb or the sanitizer build, and report it with the steps below |

Older reports of crashes in FDP garbage collection (#186, #189, #191) and of
controllers disabled under load (#22, #30) were made against older FEMU
versions. Reproduce on current `master` before you report one.

## Reporting a bug

Open an issue with:

- the FEMU commit (`git log -1 --oneline`) and how you built it;
- the full QEMU command line, or the launcher and every change you made to
  it;
- the guest kernel (`uname -r`) and the commands you ran in the guest;
- the QEMU console output and the guest's `dmesg`;
- for a crash, the `thread apply all bt` output from gdb, or the sanitizer
  report.

Report a security problem privately, as [SECURITY.md](../../../../SECURITY.md)
says.

## Related pages

- [Testing](testing.md)
- [Troubleshooting](../troubleshooting.md)
- [Architecture](../concepts/architecture.md)

Related issues: #18, #22, #30, #105; discussion #133.
