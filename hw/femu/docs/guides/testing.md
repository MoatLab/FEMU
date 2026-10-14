# Testing

FEMU has five kinds of tests. The first four run without a guest and run in
CI; the last runs inside a booted guest.

| Tests | Where | What they cover | Run with |
| --- | --- | --- | --- |
| Unit tests | `hw/femu/tests/unit/` | the NAND timing math, the completion priority queue, the hybrid mapping, the CXL cache, page table entries and caching API ring | `make -C hw/femu/tests check` and `meson test` in a build; each runs a different subset |
| Device tests (qtest) | `hw/femu/tests/qtest/femu-test.c` | about 400 cases that drive the controller through its registers with no guest: every mode, admin and I/O commands, error paths, fuzzers, the CXL SSD | `qos-test` |
| Documentation checks | `hw/femu/scripts/` | the property reference, mode tables, links and every example in the docs | `make -C hw/femu/tests check-docs` |
| Host tool checks | `hw/femu/scripts/femu-stat.py`, `femu-config-check.py` | the host tools against QEMU under qtest, with planted faults | `make -C hw/femu/tests check-tools` |
| Configuration files | `hw/femu/scripts/ssd-config-test.sh` | every file in `scripts/configs/` starts QEMU | `ssd-config-test.sh BINARY` |
| Guest-side tests | `hw/femu/scripts/`, `hw/femu/tests/csd/`, `hw/femu/tools/cca/` | the device as Linux sees it, with blktests and the nvme-cli suite among them | inside the guest, or `guest-conformance.sh` from the host |

CONTRIBUTING.md asks for a test that fails without your change and passes
with it.

## Build for testing

The qtests and the documentation checks need QEMU and `qos-test`. A debug
build is the usual choice:

```sh
mkdir build && cd build
../configure --target-list=x86_64-softmmu --disable-docs --enable-debug --enable-slirp
ninja qemu-system-x86_64 tests/qtest/qos-test
```

## Unit tests

Without a QEMU build, from the source tree:

```sh
make -C hw/femu/tests check
make -C hw/femu/tests clean
```

This compiles the NAND media, hybrid mapping, CXL cache, page table entry
and caching API ring tests against a stub `qemu/osdep.h` and runs them, in
about a second. The CXL cache test needs GLib development files and is
skipped without them. In a configured build directory, meson runs the NAND
media, priority queue and hybrid mapping tests against QEMU's real headers.
CI runs both:

```sh
cd build
./pyvenv/bin/meson test test-femu-nand-media test-femu-pqueue test-femu-hybrid-oracle \
    --print-errorlogs
```

## Device tests (qtest)

From the build directory, run every FEMU qtest:

```sh
QTEST_QEMU_BINARY=./qemu-system-x86_64 ./tests/qtest/qos-test -m quick \
    -p /x86_64/pc/i440FX-pcihost/pci-bus-pc/pci-bus/femu/femu-tests
```

List them, or run one by its full path:

```sh
QTEST_QEMU_BINARY=./qemu-system-x86_64 ./tests/qtest/qos-test -l |
    sed -n 's|^# \(.*femu-tests/.*\)|\1|p'
QTEST_QEMU_BINARY=./qemu-system-x86_64 ./tests/qtest/qos-test -m quick \
    -p /x86_64/pc/i440FX-pcihost/pci-bus-pc/pci-bus/femu/femu-tests/cc-states
```

Each case starts its own QEMU under the qtest accelerator, so no KVM and no
guest are needed. The default device is a 64 MiB NoSSD controller at PCI
address 04.0; a case can add its own device options. The CXL cases start
their own machine with a `femu-cxl-ssd`, which the `x86_64-softmmu` build
includes by default.

### Sanitizer build

CI also runs the unit tests and qtests in a build with AddressSanitizer,
UndefinedBehaviorSanitizer and the FTL invariant checks on. A bound
violation that the normal build silently survives aborts there:

```sh
mkdir build-debug && cd build-debug
../configure --enable-kvm --target-list=x86_64-softmmu --enable-slirp \
    --disable-libnfs --disable-libiscsi --disable-curl \
    --enable-asan --enable-ubsan --extra-cflags=-DFEMU_FTL_ASSERT
make -j"$(nproc)"
```

Run the qtests in that build with the sanitizer options CI uses. Without
`abort_on_error=1`, a sanitizer report does not fail the test:

```sh
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1
export UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1
QTEST_QEMU_BINARY=./qemu-system-x86_64 ./tests/qtest/qos-test -m quick \
    -p /x86_64/pc/i440FX-pcihost/pci-bus-pc/pci-bus/femu/femu-tests
```

The fuzz cases (names containing `fuzz`) take most of the sanitized run
time, and CI splits them over three jobs.

## Documentation checks

From the source tree, with the build above in `build/`:

```sh
make -C hw/femu/tests check-docs
```

It regenerates the property reference and mode tables and compares them,
checks every relative link, and runs every example tagged
`femu-example` under qtest. Set `QEMU=` and `QOS_TEST=` for a build
elsewhere. [docs-maintenance.md](../development/docs-maintenance.md) says
how to tag a new example.

## Host tool checks

The host tools check themselves under qtest, with QEMU and no guest:

- `femu-stat.py` writes pages through the qtest protocol and checks the
  counters, WAF and stage times it shows.
- `femu-config-check.py` enables the controllers and checks the
  configuration it derives. It also checks its exit status on refused
  configurations.

Each self-test also plants faults in its tool and requires each fault to
fail its check:

```sh
make -C hw/femu/tests check-tools
```

Set `QEMU=` for a build elsewhere. CI runs the same self-tests.

## Guest-side tests

These need a booted guest; CI does not run them. Copy the files into the
guest first, for example with `scp -P 8080` and the key from
`make-guest-image.sh`.

`femu-test.sh` checks one namespace end to end: data written comes back,
the counters move, deallocate works, and zones or key-value commands answer
when the namespace has them. **It overwrites the whole namespace**:

```sh
sudo bash femu-test.sh --yes /dev/nvme0n1
```

It prints `PASS`, `FAIL` and `SKIP` lines and a summary, and exits non-zero
when a check failed, so a script can check it. A read that fails counts as a
failure, the same as a bad checksum. It refuses a mounted device. A
key-value namespace has no block node, so it is driven by passthrough
through its generic node, `/dev/ngXnY`; name it as `/dev/nvmeXnY` or
`/dev/ngXnY`. It makes no timing claims. A BlackBox run prints lines like
these (`N` stands for the counts; `...` for lines left out here).
`max_block_reads` is the read count of the most-read block since its
erase:

```text
== device ==
  PASS  controller answers Identify
== data survives the FTL ==
  PASS  random write then verify (crc32c)
== deallocate ==
  PASS  deallocate accepted
  ...
== counters ==
  PASS  SMART log readable
  data_units_written=N host_write_commands=N
  ...
  waf_x1000=N host_pages=N nand_pages=N max_block_reads=N read_reclaims=N
  PASS  host writes counted
  PASS  write amplification reported

FEMU_TEST pass=N fail=0 skip=N
```

Smaller probes, built in the guest with `gcc -O2 -o NAME NAME.c`:

| Probe | Run | Checks |
| --- | --- | --- |
| `kv-probe.c` | `sudo ./kv-probe /dev/nvme0` | key-value Store, Exist, Retrieve and Delete |
| `kv-bench.c` | `sudo ./kv-bench /dev/ng0n1` (build with `-pthread`) | a key-value workload, with each answer checked against a model of the keys ([KV benchmark](#kv-benchmark)) |
| `aer-probe.c` | `sudo ./aer-probe /dev/nvme0` | a temperature event completes an Asynchronous Event Request |
| `zone-aen-probe.c` | `sudo ./zone-aen-probe /dev/nvme0 /dev/nvme0n1` | Zone Descriptor Changed notices, on a ZNS device with `err_write_fail_ppm` set |

Mode-specific suites:

- FDP: `fdp-test-nvme-admin.sh` checks the FDP admin commands against the
  device `run-blackbox-fdp.sh` creates.
- CSD: the programs and guest tool in `hw/femu/tests/csd/`
  ([CSD guide](../modes/csd.md#use-it-from-the-guest)).
- CXL caching API: `hw/femu/tools/cca/run-guest-tests.sh`
  ([CCA guide](../features/cxl-cca.md#guest-tests)).

All of them are listed in the [scripts reference](../reference/scripts.md#guest-side-test-tools).

### Conformance suites

Two external suites check FEMU as Linux sees it:
[blktests](https://github.com/linux-blktests/blktests) and the
end-to-end tests of [nvme-cli](https://github.com/linux-nvme/nvme-cli).
Two more suites check FEMU under real workloads. `zenfs-crash` runs a
RocksDB crash test on [ZenFS](https://github.com/westerndigitalcorporation/zenfs)
on a ZNS namespace. `kv-bench` drives a key-value namespace with the
NVMe-KV commands and checks every answer. `guest-conformance.sh` runs the
suites on the host. For each suite it boots a fresh guest with one FEMU
device, runs the suite inside, and stops the guest:

```text
 host: guest-conformance.sh SUITE...
   for each suite:
     qemu-img overlay of the guest image (the image does not change)
       |
       v
     QEMU + KVM + FEMU (suite device options) --ssh--> guest
                                                        |
                                    SUITE's guest script
                                    (apt-get, git clone, build, run)
       |
       v
     OUTDIR/SUITE.log, SUITE.qemu.log, SUITE.serial.log --> RESULT SUITE PASS|FAIL
```

| Suite | Device | Runs |
| --- | --- | --- |
| `blktests-block` | BlackBox SSD, 768 MiB | blktests `block` group with `TEST_DEVS=(/dev/nvme0n1)` |
| `blktests-zbd` | ZNS SSD, 1 GiB | blktests `zbd` group |
| `nvme-cli` | BlackBox SSD with `oncs=415,vwc=1` (Compare, Write Uncorrectable, Dataset Management, Write Zeroes, Verify, Copy and Flush) | nvme-cli `tests/nvme-cli-e2e`, tag `v3.1` by default |
| `zenfs-crash` | ZNS SSD, 4 GiB in 64 zones of 64 MiB; the guest gets 16 vCPUs and 16 GiB | `zenfs-crash-guest.sh`: RocksDB `v9.10.0` with ZenFS `919c2eb`, a blackbox crash test |
| `kv-bench` | KV SSD, 1 GiB | `kv-bench-guest.sh`: `kv-probe`, then two `kv-bench` runs |

The guest is the image that `make-guest-image.sh` builds. The suites fetch
packages and sources, so the guest needs network access; QEMU's user
networking gives it. Run from `build-femu/`. A suite takes 5 to 60
minutes, and `zenfs-crash` builds RocksDB first:

<!-- femu-untested: needs a guest image, KVM and network access -->
```bash
../femu-scripts/guest-conformance.sh all
../femu-scripts/guest-conformance.sh --outdir /tmp/conf nvme-cli
../femu-scripts/guest-conformance.sh --keep zenfs-crash kv-bench
```

`--help` lists the options. They set the QEMU binary, the image, the SSH
key and port, and the result directory. Others set the time limits, the
guest size and a device for control runs.

`BLKTESTS_REF` and `NVMECLI_REF` select a blktests commit and an nvme-cli
tag. `ROCKSDB_REF` and `ZENFS_REF` select the RocksDB tag and the ZenFS
commit.

The script prints `RESULT SUITE PASS`, `FAIL` or `SETUP-ERROR` for each
suite. The exit status is 0 when every suite passed and 1 when a suite
failed. It is 2 when a suite could not run and no suite failed.

A blktests suite fails when a test that ran on the FEMU namespace failed.
It also fails when the run stopped before every test reported a status. Some tests use `null_blk`, `scsi_debug` or device-mapper instead of
the namespace. Their failures count in `FAILED` but stay out of the
`DEVICE_FAILED` count. A test that needs a feature FEMU or the guest kernel
lacks shows as `not run`, and the suite log gives the reason.

The nvme-cli suite fails when a test fails, with one exception. In nvme-cli
v3.1, `test_get_lba_status` passes the namespace device path as the
namespace ID. When that test fails, the script runs the same command with
the numeric namespace ID. If the command passes, the log shows the test as
`KNOWN_DEFECT` and the suite still passes. If it fails, FEMU fails the test.

#### ZenFS crash test

`zenfs-crash-guest.sh` builds RocksDB with the ZenFS plugin in the guest
and runs the RocksDB blackbox crash test on the zoned namespace:

```text
 zenfs mkfs --zbd=nvme0n1
   |
   v
 round 1..6:  db_stress (60 s) --SIGKILL-->  next round opens the database
              and checks it against the expected state on the host
   |
   v
 final:       db_stress --verification_only=1 checks every key
   |
   v
 blkzone report: data zones past the 3 ZenFS metadata zones hold data
```

The test passes when all of these are true:

- `zenfs mkfs` succeeds.
- Each round runs until the SIGKILL of its timeout and writes nothing to
  stderr. Each round opens the database and checks it first.
- In each round, a `db_stress` thread reports at least 1000 finished
  operations, and the SMART host write count grows.
- The final run exits 0, prints `Verification successful` and writes
  nothing to stderr.
- ZenFS wrote data zones on the device.

The options are those of ZenFS's own crash test, with zone-sized SST
files and no injected RocksDB faults. ZenFS keeps unsynced WAL data in
the process, and a SIGKILL loses it. Thus `--sync=1` syncs each write,
and every write that completed must survive the kill. ZenFS's own driver passes
`--expected_values_path`, a flag that RocksDB removed before 7.0. Thus
the script starts `db_stress` itself, as RocksDB's `db_crashtest.py` does.
The build goes to `/opt/femu-zenfs`. A kept overlay (`--keep`) can serve as
the `--image` of a later run, which then skips the build.

Two control runs show that the test can fail:

- `ZENFS_CONTROL=reset-zones` resets every data zone that holds data after
  round 1. Round 2 must then fail. A control run that passes ends as a
  setup error.
- `--device` with BlackBox SSD properties gives a conventional namespace.
  `zenfs mkfs` must then refuse it.

#### KV benchmark

`kv-bench.c` sends the NVMe-KV commands through the passthrough ioctl of
`/dev/ngXnY`: Store (01h), Retrieve (02h), List (06h), Delete (10h) and
Exist (14h). It keeps a model of every key and checks each answer against
it:

```text
 load          store every key
   |
 mixed         Store, Retrieve, Delete and Exist by the --mix shares
   |
 verify        Exist and Retrieve of every key
   |
 List          the keys == the live keys of the model
   |
 delete half   Delete; then Exist and Retrieve give 0x87
   |
 verify, List
   |
 cleanup       Delete the rest; List returns no key
```

Each Retrieve compares the value bytes and the size in the completion.
Each command on a deleted key must return Key Does Not Exist (0x87). The
List walk must return each live key once and no other key. The
namespace must hold no key at the start. The workload options follow
Samsung's kvbench: key count, key length, value sizes and their shares,
and the operation shares. The program also prints the rate of each phase
and the latency of each command.

`kv-bench-guest.sh` runs `kv-probe`, then `kv-bench` with 20000 keys of
4 to 16 bytes and values of 512, 2048 and 4096 bytes. A second run uses
256 keys with values of 4 KiB to 256 KiB. The suite passes when `kv-probe`
reports no failure and each `kv-bench` run reports no error and no
mismatch.

Two control runs show that the checks can fail:

- `KVBENCH_CONTROL=legacy-opcodes` sends Samsung's driver opcodes (81h,
  90h, A1h, B3h, B2h). FEMU rejects them, so the run must fail.
- `KVBENCH_CONTROL=corrupt-model` changes one byte of the expected value
  of one key. The checks must report that key as a mismatch.

#### Guest scripts on their own

The guest scripts also run on their own in any guest:

```sh
sudo bash blktests-guest.sh block /dev/nvme0n1
sudo bash nvme-cli-e2e-guest.sh /dev/nvme0 /dev/nvme0n1
sudo bash zenfs-crash-guest.sh nvme0n1
sudo bash kv-bench-guest.sh /dev/ng0n1
```

All of them write to the namespace. The nvme-cli suite can format it, and
`zenfs-crash-guest.sh` formats it with ZenFS. `kv-bench-guest.sh` needs
`kv-probe.c` and `kv-bench.c` in its own directory.

## Adding a test

### A qtest

1. Write a function in `hw/femu/tests/qtest/femu-test.c` with the signature
   `static void femu_test_NAME(void *obj, void *data, QGuestAllocator *alloc)`.
   `obj` is the `QFemu` device; the existing helpers enable the controller,
   create queues and submit commands. Read a similar case first.
2. Register it in `femu_register_nodes()`. For the default device:

   ```c
   qos_add_test("my-case", "femu", femu_test_my_case, NULL);
   ```

   For other device options:

   ```c
   qos_add_test("my-bbssd-case", "femu", femu_test_my_case,
                &(QOSGraphTestOptions) {
       .edge.extra_device_opts =
           "serial=my-bbssd-case,devsz_mb=4,femu_mode=1,secs_per_pg=8,"
           "pgs_per_blk=4,blks_per_pl=128,pls_per_lun=1,luns_per_ch=2,nchs=2"
   });
   ```

3. Rebuild `tests/qtest/qos-test` and run the case by its path.
4. Show that it can fail: revert your fix, or plant the bug it is meant to
   catch, and check that the case goes red.

### A unit test

Put it in `hw/femu/tests/unit/` and add it to `UNIT_TESTS`, a build rule
and the `clean` rule in `hw/femu/tests/Makefile`. If it should also build against QEMU's
headers, add it to `femu_unit_tests` in `hw/femu/tests/meson.build`.

### A documentation example

Put the command line in a code block with a `femu-example` tag. The check
starts it, enables each controller, and writes and reads one block. See
[docs-maintenance.md](../development/docs-maintenance.md#writing-an-example).

## Related pages

- [Debugging](debugging.md)
- [Scripts reference](../reference/scripts.md)
- [CONTRIBUTING.md](../../../../CONTRIBUTING.md)
