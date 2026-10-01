# Keeping the documentation correct

Four checks keep the documentation in step with the code. CI runs all of
them, and so does

```sh
make -C hw/femu/tests check-docs QEMU=$PWD/build/qemu-system-x86_64 \
    QOS_TEST=$PWD/build/tests/qtest/qos-test
```

| Check | Script | Fails when |
| --- | --- | --- |
| Property reference | `hw/femu/scripts/gen-property-docs.py --check` | a property has no description, or `reference/properties.md` or `reference/runtime-properties.md` differs from the binary |
| Mode table | `hw/femu/scripts/gen-mode-table.py --check` | a mode table differs from `modes.py`, or `modes.py` disagrees with the tree |
| Links | `hw/femu/scripts/check-doc-links.py` | a relative link or heading anchor does not exist |
| Examples | `hw/femu/scripts/check-doc-examples.py` | a code block is not tagged, or a tagged example does not work |

Only two reference pages are generated: `reference/properties.md` and
`reference/runtime-properties.md`, from the built binary plus
`reference/property-topics.py` and `reference/environment.inc.md`. The
others, `reference/log-pages-and-counters.md` and `reference/scripts.md`,
are written by hand and no check compares them with the code, so update
them in the same commit as the change they describe. A user-visible change
also needs an entry in [CHANGELOG.md](../CHANGELOG.md).

## Per-mode facts: `modes.py`

[`hw/femu/docs/modes.py`](../modes.py) holds one entry per mode or feature:
how to turn it on, a minimal example, the guest kernel and tools it needs,
host requirements, its launcher and the page that documents it. Change a
fact there, never in a table, then run

```sh
python3 hw/femu/scripts/gen-mode-table.py
```

The script rewrites the text between `<!-- modes-table:start -->` and
`<!-- modes-table:end -->` in README.md and in any page under
`hw/femu/docs/` that has the two markers. To put the table on a new page, add
the markers and run the script. README.md must keep its markers.

`--check` also compares `modes.py` with the code. Each `symbol` must have the
stated `femu_mode` value in `hw/femu/nvme.h`, every mode in that enum must
have an entry, each launcher must exist in `hw/femu/scripts/`, and each guide
link must resolve. Each entry's `example` is run by the example check below,
so the "Checked" column states what CI really does with it.

## Code blocks in the documentation

Every fenced code block in README.md and `hw/femu/docs/**` falls into one of
these classes:

| Block | Meaning | Checked |
| --- | --- | --- |
| preceded by `<!-- femu-example: NAME -->` | a QEMU command line, `-device` options or a `run-*.sh` launcher | run under qtest |
| preceded by `<!-- femu-untested: REASON -->` | a command that cannot run in CI | the reason must have at least three words |
| ```` ```sh ```` | shell commands that do not start FEMU: git, apt, configure, commands inside the guest | must not start FEMU |
| ```` ```bash ````, ```` ```shell ````, ```` ```console ````, ```` ```zsh ```` | not allowed untagged | fails |
| any other info string, or none | output, configuration files, code | must not start FEMU |

A block "starts FEMU" when, outside shell comments, it runs
`qemu-system-*` as a command, passes `-device femu...`, or names a `run-*.sh`
launcher other than `run-guest-ssh.sh`. The tag comment goes on the line right before
the fence. GitHub does not show it and still highlights the block.

### Writing an example

<!-- femu-untested: shows the tag syntax; the device lines below are not run -->
```text
<!-- femu-example: zns-small -->
-device femu,devsz_mb=1024,femu_mode=3
```

- One example per block, or several separated by blank lines; each is named
  `NAME`, `NAME.2`, and so on in the report.
- `...` stands for options left out and is dropped, so
  `-device femu,...,femu_mode=1,read_reclaim_limit=100000` is tested as
  `-device femu,femu_mode=1,read_reclaim_limit=100000`.
- A launcher such as `./run-zns.sh` (with optional `VAR=value` settings in
  front) is run with stand-ins for `sudo` and QEMU that record the command
  line it builds, so the launcher's own options are what gets tested.
  `OSIMGF` is replaced by an empty file, and lines that run
  `run-guest-ssh.sh` are skipped.
- A list of `key=value` lines can be tested as one device:
  `<!-- femu-example: zns-params; device: femu,femu_mode=3 -->`.
- `io: rw`, `io: kv`, `io: identify` or `io: none` overrides what the I/O
  stage does; by default it follows the mode, from `modes.py`.
- `allow-warning: TEXT` allows one expected warning, for example
  `allow-warning: FEMU CXL DER unavailable` for `der=cylon`, which falls back
  to MMIO without a Cylon host.

### What the example check does

1. QEMU starts with the example's FEMU devices, their memory backends and
   CXL topology, and its `-machine` options (q35 when none is given), under
   `-accel qtest -S`. Options that need a guest or host resource are dropped:
   `-enable-kvm`, `-cpu`, `-smp`, `-m`, `-drive`, `-net`, guest disks, `-qmp`.
   QMP must show every `femu`, `femu-subsys` and `femu-cxl-ssd` created, and
   `query-pci` must list each `femu` as an NVMe controller. Anything on
   stderr fails the example, except FEMU's `[FEMU] Log:` lines, the notice
   that the memory backend could not be pinned (the check lowers
   `RLIMIT_MEMLOCK` so that it never pins), and allowed warnings. Test-only
   properties (`x-...`) are refused.
2. For an example with an NVMe controller, the `doc-examples` case in
   `hw/femu/tests/qtest/femu-test.c` starts the same options, enables each
   controller, sends Identify, and writes and reads back one block of
   namespace 1 (stores and retrieves one value in KV mode). Open-Channel
   controllers stop after Identify. A controller whose namespace 1 is not
   attached stops after Identify, but at least one controller in the example
   must move data.

The check does not boot a guest. Guest kernel versions, guest tools and
anything done inside the guest are outside what it can see.

`--self-test` runs planted mistakes (an untagged block, a misspelled
property, `femu_mode=9`, a warning-only `der=cylon`, an I/O-only failure, a
test-only property) and requires each to fail with the expected message, so
a check that stopped catching them fails rather than passing everything.

```sh
python3 hw/femu/scripts/check-doc-examples.py --lint          # tags only
python3 hw/femu/scripts/check-doc-examples.py --list          # what would run
python3 hw/femu/scripts/check-doc-examples.py \
    --qemu build/qemu-system-x86_64 --qos-test build/tests/qtest/qos-test \
    --only quick-start-bbssd
```
