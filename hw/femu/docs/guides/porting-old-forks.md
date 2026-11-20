# Porting a fork of an old FEMU release

This guide is for a group with a fork of an old FEMU release that wants
its changes on current master. It covers five steps:

1. Find the release that your fork started from.
2. Map the old symbols and files to their names on master.
3. Update the command lines and configuration files.
4. Move the fork's commits onto master.
5. Run the checks that a ported fork must pass.

Each fact in this guide comes from git in this repository. The commands
that show it are next to it, so you can check it on your own clone.

## 1. Which release is your fork from

The repository has five release tags. Each tag has its own QEMU base and
its own source layout:

| Tag | Date | QEMU base | FEMU sources | Launchers |
| --- | --- | --- | --- | --- |
| `femu-v5.2` | 2021-01-03 | 5.2.0 | `hw/block/femu/` | `femu-scripts/` |
| `femu-v5.2.1` | 2022-01-13 | 5.2.0 | `hw/block/femu/` | `femu-scripts/` |
| `femu-v7.0.0` | 2022-04-22 | 7.0.0 | `hw/femu/` | `femu-scripts/` |
| `femu-v8.0.0` | 2023-04-25 | 8.0.0 | `hw/femu/` | `femu-scripts/` |
| `femu-v9.0.1` | 2024-06-20 | 9.0.1 | `hw/femu/` | `femu-scripts/` |
| master | | 11.1.3 | `hw/femu/` | `hw/femu/scripts/`, with `femu-scripts` as a link |

`git log -1 TAG` gives the date, and `git show TAG:VERSION` gives the QEMU
base. Add your fork as a remote, then find its base:

```sh
git remote add fork https://example.org/your-group/FEMU.git
git fetch fork --tags
git fetch origin --tags
base=$(git merge-base fork/main origin/master)
git describe --tags --match 'femu-v*' "$base"
```

A result such as `femu-v9.0.1-12-gabc1234` means that the fork started 12
commits after `femu-v9.0.1`. Use that tag as OLD in the next steps. If the
fork has no common history with this repository, find the tag whose
`hw/femu` (or `hw/block/femu`) tree is nearest to the fork's tree:

```sh
for t in $(git tag -l 'femu-v*'); do
    p=hw/femu
    git cat-file -e "$t:$p" 2>/dev/null || p=hw/block/femu
    printf '%s %s\n' "$t" \
        "$(git diff --shortstat "$t:$p" "fork/main:$p" 2>/dev/null)"
done
```

## 2. What moved between the releases

```
 2021-01-22    1730ba87b   OCSSD 2.0; mem-backend.c -> backend/dram.c;
                           femu_oc12_* -> oc12_*; FEMU_OC12_* structs -> Oc12*
 2022-04-22    1cfe6187b   hw/block/femu/ -> hw/femu/   (femu-v7.0.0)
 2023-05-04    6819f1219   properties zns_read, zns_write added (femu-v9.0.1)
 2024-08-07    0326ab489   ZNS FTL in zns/zftl.c; properties zns_read,
                           zns_write removed; old ZNS handlers removed
 2026-05-29    eb01bb73b   CSD mode: femu_mode=4
 2026-08-18    e72465909   KV mode: femu_mode=5
 2026-07-22    274253022   bbssd/ftl.c: page mapping -> ftl-map.c
 2026-07-22    b130c614a   bbssd/ftl.c: geometry -> ftl-geom.c, ftl-internal.h
 2026-07-22    46cb582c9   bbssd/ftl.c: NAND op timing -> ftl-media.c, nand/nand-media.c
 2026-07-23    3e4cab1ba   bbssd/ftl.c: lines and GC -> ftl-line-gc.c
 2026-07-23    66c10f14b   bbssd/ftl.c: read and write path -> ftl-datapath.c
 2026-10-04    2637020f6   timing-model/timing.c -> ocssd/oc-timing.c
```

The dates are author dates. `git show --stat COMMIT` shows each change.
Three of them matter most for a port:

- A fork from `femu-v5.2` or `femu-v5.2.1` has its code under
  `hw/block/femu/`. The same files are now under `hw/femu/`.
- A fork that changed the bbssd FTL changed `bbssd/ftl.c`. The
  functions of that file are now in seven files, `ftl.c` included.
- Each new property needs help text in `femu-props.c` (9489cf692). The
  property reference is generated from that text.

## 3. The symbol map

`hw/femu/scripts/femu-symbol-map.py` reads two git revisions. It prints
what became of each old file, function, struct, field, enum constant,
macro and `-device` property:

```sh
python3 hw/femu/scripts/femu-symbol-map.py femu-v9.0.1 origin/master
python3 hw/femu/scripts/femu-symbol-map.py femu-v9.0.1 origin/master --summary
python3 hw/femu/scripts/femu-symbol-map.py femu-v9.0.1 origin/master \
    --touched femu-v9.0.1..fork/main
```

The third form is the one to use for a port. It keeps only the old names
that the changed lines of your fork use, and the old files that the fork
changes. It needs no build. It takes about 10 s for `femu-v9.0.1` and
about 50 s for `femu-v5.2`.

```
 git ls-tree + cat-file OLD --> old definitions --+
                                                  +--> same / moved / split
 git ls-tree + cat-file NEW --> new definitions --+    redefined / default / value
                                                         |
                                                         | name gone at NEW
 git log -p OLD..NEW --> newest commit that removed more definitions
                         of the name than it added (comments left out)
                                                         |
                     similar name defined in that commit?
                         yes --> candidate (with a score)
                         no  --> removed
```

Each line has seven tab-separated columns: kind, old name, status, new
name, file at NEW, commit and note. The status is one of these:

| Status | Meaning |
| --- | --- |
| `same` | same name, same file (printed only with `--all`); the code can still differ |
| `moved` | same name, another file; for a field, a renamed struct |
| `redefined` | a function with the same name but other parameter or return types |
| `split` | the functions of the old file are now in more than one file |
| `candidate` | the name is gone; the commit that removed it added a similar name, or a field of the same name is in another struct |
| `removed` | the name is gone, with no similar name in the removal commit |
| `default` | a property with another default |
| `value` | an enum constant with another value |

A `candidate` is a lead and not a proof. Read `git show COMMIT` before
you use it. For example, `femu-v9.0.1` gives the candidate
`advance_read_pointer` -> `zns_advance_write_pointer` with score 0.80.
That function went away when 0326ab489 rewrote the ZNS timing, so check
it by hand. A note `lead` means that the script found the commit only
from the bare name, and not from a definition.

The map is a start, not a full port plan. It names definitions, not the
behaviour behind them. The parser reads C with regular expressions, and
it finds definitions at the start of a line, in the QEMU style. A name
that is defined in two old files (two static helpers) gets one line for
each file.

`redefined` is common for ZNS. In `femu-v9.0.1`, `zns_read` and
`zns_write` in `zns/zns.c` were NVMe command handlers that returned a
status. On master, functions with the same names in `zns/zftl.c` return a
latency for the zone FTL. The NVMe entry point is now `zns_nvme_rw` in
`zns/zns.c` (0326ab489).

Counts of old definitions that changed, against master e28c2577d
(`--summary`, all kinds):

| Old tag | moved | redefined | candidate | removed | split | default | value |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `femu-v5.2` | 480 | 15 | 101 | 40 | 4 | 7 | 1 |
| `femu-v5.2.1` | 59 | 39 | 47 | 23 | 4 | 1 | 3 |
| `femu-v7.0.0` | 59 | 39 | 47 | 23 | 4 | 1 | 3 |
| `femu-v9.0.1` | 59 | 44 | 44 | 29 | 3 | 1 | 3 |

The move from `hw/block/femu` to `hw/femu` (1cfe6187b) does not count as
a move. `femu-v8.0.0` gives the same counts as `femu-v7.0.0`.

## 4. Hook points that a fork changes

Most research forks change the bbssd FTL: the write path, the mapping,
GC or the NAND timing. The table gives the place of each hook in
`femu-v9.0.1` and on master. The symbol map gives each entry.

| Hook | `femu-v9.0.1` | master |
| --- | --- | --- |
| read and write path | `ssd_read`, `ssd_write` in `bbssd/ftl.c` | [`bbssd/ftl-datapath.c`](../../bbssd/ftl-datapath.c) |
| mapping table | `get_maptbl_ent`, `set_maptbl_ent` in `bbssd/ftl.c` | [`bbssd/ftl-internal.h`](../../bbssd/ftl-internal.h) |
| mapping setup | `ssd_init_maptbl`, `ssd_init_rmap` in `bbssd/ftl.c` | [`bbssd/ftl-map.c`](../../bbssd/ftl-map.c) |
| GC | `do_gc`, `select_victim_line`, `gc_read_page`, `gc_write_page`, `clean_one_block` in `bbssd/ftl.c` | [`bbssd/ftl-line-gc.c`](../../bbssd/ftl-line-gc.c) |
| line and page state | `mark_page_valid`, `mark_page_invalid`, `get_new_page`, `ssd_advance_write_pointer` | `bbssd/ftl-line-gc.c` |
| NAND timing | `ssd_advance_status` in `bbssd/ftl.c` | [`bbssd/ftl-media.c`](../../bbssd/ftl-media.c), over [`nand/nand-media.c`](../../nand/nand-media.c) |
| NAND page times | `get_page_read_latency` and others in `nand/nand.h` | [`nand/nand.c`](../../nand/nand.c) |
| geometry | `ssd_init_params`, `check_params` in `bbssd/ftl.c` | [`bbssd/ftl-geom.c`](../../bbssd/ftl-geom.c) |
| FTL thread | `ftl_thread` in `bbssd/ftl.c` | candidate `femu_ftl_thread` in [`femu.c`](../../femu.c) (053fd8936) |
| ZNS timing | `zns_advance_status` in `zns/zns.c` | [`zns/zftl.c`](../../zns/zftl.c) |
| OCSSD timing | `timing-model/timing.c` | [`ocssd/oc-timing.c`](../../ocssd/oc-timing.c) |

Master also has two plug-in interfaces in
[`bbssd/ftl-ops.h`](../../bbssd/ftl-ops.h). A fork that replaced the mapping or
the GC victim choice can often become one entry in a table. Then it
needs no edits to the write path:

```
 ssd_write() --> ssd_program_lpn()            (ftl-datapath.c)
     1  ssd->mapping->prepare_write()       choose the write class
     2  get_new_page_class()                take a page in that class
     3  ssd->mapping->commit_write()        invalidate the old page, map lpn
     4  mark_page_valid()                   (ftl-line-gc.c)
     5  NAND program time                   ssd_advance_status (ftl-media.c)

 do_gc()  (ftl-line-gc.c)
     1  ssd->policy->select_victim_line()
     2  gc_read_page(), gc_write_page()
     3  ssd->mapping->gc_relocate_commit()  point lpn at the copied page

 ssd_read() --> ssd->mapping->translate()
```

- `struct femu_mapping_ops` (in `bbssd/ftl-ops.h`): `translate`,
  `prepare_write`, `commit_write`, `gc_relocate_commit`, `trim`,
  `needs_reclaim` and `reclaim`. The list `femu_mapping_list[]` in
  `ftl-map.c` holds the schemes. The `mapping` property selects one by
  name.
- `struct femu_ftl_policy_ops` (in `bbssd/ftl-ops.h`):
  `select_victim_line`. The table `femu_ftl_policies[]` in
  `ftl-line-gc.c` holds the policies. The `gc_policy` property selects
  one by name.
- [Extension interface](../development/extension-interface.md) states
  the rules that each table must keep. Realize refuses a table that
  breaks them.

The order matters for a port. `commit_write` runs before the page is
marked valid and before the program time is charged. The flat scheme
in `ftl-map.c` updates the reverse map and the page state there. A new
mapping scheme must do the same work. A scheme with its
own merge work sets `needs_reclaim` and `reclaim`, and charges the NAND
time inside `reclaim`.

The FTL thread changed too. Now one worker per controller takes each
request. The function `femu_ftl_process_req` in `femu.c` chooses the
backend from the namespace of the request.

The bbssd state is per namespace,
in `ns->ssd`. A fork that kept global state in the old `ftl_thread` must
move it into the namespace state. Teardown stops the pollers and the FTL
thread before it frees that state.

NAND timing has two layers on master:

```
 bbssd / ZNS / OCSSD address --> NandLoc --> nand_media_op() --> NandOpCompletion
 (controller adapter:            (nand/nand-media.c:              done_ns    absolute time
  ftl-media.c, zftl.c, oc*.c)     timing policy, busy math)       latency_ns done - start
```

- The adapter turns the controller address into a `NandLoc`. The
  controller owns the busy timelines (`next_*_avail_time`).
- The media layer owns the timing policy. It never reads a controller
  header.
- All times are in ns. Keep one charge for each NAND operation: a fork
  that adds a delay in the adapter and also in the media layer counts it
  twice.

A new property needs three more changes:

1. Add a `DEFINE_PROP_*` line in `femu.c`.
2. Add its help text in `femu-props.c`.
3. Regenerate the reference with `gen-property-docs.py`, and name the
   property in a test ([testing](testing.md)).

## 5. Command lines, old and current

A few old settings now mean something else, or are gone. Each row gives
the evidence:

| Old setting | Then | Now | Evidence |
| --- | --- | --- | --- |
| `femu_mode=0` with no `lver` (`femu-v5.2`) | OCSSD 1.2, the only version | `lver` defaults to 2; add `lver=1` for 1.2 | `femu-v5.2` has no `lver` property and no OCSSD 2.0 file |
| `zns_read`, `zns_write` (`femu-v9.0.1` only) | fixed ZNS page read and write delay, ns | gone; use `zns_pg_rd_lat`, `zns_pg_wr_lat` | added 6819f1219, removed 0326ab489 |
| `femu_mode=4` (`femu-v5.2.1` to `femu-v9.0.1`) | `FEMU_SMARTSSD_MODE`, with no command handlers | CSD, which needs `fdm_size` | CSD took 4 in eb01bb73b; 6 is refused (c3b8e88ef) |
| `femu_mode=5` | `FEMU_KVSSD_MODE`, an enum value with no code | the KV mode | e72465909; no tag has a `kvssd/` folder |
| `multipoller_enabled` (`femu-v5.2`) | default 1 | default 0 | 1730ba87b |
| `lnum_ch`, `lnum_lun`, `lnum_pln`, `lsecs_per_pg`, `lpgs_per_blk` (`femu-v5.2`) | defaults 1, 1, 1, 1, 256 | defaults 2, 8, 2, 4, 512 | 1730ba87b |
| `oncs` | default: DSM only | also Compare, Write Zeroes, Features, Verify and Copy | first change 2380e4ecc |

`femu-symbol-map.py OLD origin/master --kind prop,enum` prints these rows
for your tag. The bbssd geometry and NAND time properties kept their
names in every release.

Each `femu_mode` number also has a name now (e2c546af9). The names are
`ocssd`, `bbssd`, `nossd`, `zns`, `csd` and `kv`, set with `mode=`.
Use one of the two, or give both the same mode. Realize refuses
`femu_mode=1,mode=zns` (`femu_mode_resolve` in `femu.c`). `femu_mode=2`
is the exception: FEMU cannot tell it from the default, so `mode=` wins.

The `femu-config-check.py` script shows what FEMU builds from a line, or
why it refuses the line ([debugging](debugging.md)).

The binary moved too. A `femu-v5.2` build puts it at
`x86_64-softmmu/qemu-system-x86_64`. Builds since then put it at
`./qemu-system-x86_64` in the build directory.

### NoSSD

The `femu-v5.2` `run-nossd.sh` line still works as written:

<!-- femu-example: port-nossd -->
```text
-device femu,devsz_mb=1024,id=nvme0

-device femu,mode=nossd,devsz_mb=1024
```

### BlackBox SSD (bbssd)

The `femu-v5.2` `run-blackbox.sh` line still works as written. The second
line is the same device with the mode name:

<!-- femu-example: port-bbssd-v52 -->
```text
-device femu,devsz_mb=1024,femu_mode=1

-device femu,mode=bbssd,devsz_mb=1024
```

The `femu-v9.0.1` `run-blackbox.sh` line is the same as the master
launcher, so it needs no change. The
[BlackBox mode page](../modes/blackbox.md) has the tested launcher.

### OCSSD 1.2

The `femu-v5.2` `run-whitebox.sh` line gave OCSSD 1.2:

<!-- femu-untested: old femu-v5.2 syntax that master reads as OCSSD 2.0 -->
```text
-device femu,devsz_mb=1024,namespaces=1,lmetasize=16,nlbaf=5,lba_index=3,mdts=10,lnum_ch=2,lnum_lun=8,lnum_pln=2,lsec_size=4096,lsecs_per_pg=4,lpgs_per_blk=512,femu_mode=0
```

On master the same line gives OCSSD 2.0, because `lver` defaults to 2.
Add `lver=1` to keep 1.2:

<!-- femu-example: port-ocssd12-v52 -->
```text
-device femu,devsz_mb=1024,namespaces=1,lver=1,lmetasize=16,nlbaf=5,lba_index=3,mdts=10,lnum_ch=2,lnum_lun=8,lnum_pln=2,lsec_size=4096,lsecs_per_pg=4,lpgs_per_blk=512,femu_mode=0
```

### OCSSD 2.0

The `femu-v9.0.1` `run-whitebox.sh` line sets `lver=2` and works as
written. The [OCSSD mode page](../modes/ocssd.md) has it as a tested
example.

### ZNS

The `femu-v9.0.1` `run-zns.sh` line used two properties that are gone.
They were in `femu-v9.0.1` only:

<!-- femu-untested: old femu-v9.0.1 syntax; zns_read and zns_write are gone -->
```text
-device femu,devsz_mb=4096,namespaces=1,zns_num_ch=8,zns_num_lun=4,zns_read=40000,zns_write=200000,femu_mode=3
```

Use `zns_pg_rd_lat` and `zns_pg_wr_lat` for the same page times:

<!-- femu-example: port-zns-v901 -->
```text
-device femu,devsz_mb=4096,namespaces=1,zns_num_ch=8,zns_num_lun=4,zns_pg_rd_lat=40000,zns_pg_wr_lat=200000,femu_mode=3
```

The numbers do not stay the same. In `femu-v9.0.1`, each ZNS read or
write cost one fixed delay. Each erase cost a fixed 2000000 ns.

Since 0326ab489, a write cache and the FTL of `zns/zftl.c` time each ZNS
command. The erase time comes from `zns_blk_er_lat` when it is set.
Otherwise it is the built-in time of the NAND type in `zns_flash_type`
(QLC by default).

A ZNS time of 0 selects the built-in time, not zero time. The zone size
now comes from the geometry.
[ZNS](../modes/zns.md) has the full model.

### KV and CSD

No old release has KV or CSD code. `femu-v9.0.1` names `FEMU_KVSSD_MODE`
only in an enum. A fork that added its own KV or computational mode must
compare its code with [KV](../modes/kvssd.md) and [CSD](../modes/csd.md)
on master.

A `femu_mode=4` line now asks for a CSD device. CSD needs `fdm_size`, so
an old line with no `fdm_size` fails at realize (`hw/femu/csd/csd.c`).

### Configuration files

`ssd-config.sh` turns a file of `key = value` lines into the `-device`
line ([tutorial 09](../tutorials/09-ssd-config-files.md)). A file is a
good way to keep a ported configuration. This file is the
`femu-v9.0.1` ZNS drive:

```ini
# The femu-v9.0.1 run-zns.sh drive on current master.
[device]
mode       = zns
devsz_mb   = 4096
namespaces = 1

[zones]
zns_num_ch  = 8
zns_num_lun = 4

[timing]
zns_pg_rd_lat = 40000
zns_pg_wr_lat = 200000
```

From the build directory, on the host:

```sh
export FEMU_BIN=$PWD/qemu-system-x86_64
../femu-scripts/ssd-config.sh old-zns.conf
```

<!-- femu-example: port-zns-conf -->
```text
-device femu,id=nvme0,devsz_mb=4096,namespaces=1,zns_num_ch=8,zns_num_lun=4,zns_pg_rd_lat=40000,zns_pg_wr_lat=200000,femu_mode=3
```

With `FEMU_BIN` set, the script refuses a key that the binary does not
know. An old `zns_read` key stops the script with an error.

## 6. Move the commits onto master

A port moves only the fork's own commits. The QEMU base under them
changes from the old one to 11.1.3. Do not merge the old QEMU tree.

```
 femu-vX ---- fork commits ---- fork/main
    |
    +---- ... master commits ... ---- origin/master ---- port commits (new)
                                                          ^
                    git cherry-pick -x, one commit at a time
```

1. Make a branch from master: `git switch -c port origin/master`.
2. List the fork's commits: `git log --oneline --reverse "$base"..fork/main`.
3. Find the commits that change QEMU outside `hw/femu`:
   `git log --oneline "$base"..fork/main -- . ':!hw/femu' ':!hw/block/femu'`.
4. Print the symbol map for the fork, with `--touched "$base"..fork/main`.
5. Apply the commits in order: `git cherry-pick -x COMMIT`.
6. On a conflict in a split file, put each hunk in the file the map gives.
7. Rename each old symbol to its new name, after you check the map line.
8. Build after each commit, so each error points to one commit.
9. Compare the series: `git range-diff "$base"..fork/main origin/master..port`.

Git follows a rename such as `hw/block/femu/` to `hw/femu/` when the
content stays similar. Git cannot follow a split of one file into seven.
For a fork of `bbssd/ftl.c`, this way is often faster:

1. Export the fork's change of that file:
   `git diff "$base" fork/main -- hw/femu/bbssd/ftl.c > ftl-fork.diff`.
2. Find each changed function in the map. The map gives its new file.
3. Make the same change in the new file by hand.

`git range-diff` puts each old commit next to its new version. A commit
that lost a hunk shows as a removed line in the range-diff, so read it
before you trust the port. The map and the range-diff do not replace a
full read of the fork diff. A change to a macro body or a build file
names no symbol, so `--touched` cannot find it.

## 7. Checks for a ported fork

Run these after the port. [Testing](testing.md) explains each one.

```
 unit tests --> qtests --> doc and property checks --> config check --> guest test
 (no build)    (build)     (build)                     (build)          (KVM, image)
```

1. Unit tests with no build: `make -C hw/femu/tests check`.
2. Build QEMU and `qos-test` as in
   [testing](testing.md#build-for-testing), with `femu-compile.sh` or by hand.
3. Unit tests in the build: `meson test --suite femu-unit`.
4. All FEMU qtests: the `qos-test` command in
   [testing](testing.md#device-tests-qtest).
5. The qtests again in a sanitizer build with `-DFEMU_FTL_ASSERT`
   ([sanitizer build](testing.md#sanitizer-build)).
6. Doc and property checks: `make -C hw/femu/tests check-docs`.
7. Property tests: `python3 hw/femu/scripts/check-property-tests.py`.
8. Code style: `python3 hw/femu/scripts/check-c-style.py hw/femu`.
9. Each of your command lines: `femu-config-check.py` on it.
10. A guest boot with your workload, then the C0h counters
    ([measuring](measuring.md)).

Steps 1 to 8 are also in CI. Each check covers a different part:

| Check | What it shows |
| --- | --- |
| doc lint | each command block has a tag |
| doc example run | QEMU realizes the line; then Identify, and one write and read (Identify only for OCSSD) |
| qtests | admin and I/O commands, GC, overwrite and trim paths of each mode |
| guest test | the real driver, your workload and its numbers |

For a ZNS fork, also check zone reset, Zone Append and the write pointer
in the guest. For an OCSSD fork, check the version (`lver`), the geometry
and the guest tools that [OCSSD](../modes/ocssd.md) names.

A fork that adds a property must name it in a test, or step 7 fails. A fork that adds a refusal must also add it to
[combinations](../reference/combinations.md) with `gen-combinations.py`.

Compare your old numbers with the new ones only after you read
[the changelog](../CHANGELOG.md#behaviour-changes-still-boots-numbers-move).
Many defaults and timing models changed since the old releases, so a
change in WAF or latency is not by itself a port error.
