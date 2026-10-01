# Tutorial 09: configuration files

You describe a device in a short INI-style file instead of a long
`-device femu,...` line, expand it with `ssd-config.sh`, let the script
catch a misspelled property, and boot the result. It takes about ten
minutes.

You need: a built FEMU and the variables from
[Before you start](README.md#before-you-start). Steps 1 to 4 run on the
host and start no guest.

## Background

`hw/femu/scripts/ssd-config.sh` turns a file of `key = value` lines into
QEMU `-device` arguments. Keys are the `femu` device's property names and
mean exactly what [the property reference](../reference/properties.md)
says. Two additions:

- `mode = bbssd` (or `znssd`, `nossd`, `ocssd`, `csd`, `kvssd`) stands for
  `femu_mode`.
- Keys under a `[subsys]` section become a separate
  `-device femu-subsys,...`, which the `femu` device is joined to. FDP
  lives there.

Other section headers are labels for the reader. `#` and `;` start a
comment, and a key with an empty value is ignored, so a file can list a
property and leave it at its default. The script checks every key against
`-device femu,help` of the binary named by `FEMU_BIN`.

## 1. Write a configuration

Save the drive of [tutorial 02, step 6](02-gc-and-waf.md#6-hotcold-separation)
as `gc-study.conf` in `build-femu/`:

```ini
# Tutorial 02's skewed-workload drive: 2 GiB of NAND, 25% spare,
# GC only when forced, cost-benefit victims, hot and cold separated.

[device]
mode     = bbssd
op_pcent = 25

[geometry]
nchs        = 4
luns_per_ch = 4
blks_per_pl = 128

[gc]
gc_thres_pcent = 95
gc_policy      = cost-benefit
hot_cold_sep   = on
```

## 2. Expand it

From `build-femu/`, on the host:

```sh
export FEMU_BIN=$PWD/qemu-system-x86_64
../femu-scripts/ssd-config.sh gc-study.conf
```

<!-- femu-example: tut09-gc-study -->
```text
-device femu,id=nvme0,op_pcent=25,nchs=4,luns_per_ch=4,blks_per_pl=128,gc_thres_pcent=95,gc_policy=cost-benefit,hot_cold_sep=on,femu_mode=1
```

That is the line you would otherwise type, and the documentation checks
start it under QEMU.

The script adds `id=nvme0` unless the file sets an `id`. `--device-only`
prints the arguments without the `-device` words, for a launcher that adds
them itself. Set `FEMU_BIN`: run through the `../femu-scripts` link, the
script cannot find the binary on its own and then skips the key check
with a warning.

## 3. Let it catch mistakes

Misspell a key:

```sh
printf '[device]\nmode = bbssd\ngc_polcy = greedy\n' > bad.conf
../femu-scripts/ssd-config.sh bad.conf; echo "exit $?"
```

```text
ssd-config: unknown property 'gc_polcy' -- not one FEMU accepts
ssd-config: config rejected; see the warnings above
exit 1
```

Put a subsystem property on the controller:

```sh
printf '[device]\nmode = bbssd\nfdp = on\n' > bad.conf
../femu-scripts/ssd-config.sh bad.conf
```

```text
ssd-config: 'fdp' is a subsystem property; move it under [subsys]
ssd-config: config rejected; see the warnings above
```

`--check` validates a file without printing the arguments: it prints the
same warnings for a bad file, nothing for a good one, and its exit status
says which. The script checks names only. Values, ranges and combinations
are checked when QEMU creates the device, which stops with a message; the
"Limits and refusals" section of each mode page lists them, for example
[BlackBox](../modes/blackbox.md#limits-and-refusals).

## 4. Lists and subsystems

The shipped files in `hw/femu/scripts/configs/` show the two conveniences.
A list value is written with plain commas, and the script doubles them for
QEMU:

```sh
../femu-scripts/ssd-config.sh ../femu-scripts/configs/heterogeneous.conf
```

<!-- femu-example: tut09-heterogeneous -->
```text
-device femu,id=nvme0,devsz_mb=6144,namespaces=3,namespace_modes=bbssd,,znssd,,nossd,secsz=512,secs_per_pg=8,pgs_per_blk=256,blks_per_pl=256,pls_per_lun=1,luns_per_ch=8,nchs=8,femu_mode=1
```

A `[subsys]` section becomes its own device, placed first, with the
controller joined to it:

```sh
../femu-scripts/ssd-config.sh ../femu-scripts/configs/fdp.conf
```

<!-- femu-example: tut09-fdp -->
```text
-device femu-subsys,id=femu-subsys-0,nqn=subsys0,fdp=on,fdp.nruh=4,fdp.nrg=1,fdp.nru=256 -device femu,id=nvme0,devsz_mb=4096,namespaces=1,secsz=512,secs_per_pg=8,pgs_per_blk=256,blks_per_pl=256,pls_per_lun=1,luns_per_ch=8,nchs=8,femu_mode=1,subsys=femu-subsys-0
```

## 5. Boot it

The launchers take no arguments, so put the expansion on your own QEMU
command line, the one from
[tutorial 01, step 2](01-first-ssd.md#2-start-the-guest-on-the-host), in
place of its `-device femu` option. In bash:

<!-- femu-untested: the device options come from ssd-config.sh at run time -->
```bash
QEMU_ARGS=$(../femu-scripts/ssd-config.sh gc-study.conf)
./qemu-system-x86_64 -name femu-tut09,debug-threads=on \
    -enable-kvm -cpu host -smp 4 -m 4G \
    -device virtio-scsi-pci,id=scsi0 -device scsi-hd,drive=hd0 \
    -drive file=$OSIMGF,if=none,cache=none,format=qcow2,id=hd0 \
    -net user,hostfwd=tcp::$SSH_PORT-:22 -net nic,model=virtio \
    $QEMU_ARGS -nographic
```

`$QEMU_ARGS` is left unquoted on purpose: bash splits it into the
`-device` word and its options. zsh does not split an unquoted variable,
and QEMU then stops with `invalid option`; in zsh write `${=QEMU_ARGS}`,
or run the command under bash. In the guest, `sudo nvme list` shows the
1.72 GB BlackBox drive of tutorial 01.

## What you learned

- A configuration file names the same properties as `-device femu`, with
  `mode` for `femu_mode` and a `[subsys]` section for FDP.
- `ssd-config.sh` checks names against the binary in `FEMU_BIN`; QEMU
  checks values when it starts.
- List values need no doubled commas in the file.

## Next

- [Scripts and tools](../reference/scripts.md#configuration-files)
  describes `ssd-config.sh` and the shipped files.
- [The parameter manual](../reference/parameter-manual.md) explains what
  to put in a configuration, group by group.
