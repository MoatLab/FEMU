# Running this FEMU

Every command below was run on the measurement host and its output is what is
quoted. Two entry points, because they answer different questions.

| you want | go to |
|---|---|
| a VM with this project's SSD attached, to poke at | [A device](#a-device) |
| the placement measurement, end to end | [A measurement](#a-measurement) |

The device is the same either way, and no geometry argument is needed for it:
`compose.yaml` defaults to the configuration the measurements were taken on --
64 GiB over 2 channels x 4 LUNs, 512 pages per block, QLC, `op_pcent=7`.

## Why a container

The [README](README.md)'s path builds on the host and launches with
`run-blackbox.sh`. That does not work here. `pkgdep.sh` installs packages, and
FEMU pins its memory backend, which needs `RLIMIT_MEMLOCK` raised past the
device size -- this host allows 64 MiB against 64 GiB. Both need root, and
there is no passwordless sudo.

The container is given `IPC_LOCK` and an unlimited memlock, so it pins without
the host granting root to anyone. The steps are the README's:

| README | here |
|---|---|
| `sudo ./pkgdep.sh` | `docker/Dockerfile`, builder stage |
| `./femu-compile.sh` | `docker/Dockerfile`, builder stage |
| `./qemu-system-x86_64 -device femu,help` | `femu-docker.sh verify` |
| `./run-blackbox.sh` | `femu-docker.sh run` |

Inside the container that argument no longer applies -- it runs as root -- and
`run-blackbox.sh` is usable there too: it now reads the same environment
variables. What it could not do before was take any configuration at all; the
layout was written into the file.

## A device

```bash
cd /data/kwkim02/MoE_FEMU

export FEMU_GUEST_DIR=/data/kwkim02/images          # where guest disks live
export FEMU_DATA_DIR=$PWD/docker-data               # container's /data
export FEMU_INSTANCE=demo                           # names disk, seed, container
```

**Build.** Dependencies and compile happen inside; the host gets nothing.

```bash
./femu-scripts/femu-docker.sh build
```

**Check the device registered.**

```bash
./femu-scripts/femu-docker.sh verify
#   femu options:
#     acl=<uint8> ... blks_per_pl=<int32> ... nand_cell_type=<uint8> ...
```

**Make this instance's guest disk.** A copy-on-write overlay plus a cloud-init
seed carrying your ssh key. The base image is never written, and the cloud
image ships no password, so without the seed there is no way in.

```bash
./femu-scripts/femu-docker.sh image
#   overlay /data/kwkim02/images/femu-root-demo.qcow2
#   seed    /data/kwkim02/images/seed-demo.iso
```

**Start it.** Holds the terminal; Ctrl-C detaches and leaves the container up.

```bash
./femu-scripts/femu-docker.sh run
#   FEMU mode=bbssd, NAND cell type=4, image=/guest/femu-root-demo.qcow2
#   Guest SSH is forwarded to container port 2222
```

**Get in.** Boot takes three to four minutes. The `femu login:` prompt appears
well before you can log in -- cloud-init installs the key after it. Wait for
`Cloud-init ... finished` on the console.

```bash
./femu-scripts/femu-docker.sh ssh
#   femu@femu:~$ lsblk -dno NAME,SIZE /dev/nvme0n1
#   nvme0n1 59.8G
```

59.8 G rather than 64 is `op_pcent=7`: the over-provisioning every layout here
is planned against.

**Stop.**

```bash
./femu-scripts/femu-docker.sh stop
```

**What am I about to get.**

```bash
./femu-scripts/femu-docker.sh status
#   cell=4 size=65536MB 2ch x 4LUN 512pg/blk 1024blk/pl opts=op_pcent=7
```

## A measurement

A device with nothing on it measures nothing. A run also needs a payload image,
a compiled trace and the placement checks, which is a different entry point:

```bash
FEMU_PROJECT_ROOT=/data/kwkim02/MoE_SSD \
  bash /data/kwkim02/MoE_FEMU/moe-harness/exp/moe_bcq/femu_run/run_device.sh \
       DEVICE_TAG IMAGE_BASENAME IMAGE_PAGES SPECFILE
```

`FEMU_PROJECT_ROOT` is where the data lives. The harness resolves its own code
from where it sits and the data from there, so the two need not be together --
the images, payload packages and records are tens of gigabytes and are
distributed separately from this repository.

It boots a device, fills it, asserts the placement landed, replays each trace
in the spec file, and writes `groups.jsonl.gz` and `replay.csv` per run under
`<data root>/exp/moe_bcq/femu_run/records/<run name>/`.

See [moe-harness/README.md](moe-harness/README.md) for what a spec file is, what
the fill contract is, and why a matching read-back hash does not mean the
placement is right.

## If something goes wrong

**`no python3 with pycdlib`** — the seed builder needs it. `pip install --user
pycdlib`, or set `PYTHON` to an interpreter that has it.

**`kex_exchange_identification: Connection closed`** — the guest is up but
cloud-init has not installed the key yet. Wait for `Cloud-init ... finished`.

**`already exists: .../femu-root-demo.qcow2`** — `image` refuses to overwrite an
instance's disk. Delete it to start over, or use another `FEMU_INSTANCE`.

**A device that is not 59.8 G** — something is overriding the compose defaults.
`femu-docker.sh status` prints what the instance would actually get.

**Port 2222 already bound** — another instance is running. `docker ps`, then
`FEMU_INSTANCE=<that one> ./femu-scripts/femu-docker.sh stop`, or set
`FEMU_SSH_PORT` for this one.
