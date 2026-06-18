# FEMU high-IOPS socket-isolation benchmark

Reproduces the single-VM high-IOPS results in `../../HIOPS.md`. The harness pins
the guest VM to one CPU socket and the FEMU emulation (poller threads + the
emulated-SSD backend) to the other, then drives the device from inside the guest
with SPDK (and, optionally, fio on the SPDK plugin).

## Prerequisites (one-time)

### Host
- A 2-socket (NUMA) x86_64 server with KVM. Results in `HIOPS.md` are from a
  2x Intel Xeon Gold 6548Y+ (Emerald Rapids, 64 physical / 128 logical cores).
- Build FEMU (`../femu-compile.sh`); note the `build/` dir.
- Kernel cmdline with **1 GiB hugepages** and the IOMMU enabled, e.g.:
  ```
  intel_iommu=on,sm_on default_hugepagesz=1G hugepagesz=1G hugepages=96 \
  hugepagesz=2M hugepages=24576 mitigations=off
  ```
  (The 1G pool is split ~evenly across the two NUMA nodes; you need at least
  `MEM` GiB free on the guest's node. `mitigations=off` removes per-exit cost.)
- `sudo mount -t hugetlbfs hugetlbfs /dev/hugepages` (step 0 does this if needed).

### Guest image
A cloud guest (the results used Ubuntu 24.04, kernel 6.8) prepared with:
- cloud-init user/pass `femu`/`femu`, sshd enabled (the seed.iso).
- **SPDK** built in `~/spdk` **with the fio plugin**:
  ```
  git clone https://github.com/spdk/spdk; cd spdk; git submodule update --init
  ./scripts/pkgdep.sh
  ./configure --with-fio=/path/to/fio/source   # build fio from source first
  make
  ```
  This produces `~/spdk/build/examples/bdevperf` and
  `~/spdk/build/fio/spdk_nvme` (the fio engine).
- **fio** (3.36+) installed.
- Guest cmdline `intel_iommu=off` (SPDK uses vfio-pci no-IOMMU mode).

## Configure

Edit the paths and knobs at the top of `env.sh` (or pass them as env vars):
`FEMU_BUILD`, `BASE_IMG`, `SEED`, `SMP`, `MEM`, `DEVSZ_MB`.

`SMP` should equal the number of logical CPUs you give the guest on one socket
(e.g. 48 on a 64-logical-CPU socket, leaving headroom for the OS). It is used as
vCPUs == IO queues == SPDK reactors.

## Run

```
bash run-all.sh                 # isolated, SPDK bdevperf, 512B random read
IOSIZE=4096 bash run-all.sh     # 4 KiB
ENGINE=fio  bash run-all.sh     # fio on the SPDK plugin
GUEST_NODE=1 bash run-all.sh    # non-isolated baseline (everything on node1)
```

Or step by step (each is standalone):

| Step | Does |
|---|---|
| `00-check-host.sh` | hugepage pools, NUMA topology, artifacts, stale-VM check |
| `01-launch-vm.sh`  | launch QEMU detached; guest RAM -> node0, mbe -> node1 |
| `02-guest-prep.sh` | bind the device to SPDK in the guest + warm run (spawns pollers) |
| `03-pin.sh`        | pin vCPUs -> node0, femu-pollers -> node1; print isolation check |
| `04-measure.sh`    | run the measured bench, print IOPS |

## Notes

- **The pinning assumes node0 = even logical CPUs, node1 = odd.** Verify with
  `cat /sys/devices/system/node/node0/cpulist`; adjust `03-pin.sh` if your host
  enumerates sockets as contiguous ranges instead.
- The FEMU pollers only exist while the controller is enabled, so always run
  step 2 (which spawns them) before step 3 (which pins them).
- 4 KiB random read is cross-socket-bandwidth bound on a 2-socket host; the
  high IOPS headline is the 512B number.
- A non-isolated run (`GUEST_NODE=1`, no pinning) is much slower -- it
  oversubscribes one socket; that contrast is the point of the split.
