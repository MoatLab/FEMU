# Performance tuning

FEMU's timing model computes when each command should complete, and a
poller thread posts the completion once the host clock passes that time
([timing model](../concepts/timing-model.md#compute-then-hold)). The model
gives a lower bound: if a poller does not get a host CPU when a completion
is due, the guest waits longer than the model says. Tuning is mostly about
giving FEMU's threads the CPUs and memory they need, so that the latency
you measure is the model's and not the host's.

## Threads and cores

These threads run inside QEMU:

| Thread name | How many | Started | Uses a core |
| --- | --- | --- | --- |
| `CPU N/KVM` | one per guest vCPU (`-smp`) | at start | while the vCPU runs |
| `femu-poller` | 1, or `ceil(queues / poller_ratio)` with `multipoller_enabled=1` | when the guest first enables the controller | always: it spins while the controller is enabled |
| `FEMU-FTL-Thread` | one per controller with a BlackBox, ZNS or CSD namespace | at start | always: it spins while the controller is enabled |
| `femu-cxl-ftl` | one per `femu-cxl-ssd` with `ftl=on` (the default) | at start | only while it serves a miss |
| `femu-cxl-cca` | one per `femu-cxl-ssd` with `cca=on` | at start | only while it serves a command |

Linux shows these names only when QEMU runs with `-name NAME,debug-threads=on`.
The launchers pass `-name` without it, so every thread is called
`qemu-system-x86`. To see the names, add `,debug-threads=on` to the `-name`
option in the launcher you use, for example
`-name "FEMU-BBSSD-VM",debug-threads=on` in `run-blackbox.sh`.

Plan one host core for every poller and FTL thread, on top of one per vCPU.
`run-blackbox.sh` (4 vCPUs, one poller, one FTL thread) needs at least 6
cores to itself; 8 is comfortable. When cores are short, the first sign is
latency above the configured NAND time and run-to-run variation.

## Pollers and queues

Properties: [queues, pollers and interrupts](../reference/properties.md#queues-pollers-and-interrupts).

| Setting | Pollers | Use it when |
| --- | --- | --- |
| `multipoller_enabled=0` (default) | 1, serving every I/O queue | You measure latency at low queue depth, or have few spare cores |
| `multipoller_enabled=1`, `poller_ratio=1` | one per I/O queue | You need throughput from several guest jobs and have a core per queue |
| `multipoller_enabled=1`, `poller_ratio=R` | `ceil(queues / R)`, each serving R queues | You need more than one poller but have fewer spare cores than queues |

Other values of `multipoller_enabled` are refused at start. `poller_ratio=0`
counts as 1.

The number of pollers comes from the `queues` property (default 8), not from
the number of queues the guest creates. Linux creates about one I/O queue
pair per guest CPU, up to `queues`. A poller whose queues the guest never
created still spins. So set `queues` to the guest's vCPU count when you turn
on more pollers. With 4 vCPUs and a poller per queue:

<!-- femu-example: tuning-pollers -->
```
-device femu,devsz_mb=4096,femu_mode=1,queues=4,multipoller_enabled=1
```

What you trade:

- One poller walks every queue on each pass. It needs only one core, but
  its pass gets longer with each busy queue, and all completions share it.
- A poller per queue keeps each queue's path short and scales with guest
  jobs, at the cost of one spinning core per queue.
- `poller_ratio` sits in between. Each poller serves its queues
  round-robin: poller i serves queues i, i + P, i + 2P and so on, where P is
  the number of pollers.

## Pin the threads

Unpinned, the scheduler moves vCPUs and pollers between cores and lets them
share a core with other work. Pin them to separate cores. With
`debug-threads=on` added to the launcher (see above), boot the guest, then
on the host:

```sh
pid=$(pgrep -x qemu-system-x86)
ps -T -p "$pid" -o tid=,comm=
```

Pin the vCPUs with the QMP helper that `femu-copy-scripts.sh` copies to
`build-femu/ftk/`. This puts vCPU 0 to 3 on host CPUs 0 to 3:

```sh
sudo ./ftk/qmp-vcpu-pin -s ./qmp-sock 0 1 2 3
```

Then give each poller and the FTL thread a core of its own, here starting
at host CPU 4. The pollers exist only after the guest has enabled the
controller, so run this after the guest has booted:

```sh
cpu=4
for tid in $(ps -T -p "$pid" -o tid=,comm= |
             awk '$2 == "femu-poller" || $2 == "FEMU-FTL-Thread" {print $1}'); do
    sudo taskset -pc "$cpu" "$tid"
    cpu=$((cpu + 1))
done
```

Before you pin anything, move every existing QEMU thread off the cores you
reserve for FEMU, for example with `sudo taskset -apc 8-15 "$pid"`, then pin
the vCPUs and FEMU's threads as above. A thread created later inherits the
affinity of the thread that creates it. Choose cores that are
not hardware-thread siblings of each other (`lscpu -e` shows the core of
each CPU), so that two spinning threads do not share one physical core.

`pin.sh` pins only the vCPUs and the main thread, not the pollers or the
FTL thread ([scripts reference](../reference/scripts.md#host-tuning-helpers)).

## Hugepages

FEMU's device memory is ordinary anonymous memory; FEMU does not request
hugepages for it (a host with transparent hugepages set to `always` may still
use them). You can back the guest's RAM with hugepages, which
reduces TLB misses in the guest. Reserve them on the host (2048 pages of
2 MiB for a 4 GiB guest):

```sh
echo 2048 | sudo tee /proc/sys/vm/nr_hugepages
grep HugePages_Free /proc/meminfo
```

Then, in the launcher, replace `-m 4G` with these options:

```text
-m 4G -object memory-backend-memfd,id=ram0,size=4G,hugetlb=on,prealloc=on \
-machine memory-backend=ram0
```

If the host has too few free hugepages, QEMU stops at start with
`unable to map backing store for guest RAM: Cannot allocate memory`. CI does
not test this setup.

`femu-cxl-ssd` with `der=cylon` needs its CXL memory on a shared,
preallocated hugetlb backend; see the
[CXL SSD guide](../modes/cxl-ssd.md#dercylon).

## NUMA

On a host with more than one NUMA node, a thread that reads memory on the
other node pays the inter-socket latency on every access. Each NVMe command
copies its data between the guest's RAM and FEMU's device memory, so keep
the vCPUs, the pollers, the guest RAM and the device memory on one node,
unless you mean to study the other case.

To keep the whole QEMU process on node 0, start the launcher under
`numactl`:

<!-- femu-untested: needs a NUMA host, root and a guest image -->
```bash
sudo numactl --cpunodebind=0 --membind=0 ./run-blackbox.sh
```

To place only the device memory, set `FEMU_MBE_INTERLEAVE` in QEMU's
environment: `0` or `1` binds it to that node, `on` interleaves it across
nodes 0 and 1
([environment variables](../reference/properties.md#environment-variables)).
The launchers other than `run-cxlssd.sh` start QEMU with `sudo`, which drops
your environment, so put
the variable on the launcher's `sudo` line:

<!-- femu-untested: an edit to the sudo line inside a launcher, not a full command -->
```bash
sudo FEMU_MBE_INTERLEAVE=1 ./qemu-system-x86_64 \
```

FEMU prints `backend: N MB bound via FEMU_MBE_INTERLEAVE=1` when the binding
worked. One layout that keeps the guest and the emulator from competing for
memory bandwidth puts the vCPUs and guest RAM on one node, and the pollers,
the FTL thread and the device memory on the other.

## Host settings

- **CPU frequency.** A core that changes frequency changes how long FEMU's
  own work takes. Set every core to the performance policy:
  `sudo cpupower frequency-set -g performance`, or
  `sudo ../femu-scripts/set_cpu_perf_mode.sh`.
- **Locked device memory.** Under `sudo`, FEMU locks its device memory so
  that page faults do not add latency. As a normal user it needs
  `ulimit -l unlimited` or a matching `/etc/security/limits.conf` entry;
  without it FEMU prints `cannot pin the N MiB memory backend` and runs with
  less precise latency.
- **Other work.** Keep other busy processes off the cores you gave FEMU. The
  `isolcpus=` kernel parameter keeps the scheduler from placing other tasks
  there.
- **Physical host.** Nested virtualization and WSL add their own delays
  ([requirements](../getting-started/requirements.md#operating-system-and-cpu)).

## What each knob trades

| Knob | Gains | Costs |
| --- | --- | --- |
| `multipoller_enabled=1` | throughput that scales with guest jobs | one spinning core per poller |
| `poller_ratio` above 1 | fewer cores used | longer passes, more completion delay per poller |
| `queues` | one queue per guest CPU, no queue sharing in the guest | with `multipoller_enabled=1` and `poller_ratio=1`, each extra queue adds a spinning poller |
| Pinning | stable latency, no migrations | cores reserved for FEMU |
| Guest RAM on hugepages | fewer TLB misses in the guest | memory reserved up front |
| One NUMA node | no cross-socket copies | that node's cores and memory bandwidth only |
| Performance CPU frequency | stable service times | power and heat |
| Locked device memory | no page faults in the I/O path | memory resident from start-up |

## Related pages

- [Measuring](measuring.md): repeatable numbers once the host is tuned
- [Timing model](../concepts/timing-model.md)
- [Security and limits: host sizing](../concepts/security-and-limits.md#host-sizing)
- [Requirements](../getting-started/requirements.md)

Related issues: #7, #69, #77, #93, #101.
