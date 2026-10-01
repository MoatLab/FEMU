# Tutorials

Hands-on walkthroughs. Each one starts a guest with an emulated device,
runs a workload inside it, and reads what the device reports. Every
tutorial stands on its own, but they build on each other in this order.

| Tutorial | You learn to | Device |
| --- | --- | --- |
| [01 Your first SSD](01-first-ssd.md) | boot a BlackBox SSD from your own QEMU command line, measure read and write latency, read the write amplification factor (WAF) | BBSSD, 2 GiB of NAND |
| [02 Garbage collection and WAF](02-gc-and-waf.md) | provoke garbage collection (GC), measure the WAF of one run, and see how over-provisioning, the GC threshold, the victim policy and hot/cold separation change it | BBSSD |
| [03 Zoned namespaces](03-zns.md) | read the zone report, move zones through their states, use Zone Append, fio's zoned mode and zonefs | ZNS |
| [04 Flexible Data Placement](04-fdp.md) | write through placement identifiers, read the FDP log pages, and measure what placement does to the WAF | BBSSD with FDP |
| [05 Latency tuning](05-latency-tuning.md) | change NAND times, the cell type, the channel bus, the host link and the firmware cost, and measure each with fio | BBSSD |
| [06 Several namespaces](06-multi-namespace.md) | run a BlackBox, a ZNS, a NoSSD and a KV namespace on one controller | mixed |
| [07 Key-value SSD](07-kv.md) | store, retrieve, list and delete values with nvme-cli | KV |
| [08 CXL SSD as memory](08-cxl-memory.md) | start a `femu-cxl-ssd`, find it in the guest, use it as a DAX device or a NUMA node, and read its counters | CXL Type-3 SSD |
| [09 Configuration files](09-ssd-config-files.md) | describe a device in a file and expand it with `ssd-config.sh` instead of writing a long `-device` line | any |

## Before you start

You need a built FEMU and a guest image. The
[quick start](../getting-started/quick-start.md) does both in about five
minutes of work: `femu-compile.sh` in `build-femu/` and
`make-guest-image.sh` for the image.

The tutorials use three shell variables on the host. Set them once in the
terminal you start QEMU from and in the one you use to reach the guest:

```sh
cd build-femu                      # the directory femu-compile.sh built in
export IMGDIR=$HOME/images         # where make-guest-image.sh put the image
export OSIMGF=$IMGDIR/u20s.qcow2   # the guest image
export SSH_PORT=8080               # host port forwarded to the guest's SSH
```

`run-guest-ssh.sh` reads `IMGDIR` and `SSH_PORT`, so with these set,
`./run-guest-ssh.sh` opens a shell in the guest and
`./run-guest-ssh.sh CMD` runs one command there.

## How to read the tutorials

- Blocks marked as a FEMU example hold a QEMU command line or `-device`
  options. The documentation checks start each of them under QEMU's
  `qtest` accelerator, so they are known to be accepted by the current
  code. The checks do not boot a guest.
- `sh` blocks run inside the guest unless the text says "on the host".
  Run them in the shell `./run-guest-ssh.sh` gives you.
- `text` blocks show output. Unless a block says it is illustrative, it
  was captured from a real run: FEMU at the commit that added these pages,
  the Ubuntu 24.04 guest from `make-guest-image.sh` (Linux 6.8, nvme-cli
  2.8, fio 3.36), on a 20-core host. Latencies and throughput depend on
  the host. Counter values such as the WAF depend only on the workload,
  and fio's random offsets change between runs, so expect them within a
  few percent of the values shown.
- The QEMU command lines run without `sudo`. That works when your user is
  in the `kvm` group; otherwise put `sudo` in front, as the `run-*.sh`
  launchers do.
- Each emulated device lives in host memory: plan for the device size
  plus the guest's `-m` in free host RAM.

## Where to go next

- [Measuring](../guides/measuring.md) and
  [performance tuning](../guides/performance-tuning.md) explain how to get
  numbers that repeat.
- [The parameter manual](../reference/parameter-manual.md) explains every
  group of device parameters and how they interact.
- [The design pages](../design/README.md) explain what happens inside the
  device.
