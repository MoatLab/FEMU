# Code structure

All FEMU code, scripts, tests and documentation live under `hw/femu/`, so
the rest of the tree stays QEMU. A top-level `femu-scripts` link points to
`hw/femu/scripts/`, which keeps the `cd build-femu && ../femu-scripts/...`
workflow working. How the pieces fit together at run time, layer by layer,
is in [architecture](../concepts/architecture.md).

## Directory map

| Path | What is there |
| --- | --- |
| [`femu.c`](../../femu.c) | QOM types `femu` and `femu-subsys`, property definitions, realize and exit, the FTL thread, mode registration |
| [`femu-props.c`](../../femu-props.c) | Help text for every `femu` and `femu-subsys` property (what `-device femu,help` prints) |
| [`nvme.h`](../../nvme.h) | NVMe structures, the `femu_mode` enum and the controller state `FemuCtrl` |
| [`nvme-admin.c`](../../nvme-admin.c) | Admin commands, starting the pollers, namespace management, asynchronous events |
| [`nvme-caps.c`](../../nvme-caps.c) | What the controller advertises: the Commands Supported and Effects and Supported Log Pages entries, and the Identify bits derived from them |
| [`nvme-io.c`](../../nvme-io.c) | I/O commands and the poller loop that fetches submissions and posts completions |
| [`nvme-util.c`](../../nvme-util.c) | Deallocation state per LBA (TRIM, Write Zeroes with deallocate, DULBE), queue head and tail and completion posting helpers, poller pause and resume, the Timestamp feature |
| [`nvme-pel.c`](../../nvme-pel.c) | Persistent Event log and its `pel_file` |
| [`nvme-pi.c`](../../nvme-pi.c) | Metadata and protection information |
| [`nvme-streams.c`](../../nvme-streams.c) | Streams directive |
| [`dma.c`](../../dma.c) | PRP and SGL mapping, copies between guest memory and the device |
| [`intr.c`](../../intr.c) | MSI-X, MSI and pin interrupts |
| [`bbssd/`](../../bbssd) | BlackBox mode (`bb.c`) and its FTL: geometry, data path, mapping schemes, read cache, GC and lines, FDP, the bridge to the NAND media layer |
| [`zns/`](../../zns) | ZNS mode (`zns.c`) and its zone FTL (`zftl.c`) |
| [`ocssd/`](../../ocssd) | Open-Channel 1.2 (`oc12.c`) and 2.0 (`oc20.c`) |
| [`nossd/`](../../nossd) | NoSSD mode (`nop.c`) |
| [`kvssd/`](../../kvssd) | Key-value mode: commands, its FTL, Identify and features |
| [`csd/`](../../csd) | Computational storage mode and its private commands |
| [`cxlssd/`](../../cxlssd) | `femu-cxl-ssd`: QOM glue, the page cache, the DER modes, the caching API |
| [`nand/`](../../nand) | NAND media layer: per-cell-type timing tables and the timing of each operation |
| [`timing-model/`](../../timing-model) | Per-chip and per-channel timestamps used by Open-Channel |
| [`backend/`](../../backend) | The DRAM backend that holds the emulated medium |
| [`lib/`](../../lib), [`inc/`](../../inc) | Lock-free rings and the priority queue, and their headers |
| [`scripts/`](../../scripts) | Build and launch scripts, configs, guest tools, documentation tooling ([scripts reference](../reference/scripts.md)) |
| [`tools/`](../../tools) | Guest tools for the CXL caching API |
| [`tests/`](../../tests) | Unit tests, the qtest file, CSD guest tests ([testing](../guides/testing.md)) |
| [`docs/`](..) | This documentation ([doc map](../README.md)) |

## Making a change

[CONTRIBUTING.md](../../../../CONTRIBUTING.md) has the process: style
(`checkpatch.pl`), tests, sign-off and pull requests. For a new property,
add its help text in `femu-props.c` and regenerate the property reference
([keeping the documentation correct](docs-maintenance.md)). For a new mode,
add it to the `femu_mode` enum in `nvme.h`, register its handlers the way
the existing modes do in `femu.c`, and add an entry to `docs/modes.py`.
