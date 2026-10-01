# FEMU documentation

Start with the goal you have. What changed since the last release is in the
[changelog](CHANGELOG.md).

## I am new to FEMU

Read these in order:

1. [Requirements](getting-started/requirements.md): host OS, KVM, memory, and
   the guest kernel each mode needs.
2. [Build](getting-started/build.md): dependencies, `femu-compile.sh`, optional
   features, common build errors.
3. [Guest image](getting-started/guest-image.md): `make-guest-image.sh`, other
   ways to get an image, SSH access.
4. [Quick start](getting-started/quick-start.md): build, boot a BlackBox SSD,
   run fio and read the write amplification factor.

## I want to learn by doing

The [tutorials](tutorials/README.md) walk through nine tasks in a real
guest, with the output each step should print: a first SSD, GC and WAF,
ZNS, FDP, latency tuning, several namespaces, KV, CXL memory and
configuration files.

## I want a specific kind of SSD

[Choosing a mode](concepts/choosing-a-mode.md) has the full decision table:
every `femu_mode` value, the settings for each goal, which features combine,
and what the guest needs. In short:

| Goal | Mode | Launcher | Guide |
| --- | --- | --- | --- |
| A fast NVMe drive with no FTL timing | NoSSD (`femu_mode=2`, the default) | `run-nossd.sh` | [NoSSD](modes/nossd.md) |
| A conventional SSD with a device FTL, GC and WAF | BlackBox SSD (`femu_mode=1`) | `run-blackbox.sh` | [BlackBox](modes/blackbox.md) |
| A Zoned Namespace SSD | ZNS (`femu_mode=3`) | `run-zns.sh` | [ZNS](modes/zns.md) |
| A host-managed OpenChannel SSD | OCSSD (`femu_mode=0`) | `run-whitebox.sh` | [OCSSD](modes/ocssd.md) |
| A key-value SSD | KV (`femu_mode=5`) | none | [KV](modes/kvssd.md) |
| Computational storage | CSD (`femu_mode=4`) | `run-csd.sh` | [CSD](modes/csd.md), [CSD guest tools](../tests/csd/README.md) |
| Flexible Data Placement | BBSSD with `femu-subsys,fdp=on` | `run-blackbox-fdp.sh` | [FDP](features/fdp.md) |
| Create and delete namespaces from the guest | NoSSD or BBSSD with `ns_mgmt=on` | none | [Namespace management](features/ns-management-and-pi.md#namespace-management) |
| Per-block metadata and protection information | NoSSD or BBSSD with `meta`, `mc`, `pi=on` | none | [Metadata and PI](features/ns-management-and-pi.md#metadata-and-protection-information) |
| Several namespaces on one controller | any NVMe mode | none | [Several namespaces](features/multi-namespace.md) |
| A CXL memory-semantic SSD | `femu-cxl-ssd` device | `run-cxlssd.sh` | [CXL SSD](modes/cxl-ssd.md), [design note](cxlssd.md) |
| Guest control of the CXL SSD cache: pin, drop, uncached ranges | `femu-cxl-ssd,cca=on` | `run-cxlssd.sh` | [CXL caching API](features/cxl-cca.md) |
| The CXL SSD medium also as an NVMe namespace | `femu,femu_mode=1,cxl_ssd=<id>` | `run-cxlssd.sh` plus `-device femu,...` | [CXL NVMe link](features/cxl-nvme-link.md) |

The guest kernel each mode needs is in
[requirements.md](getting-started/requirements.md#kernel-per-mode).

## I want to look up a parameter or counter

- [Device properties](reference/properties.md): every `-device femu`,
  `femu-subsys` and `femu-cxl-ssd` property, generated from the binary.
- [Parameter manual](reference/parameter-manual.md): the parameters grouped
  by component, with units, valid values, interactions and worked
  configurations.
- [Runtime properties](reference/runtime-properties.md): QOM properties and
  counters you read or set with `qom-get` and `qom-set`.
- [Log pages and counters](reference/log-pages-and-counters.md): vendor log C0h
  (WAF and media counters), telemetry, supported log pages, asynchronous
  events, keeping the Persistent Event log in a file.
- [Changelog](CHANGELOG.md): what changed since femu-v9.0.1, including
  properties that are now refused and settings whose effect changed.
- [Scripts and tools](reference/scripts.md): every shipped script and tool,
  its arguments and environment variables, and which ones are legacy.

## I want to understand how FEMU works

- [Architecture](concepts/architecture.md): the layers from the guest
  interface to the memory backend, the threads, and a walk through one NVMe
  write and one CXL load.
- [Choosing a mode](concepts/choosing-a-mode.md): which mode or feature fits
  a goal, and which ones combine.
- [Timing model](concepts/timing-model.md): how latency is computed and
  enforced, the properties that control it, and how to measure it.
- [Security and limits](concepts/security-and-limits.md): what a guest can
  do to the host, migration and snapshots, property compatibility, host
  sizing.
- [CXL SSD design](cxlssd.md): the design note for `femu-cxl-ssd`.

## I want the full design

The [design manual](design/README.md) has one chapter per component, each
with diagrams, data structures, algorithms, parameters, counters, limits
and a source map:

- [Overview](design/README.md) and [NVMe frontend](design/nvme-frontend.md):
  the component hierarchy, queues, pollers, dispatch and completion.
- [BlackBox FTL](design/ftl.md) and [NAND media and timing](design/nand-timing.md).
- [ZNS](design/zns.md), [FDP](design/fdp.md) and
  [namespaces and subsystems](design/namespaces.md).
- [OCSSD](design/ocssd.md), [KV](design/kvssd.md), [CSD](design/csd.md),
  [NoSSD](design/nossd.md) and [CXL SSD](design/cxl-ssd.md).

## I want to measure or tune

- [Measuring](guides/measuring.md): WAF and counters from log page C0h,
  SMART, CXL counters, fio recipes per mode, repeatable numbers.
- [Performance tuning](guides/performance-tuning.md): pollers, CPU pinning,
  hugepages, NUMA, host settings, and what each knob trades.

## Something does not work

- [Troubleshooting and FAQ](troubleshooting.md): answers to the 18 most
  common questions from the issue tracker.
- [Debugging](guides/debugging.md): where messages go, gdb, compile-time
  debug switches, common crash reports, what to put in a bug report.
- [Build errors](getting-started/build.md#common-build-errors).

## I want to change FEMU

- [Testing](guides/testing.md): unit tests, the qtests, the documentation
  checks, guest-side tests, and how to add a test.
- [Keeping the documentation correct](development/docs-maintenance.md): the
  generated references, the mode table and the example checks.
- [Code structure](development/code-structure.md): what lives where under
  `hw/femu/`, and where to start a change. [Architecture](concepts/architecture.md)
  explains how the parts work together.
- [Contributing](../../../CONTRIBUTING.md): style, tests, sign-off and pull
  requests.
- `hw/femu/scripts/gen-property-docs.py` regenerates the property reference,
  and `hw/femu/scripts/check-doc-links.py` checks that every relative link in
  the docs resolves. CI runs both.

## How to cite

If you use FEMU in your research, cite the FAST '18 paper. The BibTeX entry
is in [the README](../../../README.md#primary-citation), and
[CITATION.cff](../../../CITATION.cff) has the same entry for citation tools.
