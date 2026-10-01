# FEMU documentation

Start with the goal you have. Pages marked "coming" are planned and not
written yet; until then the [top-level README](../../../README.md) covers them.

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
- [Runtime properties](reference/runtime-properties.md): QOM properties and
  counters you read or set with `qom-get` and `qom-set`.
- [Log pages and counters](reference/log-pages-and-counters.md): vendor log C0h
  (WAF and media counters), telemetry, supported log pages.
- [Configuration changes](CONFIGURATION-CHANGES.md): properties whose meaning
  or default changed.
- `reference/scripts.md`: every shipped script and its knobs (coming).

## I want to understand how FEMU works

- [Architecture](concepts/architecture.md): the layers from the guest
  interface to the memory backend, the threads, and a walk through one NVMe
  write and one CXL load.
- [Choosing a mode](concepts/choosing-a-mode.md): which mode or feature fits
  a goal, and which ones combine.
- [Timing model](concepts/timing-model.md): how latency is computed and
  enforced, the properties that control it, and how to measure it.
- [CXL SSD design](cxlssd.md): the design note for `femu-cxl-ssd`.

## I want to measure or tune

- `guides/measuring.md`: WAF, latency, counters, fio recipes (coming).
- `guides/performance-tuning.md`: pollers, CPU pinning, hugepages, NUMA
  (coming).

## Something does not work

- `troubleshooting.md`: answers to common questions from the issue tracker
  (coming). Until then, see
  [the README's troubleshooting section](../../../README.md#troubleshooting)
  and [build errors](getting-started/build.md#common-build-errors).

## I want to change FEMU

- `development/code-structure.md`, `development/adding-a-mode.md` and
  `development/docs-maintenance.md` (coming). Until then, see
  [the README's development section](../../../README.md#development).
- `hw/femu/scripts/gen-property-docs.py` regenerates the property reference,
  and `hw/femu/scripts/check-doc-links.py` checks that every relative link in
  the docs resolves. CI runs both.
