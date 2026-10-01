# FEMU Roadmap

A living plan. Items move as maintainers and contributors take them on; open an
issue to propose or claim one.

## Recently landed (2026)
- NVMe conformance: telemetry logs, LBA metadata (separate and extended),
  Get LBA Status, Copy (formats 0 and 2), Verify, Device Self-test, Sanitize,
  Timestamp, Persistent Event log (optionally retained across runs in a file).
- Namespace Management and Attachment (opt-in, NoSSD and black-box SSD),
  including namespaces shared by the controllers of one subsystem.
- Crash-consistency testing: an opt-in power-loss model for the volatile write
  cache.
- Open-Channel 1.2 per-channel transfer timing (opt-in).
- CXL-attached SSD emulation (Cylon, FAST '26): merged into master as the
  `femu-cxl-ssd` device; see `hw/femu/docs/cxlssd.md`.
- End-to-end protection information (opt-in, Types 1-3).
- Streams directive (opt-in) alongside Flexible Data Placement.
- Zoned: ZRWA, conventional zones, zone width, Changed Zone List.
- Robustness: structured fuzzers for admin, I/O, zoned, FDP, key-value,
  Open-Channel and computational storage paths; ASan/UBSan CI.

## Next
- A published guest regression suite (`hw/femu/tests/guest/`).
- A release with signed tags, checksums, SBOM and build provenance.

## Later / proposals
- More calibrated device profiles and timing validation against real SSDs.

## How to help
See CONTRIBUTING.md. Issues labelled `good first issue` are sized for a first
contribution.
