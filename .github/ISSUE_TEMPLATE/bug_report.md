---
name: Bug Report
about: Report a bug in FEMU
title: "[BUG] "
labels: bug
assignees: ''

---

**Describe the bug**
What happened, and what you expected to happen.

**Environment**
- Host OS and kernel: [e.g. Ubuntu 24.04, 6.8.0]
- FEMU commit: [output of `git rev-parse --short HEAD`]
- Guest kernel: [output of `uname -r` in the guest]
- The full `-device femu,...` (or `-device femu-cxl-ssd,...`) line:

```
-device femu,...
```

**FEMU mode or feature** (check every one that the command line turns on)
<!-- modes-list:start -->
<!-- Generated from hw/femu/docs/modes.py by hw/femu/scripts/gen-mode-table.py; edit modes.py, not this table. -->
- [ ] NoSSD: `femu_mode=2` (the default)
- [ ] BlackBox SSD (BBSSD): `femu_mode=1`
- [ ] Zoned Namespace (ZNS): `femu_mode=3`
- [ ] Open-Channel SSD 1.2: `femu_mode=0,lver=1`
- [ ] Open-Channel SSD 2.0: `femu_mode=0` (`lver=2` is the default)
- [ ] Key-value SSD (KV): `femu_mode=5`
- [ ] Computational storage (CSD): `femu_mode=4,fdm_size=<MiB>`
- [ ] Flexible Data Placement (FDP): `femu-subsys,fdp=on,fdp.nruh=<n>` and `femu,femu_mode=1,subsys=<id>`
- [ ] Multiple namespaces: `namespaces=<n>`, optionally `namespace_sizes` and `namespace_modes`
- [ ] Namespace management: `ns_mgmt=on` on a NoSSD or BBSSD controller; `femu-subsys,ns_mgmt=on` to share namespaces
- [ ] Metadata and protection information: `meta=<bytes>,mc=<mask>`, plus `pi=on` with `meta` of 8 or more
- [ ] CXL SSD, `der=off`: `femu-cxl-ssd` below `pxb-cxl` and `cxl-rp` on `-machine q35,cxl=on`
- [ ] CXL SSD, `der=memslot`: `der=memslot` on `femu-cxl-ssd`
- [ ] CXL SSD, `der=cylon`: `der=cylon,cylon-kernel-ack=on` on `femu-cxl-ssd`
- [ ] CXL caching API (CCA): `cca=on` on `femu-cxl-ssd`
- [ ] NVMe front end on a CXL SSD: `femu,bus=pcie.0,femu_mode=1,cxl_ssd=<id>` after the `femu-cxl-ssd`
<!-- modes-list:end -->

**To reproduce**
1. Start QEMU with '...'
2. In the guest, run '...'
3. See the error

**Logs**
- QEMU output (stdout and stderr) up to the error.
- `dmesg` from the guest, if the guest saw an error.
- If QMP is on: the output of `query-femu` for the namespace
  (see `hw/femu/docs/reference/query-femu.md`).

**Additional context**
Anything else: guest RAM, host CPU, other devices on the command line.
