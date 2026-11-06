## Description
Brief description of changes made.

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Code refactoring

## Testing
- [ ] I have tested my changes locally
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] All existing tests pass
- [ ] I have tested across multiple FEMU modes (if applicable)

## FEMU Modes Tested
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
- [ ] Not applicable

## Platform Testing
- [ ] Ubuntu 22.04 or 24.04 (the CI hosts)
- [ ] Other distributions (specify): ___________
- [ ] Build verification completed

## Checklist
- [ ] My code follows QEMU coding standards
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] My changes generate no new compiler warnings
- [ ] I have updated documentation if necessary
- [ ] `python3 hw/femu/scripts/check-c-style.py` passes (no C99 comments, no trailing whitespace)

## AI assistance
- [ ] No generative AI tool wrote or rewrote any part of this change.
- [ ] An AI tool was used. Each affected commit has an `Assisted-by:` line, and
      I describe below what the tool did and what I checked by hand.
- [ ] I understand every line of this change and can explain it in review.
- [ ] I ran the tests myself; the output quoted here is real and unedited.

See the [AI policy](../hw/femu/docs/ai-policy.md). Tool use and what I verified (if applicable):

## Related Issues
Fixes #(issue number)

## Additional Notes
Any additional information, configuration changes, or notes for reviewers.