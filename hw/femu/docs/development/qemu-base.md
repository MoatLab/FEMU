# QEMU base

FEMU is a QEMU tree with FEMU code added. The QEMU base is **v11.1.3**.
This page lists the QEMU files whose contents FEMU changes, why, and
where each change can go upstream. It omits `hw/femu/`, `roms/`, file
mode changes, and files that FEMU removes.

```
 QEMU v11.1.3 tree
   + hw/femu/            FEMU devices, tests, docs, scripts (FEMU only)
   + roms/               firmware sources (kept as FEMU ships them)
   + 25 QEMU files       content changes, listed below
```

## Files that FEMU changes

### Build and schema hooks (FEMU only)

| File | Change |
| --- | --- |
| `hw/Kconfig`, `hw/meson.build` | Add the `hw/femu` directory |
| `meson.build`, `meson_options.txt`, `scripts/meson-buildoptions.sh` | The `femu_csd_ubpf` options for computational storage |
| `qapi/meson.build`, `qapi/qapi-schema.json` | Add `qapi/femu.json` (`query-femu`) |
| `tests/qtest/meson.build` | Build the FEMU qtests into `qos-test` |
| `tests/qtest/libqos/qgraph.h` | Longer qgraph path elements for the FEMU test names |
| `tests/qtest/qmp-cmd-test.c` | `query-femu` fails without a FEMU device |
| `tests/qtest/fuzz/generic_fuzz_configs.h` | Five `generic-fuzz-femu-*` targets for the generic fuzzer |
| `scripts/checkpatch.pl` | Allow the test file layout of `hw/femu/tests/` |
| `.gitignore` | FEMU build products |

### Core hooks (upstream candidates)

| File | Change | Upstream path |
| --- | --- | --- |
| `util/async.c`, `include/qemu/main-loop.h`, `system/memory.c`, `net/net.c` | Guarded I/O sections: a device thread can tell one MMIO dispatch or bottom half from the next | Propose with a user in QEMU |
| `accel/kvm/kvm-all.c`, `include/system/kvm.h` | Memory slot reservations, exit handlers by reason, and a vCPU destroy hook for the CXL SSD DER modes | Needs a QEMU user; FEMU only for now |
| `system/qtest.c`, `include/system/qtest.h` | `qtest_command_running()` for test-only paths | FEMU only |
| `hw/cxl/cxl-device-utils.c`, `include/hw/cxl/cxl_device.h` | Atomic memory device status, read outside the BQL | Upstream candidate |
| `hw/cxl/cxl-mailbox-utils.c`, `include/hw/cxl/cxl_device.h` | Hooks before and after each mailbox command | Upstream candidate |
| `hw/cxl/cxl-host.c` | Turn off the 11.1 direct mapping of CXL decoders | Report the alias bugs first (below) |
| `qapi/stats.json`, `stats/stats-qmp-cmds.c`, `stats/stats-hmp-cmds.c` | The `query-stats` provider and target `femu`; HMP `info stats` prints the QOM path of each `femu` result | FEMU only; QEMU takes a provider with an in-tree user |

### Changes that the 11.1 base already holds

The TCG fix that removed `iotlb_to_section()` is in QEMU 11.1. FEMU no
longer changes `accel/tcg/cputlb.c`, `include/accel/tcg/iommu.h`,
`include/exec/cputlb.h`, `include/hw/core/cpu.h` or `system/physmem.c`.

## The CXL direct mapping

QEMU 11.1 maps a committed CXL decoder without interleave straight into
the window. FEMU turns this off.

```
 guest access --> CXL window --> device handlers --> femu-cxl-ssd timing, DER, prefetch
                             x-> direct alias (off in FEMU)
```

- An alias stays after the decoder uncommits or the machine resets.
- An alias covers the whole decoder, also a part routed to another device.
- With an alias, `femu-cxl-ssd` sees no access, so its model does nothing.

## Pinned machine types

The launchers pin a versioned machine, so a new QEMU base keeps the
guest-visible machine. `FEMU_MACHINE` sets another one.

| Launcher | Machine |
| --- | --- |
| `run-*.sh` for NVMe modes, `guest-conformance.sh` | `pc-i440fx-10.1` |
| `run-cxlssd.sh`, the guest boot test | `pc-q35-10.1` |

## QEMU canary

Once a week, the `QEMU canary` workflow merges FEMU master with QEMU
master. It builds the result and runs the FEMU qtests. You can also start
it by hand with another QEMU ref.

```
 QEMU base (v + VERSION) --+
 FEMU master --------------+--> qemu-canary.py --> build --> FEMU qtests
 QEMU master --------------+      report.txt
```

`hw/femu/scripts/qemu-canary.py` does the merge. Two lists in the script
hold the conflicts that follow FEMU policy:

- QEMU changes a file that FEMU does not ship, for example GitLab CI.
- QEMU has a submodule where FEMU ships a directory, for example
  `roms/edk2`.

Any other conflict makes the run red, and `report.txt` names the path. A
red run shows work for the next base move. It does not block a push.

## Move to a new QEMU base

Do a base move about twice a year, after a QEMU release.

1. Run the canary on the release tag. Fix each conflict and build error.
2. Make one commit, `Rebase FEMU onto QEMU X.Y.Z`, with `VERSION` set to
   `X.Y.Z`.
3. Keep the pinned machine types. Compare the guest view on the old and
   the new base.
4. Update the file table on this page.

CI checks only the `hw/femu/` part of the base move commit, since the
rest is upstream QEMU code.

## Update an old checkout

QEMU 11.1 installs `qemu.qmp` into the build `pyvenv` at configure time.
An old checkout keeps an ignored `python/qemu/qmp/` directory.

1. Remove `python/qemu/qmp/`.
2. Configure in a new build directory.

Without these steps, the functional tests stop with an `ImportError`.

## Related pages

- [Testing](../guides/testing.md)
