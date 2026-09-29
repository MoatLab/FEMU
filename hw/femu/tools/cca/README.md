<!--
SPDX-License-Identifier: GPL-2.0-or-later
-->

# CCA guest tools

Guest-side code for the caching API (CCA) of `femu-cxl-ssd`: a small C
library, the `ccactl` command-line tool and the `cca-test` self-test. They
talk to BAR5 of the device, which exists only with `cca=on`; see
`hw/femu/docs/cxlssd.md` for the device side. The library and the device
compile the same layout header, `hw/femu/cxlssd/cca-abi.h`.

## Build

Inside an x86-64 guest, with a C compiler and make:

    make -C hw/femu/tools/cca

This produces `libcca.a`, `ccactl` and `cca-test`. No kernel module, UIO
driver or extra library is needed: the tools map
`/sys/bus/pci/devices/<function>/resource5`, which needs root and a kernel
without PCI lockdown.

## Device pages

Commands take ranges of 4 KiB device pages, that is DPA / 4096. For a
devdax mapping of a non-interleaved region on the memdev,
`cca_attach_dax()` reads the region and endpoint decoder from sysfs, after
which the `*_addr` calls accept virtual addresses in the mapping.

## ccactl

    ccactl [-d mem0] info
    ccactl [-d mem0] pin 0 16          # pin device pages 0..15
    ccactl [-d mem0] query all         # whole-device census
    ccactl [-d mem0] -f invalidate all # unpin, write back and drop all
    ccactl [-d mem0] disable 100 8     # bypass the cache for 8 pages
    ccactl [-d mem0] enable all
    ccactl [-d mem0] reset all         # rings, pins and bypass

`-d` accepts a memdev name, a PCI address or a `resource5` path; without it
the only CCA device is used. The exit status is 0 when the device returned
status 0.

## Library

`cca.h` documents every call. Synchronous calls return the device status
(0 or a negative errno) and fill a `struct cca_result`, whose `pages` is the
number of pages the command acted on. `cca_submit()` and `cca_reap()` keep
up to 2048 commands in flight; `CCA_SUBMIT_DEFER` batches doorbells. One
mutex serializes the rings, so any number of threads may call the library,
and `flock()` keeps other processes out. A process that dies holding the
device leaves its ring indices behind; the next `cca_open()` resets the
rings.

Device statuses: `-EINVAL` malformed command, `-ERANGE` range beyond the
media, `-ENOSPC` a set has no way left to pin, `-EBUSY` pinned pages without
FORCE or a direct ratio in the way, `-EOPNOTSUPP` pin or unpin without a
cache, `-ENODEV` media disabled, `-EIO` the media refused a write,
`-EAGAIN` a way change during PIN left no room. A fatal ring error makes
every call return `-EPROTO` until `cca_reset()`.

## Guest tests

`run-guest-tests.sh` builds the tools, records the kernel and whether BAR5
was assigned, finds the devdax device of a non-interleaved region on the
memdev and runs `cca-test`:

    ./run-guest-tests.sh [-d mem0] [-x dax0.0] [-o LOG] [CASE...]

Create the region first, for example with `cxl create-region -t ram -m mem0
-d decoder0.0`, and keep it in devdax mode (no `dax_kmem`). The cases are:

| Case | Checks |
| --- | --- |
| info | Version, media and cache geometry, pin limit |
| nop | 5000 commands complete |
| query | One touched page is resident and dirty |
| thrash | A pinned page stays resident and at hit latency while 4x the cache streams past; an invalidated control, programmed first and flushed from the CPU cache before each invalidate (an emulated CLFLUSH reads the page), is at least 5x slower |
| invalidate | 64 dirty pages are written back, dropped and read back unchanged |
| disable | A bypassed page is at least 5x slower than once re-enabled |
| errors | `-ERANGE`, `-ENOSPC` and `-EBUSY` through the library |
| threads | 8 threads, 800,000 asynchronous commands, no lost or duplicate tags |
| crash | A holder killed with SIGKILL mid-batch does not wedge the next open |
| before-reboot, after-reboot | Pins and bypass do not survive a guest reboot |

Lines starting with `CCA-MARK` bracket steps whose host counters a runner
should compare; `invalidate` expects `media-writes` to rise by 64 between
its two marks. The before and after reboot cases are not run by default.
