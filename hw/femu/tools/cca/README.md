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

    ccactl [-d DEV] [-f] [-t MS] COMMAND [LPN COUNT | all]

    ccactl -d mem0 info
    ccactl -d mem0 nop
    ccactl -d mem0 pin 0 16            # pin device pages 0..15
    ccactl -d mem0 query all           # whole-device census
    ccactl -d mem0 -f invalidate all   # unpin, write back and drop all
    ccactl -d mem0 disable 100 8       # leave pages 100..107 uncached
    ccactl -d mem0 enable all
    ccactl -d mem0 reset               # rings only
    ccactl -d mem0 reset all           # rings, pins and uncached ranges

`-d` accepts a memdev name, a PCI address or a `resource5` path; without it
the only CCA device is used. `-f` sets FORCE, which lets `invalidate` and
`disable` unpin pinned pages. `-t` sets the command timeout in
milliseconds (default 10000); a negative value waits forever, and a
non-numeric or out-of-range value is a usage error. `pin`, `unpin`,
`invalidate`, `disable`, `enable` and `query` need a range: a start page and
a count, decimal or `0x` hexadecimal, or `all` for the whole media.

`info` prints `version`, `media_pages`, `cache_pages`, `cache_ways`,
`pin_limit` and `completed`, one per line. `nop` prints `status N (text)`.
The range commands print `status N (text)` and `pages N`, the pages acted on;
a successful `query` adds `resident`, `dirty`, `pinned` and `uncached`.
`reset` prints `reset rings: text` or `reset all: text`. The exit status is
0 on device status 0 (always for `info`), 1 on an error status or when the
device cannot be opened, and 2 on a usage error.

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
cache, `-ENODEV` media disabled, `-EIO` the media refused a read or write,
`-EAGAIN` a way change during PIN left no room. `-EBUSY` also answers a PIN
over an uncached page. A CACHE_DISABLE that fails with `-EIO` clears the
uncached mark of the pages it could not drop, so an uncached page is never
resident.

The library adds its own: `-ETIMEDOUT` when the device does not answer
within the timeout (`cca_set_timeout()`, default 10 s), and `-ECANCELED`
when a device reset cancels a command while it waits to be posted or to
complete, including a reset seen in the middle of reaping responses. A fatal
ring error makes every call return `-EPROTO` until `cca_reset()`; a reset
that races a post can itself leave the device fatal, and `cca_reset(d, 0)`
(rings only) recovers it, as does the next `cca_open()`.

## Guest tests

`run-guest-tests.sh` builds the tools, records the kernel and whether BAR5
was assigned, finds the devdax device of a non-interleaved region on the
memdev and runs `cca-test`:

    ./run-guest-tests.sh [-d mem0] [-x dax0.0] [-o LOG] [CASE...]

`-d` defaults to `mem0`, `-x` to the devdax device found, and `-o` to
`cca-guest-<date>-<time>.log` in the current directory. With no case, every
case but the reboot pair runs; the script needs root and runs on any bash
version. `cca-test [-d mem0] [-x dax0.0] [CASE...]` can also be run by hand.
It prints `PASS`, `FAIL` or `SKIP` per case and exits 1 if any failed.

Create the region first, for example with `cxl create-region -t ram -m mem0
-d decoder0.0`, and keep it in devdax mode (no `dax_kmem`). The cases
`query`, `thrash`, `invalidate` and `disable` map the devdax device and are
skipped without one of at least 2 MiB; the tests map at most 1 GiB of it.
The cases are:

| Case | Checks |
| --- | --- |
| info | Version, media and cache geometry, pin limit |
| nop | 5000 commands complete |
| query | One touched page is resident and dirty |
| thrash | A pinned page stays resident and at hit latency while 4x the cache streams past; an invalidated control, programmed first and flushed from the CPU cache before each invalidate (an emulated CLFLUSH reads the page), is at least 5x slower |
| invalidate | 64 dirty pages are written back, dropped and read back unchanged |
| disable | An uncached page is at least 5x slower than once re-enabled |
| errors | `-ERANGE`, `-ENOSPC` and `-EBUSY` through the library |
| threads | 8 threads, 800,000 asynchronous commands, no lost or duplicate tags |
| crash | A holder killed with SIGKILL mid-batch does not wedge the next open |
| before-reboot, after-reboot | Pins and uncached ranges do not survive a guest reboot |

Lines starting with `CCA-MARK` bracket steps whose host counters a runner
should compare; `invalidate` expects `media-writes` to rise by 64 between
its two marks. The before and after reboot cases are not run by default.
