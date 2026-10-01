<!--
SPDX-License-Identifier: GPL-2.0-or-later
-->

# CXL caching API (CCA)

The caching API lets software in the guest control the DRAM cache of a
[`femu-cxl-ssd`](../modes/cxl-ssd.md): pin pages so they stay cached, write
back and drop ranges, mark ranges uncached so every access goes to the
media, and ask what is resident. Ranges are in 4 KiB device pages. It
follows the caching API of the Cylon CXL SSD emulator.

The guest talks to the device through PCI BAR5 of the CXL function. FEMU
ships a small C library, the `ccactl` command-line tool and a self-test in
`hw/femu/tools/cca/`. The design note's
[caching API section](../cxlssd.md#caching-api-cca) describes the register
layout and the rings in full.

## Turning it on

`cca=on` on the device (default off). With it off there is no BAR5 and the
device behaves exactly as without the feature. `run-cxlssd.sh` has no
variable for it, so pass a `-global`:

<!-- femu-example: cxl-cca-launch -->
```bash
../femu-scripts/run-cxlssd.sh -global femu-cxl-ssd.cca=on \
    -drive file=$HOME/images/u20s.qcow2,if=none,id=hd0 \
    -device virtio-blk-pci,drive=hd0,bus=pcie.0 \
    -netdev user,id=net0,hostfwd=tcp::8080-:22 \
    -device virtio-net-pci,netdev=net0,bus=pcie.0
```

On a full command line, add `cca=on` to the device:

<!-- femu-example: cxl-cca-cmdline -->
```bash
./qemu-system-x86_64 -machine q35,cxl=on,smm=off -accel kvm -cpu host -smp 4 -m 4G \
    -object memory-backend-ram,id=cxlmem,size=256M \
    -device pxb-cxl,id=cxl.0,bus=pcie.0,bus_nr=52 \
    -device cxl-rp,id=rp0,bus=cxl.0,chassis=0,slot=0 \
    -device femu-cxl-ssd,id=cxlssd,bus=rp0,volatile-memdev=cxlmem,cache-pages=1024,cache-ways=16,cca=on \
    -M cxl-fmw.0.targets.0=cxl.0,cxl-fmw.0.size=256M
```

The device starts a `femu-cxl-cca` thread that runs the commands. PIN and
UNPIN need a cache (`cache-pages` above 0).

## Guest setup

The tools map `/sys/bus/pci/devices/<function>/resource5`. That needs root and
a guest kernel without PCI lockdown; no kernel module or UIO driver is
needed. Check that firmware assigned BAR5 under the CXL host bridge:

```sh
fn=$(basename "$(readlink -f /sys/bus/cxl/devices/mem0/..)")   # PCI function of mem0
lspci -vv -s "$fn" | grep Region            # a Region 5 line must be present
ls -l /sys/bus/pci/devices/$fn/resource5
```

Build the tools inside the guest from a copy of the FEMU source tree:

```sh
sudo apt install build-essential
make -C hw/femu/tools/cca
```

This builds `libcca.a`, `ccactl` and `cca-test`. Commands work without a
region. The address helpers of the library and most self-test cases need a
devdax region on the memdev; create one as in
[creating the region](../modes/cxl-ssd.md#creating-the-region-in-the-guest)
and keep it in devdax mode.

## `ccactl`

```text
ccactl [-d DEV] [-f] [-t MS] COMMAND [LPN COUNT | all]
```

| Option | Meaning |
| --- | --- |
| `-d DEV` | A memdev name (`mem0`), a PCI address or a `resource5` path. Without it, the only CCA device is used |
| `-f` | FORCE: lets `invalidate` and `disable` act on pinned pages, unpinning them |
| `-t MS` | Command timeout in milliseconds, default 10000; negative waits forever |
| `LPN COUNT` | First device page (DPA / 4096) and number of pages, decimal, `0x` hexadecimal or, with a leading 0, octal; `all` is the whole media |

| Command | What it does |
| --- | --- |
| `info` | Print the layout version, media pages, cache pages, cache ways, pins allowed per set and commands completed |
| `nop` | Round trip with no effect |
| `pin LPN COUNT` | Keep the pages cached until unpinned |
| `unpin LPN COUNT` | Let the pages be evicted again |
| `invalidate LPN COUNT` | Write dirty pages back to NAND and drop them from the cache |
| `disable LPN COUNT` | Mark the pages uncached and drop them |
| `enable LPN COUNT` | End the uncached marking |
| `query LPN COUNT` | Count resident, dirty, pinned and uncached pages |
| `reset` | Reset the rings only |
| `reset all` | Reset the rings, unpin every page and end every uncached range |

```sh
sudo ./ccactl -d mem0 info
sudo ./ccactl -d mem0 pin 0 16            # pin device pages 0..15
sudo ./ccactl -d mem0 query all
sudo ./ccactl -d mem0 -f invalidate all   # unpin, write back and drop all
sudo ./ccactl -d mem0 disable 100 8       # pages 100..107 uncached
sudo ./ccactl -d mem0 enable all
```

Range commands print `status N (text)` and `pages N`, the number of pages
acted on; `query` adds `resident`, `dirty`, `pinned` and `uncached`. The exit
status is 0 when the device returns status 0 (always for `info`), 1 on an
error status or when the device cannot be opened, and 2 on a usage error.
`ccactl` opens the device before it checks the command, so with no device a
usage error also exits 1.

## What each command does

PIN
: Refused as a whole with `-ENOSPC` when the pins cannot fit. Resident pages
  are pinned. Other pages are read from NAND
  as a miss would read them (counted in `media-reads` and `cca-pin-fills`,
  not as guest misses), possibly evicting an unpinned page, then pinned.
  Pinned pages leave the eviction queues, so eviction and prefetch never
  touch them. Every way of a set may be pinned; a miss to a set whose ways
  are all pinned is served from NAND without caching and counted in
  `cca-pinned-set-misses`. On `-EIO` or `-EAGAIN` partway through, the pages
  pinned before the failure stay pinned; `pages` says how many.

UNPIN
: Returns pinned pages to the replacement queue a newly inserted page would
  join. Dirty pages stay dirty.

INVALIDATE
: Writes dirty pages back to NAND and drops them from the cache. Pinned
  pages need FORCE; without it nothing changes and the status is `-EBUSY`.
  Direct mappings of the pages are revoked first.

CACHE_DISABLE (`disable`)
: Marks the pages uncached, then drops resident ones as INVALIDATE does.
  An uncached page is never inserted, prefetched or direct-mapped: every
  read is a NAND read and every write a NAND program. A failed command
  clears the mark from the pages it could not drop, so an uncached page is
  never resident.

CACHE_ENABLE (`enable`)
: Ends the uncached marking; the next access caches the page again.

QUERY
: Counts resident, dirty, pinned and uncached pages. Dirty comes from the
  cache metadata; with `der=cylon` a page written through a direct mapping
  may not show as dirty until its EPT dirty bit is sampled.

Commands run one at a time in submission order, in chunks of at most 256
pages, and each chunk waits out its media time. Guest accesses run between
chunks. A page is changed atomically within its chunk, but a range is not:
if a range must stay non-resident, stop accessing it while the command runs.

Pins and uncached ranges survive a cache flush (`flush-cache`, control
commands 2, 9 and 11) and a `cache-ways` change; a flush writes pinned dirty
pages back and keeps them resident. A way change that cannot fit the pinned
pages is refused. A device reset, including a guest reboot, unpins
everything and ends every uncached range. A direct ratio (`der-ratio`) and
uncached ranges exclude each other.

## Errors

Status values from the device:

| Status | Meaning |
| --- | --- |
| `-EINVAL` | Unknown command or flag, nonzero reserved field, or an empty range |
| `-ERANGE` | The range goes past the end of the media |
| `-ENOSPC` | PIN: a set has no way left to pin |
| `-EBUSY` | INVALIDATE or CACHE_DISABLE over pinned pages without FORCE; PIN over an uncached page; CACHE_DISABLE while a direct ratio is set |
| `-EOPNOTSUPP` | PIN or UNPIN without a cache |
| `-ENODEV` | The CXL media is disabled; every command but NOP fails. Nothing a guest does through the CXL mailbox in this QEMU disables it |
| `-EIO` | NAND refused a read or write. INVALIDATE leaves that page and the rest of the range resident |
| `-EAGAIN` | A `cache-ways` change during a PIN left no room for the rest |

The library adds its own:

| Status | Meaning |
| --- | --- |
| `-ETIMEDOUT` | No answer within the timeout |
| `-ECANCELED` | A device reset cancelled the command while it waited |
| `-EPROTO` | The rings hit a fatal error; every call fails until `cca_reset()`, or the next `cca_open()` |
| `-EBUSY` (from `cca_open()`) | Another process holds the device |

## Library

`hw/femu/tools/cca/cca.h` documents every call. Link with `libcca.a` and
`-pthread`. A short example:

```c
#include "cca.h"

struct cca_dev *d;
struct cca_result r;

if (cca_open("mem0", &d) == 0) {
    cca_pin(d, 0, 16, &r);           /* returns r.status */
    cca_query(d, 0, 16, &r);         /* r.resident, r.pinned, ... */
    cca_unpin(d, 0, 16, &r);
    cca_close(d);
}
```

- Synchronous calls (`cca_pin`, `cca_unpin`, `cca_invalidate`,
  `cca_cache_disable`, `cca_cache_enable`, `cca_query`) return the device
  status and fill `struct cca_result`; `pages` is the number of pages acted
  on. `cca_nop` returns the status only. Pass `CCA_FLAG_FORCE` to
  `cca_invalidate` and `cca_cache_disable`, and `CCA_WHOLE` as the count with
  a start of 0 for the whole media.
- `cca_submit()` and `cca_reap()` keep up to 2048 commands in flight;
  `CCA_SUBMIT_DEFER` batches doorbells, and `cca_kick()` rings once.
- `cca_attach_dax()` takes a devdax mapping of a non-interleaved region on
  the memdev; afterwards `cca_pin_addr()` and the other `*_addr` calls take
  virtual addresses in the mapping and widen them to whole pages.
- All calls are thread safe. The library locks `resource5` with `flock()`,
  so one process uses a device at a time. A process that dies holding it
  leaves its ring state behind; the next `cca_open()` resets the rings. Its
  pins and uncached ranges stay; `ccactl reset all` clears them.
- `cca_set_timeout()` changes the 10 second default; negative waits forever.

## Guest tests

`run-guest-tests.sh` builds the tools, records the kernel and whether BAR5
was assigned, finds the devdax device of the memdev and runs `cca-test`.
Run it as root inside the guest:

<!-- femu-untested: runs inside the guest, not a FEMU launcher -->
```sh
cd hw/femu/tools/cca
sudo ./run-guest-tests.sh -d mem0
```

`-x dax0.0` names the devdax device and `-o LOG` the log file (default
`cca-guest-<date>-<time>.log`). Cases can be named after the options. Each
case prints `PASS`, `FAIL` or `SKIP`, and the script exits 1 if any failed.
The `query`, `thrash`, `invalidate` and `disable` cases map the devdax
device and are skipped without one of at least 2 MiB. The
[tools README](../../tools/cca/README.md#guest-tests) lists every case.

The `thrash` and `disable` cases compare access times and expect a factor of 5.
With `der=off` a cache hit already costs microseconds of emulation, so
`disable` can fail that ratio without anything being wrong; with
`der=memslot` and `der=cylon` all cases passed in FEMU's guest runs.
`invalidate` brackets its step with `CCA-MARK` lines; between them the
host's `media-writes` counter must rise by 64.

## Counters

Read with `qom-get` as described in
[counters](../modes/cxl-ssd.md#counters):

| Counter | Meaning |
| --- | --- |
| `cca-commands`, `cca-errors` | Commands completed, and those with a nonzero status |
| `cca-pinned`, `cca-uncached` | Pages pinned now, pages in uncached ranges now |
| `cca-pin-fills` | Pages PIN read from NAND |
| `cca-writebacks`, `cca-dropped` | Dirty pages programmed, and resident pages dropped, by INVALIDATE and CACHE_DISABLE |
| `cca-pinned-set-misses` | Misses served from NAND because every way of the set is pinned |

`stats-reset` clears the event counters and keeps the two gauges.

## Related pages

- [CXL SSD](../modes/cxl-ssd.md)
- [CCA guest tools README](../../tools/cca/README.md)
- [CXL SSD design note](../cxlssd.md#caching-api-cca)
