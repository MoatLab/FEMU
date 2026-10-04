# Log pages and counters

How to read FEMU's own counters from the guest. Device properties are in
[properties.md](properties.md), and the counters of `femu-cxl-ssd` are QOM
properties listed in [runtime-properties.md](runtime-properties.md).

## Vendor log page C0h

`nvme get-log /dev/nvme0 --log-id=0xc0 --log-len=512 -b` returns the emulator's
own media counters, little-endian at these offsets (`FemuStatsLog` in
`hw/femu/nvme.h`):

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 4 | Write amplification factor, scaled by 1000: (pages programmed + pages relocated by garbage collection) x 1000 / pages the host asked to program |
| 8 | 8 | Pages the host asked to program |
| 16 | 8 | Pages relocated by garbage collection |
| 24 | 8 | Pages actually programmed |
| 32 | 8 | Reads of the most-read block since its erase |
| 40 | 8 | Lines rewritten because of read stress |
| 48 | 8 | Lines rewritten because of retention age |
| 56 | 8 | Host read pages the write buffer saw |
| 64 | 8 | Of those, pages the buffer held |
| 72 | 8 | Host write pages the write buffer saw |
| 80 | 8 | Of those, pages the buffer already held |
| 88 | 8 | Log-block switch merges (`mapping=hybrid` only) |
| 96 | 8 | Log-block full merges |
| 104 | 8 | Erases charged to log-block merges |

Bytes 4-7 and 112-511 are reserved and read as zero. The counters are summed
over the controller's bbssd, CSD and KV namespaces (the block read count is the
largest of them); other modes leave them zero. The write amplification factor
stays zero until the host has written a page.
Bytes 8 and 24 are equal when no write buffer is configured; a buffer that
absorbs repeated writes to one page makes the factor drop below 1.

They were previously written into the SMART log from byte 192, which NVMe Base
2.0 assigned to the composite temperature times, the temperature sensors and
the thermal transition counts.

The host can read the same page counters per namespace without the guest,
together with the line states, through the QMP command
[query-femu](query-femu.md).

The same counters can be captured through the standard Telemetry Host-Initiated
log (07h): `nvme telemetry-log /dev/nvme0 --output-file=telemetry.bin` takes a
snapshot and saves it. Data Area 1 is one 512-byte block laid out as above, and
it stays as captured until the next capture. The Controller-Initiated log (08h)
never holds data, because the controller does not capture on its own.

`nvme get-log /dev/nvme0 --log-id=0 --log-len=1024 -b` lists every log page the
controller answers, four bytes per identifier with bit 0 set for the ones it
supports, so this page can be discovered rather than assumed.

## Asynchronous events

The controller completes an outstanding Asynchronous Event Request when one
of these happens:

| Event | Raised when | Log page it names |
| --- | --- | --- |
| SMART temperature warning | the host has enabled it with Async Event Configuration and set a temperature threshold at or below the reported value (`temperature`, in Kelvin, default 323, which is 50 C) | SMART / Health (02h) |
| Error | the host writes a doorbell that does not exist, or a value past the end of its queue | Error Information (01h) |
| Namespace Attribute Changed | with `ns_mgmt=on`, a namespace is attached, detached, deleted or formatted, and the host enabled the notice | Changed Namespace List (04h) |
| Zone Descriptor Changed | an injected write fault (`err_write_fail_ppm`) made a ZNS zone read only, and the host enabled Zone Descriptor Changed notices (bit 27) | Changed Zone List (BFh) |

An event of a given type is reported once and then held back until the
host reads the log page it named without Retain Asynchronous Event (RAE), so
the same condition is not reported again before the host has looked. A
controller reset drops anything outstanding. `hw/femu/scripts/aer-probe.c`
checks the temperature path from inside the guest:

```sh
gcc -O2 -o aer-probe femu-scripts/aer-probe.c   # inside the guest
sudo ./aer-probe /dev/nvme0
```

## Persistent Event log retention

The Persistent Event log (0Dh) lives in memory and is lost when QEMU exits.
Set `pel_file=/absolute/path/events.pel` on a `femu` device to keep it
across QEMU runs. A missing file starts an empty history. A corrupt or
incompatible file refuses device creation and is left unchanged.

The file holds the encoded events, the log generation and the power cycle
count. Each realize adds one power cycle, a power-on event and a SMART
snapshot. The PEL header's power cycle count (PWRCC), the Controller Power
Cycle and SMART Power Cycles all use the retained count. Reporting contexts,
the other SMART counters, namespace data and power-on hours are not
retained.

The file is written on the main loop after events and generation changes,
and again at controller reset, device removal and normal process exit. Each
write goes to a temporary file in the same directory, which is synced,
renamed over the old file, and followed by a sync of the directory. At
normal exit, event collection closes under the log mutex before the last
write: events added before that point are saved, and later ones, including
completions of outstanding I/O, are dropped. The exit path does not wait
for the pollers, whose MMIO DMA may need the main thread's lock. Killing
QEMU abruptly can lose changes still queued for the main loop. A write
error is printed to stderr, and the next event or lifecycle save tries
again.

Use one file per device and one QEMU writing it. The file is not a way to
share a log between devices or to migrate one.
