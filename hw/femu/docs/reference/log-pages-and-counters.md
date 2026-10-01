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

They were previously written into the SMART log from byte 192, which NVMe Base
2.0 assigned to the composite temperature times, the temperature sensors and
the thermal transition counts.

The same counters can be captured through the standard Telemetry Host-Initiated
log (07h): `nvme telemetry-log /dev/nvme0 --output-file=telemetry.bin` takes a
snapshot and saves it. Data Area 1 is one 512-byte block laid out as above, and
it stays as captured until the next capture. The Controller-Initiated log (08h)
never holds data, because the controller does not capture on its own.

`nvme get-log /dev/nvme0 --log-id=0 --log-len=1024 -b` lists every log page the
controller answers, four bytes per identifier with bit 0 set for the ones it
supports, so this page can be discovered rather than assumed.
