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
| 0 | 4 | Write amplification factor, scaled by 1000: (pages programmed + pages relocated by garbage collection + pad pages at offset 264 + translation pages at offset 280) x 1000 / pages the host asked to program |
| 8 | 8 | Pages the host asked to program |
| 16 | 8 | Data pages relocated by garbage collection |
| 24 | 8 | Pages actually programmed |
| 32 | 8 | Reads of the most-read block since its erase |
| 40 | 8 | Lines rewritten because of read stress (reclaim units under FDP) |
| 48 | 8 | Lines rewritten because of retention age (reclaim units under FDP) |
| 56 | 8 | Host read pages the write buffer saw |
| 64 | 8 | Of those, pages the buffer held |
| 72 | 8 | Host write pages the write buffer saw |
| 80 | 8 | Of those, pages the buffer already held |
| 88 | 8 | Log-block switch merges (`mapping=hybrid` only) |
| 96 | 8 | Log-block full merges |
| 104 | 8 | Erases charged to log-block merges |
| 112 | 8 | Blocks in service past their erase limit (`blk_pe_limit`) |
| 120 | 8 | Worn-out blocks taken out of service |
| 128 | 8 | Lines taken out of service (under FDP, the lines of retired reclaim units) |
| 136 | 8 | Lines moved by static wear levelling (`wl_spread`) |
| 144 | 8 | Pages those moves copied (also counted at offset 16) |
| 152 | 8 | NAND pages host writes covered only in part (a device reads such a page to program it again; FEMU does not charge that read) |
| 160 | 8 | Plane reads charged to NAND (a multi-plane command counts each plane) |
| 168 | 8 | Plane programs |
| 176 | 8 | Plane erases |
| 184 | 8 | Energy in uJ: the three counts above times `energy_read_nj`, `energy_prog_nj` and `energy_erase_nj` |
| 192 | 8 | Host writes that waited for forced garbage collection to make room |
| 200 | 8 | Forced collection passes run inside those writes |
| 208 | 8 | Host writes that emptied a full write buffer to make room |
| 216 | 8 | Completions held because the host's completion queue was full (summed over pollers) |
| 224 | 8 | Pages paced collection copied (`gc_pace`; also counted at offset 16) |
| 232 | 8 | Lines paced collection finished, freed or retired |
| 240 | 8 | Paced lines the forced pass or the budget finished in one pass |
| 248 | 8 | Pages collection moved by copyback on their die (`gc_copyback`; also counted at offset 16) |
| 256 | 8 | Lines (reclaim units under FDP) rewritten for the open-block read limit (`pd_open_read_limit`); not counted at offset 40 |
| 264 | 8 | Pages programmed with pad data to close lines or units left open (`pd_open_close_sec`) |
| 272 | 8 | Lines or units those pads closed |
| 280 | 8 | Translation pages programmed (`mapping=dftl` without FDP): dirty CMT evictions, published changes, and translation pages that collection, refresh or wear levelling moved |
| 288 | 8 | Translation pages read from flash (`mapping=dftl` without FDP) |

Bytes 4-7 and 296-511 are reserved and read as zero. The counters are summed
over the controller's bbssd, CSD and KV namespaces (the block read count is the
largest of them); other modes leave them zero. The write amplification factor
stays zero until the host has written a page.
Bytes 8 and 24 are equal when no write buffer is configured; a buffer that
absorbs repeated writes to one page makes the factor drop below 1.

A KV namespace with `kv_index=lsm` adds its merge programs to offset 24. It
adds the meta pages that value GC moves to offset 16. Thus its factor
includes the index.

With value packing (`kv_pack=on`, the default), a KV namespace counts
host data at offset 8. The count is the value bytes of its Stores, in
whole pages, rounded down. At offset 24 it counts each packed page and
each whole value page it programs. Thus the factor is programmed pages over host data, and it
drops below 1 when the open page drops overwritten values. With
`kv_pack=off`, offset 8 counts the pages of each value, as before
([KV value packing](../features/kv-value-packing.md#counters)).

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

## Computational programs and reachability

A CSD controller with `csd_slm_size` or `csd_cp` answers these pages
([CP and SLM](../features/cp-slm.md)):

| LID | Page | CSI | NSID | Content |
| --- | --- | --- | --- | --- |
| 1Ah | Reachability Groups | any | any | one group, RGID 1, with every namespace; LSP bit 0 (RGO) leaves out the NSIDs |
| 1Bh | Reachability Associations | any | any | one association, RASID 1, RAC 01h, holding RGID 1; LSP bit 0 (RAO) leaves out the RGIDs |
| 82h | Program List | 04h | the compute namespace | 16 descriptors, one per PIND |
| 83h | Downloadable Program Types List | 04h | the compute namespace | C3h with `csd_program_dir`; C1h also with uBPF |
| 84h | Memory Range Set List | 04h | the compute namespace | RSID 0h, then every set by RSID; LSP bit 0 (RIO) leaves out the ranges |

Both change counts of 1Ah and 1Bh stay 0h, because the groups never change.

## Asynchronous events

The controller completes an outstanding Asynchronous Event Request when one
of these happens:

| Event | Raised when | Log page it names |
| --- | --- | --- |
| SMART temperature warning | the host has enabled it with Async Event Configuration and the reported temperature (`temperature`, in Kelvin, default 323, which is 50 C) is at or above the over threshold (default 343 K, the warning temperature WCTEMP) or at or below the under threshold (default 0); with the thermal model on, also when the modelled temperature crosses one | SMART / Health (02h) |
| Error | the host writes a doorbell that does not exist, or a value past the end of its queue | Error Information (01h) |
| Namespace Attribute Changed | with `ns_mgmt=on`, a namespace is attached, detached, deleted or formatted, and the host enabled the notice | Changed Namespace List (04h) |
| SMART spare below threshold (02h), reliability (00h) | with `blk_pe_limit`: the spare falls below 20, the first block stays in service past its limit, or the media goes read-only; bit 0, 2 or 3 of Async Event Configuration enables each | SMART / Health (02h) |
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

## End of life

With `blk_pe_limit` and `eol_read_only` (on by default), the media goes
read-only when a worn-out block has no replacement. These fields then show
it:

| Where | Field | Value |
| --- | --- | --- |
| SMART / Health (02h) | Critical Warning bit 3 (All Media Read-Only) | 1 |
| SMART / Health (02h) | Available Spare | 0 |
| SMART / Health (02h) | Endurance Group Critical Warning Summary (byte 6) | bits 0, 2 and 3 of the endurance group's warning; needs a `femu-subsys` |
| Endurance Group Information (09h) | Critical Warning bit 3 (Endurance Group Read-Only) | 1 |
| Identify Namespace, CNS 00h byte 99 and CNS 08h byte 8 | NSATTR bit 0 (Currently Write Protected) | 1 |
| Asynchronous event | SMART, information 00h (reliability), log page 02h | once, if bit 3 of Async Event Configuration is set |
| Persistent Event log (0Dh) | hardware error event, code 06h (critical warning) | once, with the warning byte when the media went read-only |

Writes fail with Attempted Write to Read Only Range (status 182h, DNR). The
same holds for Write Zeroes, Write Uncorrectable, Copy and a deallocating
Dataset Management. The NVM Identify Controller (CNS 06h, CSI 00h) reports
WZSL in byte 1, equal to MDTS. ONCS bit 3 is clear, so WZSL is a hard
limit.

## Thermal model

With `thermal_tau_ms` set, the composite temperature in the SMART log
follows the NAND work instead of staying at `temperature`. Every constant
comes from the user; FEMU has no built-in figures.

```text
  power (mW)  = idle_mw + NAND energy since the last step / the step
                (plane reads, programs, erases x energy_*_nj; bbssd, CSD, KV)
  target (K)  = temperature + power x thermal_r / 1000     (thermal_r: mK per mW)
  every thermal_step_ms of virtual time:
    T = target + (T - target) x exp(-step / thermal_tau_ms)
    SMART temperature = T rounded to a Kelvin
    T reaches the over threshold, or falls to the under threshold:
      SMART critical warning bit 1, Persistent Event log entry,
      and one SMART temperature event if the host enabled it
```

- The clock is QEMU's virtual clock, so a paused VM does not cool. NAND work
  that FEMU does while the VM is paused counts in the first step after it.
- The model does not throttle I/O, and the SMART time-over-threshold fields
  stay 0.
- One event is raised each time the condition starts while the host has
  temperature events enabled, including when it enables them during an
  excursion. A SMART read without RAE discards queued SMART events, so an
  excursion that ends and starts again before the host reads the log is not
  reported twice.
- Refused with namespace management, shared namespaces, `cxl_ssd` and
  `-icount`. `thermal_tau_ms` needs `thermal_r`; `thermal_step_ms` is 1 to
  60000.

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
