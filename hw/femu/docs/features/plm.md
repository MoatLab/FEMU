# Predictable Latency Mode

Predictable Latency Mode (PLM, NVMe Base 2.3, 8.1.20) lets the host
split the time of an NVM Set into two windows. In the Deterministic
Window (DTWIN) the drive does only the work that host commands need, so
reads see a short tail. In the Non-Deterministic Window (NDWIN) the drive
does its background work and prepares the next DTWIN.

FEMU models PLM on a [BlackBox](../modes/blackbox.md) SSD. It is off by
default. With `plm=off`, the controller reports and does the same as
before. The register and log details are in
[NVM Sets](../design/nvme-frontend.md#nvm-sets-plm).

Use it to study how a host schedules reads around garbage collection
(GC). It also shows what a drive must hold back to keep a read tail
short.

## Requirements

PLM works per NVM Set, and a set belongs to an Endurance Group. FEMU
reports an Endurance Group only with a `femu-subsys`. So `plm=on` needs:

- `femu_mode=1` (bbssd) with exactly one namespace and `mapping=page`;
- a `femu-subsys` that holds this one controller;
- `rrl=on`, because PLM needs Read Recovery Levels (Feature 12h).

Without `rber_ppb`, Feature 12h takes each level, and a level changes no
read. The guest needs a Linux kernel with the NVMe driver. The commands
below use nvme-cli 2.0 or newer.

## Launch

The subsystem comes first on the command line, because the controller
names it with `subsys=`:

<!-- femu-example: plm-minimal -->
```
-device femu-subsys,id=plm0 -device femu,devsz_mb=1024,femu_mode=1,subsys=plm0,rrl=on,plm=on
```

The window limits are properties. This device ends a DTWIN after 64
writes of one flash page each, or after 2 s:

<!-- femu-example: plm-limits -->
```
-device femu-subsys,id=plm0 -device femu,devsz_mb=1024,femu_mode=1,subsys=plm0,rrl=on,plm=on,plm_dtwin_ms=2000,plm_dtwin_writes=64,plm_ndwin_ms=1000,plm_ndwin_min_ms=100
```

## Properties

| Property | Log 0Ah field | Default | Meaning |
| --- | --- | --- | --- |
| `plm` | none | `off` | NVM Set 1, Features 13h and 14h, logs 0Ah and 0Bh |
| `plm_dtwin_ms` | DTWTM | `1000` | the longest DTWIN in ms, 1 to 3600000 |
| `plm_dtwin_reads` | DTWRT | `1048576` | the reads of a DTWIN, in 4 KiB units |
| `plm_dtwin_writes` | DTWWT | `0` | the writes of a DTWIN, in OWS units; 0 is the room of a full NDWIN |
| `plm_ndwin_ms` | NTWTMH | `1000` | the NDWIN time that log 0Ah reports, in ms |
| `plm_ndwin_min_ms` | NTWTML | `0` | the shortest NDWIN before a Set 14h DTWIN completes, in ms |
| `plm_ndwin_lines` | none | `0` | the free lines that the NDWIN GC collects up to; 0 is `gc_thres_lines`, kept in range |

OWS is the Optimal Write Size of the NVM Set. With `perf_hints=on` it is
one stripe (NOWS + 1 blocks). Without it, CNS 04h reports 0, and FEMU
counts writes in flash pages. FEMU reports NTWTMH as given. It does not
prove that the NDWIN GC finishes in that time.

## The windows

The host turns PLM on with Set Features 13h. It then selects each window
with Set Features 14h. The device also leaves a DTWIN on its own:

```
                 Set 13h LPE=1 (from any window)
   +-----------+ ----------------------------> +-----------+
   | DISABLED  |                               |   NDWIN   |<------------+
   | PLMW 000b | <---------------------------- | PLMW 010b |             |
   +-----------+   Set 13h LPE=0, reset        +-----------+             |
        ^                                        |      ^                |
        |                                        |      | Set 14h NDWIN, |
        |           Set 14h DTWIN (held until    |      | Format,        |
        |           NTWTML and the media end)    |      | Sanitize       |
        |                                        v      | (no event)     |
        |                                      +-----------+             |
        +------------------------------------- |   DTWIN   | ------------+
              Set 13h LPE=0, reset             | PLMW 001b |  on its own:
                                               +-----------+  MVEAT or DEAT
```

- Set 13h LPE=1 always starts an NDWIN, also from a DTWIN.
- A Set 14h DTWIN from NDWIN waits until `plm_ndwin_min_ms` has passed in
  the NDWIN, and the media work booked at its arrival has ended. Other
  admin commands still run meanwhile.
- A Set 14h DTWIN while in DTWIN keeps the counts of the window. So a host
  cannot get a new budget without an NDWIN.
- A reset, a power cycle or Set 13h LPE=0 disables PLM. Features 13h and
  14h do not persist.

## What a DTWIN holds back

In a DTWIN the FTL does host commands and holds all background work. A
held item keeps its state and runs in the next NDWIN:

| Work | DTWIN | NDWIN |
| --- | --- | --- |
| host commands, Flush, destage of a full write buffer | run | run |
| forced GC at `gc_thres_pcent_high` | leave DTWIN (DEAT), then run | run |
| background GC, idle GC, `maint_idle` | hold | run |
| idle write-back (`buffer_low_pcent`) | hold | run |
| read reclaim, retention refresh, wear levelling | hold | run |
| RAIN rebuild, pad of aged open lines | hold | run |
| preparation GC up to `plm_ndwin_lines` | hold | run |

In an NDWIN, a preparation GC raises the free lines to the target of
`plm_ndwin_lines`. It stops when a step frees no line. It starts again
when the host writes or deallocates more pages.

## The exits: MVEAT and DEAT

The FTL counts the reads (4 KiB units) and the writes (OWS units) of
each DTWIN. It leaves the DTWIN on its own in these cases:

```
 reads > DTWRT, writes > DTWWT, or time >= DTWTM --> NDWIN, ETYP bit 14 (MVEAT)
 a forced GC pass, a failed die (x-rain-fail)    --> NDWIN, ETYP bit 15 (DEAT)
```

A DEAT comes first and the GC pass then runs, so a full device never
blocks a write. A cache disable (Set Features 06h) that forces GC in its
drain is a DEAT too. Format NVM and Sanitize move the set to NDWIN with
no event, because the host asked for the media work.

## Events and logs

Log 0Ah (512 bytes, LSI 1) gives the window (PLMW), the event bits
(ETYP), the limits and the estimates of what the DTWIN has left. Log 0Bh
lists set 1 while it has an enabled event. A log read never pauses the
data plane.

```
 MVEAT, DEAT ----------------------------> ETYP bit, also with ENEV clear
 estimate < DTRT, DTWT or DTTT, ENEV bit -> warning bit, once per DTWIN
 event with its ENEV bit ----------------> log 0Bh entry
 new entry and AEC bit 12 ---------------> AEN (Notice, 04h, log 0Bh)
 Get Log 0Ah without RAE ----------------> ETYP and the entry clear
 Get Log 0Bh without RAE ----------------> the Notice is no longer masked
```

ENEV and the thresholds DTRT, DTWT and DTTT come from the 512-byte data
of Set 13h (Figure 423). Linux leaves AEC bit 12 clear, so it gets no
AEN. A host that sets the bit must read log 0Bh, or the Notice type stays
masked.

### What GC did in an NDWIN

Log C0h, the FEMU counter page, also records the GC of the last NDWIN
that ended. The record runs from the NDWIN entry to its exit, a held Set
14h included. Read it after each Set 14h DTWIN:

```sh
nvme get-log /dev/nvme0 --log-id=0xc0 --log-len=512 -b | xxd -s 352 -l 144
```

```
 NDWIN entry: seq, free lines, victim lines, media work booked ahead
      |
      |  GC passes: copies, erases, LUN time booked, victims by kind
      v
 NDWIN exit (DTWIN or LPE=0): length, free lines, most work ahead
      --> log C0h bytes 352 to 495 (one record, the last NDWIN)
```

The LUN time is the time each GC booking adds to the busy-until time of
its LUN, summed over all LUNs. Divide it by the LUN count (byte 488) for
the mean GC time of a LUN. A host read on a LUN waits for the work booked
ahead of it, so this mean shows the read stall of the NDWIN. The fields
are in [log page C0h](../reference/log-pages-and-counters.md#vendor-log-page-c0h).
With plm=off the bytes stay zero.

## Refusals

Realize refuses `plm=on` with an error that names the cause:

```
 refused with plm=on   femu_mode other than bbssd, namespace_modes, ns_mgmt,
                       shared namespaces, FDP, ocp, gc_pace, streams,
                       tier_mode, cxl_ssd, power_loss, persist_file
 needed with plm=on    rrl=on, a femu-subsys, namespaces=1, mapping=page
 out of range          plm_* limits, plm_ndwin_lines above what the user
                       data leaves free, plm_dtwin_writes above the room
                       of a full NDWIN; any plm_* property with plm=off
```

At run time, these commands fail with Invalid Field in Command:

- an NVMSETID other than 1;
- an NSID other than 0 on Features 12h, 13h or 14h;
- reserved bits, or a WSEL other than DTWIN or NDWIN;
- Feature 14h while PLM is disabled.

SV=1 fails with Feature Identifier Not Saveable.

## nvme-cli

These commands run in the guest. In nvme-cli 2.x, `-c` of get-feature
is CDW11 (the NVMSETID). The `-V` and `-c` of set-feature are CDW11 and
CDW12:

```sh
nvme id-ctrl /dev/nvme0 | grep -E '^(ctratt|oaes|nsetidmax)'
nvme id-nvmset /dev/nvme0
# 512 bytes for Set 13h: ENEV bits 14 and 15 (MVEAT, DEAT), no thresholds
printf '\x00\xc0' > plm.cfg && truncate -s 512 plm.cfg
nvme set-feature /dev/nvme0 -n 0 -f 0x13 -V 1 -c 1 -l 512 -d plm.cfg
nvme get-feature /dev/nvme0 -n 0 -f 0x13 -c 1 -l 512
nvme get-feature /dev/nvme0 -n 0 -f 0x14 -c 1    # 2: NDWIN
nvme set-feature /dev/nvme0 -n 0 -f 0x14 -V 1 -c 1   # select DTWIN
nvme set-feature /dev/nvme0 -n 0 -f 0x14 -V 1 -c 2   # select NDWIN
nvme get-log /dev/nvme0 -i 0x0a -l 512 --lsi=1 --rae
nvme get-log /dev/nvme0 -i 0x0b -l 512 --rae
nvme predictable-lat-log /dev/nvme0
```

Byte 0 of log 0Ah is PLMW, bytes 3:2 are ETYP, and bytes 151:128 are
DTWRE, DTWWE and DTWTE.

## Guest check

`hw/femu/scripts/plm-guest.py` runs the checks of this page in a guest.
`plm-verdict.py` judges its output on the host. Boot the device with a
long `plm_dtwin_ms`, so only the writes end the DTWIN:

<!-- femu-example: plm-guest-check -->
```
-device femu-subsys,id=plm0 -device femu,devsz_mb=1024,femu_mode=1,subsys=plm0,rrl=on,plm=on,perf_hints=on,plm_dtwin_ms=60000,plm_dtwin_writes=64
```

Then, as root in the guest and on the host:

```sh
python3 plm-guest.py check --need nvme,fio
python3 plm-guest.py gplm1 > gplm1.out          # in the guest: writes to nvme0n1
python3 plm-verdict.py gplm1 --guest gplm1.out  # on the host
```

The check writes DTWWT units in a DTWIN and requires the window to stay.
One more unit must end it with MVEAT. It also checks the Identify bits,
the NVM Set List, the refusals and the log reads that clear the events.

```
 Set 14h DTWIN --> DTWWT units --> still DTWIN, DTWWE fell
               --> 1 more unit --> NDWIN, ETYP MVEAT --> logs clear on read
```

`plm-guest.py tail` runs one repeat of the read tail experiment. It
issues 4 KiB random reads at QD 1 next to a write stream of fixed rate.
Meanwhile it switches the windows, and it reports p50, p99 and p99.9 of
the reads in each window. The NDWIN runs up to the end of the held Set
14h DTWIN, so reads in the hold count as NDWIN reads:

```
 nd0 .......... Set 14h DTWIN sent ...... CQE (DTWIN entry) ...... end
 |<------------- NDWIN, hold included ------->|<------ DTWIN ------>|
```

fio runs open-ended, and the script stops it after the last cycle. So
every cycle carries load, however long the holds are. After each DTWIN
entry the script reads the [GC record](#what-gc-did-in-an-ndwin) of log
C0h. It prints the record in the cycle line (`FGC`). After the run it
prints the NDWIN reads of each cycle (`FGN`).

`plm-verdict.py tail` then sets these pass rules:

- Only the reads of valid cycles count. A valid cycle starts its DTWIN
  with enough write room and has no DEAT.
- Each repeat has at least 1000 DTWIN reads and 1000 NDWIN reads. Each
  control repeat has at least 1000 reads in each set of slots.
- The median DTWIN p99 is at least 20 % below the median NDWIN p99.
- In each repeat, the DTWIN p99.9 is below the NDWIN p99.9.
- In each repeat, the DTWIN p99.9 is at least 20 % below the control
  p99.9.
- No DEAT occurs in a cycle that started with enough write room.
- In each repeat, a read waits over 10 ms in at most 5 % of the NDWIN
  time. This is the main NDWIN rule.
- In each repeat, the NDWIN p99.9 is at most 20 ms.
- At least 90 % of the cycles read the GC record of their own NDWIN.
- A plm=off run with the same time slots (`--phantom`) is the control.
  Its two sets of slots must agree.

The time share counts the stall time that the read count hides. At QD 1
one read that waits 2 seconds blocks all reads behind it. It is one read
in the count, but 2 seconds of the time:

```
 read   R1 waits 2.4 s ---------------------->|R2 R3 R4 ...
 count  1 read of many                --> p99.9 can stay low
 time   2.39 s over 10 ms of a 3.5 s NDWIN --> share 68 %
```

With `--nd-rules report` the verdict prints the NDWIN rules and does not
apply them. A run of a build that collects in bursts uses it. The
verdict also gives the cause check. It compares the longest NDWIN read
of a cycle with the GC time of one LUN in that NDWIN:

```
 ratio = longest NDWIN read / (LUN GC time + work booked ahead at entry)
 0.5 <= ratio <= 2 and FTL thread time <= 0.1 x LUN GC time --> CAUSE yes
```

`plm-guest.py gplm1` sends every admin command that it checks through
the NVMe ioctl, so it does not depend on the output format of nvme-cli.
It runs the nvme-cli commands of this page too, and records only how
each ended. A failed command prints its raw data as `FG_RAW` lines.

## Limits

- One NVM Set, one namespace and one controller. SQ Associations and
  Namespace Management are not modelled.
- Set 13h completes at once; the spec allows it to wait.
- A DTWIN still has host programs, which contend with reads on a die.
- Read reclaim waits in a DTWIN; `plm_dtwin_ms` bounds the wait.

## Related pages

- [NVM Sets: the register and log details](../design/nvme-frontend.md#nvm-sets-plm)
- [BlackBox SSD](../modes/blackbox.md)
- [Testing](../guides/testing.md)
