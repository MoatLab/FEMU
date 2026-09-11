# NAND host tests

Both tests build and run outside QEMU — no guest, no KVM, no root. Run them from
the FEMU checkout root.

## test_channel — the media timing model

`nand_media_op()` is pure timing arithmetic over a caller-supplied timeline.

```bash
mkdir -p /tmp/nandtest/qemu
printf '#include <stdint.h>\n#include <stdbool.h>\n#include <stddef.h>\n#include <string.h>\n' \
    > /tmp/nandtest/qemu/osdep.h
gcc -c -I/tmp/nandtest -Ihw/femu/nand -o /tmp/nandtest/nand-media.o hw/femu/nand/nand-media.c
gcc -I/tmp/nandtest -Ihw/femu/nand -o /tmp/nandtest/t \
    hw/femu/nand/test/test_channel.c /tmp/nandtest/nand-media.o -lm
/tmp/nandtest/t
```

## test_pairing — the QLC page-class table

`init_qlc_page_pairing()` is static and its translation unit pulls in QEMU, so the
function text is extracted from `nand.c` instead of being copied into the test.
Re-extract on every build; a stale `.inc` would test nothing.

```bash
mkdir -p /tmp/nandtest
sed -n '/^static void init_qlc_page_pairing/,/^}/p' hw/femu/nand/nand.c \
    > /tmp/nandtest/pairing_extract.inc
gcc -std=c11 -Wall -Wextra -Werror -I/tmp/nandtest -o /tmp/nandtest/tp \
    hw/femu/nand/test/test_pairing.c
/tmp/nandtest/tp
```

Expected output is `class page counts: 132 128 126 126` and `test_pairing: ok`.

The table is what every physical-layout experiment predicts against, and a
mismatch is silent — the mapper still emits a plan and the device still serves the
reads, only the latency is wrong. Upstream's loop bound was `rows - 3`, which
stops at page index 495 and leaves 496..511 at the zero-initialised value, a
valid-looking `QLC_LOWER_PAGE`. That is invisible at `pgs_per_blk <= 496` — which
is why the earlier 256-page runs were unaffected — and wrong at the 512 pages the
QLC-aligned expert layout requires. Against the unpatched source this test reports
`FAIL pg 496` and counts `128 124 122 122`.

## What the timing tests establish

**bbssd never enables the channel stage.** `ftl-media.c` copies `pg_xfer_lat` into
`cfg.timing.page_xfer_ns` and then sets `cfg.policy.channel_mode = NAND_CH_OFF`
unconditionally. `nand-media.c` reads `page_xfer_ns` only under `NAND_CH_STAGED`,
so passing `pg_xfer_lat=...` on the command line today changes nothing.
`NAND_CH_STAGED` is dead code: both call sites (`bbssd/ftl-media.c`,
`zns/zftl.c`) set `NAND_CH_OFF`.

**Turning it on is not behaviour-preserving, even with a zero bus.** With every
bus phase at 0, `NAND_CH_STAGED` still differs from `NAND_CH_OFF`, because the
channel timeline is advanced to each op's data-out time and the next op's
command phase is clamped to it. Any `channel_model` option must therefore default
to `off`.

**The staged model serialises the channel across LUNs.** Reservations are made in
op-submission order, so an op's command phase waits for the *previous* op's
data-out even when the two are on different LUNs. Measured with two LUNs on one
channel, both reads issued at t=0, slow page (228.1 us array):

| bus transfer | LUN0 done | LUN1 done | if sensing overlapped |
|---|---:|---:|---:|
| 0 us | 228.1 us | 456.2 us | 228.1 us |
| 52.4 us | 280.5 us | 561.1 us | 280.5 us |

Real NAND issues LUN1's command while LUN0 senses; the bus is needed only for the
command and the data burst. This model holds the channel from command through
data-out, so **adding LUNs per channel buys nothing** and per-op cost is always
`array + transfer`. It describes a controller that does not pipeline.

The consequence for page-mapping studies: the gain is `(mean_array + xfer) /
(aware_array + xfer)` at every LUN count — 1.219x for the 2-tier unified-LRU
traffic mix at 1.8 GB — rather than falling toward 1.0 as the channel saturates.
That flat 1.219x is a property of the model, not of the device. Anything claiming
a LUN-count dependence needs the reservation order fixed first (event-driven
issue, or a separate command-phase timeline), with these tests extended to cover
it.
