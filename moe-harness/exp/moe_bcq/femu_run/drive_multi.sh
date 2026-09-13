#!/bin/bash
# Replay several traces against one already-filled device.
#
# A placement is a property of the image, not of the trace: re-filling the
# device for every trace would re-run out-of-place allocation and land the pages
# on different physical classes, so the fill has to happen once and every trace
# that shares that placement has to be replayed on it. replay_v1 resets the QLC
# counters when it starts and snapshots them when it ends, so consecutive
# replays on one device still report independent per-class totals.
#
# Two things from drive_run.sh carry over because they are what made earlier
# runs unrecoverable: FEMU rewrites one stats file per snapshot and the guest
# cannot read it, so the host copies it between steps; and replay_v1 refuses to
# overwrite its outputs, so every replay needs unique paths or it exits without
# running and leaves the previous counters in place, which reads as success.
set -uo pipefail

TAG=${1:?usage: drive_multi.sh DEVICE_TAG SPECFILE}
SPEC=${2:?usage: drive_multi.sh DEVICE_TAG SPECFILE}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
CSV=$ROOT/runs/femu/${TAG}_qlc.csv
RECORDS=$ROOT/exp/moe_bcq/femu_run/records
# -n on every ssh that is not being fed a file: without it ssh inherits the
# loop's stdin and swallows the rest of the spec, so the first replay runs and
# the loop then reads EOF and exits reporting success. SSHIN is the one that
# does take stdin, for streaming a binary in.
SSHOPT="-p ${SSH_PORT:-2222} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10"
SSH="ssh -n $SSHOPT femu@127.0.0.1"
SSHIN="ssh $SSHOPT femu@127.0.0.1"

echo "== device $TAG =="
echo "  queue: $($SSH 'cat /sys/block/nvme0n1/queue/max_segments /sys/block/nvme0n1/queue/max_sectors_kb' 2>/dev/null | tr '\n' ' ')"

# ---- placement check, once per device -------------------------------------
# Asserted, not printed. A drifted fill still produces a plausible counter row,
# and the whole reason the earlier runs went unnoticed is that a human had to
# spot the difference. The whole image, not a prefix: the pages past a partial
# range are exactly the ones that check would miss.
IMAGE_PAGES=${IMAGE_PAGES:?IMAGE_PAGES must be set (Qwen 471040, DeepSeek 544768)}
CONF=$ROOT/runs/femu/$TAG
mkdir -p "$CONF"
echo "  class          c0        c1        c2        c3"
for c in 0 1 2 3; do
    before=$(stat -c %Y.%N "$CSV" 2>/dev/null || echo none)
    $SSH "sudo /usr/local/bin/class_confusion /dev/nvme0n1 /dev/nvme0 $c $IMAGE_PAGES" \
        > "$CONF/confusion_c$c.stdout" 2>"$CONF/confusion_c$c.stderr" || {
        echo "  confusion_c$c FAILED"; tail -3 "$CONF/confusion_c$c.stderr" | sed 's/^/    /'; exit 1; }
    for _ in $(seq 40); do
        [ -f "$CSV" ] && [ "$(stat -c %Y.%N "$CSV" 2>/dev/null)" != "$before" ] && break
        sleep 0.5
    done
    cp "$CSV" "$CONF/confusion_c$c.csv" || exit 1
    read -r -a got <<<"$(grep -v '^#' "$CONF/confusion_c$c.csv" | grep -v page_class | cut -d, -f2 | tr '\n' ' ')"
    printf '  confusion_c%-3s' "$c"; printf '%9d ' "${got[@]:0:4}"; printf '\n'
    for k in 0 1 2 3; do
        if { [ "$k" = "$c" ] && [ "${got[$k]}" -eq 0 ]; } ||
           { [ "$k" != "$c" ] && [ "${got[$k]}" -ne 0 ]; }; then
            echo "  FAIL class $c leaked into class $k -- the fill did not land as planned"
            echo "       counters: ${got[*]}"; exit 1
        fi
    done
done
echo "  confusion diagonal over $IMAGE_PAGES pages: clean"

# ---- one replay per spec line ---------------------------------------------
rc=0
mapfile -t SPEC_LINES < "$SPEC"
for LINE in "${SPEC_LINES[@]}"; do
    read -r NAME BIN <<<"$LINE"
    [ -n "${NAME:-}" ] || continue
    case $NAME in \#*) continue;; esac
    OUT=$RECORDS/$NAME
    if [ -f "$OUT/replay.csv" ] && [ -f "$OUT/groups.jsonl.gz" ]; then
        echo "  -- $NAME already collected, skipping"
        continue
    fi
    [ -f "$ROOT/$BIN" ] || { echo "  -- $NAME MISSING binary $BIN"; rc=1; continue; }
    mkdir -p "$OUT"
    echo "  -- $NAME ($(du -h "$ROOT/$BIN" | cut -f1))"

    # Fresh guest-side paths each time: replay_v1 opens its outputs O_EXCL, so a
    # reused path makes it exit without replaying while the old counters stay
    # put -- indistinguishable from a successful repeat unless rc is checked.
    $SSH "rm -f /home/femu/current.bin /dev/shm/$NAME.*" >/dev/null 2>&1
    if ! $SSHIN "cat > /home/femu/current.bin" < "$ROOT/$BIN"; then
        echo "     binary transfer FAILED"; rc=1; continue
    fi
    want=$(stat -c %s "$ROOT/$BIN"); got=$($SSH "stat -c %s /home/femu/current.bin" 2>/dev/null)
    [ "$want" = "$got" ] || { echo "     binary truncated in transit ($got of $want)"; rc=1; continue; }

    before=$(stat -c %Y.%N "$CSV" 2>/dev/null || echo none)
    if ! $SSH "sudo /usr/local/bin/replay_v1 --trace /home/femu/current.bin --device /dev/nvme0n1 \
            --controller /dev/nvme0 --qd 32 --group-log /dev/shm/$NAME.groups.jsonl \
            --summary /dev/shm/$NAME.summary.json && cat /dev/shm/$NAME.summary.json" \
            > "$OUT/replay.stdout" 2>"$OUT/replay.stderr"; then
        echo "     replay FAILED"; tail -3 "$OUT/replay.stderr" | sed 's/^/       /'; rc=1
        $SSH "rm -f /home/femu/current.bin /dev/shm/$NAME.*" >/dev/null 2>&1
        continue
    fi
    for _ in $(seq 60); do
        [ -f "$CSV" ] && [ "$(stat -c %Y.%N "$CSV" 2>/dev/null)" != "$before" ] && break
        sleep 0.5
    done
    cp "$CSV" "$OUT/replay.csv" || { echo "     counters not captured"; rc=1; }
    if $SSH "sudo gzip -c /dev/shm/$NAME.groups.jsonl" > "$OUT/groups.jsonl.gz" 2>/dev/null &&
       gzip -t "$OUT/groups.jsonl.gz" 2>/dev/null; then
        echo "     group log $(zcat "$OUT/groups.jsonl.gz" | wc -l) lines"
    else
        echo "     WARNING group log not retrieved -- per-phase timing unavailable"; rc=1
    fi
    python3 - "$OUT" <<'PY'
import json, sys
from pathlib import Path
out = Path(sys.argv[1])
s = json.loads((out/'replay.stdout').read_text())
cls = [int(l.split(',')[1]) for l in (out/'replay.csv').read_text().splitlines()
       if l[:1].isdigit()]
print(f"     groups {s['groups']:,}  commands {s['commands']:,}  "
      f"{s['requested_bytes']/2**30:.1f} GiB  io {s['sum_group_io_ns']/1e9:.1f}s  "
      f"pages {sum(cls):,}")
PY
    # tmpfs is small and the gsm8k logs are tens of MB; the record is on the host now.
    $SSH "rm -f /home/femu/current.bin /dev/shm/$NAME.*" >/dev/null 2>&1
done

echo "== device $TAG done (rc=$rc) =="
exit $rc
