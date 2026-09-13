#!/bin/bash
# Drive one measurement run from the host, preserving a counter snapshot per step.
#
# FEMU rewrites the same stats file on every snapshot and the guest cannot see
# that file, so a step's counters survive only if the host copies them before the
# next step runs. The previous run lost its replay-only snapshot exactly this way,
# leaving a reported result that could not be re-checked.
#
# Every guest command's exit status is checked. replay_v1 refuses to overwrite an
# existing output file, so a repeated run with the same paths exits non-zero and
# leaves the counters untouched -- which reads as a successful repeat unless the
# status is examined.
set -uo pipefail

RUN=${1:?usage: drive_run.sh RUN_TAG}
# Derive the checkout root from this script rather than naming it, so the same
# script drives a run on whichever machine it was copied to.
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
CSV=$ROOT/runs/femu/${RUN}_qlc.csv
OUT=$ROOT/runs/femu/$RUN
SSH="ssh -p ${SSH_PORT:-2222} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 femu@127.0.0.1"

mkdir -p "$OUT"

# Wait for FEMU to rewrite the stats file, then keep it under a step-specific name.
keep() {
    local label=$1 before=$2
    for _ in $(seq 40); do
        [ -f "$CSV" ] && [ "$(stat -c %Y.%N "$CSV" 2>/dev/null)" != "$before" ] && break
        sleep 0.5
    done
    cp "$CSV" "$OUT/$label.csv" || return 1
    printf '  %-14s ' "$label"
    grep -v '^#' "$OUT/$label.csv" | tail -4 | awk -F, '{printf "%9d ", $2} END {print ""}'
}

step() {                       # step LABEL COMMAND...
    local label=$1; shift
    local before; before=$(stat -c %Y.%N "$CSV" 2>/dev/null || echo none)
    if ! $SSH "$@" > "$OUT/$label.stdout" 2>"$OUT/$label.stderr"; then
        echo "  $label FAILED (rc=$?); see $OUT/$label.stderr"
        tail -3 "$OUT/$label.stderr" | sed 's/^/    /'
        return 1
    fi
    keep "$label" "$before"
}

echo "== $RUN =="
echo "  queue: $($SSH 'cat /sys/block/nvme0n1/queue/max_segments /sys/block/nvme0n1/queue/max_sectors_kb' 2>/dev/null | tr '\n' ' ')"
echo "  class          c0        c1        c2        c3"
# Assert the diagonal rather than print it. A drifted fill still produces a
# plausible-looking counter row, and the whole reason the earlier runs went
# unnoticed for so long is that a human had to spot the difference. Reading the
# whole image, not a prefix: pages past the checked range are exactly the ones a
# partial check would miss.
IMAGE_PAGES=${IMAGE_PAGES:-471040}
for c in 0 1 2 3; do
    step "confusion_c$c" "sudo /usr/local/bin/class_confusion /dev/nvme0n1 /dev/nvme0 $c $IMAGE_PAGES" || exit 1
    read -r -a got <<<"$(grep -v '^#' "$OUT/confusion_c$c.csv" | grep -v page_class | cut -d, -f2 | tr '\n' ' ')"
    for k in 0 1 2 3; do
        if { [ "$k" = "$c" ] && [ "${got[$k]}" -eq 0 ]; } ||
           { [ "$k" != "$c" ] && [ "${got[$k]}" -ne 0 ]; }; then
            echo "  FAIL class $c leaked into class $k — the fill did not land as planned"
            echo "       counters: ${got[*]}"
            exit 1
        fi
    done
done
echo "  confusion diagonal over $IMAGE_PAGES pages: clean"
step replay "sudo /usr/local/bin/replay_v1 --trace /root/replay.bin --device /dev/nvme0n1 \
    --controller /dev/nvme0 --qd 32 --group-log /dev/shm/$RUN.groups.jsonl \
    --summary /dev/shm/$RUN.summary.json && cat /dev/shm/$RUN.summary.json" || exit 1
# Phase-aware counters are optional. The replayer announces each phase change
# with an admin FLIP (selectors 10-12), but FEMU's bb_flip only implements 8 and
# 9, so those announcements currently fall through to default and no phase
# columns are produced. That is not a reason to throw the run away: NAND energy
# is exactly linear in per-class page count, and compose_e2e.py splits it on the
# host from the page_class each compiled command carries, checking that its
# per-class totals equal the ones below. If a rebuilt FEMU does emit the
# columns, they are checked here and become a second, independent split.
python3 - "$OUT/replay.csv" <<'PY' || exit 1
import csv
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    rows = list(csv.DictReader(line for line in source if not line.startswith("#")))
if len(rows) != 4:
    raise SystemExit(f"expected 4 page-class rows, found {len(rows)}")
required = {
    "prefill_n_read", "prefill_bytes_read",
    "decode_n_read", "decode_bytes_read",
    "teacher_forced_n_read", "teacher_forced_bytes_read",
}
if not required.issubset(rows[0]):
    print("  phase counters: absent (FEMU bb_flip lacks selectors 10-12); "
          "the prefill/decode split comes from the compiled commands on the host")
    raise SystemExit(0)
for row in rows:
    for suffix in ("n_read", "bytes_read"):
        total = int(row[suffix])
        phases = sum(int(row[f"{phase}_{suffix}"])
                     for phase in ("prefill", "decode", "teacher_forced"))
        if total != phases:
            raise SystemExit(
                f"class {row['page_class']} {suffix}: total {total} != phase sum {phases}")
if not any(int(row["prefill_n_read"]) for row in rows):
    raise SystemExit("prefill physical-read counter is empty")
if not any(int(row["decode_n_read"]) for row in rows):
    raise SystemExit("decode physical-read counter is empty")
print("  phase counter closure: total = prefill + decode + teacher-forced")
PY
# The group log carries per-phase timing and is the only record of it; the guest
# writes it to tmpfs, so it dies with the container unless it is pulled here.
if $SSH "sudo gzip -c /dev/shm/$RUN.groups.jsonl" > "$OUT/groups.jsonl.gz" 2>/dev/null &&
   gunzip -f -k "$OUT/groups.jsonl.gz" 2>/dev/null; then
    echo "  group log $(wc -l < "$OUT/groups.jsonl") lines"
else
    echo "  WARNING group log not retrieved; per-phase timing will be unavailable"
fi
echo "  saved under $OUT/"
