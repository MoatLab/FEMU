#!/bin/bash
# Boot one FEMU device, fill it from a given image, then replay a list of traces.
#
# This is deliberately NOT a patch to run_policy.sh. That file also exists on the
# GPU host and the trace delivery rsyncs the whole femu_run directory over, which
# silently reverted two edits to it mid-sweep on 2026-09-10. Files that exist
# only here survive that sync, so the multi-replay path lives in its own.
#
# One device per placement, several traces per device: the image decides which
# physical class each plane lands on, and every trace sharing that image shares
# that placement. Re-filling per trace would re-run out-of-place allocation.
set -uo pipefail

TAG=${1:?usage: run_device.sh DEVICE_TAG IMAGE_BASENAME IMAGE_PAGES SPECFILE}
IMG_BASE=${2:?}; PAGES=${3:?}; SPEC=${4:?}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
IMAGES=${FEMU_GUEST_DIR:-$HOME/images}
SSH_PUBKEY=${FEMU_SSH_PUBKEY:-$HOME/.ssh/id_rsa.pub}
QEMU_IMG=${QEMU_IMG:-$(command -v qemu-img || echo "$ROOT/_deps/FEMU-MoE/build/qemu-img")}
cd "$ROOT"

# make_seed.py needs pycdlib, which is installed for the system interpreter and
# not for whatever python3 a shell resolves first. Fail here, not three lines
# into building the seed after the caller has committed to the run.
if [ -z "${PYTHON:-}" ]; then
    for c in python3 /usr/bin/python3 python3.8; do
        command -v "$c" >/dev/null 2>&1 || continue
        "$c" -c 'import pycdlib' 2>/dev/null && { PYTHON=$c; break; }
    done
fi
[ -n "${PYTHON:-}" ] || { echo "  no python3 with pycdlib; pip install --user pycdlib"; exit 1; }

IMG=/data/images/$IMG_BASE                       # container path; /data is runs/femu
HOST_IMG=$ROOT/runs/femu/images/$IMG_BASE
[ -f "$HOST_IMG" ] || { echo "  no image at $HOST_IMG"; exit 1; }
[ -s "$SPEC" ] || { echo "  empty or missing spec $SPEC"; exit 1; }
SEED=$IMAGES/seed-$TAG.iso
OVL=$IMAGES/femu-root-$TAG.qcow2

echo "=== device $TAG  image $IMG_BASE  pages $PAGES  ($(grep -cve '^\s*$' "$SPEC") traces) ==="
rm -f "$SEED" "$OVL" "runs/femu/${TAG}_qlc.csv"
# No replay.bin in the seed: the binaries are streamed in per replay, and the
# gsm8k ones are ~100 MB each.
(cd exp/gating_nand/femu && "$PYTHON" make_seed.py -o "$SEED" --tag "${TAG^^}" \
    --instance-id "femu-$TAG" --ssh-key "$SSH_PUBKEY" \
    --file /usr/local/bin/replay_v1=$ROOT/build/guest/replay_v1:0755 \
    --file /usr/local/bin/class_confusion=$ROOT/build/guest/class_confusion:0755 \
    --file /usr/local/bin/guest_replay.sh=$ROOT/exp/moe_bcq/femu_run/guest_replay.sh:0755 \
    --run "/usr/local/bin/guest_replay.sh > /dev/ttyS0 2>&1") >/dev/null || exit 1
"$QEMU_IMG" create -f qcow2 -F qcow2 -b jammy-server-cloudimg-amd64.img "$OVL" 32G >/dev/null

sed -e "s|^FEMU_QLC_STATS_PATH=.*|FEMU_QLC_STATS_PATH=/data/${TAG}_qlc.csv|" \
    -e "s|^FEMU_IMAGE_NAME=.*|FEMU_IMAGE_NAME=$(basename "$OVL")|" \
    -e "s|^FEMU_CONTAINER_NAME=.*|FEMU_CONTAINER_NAME=femu-$TAG|" \
    -e "s|FEMU_EXTRA_DRIVES=.*|FEMU_EXTRA_DRIVES='file=/guest/$(basename "$SEED"),if=virtio,format=raw,readonly=on;file=$IMG,if=virtio,format=raw,readonly=on'|" \
    runs/femu/run01.env > "runs/femu/${TAG}.env"

set -a; . "runs/femu/${TAG}.env"; set +a
if [ -z "${FEMU_SOURCE_DIR:-}" ]; then
    # "$ROOT/.." is this harness living inside the FEMU checkout itself, which
    # is how the published repository is laid out; the _deps forms are the
    # original layout, where the harness was the outer project.
    for c in "$ROOT/_deps/FEMU-MoE" "$ROOT/FEMU-MoE" "$ROOT/.."; do
        [ -f "$c/compose.yaml" ] && { FEMU_SOURCE_DIR=$c; break; }
    done
fi
[ -n "${FEMU_SOURCE_DIR:-}" ] || { echo "  no FEMU checkout with compose.yaml"; exit 1; }
export FEMU_SOURCE_DIR
nohup bash scripts/femu_compose.sh up femu > "runs/femu/${TAG}.console.log" 2>&1 &
until grep -qa "ALL DONE\|FATAL" "runs/femu/${TAG}.console.log" 2>/dev/null; do sleep 10; done
grep -qa FATAL "runs/femu/${TAG}.console.log" && { echo "  FATAL during fill"; exit 1; }
grep -a "fill done\|read-back OK" "runs/femu/${TAG}.console.log" | tr -d '\r' | sed 's/^femu[^|]*| /  /'

IMAGE_PAGES=$PAGES bash exp/moe_bcq/femu_run/drive_multi.sh "$TAG" "$SPEC"; rc=$?
export FEMU_CONTAINER_NAME=femu-$TAG
bash scripts/femu_compose.sh down >/dev/null 2>&1
echo "  device torn down (rc=$rc)"
exit $rc
