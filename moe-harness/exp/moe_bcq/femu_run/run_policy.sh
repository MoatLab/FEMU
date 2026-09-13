#!/bin/bash
# One placement policy end to end: fresh device, 256 KiB fill, class check, replay.
#
# Each policy needs its own device. Refilling an existing one would land every
# page on a fresh PPA (out-of-place update), so the second fill would not be the
# layout the image describes.
set -uo pipefail
POL=${1:?usage: run_policy.sh POLICY}
# Same reason as drive_run.sh: the path is where the script is, not a constant.
HARNESS=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
ROOT=${FEMU_PROJECT_ROOT:-$HARNESS}
# Guest images and the key authorised inside them are per-machine.
IMAGES=${FEMU_GUEST_DIR:-$HOME/images}
SSH_PUBKEY=${FEMU_SSH_PUBKEY:-$HOME/.ssh/id_rsa.pub}
# The patched build ships one; a system qemu-img works too and is preferred when
# present, since it does not depend on the checkout having been built yet.
QEMU_IMG=${QEMU_IMG:-$(command -v qemu-img || echo "$HARNESS/../build/qemu-img")}
cd "$ROOT"

# One knob, not two. The run tag defaulted to something different from the
# layout prefix once, and the results then carried a name that did not say which
# layout produced them.
TAG=${TAG_PREFIX:-${LAYOUT_PREFIX:-pol}}_$POL
IMG=/data/images/${IMG_PREFIX:-qwen_C}_$POL.img
SEED=$IMAGES/seed-$TAG.iso
OVL=$IMAGES/femu-root-$TAG.qcow2
LAYOUT=${LAYOUT_PREFIX:-qlc}_epm_aif_2ch4lun_$POL
BIN=exp/moe_bcq/femu_handoff/packages/qwen_C/layouts/$LAYOUT/replay_qd32.bin

echo "=== $POL ==="
rm -f "$SEED" "$OVL" "runs/femu/${TAG}_qlc.csv"
(cd exp/gating_nand/femu && python3 make_seed.py -o "$SEED" --tag "${TAG^^}" \
    --instance-id "femu-$TAG" --ssh-key "$SSH_PUBKEY" \
    --file /usr/local/bin/replay_v1=$ROOT/build/guest/replay_v1:0755 \
    --file /usr/local/bin/class_confusion=$ROOT/build/guest/class_confusion:0755 \
    --file /root/replay.bin=$ROOT/$BIN \
    --file /usr/local/bin/guest_replay.sh=$HARNESS/exp/moe_bcq/femu_run/guest_replay.sh:0755 \
    --run "/usr/local/bin/guest_replay.sh > /dev/ttyS0 2>&1") >/dev/null || exit 1
"$QEMU_IMG" create -f qcow2 -F qcow2 -b jammy-server-cloudimg-amd64.img "$OVL" 32G >/dev/null

sed -e "s|^FEMU_QLC_STATS_PATH=.*|FEMU_QLC_STATS_PATH=/data/${TAG}_qlc.csv|" \
    -e "s|^FEMU_IMAGE_NAME=.*|FEMU_IMAGE_NAME=$(basename "$OVL")|" \
    -e "s|^FEMU_CONTAINER_NAME=.*|FEMU_CONTAINER_NAME=femu-$TAG|" \
    -e "s|FEMU_EXTRA_DRIVES=.*|FEMU_EXTRA_DRIVES='file=/guest/$(basename "$SEED"),if=virtio,format=raw,readonly=on;file=$IMG,if=virtio,format=raw,readonly=on'|" \
    runs/femu/run01.env > "runs/femu/${TAG}.env"

set -a; . "runs/femu/${TAG}.env"; set +a
# setup_femu.sh puts the checkout under _deps; a working tree kept beside it is
# the older layout. Prefer whichever actually has the compose file rather than
# naming one, or the run stalls waiting for a container that was never started.
if [ -z "${FEMU_SOURCE_DIR:-}" ]; then
    for c in "$HARNESS/.." "$ROOT/_deps/FEMU-MoE" "$ROOT/FEMU-MoE"; do
        [ -f "$c/compose.yaml" ] && { FEMU_SOURCE_DIR=$c; break; }
    done
fi
[ -n "${FEMU_SOURCE_DIR:-}" ] || { echo "  no FEMU checkout with compose.yaml; run scripts/setup_femu.sh"; exit 1; }
export FEMU_SOURCE_DIR
nohup bash "$HARNESS/scripts/femu_compose.sh" up femu > "runs/femu/${TAG}.console.log" 2>&1 &
until grep -qa "ALL DONE\|FATAL" "runs/femu/${TAG}.console.log" 2>/dev/null; do sleep 10; done
grep -qa FATAL "runs/femu/${TAG}.console.log" && { echo "  FATAL during fill"; exit 1; }
grep -a "fill done\|read-back OK" "runs/femu/${TAG}.console.log" | tr -d '\r' | sed 's/^femu[^|]*| /  /'

bash exp/moe_bcq/femu_run/drive_run.sh "$TAG" || exit 1
export FEMU_CONTAINER_NAME=femu-$TAG
bash "$HARNESS/scripts/femu_compose.sh" down >/dev/null 2>&1
echo "  device torn down"
