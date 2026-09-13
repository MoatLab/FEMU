#!/usr/bin/env bash
# The README's build-and-run path, done in a container.
#
# The README tells you to install dependencies with sudo, compile into
# build-femu/, and launch with run-blackbox.sh. Step one does not work on the
# host this fork is measured on -- there is no passwordless sudo -- and step
# three would not either: run-blackbox.sh launches QEMU under sudo, and FEMU
# pins its memory backend, which needs RLIMIT_MEMLOCK raised. This host allows
# 64 MiB against a 64 GiB device.
#
# So the same three steps happen in a container, which gets IPC_LOCK and an
# unlimited memlock without the host granting root to anyone:
#
#     README                      here
#     sudo ./pkgdep.sh            docker/Dockerfile, builder stage
#     ./femu-compile.sh           docker/Dockerfile, builder stage
#     ./run-blackbox.sh           docker/femu-run bbssd, via compose
#
# The device is the same either way. Geometry, cell type and the energy
# coefficients come from compose.yaml, whose defaults are the configuration the
# measurements in this repository were taken on.
set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/.." && pwd)

# Where guest disks live. The README has you build a VM image by hand and keep
# it beside the build; this is that directory.
IMAGES=${FEMU_GUEST_DIR:-$HOME/images}
# What the container sees as /data: the counter CSV and the console log land here.
DATA=${FEMU_DATA_DIR:-$REPO/docker-data}
BASE=${FEMU_BASE_IMAGE:-jammy-server-cloudimg-amd64.img}
TAG=${FEMU_INSTANCE:-femu}
SSH_PORT=${FEMU_SSH_PORT:-2222}
SSH_PUBKEY=${FEMU_SSH_PUBKEY:-$HOME/.ssh/id_rsa.pub}

compose() {
    FEMU_GUEST_DIR=$IMAGES FEMU_DATA_DIR=$DATA \
    FEMU_CONTAINER_NAME=femu-$TAG FEMU_SSH_PORT=$SSH_PORT \
    FEMU_IMAGE_NAME=femu-root-$TAG.qcow2 \
    FEMU_QLC_STATS_PATH=/data/${TAG}_qlc.csv \
    FEMU_EXTRA_DRIVES="${FEMU_EXTRA_DRIVES:-file=/guest/seed-$TAG.iso,if=virtio,format=raw,readonly=on}" \
        docker compose -f "$REPO/compose.yaml" "$@"
}

usage() {
    cat <<'EOF'
Usage: femu-docker.sh COMMAND

  build     Build the FEMU image. Dependencies and compile both happen inside,
            so nothing is installed on the host.
  verify    Ask the built binary whether the femu device registered.
  image     Create this instance's guest disk and cloud-init seed. The overlay
            is copy-on-write over the base image, which is never written.
  run       Start the device and boot the guest. Ctrl-C detaches; the container
            keeps running.
  ssh       Open a shell in the guest.
  stop      Stop the container and remove it.
  status    What is running, and the device this instance would get.

Environment:
  FEMU_INSTANCE      name for this instance's disk, seed and container (femu)
  FEMU_GUEST_DIR     where guest disks live ($HOME/images)
  FEMU_DATA_DIR      what the container sees as /data (<repo>/docker-data)
  FEMU_BASE_IMAGE    base image the overlay is cut from
                     (jammy-server-cloudimg-amd64.img)
  FEMU_SSH_PORT      host port forwarded to the guest's sshd (2222)
  FEMU_SSH_PUBKEY    key authorised in the guest (~/.ssh/id_rsa.pub)

Running an actual measurement is a different entry point: it needs a payload
image, a compiled trace and the placement checks. See moe-harness/README.md.
EOF
}

case "${1:-help}" in
help|-h|--help) usage ;;

build)
    echo "== building (dependencies and compile are inside the image) =="
    compose build femu
    ;;

verify)
    echo "== does the femu device register? =="
    compose run --rm --entrypoint qemu-system-x86_64 femu -device femu,help 2>&1 |
        head -20
    ;;

image)
    mkdir -p "$IMAGES" "$DATA"
    [ -f "$IMAGES/$BASE" ] || {
        echo "no base image at $IMAGES/$BASE"
        echo "download an Ubuntu 22.04 cloud image there, or set FEMU_BASE_IMAGE"
        exit 1
    }
    [ -f "$SSH_PUBKEY" ] || { echo "no ssh public key at $SSH_PUBKEY"; exit 1; }
    ovl=$IMAGES/femu-root-$TAG.qcow2
    seed=$IMAGES/seed-$TAG.iso
    # Never write the base image: a run gets its own overlay, so a broken guest
    # is one file to delete rather than a re-download.
    [ -e "$ovl" ] && { echo "already exists: $ovl (delete it to start over)"; exit 1; }
    qemu-img create -f qcow2 -F qcow2 -b "$BASE" "$ovl" 32G >/dev/null
    echo "  overlay $ovl"
    # The cloud image ships no password, so without a seed carrying a key there
    # is no way in. No --run: this seed only authorises the key.
    for c in python3 /usr/bin/python3 python3.8; do
        command -v "$c" >/dev/null 2>&1 || continue
        "$c" -c 'import pycdlib' 2>/dev/null && { PY=$c; break; }
    done
    [ -n "${PY:-}" ] || { echo "no python3 with pycdlib; pip install --user pycdlib"; exit 1; }
    (cd "$REPO/moe-harness/exp/gating_nand/femu" &&
        "$PY" make_seed.py -o "$seed" --tag "${TAG^^}" \
            --instance-id "femu-$TAG" --ssh-key "$SSH_PUBKEY") >/dev/null || exit 1
    echo "  seed    $seed"
    ;;

run)
    [ -f "$IMAGES/femu-root-$TAG.qcow2" ] || {
        echo "no guest disk for instance '$TAG'; run: $0 image"; exit 1; }
    mkdir -p "$DATA"
    echo "== starting femu-$TAG (Ctrl-C detaches, container keeps running) =="
    compose up femu
    ;;

ssh)
    exec ssh -p "$SSH_PORT" -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null femu@127.0.0.1 "${@:2}"
    ;;

stop)
    compose down
    ;;

status)
    echo "== containers =="
    docker ps --filter "name=femu-$TAG" --format '  {{.Names}}  {{.Status}}' || true
    echo "== the device this instance gets =="
    compose run --rm --entrypoint sh femu -c 'echo "  \
cell=$FEMU_NAND_CELL_TYPE size=${FEMU_SSD_SIZE_MB}MB \
${FEMU_CHANNELS}ch x ${FEMU_LUNS_PER_CHANNEL}LUN \
${FEMU_PAGES_PER_BLOCK}pg/blk ${FEMU_BLOCKS_PER_PLANE}blk/pl \
opts=$FEMU_EXTRA_DEVICE_OPTS"' 2>/dev/null | tail -1
    ;;

*)
    echo "unknown command: $1"; echo; usage; exit 1 ;;
esac
