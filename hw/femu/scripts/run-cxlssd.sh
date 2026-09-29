#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
set -euo pipefail
#
# Launch QEMU with one femu-cxl-ssd below a pxb-cxl host bridge and one
# cxl-rp root port, in a single-target CXL window. Arguments after the
# script name are passed to QEMU. Settings come from the environment:
#
#   QEMU               QEMU executable (./qemu-system-x86_64)
#   CXL_SIZE           media size, integer with M or G (256M)
#   CACHE_PAGES        cache-pages (a size/20 MiB cache: size_mb / 20 * 256)
#   CACHE_WAYS         cache-ways (1); "full" means CACHE_PAGES
#   BLOCKS_PER_PLANE   blocks-per-plane (768 for 48G, 1536 for 96G, else 0,
#                      which lets FEMU size it)
#   CACHE_POLICY       cache-policy (fifo)
#   DER                der (off)
#   CYLON_KERNEL_ACK   cylon-kernel-ack (off)
#   PREFETCH_DEGREE    prefetch-degree (0)
#   PREFETCH_STRIDE    prefetch-stride (1)
#   CHANNELS           channels (8)
#   LUNS_PER_CHANNEL   luns-per-channel (8)
#   PAGES_PER_BLOCK    pages-per-block (256)
#   READ_NS            read-ns (40000)
#   PROGRAM_NS         program-ns (200000)
#   ERASE_NS           erase-ns (2000000)
#   CHANNEL_NS         channel-ns (0)
#   GC_THRESHOLD       gc-threshold (75)
#   GC_THRESHOLD_HIGH  gc-threshold-high (95)
#   FTL                ftl (on)
#   LSA_CONTROL        lsa-control (on: Cylon's scripts use Get LSA
#                      commands 1 and 5)
#   CYLON_FIRST_TOUCH_PROGRAM  cylon-first-touch-program (off)
#   CYLON_FREE_WRITEBACK       cylon-free-writeback (off)
#   LOG_DIR            log-dir (.)
#   LOG_LIMIT          log-limit (64M)
#   TRACEFS_DIR        tracefs-dir (unset: not passed)
#   CXL_BACKEND        memory backend type and options (memory-backend-ram)
#   ACCEL              accelerator (kvm)
#   CPU                CPU model (host)
#   CPUS               vCPUs (4)
#   RAM                guest RAM (4G)
#   DRY_RUN            1 prints the command instead of running it (0)
#
# These defaults follow Cylon's launch script and differ from the device's
# own property defaults: cache-ways 1 instead of 16, 8x8 channels and LUNs
# instead of 4x4, and lsa-control on instead of off.

# Run from a build directory, or set QEMU to the built executable.
QEMU=${QEMU:-./qemu-system-x86_64}
CXL_SIZE=${CXL_SIZE:-256M}
if [[ $CXL_SIZE =~ ^([0-9]+)([MG])$ ]]; then
    size_mb=${BASH_REMATCH[1]}
    if [[ ${BASH_REMATCH[2]} == G ]]; then
        size_mb=$((size_mb * 1024))
    fi
else
    echo 'CXL_SIZE must be an integer followed by M or G' >&2
    exit 1
fi
# Match Cylon's launch script: a buffer of size/20 MiB, direct mapped.
CACHE_PAGES=${CACHE_PAGES:-$(((size_mb / 20) * 256))}
CACHE_WAYS=${CACHE_WAYS:-1}
if [[ $CACHE_WAYS == full ]]; then
    CACHE_WAYS=$CACHE_PAGES
fi
# Cylon's 48/96 GiB presets use no over-provisioning; 0 lets FEMU size it.
case $size_mb in
49152) default_blocks=768 ;;
98304) default_blocks=1536 ;;
*) default_blocks=0 ;;
esac
BLOCKS_PER_PLANE=${BLOCKS_PER_PLANE:-$default_blocks}
CACHE_POLICY=${CACHE_POLICY:-fifo}
DER=${DER:-off}
LOG_DIR=${LOG_DIR:-.}
LOG_LIMIT=${LOG_LIMIT:-64M}
CXL_BACKEND=${CXL_BACKEND:-memory-backend-ram}
CXL_OPTS="femu-cxl-ssd,id=cxlssd,bus=cxl-rp0,volatile-memdev=cxlmem"
CXL_OPTS+=",cache-pages=$CACHE_PAGES,cache-ways=$CACHE_WAYS"
CXL_OPTS+=",cache-policy=$CACHE_POLICY,der=$DER"
CXL_OPTS+=",cylon-kernel-ack=${CYLON_KERNEL_ACK:-off}"
CXL_OPTS+=",prefetch-degree=${PREFETCH_DEGREE:-0}"
CXL_OPTS+=",prefetch-stride=${PREFETCH_STRIDE:-1}"
CXL_OPTS+=",channels=${CHANNELS:-8},luns-per-channel=${LUNS_PER_CHANNEL:-8}"
CXL_OPTS+=",blocks-per-plane=$BLOCKS_PER_PLANE"
CXL_OPTS+=",pages-per-block=${PAGES_PER_BLOCK:-256}"
CXL_OPTS+=",read-ns=${READ_NS:-40000},program-ns=${PROGRAM_NS:-200000}"
CXL_OPTS+=",erase-ns=${ERASE_NS:-2000000},channel-ns=${CHANNEL_NS:-0}"
CXL_OPTS+=",gc-threshold=${GC_THRESHOLD:-75}"
CXL_OPTS+=",gc-threshold-high=${GC_THRESHOLD_HIGH:-95}"
CXL_OPTS+=",ftl=${FTL:-on},lsa-control=${LSA_CONTROL:-on}"
CXL_OPTS+=",cylon-first-touch-program=${CYLON_FIRST_TOUCH_PROGRAM:-off}"
CXL_OPTS+=",cylon-free-writeback=${CYLON_FREE_WRITEBACK:-off}"
CXL_OPTS+=",log-dir=${LOG_DIR//,/,,},log-limit=$LOG_LIMIT"
if [[ -n ${TRACEFS_DIR:-} ]]; then
    CXL_OPTS+=",tracefs-dir=${TRACEFS_DIR//,/,,}"
fi

args=(
    -machine q35,cxl=on,smm=off -accel "${ACCEL:-kvm}"
    -cpu "${CPU:-host}" -smp "${CPUS:-4}" -m "${RAM:-4G}"
    -object "$CXL_BACKEND,id=cxlmem,size=$CXL_SIZE"
    -device pxb-cxl,id=cxl.0,bus=pcie.0,bus_nr=52
    -device cxl-rp,id=cxl-rp0,bus=cxl.0,chassis=0,slot=0
    -device "$CXL_OPTS"
    -M "cxl-fmw.0.targets.0=cxl.0,cxl-fmw.0.size=$CXL_SIZE"
    -nographic
)
if [[ ${DRY_RUN:-0} == 1 ]]; then
    printf '%q ' "$QEMU" "${args[@]}" "$@"
    printf '\n'
else
    exec "$QEMU" "${args[@]}" "$@"
fi
