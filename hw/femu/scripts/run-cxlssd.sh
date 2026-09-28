#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
set -euo pipefail

# Run from a build directory, or set QEMU to the built executable.
QEMU=${QEMU:-./qemu-system-x86_64}
CXL_SIZE=${CXL_SIZE:-256M}
CACHE_PAGES=${CACHE_PAGES:-1024}
CACHE_WAYS=${CACHE_WAYS:-16}
CACHE_POLICY=${CACHE_POLICY:-fifo}
DER=${DER:-on}
CXL_OPTS="femu-cxl-ssd,id=cxlssd,bus=cxl-rp0,volatile-memdev=cxlmem"
CXL_OPTS+=",cache-pages=$CACHE_PAGES,cache-ways=$CACHE_WAYS"
CXL_OPTS+=",cache-policy=$CACHE_POLICY,der=$DER"

exec "$QEMU" \
    -machine q35,cxl=on -accel kvm -cpu host -smp 4 -m 4G \
    -object "memory-backend-ram,id=cxlmem,size=$CXL_SIZE" \
    -device pxb-cxl,id=cxl.0,bus=pcie.0,bus_nr=52 \
    -device cxl-rp,id=cxl-rp0,bus=cxl.0,chassis=0,slot=0 \
    -device "$CXL_OPTS" \
    -M "cxl-fmw.0.targets.0=cxl.0,cxl-fmw.0.size=$CXL_SIZE" \
    -nographic "$@"
