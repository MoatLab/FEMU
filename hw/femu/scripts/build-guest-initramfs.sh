#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Build the initramfs of the FEMU guest boot test.
#
#   build-guest-initramfs.sh OUTDIR
#
# It holds a static busybox (Ubuntu package busybox-static), the static
# femu-guest-check helper and hw/femu/tests/functional/init. It is
# rebuilt on each run, so the cache never serves an old check.
set -euo pipefail

out=${1:?usage: build-guest-initramfs.sh OUTDIR}
here=$(cd "$(dirname "$0")" && pwd)
fdir=$here/../tests/functional
bb=${BUSYBOX:-/usr/bin/busybox}
mkdir -p "$out"
out=$(cd "$out" && pwd)
root=$out/initramfs-root
rm -rf "$root"
mkdir -p "$root/bin" "$root/proc" "$root/sys" "$root/dev"

if ! file -L "$bb" | grep -q 'statically linked'; then
    echo "build-guest-initramfs: $bb is not a static busybox" >&2
    exit 1
fi
cp "$bb" "$root/bin/busybox"
ln -s busybox "$root/bin/sh"
gcc -static -O2 -Wall -Wextra -Werror -pthread \
    -o "$root/bin/femu-guest-check" "$fdir/femu-guest-check.c"
cp "$fdir/init" "$root/init"
chmod 755 "$root/init"
(cd "$root" && find . | LC_ALL=C sort | cpio -o -H newc -R 0:0 --quiet) |
    gzip -9n >"$out/initramfs.cpio.gz"
dpkg-query -W busybox-static 2>/dev/null || true
sha256sum "$root/bin/busybox" "$root/bin/femu-guest-check" "$root/init" \
    "$out/initramfs.cpio.gz"
