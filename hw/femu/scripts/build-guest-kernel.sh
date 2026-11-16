#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Build the small Linux kernel of the FEMU guest boot test.
#
#   build-guest-kernel.sh OUTDIR
#
# Inputs are pinned: the kernel.org tarball (version and SHA-256 below)
# and hw/femu/tests/functional/guest.config. The result is
# OUTDIR/bzImage. Every option in guest.config must read "=y" after
# olddefconfig, or the build fails with the option name.
set -euo pipefail

KVER=6.12.117
KSHA=74e99aa5e60e242e0a165fed8cb2ea0d054bf7a401f01861d403d75733456613
URL=https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$KVER.tar.xz

out=${1:?usage: build-guest-kernel.sh OUTDIR}
here=$(cd "$(dirname "$0")" && pwd)
frag=$here/../tests/functional/guest.config
mkdir -p "$out"
out=$(cd "$out" && pwd)
tar=$out/linux-$KVER.tar.xz
src=$out/linux-$KVER

# objtool needs libelf; flex, bison and bc build kconfig and the kernel
if [[ ! -f /usr/include/gelf.h ]]; then
    echo "build-guest-kernel: install libelf-dev" >&2
    exit 1
fi
for t in flex bison bc; do
    if ! command -v "$t" >/dev/null; then
        echo "build-guest-kernel: install $t" >&2
        exit 1
    fi
done
if [[ ! -f $tar ]]; then
    curl -fsSL --retry 3 -o "$tar.part" "$URL"
    mv "$tar.part" "$tar"
fi
echo "$KSHA  $tar" | sha256sum -c --quiet || {
    echo "build-guest-kernel: SHA-256 of $tar differs" >&2
    exit 1
}
rm -rf "$src"
tar -C "$out" -xf "$tar"
# fixed build stamps give the same bzImage for the same inputs
export KBUILD_BUILD_TIMESTAMP="1970-01-01 00:00:00 UTC"
export KBUILD_BUILD_USER=femu KBUILD_BUILD_HOST=femu KBUILD_BUILD_VERSION=1
mk=(make -C "$src" ARCH=x86_64 -j"$(nproc)")
"${mk[@]}" tinyconfig >/dev/null
"$src/scripts/kconfig/merge_config.sh" -m -O "$src" "$src/.config" "$frag" \
    >/dev/null
"${mk[@]}" olddefconfig >/dev/null
missing=0
while read -r line; do
    [[ $line == CONFIG_* ]] || continue
    if ! grep -qx "$line" "$src/.config"; then
        echo "build-guest-kernel: $line did not stay set" >&2
        missing=1
    fi
done <"$frag"
((missing == 0)) || exit 1
"${mk[@]}" bzImage >"$out/kernel-build.log" 2>&1 || {
    tail -20 "$out/kernel-build.log" >&2
    exit 1
}
cp "$src/arch/x86/boot/bzImage" "$out/bzImage"
sha256sum "$out/bzImage"
