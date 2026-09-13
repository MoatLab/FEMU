#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src="${repo_root}/exp/gating_nand/femu/replay.c"
out_dir="${repo_root}/build/guest"

mkdir -p "${out_dir}"

if ! pkg-config --exists liburing; then
    echo "build_replay: liburing development files are missing" >&2
    echo "install liburing-dev, or activate the conda environment containing liburing" >&2
    exit 1
fi

read -r -a uring_flags <<< "$(pkg-config --cflags --libs liburing)"
cc -O2 -Wall -Wextra "${src}" -o "${out_dir}/replay" "${uring_flags[@]}"

echo "build_replay: wrote ${out_dir}/replay"
