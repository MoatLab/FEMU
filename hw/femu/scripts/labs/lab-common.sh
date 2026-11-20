# SPDX-License-Identifier: GPL-2.0-or-later
# shellcheck shell=bash
#
# Shared helpers of the FEMU teaching labs (hw/femu/docs/labs/). The lab
# scripts source this file from their own directory; do not run it.
#
# Environment:
#   LAB_CTRL  controller node (default /dev/nvme0)
#   LAB_NS    block node of namespace 1 (default /dev/nvme0n1)
#   LAB_DIR   where the fio JSON files go (default ./lab-out)

LAB_CTRL=${LAB_CTRL:-/dev/nvme0}
LAB_NS=${LAB_NS:-/dev/nvme0n1}
LAB_DIR=${LAB_DIR:-./lab-out}

# Field names of log page C0h and their byte offsets
# (hw/femu/docs/reference/log-pages-and-counters.md).
LAB_FIELDS=(host:8 gc:16 nand:24 forced_waits:192 forced_passes:200
        pad:264 tp_prog:280 tp_read:288)

lab_die() {
    echo "LAB-ERROR $*" >&2
    exit 2
}

lab_start() {
    if ((EUID != 0)); then
        lab_die "run as root: sudo bash $0"
    fi
    local tool
    for tool in nvme fio od awk python3; do
        command -v "$tool" >/dev/null || lab_die "$tool is not installed"
    done
    [[ -b $LAB_NS ]] || lab_die "$LAB_NS is not a block device"
    mkdir -p "$LAB_DIR"
}

# Print "name value" for each C0h field.
lab_c0() {
    local raw f
    local -a v
    raw=$(nvme get-log "$LAB_CTRL" --log-id=0xc0 --log-len=512 -b |
        od -An -v -t u8 -w8) || lab_die "cannot read log page C0h"
    read -r -d '' -a v <<<"$raw" || true
    ((${#v[@]} == 64)) || lab_die "log page C0h gave ${#v[@]} words, not 64"
    for f in "${LAB_FIELDS[@]}"; do
        echo "${f%%:*} ${v[${f##*:} / 8]}"
    done
}

lab_snap() {
    lab_c0 >"$1"
}

# Print "name=after-before" for each field, then the WAF of the interval:
# (nand + gc + tp_prog + pad) / host, as the C0h WAF counts it.
lab_diff() {
    awk 'NR == FNR { b[$1] = $2; next }
         { d[$1] = $2 - b[$1]; printf "%s=%d ", $1, d[$1] }
         END {
        if (d["host"] > 0)
            printf "waf=%.3f", (d["nand"] + d["gc"] + d["tp_prog"] + d["pad"]) / d["host"]
        else
            printf "waf=none"
         }' "$1" "$2"
}

# Value of one field in a lab_diff line.
lab_field() {
    local line=$1 key=$2
    sed -n "s/.*\b${key}=\([0-9.]*\).*/\1/p" <<<"$line"
}

# Make GC and the NAND operations take no time (vendor command 0xEF, codes
# 2 and 4). The page counts do not change; the runs take seconds.
# Restart QEMU to get the configured times back.
lab_time_off() {
    nvme admin-passthru "$LAB_CTRL" --opcode=0xef --cdw10=2 >/dev/null ||
        lab_die "vendor command 0xEF code 2 failed"
    nvme admin-passthru "$LAB_CTRL" --opcode=0xef --cdw10=4 >/dev/null ||
        lab_die "vendor command 0xEF code 4 failed"
}

# Run fio with JSON output to $LAB_DIR/$1.json; the other arguments go to
# fio. Exit on a fio error.
lab_fio() {
    local name=$1
    shift
    fio --output-format=json --output="$LAB_DIR/$name.json" "$@" ||
        lab_die "fio step $name failed"
}

# Print one value of a fio JSON file, summed over its jobs:
#   write_bytes, read_bytes, read_clat_mean_us, read_p50_us, read_p99_us
lab_fio_get() {
    python3 -I - "$1" "$2" <<'EOF'
import json, sys
jobs = json.load(open(sys.argv[1]))["jobs"]
key = sys.argv[2]
if key in ("write_bytes", "read_bytes"):
    print(sum(j[key.split("_")[0]]["io_bytes"] for j in jobs))
else:
    r = jobs[0]["read"]["clat_ns"]
    if key == "read_clat_mean_us":
        print("%.1f" % (r["mean"] / 1000))
    else:
        pct = {"read_p50_us": "50.000000", "read_p99_us": "99.000000"}[key]
        print("%.1f" % (r["percentile"][pct] / 1000))
EOF
}

# Check that the host page count matches the bytes fio wrote, within 10%
# either way, and that fio wrote something; print "check=ok" or
# "check=FAIL". It shows that the run reached the measured namespace. It
# does not show that a mechanism (GC, DFTL, placement) took part.
lab_check_host() {
    local host_pages=$1 bytes=$2
    local want=$((bytes / 4096))
    if ((want > 0 && host_pages * 10 >= want * 9 &&
        host_pages * 10 <= want * 11)); then
        echo "check=ok"
    else
        echo "check=FAIL"
    fi
}
