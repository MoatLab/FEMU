#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Workload recipe: RocksDB db_bench on a FEMU BlackBox namespace.
# RocksDB keeps its data in an LSM tree: a write goes to a log and a
# memtable, a flush writes a sorted file, and compaction rewrites files
# into lower levels. The recipe runs three db_bench phases on an ext4
# file system on the namespace and reads the FEMU counters around each.
#
#   sudo bash recipe-rocksdb-guest.sh --yes [NAMESPACE]
#
# NAMESPACE is a block device name such as nvme0n1 (the default). The
# script makes an ext4 file system on it, so --yes is necessary. It
# installs packages with apt-get and builds db_bench from a RocksDB tag,
# so the guest needs network access. recipe-guest-lib.sh must be next to
# this script.
#
#   fill       fillrandom: ROCKSDB_NUM random keys into a new database
#   overwrite  overwrite: ROCKSDB_NUM random writes over the database
#   mixed      readrandomwriterandom: 90% reads, 10% writes, a fixed
#              count of operations on ROCKSDB_THREADS threads
#   counters   log page C0h and the block layer, around each phase
#
# Each phase ends with a memtable flush and a wait for compaction, so
# the statistics and the counters cover the same finished work.
#
# Pass criterion:
#   - each db_bench phase exits 0 inside its time limit, prints its
#     result line with the planned operation count, prints no
#     "get error:" line, and prints its statistics;
#   - fill and overwrite: each operation writes a key, and the block
#     layer writes and the C0h host pages each count at least 90% of
#     the flush and compaction bytes of the phase;
#   - overwrite: compaction wrote bytes;
#   - mixed: 5% to 15% of the operations write a key, the block layer
#     reads at least 1 KiB for each key read, and the C0h plane read
#     count grows.
# PASS means that the recipe ran and the counters moved. It is not a
# statement on performance.
#
# Environment:
#   ROCKSDB_REPO       git URL (default
#                      https://github.com/facebook/rocksdb.git)
#   ROCKSDB_REF        tag, branch or commit (default v9.10.0)
#   ROCKSDB_PREFIX     directory of the build (default /opt/femu-rocksdb);
#                      a build of the same ref is used again
#   ROCKSDB_JOBS       build jobs (default: the number of CPUs)
#   ROCKSDB_NUM        keys of fill and writes of overwrite (default
#                      400000)
#   ROCKSDB_VALUE_SIZE value bytes (default 1000); keys have 16 bytes
#   ROCKSDB_MIXED_READS  operations of each thread in the mixed phase
#                      (default 150000)
#   ROCKSDB_THREADS    threads of the mixed phase (default 2)
#   ROCKSDB_SEED       seed of the key generator (default 42)
#   ROCKSDB_TIMEOUT    seconds for each db_bench phase (default 1800)
#   ROCKSDB_INSTALL_TIMEOUT  seconds for all install steps together
#                      (default 3600)
#   ROCKSDB_CONTROL    db-off-device: put the database in the scratch
#                      directory, so the device checks must fail. Use it
#                      only to show that the checks can fail.
#   RECIPE_CTRL        controller device (default /dev/nvmeX)
#   WORKDIR            parent of the new scratch directory (default /tmp)
#
# user_bytes is rocksdb.bytes.written: write batch bytes, 1032 for a
# 16-byte key and a 1000-byte value. payload_bytes is the keys written
# times the key and value size.
#
# Summary lines start with ROCKSDB_. The last line is
# ROCKSDB_RESULT=PASS|FAIL|SETUP-ERROR with key=value fields. The exit
# status is 0 when each check passed, 1 when one failed and 2 when the
# setup failed.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
readonly RECIPE=ROCKSDB
readonly PAGE=4096
readonly KEY_SIZE=16

# shellcheck source-path=SCRIPTDIR source=recipe-guest-lib.sh
source "$SCRIPT_DIR/recipe-guest-lib.sh" || {
    echo "ROCKSDB_RESULT=SETUP-ERROR reason=missing-recipe-guest-lib.sh"
    exit 2
}

# dbb_parse LOG PHASE BENCH: read one db_bench log. Print the line
# ROCKSDB_BENCH= and one ROCKSDB_LATENCY= line for each histogram, and
# set b_result (1 when the result line of BENCH is there), b_ops,
# b_micros, b_nops, b_user, b_flush, b_compact, b_wal, b_keys, b_kw and
# b_gerr. A value that the log does not hold is "-". b_gerr counts the
# "get error:" lines. The values come from these lines:
#
#   fillrandom   :       2.345 micros/op 426439 ops/sec 0.938 seconds
#                        400000 operations; ...   (one line)
#   rocksdb.flush.write.bytes COUNT : 123456
#   Microseconds per write:
#   Percentiles: P50: 2.10 P75: 3.03 P99: 8.95 P99.9: 14.91 P99.99: 24.23
dbb_parse() {
    local log=$1 phase=$2 bench=$3 line nlat=0 _

    b_result=0 b_ops=- b_micros=- b_nops=- b_user=- b_flush=-
    b_compact=- b_wal=- b_keys=- b_kw=- b_gerr=0
    while IFS= read -r line; do
        case $line in
        "V "*)
            read -r _ b_result b_ops b_micros b_nops b_user b_flush \
                b_compact b_wal b_keys b_kw b_gerr <<<"$line"
            ;;
        "L "*)
            echo "${RECIPE}_LATENCY=$phase ${line#L }"
            nlat=$((nlat + 1))
            ;;
        esac
    done < <(awk -v bench="$bench" '
        BEGIN {
            res = 0; ops = "-"; us = "-"; nops = "-"; gerr = 0
            split("bytes.written flush.write.bytes compact.write.bytes " \
                "wal.bytes number.keys.read number.keys.written", names, " ")
            for (i in names) val[names[i]] = "-"
        }
        $1 == bench && $2 == ":" && $4 == "micros/op" && $3 ~ /^[0-9.]+$/ &&
            $5 ~ /^[0-9]+$/ && $6 ~ /^ops\/sec/ {
            res = 1; us = $3; ops = $5
            for (i = 7; i <= NF; i++)
                if ($i == "operations;" && $(i - 1) ~ /^[0-9]+$/)
                    nops = $(i - 1)
        }
        /get error:/ { gerr++ }
        $1 ~ /^rocksdb\./ && $2 == "COUNT" && $3 == ":" && $4 ~ /^[0-9]+$/ {
            k = substr($1, 9)
            if (k in val) val[k] = $4
        }
        /^Microseconds per [a-z]+:$/ { op = $3; sub(/:$/, "", op) }
        $1 == "Percentiles:" && op != "" {
            out = "L op=" op
            for (i = 2; i < NF; i += 2) {
                p = $i; sub(/:$/, "", p)
                out = out " " tolower(p) "=" $(i + 1)
            }
            print out
            op = ""
        }
        END {
            print "V", res, ops, us, nops, val["bytes.written"],
                val["flush.write.bytes"], val["compact.write.bytes"],
                val["wal.bytes"], val["number.keys.read"],
                val["number.keys.written"], gerr
        }' "$log" 2>/dev/null)
    echo "${RECIPE}_BENCH=$phase ops_per_sec=$b_ops micros_per_op=$b_micros" \
        "operations=$b_nops user_bytes=$b_user flush_bytes=$b_flush" \
        "compact_bytes=$b_compact wal_bytes=$b_wal keys_read=$b_keys" \
        "keys_written=$b_kw get_errors=$b_gerr"
    ((nlat > 0)) || echo "${RECIPE}_NOTE=no-percentiles-$phase"
}

# phase_check PHASE KIND STATUS OPS: the checks of one phase. KIND is
# write (fill), rewrite (overwrite) or mixed, and OPS is the planned
# operation count. It reads the b_* values of dbb_parse and the d_*
# values of counter_change. The WAL bytes are not in the write checks:
# a log file can go away before the kernel writes it back, while RocksDB
# syncs each table file that a flush or a compaction writes.
phase_check() {
    local phase=$1 kind=$2 st=$3 want=$4 lsm n

    ((st == 0)) || check_fail "$phase-status-$st"
    ((b_result == 1)) || check_fail "$phase-no-result-line"
    [[ $b_nops == "$want" ]] || check_fail "$phase-op-count"
    ((b_gerr == 0)) || check_fail "$phase-get-errors"
    for n in "$b_user" "$b_flush" "$b_compact" "$b_kw"; do
        [[ $n =~ ^[0-9]+$ ]] || {
            check_fail "$phase-no-statistics"
            return 0
        }
    done
    if [[ $kind != mixed ]]; then
        ((b_kw == want)) || check_fail "$phase-keys-written"
        lsm=$((b_flush + b_compact))
        if ((lsm > 0)); then
            at_least_90 "$d_wr" "$lsm" || check_fail "$phase-block-writes"
            at_least_90 "$((d_host * PAGE))" "$lsm" ||
                check_fail "$phase-c0-host-pages"
        else
            check_fail "$phase-no-lsm-writes"
        fi
        if [[ $kind == rewrite ]] && ((b_compact == 0)); then
            check_fail "$phase-no-compaction"
        fi
        return 0
    fi
    # 10% of the operations write. The share check finds a phase that
    # ran with other options.
    if ((b_kw * 100 < want * 5 || b_kw * 100 > want * 15)); then
        check_fail "$phase-write-share"
    fi
    # About a third of the keys are absent and a bloom filter can answer
    # them with no read. The floor of 1 KiB for each key read is an
    # empirical check of this workload, not a bound.
    if [[ $b_keys =~ ^[0-9]+$ ]] && ((b_keys > 0)); then
        ((d_rd >= b_keys * 1024)) || check_fail "$phase-block-reads"
    else
        check_fail "$phase-no-reads"
    fi
    ((d_planes > 0)) || check_fail "$phase-no-nand-reads"
}

usage() {
    echo "usage: sudo bash $(basename "$0") --yes [NAMESPACE]" >&2
    setup_fail usage
}

[[ ${1:-} == --yes ]] || usage
shift
[[ $# -le 1 ]] || usage

repo=${ROCKSDB_REPO:-https://github.com/facebook/rocksdb.git}
ref=${ROCKSDB_REF:-v9.10.0}
prefix=${ROCKSDB_PREFIX:-/opt/femu-rocksdb}
jobs=${ROCKSDB_JOBS:-$(nproc)}
num=${ROCKSDB_NUM:-400000}
vsize=${ROCKSDB_VALUE_SIZE:-1000}
mixed_reads=${ROCKSDB_MIXED_READS:-150000}
threads=${ROCKSDB_THREADS:-2}
seed=${ROCKSDB_SEED:-42}
limit=${ROCKSDB_TIMEOUT:-1800}
install_limit=${ROCKSDB_INSTALL_TIMEOUT:-3600}
control=${ROCKSDB_CONTROL:-}
parent=${WORKDIR:-/tmp}

need_number jobs num vsize mixed_reads threads seed limit install_limit
case $control in
'' | db-off-device) ;;
*) setup_fail "bad-control-$control" ;;
esac
[[ $EUID -eq 0 ]] || setup_fail not-root
for tool in nvme lsblk timeout blockdev; do
    command -v "$tool" >/dev/null || setup_fail "no-$tool"
done

resolve_namespace "${1:-nvme0n1}"
size=$(blockdev --getsize64 "$ns_dev") || setup_fail no-size
# Obsolete files wait for compaction, and a compaction writes its output
# before it deletes its input, so the file system needs room.
raw=$((num * (KEY_SIZE + vsize)))
need=$((raw * 3))
((size >= need)) || setup_fail "namespace-below-$need"
workdir=$(mktemp -d "$parent/femu-rocksdb.XXXXXX") || setup_fail mktemp
recipe_workdir=$workdir
echo "ROCKSDB_DEVICE=$ns_name workdir=$workdir"

# One deadline covers all install steps, so a slow install cannot use
# the time of the workload.
install_end=$((SECONDS + install_limit))
install_left() {
    left=$((install_end - SECONDS))
    ((left > 0)) || setup_fail install-time-limit
}
export DEBIAN_FRONTEND=noninteractive
install_left
apt_step "$left" update || setup_fail apt-update
install_left
apt_step "$left" install -y build-essential git libgflags-dev \
    e2fsprogs || setup_fail apt-install

# The build goes to $prefix and is used again when the ref matches. A
# shallow fetch takes a tag, a branch or a full commit id.
stamp=$prefix/femu-rocksdb-ref
bin=$prefix/bin/db_bench
if [[ -x $bin && -r $stamp && $(<"$stamp") == "$ref "* ]]; then
    echo "ROCKSDB_BUILD=reused $prefix"
else
    src=$workdir/rocksdb
    git init -q "$src" || setup_fail mkdir-build
    install_left
    bounded "$left" git -C "$src" fetch -q --depth 1 "$repo" \
        "$ref" || setup_fail clone-rocksdb
    git -C "$src" -c advice.detachedHead=false checkout -q FETCH_HEAD ||
        setup_fail "checkout-$ref"
    commit=$(git -C "$src" rev-parse HEAD)
    # GCC 13 reports a false array-bounds error in RocksDB 9.10, so
    # warnings do not stop the build. PORTABLE=1 leaves out -march=native.
    install_left
    bounded "$left" make -C "$src" -j "$jobs" DEBUG_LEVEL=0 \
        PORTABLE=1 DISABLE_WARNING_AS_ERROR=1 db_bench \
        >"$workdir/build.log" 2>&1 || {
        tail -n 20 "$workdir/build.log"
        setup_fail build-rocksdb
    }
    install -D -m 755 "$src/db_bench" "$bin" || setup_fail install-rocksdb
    echo "$ref $commit" >"$stamp" || setup_fail install-rocksdb
    echo "ROCKSDB_BUILD=built $prefix"
fi

# A db_bench built with no gflags prints a note and exits 1, and a
# db_bench with no flush or waitforcompaction benchmark also exits 1.
# The smoke run uses the scratch directory and the options of the
# phases, so a failure here is not the device.
bounded 300 "$bin" --benchmarks=fillseq,flush,waitforcompaction \
    --num=1000 --compression_type=none "--db=$workdir/smoke" \
    >"$workdir/smoke.log" 2>&1 || {
    tail -n 5 "$workdir/smoke.log"
    setup_fail smoke-rocksdb
}
rm -rf "$workdir/smoke"
echo "ROCKSDB_REF=$(<"$stamp")"

mount_fresh "$workdir/mnt"
db=$recipe_mnt/db
if [[ $control == db-off-device ]]; then
    db=$workdir/db
fi

# The options that each phase shares. No compression, so the byte
# counts do not depend on the data. Small memtables and files give a
# small database several levels. Reads use O_DIRECT, so each read that
# the block cache does not hold goes to the device.
common=("--db=$db" "--num=$num" "--key_size=$KEY_SIZE"
    "--value_size=$vsize" --compression_type=none "--seed=$seed"
    --statistics=1 --histogram=1 --write_buffer_size=33554432
    --target_file_size_base=33554432 --max_bytes_for_level_base=134217728
    --max_background_jobs=2 --bloom_bits=10 --cache_size=8388608
    --use_direct_reads=1)
echo "ROCKSDB_OPTIONS=${common[*]}"

tot_user=0
tot_payload=0
tot_lsm=0
tot_host=0
tot_nand=0
tot_gc=0
# run_phase NAME BENCH KIND OPS ARGS...: one db_bench process between
# two counter samples. The flush and waitforcompaction benchmarks run
# before db_bench prints its statistics. A db_bench that fails is a
# check failure: the smoke run showed that the binary works.
run_phase() {
    local name=$1 bench=$2 kind=$3 ops=$4 rc=0
    shift 4

    drop_caches
    sample "s0_$name"
    bounded "$limit" "$bin" "${common[@]}" \
        "--benchmarks=$bench,flush,waitforcompaction" "$@" \
        >"$workdir/$name.log" 2>&1 || rc=$?
    ((rc == 0)) || tail -n 20 "$workdir/$name.log"
    flush_device
    sample "s1_$name"
    counter_change "$name" "s0_$name" "s1_$name"
    dbb_parse "$workdir/$name.log" "$name" "$bench"
    phase_check "$name" "$kind" "$rc" "$ops"
    [[ $b_user =~ ^[0-9]+$ ]] && tot_user=$((tot_user + b_user))
    [[ $b_kw =~ ^[0-9]+$ ]] &&
        tot_payload=$((tot_payload + b_kw * (KEY_SIZE + vsize)))
    [[ $b_flush =~ ^[0-9]+$ ]] && tot_lsm=$((tot_lsm + b_flush))
    [[ $b_compact =~ ^[0-9]+$ ]] && tot_lsm=$((tot_lsm + b_compact))
    tot_host=$((tot_host + d_host))
    tot_nand=$((tot_nand + d_nand))
    tot_gc=$((tot_gc + d_gc))
}

run_phase fill fillrandom write "$num" --use_existing_db=0
run_phase overwrite overwrite rewrite "$num" --use_existing_db=1
run_phase mixed readrandomwriterandom mixed "$((threads * mixed_reads))" \
    --use_existing_db=1 \
    --readwritepercent=90 "--threads=$threads" "--reads=$mixed_reads"

# The effect of the recipe. lsm_wa is the table bytes over the user
# bytes, host_wa the host bytes over the user bytes, and device_waf the
# NAND bytes over the host bytes. The host bytes also hold the WAL and
# the file system, so end_to_end_wa is host_wa x device_waf, not
# lsm_wa x device_waf.
ratio() {
    awk -v a="$1" -v b="$2" \
        'BEGIN { if (b > 0) printf "%.3f", a / b; else print "-" }'
}
lsm_wa=$(ratio "$tot_lsm" "$tot_user")
host_wa=$(ratio "$((tot_host * PAGE))" "$tot_user")
device_waf=$(ratio "$((tot_nand + tot_gc))" "$tot_host")
e2e=$(ratio "$(((tot_nand + tot_gc) * PAGE))" "$tot_user")
echo "ROCKSDB_EFFECT=user_bytes=$tot_user payload_bytes=$tot_payload" \
    "lsm_write_bytes=$tot_lsm lsm_wa=$lsm_wa" \
    "host_bytes=$((tot_host * PAGE)) host_wa=$host_wa" \
    "nand_bytes=$(((tot_nand + tot_gc) * PAGE)) device_waf=$device_waf" \
    "end_to_end_wa=$e2e"

recipe_finish "recipe=rocksdb" "ref=$ref" "num=$num" "value_size=$vsize" \
    "user_bytes=$tot_user" "lsm_write_bytes=$tot_lsm" "lsm_wa=$lsm_wa" \
    "device_waf=$device_waf" "control=${control:-none}"
