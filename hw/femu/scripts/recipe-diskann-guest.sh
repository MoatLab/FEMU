#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Workload recipe: a DiskANN vector index on a FEMU BlackBox namespace.
# DiskANN keeps a graph index in one file and reads it with small random
# O_DIRECT reads, a few 4 KiB sectors for each query. The recipe builds
# an index of random vectors on the namespace and runs queries. It needs
# no accelerator.
#
#   sudo bash recipe-diskann-guest.sh --yes [NAMESPACE]
#
# NAMESPACE is a block device name such as nvme0n1 (the default). The
# script makes an ext4 file system on it, so --yes is necessary. It
# installs packages with apt-get, and it clones and builds DiskANN, so
# the guest needs network access. recipe-guest-lib.sh must be next to
# this script.
#
#   data      random base and query vectors, and the exact neighbours,
#             in the scratch directory (not on the namespace)
#   build     build_disk_index writes the index to the namespace
#   search    search_disk_index runs each query at each search list size
#   counters  log page C0h and the block layer, around build and search
#
# Pass criterion:
#   - each DiskANN tool exits 0 inside its time limit;
#   - build: the index file exists, and the block layer and the C0h host
#     pages each count at least 90% of its size;
#   - search: a result file of the expected size exists for each list
#     size, the block layer reads at least one 4 KiB sector for each
#     query at each list size, and the C0h plane read count grows, so
#     the queries read NAND and not the guest page cache.
# PASS means that the recipe ran and the counters moved. It is not a
# statement on performance or on recall.
#
# Environment:
#   DISKANN_REPO       git URL (default
#                      https://github.com/microsoft/DiskANN.git)
#   DISKANN_REF        tag, branch or commit (default 0.7.0, the last tag
#                      of the C++ code; cpp_main is its branch)
#   DISKANN_PREFIX     directory of the build (default /opt/femu-diskann);
#                      a build of the same ref is used again
#   DISKANN_JOBS       build jobs (default: the number of CPUs)
#   DISKANN_POINTS     base vectors (default 200000)
#   DISKANN_DIM        dimensions (default 96)
#   DISKANN_QUERIES    query vectors (default 2000)
#   DISKANN_LISTS      search list sizes, each 10 or more (default
#                      "20 40 80")
#   DISKANN_THREADS    search and build threads (default 4)
#   DISKANN_SEARCH_GB  -B, memory of the index at search time (default
#                      0.006)
#   DISKANN_BUILD_GB   -M, memory of the build (default 1)
#   DISKANN_TIMEOUT    seconds for each DiskANN tool (default 3600)
#   DISKANN_INSTALL_TIMEOUT  seconds for the install (default 3600)
#   DISKANN_CONTROL    index-off-device: put the index in the scratch
#                      directory, so the device checks must fail. Use it
#                      only to show that the checks can fail.
#   RECIPE_CTRL        controller device (default /dev/nvmeX)
#   WORKDIR            parent of the new scratch directory (default /tmp)
#
# Summary lines start with DISKANN_. The last line is
# DISKANN_RESULT=PASS|FAIL|SETUP-ERROR with key=value fields. The exit
# status is 0 when each check passed, 1 when one failed and 2 when the
# setup failed.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
readonly RECIPE=DISKANN
readonly PAGE=4096
readonly TOP_K=10

# shellcheck source-path=SCRIPTDIR source=recipe-guest-lib.sh
source "$SCRIPT_DIR/recipe-guest-lib.sh" || {
    echo "DISKANN_RESULT=SETUP-ERROR reason=missing-recipe-guest-lib.sh"
    exit 2
}

usage() {
    echo "usage: sudo bash $(basename "$0") --yes [NAMESPACE]" >&2
    setup_fail usage
}

[[ ${1:-} == --yes ]] || usage
shift
[[ $# -le 1 ]] || usage

repo=${DISKANN_REPO:-https://github.com/microsoft/DiskANN.git}
ref=${DISKANN_REF:-0.7.0}
prefix=${DISKANN_PREFIX:-/opt/femu-diskann}
jobs=${DISKANN_JOBS:-$(nproc)}
points=${DISKANN_POINTS:-200000}
dim=${DISKANN_DIM:-96}
queries=${DISKANN_QUERIES:-2000}
threads=${DISKANN_THREADS:-4}
search_gb=${DISKANN_SEARCH_GB:-0.006}
build_gb=${DISKANN_BUILD_GB:-1}
limit=${DISKANN_TIMEOUT:-3600}
install_limit=${DISKANN_INSTALL_TIMEOUT:-3600}
control=${DISKANN_CONTROL:-}
parent=${WORKDIR:-/tmp}
read -r -a lists <<<"${DISKANN_LISTS:-20 40 80}"

need_number jobs points dim queries threads limit install_limit
# The search tool skips a list size below the result count K.
for l in "${lists[@]}"; do
    [[ $l =~ ^[1-9][0-9]*$ ]] || setup_fail "bad-list-$l"
    ((l >= TOP_K)) || setup_fail "list-$l-below-$TOP_K"
done
((${#lists[@]} > 0)) || setup_fail no-list
for v in search_gb build_gb; do
    [[ ${!v} =~ ^[0-9]+(\.[0-9]+)?$ ]] || setup_fail "bad-$v-${!v}"
done
case $control in
'' | index-off-device) ;;
*) setup_fail "bad-control-$control" ;;
esac
[[ $EUID -eq 0 ]] || setup_fail not-root
for tool in nvme lsblk timeout; do
    command -v "$tool" >/dev/null || setup_fail "no-$tool"
done

resolve_namespace "${1:-nvme0n1}"
size=$(blockdev --getsize64 "$ns_dev") || setup_fail no-size
# The build keeps the vectors, a graph and merge files next to the index.
need=$((points * dim * 4 * 6))
((size >= need)) || setup_fail "namespace-below-$need"
workdir=$(mktemp -d "$parent/femu-diskann.XXXXXX") || setup_fail mktemp
recipe_workdir=$workdir
echo "DISKANN_DEVICE=$ns_name workdir=$workdir"

export DEBIAN_FRONTEND=noninteractive
apt_step "$install_limit" update || setup_fail apt-update
apt_step "$install_limit" install -y git make cmake g++ libaio-dev \
    libgoogle-perftools-dev clang-format libboost-all-dev libmkl-full-dev \
    e2fsprogs || setup_fail apt-install

# The build goes to $prefix and is used again when the ref matches.
stamp=$prefix/femu-diskann-ref
bin=$prefix/bin
tools=(build_disk_index search_disk_index rand_data_gen compute_groundtruth)
have=1
for t in "${tools[@]}"; do
    [[ -x $bin/$t ]] || have=0
done
if ((have)) && [[ -r $stamp && $(<"$stamp") == "$ref "* ]]; then
    echo "DISKANN_BUILD=reused $prefix"
else
    src=$workdir/DiskANN
    bounded "$install_limit" git clone -q "$repo" "$src" ||
        setup_fail clone-diskann
    git -C "$src" -c advice.detachedHead=false checkout -q "$ref" ||
        setup_fail "checkout-$ref"
    commit=$(git -C "$src" rev-parse HEAD)
    mkdir -p "$src/build" "$bin" || setup_fail mkdir-build
    (cd "$src/build" &&
        bounded "$install_limit" cmake -DCMAKE_BUILD_TYPE=Release .. &&
        bounded "$install_limit" make -j "$jobs") \
        >"$workdir/build.log" 2>&1 || {
        tail -n 20 "$workdir/build.log"
        setup_fail build-diskann
    }
    install -m 755 "$src/build/apps/build_disk_index" \
        "$src/build/apps/search_disk_index" \
        "$src/build/apps/utils/rand_data_gen" \
        "$src/build/apps/utils/compute_groundtruth" "$bin/" ||
        setup_fail install-diskann
    echo "$ref $commit" >"$stamp"
    echo "DISKANN_BUILD=built $prefix"
fi
echo "DISKANN_REF=$(<"$stamp")"

# Each search thread makes an asynchronous I/O context of its own.
sysctl -q -w fs.aio-max-nr=1048576 || true

# Run one DiskANN tool with a time limit; a failure of a data step is a
# setup failure, and a failure of build or search is a check failure.
run_tool() {
    local name=$1 rc=0
    shift

    bounded "$limit" "$@" >"$workdir/$name.log" 2>&1 || rc=$?
    if ((rc != 0)); then
        tail -n 20 "$workdir/$name.log"
        case $name in
        build | search) check_fail "$name-status-$rc" ;;
        *) setup_fail "$name-status-$rc" ;;
        esac
    fi
}

base=$workdir/base.fbin
query=$workdir/query.fbin
truth=$workdir/truth
run_tool base "$bin/rand_data_gen" --data_type float --output_file "$base" \
    -D "$dim" -N "$points" --norm 1.0
run_tool query "$bin/rand_data_gen" --data_type float \
    --output_file "$query" -D "$dim" -N "$queries" --norm 1.0
run_tool truth "$bin/compute_groundtruth" --data_type float --dist_fn l2 \
    --base_file "$base" --query_file "$query" --gt_file "$truth" --K 100

mount_fresh "$workdir/mnt"
index=$recipe_mnt/index
if [[ $control == index-off-device ]]; then
    index=$workdir/index
fi

sample s0
run_tool build "$bin/build_disk_index" --data_type float --dist_fn l2 \
    --data_path "$base" --index_path_prefix "$index" -R 32 -L 50 \
    -B "$search_gb" -M "$build_gb" -T "$threads"
flush_device
sample s1
counter_change build s0 s1

index_bytes=0
[[ -r ${index}_disk.index ]] &&
    index_bytes=$(stat -c %s "${index}_disk.index")
echo "DISKANN_INDEX=bytes=$index_bytes"
((index_bytes > 0)) || check_fail no-index-file
if ((index_bytes > 0)); then
    at_least_90 "$d_wr" "$index_bytes" || check_fail build-block-writes
    at_least_90 "$((d_host * PAGE))" "$index_bytes" ||
        check_fail build-c0-host-pages
fi

# No node is kept in memory, so each query reads the index file.
drop_caches
sample s2
run_tool search "$bin/search_disk_index" --data_type float --dist_fn l2 \
    --index_path_prefix "$index" --query_file "$query" \
    --gt_file "$truth" -K "$TOP_K" -L "${lists[@]}" \
    --result_path "$workdir/result" --num_nodes_to_cache 0 \
    -T "$threads" -W 2
sample s3
counter_change search s2 s3

# The result lines of the tool, for the reader: list size, beam width,
# queries per second, mean and 99.9th percentile latency, mean reads,
# CPU and recall. No check uses them.
grep -E '^ *(L +Beamwidth|[0-9]+ +[0-9]+ +[0-9.]+ +[0-9.]+)' \
    "$workdir/search.log" | sed 's/^/DISKANN_SEARCH: /' || true

# The tool writes one result file for each list size that it searched:
# a header of two 32-bit numbers, then K identifiers for each query.
done_lists=0
want=$((8 + queries * TOP_K * 4))
for l in "${lists[@]}"; do
    ids=$workdir/result_${l}_idx_uint32.bin
    if [[ -r $ids && $(stat -c %s "$ids") -eq $want ]]; then
        done_lists=$((done_lists + 1))
    else
        check_fail "search-no-result-for-list-$l"
    fi
done
echo "DISKANN_LISTS_DONE=$done_lists of ${#lists[@]}"

min_read=$((queries * ${#lists[@]} * PAGE))
((d_rd >= min_read)) || check_fail search-block-reads
((d_planes > 0)) || check_fail search-no-nand-reads

recipe_finish "recipe=diskann" "ref=$ref" "points=$points" \
    "queries=$queries" "index_bytes=$index_bytes" \
    "search_read_bytes=$d_rd" "control=${control:-none}"
