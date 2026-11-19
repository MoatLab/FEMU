#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Workload recipe: the DLIO benchmark on a FEMU BlackBox namespace. DLIO
# gives the storage I/O of a training job: it writes a dataset, reads it
# in batches and writes checkpoints. A sleep stands for the accelerator,
# so the guest needs none.
#
#   sudo bash recipe-dlio-guest.sh --yes [NAMESPACE]
#
# NAMESPACE is a block device name such as nvme0n1 (the default). The
# script makes an ext4 file system on it, so --yes is necessary. It
# installs packages with apt-get and pip, and it clones DLIO, so the
# guest needs network access and several GiB of free space under
# DLIO_PREFIX. recipe-guest-lib.sh must be next to this script.
#
#   generate    DLIO writes the dataset (npz files) to the namespace
#   train       DLIO reads the dataset with O_DIRECT for DLIO_EPOCHS
#               epochs and writes one checkpoint after each epoch
#   counters    log page C0h and the block layer, around each phase
#
# Pass criterion:
#   - each DLIO run exits 0 inside its time limit, and the training run
#     writes summary.json;
#   - the dataset on the namespace has at least half of the configured
#     size, so the size options took effect;
#   - generate: the block layer and the C0h host pages each count at
#     least 90% of the dataset size;
#   - train: the block layer reads at least 90% of the training files,
#     and the C0h plane read count grows, so the reads came from NAND
#     and not from the guest page cache;
#   - train: after a sync, the block layer and the C0h host pages each
#     count at least 90% of one checkpoint. DLIO v2.0.1 does not call
#     fsync for a checkpoint, so the script calls sync after each run.
# PASS means that the recipe ran and the counters moved. It is not a
# statement on performance.
#
# Environment:
#   DLIO_REPO          git URL (default
#                      https://github.com/argonne-lcf/dlio_benchmark.git)
#   DLIO_REF           tag or commit (default v2.0.1)
#   DLIO_PREFIX        directory of the Python environment (default
#                      /opt/femu-dlio); an install of the same ref is
#                      used again
#   DLIO_FILES         training files (default 64)
#   DLIO_RECORD_BYTES  bytes of one file (default 16777216)
#   DLIO_EPOCHS        epochs (default 2)
#   DLIO_BATCH         samples in one batch (default 4)
#   DLIO_COMPUTE_SEC   sleep per batch, for the accelerator (default 0.05)
#   DLIO_MODEL_BYTES   bytes of one checkpoint (default 268435456)
#   DLIO_TIMEOUT       seconds for each DLIO run (default 1800)
#   DLIO_INSTALL_TIMEOUT  seconds for the install (default 3600)
#   DLIO_CONTROL       page-cache: read without O_DIRECT and keep the
#                      page cache, so the read checks must fail. Use it
#                      only to show that the checks can fail.
#   RECIPE_CTRL        controller device (default /dev/nvmeX)
#   WORKDIR            parent of the new scratch directory (default /tmp)
#
# Summary lines start with DLIO_. The last line is
# DLIO_RESULT=PASS|FAIL|SETUP-ERROR with key=value fields. The exit
# status is 0 when each check passed, 1 when one failed and 2 when the
# setup failed.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
readonly RECIPE=DLIO
readonly PAGE=4096
readonly EVAL_FILES=8

# shellcheck source-path=SCRIPTDIR source=recipe-guest-lib.sh
source "$SCRIPT_DIR/recipe-guest-lib.sh" || {
    echo "DLIO_RESULT=SETUP-ERROR reason=missing-recipe-guest-lib.sh"
    exit 2
}

usage() {
    echo "usage: sudo bash $(basename "$0") --yes [NAMESPACE]" >&2
    setup_fail usage
}

[[ ${1:-} == --yes ]] || usage
shift
[[ $# -le 1 ]] || usage

repo=${DLIO_REPO:-https://github.com/argonne-lcf/dlio_benchmark.git}
ref=${DLIO_REF:-v2.0.1}
prefix=${DLIO_PREFIX:-/opt/femu-dlio}
files=${DLIO_FILES:-64}
record=${DLIO_RECORD_BYTES:-16777216}
epochs=${DLIO_EPOCHS:-2}
batch=${DLIO_BATCH:-4}
compute=${DLIO_COMPUTE_SEC:-0.05}
model=${DLIO_MODEL_BYTES:-268435456}
limit=${DLIO_TIMEOUT:-1800}
install_limit=${DLIO_INSTALL_TIMEOUT:-3600}
control=${DLIO_CONTROL:-}
parent=${WORKDIR:-/tmp}

need_number files record epochs batch model limit install_limit
[[ $compute =~ ^[0-9]+(\.[0-9]+)?$ ]] || setup_fail "bad-compute-$compute"
case $control in
'' | page-cache) ;;
*) setup_fail "bad-control-$control" ;;
esac
[[ $EUID -eq 0 ]] || setup_fail not-root
for tool in nvme lsblk timeout; do
    command -v "$tool" >/dev/null || setup_fail "no-$tool"
done

resolve_namespace "${1:-nvme0n1}"
size=$(blockdev --getsize64 "$ns_dev") || setup_fail no-size
need=$(((files + EVAL_FILES) * record + epochs * model))
((size >= need + need / 4)) || setup_fail "namespace-below-$((need + need / 4))"
workdir=$(mktemp -d "$parent/femu-dlio.XXXXXX") || setup_fail mktemp
recipe_workdir=$workdir
echo "DLIO_DEVICE=$ns_name workdir=$workdir"

export DEBIAN_FRONTEND=noninteractive
apt_step "$install_limit" update || setup_fail apt-update
apt_step "$install_limit" install -y git build-essential python3-dev \
    python3-venv openmpi-bin libopenmpi-dev e2fsprogs ||
    setup_fail apt-install

# The install goes to $prefix and is used again when the ref matches.
stamp=$prefix/femu-dlio-ref
dlio=$prefix/venv/bin/dlio_benchmark
if [[ -x $dlio && -r $stamp && $(<"$stamp") == "$ref "* ]]; then
    echo "DLIO_INSTALL=reused $prefix"
else
    src=$workdir/dlio_benchmark
    bounded "$install_limit" git clone -q "$repo" "$src" ||
        setup_fail clone-dlio
    git -C "$src" -c advice.detachedHead=false checkout -q "$ref" ||
        setup_fail "checkout-$ref"
    commit=$(git -C "$src" rev-parse HEAD)
    mkdir -p "$prefix" || setup_fail mkdir-prefix
    python3 -m venv "$prefix/venv" || setup_fail venv
    bounded "$install_limit" "$prefix/venv/bin/pip" install -q \
        --upgrade pip >"$workdir/pip.log" 2>&1 || setup_fail pip-upgrade
    (cd "$src" && bounded "$install_limit" "$prefix/venv/bin/pip" \
        install -q .) >>"$workdir/pip.log" 2>&1 || {
        tail -n 20 "$workdir/pip.log"
        setup_fail pip-install-dlio
    }
    [[ -x $dlio ]] || setup_fail no-dlio_benchmark
    echo "$ref $commit" >"$stamp"
    echo "DLIO_INSTALL=built $prefix"
fi
echo "DLIO_REF=$(<"$stamp")"

mount_fresh "$workdir/mnt"
data=$recipe_mnt/data
ckpt=$recipe_mnt/checkpoints

# The options that both runs share. unet3d_a100 is the base workload
# (npz files, the PyTorch loader); the options below make it small.
common=(workload=unet3d_a100
    "++workload.dataset.data_folder=$data"
    "++workload.dataset.num_files_train=$files"
    "++workload.dataset.num_files_eval=$EVAL_FILES"
    ++workload.dataset.num_samples_per_file=1
    "++workload.dataset.record_length_bytes=$record"
    ++workload.dataset.record_length_bytes_stdev=0
    "++workload.checkpoint.checkpoint_folder=$ckpt"
    ++workload.workflow.evaluation=False)

# Run DLIO from the scratch directory, where Hydra keeps its own log.
run_dlio() {
    local name=$1 rc=0
    shift

    (cd "$workdir" && bounded "$limit" "$dlio" "${common[@]}" "$@") \
        >"$workdir/$name.log" 2>&1 || rc=$?
    if ((rc != 0)); then
        tail -n 20 "$workdir/$name.log"
        check_fail "$name-status-$rc"
    fi
    flush_device
}

sample s0
run_dlio generate ++workload.workflow.generate_data=True \
    ++workload.workflow.train=False ++workload.workflow.checkpoint=False \
    "++workload.output.folder=$workdir/out-generate"
sample s1
counter_change generate s0 s1

dataset=0
train_bytes=0
if [[ -d $data ]]; then
    dataset=$(du -sb "$data" | cut -f1)
    [[ -d $data/train ]] && train_bytes=$(du -sb "$data/train" | cut -f1)
fi
echo "DLIO_DATASET=bytes=$dataset train_bytes=$train_bytes" \
    "configured=$(((files + EVAL_FILES) * record))"
((dataset * 2 >= (files + EVAL_FILES) * record)) ||
    check_fail dataset-below-half-of-configured
if ((dataset > 0)); then
    at_least_90 "$d_wr" "$dataset" || check_fail generate-block-writes
    at_least_90 "$((d_host * PAGE))" "$dataset" ||
        check_fail generate-c0-host-pages
fi

# The training run must read the files from the device.
odirect=True
if [[ $control == page-cache ]]; then
    odirect=False
    cat "$data"/train/* >/dev/null 2>&1 || true
else
    drop_caches
fi

sample s2
run_dlio train ++workload.workflow.generate_data=False \
    ++workload.workflow.train=True ++workload.workflow.checkpoint=True \
    "++workload.train.epochs=$epochs" \
    "++workload.train.computation_time=$compute" \
    "++workload.reader.batch_size=$batch" \
    ++workload.reader.read_threads=0 \
    "++workload.reader.odirect=$odirect" \
    ++workload.checkpoint.checkpoint_after_epoch=1 \
    ++workload.checkpoint.epochs_between_checkpoints=1 \
    "++workload.model.model_size_bytes=$model" \
    "++workload.output.folder=$workdir/out-train"
sample s3
counter_change train s2 s3

summary=$workdir/out-train/summary.json
au=-
if [[ -r $summary ]]; then
    au=$(python3 - "$summary" <<'EOF' || true
import json
import sys

try:
    with open(sys.argv[1]) as f:
        print(json.load(f)["metric"]["train_au_mean_percentage"])
except (OSError, ValueError, KeyError, TypeError):
    print("-")
EOF
    )
else
    check_fail no-summary.json
fi
checkpoints=0
[[ -d $ckpt ]] && checkpoints=$(du -sb "$ckpt" | cut -f1)
echo "DLIO_TRAIN=au_mean_percent=${au:--} checkpoint_bytes=$checkpoints"

if ((train_bytes > 0)); then
    at_least_90 "$d_rd" "$train_bytes" || check_fail train-block-reads
fi
((d_planes > 0)) || check_fail train-no-nand-reads
at_least_90 "$d_wr" "$model" || check_fail checkpoint-block-writes
at_least_90 "$((d_host * PAGE))" "$model" ||
    check_fail checkpoint-c0-host-pages

recipe_finish "recipe=dlio" "ref=$ref" "dataset_bytes=$dataset" \
    "epochs=$epochs" "checkpoint_bytes=$checkpoints" "waf=$d_waf" \
    "control=${control:-none}"
