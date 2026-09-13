#!/bin/bash
# Run one bundle's placement policies end to end, preflight first.
#
# Usage: run_sweep.sh BUNDLE LAYOUT_PREFIX IMG_PREFIX TAG_PREFIX [policy ...]
#   run_sweep.sh deepseek_C gen256 ds256 ds256
#   run_sweep.sh qwen_C     gen256 qw256 qw256 inverted
#
# The preflight call is the point of this wrapper: run_policy.sh reverted once
# between two policies of a live sweep, and the unpatched defaults fail quietly
# (see preflight.sh). Going through here means no sweep can start on a reverted
# script, and a revert mid-sweep is caught at the next policy.
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
HERE=$ROOT/exp/moe_bcq/femu_run

BUNDLE=${1:?usage: run_sweep.sh BUNDLE LAYOUT_PREFIX IMG_PREFIX TAG_PREFIX [policy ...]}
LAYOUT_PREFIX=${2:?}; IMG_PREFIX=${3:?}; TAG_PREFIX=${4:?}
shift 4
POLICIES=("$@"); [ ${#POLICIES[@]} -gt 0 ] || POLICIES=(aligned rotated inverted)

cd "$ROOT"
rc=0
for pol in "${POLICIES[@]}"; do
    # Re-checked per policy, not once at the top: the observed revert landed
    # between two policies of a running sweep.
    bash "$HERE/preflight.sh" || { echo "!!!! preflight failed; not running $pol"; rc=1; break; }
    echo "############ $(date +%T) $TAG_PREFIX $pol ############"
    BUNDLE=$BUNDLE LAYOUT_PREFIX=$LAYOUT_PREFIX IMG_PREFIX=$IMG_PREFIX TAG_PREFIX=$TAG_PREFIX \
        bash "$HERE/run_policy.sh" "$pol" || { echo "!!!! $pol FAILED rc=$?"; rc=1; }
done
echo "############ $(date +%T) sweep done (rc=$rc) ############"
exit $rc
