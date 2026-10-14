#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Check a FEMU key-value namespace from inside the guest with kv-probe and
# kv-bench.
#
#   sudo bash kv-bench-guest.sh [NODE]
#
# NODE is the generic node of the KV namespace, such as /dev/ng0n1. Linux
# makes no block device for a KV namespace, so the default is the one
# /dev/ngXnY whose /dev/nvmeXnY does not exist. kv-probe.c and kv-bench.c
# must be in the directory of this script. The script installs gcc with
# apt-get when the guest has none. It stores and deletes keys.
#
#   kv-probe NODE        one key through each command and status
#   kv-bench (values)    small values: KVBENCH_KEYS keys, the default sizes
#   kv-bench (large)     values of 4 KiB to 256 KiB on 256 keys
#
# Pass criterion: kv-probe reports no failure, and each kv-bench run exits
# 0 with no error or mismatch. kv-bench checks every Retrieve against a
# model of the keys, Exist and Retrieve of deleted keys, and that List
# returns exactly the live keys. It needs an empty namespace.
#
# Environment:
#   KVBENCH_KEYS     keys of the small-value run (default 20000)
#   KVBENCH_OPS      mixed commands per thread (default 25000)
#   KVBENCH_THREADS  threads (default 4)
#   KVBENCH_SEED     seed (default 1)
#   KVBENCH_CONTROL  legacy-opcodes or corrupt-model, passed to kv-bench to
#                    show that its checks fail; the run must then fail
#   WORKDIR          parent of the new scratch directory (default /tmp)
#
# Summary lines start with KVBENCH_ or KVPROBE_. The exit status is 0 when
# every check passed, 1 when one failed and 2 when the setup failed.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

usage() {
	echo "usage: sudo bash $(basename "$0") [NODE]" >&2
	exit 2
}

[[ $# -le 1 ]] || usage
[[ ${1:-} == -h || ${1:-} == --help ]] && usage

keys=${KVBENCH_KEYS:-20000}
ops=${KVBENCH_OPS:-25000}
threads=${KVBENCH_THREADS:-4}
seed=${KVBENCH_SEED:-1}
control=${KVBENCH_CONTROL:-}
parent=${WORKDIR:-/tmp}

setup_fail() {
	echo "KVBENCH_SETUP=$1"
	exit 2
}

for v in keys ops threads seed; do
	[[ ${!v} =~ ^[1-9][0-9]*$ ]] || setup_fail "bad-$v-${!v}"
done
case $control in
'' | legacy-opcodes | corrupt-model) ;;
*) setup_fail "bad-control-$control" ;;
esac
[[ $EUID -eq 0 ]] || setup_fail not-root
for f in kv-probe.c kv-bench.c; do
	[[ -r $SCRIPT_DIR/$f ]] || setup_fail "missing-$f"
done

node=${1:-}
if [[ -z $node ]]; then
	candidates=()
	for g in /dev/ng*n*; do
		[[ -c $g ]] || continue
		b=${g#/dev/ng}
		[[ -e /dev/nvme${b%%n*}n${b#*n} ]] || candidates+=("$g")
	done
	((${#candidates[@]} == 1)) ||
		setup_fail "found-${#candidates[@]}-kv-nodes-name-one"
	node=${candidates[0]}
fi
[[ -c $node ]] || setup_fail "no-node-$node"
echo "KVBENCH_NODE=$node"

if ! command -v gcc >/dev/null; then
	export DEBIAN_FRONTEND=noninteractive
	apt-get -qq update >/dev/null 2>&1 || setup_fail apt-update
	apt-get -qq install -y gcc libc6-dev >/dev/null 2>&1 ||
		setup_fail apt-install
fi

workdir=$(mktemp -d "$parent/femu-kv-bench.XXXXXX") || setup_fail mktemp
echo "KVBENCH_WORKDIR=$workdir"
gcc -O2 -Wall -o "$workdir/kv-probe" "$SCRIPT_DIR/kv-probe.c" ||
	setup_fail build-kv-probe
gcc -O2 -Wall -pthread -o "$workdir/kv-bench" "$SCRIPT_DIR/kv-bench.c" ||
	setup_fail build-kv-bench

failed=0

rc=0
"$workdir/kv-probe" "$node" >"$workdir/kv-probe.log" 2>&1 || rc=$?
grep -E '^(KVPROBE_| *FAIL)' "$workdir/kv-probe.log" || true
if ((rc != 0)); then
	echo "KVBENCH_STEP=kv-probe FAIL status=$rc"
	failed=1
else
	echo "KVBENCH_STEP=kv-probe ok"
fi

# Run kv-bench; print its summary lines and record a failure.
bench() {
	local name=$1 rc=0
	shift
	local -a args=(--threads "$threads" --seed "$seed")
	[[ -n $control ]] && args+=(--control "$control")
	"$workdir/kv-bench" "${args[@]}" "$@" "$node" \
		>"$workdir/kv-bench-$name.log" 2>&1 || rc=$?
	grep -E '^KVBENCH_' "$workdir/kv-bench-$name.log" | sed "s/^/[$name] /"
	if ((rc != 0)); then
		echo "KVBENCH_STEP=$name FAIL status=$rc"
		failed=1
	else
		echo "KVBENCH_STEP=$name ok"
	fi
}

# Each kv-bench run needs an empty namespace and deletes its keys at the
# end, so the runs follow one another.
bench values --keys "$keys" --ops "$ops" --key-len 4-16
bench large --keys 256 --ops 64 --values 4096,65536,262144 \
	--ratio 50:30:20

if ((failed)); then
	echo "KVBENCH_DONE=FAIL"
	exit 1
fi
echo "KVBENCH_DONE=PASS"
exit 0
