#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Build RocksDB with the ZenFS plugin inside a FEMU guest and run a crash
# test on a zoned namespace.
#
#   sudo bash zenfs-crash-guest.sh [NAMESPACE]
#
# NAMESPACE is a block device name such as nvme0n1. The default is the
# first host-managed zoned NVMe namespace. The script installs packages
# with apt-get and clones RocksDB and ZenFS, so the guest needs network
# access. It formats the namespace with ZenFS.
#
# The crash test is the RocksDB blackbox crash test with the ZenFS
# options of ZenFS's own test (tests/crashtest in the ZenFS tree):
#
#   zenfs mkfs
#   round 1..R: db_stress, killed with SIGKILL after INTERVAL seconds;
#               each start checks the database against the expected state
#   final:      db_stress --verification_only=1 checks every key
#
# ZenFS's own driver passes --expected_values_path, which RocksDB removed
# before 7.0, so this script starts db_stress itself.
#
# Pass criterion:
#   - zenfs mkfs succeeds;
#   - in each round, db_stress runs until the SIGKILL of its timeout,
#     writes nothing to stderr, and a thread reports at least 1000
#     finished operations; the SMART host write count grows;
#   - the final run exits 0, prints "Verification successful" and writes
#     nothing to stderr;
#   - ZenFS wrote to more zones than its metadata zones.
#
# Environment:
#   ROCKSDB_REPO    git URL (default https://github.com/facebook/rocksdb.git)
#   ROCKSDB_REF     tag (default v9.10.0)
#   ZENFS_REPO      git URL (default
#                   https://github.com/westerndigitalcorporation/zenfs.git)
#   ZENFS_REF       commit (default 919c2ebbcdc170525a9abffb8b61a3795b1e6ae5)
#   ZENFS_PREFIX    install directory of the build (default /opt/femu-zenfs);
#                   a build that matches both refs is used again
#   ZENFS_JOBS      build jobs (default: the number of CPUs)
#   ZENFS_ROUNDS    kill rounds (default 6)
#   ZENFS_INTERVAL  seconds before each kill (default 60)
#   ZENFS_THREADS   db_stress threads (default 8)
#   ZENFS_KEYS      db_stress --max_key (default 100000)
#   ZENFS_CONTROL   reset-zones: reset every written data zone after round
#                   1, so the next round must fail. Use it only to show
#                   that the test detects lost data. A control that is
#                   not detected ends as a setup error (status 2).
#   WORKDIR         parent of the new scratch directory (default /tmp)
#
# Summary lines start with ZENFS_, ROCKSDB_COMMIT or ZENFS_COMMIT. The exit
# status is 0 when the test passed, 1 when it failed and 2 when the setup
# failed.

set -euo pipefail

readonly META_ZONES=3

usage() {
	echo "usage: sudo bash $(basename "$0") [NAMESPACE]" >&2
	exit 2
}

[[ $# -le 1 ]] || usage
[[ ${1:-} == -h || ${1:-} == --help ]] && usage

rocksdb_repo=${ROCKSDB_REPO:-https://github.com/facebook/rocksdb.git}
rocksdb_ref=${ROCKSDB_REF:-v9.10.0}
zenfs_repo=${ZENFS_REPO:-https://github.com/westerndigitalcorporation/zenfs.git}
zenfs_ref=${ZENFS_REF:-919c2ebbcdc170525a9abffb8b61a3795b1e6ae5}
prefix=${ZENFS_PREFIX:-/opt/femu-zenfs}
jobs=${ZENFS_JOBS:-$(nproc)}
rounds=${ZENFS_ROUNDS:-6}
interval=${ZENFS_INTERVAL:-60}
threads=${ZENFS_THREADS:-8}
keys=${ZENFS_KEYS:-100000}
control=${ZENFS_CONTROL:-}
parent=${WORKDIR:-/tmp}

setup_fail() {
	echo "ZENFS_SETUP=$1"
	exit 2
}

for v in jobs rounds interval threads keys; do
	[[ ${!v} =~ ^[1-9][0-9]*$ ]] || setup_fail "bad-$v-${!v}"
done
case $control in
'' | reset-zones) ;;
*) setup_fail "bad-control-$control" ;;
esac
[[ $EUID -eq 0 ]] || setup_fail not-root

# Pick the namespace: the argument, or the first host-managed NVMe one.
dev=${1:-}
if [[ -z $dev ]]; then
	for z in /sys/block/nvme*n*/queue/zoned; do
		[[ -r $z && $(<"$z") == host-managed ]] || continue
		dev=$(basename "$(dirname "$(dirname "$z")")")
		break
	done
	# No zoned namespace: take the first NVMe namespace, so that the
	# ZenFS checks decide. That is the conventional-namespace control.
	if [[ -z $dev ]]; then
		for b in /sys/block/nvme*n*; do
			[[ -e $b ]] && dev=$(basename "$b") && break
		done
	fi
fi
dev=${dev#/dev/}
[[ -b /dev/$dev ]] || setup_fail "no-namespace-$dev"
echo "ZENFS_DEVICE=$dev zoned=$(cat "/sys/block/$dev/queue/zoned")"

export DEBIAN_FRONTEND=noninteractive
apt-get -qq update >/dev/null 2>&1 || setup_fail apt-update
apt-get -qq install -y build-essential git python3 pkg-config util-linux \
	libgflags-dev libsnappy-dev zlib1g-dev libbz2-dev liblz4-dev \
	libzstd-dev libzbd-dev nvme-cli >/dev/null 2>&1 || setup_fail apt-install

workdir=$(mktemp -d "$parent/femu-zenfs.XXXXXX") || setup_fail mktemp
echo "ZENFS_WORKDIR=$workdir"

# The build goes to $prefix and is used again when both refs match, so
# a guest image kept from an earlier run skips the build.
stamp=$prefix/femu-build-refs
want_stamp="rocksdb=$rocksdb_ref zenfs=$zenfs_ref"
if [[ -x $prefix/bin/db_stress && -x $prefix/bin/zenfs && -r $stamp &&
	$(<"$stamp") == "$want_stamp" ]]; then
	echo "ZENFS_BUILD=reused $prefix"
else
	src=$workdir/rocksdb
	git -c advice.detachedHead=false clone -q --depth 1 \
		--branch "$rocksdb_ref" "$rocksdb_repo" "$src" ||
		setup_fail clone-rocksdb
	# ZenFS names its version with git describe, so it needs the tags.
	git clone -q "$zenfs_repo" "$src/plugin/zenfs" || setup_fail clone-zenfs
	git -C "$src/plugin/zenfs" -c advice.detachedHead=false checkout -q \
		"$zenfs_ref" || setup_fail checkout-zenfs
	echo "ROCKSDB_COMMIT=$(git -C "$src" rev-parse --short=12 HEAD)"
	echo "ZENFS_COMMIT=$(git -C "$src/plugin/zenfs" rev-parse --short=12 HEAD)"

	# The same variables go to every make call: install-static rebuilds
	# the library when they differ. GCC 13 reports a false array-bounds
	# error in RocksDB 9.10, so warnings do not stop the build.
	make_cmd=(make -C "$src" DEBUG_LEVEL=0 ROCKSDB_PLUGINS=zenfs
		DISABLE_WARNING_AS_ERROR=1 PREFIX="$prefix")
	"${make_cmd[@]}" -j"$jobs" db_stress static_lib \
		>"$workdir/build.log" 2>&1 || {
		tail -20 "$workdir/build.log"
		setup_fail build-rocksdb
	}
	"${make_cmd[@]}" install-static >>"$workdir/build.log" 2>&1 || {
		tail -20 "$workdir/build.log"
		setup_fail install-rocksdb
	}
	PKG_CONFIG_PATH=$prefix/lib/pkgconfig \
		make -C "$src/plugin/zenfs/util" >>"$workdir/build.log" 2>&1 || {
		tail -20 "$workdir/build.log"
		setup_fail build-zenfs-util
	}
	install -D -m 755 "$src/db_stress" "$prefix/bin/db_stress"
	install -D -m 755 "$src/plugin/zenfs/util/zenfs" "$prefix/bin/zenfs"
	echo "$want_stamp" >"$stamp"
	echo "ZENFS_BUILD=built $prefix"
fi
echo "ZENFS_REFS=$(<"$stamp")"
db_stress=$prefix/bin/db_stress
zenfs=$prefix/bin/zenfs

# ZenFS refuses a zoned device without mq-deadline. A conventional device
# may have no such scheduler; ZenFS refuses that device anyway.
echo mq-deadline >"/sys/block/$dev/queue/scheduler" 2>/dev/null || true
echo "ZENFS_SCHEDULER=$(cat "/sys/block/$dev/queue/scheduler")"

# Zone capacity in bytes, from the first zone.
zone_cap=0
if [[ $(cat "/sys/block/$dev/queue/zoned") == host-managed ]]; then
	cap_hex=$(blkzone report -c 1 "/dev/$dev" | sed -nE 's/.*cap (0x[0-9a-f]+).*/\1/p')
	[[ -n $cap_hex ]] && zone_cap=$((cap_hex * 512))
	echo "ZENFS_ZONES=$(blkzone report "/dev/$dev" | wc -l) cap_bytes=$zone_cap"
fi

fail() {
	echo "ZENFS_FAIL=$1"
	echo "ZENFS_RESULT=FAIL"
	exit 1
}

aux=$workdir/aux
if ! "$zenfs" mkfs --zbd="$dev" --aux_path="$aux" --force \
	>"$workdir/mkfs.log" 2>&1; then
	tail -5 "$workdir/mkfs.log"
	fail mkfs
fi
echo "ZENFS_MKFS=ok"

# The options of ZenFS's simple blackbox crash test, the zone-sized SST
# target of its parameter script, and no injected faults: the test is of
# the device, not of RocksDB's error paths. ZenFS keeps unsynced WAL data
# in the process, so a SIGKILL loses it; --sync=1 syncs each write, and
# then every write that completed must survive the kill.
target=$((zone_cap > 0 ? zone_cap * 95 / 100 : 64 << 20))
expected=$workdir/expected
mkdir -p "$expected"
stress_opts=(
	--fs_uri="zenfs://dev:$dev" --db=femu-crashtest
	--expected_values_dir="$expected" --destroy_db_initially=0 --sync=1
	--max_key="$keys" --threads="$threads" --column_families=1
	--reopen=20 --block_size=16384 --memtablerep=skip_list
	--writepercent=35 --readpercent=50 --prefixpercent=0 --prefix_size=-1
	--iterpercent=10 --delpercent=4 --delrangepercent=1
	--max_background_compactions=1 --max_bytes_for_level_base=67108864
	--target_file_size_base="$target" --target_file_size_multiplier=1
	--write_buffer_size=33554432 --level_compaction_dynamic_level_bytes=0
	--open_files=-1 --set_options_one_in=0 --clear_column_family_one_in=0
	--use_direct_reads=1 --use_direct_io_for_flush_and_compaction=1
	--read_fault_one_in=0 --write_fault_one_in=0
	--metadata_read_fault_one_in=0 --metadata_write_fault_one_in=0
	--open_metadata_write_fault_one_in=0 --open_write_fault_one_in=0
	--open_read_fault_one_in=0 --sync_fault_injection=0
)

# Print stderr lines; return 1 when there are any. RocksDB's crash test
# fails a round with any stderr output.
stderr_clean() {
	local file=$1
	[[ -s $file ]] || return 0
	sed -n '1,10p' "$file" | cut -c1-200 | sed 's/^/  stderr: /'
	return 1
}

# Count, or with "reset" also reset, the data zones that hold data: the
# zones after ZenFS's metadata zones whose write pointer is past the
# start. blkzone prints the write pointer as an offset in the zone. The
# count goes to zones_found; a failed report or reset ends the test.
zones_found=0
data_zones() {
	local action=$1 report line start wp idx=0
	zones_found=0
	report=$(blkzone report "/dev/$dev") || fail zone-report
	while read -r line; do
		[[ $line =~ start:\ (0x[0-9a-f]+),.*wptr\ (0x[0-9a-f]+) ]] || continue
		start=${BASH_REMATCH[1]}
		wp=${BASH_REMATCH[2]}
		if ((idx >= META_ZONES && wp != 0)); then
			if [[ $action == reset ]]; then
				blkzone reset -o "$start" -c 1 "/dev/$dev" || fail zone-reset
			fi
			zones_found=$((zones_found + 1))
		fi
		idx=$((idx + 1))
	done <<<"$report"
	((idx > 0)) || fail zone-report-empty
}

# Write commands the controller completed, from the SMART log.
ctrl=/dev/${dev%n*}
write_cmds() {
	nvme smart-log "$ctrl" --output-format=json |
		python3 -c 'import json, sys; print(json.load(sys.stdin)["host_write_commands"])'
}

# A round passes when db_stress ran until the timeout's SIGKILL, wrote
# nothing to stderr, and reported at least MIN_OPS finished operations;
# each operation ends after its write is synced. The SMART host write
# count must also grow. stdbuf keeps the progress lines that db_stress
# prints without a flush, which a SIGKILL would otherwise lose.
readonly MIN_OPS=1000
for ((r = 1; r <= rounds; r++)); do
	out=$workdir/round-$r.out
	err=$workdir/round-$r.err
	rc=0
	before=$(write_cmds) || fail smart-log
	t0=$SECONDS
	timeout -s KILL "$interval" stdbuf -o0 "$db_stress" "${stress_opts[@]}" \
		--ops_per_thread=100000000 >"$out" 2>"$err" || rc=$?
	ran=$((SECONDS - t0))
	after=$(write_cmds) || fail smart-log
	ops=$(tr '\r' '\n' <"$out" | sed -nE 's/^\.\.\. finished ([0-9]+) ops.*/\1/p' |
		sort -n | tail -1)
	ops=${ops:-0}
	if ((rc != 137 || ran < interval)); then
		echo "ZENFS_ROUND=$r FAIL exit-before-kill status=$rc after=${ran}s"
		stderr_clean "$err" || true
		tail -5 "$out" | sed 's/^/  stdout: /'
		fail "round-$r"
	fi
	if ! stderr_clean "$err"; then
		echo "ZENFS_ROUND=$r FAIL stderr"
		fail "round-$r"
	fi
	if ((ops < MIN_OPS)); then
		echo "ZENFS_ROUND=$r FAIL ops=$ops"
		fail "round-$r"
	fi
	if ((after <= before)); then
		echo "ZENFS_ROUND=$r FAIL no-writes write_cmds=$before"
		fail "round-$r"
	fi
	echo "ZENFS_ROUND=$r ok killed-after=${ran}s thread_ops=$ops write_cmds=$((after - before))"
	if [[ $control == reset-zones && $r -eq 1 ]]; then
		data_zones reset
		echo "ZENFS_CONTROL_RESET_ZONES=$zones_found"
		((zones_found > 0)) || setup_fail control-reset-nothing
	fi
	sleep 2
done

out=$workdir/final.out
err=$workdir/final.err
rc=0
# RocksDB refuses --reopen at or past --ops_per_thread, so no reopen here.
timeout 1800 "$db_stress" "${stress_opts[@]}" --verification_only=1 \
	--reopen=0 --ops_per_thread=1 >"$out" 2>"$err" || rc=$?
grep -m1 'Verification successful' "$out" | sed 's/^/ZENFS_FINAL_LINE=/' || true
if ((rc != 0)) || ! grep -q 'Verification successful' "$out"; then
	echo "ZENFS_FINAL=FAIL status=$rc"
	stderr_clean "$err" || true
	fail final
fi
if ! stderr_clean "$err"; then
	echo "ZENFS_FINAL=FAIL stderr"
	fail final
fi
echo "ZENFS_FINAL=ok"

# The data must be on the device: count the zones past the metadata zones
# that hold data.
data_zones count
echo "ZENFS_WRITTEN_ZONES=$zones_found"
((zones_found > 0)) || fail no-data-zones
"$zenfs" list --zbd="$dev" --path=femu-crashtest 2>/dev/null |
	wc -l | sed 's/^/ZENFS_FILES=/' || true
# A control that got here was not detected, so the test cannot see the
# loss it planted.
[[ -z $control ]] || setup_fail "control-not-detected-$control"
echo "ZENFS_RESULT=PASS"
exit 0
