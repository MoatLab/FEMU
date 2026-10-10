#!/bin/bash
# Run one blktests group inside a FEMU guest and print a summary.
#
#   sudo bash blktests-guest.sh GROUP [DEVICE]
#
# GROUP is a blktests group, for example "block" or "zbd". DEVICE is the
# FEMU namespace (default /dev/nvme0n1). The script installs a compiler and
# the extra kernel modules with apt-get, then clones and builds blktests, so
# the guest needs network access. It writes to DEVICE.
#
# Environment:
#   BLKTESTS_REPO  git URL (default https://github.com/linux-blktests/blktests.git)
#   BLKTESTS_REF   commit, branch or tag to test (default: the remote HEAD)
#   WORKDIR        parent of the new scratch directory (default /tmp)
#
# Summary lines: BLKTESTS_WORKDIR, BLKTESTS_COMMIT, PASSED/FAILED/NOT_RUN
# counts, DEVICE_FAILED (failures of tests that ran on DEVICE), one
# FAILED_TEST line per failure, then BLKTESTS_DONE. Failures of tests that
# use only null_blk, scsi_debug or device-mapper do not count. The exit
# status is 0 when no test that ran on DEVICE failed, 1 when one did or the
# run ended abnormally, and 2 when the setup failed.

set -euo pipefail

usage() {
	echo "usage: sudo bash $(basename "$0") GROUP [DEVICE]" >&2
	exit 2
}

[[ $# -ge 1 && $# -le 2 ]] || usage
[[ $1 == -h || $1 == --help ]] && usage
group=$1
device=${2:-/dev/nvme0n1}
repo=${BLKTESTS_REPO:-https://github.com/linux-blktests/blktests.git}
ref=${BLKTESTS_REF:-}
parent=${WORKDIR:-/tmp}

setup_fail() {
	echo "BLKTESTS_SETUP=$1"
	exit 2
}

[[ $EUID -eq 0 ]] || setup_fail not-root
[[ -b $device ]] || setup_fail "no-block-device-$device"

export DEBIAN_FRONTEND=noninteractive
apt-get -qq update >/dev/null 2>&1 || setup_fail apt-update
apt-get -qq install -y build-essential git fio >/dev/null 2>&1 ||
	setup_fail apt-install
# null_blk and scsi_debug are in the extra modules; some tests need them.
if apt-get -qq install -y "linux-modules-extra-$(uname -r)" >/dev/null 2>&1; then
	echo "MODULES_EXTRA=yes"
else
	echo "MODULES_EXTRA=no"
fi
mountpoint -q /sys/kernel/debug || mount -t debugfs none /sys/kernel/debug ||
	setup_fail debugfs-mount

workdir=$(mktemp -d "$parent/femu-blktests.XXXXXX") || setup_fail mktemp
echo "BLKTESTS_WORKDIR=$workdir"
src=$workdir/blktests
results=$workdir/results
log=$workdir/check.log
git clone -q "$repo" "$src" || setup_fail clone
if [[ -n $ref ]]; then
	git -C "$src" checkout -q "$ref" || setup_fail "checkout-$ref"
fi
echo "BLKTESTS_COMMIT=$(git -C "$src" rev-parse --short HEAD)"
make -s -C "$src" >"$workdir/make.log" 2>&1 || {
	tail -5 "$workdir/make.log"
	setup_fail make
}
echo "TEST_DEVS=($device)" >"$src/config"

rc=0
(cd "$src" && ./check -o "$results" "$group") >"$log" 2>&1 || rc=$?
echo "BLKTESTS_RC=$rc"

count() {
	grep -c "$1" "$log" || true
}

dev_name=$(basename "$device")
passed=$(count '\[passed\]')
failed=$(count '\[failed\]')
not_run=$(count '\[not run\]')
dev_failed=$(grep -c "=> $dev_name .*\[failed\]" "$log" || true)
echo "PASSED=$passed FAILED=$failed NOT_RUN=$not_run DEVICE_FAILED=$dev_failed"

mapfile -t failures < <(grep '\[failed\]' "$log" |
	grep -oE '^[a-z]+/[0-9]+( => [a-z0-9]+)?' | sort -u)
for t in "${failures[@]}"; do
	echo "FAILED_TEST=$t"
	name=${t%% *}
	find "$results" -path "*${name}*" -name '*.out.bad' \
		-exec tail -8 {} \; 2>/dev/null | head -16
done

echo "--- not run, with reasons"
grep -A1 '\[not run\]' "$log" | grep -v '^--$' | paste - - |
	sed -E 's/ +/ /g' | cut -c1-160 | head -60 || true
echo "--- passed"
grep '\[passed\]' "$log" | grep -oE '^[a-z]+/[0-9]+[^[]*' |
	sed -E 's/ +$//' || true
echo BLKTESTS_DONE

if ((dev_failed > 0)); then
	exit 1
fi
# Each test of the group reports one status line for the one device. Fewer
# lines mean the run stopped early. check exits non-zero when any test
# failed, so a non-zero status with no failed test means the run broke.
expected=$(find "$src/tests/$group" -maxdepth 1 -name '[0-9][0-9][0-9]' | wc -l)
if ((passed + failed + not_run < expected || expected == 0)); then
	echo "BLKTESTS_ABNORMAL=results-$((passed + failed + not_run))-of-$expected"
	exit 1
fi
if ((rc != 0 && failed == 0)); then
	echo "BLKTESTS_ABNORMAL=check-status-$rc"
	exit 1
fi
exit 0
