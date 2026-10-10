#!/bin/bash
# Build nvme-cli inside a FEMU guest and run its end-to-end test suite.
#
#   sudo bash nvme-cli-e2e-guest.sh [CONTROLLER [NAMESPACE]]
#
# CONTROLLER and NAMESPACE default to /dev/nvme0 and /dev/nvme0n1. The
# script installs the build tools with apt-get and clones nvme-cli, so the
# guest needs network access. The suite writes to NAMESPACE and can format
# it.
#
# Environment:
#   NVMECLI_REPO     git URL (default https://github.com/linux-nvme/nvme-cli.git)
#   NVMECLI_REF      branch or tag (default v3.1)
#   E2E_TIMEOUT      time limit of the suite in seconds (default 2400)
#   WORKDIR          parent of the new scratch directory (default /tmp)
#
# One test has a known defect in nvme-cli v3.1: test_get_lba_status passes
# the namespace device path as --namespace-id. When it fails, the script
# runs the same command with the numeric namespace ID. If that command
# passes, the failure counts as KNOWN_DEFECT; if it fails, as FAILED_TEST.
#
# Summary lines: E2E_WORKDIR, NVMECLI_COMMIT, NVME_VERSION, TAP_PLAN,
# TAP_OK, TAP_NOT_OK, the "not ok" and SKIP lines, one FAILED_TEST or KNOWN_DEFECT
# line per failed test, the report's MESSAGE lines, then E2E_DONE. The exit
# status is 0 when no test failed, 1 when one did or the suite ended
# abnormally, and 2 when the setup failed.

set -euo pipefail

usage() {
	echo "usage: sudo bash $(basename "$0") [CONTROLLER [NAMESPACE]]" >&2
	exit 2
}

[[ $# -le 2 ]] || usage
[[ ${1:-} == -h || ${1:-} == --help ]] && usage
ctrl=${1:-/dev/nvme0}
ns=${2:-/dev/nvme0n1}
repo=${NVMECLI_REPO:-https://github.com/linux-nvme/nvme-cli.git}
ref=${NVMECLI_REF:-v3.1}
tmo=${E2E_TIMEOUT:-2400}
parent=${WORKDIR:-/tmp}

setup_fail() {
	echo "E2E_SETUP=$1"
	exit 2
}

[[ $EUID -eq 0 ]] || setup_fail not-root
[[ -c $ctrl ]] || setup_fail "no-controller-$ctrl"
[[ -b $ns ]] || setup_fail "no-namespace-$ns"

export DEBIAN_FRONTEND=noninteractive
apt-get -qq update >/dev/null 2>&1 || setup_fail apt-update
apt-get -qq install -y build-essential meson ninja-build pkg-config \
	libjson-c-dev python3 git uuid-dev libdbus-1-dev >/dev/null 2>&1 ||
	setup_fail apt-install

workdir=$(mktemp -d "$parent/femu-nvme-cli.XXXXXX") || setup_fail mktemp
echo "E2E_WORKDIR=$workdir"
src=$workdir/nvme-cli
nvme=$src/.build/nvme
tap=$workdir/e2e.tap
report=$workdir/e2e.json
git -c advice.detachedHead=false clone -q --depth 1 --branch "$ref" "$repo" "$src" || setup_fail clone
echo "NVMECLI_COMMIT=$(git -C "$src" rev-parse --short HEAD)"
meson setup "$src/.build" "$src" >"$workdir/setup.log" 2>&1 || {
	tail -20 "$workdir/setup.log"
	setup_fail meson
}
ninja -C "$src/.build" >"$workdir/build.log" 2>&1 || {
	tail -20 "$workdir/build.log"
	setup_fail build
}
echo "NVME_VERSION=$("$nvme" version | head -1)"

rc=0
(cd "$src" && timeout "$tmo" python3 tests/nvme-cli-e2e \
	--controller "$ctrl" --ns1 "$ns" --nvme-bin "$nvme" \
	--plugins=none --json-report "$report") >"$tap" 2>&1 || rc=$?
echo "E2E_RC=$rc"

ok=$(grep -cE '^ok ' "$tap" || true)
not_ok=$(grep -cE '^not ok ' "$tap" || true)
plan=$(sed -nE 's/^1\.\.([0-9]+).*/\1/p' "$tap" | head -1)
echo "TAP_PLAN=${plan:-none}"
echo "TAP_OK=$ok"
echo "TAP_NOT_OK=$not_ok"
grep -E '^not ok |# SKIP' "$tap" | cut -c1-150 | head -40 || true

# Run the command of test_get_lba_status with the numeric namespace ID.
# Success shows that the test failed on its own defect, not on FEMU.
lba_status_works() {
	local nsid
	nsid=$("$nvme" get-ns-id "$ns" | sed -nE 's/.*namespace-id:[[:space:]]*([0-9]+).*/\1/p')
	[[ -n $nsid ]] || return 1
	"$nvme" get-lba-status "$ctrl" --namespace-id="$nsid" --start-lba=0 \
		--max-dw=1 --action=17 --range-len=1 >/dev/null
}

# The TAP lines decide the result; the JSON report adds the messages.
unexpected=0
mapfile -t failed < <(sed -nE 's/^not ok [0-9]+ - ([A-Za-z0-9_]+).*/\1/p' "$tap")
for t in "${failed[@]}"; do
	if [[ $t == test_get_lba_status ]] && lba_status_works; then
		echo "KNOWN_DEFECT=$t (passes with the numeric namespace ID)"
	else
		echo "FAILED_TEST=$t"
		unexpected=1
	fi
done

python3 - "$report" <<'PY' || true
import json
import sys

try:
    with open(sys.argv[1]) as f:
        r = json.load(f)
except (OSError, ValueError) as e:
    print("JSON_REPORT_MISSING", e)
    raise SystemExit
tests = r.get("tests", []) if isinstance(r, dict) else r
for t in tests:
    if t.get("outcome") not in ("passed", "pass", "ok", "skipped", "skip"):
        msg = (t.get("message") or "")[-400:].replace("\n", " ")
        print("MESSAGE", t.get("name"), "|", msg)
PY
echo E2E_DONE

# The suite exits 0 also when a test fails, so any other status, a
# timeout included, means it ended abnormally. So does a run whose result
# count differs from the TAP plan.
if [[ -z $plan ]] || ((ok + not_ok != plan || plan == 0)); then
	echo "E2E_ABNORMAL=results-$((ok + not_ok))-plan-${plan:-none}"
	exit 1
fi
if ((unexpected || rc != 0)); then
	exit 1
fi
exit 0
