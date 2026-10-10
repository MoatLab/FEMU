#!/bin/bash
# Boot a FEMU guest for each conformance suite, run the suite inside it and
# collect the results. Each suite gets a fresh copy-on-write overlay of the
# guest image, so the image itself does not change.
#
#   ./guest-conformance.sh [options] SUITE...
#
# Suites:
#   blktests-block  blktests "block" group on a BlackBox SSD
#   blktests-zbd    blktests "zbd" group on a ZNS SSD
#   nvme-cli        the nvme-cli end-to-end suite on a BlackBox SSD with the
#                   optional NVM commands and a volatile write cache on
#   all             the three above
#
# The guest is the one make-guest-image.sh builds: user femu, an SSH key,
# and passwordless sudo. The suites fetch their sources and packages, so
# the guest needs network access through QEMU's user networking. A suite
# takes 10 to 40 minutes.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

imgdir=${IMGDIR:-${HOME:?HOME is not set}/images}
qemu=${QEMU:-./qemu-system-x86_64}
image=${OSIMGF:-$imgdir/u20s.qcow2}
ssh_key=${SSH_KEY:-$imgdir/femu-guest-key}
ssh_port=${SSH_PORT:-8090}
outdir=""
suite_timeout=3600
boot_timeout=300
use_sudo=0
keep=0
suites=()

bb_dev="devsz_mb=768,namespaces=1,femu_mode=1,secsz=512,secs_per_pg=8"
bb_dev+=",pgs_per_blk=256,blks_per_pl=64,pls_per_lun=1,luns_per_ch=4,nchs=4"
zns_dev="devsz_mb=1024,namespaces=1,femu_mode=3,secsz=512,secs_per_pg=8"
zns_dev+=",pgs_per_blk=256,blks_per_pl=64,pls_per_lun=1,luns_per_ch=4,nchs=4"
# Compare, Write Uncorrectable, Dataset Management, Write Zeroes,
# Save/Select, Verify and Copy (0x19f), plus Flush through vwc=1.
cli_dev="$bb_dev,oncs=415,vwc=1"

usage() {
	cat <<EOF
Usage: $(basename "$0") [options] SUITE...

Run blktests and the nvme-cli end-to-end suite in a FEMU guest.
SUITE is blktests-block, blktests-zbd, nvme-cli or all.

Options:
  --qemu PATH       qemu-system-x86_64 to run (default: \$QEMU or
                    ./qemu-system-x86_64)
  --image FILE      guest image (default: \$OSIMGF or \$IMGDIR/u20s.qcow2)
  --key FILE        SSH private key (default: \$SSH_KEY or
                    \$IMGDIR/femu-guest-key)
  --port N          host port forwarded to the guest's SSH port
                    (default: \$SSH_PORT or 8090)
  --outdir DIR      result directory (default: ./conformance-DATE-TIME)
  --timeout SEC     time limit of one suite (default: 3600)
  --boot-timeout SEC  time limit for the guest to answer SSH (default: 300)
  --sudo            start QEMU with sudo (default: as you; needs /dev/kvm)
  --keep            keep each suite's overlay image
  -h, --help        show this help

BLKTESTS_REPO, BLKTESTS_REF, NVMECLI_REPO and NVMECLI_REF are passed on
to the guest scripts when set.
Exit status: 0 if every suite passed, 1 if a suite failed, 2 on a usage
or setup error and no suite failed.
EOF
}

die() {
	echo "guest-conformance: $*" >&2
	exit 2
}

while [[ $# -gt 0 ]]; do
	case $1 in
	--qemu) qemu=${2:?--qemu needs a path}; shift 2 ;;
	--image) image=${2:?--image needs a file}; shift 2 ;;
	--key) ssh_key=${2:?--key needs a file}; shift 2 ;;
	--port) ssh_port=${2:?--port needs a number}; shift 2 ;;
	--outdir) outdir=${2:?--outdir needs a directory}; shift 2 ;;
	--timeout) suite_timeout=${2:?--timeout needs seconds}; shift 2 ;;
	--boot-timeout) boot_timeout=${2:?--boot-timeout needs seconds}; shift 2 ;;
	--sudo) use_sudo=1; shift ;;
	--keep) keep=1; shift ;;
	-h | --help) usage; exit 0 ;;
	-*) usage >&2; die "unknown option $1" ;;
	all) suites+=(blktests-block blktests-zbd nvme-cli); shift ;;
	blktests-block | blktests-zbd | nvme-cli) suites+=("$1"); shift ;;
	*) usage >&2; die "unknown suite $1" ;;
	esac
done

((${#suites[@]} > 0)) || { usage >&2; die "name at least one suite"; }
[[ -x $qemu ]] || die "QEMU binary not found: $qemu (use --qemu)"
[[ -r $image ]] || die "guest image not found: $image (build one with make-guest-image.sh)"
[[ -r $ssh_key ]] || die "SSH key not found: $ssh_key (use --key)"
[[ $ssh_port =~ ^[0-9]+$ ]] || die "bad port: $ssh_port"
for tool in qemu-img ssh scp timeout; do
	command -v "$tool" >/dev/null || die "$tool is not installed"
done
for f in blktests-guest.sh nvme-cli-e2e-guest.sh; do
	[[ -r $SCRIPT_DIR/$f ]] || die "missing $SCRIPT_DIR/$f"
done

outdir=${outdir:-./conformance-$(date +%Y%m%d-%H%M%S)}
mkdir -p "$outdir"
outdir=$(cd "$outdir" && pwd)
image=$(cd "$(dirname "$image")" && pwd)/$(basename "$image")

ssh_opts=(
	-o StrictHostKeyChecking=no
	-o UserKnownHostsFile=/dev/null
	-o LogLevel=ERROR
	-o ConnectTimeout=8
	-o BatchMode=yes
	-o IdentitiesOnly=yes
	-i "$ssh_key"
)

qemu_pid=""

# With --sudo, QEMU runs as root, so the checks and signals go through sudo
# too; ps or kill -0 as the user can fail on a root process.
as_owner() {
	if ((use_sudo)); then
		sudo "$@"
	else
		"$@"
	fi
}

alive() {
	[[ -n $qemu_pid ]] && as_owner kill -0 "$qemu_pid" 2>/dev/null
}

stop_guest() {
	if alive; then
		as_owner kill "$qemu_pid" 2>/dev/null || true
		for _ in {1..20}; do
			alive || break
			sleep 0.5
		done
		alive && as_owner kill -9 "$qemu_pid" 2>/dev/null
	fi
	qemu_pid=""
}
trap stop_guest EXIT
trap 'exit 130' INT TERM

guest_ssh() {
	ssh "${ssh_opts[@]}" -p "$ssh_port" femu@localhost "$@"
}

# Start the guest with one FEMU device and wait for SSH; leave the QEMU PID
# in qemu_pid. Every step checks its own status: the caller runs this
# function in a condition, where set -e does not apply.
start_guest() {
	local name=$1 dev=$2 overlay=$3
	local pidfile=$outdir/$name.pid
	# A nonce in an SMBIOS OEM string tells this guest from another guest
	# that answers on the same port.
	local nonce
	nonce="femu-conformance-$$-$RANDOM$RANDOM"
	local -a cmd=()

	if ss -ltn 2>/dev/null | grep -q ":$ssh_port "; then
		echo "$name: port $ssh_port is in use (use --port)"
		return 2
	fi
	if [[ -e $overlay || -e $pidfile ]]; then
		echo "$name: $overlay or $pidfile exists (use another --outdir)"
		return 2
	fi
	qemu-img create -q -f qcow2 -b "$image" -F qcow2 "$overlay" || {
		echo "$name: cannot create $overlay"
		return 2
	}
	((use_sudo)) && cmd+=(sudo)
	cmd+=("$qemu" -name "femu-conformance-$name" -enable-kvm -cpu host
		-smp 4 -m 4G -pidfile "$pidfile"
		-smbios "type=11,value=$nonce"
		-device "virtio-scsi-pci,id=scsi0" -device "scsi-hd,drive=hd0"
		-drive "file=$overlay,if=none,cache=none,format=qcow2,id=hd0"
		-device "femu,$dev"
		-net "user,hostfwd=tcp:127.0.0.1:$ssh_port-:22"
		-net "nic,model=virtio"
		-display none -monitor none
		-serial "file:$outdir/$name.serial.log")
	"${cmd[@]}" >"$outdir/$name.qemu.log" 2>&1 </dev/null &
	local launcher=$!

	local deadline=$((SECONDS + boot_timeout))
	while [[ ! -s $pidfile ]]; do
		if ! as_owner kill -0 "$launcher" 2>/dev/null || ((SECONDS >= deadline)); then
			echo "$name: QEMU did not start; see $outdir/$name.qemu.log"
			tail -3 "$outdir/$name.qemu.log"
			return 2
		fi
		sleep 0.5
	done
	# QEMU creates the PID file with mode 0600, so read it as its owner.
	qemu_pid=$(as_owner cat "$pidfile") || return 2

	while ((SECONDS < deadline)); do
		if ! alive; then
			echo "$name: QEMU exited; see $outdir/$name.qemu.log"
			tail -3 "$outdir/$name.qemu.log"
			return 2
		fi
		if guest_ssh true 2>/dev/null; then
			if guest_ssh sudo grep -qaF "$nonce" /sys/firmware/dmi/entries/11-0/raw; then
				return 0
			fi
			echo "$name: port $ssh_port answers for another guest (use --port)"
			return 2
		fi
		sleep 3
	done
	echo "$name: no SSH answer within ${boot_timeout}s"
	return 2
}

# Return 0 when the suite passed, 1 when it failed, 2 on a setup error.
run_suite() {
	local name=$1 dev script
	local -a args=() envs=()

	case $name in
	blktests-block) dev=$bb_dev; script=blktests-guest.sh; args=(block) ;;
	blktests-zbd) dev=$zns_dev; script=blktests-guest.sh; args=(zbd) ;;
	nvme-cli) dev=$cli_dev; script=nvme-cli-e2e-guest.sh ;;
	esac
	for v in BLKTESTS_REPO BLKTESTS_REF NVMECLI_REPO NVMECLI_REF; do
		[[ -n ${!v:-} ]] && envs+=("$v=${!v}")
	done

	local overlay=$outdir/$name.qcow2 log=$outdir/$name.log rc=0
	local remote_script=/tmp/femu-conformance-$$-$script
	echo "=== $name: device femu,$dev"
	start_guest "$name" "$dev" "$overlay" || { stop_guest; return 2; }
	if ! scp "${ssh_opts[@]}" -P "$ssh_port" "$SCRIPT_DIR/$script" \
		"femu@localhost:$remote_script" >/dev/null; then
		echo "$name: cannot copy $script into the guest"
		stop_guest
		return 2
	fi
	# ssh joins its arguments into one remote command; quote each word.
	local remote
	remote=$(printf '%q ' sudo env "${envs[@]}" bash "$remote_script" "${args[@]}")
	timeout "$suite_timeout" ssh "${ssh_opts[@]}" -p "$ssh_port" \
		femu@localhost "$remote" >"$log" 2>&1 || rc=$?
	stop_guest
	((keep)) || rm -f "$overlay"

	grep -E '^(BLKTESTS_COMMIT|NVMECLI_COMMIT|PASSED|TAP_PLAN|TAP_OK|TAP_NOT_OK|FAILED_TEST|KNOWN_DEFECT|E2E_SETUP|BLKTESTS_SETUP|BLKTESTS_ABNORMAL|E2E_ABNORMAL)' \
		"$log" || true
	case $rc in
	0 | 1 | 2) ;;
	124) echo "$name: no result within ${suite_timeout}s"; rc=1 ;;
	255) echo "$name: SSH to the guest failed"; rc=2 ;;
	*) echo "$name: the guest script ended with status $rc"; rc=1 ;;
	esac
	if grep -aqE 'ERROR: AddressSanitizer|runtime error:|Assertion .* failed' \
		"$outdir/$name.qemu.log"; then
		echo "$name: QEMU reported a sanitizer error or an assertion"
		rc=1
	fi
	echo "$name: status $rc (log $log)"
	return "$rc"
}

failed=0
setup_failed=0
for s in "${suites[@]}"; do
	rc=0
	run_suite "$s" || rc=$?
	case $rc in
	0) echo "RESULT $s PASS" ;;
	2) echo "RESULT $s SETUP-ERROR"; setup_failed=1 ;;
	*) echo "RESULT $s FAIL"; failed=1 ;;
	esac
done
echo "results in $outdir"
if ((failed)); then
	exit 1
elif ((setup_failed)); then
	exit 2
fi
exit 0
