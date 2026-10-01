#!/bin/bash
# Build a ready-to-use FEMU guest image from the Ubuntu 24.04 cloud image.
#
# The image boots with a serial console, has user "femu" with an SSH key and
# passwordless sudo, and carries nvme-cli and fio. The run-*.sh launchers look
# for $IMGDIR/u20s.qcow2, so that is the default output name.
#
# All files, including the download cache, are written to the output
# directory. No root access is needed; the user must be able to open /dev/kvm.

set -euo pipefail

readonly RELEASE_URL="https://cloud-images.ubuntu.com/releases/noble/release"
readonly CLOUD_IMG="ubuntu-24.04-server-cloudimg-amd64.img"
readonly KEYRING="/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg"
readonly READY_MARK="FEMU-GUEST-IMAGE-READY"
readonly FAIL_MARK="FEMU-GUEST-IMAGE-FAILED"

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

outdir=${IMGDIR:-${HOME:?HOME is not set}/images}
name="u20s.qcow2"
size="32G"
ssh_pubkey=""
password=""
with_cxl=0
extra_pkgs=()
qemu=${QEMU:-}
qemu_img=${QEMU_IMG:-}
use_kvm=1
force=0
timeout_s=1800
iso_tool=""

usage() {
	cat <<EOF
Usage: $(basename "$0") [options]

Build an Ubuntu 24.04 guest image for FEMU.

Options:
  -o, --outdir DIR      output directory (default: \$IMGDIR or \$HOME/images)
  -n, --name FILE       image file name (default: u20s.qcow2, which the
                        run-*.sh scripts expect)
  -s, --size SIZE       virtual disk size, qemu-img syntax (default: 32G)
  -k, --ssh-key FILE    public key to authorize for user femu (default:
                        generate DIR/femu-guest-key and use its .pub)
  -p, --password PW     also set a password for femu (for console login)
      --cxl             also install ndctl, daxctl and cxl-cli
      --packages LIST   extra comma-separated Ubuntu packages to install
      --qemu PATH       qemu-system-x86_64 to run provisioning with
      --qemu-img PATH   qemu-img to use
      --no-kvm          provision without KVM (much slower)
      --timeout SEC     provisioning time limit (default: 1800)
  -f, --force           replace an existing output image
  -h, --help            show this help

After it finishes, start FEMU with a run-*.sh script and log in with:
  ssh -i DIR/femu-guest-key -p 8080 femu@localhost
EOF
}

die() {
	echo "error: $*" >&2
	exit 1
}

info() {
	echo "==> $*"
}

parse_args() {
	while (( $# > 0 )); do
		case "$1" in
		-o|--outdir) outdir=${2:?missing value for $1}; shift ;;
		-n|--name) name=${2:?missing value for $1}; shift ;;
		-s|--size) size=${2:?missing value for $1}; shift ;;
		-k|--ssh-key) ssh_pubkey=${2:?missing value for $1}; shift ;;
		-p|--password) password=${2:?missing value for $1}; shift ;;
		--cxl) with_cxl=1 ;;
		--packages)
			local list=${2:?missing value for $1}
			local -a more
			IFS=',' read -r -a more <<< "$list"
			extra_pkgs+=("${more[@]}")
			shift
			;;
		--qemu) qemu=${2:?missing value for $1}; shift ;;
		--qemu-img) qemu_img=${2:?missing value for $1}; shift ;;
		--no-kvm) use_kvm=0 ;;
		--timeout) timeout_s=${2:?missing value for $1}; shift ;;
		-f|--force) force=1 ;;
		-h|--help) usage; exit 0 ;;
		*) usage >&2; die "unknown option: $1" ;;
		esac
		shift
	done
	[[ "$name" != */* ]] || die "--name takes a file name, not a path"
	[[ "$timeout_s" =~ ^[0-9]+$ ]] || die "--timeout takes a number of seconds"
	local p
	for p in "${extra_pkgs[@]}"; do
		[[ "$p" =~ ^[a-z0-9][a-z0-9.+-]*$ ]] || die "bad package name: '$p'"
	done
}

# Find a QEMU binary: an explicit path, then one next to this script (the
# build directory after femu-copy-scripts.sh), then the repository build
# directory, then $PATH.
find_tool() {
	local tool=$1
	local c
	for c in "$SCRIPT_DIR/$tool" "$SCRIPT_DIR/../../../build/$tool"; do
		if [[ -x "$c" ]]; then
			echo "$c"
			return 0
		fi
	done
	command -v "$tool" || true
}

check_host() {
	local -a missing=()
	local t
	for t in curl sha256sum ssh-keygen timeout; do
		command -v "$t" > /dev/null || missing+=("$t")
	done

	[[ -n "$qemu" ]] || qemu=$(find_tool qemu-system-x86_64)
	[[ -n "$qemu_img" ]] || qemu_img=$(find_tool qemu-img)
	[[ -n "$qemu" && -x "$qemu" ]] || missing+=("qemu-system-x86_64")
	[[ -n "$qemu_img" && -x "$qemu_img" ]] || missing+=("qemu-img")

	if command -v cloud-localds > /dev/null; then
		iso_tool=cloud-localds
	elif command -v genisoimage > /dev/null; then
		iso_tool=genisoimage
	elif command -v xorriso > /dev/null; then
		iso_tool=xorriso
	elif command -v mkisofs > /dev/null; then
		iso_tool=mkisofs
	else
		missing+=("cloud-localds or genisoimage or xorriso or mkisofs")
	fi

	if (( ${#missing[@]} > 0 )); then
		echo "error: missing host tools:" >&2
		printf '  %s\n' "${missing[@]}" >&2
		echo "On Debian/Ubuntu: sudo apt install curl cloud-image-utils" \
		     "qemu-utils openssh-client" >&2
		echo "qemu-system-x86_64 can be the FEMU build; pass --qemu PATH." >&2
		exit 1
	fi

	if (( use_kvm )); then
		[[ -r /dev/kvm && -w /dev/kvm ]] ||
			die "cannot open /dev/kvm; add yourself to the kvm group" \
			    "(sudo usermod -aG kvm \"\$USER\", then log in again)" \
			    "or pass --no-kvm"
	fi
}

download_base() {
	local cache=$1
	local sums="$cache/SHA256SUMS"

	mkdir -p "$cache"
	info "fetching $RELEASE_URL/SHA256SUMS"
	curl -fsSL --retry 3 -o "$sums" "$RELEASE_URL/SHA256SUMS"

	if command -v gpgv > /dev/null && [[ -r "$KEYRING" ]]; then
		curl -fsSL --retry 3 -o "$sums.gpg" "$RELEASE_URL/SHA256SUMS.gpg"
		gpgv --keyring "$KEYRING" "$sums.gpg" "$sums" 2> /dev/null ||
			die "SHA256SUMS signature check failed"
		info "SHA256SUMS signature verified"
	else
		info "gpgv or $KEYRING not found; skipping the signature check"
	fi

	local want
	want=$(awk -v f="*$CLOUD_IMG" '$2 == f { print $1 }' "$sums")
	[[ "$want" =~ ^[0-9a-f]{64}$ ]] || die "$CLOUD_IMG not listed in SHA256SUMS"

	local img="$cache/$CLOUD_IMG"
	if [[ -f "$img" ]] && [[ $(sha256sum "$img" | cut -d' ' -f1) == "$want" ]]; then
		info "using cached $img"
		return 0
	fi

	info "downloading $CLOUD_IMG"
	curl -fL --progress-bar --retry 3 -o "$img.part" "$RELEASE_URL/$CLOUD_IMG"
	local got
	got=$(sha256sum "$img.part" | cut -d' ' -f1)
	if [[ "$got" != "$want" ]]; then
		rm -f "$img.part"
		die "SHA256 mismatch for $CLOUD_IMG (got $got, want $want)"
	fi
	mv "$img.part" "$img"
	info "SHA256 verified: $want"
}

ensure_key() {
	if [[ -n "$ssh_pubkey" ]]; then
		[[ -r "$ssh_pubkey" ]] || die "cannot read SSH key $ssh_pubkey"
		return 0
	fi
	local key="$outdir/femu-guest-key"
	if [[ ! -f "$key" ]]; then
		info "generating SSH key $key"
		ssh-keygen -q -t ed25519 -N "" -C "femu-guest" -f "$key"
	fi
	ssh_pubkey="$key.pub"
}

write_seed() {
	local work=$1
	local seed=$2
	local -a pkgs=(nvme-cli fio)
	if (( with_cxl )); then
		pkgs+=(ndctl daxctl cxl)
	fi
	pkgs+=("${extra_pkgs[@]}")

	local pub
	pub=$(head -n1 "$ssh_pubkey")
	[[ "$pub" == ssh-* || "$pub" == ecdsa-* ]] || die "$ssh_pubkey is not an SSH public key"

	local pw_lines="    lock_passwd: true"
	if [[ -n "$password" ]]; then
		local q="'"
		pw_lines="    lock_passwd: false
    plain_text_passwd: $q${password//$q/$q$q}$q"
	fi

	{
		cat <<EOF
#cloud-config
hostname: femu-guest
users:
  - name: femu
    shell: /bin/bash
    groups: [sudo]
    sudo: "ALL=(ALL) NOPASSWD:ALL"
$pw_lines
    ssh_authorized_keys:
      - $pub
ssh_pwauth: false
package_update: true
package_upgrade: false
packages:
EOF
		local p
		for p in "${pkgs[@]}"; do
			echo "  - $p"
		done
		cat <<EOF
write_files:
  - path: /etc/default/grub.d/90-femu-serial.cfg
    content: |
      GRUB_CMDLINE_LINUX_DEFAULT="console=tty1 console=ttyS0,115200n8"
      GRUB_TERMINAL="console serial"
      GRUB_SERIAL_COMMAND="serial --unit=0 --speed=115200"
      GRUB_TIMEOUT=1
      GRUB_TIMEOUT_STYLE=menu
runcmd:
  - [ update-grub ]
  - [ systemctl, disable, systemd-networkd-wait-online.service ]
  - [ touch, /etc/cloud/cloud-init.disabled ]
  - [ sh, -c, 'if command -v nvme && command -v fio; then echo $READY_MARK > /dev/ttyS0; else echo $FAIL_MARK > /dev/ttyS0; fi' ]
power_state:
  mode: poweroff
  condition: true
EOF
	} > "$work/user-data"

	printf 'instance-id: femu-guest-1\nlocal-hostname: femu-guest\n' > "$work/meta-data"

	# Match every wired NIC by name so the image keeps its network when the
	# MAC address or PCI slot changes.
	cat > "$work/network-config" <<EOF
version: 2
ethernets:
  wired:
    match:
      name: "en*"
    dhcp4: true
EOF

	rm -f "$seed"
	case "$iso_tool" in
	cloud-localds)
		cloud-localds -N "$work/network-config" "$seed" \
			"$work/user-data" "$work/meta-data"
		;;
	genisoimage|mkisofs)
		"$iso_tool" -quiet -output "$seed" -volid cidata -joliet -rock \
			"$work/user-data" "$work/meta-data" "$work/network-config"
		;;
	xorriso)
		xorriso -as mkisofs -quiet -output "$seed" -volid cidata -joliet -rock \
			"$work/user-data" "$work/meta-data" "$work/network-config" \
			2> /dev/null
		;;
	esac
}

provision() {
	local disk=$1
	local seed=$2
	local log=$3
	local -a accel=(-machine "q35,accel=tcg" -cpu max)
	if (( use_kvm )); then
		accel=(-machine "q35,accel=kvm" -cpu host)
	fi

	info "provisioning (log: $log); this takes a few minutes"
	local rc=0
	timeout -k 10 "$timeout_s" "$qemu" \
		-name femu-guest-provision \
		"${accel[@]}" -smp 2 -m 2G \
		-nodefaults -display none -no-reboot \
		-serial "file:$log" \
		-drive "file=$disk,if=virtio,format=qcow2" \
		-drive "file=$seed,if=virtio,format=raw,readonly=on" \
		-netdev user,id=net0 -device virtio-net-pci,netdev=net0 ||
		rc=$?

	if (( rc == 124 )); then
		die "provisioning did not finish in ${timeout_s}s; see $log"
	elif (( rc != 0 )); then
		die "QEMU exited with status $rc; see $log"
	fi
	if grep -aq "$FAIL_MARK" "$log"; then
		die "package installation failed in the guest; see $log"
	fi
	grep -aq "$READY_MARK" "$log" ||
		die "guest powered off before provisioning finished; see $log"
}

main() {
	parse_args "$@"
	check_host

	mkdir -p "$outdir"
	outdir=$(cd "$outdir" && pwd)
	local out="$outdir/$name"
	if [[ -e "$out" ]] && (( ! force )); then
		die "$out exists; pass --force to replace it"
	fi

	local cache="$outdir/cache"
	local work="$outdir/.make-guest-image"
	local disk="$work/$name"
	local seed="$outdir/seed.iso"
	local log="$outdir/provision.log"

	download_base "$cache"
	ensure_key
	mkdir -p "$work"
	write_seed "$work" "$seed"

	info "creating $size disk"
	rm -f "$disk"
	"$qemu_img" convert -q -O qcow2 "$cache/$CLOUD_IMG" "$disk"
	"$qemu_img" resize -q "$disk" "$size"

	local start=$SECONDS
	provision "$disk" "$seed" "$log"
	info "provisioned in $(( SECONDS - start ))s"

	mv -f "$disk" "$out"
	rm -f "$work/user-data" "$work/meta-data" "$work/network-config"
	rmdir "$work" 2> /dev/null || true

	local key_hint=""
	if [[ "$ssh_pubkey" == "$outdir/femu-guest-key.pub" ]]; then
		key_hint="-i $outdir/femu-guest-key "
	fi
	cat <<EOF

Image ready: $out
Start FEMU, for example:  OSIMGF=$out ./run-blackbox.sh
Log in from the host:     ssh ${key_hint}-p 8080 femu@localhost
EOF
}

main "$@"
