#!/bin/bash
# Build a ready-to-use FEMU guest image from the Ubuntu 24.04 cloud image.
#
# The image boots with a serial console, has user "femu" with an SSH key and
# passwordless sudo, and carries nvme-cli and fio. The run-*.sh launchers look
# for $IMGDIR/u20s.qcow2, so that is the default output name.
#
# The base image is a pinned serial with a pinned SHA-256. --kernel installs
# an Ubuntu ABI kernel or a mainline build. A second boot, with the disk on
# virtio-scsi as the launchers attach it, checks the kernel and the tools.
# The result is a standalone qcow2 with a .sha256 and a .manifest.
#
# All files, including the download cache, are written to the output
# directory. No root access is needed; the user must be able to open /dev/kvm.

set -euo pipefail

readonly SERIES_URL="https://cloud-images.ubuntu.com/releases/noble"
readonly CLOUD_IMG="ubuntu-24.04-server-cloudimg-amd64.img"
# Move these three together: the serial folder lists the digest, and its
# .manifest names the kernel.
readonly PIN_SERIAL="20261017"
readonly PIN_SHA256="04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94"
readonly PIN_KERNEL="6.8.0-147-generic"
readonly MAINLINE_URL="https://kernel.ubuntu.com/mainline"
readonly KEYRING="/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg"
readonly READY_MARK="FEMU-GUEST-IMAGE-READY"
readonly FAIL_MARK="FEMU-GUEST-IMAGE-FAILED"
readonly CHECK_MARK="FEMU-GUEST-CHECK"

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
kernel="distro"
kernel_kind="distro"
kernel_rel=""
kernel_debs=()
base_serial="$PIN_SERIAL"
base_sha256=""
base_sha_set=0
cache=""
compress=0
self_test=0
check_fields=""

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
      --kernel VERSION  guest kernel: distro (default, the cloud image
                        kernel), an Ubuntu ABI such as 6.8.0-31, or a
                        mainline version such as 6.12.40 or 6.13-rc3
      --base-serial S   cloud image serial, YYYYMMDD[.N], or latest
                        (default: $PIN_SERIAL, pinned)
      --base-sha256 HEX SHA-256 the cloud image must have
      --cache DIR       download cache (default: DIR/cache)
      --compress        write a compressed qcow2
      --cxl             also install ndctl, daxctl and cxl-cli
      --packages LIST   extra comma-separated Ubuntu packages to install
      --qemu PATH       qemu-system-x86_64 to run provisioning with
      --qemu-img PATH   qemu-img to use
      --no-kvm          provision without KVM (much slower)
      --timeout SEC     time limit of each boot (default: 1800)
  -f, --force           replace an existing output image
      --self-test       check the parsers and the GRUB entry choice, then exit
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

# Sets kernel_kind (distro, abi, mainline) and, for an ABI, kernel_rel.
classify_kernel() {
    local v=$1
    if [[ "$v" == distro ]]; then
        kernel_kind=distro
    elif [[ "$v" =~ ^[1-9][0-9]?\.[0-9]{1,2}\.[0-9]{1,3}-[0-9]{1,4}$ ]]; then
        kernel_kind=abi
        kernel_rel="$v-generic"
    elif [[ "$v" =~ ^[1-9][0-9]?\.[0-9]{1,2}(\.[0-9]{1,3})?(-rc[0-9]{1,2})?$ ]]; then
        kernel_kind=mainline
    else
        die "--kernel takes distro, an Ubuntu ABI (6.8.0-31)" \
            "or a mainline version (6.12.40), not '$v'"
    fi
}

parse_args() {
    while (( $# > 0 )); do
        case "$1" in
        -o|--outdir) outdir=${2:?missing value for $1}; shift ;;
        -n|--name) name=${2:?missing value for $1}; shift ;;
        -s|--size) size=${2:?missing value for $1}; shift ;;
        -k|--ssh-key) ssh_pubkey=${2:?missing value for $1}; shift ;;
        -p|--password) password=${2:?missing value for $1}; shift ;;
        --kernel) [[ $# -ge 2 ]] || die "missing value for $1"; kernel=$2; shift ;;
        --base-serial) base_serial=${2:?missing value for $1}; shift ;;
        --base-sha256)
            [[ $# -ge 2 ]] || die "missing value for $1"
            base_sha256=$2 base_sha_set=1
            shift
            ;;
        --cache) cache=${2:?missing value for $1}; shift ;;
        --compress) compress=1 ;;
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
        --self-test) self_test=1 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "unknown option: $1" ;;
        esac
        shift
    done
    [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] ||
        die "--name takes a plain file name, not '$name'"
    [[ "$timeout_s" =~ ^[0-9]+$ ]] || die "--timeout takes a number of seconds"
    classify_kernel "$kernel"
    [[ "$base_serial" == latest || "$base_serial" =~ ^20[0-9]{6}(\.[0-9]{1,2})?$ ]] ||
        die "--base-serial takes YYYYMMDD, YYYYMMDD.N or latest, not '$base_serial'"
    (( ! base_sha_set )) || [[ "$base_sha256" =~ ^[0-9a-f]{64}$ ]] ||
        die "--base-sha256 takes 64 lower-case hex digits"
    local p
    for p in "${extra_pkgs[@]}"; do
        [[ "$p" =~ ^[a-z0-9][a-z0-9.+-]*$ ]] || die "bad package name: '$p'"
    done
}

# mainline_rel_ok VERSION RELEASE: RELEASE is a generic build of VERSION.
# 6.12.40 -> 6.12.40-061240-generic, 6.12 -> 6.12.0-061200-generic,
# 6.13-rc3 -> 6.13.0-061300rc3-generic.
mainline_rel_ok() {
    local v=$1 rel=$2 base rc=""
    base=${v%%-rc*}
    [[ "$v" == *-rc* ]] && rc=rc${v##*-rc}
    [[ "$base" =~ ^[0-9]+\.[0-9]+$ ]] && base=$base.0
    [[ "$rel" =~ ^${base//./\\.}-[0-9]{6,7}${rc}-generic$ ]]
}

# parse_checksums FILE VERSION: reads the Sha256 part of a mainline
# CHECKSUMS file and prints "RELEASE IMAGE-DEB IMAGE-SHA MODULES-DEB
# MODULES-SHA". Fails unless there is exactly one generic amd64 image deb
# and one modules deb, of one build of VERSION.
parse_checksums() {
    local f=$1 v=$2 sec=0 h n
    local -a imgs=() mods=()
    local img_re='^linux-image-unsigned-([0-9][^_/]*-generic)_([^_/]+)_amd64\.deb$'
    while read -r h n; do
        if [[ "$h" == "#" ]]; then
            [[ "$n" == "Checksums-Sha256:" ]] && sec=1
            [[ "$n" == Checksums-Sha1: ]] && sec=0
            continue
        fi
        (( sec )) || continue
        [[ "$h" =~ ^[0-9a-f]{64}$ ]] || continue
        n=${n#\*}
        if [[ "$n" =~ $img_re ]]; then
            imgs+=("${BASH_REMATCH[1]} ${BASH_REMATCH[2]} $n $h")
        elif [[ "$n" =~ ^linux-modules-([0-9][^_/]*-generic)_([^_/]+)_amd64\.deb$ ]]; then
            mods+=("${BASH_REMATCH[1]} ${BASH_REMATCH[2]} $n $h")
        fi
    done < "$f"
    (( ${#imgs[@]} == 1 )) ||
        { echo "want one amd64 image deb, found ${#imgs[@]}" >&2; return 1; }
    (( ${#mods[@]} == 1 )) ||
        { echo "want one amd64 modules deb, found ${#mods[@]}" >&2; return 1; }
    local -a a b
    read -r -a a <<< "${imgs[0]}"
    read -r -a b <<< "${mods[0]}"
    [[ "${a[0]} ${a[1]}" == "${b[0]} ${b[1]}" ]] ||
        { echo "image ${a[0]} ${a[1]} and modules ${b[0]} ${b[1]} differ" >&2; return 1; }
    mainline_rel_ok "$v" "${a[0]}" ||
        { echo "the debs hold ${a[0]}, not a build of $v" >&2; return 1; }
    echo "${a[0]} ${a[2]} ${a[3]} ${b[2]} ${b[3]}"
}

# check_line_ok LOG NONCE WANT: the check boot prints one record. WANT is
# the release uname -r must show; when empty, the guest's own "want"
# field is used. Prints "RELEASE NVME-CLI FIO" on success.
check_line_ok() {
    local log=$1 nonce=$2 want=$3
    local -a lines=()
    mapfile -t lines < <(sed 's/\r$//' "$log" | grep -a "^$CHECK_MARK " || true)
    (( ${#lines[@]} == 1 )) ||
        { echo "want one $CHECK_MARK line, found ${#lines[@]}" >&2; return 1; }
    local re="^$CHECK_MARK v=1 nonce=([^ ]+) kernel=([^ ]+) want=([^ ]+)"
    re+=" nvme-cli=([^ ]+) fio=([^ ]+) root=([a-z]+) status=([a-z-]+) end$"
    [[ "${lines[0]}" =~ $re ]] || { echo "bad check line: ${lines[0]}" >&2; return 1; }
    local nc=${BASH_REMATCH[1]} k=${BASH_REMATCH[2]} gw=${BASH_REMATCH[3]}
    local n=${BASH_REMATCH[4]} f=${BASH_REMATCH[5]}
    local r=${BASH_REMATCH[6]} st=${BASH_REMATCH[7]}
    [[ "$nc" == "$nonce" ]] ||
        { echo "the check line is from another boot ($nc)" >&2; return 1; }
    [[ "$st" == ok ]] || { echo "the guest check reports $st" >&2; return 1; }
    [[ -n "$want" ]] || want=$gw
    [[ "$want" != none && "$k" == "$want" ]] ||
        { echo "the guest runs $k, want $want" >&2; return 1; }
    [[ "$n" != none ]] || { echo "nvme-cli is missing in the guest" >&2; return 1; }
    [[ "$f" != none ]] || { echo "fio is missing in the guest" >&2; return 1; }
    [[ "$r" == rw ]] || { echo "the guest root file system is $r" >&2; return 1; }
    grep -aq 'reboot: Power down' "$log" ||
        { echo "the check boot did not power off cleanly" >&2; return 1; }
    echo "$k $n $f"
}

# The GRUB entry choice, as POSIX sh for the guest. femu_pick_entry CFG
# REL prints the GRUB_DEFAULT value of the one normal (not recovery)
# entry of REL: "SUBMENU>ENTRY", or ENTRY in a flat menu.
guest_grub_fn() {
    cat <<'EOS'
femu_pick_entry() {
    esc=$(printf '%s' "$2" | sed 's/[.]/[.]/g')
    n=$(grep -c "menuentry_id_option 'gnulinux-$esc-advanced-" "$1" || true)
    if [ "$n" != 1 ]; then
        echo "want one GRUB entry of $2, found $n" >&2
        return 1
    fi
    ent=$(sed -n "s/.*menuentry_id_option '\(gnulinux-$esc-advanced-[^']*\)'.*/\1/p" "$1")
    sub=$(sed -n \
        "s/^submenu .*menuentry_id_option '\(gnulinux-advanced-[^']*\)'.*/\1/p" "$1")
    case $sub in
    "") echo "$ent" ;;
    *"
"*) echo "more than one GRUB submenu" >&2; return 1 ;;
    *) echo "$sub>$ent" ;;
    esac
}
EOS
}

# Each planted bad input must fail, so a check that stops working fails here.
run_self_test() {
    local t bad=0 n=0
    t=$(mktemp -d)
    # shellcheck disable=SC2064
    trap "rm -rf '$t'" EXIT
    expect() {
        local want=$1 got=0
        shift
        n=$(( n + 1 ))
        ( "$@" ) > "$t/out" 2>&1 || got=1
        if [[ "$want" == ok && $got == 0 || "$want" == fail && $got == 1 ]]; then
            return 0
        fi
        bad=$(( bad + 1 ))
        echo "FAIL want $want: $*" >&2
        sed 's/^/  /' "$t/out" >&2
    }
    same() {
        n=$(( n + 1 ))
        [[ "$2" == "$3" ]] && return 0
        bad=$(( bad + 1 ))
        echo "FAIL $1: got '$2', want '$3'" >&2
    }
    local v
    for v in distro 6.8.0-31 6.12 6.12.40 6.13-rc3 5.10.274; do
        expect ok parse_args --kernel "$v"
    done
    for v in v6.12 6 6.12. "6.12;id" latest "" 6.8.0-31-generic "6.12 6.13"; do
        expect fail parse_args --kernel "$v"
    done
    same "ABI release" \
        "$(parse_args --kernel 6.8.0-31; echo "$kernel_kind $kernel_rel")" \
        "abi 6.8.0-31-generic"
    for v in 20261017 20240523.1 latest; do
        expect ok parse_args --base-serial "$v"
    done
    for v in 2026-10-17 release ../x 1999 ""; do
        expect fail parse_args --base-serial "$v"
    done
    expect ok parse_args --base-sha256 "$PIN_SHA256"
    expect fail parse_args --base-sha256 "${PIN_SHA256:1}"
    expect fail parse_args --base-sha256 "${PIN_SHA256^^}"
    expect fail parse_args --base-sha256 ""
    expect fail parse_args --name a/b
    expect fail parse_args --name .hidden
    expect fail parse_args --timeout 5m
    expect fail parse_args --packages "fio,a;b"

    expect ok mainline_rel_ok 6.12.40 6.12.40-061240-generic
    expect ok mainline_rel_ok 6.12 6.12.0-061200-generic
    expect ok mainline_rel_ok 6.13-rc3 6.13.0-061300rc3-generic
    expect ok mainline_rel_ok 5.10.274 5.10.274-0510274-generic
    expect fail mainline_rel_ok 6.12.4 6.12.40-061240-generic
    expect fail mainline_rel_ok 6.12 6.12.40-061240-generic
    expect fail mainline_rel_ok 6.13-rc3 6.13.0-061300rc2-generic
    expect fail mainline_rel_ok 6.12.40 6.12.40-061240-lowlatency

    local bv=6.12.40-061240.202507240748
    local i=linux-image-unsigned-6.12.40-061240-generic_${bv}_amd64.deb
    local m=linux-modules-6.12.40-061240-generic_${bv}_amd64.deb
    local h=linux-headers-6.12.40-061240-generic_${bv}_amd64.deb
    local s1=865e461255486766cefbbb2a7823589b02d4804b
    local hi=6f59f982ee702b193d9191019ac15df70a84012e0cc8c2ae106cf67d78a51999
    local hm=5498222c4bd32195e0b3e3e8053b2af29f397a3ace6961eea4498d5b5815a3a1
    ck() {
        printf '# Checksums-Sha1:\n%s  %s\n#\n# Checksums-Sha256:\n' "$s1" "$i"
        printf '%s\n' "$@"
    }
    ck "$hi  $i" "$hm  $m" "$hi  $h" > "$t/ck-good"
    ck "$hm  $m" > "$t/ck-noimg"
    ck "$hi  $i" "$hi  ${i/generic/lowlatency}" "$hm  $m" > "$t/ck-lowlat"
    ck "$hi  $i" "$hi  ${i/6.12.40-061240-generic_/6.12.41-061241-generic_}" \
        "$hm  $m" > "$t/ck-two"
    ck "$hi  $i" "$hm  ${m/6.12.40-061240-generic_/6.12.41-061241-generic_}" > "$t/ck-mix"
    ck "$hi  $i" "$hm  ${m/.202507240748/.202507250000}" > "$t/ck-build"
    ck "${hi:1}  $i" "$hm  $m" > "$t/ck-shorthash"
    printf '# Checksums-Sha1:\n%s  %s\n%s  %s\n' "$hi" "$i" "$hm" "$m" > "$t/ck-sha1"
    expect ok parse_checksums "$t/ck-good" 6.12.40
    expect ok parse_checksums "$t/ck-lowlat" 6.12.40
    same "CHECKSUMS fields" "$(parse_checksums "$t/ck-good" 6.12.40 2>/dev/null)" \
        "6.12.40-061240-generic $i $hi $m $hm"
    expect fail parse_checksums "$t/ck-good" 6.12.4
    for v in noimg two mix build shorthash sha1; do
        expect fail parse_checksums "$t/ck-$v" 6.12.40
    done

    local k=6.12.40-061240-generic
    line() {
        local fmt='Booting\r\n%s v=1 nonce=%s kernel=%s want=%s'
        fmt+=' nvme-cli=%s fio=%s root=%s status=%s end\r\n'
        printf "$fmt" "$CHECK_MARK" "$@"
        printf '[   9.1] reboot: Power down\r\n'
    }
    line N1 "$k" "$k" 2.8-1 3.36-1 rw ok > "$t/log-good"
    line N1 6.8.0-147-generic 6.8.0-147-generic 2.8-1 3.36-1 rw ok > "$t/log-distro"
    line N1 6.8.0-31-generic "$k" 2.8-1 3.36-1 rw ok > "$t/log-kernel"
    line N1 "$k" "$k" none 3.36-1 rw ok > "$t/log-nvme"
    line N1 "$k" "$k" 2.8-1 none rw ok > "$t/log-fio"
    line N1 "$k" "$k" 2.8-1 3.36-1 ro ok > "$t/log-ro"
    line N1 "$k" "$k" 2.8-1 3.36-1 rw cleanup-failed > "$t/log-status"
    line N0 "$k" "$k" 2.8-1 3.36-1 rw ok > "$t/log-nonce"
    {
        line N1 "$k" "$k" 2.8-1 3.36-1 rw ok
        line N1 "$k" "$k" 2.8-1 3.36-1 rw ok
    } > "$t/log-two"
    line N1 "$k" "$k" 2.8-1 3.36-1 rw ok | sed 's/ end//' > "$t/log-cut"
    line N1 "$k" "$k" 2.8-1 3.36-1 rw ok | grep -v 'Power down' > "$t/log-nopower"
    echo "Booting" > "$t/log-none"
    expect ok check_line_ok "$t/log-good" N1 "$k"
    expect ok check_line_ok "$t/log-distro" N1 ""
    same "check line fields" \
        "$(check_line_ok "$t/log-good" N1 "$k" 2>/dev/null)" "$k 2.8-1 3.36-1"
    for v in kernel nvme fio ro status nonce two cut nopower none; do
        expect fail check_line_ok "$t/log-$v" N1 "$k"
    done
    expect fail check_line_ok "$t/log-kernel" N1 ""

    # GRUB menus: a submenu, a flat menu, recovery entries, a release
    # that is a prefix of another, a release with no entry
    sub="submenu 'Advanced options for Ubuntu'"
    sub+=" \$menuentry_id_option 'gnulinux-advanced-U1' {"
    ent() {
        local me="\tmenuentry 'Ubuntu, with Linux %s" id='$menuentry_id_option'
        printf "$me' $id 'gnulinux-%s-advanced-U1' {\n\t}\n" "$1" "$1"
        printf "$me (recovery mode)' $id 'gnulinux-%s-recovery-U1' {\n\t}\n" "$1" "$1"
    }
    {
        echo "$sub"
        ent 6.8.0-147-generic
        ent 6.12.40-061240-generic
        ent 6.12.4-061204-generic
        echo "}"
    } > "$t/grub-sub"
    { ent 6.8.0-147-generic; ent 6.12.40-061240-generic; } > "$t/grub-flat"
    {
        echo "$sub"
        ent 6.12.40-061240-generic
        echo "}"
        echo "$sub"
        echo "}"
    } > "$t/grub-twosub"
    pick() { sh -c "$(guest_grub_fn)"'
femu_pick_entry "$1" "$2"' sh "$@"; }
    same "GRUB submenu" "$(pick "$t/grub-sub" 6.12.4-061204-generic 2>&1)" \
        "gnulinux-advanced-U1>gnulinux-6.12.4-061204-generic-advanced-U1"
    same "GRUB flat" "$(pick "$t/grub-flat" 6.12.40-061240-generic 2>&1)" \
        "gnulinux-6.12.40-061240-generic-advanced-U1"
    expect fail pick "$t/grub-sub" 5.10.274-0510274-generic
    expect fail pick "$t/grub-sub" 6.12.40
    expect fail pick "$t/grub-twosub" 6.12.40-061240-generic
    { cat "$t/grub-flat"; ent 6.12.40-061240-generic; } > "$t/grub-dup"
    expect fail pick "$t/grub-dup" 6.12.40-061240-generic

    if (( bad == 0 )); then
        echo "SELFTEST=PASS ($n cases)"
    else
        echo "SELFTEST=FAIL $bad of $n"
        exit 1
    fi
    exit 0
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

# A tool that writes any files to an ISO; cloud-localds cannot.
plain_iso_tool() {
    local t
    for t in genisoimage xorriso mkisofs; do
        if command -v "$t" > /dev/null; then
            echo "$t"
            return 0
        fi
    done
    return 1
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
    elif t=$(plain_iso_tool); then
        iso_tool=$t
    else
        missing+=("cloud-localds or genisoimage or xorriso or mkisofs")
    fi
    if [[ "$kernel_kind" == mainline ]] && ! plain_iso_tool > /dev/null; then
        missing+=("genisoimage or xorriso or mkisofs (for --kernel $kernel)")
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

base_url() {
    if [[ "$base_serial" == latest ]]; then
        echo "$SERIES_URL/release"
    else
        echo "$SERIES_URL/release-$base_serial"
    fi
}

# fetch URL FILE: download to a private part file, then rename.
fetch() {
    local part
    part=$(mktemp "$2.part.XXXXXX")
    if ! curl -fL --progress-bar --retry 3 -o "$part" "$1"; then
        rm -f "$part"
        return 1
    fi
    mv -f "$part" "$2"
}

# download_base DIR: fetches the cloud image into DIR and sets base_img
# and base_sha256 to the checked file and its digest.
download_base() {
    local dir=$1
    local url
    url=$(base_url)
    mkdir -p "$dir"
    local sums
    sums=$(mktemp "$dir/SHA256SUMS.XXXXXX")

    info "fetching $url/SHA256SUMS"
    curl -fsSL --retry 3 -o "$sums" "$url/SHA256SUMS" ||
        die "cannot fetch $url/SHA256SUMS; if Ubuntu removed serial" \
            "$base_serial, pass --base-serial latest or another serial"

    if command -v gpgv > /dev/null && [[ -r "$KEYRING" ]]; then
        curl -fsSL --retry 3 -o "$sums.gpg" "$url/SHA256SUMS.gpg"
        gpgv --keyring "$KEYRING" "$sums.gpg" "$sums" 2> /dev/null ||
            die "SHA256SUMS signature check failed"
        rm -f "$sums.gpg"
        info "SHA256SUMS signature verified"
    else
        info "gpgv or $KEYRING not found; skipping the signature check"
    fi

    local listed want
    listed=$(awk -v f="*$CLOUD_IMG" '$2 == f { print $1 }' "$sums")
    rm -f "$sums"
    [[ "$listed" =~ ^[0-9a-f]{64}$ ]] || die "$CLOUD_IMG not listed in SHA256SUMS"
    if (( base_sha_set )); then
        want=$base_sha256
    elif [[ "$base_serial" == "$PIN_SERIAL" ]]; then
        want=$PIN_SHA256
    else
        want=$listed
    fi
    [[ "$listed" == "$want" ]] ||
        die "SHA256SUMS of serial $base_serial lists $listed, want $want"

    base_img="$dir/$CLOUD_IMG"
    base_sha256=$want
    if [[ -f "$base_img" ]] &&
        [[ $(sha256sum "$base_img" | cut -d' ' -f1) == "$want" ]]; then
        info "using cached $base_img"
        return 0
    fi

    info "downloading $CLOUD_IMG (serial $base_serial)"
    local tmp
    tmp=$(mktemp "$base_img.new.XXXXXX")
    fetch "$url/$CLOUD_IMG" "$tmp" || { rm -f "$tmp"; die "cannot download $CLOUD_IMG"; }
    local got
    got=$(sha256sum "$tmp" | cut -d' ' -f1)
    if [[ "$got" != "$want" ]]; then
        rm -f "$tmp"
        die "SHA256 mismatch for $CLOUD_IMG (got $got, want $want)"
    fi
    mv -f "$tmp" "$base_img"
    info "SHA256 verified: $want"
}

# fetch_mainline DIR: downloads the image and modules debs of the mainline
# kernel into DIR, checks them against CHECKSUMS, and sets kernel_rel and
# kernel_debs ("NAME SHA" entries). The debs are unsigned; CHECKSUMS comes
# over HTTPS from the same server.
fetch_mainline() {
    local dir=$1
    local url="$MAINLINE_URL/v$kernel/amd64"
    mkdir -p "$dir"
    info "fetching $url/CHECKSUMS"
    curl -fsSL --retry 3 -o "$dir/CHECKSUMS" "$url/CHECKSUMS" ||
        die "no amd64 build of mainline $kernel at $url; pick another version"
    local fields
    fields=$(parse_checksums "$dir/CHECKSUMS" "$kernel") ||
        die "no usable amd64 build of mainline $kernel in $url/CHECKSUMS"
    local -a f
    read -r -a f <<< "$fields"
    kernel_rel=${f[0]}
    kernel_debs=("${f[1]} ${f[2]}" "${f[3]} ${f[4]}")
    local e deb sum
    for e in "${kernel_debs[@]}"; do
        deb=${e% *} sum=${e#* }
        if [[ ! -f "$dir/$deb" ]] ||
            [[ $(sha256sum "$dir/$deb" | cut -d' ' -f1) != "$sum" ]]; then
            info "downloading $deb"
            fetch "$url/$deb" "$dir/$deb" || die "cannot download $deb"
        fi
        [[ $(sha256sum "$dir/$deb" | cut -d' ' -f1) == "$sum" ]] ||
            { rm -f "$dir/$deb"; die "SHA256 mismatch for $deb"; }
    done
    info "kernel $kernel_rel verified against CHECKSUMS"
}

# kernel_iso ISO DIR: the two debs on a volume the guest mounts by label.
kernel_iso() {
    local iso=$1 dir=$2
    local t
    t=$(plain_iso_tool) || die "no ISO tool for the kernel volume"
    local -a debs=()
    local e
    for e in "${kernel_debs[@]}"; do
        debs+=("$dir/${e% *}")
    done
    rm -f "$iso"
    if [[ "$t" == xorriso ]]; then
        xorriso -as mkisofs -quiet -output "$iso" -volid FEMUKERNEL -joliet \
            -rock "${debs[@]}" 2> /dev/null
    else
        "$t" -quiet -output "$iso" -volid FEMUKERNEL -joliet -rock "${debs[@]}"
    fi
}

# The guest side of provisioning. Runs as root from cloud-init, with its
# output on the serial log. Every step must pass, or no READY mark.
# Arguments: KIND (distro, abi, mainline), REL, then the package names.
guest_setup_script() {
    echo '#!/bin/sh'
    echo 'set -eu'
    guest_grub_fn
    cat <<'EOS'
kind=$1
rel=$2
shift 2
say() { echo "femu-guest-setup: $*"; }
export DEBIAN_FRONTEND=noninteractive
mkdir -p /var/lib/femu-guest
say "packages"
for p in "$@"; do
    s=$(dpkg-query -W -f '${Status}' "$p" 2>/dev/null || true)
    [ "$s" = "install ok installed" ] ||
        { say "package $p is not installed ($s)"; exit 1; }
done
if [ "$kind" = mainline ]; then
    say "mainline kernel $rel"
    mkdir -p /mnt/femu-kernel
    d=/var/tmp/femu-kernel
    rm -rf "$d"
    mkdir -p "$d"
    mount -o ro LABEL=FEMUKERNEL /mnt/femu-kernel
    cp /mnt/femu-kernel/linux-*.deb "$d/"
    umount /mnt/femu-kernel
    v=""
    for f in "$d"/linux-image-unsigned-*.deb "$d"/linux-modules-*.deb; do
        [ "$(dpkg-deb -f "$f" Architecture)" = amd64 ]
        case $(dpkg-deb -f "$f" Package) in
        "linux-image-unsigned-$rel" | "linux-modules-$rel") ;;
        *) say "unexpected package in $f"; exit 1 ;;
        esac
        fv=$(dpkg-deb -f "$f" Version)
        [ -z "$v" ] || [ "$v" = "$fv" ] || { say "two builds: $v and $fv"; exit 1; }
        v=$fv
    done
    apt-get install -y "$d"/linux-image-unsigned-*.deb "$d"/linux-modules-*.deb
    rm -rf "$d"
elif [ "$kind" = abi ]; then
    say "Ubuntu kernel $rel"
    apt-get install -y "linux-image-$rel"
fi
if [ "$kind" = distro ]; then
    want=$(uname -r)
else
    want=$rel
    [ -s "/boot/vmlinuz-$rel" ] && [ -s "/boot/initrd.img-$rel" ]
    # the disk drivers must be in the kernel or in its initrd
    for m in VIRTIO_BLK:virtio_blk SCSI_VIRTIO:virtio_scsi; do
        grep -q "^CONFIG_${m%%:*}=y" "/boot/config-$rel" ||
            lsinitramfs "/boot/initrd.img-$rel" | grep -q "/${m#*:}\.ko" ||
            { say "no ${m#*:} for $rel"; exit 1; }
    done
    # the cloud image first boots without an initrd
    rm -f /etc/default/grub.d/40-force-partuuid.cfg
    if grep -rqs GRUB_FORCE_PARTUUID /etc/default/grub /etc/default/grub.d; then
        say "GRUB_FORCE_PARTUUID is still set"
        exit 1
    fi
    update-grub
    pick=$(femu_pick_entry /boot/grub/grub.cfg "$rel")
    echo "GRUB_DEFAULT=\"$pick\"" > /etc/default/grub.d/95-femu-kernel.cfg
fi
update-grub
if [ "$kind" != distro ]; then
    grep -qF "set default=\"$pick\"" /boot/grub/grub.cfg
fi
echo "$want" > /var/lib/femu-guest/want-kernel
systemctl disable systemd-networkd-wait-online.service
dpkg-query -W > /var/lib/femu-guest/packages.txt
# the seed may hold a password; the guest keeps no copy
rm -f /var/lib/cloud/instance/user-data.txt /var/lib/cloud/instance/user-data.txt.i
rm -f /var/lib/cloud/instances/*/user-data.txt /var/lib/cloud/instances/*/user-data.txt.i
touch /etc/cloud/cloud-init.disabled
cat /proc/sys/kernel/random/boot_id > /var/lib/femu-guest/provision-boot-id
systemctl enable femu-guest-check.service
touch /var/lib/femu-guest/check-pending
say "done"
EOS
}

# The check of the next boot. It skips the provisioning boot, takes the
# nonce from SMBIOS OEM string 11, removes itself, and only then reports.
guest_check_script() {
    cat <<EOS
#!/bin/sh
mark=$CHECK_MARK
EOS
    cat <<'EOS'
s=/var/lib/femu-guest
[ "$(cat /proc/sys/kernel/random/boot_id)" != "$(cat $s/provision-boot-id)" ] || exit 0
nonce=$(tr -c 'a-z0-9-' '\n' < /sys/firmware/dmi/entries/11-0/raw |
    grep '^femu-check-' | head -n1)
st=ok
k=$(uname -r)
w=$(cat $s/want-kernel 2>/dev/null || echo none)
n=none
f=none
if [ "$(dpkg-query -W -f '${Status}' nvme-cli)" = "install ok installed" ] &&
    nvme version > /dev/null 2>&1; then
    n=$(dpkg-query -W -f '${Version}' nvme-cli)
fi
if [ "$(dpkg-query -W -f '${Status}' fio)" = "install ok installed" ] &&
    fio --version > /dev/null 2>&1; then
    f=$(dpkg-query -W -f '${Version}' fio)
fi
r=rw
case ",$(findmnt -no OPTIONS /)," in *,ro,*) r=ro ;; esac
{ touch $s/rw-probe && rm -f $s/rw-probe; } || r=ro
rm -f $s/check-pending $s/provision-boot-id
systemctl disable femu-guest-check.service || st=disable-failed
rm -f /etc/systemd/system/femu-guest-check.service /usr/local/sbin/femu-guest-check
[ ! -e $s/check-pending ] || st=cleanup-failed
[ ! -e /etc/systemd/system/multi-user.target.wants/femu-guest-check.service ] ||
    st=cleanup-failed
[ -n "$nonce" ] || st=no-nonce
sync
printf '\n%s v=1 nonce=%s kernel=%s want=%s nvme-cli=%s fio=%s root=%s status=%s end\n' \
    "$mark" "${nonce:-none}" "$k" "$w" "${n:-none}" "${f:-none}" "$r" "$st" > /dev/ttyS0
systemctl --no-block poweroff
EOS
}

guest_check_unit() {
    cat <<'EOS'
[Unit]
Description=FEMU guest image check, runs once
ConditionPathExists=/var/lib/femu-guest/check-pending
After=systemd-user-sessions.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/femu-guest-check

[Install]
WantedBy=multi-user.target
EOS
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
    [[ "$pub" == ssh-* || "$pub" == ecdsa-* ]] ||
        die "$ssh_pubkey is not an SSH public key"

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
  - path: /usr/local/sbin/femu-guest-setup
    permissions: '0755'
    content: |
EOF
        guest_setup_script | sed 's/^/      /'
        cat <<EOF
  - path: /usr/local/sbin/femu-guest-check
    permissions: '0755'
    content: |
EOF
        guest_check_script | sed 's/^/      /'
        cat <<EOF
  - path: /etc/systemd/system/femu-guest-check.service
    content: |
EOF
        guest_check_unit | sed 's/^/      /'
        local run="if /usr/local/sbin/femu-guest-setup $kernel_kind \"$kernel_rel\""
        run+=" ${pkgs[*]} > /dev/ttyS0 2>&1; then echo $READY_MARK > /dev/ttyS0;"
        run+=" else echo $FAIL_MARK > /dev/ttyS0; fi"
        cat <<EOF
runcmd:
  - [ sh, -c, '$run' ]
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

# run_guest NAME LOG MACHINE QEMU-ARGS...: one boot that must power off
# by itself.
run_guest() {
    local label=$1
    local log=$2
    local machine=$3
    shift 3
    local -a accel=(-machine "$machine,accel=tcg" -cpu max)
    if (( use_kvm )); then
        accel=(-machine "$machine,accel=kvm" -cpu host)
    fi
    local rc=0
    timeout -k 10 "$timeout_s" "$qemu" \
        -name "femu-guest-$label,debug-threads=on" \
        "${accel[@]}" -smp 2 -m 2G \
        -nodefaults -display none -no-reboot \
        -serial "file:$log" \
        "$@" \
        -netdev user,id=net0 -device virtio-net-pci,netdev=net0 ||
        rc=$?
    if (( rc == 124 )); then
        die "the $label boot did not finish in ${timeout_s}s; see $log"
    elif (( rc != 0 )); then
        die "QEMU exited with status $rc in the $label boot; see $log"
    fi
}

provision() {
    local disk=$1
    local seed=$2
    local log=$3
    local kiso=$4
    local -a drives=(-drive "file=$disk,if=virtio,format=qcow2"
        -drive "file=$seed,if=virtio,format=raw,readonly=on")
    [[ -z "$kiso" ]] || drives+=(-drive "file=$kiso,if=virtio,format=raw,readonly=on")

    info "provisioning (log: $log); this takes a few minutes"
    rm -f "$log"
    run_guest provision "$log" q35 "${drives[@]}"
    if grep -aq "$FAIL_MARK" "$log"; then
        die "provisioning failed in the guest; see the femu-guest-setup lines in $log"
    fi
    grep -aq "$READY_MARK" "$log" ||
        die "guest powered off before provisioning finished; see $log"
}

# check_boot DISK LOG: boots the image once more as the launchers do
# (i440fx, virtio-scsi), with no seed, and sets check_fields to
# "RELEASE NVME-CLI FIO" from the guest's check record.
check_boot() {
    local disk=$1
    local log=$2
    local nonce
    nonce="femu-check-$(od -An -N8 -tx1 /dev/urandom | tr -d '\n ')"
    local want=$kernel_rel
    if [[ "$kernel_kind" == distro && "$base_serial" == "$PIN_SERIAL" ]]; then
        want=$PIN_KERNEL
    fi
    info "check boot (log: $log)"
    rm -f "$log"
    run_guest check "$log" pc -smbios "type=11,value=$nonce" \
        -device virtio-scsi-pci,id=scsi0 -device scsi-hd,drive=hd0 \
        -drive "file=$disk,if=none,format=qcow2,id=hd0"
    check_fields=$(check_line_ok "$log" "$nonce" "$want") ||
        die "the check boot failed; see $log"
    info "the image runs ${check_fields%% *}"
}

# A standalone image: no backing file, and qemu-img check passes.
check_standalone() {
    local img=$1
    local js
    js=$("$qemu_img" info --output=json "$img") || die "qemu-img info failed on $img"
    [[ "$js" == *'"format": "qcow2"'* ]] || die "$img is not a qcow2 image"
    [[ "$js" != *'"backing-filename"'* ]] || die "$img has a backing file"
    "$qemu_img" check -q "$img" || die "qemu-img check failed on $img"
}

write_manifest() {
    local sum=$1
    local -a f
    read -r -a f <<< "$check_fields"
    echo "IMAGE=$name"
    echo "IMAGE_SHA256=$sum"
    echo "BASE_URL=$(base_url)/$CLOUD_IMG"
    echo "BASE_SERIAL=$base_serial"
    echo "BASE_SHA256=$base_sha256"
    echo "KERNEL_REQUEST=$kernel"
    echo "KERNEL_RELEASE=${f[0]}"
    local e i=0
    for e in "${kernel_debs[@]}"; do
        echo "KERNEL_DEB_$i=${e% *}"
        echo "KERNEL_DEB_${i}_SHA256=${e#* }"
        i=$(( i + 1 ))
    done
    echo "NVME_CLI=${f[1]}"
    echo "FIO=${f[2]}"
    echo "PACKAGES_FILE=/var/lib/femu-guest/packages.txt"
    echo "EXTRA_PACKAGES=${extra_pkgs[*]}"
    echo "CXL=$with_cxl"
    echo "SIZE=$size"
    echo "COMPRESSED=$compress"
    echo "QEMU=$("$qemu" --version | head -n1)"
    echo "QEMU_IMG=$("$qemu_img" --version | head -n1)"
    echo "SCRIPT_SHA256=$(sha256sum "${BASH_SOURCE[0]}" | cut -d' ' -f1)"
    echo "BUILT_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}

main() {
    parse_args "$@"
    (( ! self_test )) || run_self_test
    check_host

    mkdir -p "$outdir"
    outdir=$(cd "$outdir" && pwd)
    local out="$outdir/$name"
    if [[ -e "$out" ]] && (( ! force )); then
        die "$out exists; pass --force to replace it"
    fi

    [[ -n "$cache" ]] || cache="$outdir/cache"
    # a private folder per run: the seed may hold a password
    local work
    work=$(mktemp -d "$outdir/.make-guest-image.XXXXXX")
    local disk="$work/$name"
    local seed="$work/seed.iso"
    local log="$outdir/provision.log"
    local clog="$outdir/check.log"
    local kiso=""

    download_base "$cache/$base_serial"
    if [[ "$kernel_kind" == mainline ]]; then
        fetch_mainline "$cache/kernel-$kernel"
    fi
    ensure_key
    write_seed "$work" "$seed"
    if [[ "$kernel_kind" == mainline ]]; then
        kiso="$work/kernel.iso"
        kernel_iso "$kiso" "$cache/kernel-$kernel"
    fi

    info "creating $size disk"
    "$qemu_img" convert -q -O qcow2 "$base_img" "$disk"
    "$qemu_img" resize -q "$disk" "$size"

    local start=$SECONDS
    provision "$disk" "$seed" "$log" "$kiso"
    info "provisioned in $(( SECONDS - start ))s"
    check_boot "$disk" "$clog"

    if (( compress )); then
        info "compressing"
        "$qemu_img" convert -q -c -O qcow2 "$disk" "$disk.c"
        mv -f "$disk.c" "$disk"
    fi
    check_standalone "$disk"
    local sum
    sum=$(sha256sum "$disk" | cut -d' ' -f1)
    echo "$sum  $name" > "$work/$name.sha256"
    write_manifest "$sum" > "$work/$name.manifest"

    # old metadata goes first, so a stale .sha256 never names a new image
    rm -f "$out.sha256" "$out.manifest"
    mv -f "$disk" "$out"
    mv -f "$work/$name.sha256" "$out.sha256"
    mv -f "$work/$name.manifest" "$out.manifest"
    rm -rf "$work"

    local key_hint=""
    if [[ "$ssh_pubkey" == "$outdir/femu-guest-key.pub" ]]; then
        key_hint="-i $outdir/femu-guest-key "
    fi
    cat <<EOF

Image ready: $out (kernel ${check_fields%% *})
Digest and manifest: $out.sha256, $out.manifest
Start FEMU, for example:  OSIMGF=$out ./run-blackbox.sh
Log in from the host:     ssh ${key_hint}-p 8080 femu@localhost
EOF
}

main "$@"
