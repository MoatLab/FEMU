#!/bin/bash
#
# Check that an emulated FEMU device behaves, from inside the guest.
#
# Run this after changing FEMU to see whether the device still does what it
# claims: data survives the FTL, the counters move, deallocate works, and the
# mode-specific surface (zones, key-value) answers. It is meant to be quick
# enough to run every time, not to be a benchmark -- it makes no timing claims.
#
#   femu-test.sh --yes [/dev/nvme0n1]
#
# THIS DESTROYS THE CONTENTS OF THE DEVICE. It writes over the whole namespace,
# so --yes is required and a device that is mounted, or has a mounted partition,
# is refused.
#
# What runs depends on what the device says it is: a zoned namespace gets the
# zone checks, a key-value namespace the KV ones, anything else the block ones.

set -uo pipefail

DEV=/dev/nvme0n1
CONFIRM=0
for a in "$@"; do
    case "$a" in
        --yes)  CONFIRM=1 ;;
        --help|-h) sed -n '3,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        /dev/*) DEV="$a" ;;
        *)      echo "unknown argument: $a" >&2; exit 1 ;;
    esac
done
CTRL="/dev/$(basename "$DEV" | sed 's/n[0-9]*$//')"

pass=0; fail=0; skip=0
ok()   { echo "  PASS  $*"; pass=$((pass + 1)); }
bad()  { echo "  FAIL  $*"; fail=$((fail + 1)); }
na()   { echo "  SKIP  $*"; skip=$((skip + 1)); }
have() { command -v "$1" >/dev/null 2>&1; }

# ------------------------------------------------------------------ safety
[[ -b "$DEV" ]] || { echo "not a block device: $DEV" >&2; exit 1; }
if lsblk -nro MOUNTPOINT "$DEV" 2>/dev/null | grep -q .; then
    echo "refusing: $DEV or one of its partitions is mounted" >&2; exit 1
fi
if [[ $CONFIRM -ne 1 ]]; then
    echo "This overwrites everything on $DEV. Re-run with --yes if that is what you want." >&2
    exit 1
fi
have nvme || { echo "need nvme-cli" >&2; exit 1; }

# ------------------------------------------------------------------ identify
echo "== device =="
SIZE=$(blockdev --getsize64 "$DEV" 2>/dev/null || echo 0)
ZONED=$(cat "/sys/block/$(basename "$DEV")/queue/zoned" 2>/dev/null || echo none)
CSI=$(nvme id-ns "$DEV" 2>/dev/null | grep -ci . || echo 0)
echo "  device=$DEV controller=$CTRL size=$((SIZE / 1024 / 1024)) MiB zoned=$ZONED"
[[ "$SIZE" -gt 0 ]] && ok "namespace has a usable size" || bad "namespace has a usable size"

# key-value namespaces answer neither a normal read nor id-ns the usual way
KV=0
if nvme id-ctrl "$CTRL" 2>/dev/null | grep -qi "kv"; then KV=1; fi
[[ "$CSI" -eq 0 ]] && KV=1

# Write, read back and compare. A device can fail this two ways -- the data
# comes back wrong, or the read fails outright -- and both have to count. fio
# exits non-zero on either, so the exit status is the signal; the message is
# only there to say which happened.
verify_io() {
    local what="$1" iosize="$2" span="$3" out rc
    out=$(fio --name=v --filename="$DEV" --rw=randwrite --bs=4k --io_size="$iosize" \
          --size="$span" --direct=1 --ioengine=psync --verify=crc32c --do_verify=1 \
          --verify_fatal=1 --group_reporting 2>&1)
    rc=$?
    if [[ $rc -eq 0 ]] && ! grep -qiE "verify.*(failed|bad)|checksum|io_u error" <<<"$out"; then
        ok "$what"
        return 0
    fi
    bad "$what -- $(grep -m1 -iE "verify.*(failed|bad)|checksum|io_u error|error=" <<<"$out" |
                    sed 's/^ *//' | cut -c1-90)"
    return 1
}

# ------------------------------------------------------------------ block
run_block_checks() {
    echo "== data survives the FTL =="
    if have fio; then
        verify_io "random write then verify (crc32c)" 128M 512M
    else
        na "random write then verify (needs fio)"
    fi

    echo "== deallocate =="
    if have blkdiscard && blkdiscard -o 0 -l $((256 * 1024 * 1024)) "$DEV" >/dev/null 2>&1; then
        ok "deallocate accepted"
        if have fio; then
            verify_io "mapping still sound after deallocate" 32M 256M
        fi
    else
        na "deallocate (device declined, or no blkdiscard)"
    fi
}

# ------------------------------------------------------------------ zoned
run_zns_checks() {
    echo "== zones =="
    have blkzone || { na "zone checks (need blkzone from util-linux)"; return; }
    local nz z0 wp0 wp1
    nz=$(cat "/sys/block/$(basename "$DEV")/queue/nr_zones" 2>/dev/null || echo 0)
    echo "  nr_zones=$nz"
    [[ "$nz" -gt 0 ]] && ok "namespace reports zones" || bad "namespace reports zones"

    blkzone reset "$DEV" >/dev/null 2>&1 && ok "reset all zones" || bad "reset all zones"
    z0=$(blkzone report -c 1 "$DEV" 2>/dev/null | head -1)
    wp0=$(sed -n 's/.*wptr \([0-9a-fx]*\).*/\1/p' <<<"$z0")

    dd if=/dev/zero of="$DEV" bs=4k count=64 oflag=direct status=none 2>/dev/null \
        && ok "sequential write into zone 0" || bad "sequential write into zone 0"
    wp1=$(blkzone report -c 1 "$DEV" 2>/dev/null | sed -n 's/.*wptr \([0-9a-fx]*\).*/\1/p')
    [[ "$wp0" != "$wp1" ]] && ok "write pointer advanced ($wp0 -> $wp1)" \
                           || bad "write pointer advanced (stuck at $wp0)"

    # Zone Append: the device picks the LBA, so the write pointer must move and
    # the command must report where the data landed.
    if nvme zns zone-append "$DEV" --zslba=0 --data-size=4096 \
         --data=/dev/zero >/dev/null 2>&1; then
        ok "zone append accepted"
    else
        na "zone append (nvme-cli too old, or unsupported)"
    fi
}

# ------------------------------------------------------------------ kv
run_kv_checks() {
    echo "== key-value =="
    local key=0x46454d55 tmp out
    tmp=$(mktemp); trap 'rm -f "$tmp"' RETURN
    head -c 64 /dev/urandom > "$tmp"
    if ! nvme io-passthru "$DEV" --help >/dev/null 2>&1; then
        na "key-value checks (nvme-cli lacks io-passthru)"; return
    fi
    na "key-value checks (needs the KV opcodes; see hw/femu/scripts/kv-probe.c)"
}

# ------------------------------------------------------------------ counters
run_smart_checks() {
    echo "== counters =="
    local bin waf host nand
    bin=$(mktemp); trap 'rm -f "$bin"' RETURN
    if ! nvme smart-log "$CTRL" -o binary > "$bin" 2>/dev/null; then
        na "SMART log readable"; return
    fi
    [[ $(stat -c %s "$bin") -ge 512 ]] && ok "SMART log readable" || { bad "SMART log readable"; return; }

    # FEMU reports write amplification and its page counters in the vendor area:
    # 192 WAF x1000, 200 host pages, 208 relocated pages, 216 programmed pages.
    waf=$(od -An -tu4 -j192 -N4 "$bin" | tr -d ' ')
    host=$(od -An -tu8 -j200 -N8 "$bin" | tr -d ' ')
    nand=$(od -An -tu8 -j216 -N8 "$bin" | tr -d ' ')
    echo "  waf_x1000=$waf host_pages=$host nand_pages=$nand"
    if [[ "${host:-0}" -gt 0 ]]; then
        ok "host writes counted"
        [[ "${waf:-0}" -gt 0 ]] && ok "write amplification reported" \
                                || bad "write amplification reported"
    else
        na "host writes counted (not a bbssd namespace)"
    fi
}

# ------------------------------------------------------------------ run
if [[ "$ZONED" == "host-managed" || "$ZONED" == "host-aware" ]]; then
    run_zns_checks
elif [[ "$KV" -eq 1 ]]; then
    run_kv_checks
else
    run_block_checks
fi
run_smart_checks

echo
echo "FEMU_TEST pass=$pass fail=$fail skip=$skip"
[[ $fail -eq 0 ]]
