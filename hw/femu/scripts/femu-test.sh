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
have nvme || { echo "need nvme-cli" >&2; exit 1; }
# A key-value namespace is not block addressable, so the kernel makes no block
# node for it -- only the controller. Missing block device is therefore a hint
# about what this is, not an error.
BLOCK=0
[[ -b "$DEV" ]] && BLOCK=1
if [[ $BLOCK -eq 0 && ! -c "$CTRL" ]]; then
    echo "found neither a block device at $DEV nor a controller at $CTRL" >&2
    exit 1
fi
if [[ $BLOCK -eq 1 ]] && lsblk -nro MOUNTPOINT "$DEV" 2>/dev/null | grep -q .; then
    echo "refusing: $DEV or one of its partitions is mounted" >&2; exit 1
fi
if [[ $CONFIRM -ne 1 ]]; then
    echo "This overwrites everything on ${DEV}. Re-run with --yes if that is what you want." >&2
    exit 1
fi

# ------------------------------------------------------------------ identify
echo "== device =="
SIZE=0; ZONED=none
if [[ $BLOCK -eq 1 ]]; then
    SIZE=$(blockdev --getsize64 "$DEV" 2>/dev/null || echo 0)
    ZONED=$(cat "/sys/block/$(basename "$DEV")/queue/zoned" 2>/dev/null || echo none)
fi
echo "  controller=$CTRL block=$([[ $BLOCK -eq 1 ]] && echo "$DEV" || echo none)" \
     "size=$((SIZE / 1024 / 1024)) MiB zoned=$ZONED"
nvme id-ctrl "$CTRL" >/dev/null 2>&1 && ok "controller answers Identify" \
                                     || bad "controller answers Identify"

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
    # NVMe-KV commands are not in the block path, so they go through
    # io-passthru: Store 01h, Retrieve 02h, Delete 10h, Exist 14h. The key sits
    # in CDW2/3 and its length in CDW11.
    local key=0x46454d55 val ret
    # nvme-cli exits non-zero from "--help", so ask the command list instead
    if ! nvme help 2>&1 | grep -q io-passthru; then
        na "key-value checks (nvme-cli has no io-passthru)"; return
    fi
    val=$(mktemp); ret=$(mktemp)
    trap 'rm -f "$val" "$ret"' RETURN
    head -c 64 /dev/urandom > "$val"

    nvme io-passthru "$CTRL" -O 0x01 -n 1 --cdw10=64 --cdw11=4 --cdw2=$key \
        -l 64 -w -i "$val" >/dev/null 2>&1 \
        && ok "store a key" || { bad "store a key"; return; }

    nvme io-passthru "$CTRL" -O 0x14 -n 1 --cdw11=4 --cdw2=$key >/dev/null 2>&1 \
        && ok "the key exists" || bad "the key exists"

    nvme io-passthru "$CTRL" -O 0x02 -n 1 --cdw10=64 --cdw11=4 --cdw2=$key \
        -l 64 -r -b 2>/dev/null > "$ret"
    cmp -s "$val" "$ret" && ok "the value reads back byte for byte" \
                         || bad "the value reads back byte for byte"

    nvme io-passthru "$CTRL" -O 0x10 -n 1 --cdw11=4 --cdw2=$key >/dev/null 2>&1 \
        && ok "delete the key" || bad "delete the key"

    # a deleted key must be reported missing, not silently succeed
    if nvme io-passthru "$CTRL" -O 0x14 -n 1 --cdw11=4 --cdw2=$key >/dev/null 2>&1; then
        bad "a deleted key is reported missing"
    else
        ok "a deleted key is reported missing"
    fi
}

# ------------------------------------------------------------------ fdp
# Flexible Data Placement rides on top of a block namespace, so these run in
# addition to the block checks when the controller advertises it (CTRATT bit 19).
fdp_supported() {
    local ctratt
    ctratt=$(nvme id-ctrl "$CTRL" 2>/dev/null | sed -n 's/^ctratt *: *//p' | head -1)
    [[ -n "$ctratt" ]] || return 1
    (( (ctratt & 0x80000) != 0 ))
}

run_fdp_checks() {
    echo "== flexible data placement =="
    local eg=1 cfg before after
    if ! nvme help 2>&1 | grep -q '^  fdp'; then
        na "FDP checks (nvme-cli has no fdp subcommand)"; return
    fi

    # the endurance group has to be named; without -e nvme-cli just complains
    cfg=$(nvme fdp configs "$CTRL" -e "$eg" 2>&1)
    if grep -qi "Reclaim Unit Handles" <<<"$cfg"; then
        local nruh
        nruh=$(sed -n 's/.*Number of Reclaim Unit Handles: *//p' <<<"$cfg" | head -1)
        ok "configuration log readable ($nruh handles)"
    else
        bad "configuration log readable"; return
    fi

    nvme fdp status "$DEV" 2>&1 | grep -qi "Reclaim Unit Handle" \
        && ok "reclaim unit handle status readable" \
        || bad "reclaim unit handle status readable"

    # The interesting part is not that the log exists but that it moves: write a
    # little and the host/media byte counters should follow.
    before=$(nvme fdp stats "$CTRL" -e "$eg" 2>/dev/null | sed -n 's/.*(HBMW): *//p' | head -1)
    dd if=/dev/zero of="$DEV" bs=1M count=16 oflag=direct status=none 2>/dev/null
    after=$(nvme fdp stats "$CTRL" -e "$eg" 2>/dev/null | sed -n 's/.*(HBMW): *//p' | head -1)
    if [[ -n "${before:-}" && -n "${after:-}" ]] && (( after > before )); then
        ok "statistics advance with host writes ($before -> $after)"
    else
        bad "statistics advance with host writes ($before -> $after)"
    fi
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

    # The standard fields first: these are mode-independent, so a mode that
    # counts commands but not their bytes (or the reverse) shows up here.
    local duw hwc
    duw=$(od -An -tu8 -j48 -N8 "$bin" | tr -d ' ')
    hwc=$(od -An -tu8 -j80 -N8 "$bin" | tr -d ' ')
    echo "  data_units_written=$duw host_write_commands=$hwc"
    if [[ "${hwc:-0}" -gt 0 ]]; then
        ok "host write commands counted"
        [[ "${duw:-0}" -gt 0 ]] && ok "the bytes those commands wrote are counted" \
                                || bad "the bytes those commands wrote are counted"
    else
        na "host write commands counted (nothing written yet)"
    fi

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
if [[ $BLOCK -eq 0 ]]; then
    # no block node: key-value is the mode that looks like this
    run_kv_checks
elif [[ "$ZONED" == "host-managed" || "$ZONED" == "host-aware" ]]; then
    run_zns_checks
else
    run_block_checks
    fdp_supported && run_fdp_checks
fi
run_smart_checks

echo
echo "FEMU_TEST pass=$pass fail=$fail skip=$skip"
[[ $fail -eq 0 ]]
