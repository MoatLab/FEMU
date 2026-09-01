#!/bin/bash
#
# Self-test for ssd-config.sh.
#
# Expands every example config and hands the result to QEMU, so a config that
# names a property FEMU does not have, or gets the comma escaping wrong, fails
# here rather than the first time somebody tries to boot with it. Also checks
# the parser's own error handling.
#
# Usage: ssd-config-test.sh [path-to-qemu-system-x86_64]

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
CFG="$HERE/ssd-config.sh"

FEMU="${1:-${FEMU_BIN:-}}"
if [[ -z "$FEMU" ]]; then
    for c in "$ROOT/build-femu/qemu-system-x86_64" "$ROOT/build/qemu-system-x86_64" \
             "$ROOT/build-official/qemu-system-x86_64"; do
        [[ -x "$c" ]] && { FEMU="$c"; break; }
    done
fi
[[ -x "${FEMU:-}" ]] || { echo "need a FEMU binary: pass it as \$1 or set FEMU_BIN" >&2; exit 1; }
export FEMU_BIN="$FEMU"

pass=0; fail=0
ok()   { echo "  PASS  $*"; pass=$((pass + 1)); }
bad()  { echo "  FAIL  $*"; fail=$((fail + 1)); }

# QEMU checks -device properties before it realizes the device, so a bad property
# or a mis-escaped comma is reported whatever the host can actually support. A
# later failure -- pinning the memory backend, no KVM -- means the arguments
# themselves were fine, which is all this is testing.
rejects() {
    local out args
    # Shrink the capacity for the check. What is being tested is whether FEMU
    # accepts the properties, not whether this host can hold the device, and a
    # config sized for real use would have the check allocating gigabytes.
    args="$(sed -E 's/devsz_mb=[0-9]+/devsz_mb=512/' <<<"$1")"
    out="$(timeout 15 "$FEMU" -machine q35 $args -S -no-user-config -nodefaults \
           -display none </dev/null 2>&1)"
    if grep -qE "Property '[^']*' not found|invalid parameter|short-form boolean option|can't apply global|Parameter '[^']*' expects|does not exist" <<<"$out"; then
        grep -m1 -E "Property|invalid parameter|short-form|Parameter" <<<"$out" | sed 's/^/        /'
        return 0
    fi
    return 1
}

echo "== example configs =="
for conf in "$HERE"/configs/*.conf; do
    name="$(basename "$conf")"
    if ! args="$("$CFG" "$conf" 2>/dev/null)"; then
        bad "$name (did not expand)"; continue
    fi
    if rejects "$args"; then bad "$name (QEMU rejected the arguments)"; else ok "$name"; fi
done

echo "== the check itself can fail (negative control) =="
# Without this, a broken rejects() would silently pass every config above.
if rejects "-device femu,id=nvme0,devsz_mb=1024,femu_mode=1,not_a_real_prop=7" >/dev/null; then
    ok "a bogus property is detected"
else
    bad "a bogus property is detected -- the acceptance check is not working, \
so the results above mean nothing"
fi
if rejects "-device femu,id=nvme0,devsz_mb=6144,namespaces=3,femu_mode=1,namespace_modes=bbssd,znssd,nossd" >/dev/null; then
    ok "an unescaped comma in a list value is detected"
else
    bad "an unescaped comma in a list value is detected"
fi

echo "== escaping and wiring =="
out="$("$CFG" "$HERE/configs/heterogeneous.conf" 2>/dev/null)"
grep -q "namespace_modes=bbssd,,znssd,,nossd" <<<"$out" \
    && ok "list values have their commas escaped" \
    || bad "list values have their commas escaped: $out"
out="$("$CFG" "$HERE/configs/fdp.conf" 2>/dev/null)"
grep -q -- "-device femu-subsys," <<<"$out" && grep -q "subsys=femu-subsys-0" <<<"$out" \
    && ok "[subsys] emits its own device and is wired up" \
    || bad "[subsys] emits its own device and is wired up: $out"
out="$("$CFG" "$HERE/configs/bbssd.conf" --device-only 2>/dev/null)"
[[ "$out" != -device* ]] && ok "--device-only drops the -device word" \
    || bad "--device-only drops the -device word: $out"

echo "== rejects bad input =="
t="$(mktemp)"; trap 'rm -f "$t"' EXIT
printf 'mode = bbssd\nnot_a_real_property = 1\n' > "$t"
"$CFG" "$t" --check >/dev/null 2>&1 && bad "unknown property rejected" || ok "unknown property rejected"
printf 'mode = bbssd\nfdp.nruh = 4\n' > "$t"
"$CFG" "$t" --check >/dev/null 2>&1 && bad "subsystem property in [device] rejected" \
    || ok "subsystem property in [device] rejected"
printf 'mode = bbssd\nfemu_mode = 1\n' > "$t"
"$CFG" "$t" --check >/dev/null 2>&1 && bad "mode and femu_mode together rejected" \
    || ok "mode and femu_mode together rejected"
printf 'mode = nonsense\n' > "$t"
"$CFG" "$t" --check >/dev/null 2>&1 && bad "unknown mode rejected" || ok "unknown mode rejected"
printf 'this line has no equals sign\n' > "$t"
"$CFG" "$t" --check >/dev/null 2>&1 && bad "malformed line rejected" || ok "malformed line rejected"

echo
echo "SSD_CONFIG_TEST pass=$pass fail=$fail"
[[ $fail -eq 0 ]]
