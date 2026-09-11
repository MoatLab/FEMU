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
# later failure -- no KVM, say -- means the arguments themselves were fine,
# which is all this is testing.
#
# But "no property error in the output" is not the same as "the device came up".
# This used to decide purely by grepping, so a binary that died on a signal, an
# assertion or a sanitizer report scored a pass on every config: the grep found
# no property error, and the exit status was never looked at. Report those as
# their own outcome instead of silently counting them as success.
#
# Prints one word on the first line: ok, rejected, or crashed, followed by a tab
# and the evidence.
# what a crash looks like, and what a refused argument looks like
CRASH_RE="Sanitizer|runtime error:|Assertion.*failed|core dumped"
CRASH_MSG_RE="Sanitizer|runtime error:|Assertion|Aborted|Trace"
REJECT_RE="Property '[^']*' not found|invalid parameter|short-form boolean option"
REJECT_RE="$REJECT_RE|can't apply global|Parameter '[^']*' expects|does not exist"
REJECT_MSG_RE="Property|invalid parameter|short-form|Parameter"

check_args() {
    local out rc args
    # Shrink the capacity for the check. What is being tested is whether FEMU
    # accepts the properties, not whether this host can hold the device, and a
    # config sized for real use would have the check allocating gigabytes.
    args="$(sed -E 's/devsz_mb=[0-9]+/devsz_mb=512/' <<<"$1")"
    # QEMU frees little at exit by design, so leak reports say nothing about the
    # arguments; everything else a sanitizer prints does. The caller can still
    # add options, and a caller that wants leak checking can turn it back on.
    out="$(ASAN_OPTIONS="detect_leaks=0${ASAN_OPTIONS:+,$ASAN_OPTIONS}" \
           timeout 15 "$FEMU" -machine q35 $args -S -no-user-config -nodefaults \
           -display none </dev/null 2>&1)"
    rc=$?
    # A shell reports a signal death as 128+n, so an abort is 134. Sanitizers
    # and a failed assertion print rather than signal, so match those too.
    if (( rc >= 128 )) || grep -qE "$CRASH_RE" <<<"$out"; then
        printf 'crashed\t%s\n' "$(grep -m1 -E "$CRASH_MSG_RE" <<<"$out" \
                                   || echo "exit status $rc, no message")"
        return
    fi
    if grep -qE "$REJECT_RE" <<<"$out"; then
        printf 'rejected\t%s\n' "$(grep -m1 -E "$REJECT_MSG_RE" <<<"$out")"
        return
    fi
    printf 'ok\t\n'
}

# the first word of a check_args verdict
verdict() { sed -n '1s/\t.*//p' <<<"$1"; }
# everything after it
evidence() { sed -n '1s/^[a-z]*\t//p' <<<"$1"; }

echo "== example configs =="
for conf in "$HERE"/configs/*.conf; do
    name="$(basename "$conf")"
    if ! args="$("$CFG" "$conf" 2>/dev/null)"; then
        bad "$name (did not expand)"; continue
    fi
    out="$(check_args "$args")"
    case "$(verdict "$out")" in
        ok)       ok "$name" ;;
        rejected) bad "$name (QEMU rejected the arguments)"
                  echo "        $(evidence "$out")" ;;
        crashed)  bad "$name (QEMU did not survive the arguments)"
                  echo "        $(evidence "$out")" ;;
    esac
done

echo "== the check itself can fail (negative controls) =="
# Without these, a broken check_args() would silently pass every config above.
bogus="-device femu,id=nvme0,devsz_mb=1024,femu_mode=1,not_a_real_prop=7"
if [[ "$(verdict "$(check_args "$bogus")")" == rejected ]]; then
    ok "a bogus property is detected"
else
    bad "a bogus property is detected -- the acceptance check is not working, \
so the results above mean nothing"
fi
unescaped="-device femu,id=nvme0,devsz_mb=6144,namespaces=3,femu_mode=1"
unescaped="$unescaped,namespace_modes=bbssd,znssd,nossd"
if [[ "$(verdict "$(check_args "$unescaped")")" == rejected ]]; then
    ok "an unescaped comma in a list value is detected"
else
    bad "an unescaped comma in a list value is detected"
fi
# And the same for the outcome that used to be invisible: stand in a binary that
# dies the way an armed assertion or a sanitizer report does.
crasher="$(mktemp)"; trap 'rm -f "$crasher"' EXIT
printf '#!/bin/sh\nkill -ABRT $$\n' > "$crasher"; chmod +x "$crasher"
saved_femu="$FEMU"; FEMU="$crasher"
crash_verdict="$(verdict "$(check_args "-device femu,devsz_mb=512")")"
FEMU="$saved_femu"
if [[ "$crash_verdict" == crashed ]]; then
    ok "a binary that aborts is detected"
else
    bad "a binary that aborts is detected -- got '$crash_verdict', so a crash \
would be counted as a pass and the results above mean nothing"
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
t="$(mktemp)"; trap 'rm -f "$t" "$crasher"' EXIT
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
