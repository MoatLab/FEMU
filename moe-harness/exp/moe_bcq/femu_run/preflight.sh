#!/bin/bash
# Verify run_policy.sh is the patched version before committing to a run.
#
# On 2026-09-10 this file reverted, mid-sweep and silently, to its pre-patch
# state: byte-identical to the original and carrying the original mtime. What
# reverted it was never identified. Unpatched, two defaults come back and both
# fail quietly rather than loudly:
#
#   BUNDLE      -> qwen_C, so a DeepSeek run replays the Qwen binary against a
#                  DeepSeek image. Fill and read-back both still pass; neither
#                  check knows whose bytes it is looking at.
#   IMAGE_PAGES -> 471040, so the last 73,728 pages of a DeepSeek image are
#                  never class-checked and confusion still reports "clean".
#
# So the guard cannot live inside run_policy.sh -- a revert takes it too. The
# canonical copy and this check sit outside the tree that reverted.
set -uo pipefail

CANON=${FEMU_CANONICAL_DIR:-$HOME/.femu_canonical}
HARNESS=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
TARGET=$HARNESS/exp/moe_bcq/femu_run/run_policy.sh

[ -f "$CANON/SHA256SUMS" ] || { echo "preflight: no canonical copy at $CANON"; exit 1; }
want=$(awk '$2=="run_policy.sh"{print $1}' "$CANON/SHA256SUMS")
[ -n "$want" ] || { echo "preflight: SHA256SUMS has no run_policy.sh entry"; exit 1; }

got=$(sha256sum "$TARGET" 2>/dev/null | cut -d' ' -f1)
if [ "$got" = "$want" ]; then
    echo "preflight: run_policy.sh matches canonical (${want:0:12})"
    exit 0
fi

echo "preflight: run_policy.sh DOES NOT match the canonical copy"
echo "  expected ${want:0:12}  got ${got:0:12}"
# Restoring is right only when the canonical copy is itself intact; otherwise a
# corrupted canonical would be copied over a good working file.
canon_now=$(sha256sum "$CANON/run_policy.sh" 2>/dev/null | cut -d' ' -f1)
if [ "$canon_now" != "$want" ]; then
    echo "  canonical copy is itself altered -- refusing to restore. Fix $CANON by hand."
    exit 1
fi
cp -p "$CANON/run_policy.sh" "$TARGET"
chmod +x "$TARGET"
echo "  restored from $CANON/run_policy.sh"
sha256sum "$TARGET" | sed 's/^/  now /'
