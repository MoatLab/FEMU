#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# check-patches.sh BASE HEAD: run QEMU's scripts/checkpatch.pl on each
# commit in BASE..HEAD (merges left out). An ERROR, or a checker or git
# failure, fails the check; a WARNING is printed only. A base of all zeros
# (a new branch) checks HEAD alone. Binary or mode-only commits are not
# checked. The old tree is not checked: it predates this.
#
# check-patches.sh --self-test: feed checkpatch a patch with a C99
# comment, which it must report as an ERROR, so a checker that cannot
# fail turns the check red.
set -euo pipefail

top=$(git rev-parse --show-toplevel)
checkpatch="$top/scripts/checkpatch.pl"

self_test() {
    local out

    out=$(perl "$checkpatch" --no-signoff - <<'EOF' 2>&1 || true
From 0000000000000000000000000000000000000000 Mon Sep 17 00:00:00 2001
From: Self Test <self@test>
Subject: [PATCH] femu: self test

---
 hw/femu/self-test.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/hw/femu/self-test.c b/hw/femu/self-test.c
--- a/hw/femu/self-test.c
+++ b/hw/femu/self-test.c
@@ -1,1 +1,2 @@
 int a;
+int b; // a C99 comment
EOF
)
    if ! grep -q '^ERROR' <<<"$out"; then
        echo "check-patches: self-test: checkpatch found no ERROR in a" \
             "planted C99 comment" >&2
        echo "$out" >&2
        exit 1
    fi
    echo "check-patches: self-test passed"
}

if [[ ${1:-} == --self-test ]]; then
    self_test
    exit 0
fi
if [[ $# -ne 2 ]]; then
    echo "usage: $0 BASE HEAD | --self-test" >&2
    exit 2
fi

base=$1
head=$2
zero=0000000000000000000000000000000000000000

# a new branch has no base: check its last commit only
if [[ $base == "$zero" || -z $base ]]; then
    echo "check-patches: no base (a new branch); checking $head alone"
    base="${head}~1"
fi
for rev in "$base" "$head"; do
    if ! git cat-file -e "${rev}^{commit}" 2>/dev/null; then
        # a force push can leave the old tip unfetched: ask for it once
        git fetch -q origin "$rev" 2>/dev/null || true
        if ! git cat-file -e "${rev}^{commit}" 2>/dev/null; then
            echo "check-patches: no commit '$rev'" >&2
            exit 2
        fi
    fi
done
# a merge's own conflict resolution is not checked: format-patch skips it
if ! commits=$(git rev-list --no-merges --reverse "$base..$head"); then
    echo "check-patches: cannot list $base..$head" >&2
    exit 2
fi

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
bad=0
n=0
for c in $commits; do
    n=$((n + 1))
    short=$(git log -1 --format='%h %s' "$c")
    if ! git format-patch -1 --stdout "$c" > "$tmp"; then
        echo "check-patches: $short: cannot make the patch" >&2
        exit 2
    fi
    rc=0
    out=$(perl "$checkpatch" --no-signoff - < "$tmp" 2>&1) || rc=$?
    # binary files and mode changes alone are no unified diff to check
    if grep -q 'Does not appear to be a unified-diff format patch' \
            <<<"$out" &&
       ! git diff-tree --no-commit-id -r --numstat "$c" |
            awk '$1 != "-" && ($1 + $2) > 0 { found = 1 } END { exit !found }'
    then
        echo "check-patches: $short: no text change; not checked"
        continue
    fi
    if (( rc != 0 )) || grep -q '^ERROR' <<<"$out"; then
        echo "check-patches: $short"
        echo "$out"
        bad=1
    elif grep -q '^WARNING' <<<"$out"; then
        echo "check-patches: $short"
        echo "$out"
    fi
done
echo "check-patches: $n commit(s) checked"
exit $bad
