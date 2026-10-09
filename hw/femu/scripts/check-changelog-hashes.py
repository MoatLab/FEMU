#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check the commit hashes that FEMU's CHANGELOG names.

Each entry ends with the commits that made the change, as "(abc123def)" or
"(abc123def, 0123456ab)", or names them in the last cell of a table row.
Every such commit must be in the history of HEAD.
A hash from before a rebase or a squash names a commit that readers of the
public tree cannot find, so it fails here.

The check needs the full history: a shallow clone fails every hash.

Exit status: 0 when every hash is in the history of HEAD, 1 otherwise.
"""

import argparse
import re
import subprocess
import sys

DEFAULT_FILE = "hw/femu/docs/CHANGELOG.md"
HASHES = r"[0-9a-f]{7,40}(?:,\s*[0-9a-f]{7,40})*"
HASH_LIST_RE = re.compile(r"\((" + HASHES + r")\)"
                          r"|\|\s*(" + HASHES + r")\s*\|\s*$")


def in_history(commit, head):
    """Return True when @commit is an ancestor of (or equal to) @head."""
    return subprocess.run(["git", "merge-base", "--is-ancestor", commit, head],
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("file", nargs="?", default=DEFAULT_FILE)
    ap.add_argument("--head", default="HEAD",
                    help="the commit whose history must hold every hash")
    args = ap.parse_args()

    shallow = subprocess.run(["git", "rev-parse", "--is-shallow-repository"],
                             capture_output=True, text=True).stdout.strip()
    if shallow != "false":
        print("check-changelog-hashes: needs a full clone (fetch-depth: 0)")
        return 1

    checked = 0
    bad = []
    with open(args.file, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            for groups in HASH_LIST_RE.findall(line):
                group = groups[0] or groups[1]
                for commit in re.split(r",\s*", group):
                    checked += 1
                    if not in_history(commit, args.head):
                        bad.append((lineno, commit))

    for lineno, commit in bad:
        print(f"{args.file}:{lineno}: {commit} is not in the history of "
              f"{args.head}")
    print(f"check-changelog-hashes: {checked} hashes, {len(bad)} not found")
    return 1 if bad or checked == 0 else 0


if __name__ == "__main__":
    sys.exit(main())
