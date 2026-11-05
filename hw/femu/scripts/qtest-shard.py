#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Split the FEMU qtests into contiguous shards for CI.

qos-test reuses one QEMU for tests with the same device line, and a test
can leak state into the next one. So a shard is a contiguous run of the
list, in list order, in one qos-test process: the process runs the whole
femu-tests path and skips every test outside the shard. A full run of all
tests in one process stays as the nightly check.

Usage:
    qos-test -l | qtest-shard.py --shards K --index I [--only PAT] [--skip PAT]
        print the -s arguments that leave shard I of K
    qos-test -l | qtest-shard.py --shards K --check [--only PAT] [--skip PAT]
        check that the K shards cover each test once, none empty
    qtest-shard.py --self-test

--only keeps the tests whose path contains PAT, --skip drops them; both
apply before the split, and every dropped test is skipped in each shard.
"""

import argparse
import sys

BASE = "/x86_64/pc/i440FX-pcihost/pci-bus-pc/pci-bus/femu/femu-tests"


def test_paths(text):
    """The femu-tests paths in qos-test -l output, in order, once each."""
    out = []
    seen = set()
    for line in text.split("\n"):
        line = line.strip()
        if line.startswith("# "):
            line = line[2:].strip()
        if line.startswith(BASE + "/") and line not in seen:
            seen.add(line)
            out.append(line)
    return out


def select(paths, only, skip):
    keep = [p for p in paths
            if (not only or only in p) and not (skip and skip in p)]
    return keep


def shards(paths, k):
    """K contiguous chunks whose sizes differ by at most one."""
    n = len(paths)
    out = []
    start = 0
    for i in range(k):
        size = n // k + (1 if i < n % k else 0)
        out.append(paths[start:start + size])
        start += size
    return out


def skip_args(all_paths, chunk):
    keep = set(chunk)
    return [p for p in all_paths if p not in keep]


def check(all_paths, chosen, k):
    problems = []
    if not chosen:
        problems.append("no test selected")
        return problems
    if k < 1 or k > len(chosen):
        problems.append(f"{k} shards for {len(chosen)} tests")
        return problems
    parts = shards(chosen, k)
    seen = {}
    for i, part in enumerate(parts):
        if not part:
            problems.append(f"shard {i} is empty")
        run = [p for p in all_paths if p not in set(skip_args(all_paths, part))]
        if run != part:
            problems.append(f"shard {i}: the skip list does not leave the shard")
        for p in part:
            if p in seen:
                problems.append(f"{p}: in shard {seen[p]} and shard {i}")
            seen[p] = i
    for p in chosen:
        if p not in seen:
            problems.append(f"{p}: in no shard")
    return problems


def self_test():
    names = [f"{BASE}/t{i:02d}" for i in range(10)] + [f"{BASE}/io-fuzz-{i}"
                                                       for i in range(3)]
    listing = "\n".join(["/x86_64/pc/other/test"] + [f"# {p}" for p in names]
                        + [f"# {names[0]}"])
    bad = 0

    def expect(name, cond):
        nonlocal bad
        if not cond:
            print(f"self-test: {name}")
            bad += 1

    paths = test_paths(listing)
    expect("parse keeps femu-tests paths once, in order", paths == names)
    plain = select(paths, None, "fuzz")
    expect("--skip drops the fuzz tests", len(plain) == 10)
    expect("--only keeps the fuzz tests", len(select(paths, "fuzz", None)) == 3)
    parts = shards(plain, 3)
    expect("shard sizes 4 3 3", [len(p) for p in parts] == [4, 3, 3])
    expect("shards keep list order", sum(parts, []) == plain)
    expect("a good split passes", check(paths, plain, 3) == [])
    expect("more shards than tests fails", check(paths, plain, 11) != [])
    expect("no tests fails", check(paths, [], 2) != [])
    skips = skip_args(paths, parts[1])
    expect("the skip list leaves only shard 1",
           [p for p in paths if p not in skips] == parts[1])
    expect("a fuzz test is skipped in a plain shard", names[10] in skips)
    print(f"qtest-shard self-test: {10 - bad} of 10 passed")
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--shards", type=int)
    ap.add_argument("--index", type=int)
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--only")
    ap.add_argument("--skip")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    if not a.shards or (a.index is None) == (not a.check):
        ap.error("give --shards with exactly one of --index or --check")
    all_paths = test_paths(sys.stdin.read())
    chosen = select(all_paths, a.only, a.skip)
    problems = check(all_paths, chosen, a.shards)
    if problems:
        for p in problems:
            print(f"qtest-shard: {p}", file=sys.stderr)
        return 1
    if a.check:
        sizes = " ".join(str(len(p)) for p in shards(chosen, a.shards))
        print(f"qtest-shard: {len(chosen)} tests in {a.shards} shards ({sizes})")
        return 0
    if not 0 <= a.index < a.shards:
        ap.error("--index must be in 0 to K-1")
    part = shards(chosen, a.shards)[a.index]
    print(" ".join(f"-s {p}" for p in skip_args(all_paths, part)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
