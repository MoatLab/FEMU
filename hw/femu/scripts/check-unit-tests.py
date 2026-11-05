#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Check that CI runs every FEMU unit test.

The unit tests live in hw/femu/tests/unit/test-NAME.c and build as
test-femu-NAME. Two lists run them: femu_unit_tests in
hw/femu/tests/meson.build (the femu-unit suite) and UNIT_TESTS in
hw/femu/tests/Makefile (make check). A source in neither list never runs.

Usage:
    check-unit-tests.py                  every unit test is in a list
    check-unit-tests.py --meson-names    print the meson test names
    check-unit-tests.py --listed FILE    FILE (meson test --list output) names
                                         every meson test, and no other
    check-unit-tests.py --self-test
"""

import os
import re
import sys
import tempfile

TESTS = "hw/femu/tests"


def meson_names(text):
    """Test names in the femu_unit_tests dictionary of meson.build."""
    m = re.search(r"femu_unit_tests\s*=\s*\{(.*?)\n\}", text, re.S)
    if not m:
        return None
    return sorted(set(re.findall(r"'(test-femu-[a-z0-9-]+)'\s*:", m.group(1))))


def make_names(text):
    """Test names in every UNIT_TESTS assignment of the Makefile."""
    names = set()
    joined = text.replace("\\\n", " ")
    for m in re.finditer(r"^UNIT_TESTS\s*\+?=(.*)$", joined, re.M):
        names.update(re.findall(r"test-femu-[a-z0-9-]+", m.group(1)))
    return sorted(names)


def sources(unit_dir):
    """test-femu-NAME for each unit/test-NAME.c."""
    out = []
    for name in sorted(os.listdir(unit_dir)):
        m = re.fullmatch(r"test-([a-z0-9-]+)\.c", name)
        if m:
            out.append("test-femu-" + m.group(1))
    return out


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def check_tree(tests):
    """Return a list of problems for the tree at tests (hw/femu/tests)."""
    try:
        meson = meson_names(read(os.path.join(tests, "meson.build")))
        make = make_names(read(os.path.join(tests, "Makefile")))
        srcs = sources(os.path.join(tests, "unit"))
    except OSError as e:
        return [f"cannot read {e.filename}: {e.strerror}"]
    problems = []
    if not meson:
        problems.append("meson.build: no femu_unit_tests entries")
    if not make:
        problems.append("Makefile: no UNIT_TESTS entries")
    if not srcs:
        problems.append("unit/: no test-*.c source")
    for t in srcs:
        if t not in (meson or []) and t not in make:
            problems.append(f"{t}: in neither meson.build nor the Makefile")
    for t in sorted(set(meson or []) | set(make)):
        if t not in srcs:
            problems.append(f"{t}: listed, but unit/{t[len('test-femu-'):]}.c"
                            " does not exist")
    return problems


def check_listed(tests, listed_text):
    """Compare meson test --list output with the meson.build names."""
    want = meson_names(read(os.path.join(tests, "meson.build"))) or []
    got = sorted(set(re.findall(r"test-femu-[a-z0-9-]+", listed_text)))
    problems = []
    if not want:
        problems.append("meson.build: no femu_unit_tests entries")
    for t in want:
        if t not in got:
            problems.append(f"{t}: in meson.build, not in the suite list")
    for t in got:
        if t not in want:
            problems.append(f"{t}: in the suite list, not in meson.build")
    return problems


def report(problems, ok):
    for p in problems:
        print(f"check-unit-tests: {p}")
    if problems:
        return 1
    print(ok)
    return 0


MESON = """femu_unit_tests = {
  'test-femu-a': files('unit/test-a.c'),
  'test-femu-b': files('unit/test-b.c',
                       '../x.c'),
}
"""
MAKE = """UNIT_TESTS = test-femu-a test-femu-c \\
             test-femu-d
ifeq ($(HAVE_GLIB),1)
UNIT_TESTS += test-femu-e
endif
"""


def self_test():
    """Build small trees with planted faults; each must give a problem."""
    bad = 0

    def tree(units, meson=MESON, make=MAKE):
        d = tempfile.mkdtemp()
        os.mkdir(os.path.join(d, "unit"))
        for u in units:
            open(os.path.join(d, "unit", f"test-{u}.c"), "w").close()
        open(os.path.join(d, "meson.build"), "w").write(meson)
        open(os.path.join(d, "Makefile"), "w").write(make)
        return d

    cases = [
        ("all listed", tree("abcde"), 0),
        ("source in no list", tree("abcdef"), 1),
        ("listed, no source", tree("abcd"), 1),
        ("empty meson list", tree("abcde", meson="x = 1\n"), 2),
        ("empty Makefile list", tree("abcde", make="all:\n"), 4),
        ("no sources", tree(""), 6),
    ]
    for name, d, want in cases:
        got = len(check_tree(d))
        if got != want:
            print(f"self-test: {name}: {got} problem(s), want {want}")
            bad += 1
    if not check_tree(os.path.join(tempfile.gettempdir(), "no-such-tests")):
        print("self-test: a missing tree gave no problem")
        bad += 1
    d = tree("abcde")
    listed = [
        ("suite matches", "1/2 test-femu-a OK\ntest-femu-b\n", 0),
        ("suite misses one", "test-femu-a\n", 1),
        ("suite is empty", "", 2),
        ("suite has an extra", "test-femu-a test-femu-b test-femu-z\n", 1),
    ]
    for name, text, want in listed:
        got = len(check_listed(d, text))
        if got != want:
            print(f"self-test: {name}: {got} problem(s), want {want}")
            bad += 1
    total = len(cases) + 1 + len(listed)
    print(f"check-unit-tests self-test: {total - bad} of {total} passed")
    return 1 if bad else 0


def main():
    args = sys.argv[1:]
    if args == ["--self-test"]:
        return self_test()
    if args == ["--meson-names"]:
        for t in meson_names(read(os.path.join(TESTS, "meson.build"))) or []:
            print(t)
        return 0
    if len(args) == 2 and args[0] == "--listed":
        problems = check_listed(TESTS, read(args[1]))
        return report(problems, "check-unit-tests: the suite runs every "
                                "meson unit test")
    if args:
        print(__doc__, file=sys.stderr)
        return 2
    return report(check_tree(TESTS), "check-unit-tests: every unit test is "
                                     "in meson.build or the Makefile")


if __name__ == "__main__":
    sys.exit(main())
