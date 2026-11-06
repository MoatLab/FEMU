#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Check that each device property is named by a test or a script.

The property names come from hw/femu/docs/reference/properties.md, which
gen-property-docs.py writes from the binary and CI checks. A property
counts as named when a file under hw/femu/tests/ or hw/femu/scripts/ holds
the name as a whole word. hw/femu/tests/untested-properties.list lists the
properties that no file names yet, one per line, with a reason:

    NAME  REASON

The check fails for a property that is neither named nor listed, for a
listed property that a file now names (remove the line), for a listed name
that is not a property, and for a line with no reason.

Usage:
    check-property-tests.py
    check-property-tests.py --self-test
"""

import os
import re
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
FEMU = os.path.join(ROOT, "hw", "femu")
REFERENCE = os.path.join(FEMU, "docs", "reference", "properties.md")
EXEMPT = os.path.join(FEMU, "tests", "untested-properties.list")
SEARCH = [os.path.join(FEMU, "tests"), os.path.join(FEMU, "scripts")]
# files that list property names without using them
SKIP = {"gen-property-docs.py", "check-property-tests.py",
        "untested-properties.list"}
SUFFIXES = (".c", ".h", ".sh", ".py", ".ini", ".cfg", ".conf", ".json")


def property_names(text):
    """Property names from the reference tables, without the env section."""
    names = []
    section = ""
    for line in text.split("\n"):
        if line.startswith("## "):
            section = line
        if "Environment variables" in section:
            continue
        m = re.match(r"^\| `([A-Za-z0-9_.-]+)` \|", line)
        if m:
            names.append(m.group(1))
    return sorted(set(names))


def corpus(dirs):
    parts = []
    for top in dirs:
        for d, _, files in os.walk(top):
            for name in sorted(files):
                if name in SKIP:
                    continue
                if not name.endswith(SUFFIXES) and "." in name:
                    continue
                try:
                    with open(os.path.join(d, name), "rb") as f:
                        raw = f.read()
                except OSError:
                    continue
                # a built test binary names functions, not properties
                if b"\0" in raw:
                    continue
                parts.append(raw.decode("utf-8", "replace"))
    return "\n".join(parts)


def named(prop, text):
    return re.search(r"(?<![A-Za-z0-9_.-])" + re.escape(prop) +
                     r"(?![A-Za-z0-9_-])", text) is not None


def read_exempt(text):
    """Return ({name: reason}, problems)."""
    out = {}
    problems = []
    for n, line in enumerate(text.split("\n"), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) < 2:
            problems.append(f"untested-properties.list:{n}: {parts[0]} has no reason")
            continue
        if parts[0] in out:
            problems.append(f"untested-properties.list:{n}: {parts[0]} listed twice")
        out[parts[0]] = parts[1]
    return out, problems


def check(props, text, exempt_text):
    exempt, problems = read_exempt(exempt_text)
    if not props:
        problems.append("properties.md: no property names found")
    for p in props:
        hit = named(p, text)
        if not hit and p not in exempt:
            problems.append(f"{p}: no test or script names it; add a test, "
                            "or a line with a reason to untested-properties.list")
        if hit and p in exempt:
            problems.append(f"{p}: a test or script names it now; remove it "
                            "from untested-properties.list")
    for p in exempt:
        if p not in props:
            problems.append(f"{p}: in untested-properties.list, but not a property")
    return problems


def self_test():
    props = ["alpha", "beta", "gamma_x", "theta"]
    text = "-device femu,alpha=1\nqtest_set(\"beta\", 2);\ngamma_x_long=3\n"
    cases = [
        ("all covered", "gamma_x  reason\ntheta  reason\n", 0),
        ("one untested, not listed", "theta  reason\n", 1),
        ("listed but tested", "alpha  reason\ngamma_x  r\ntheta  r\n", 1),
        ("listed, not a property", "gamma_x r\ntheta r\nomega r\n", 1),
        ("no reason", "gamma_x\ntheta  r\n", 2),
        ("prefix does not count", "theta r\n", 1),
    ]
    bad = 0
    with tempfile.TemporaryDirectory() as tmp:
        open(os.path.join(tmp, "bin"), "wb").write(b"\x7fELF\0theta\0")
        open(os.path.join(tmp, "t.c"), "w").write("gamma_x=1\n")
        if named("theta", corpus([tmp])) or not named("gamma_x", corpus([tmp])):
            print("self-test: a binary counted, or a source did not")
            bad += 1
    for name, ex, want in cases:
        got = len(check(props, text, ex))
        if got != want:
            print(f"self-test: {name}: {got} problem(s), want {want}")
            bad += 1
    if not check([], text, ""):
        print("self-test: an empty property list gave no problem")
        bad += 1
    if property_names("## `femu`\n| `a_b` | `bool` |\n## Environment variables\n"
                      "| `FEMU_X` | x |\n") != ["a_b"]:
        print("self-test: the reference parser read the environment section")
        bad += 1
    total = len(cases) + 3
    print(f"check-property-tests self-test: {total - bad} of {total} passed")
    return 1 if bad else 0


def main():
    args = sys.argv[1:]
    if args == ["--self-test"]:
        return self_test()
    if args:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        with open(REFERENCE, encoding="utf-8") as f:
            props = property_names(f.read())
        with open(EXEMPT, encoding="utf-8") as f:
            exempt_text = f.read()
    except OSError as e:
        print(f"check-property-tests: cannot read {e.filename}: {e.strerror}")
        return 2
    problems = check(props, corpus(SEARCH), exempt_text)
    for p in problems:
        print(f"check-property-tests: {p}")
    if problems:
        return 1
    n = len(read_exempt(exempt_text)[0])
    print(f"check-property-tests: {len(props)} properties, {len(props) - n} "
          f"named by a test or script, {n} listed as untested")
    return 0


if __name__ == "__main__":
    sys.exit(main())
