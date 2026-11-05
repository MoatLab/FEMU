#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Check the FEMU C sources for C99 comments and trailing whitespace.

A "//" counts only outside string literals, character literals and block
comments, so a URL in a comment or a "//" in a format string passes. The
check fails when it finds no source file, so a wrong path cannot pass.

Usage:
    check-c-style.py [DIR]     scan DIR (default: hw/femu), exit 1 on a finding
    check-c-style.py --self-test
"""

import os
import sys
import tempfile


def c99_comment_lines(text):
    """Return the 1-based line numbers that hold a "//" comment."""
    hits = []
    line = 1
    state = "code"
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "\n":
            line += 1
            if state in ("str", "chr"):
                state = "code"
            i += 1
            continue
        if state == "code":
            if c == "/" and nxt == "/":
                hits.append(line)
                while i < n and text[i] != "\n":
                    i += 1
                continue
            if c == "/" and nxt == "*":
                state = "block"
                i += 2
                continue
            if c == '"':
                state = "str"
            elif c == "'":
                state = "chr"
        elif state == "block":
            if c == "*" and nxt == "/":
                state = "code"
                i += 2
                continue
        elif state in ("str", "chr"):
            if c == "\\":
                i += 2
                continue
            if (state == "str" and c == '"') or (state == "chr" and c == "'"):
                state = "code"
        i += 1
    return hits


def scan_file(path):
    """Return a list of (line, reason) findings for one file."""
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    found = [(ln, "C99 comment, use /* */") for ln in c99_comment_lines(text)]
    for ln, s in enumerate(text.split("\n"), 1):
        if s != s.rstrip():
            found.append((ln, "trailing whitespace"))
    return sorted(found)


def scan_tree(root):
    """Return (number of files, findings) for every .c and .h under root."""
    files = 0
    findings = []
    for d, _, names in os.walk(root):
        for name in sorted(names):
            if not name.endswith((".c", ".h")):
                continue
            path = os.path.join(d, name)
            files += 1
            findings += [(path, ln, why) for ln, why in scan_file(path)]
    return files, findings


def run(root):
    if not os.path.isdir(root):
        print(f"check-c-style: {root}: not a directory", file=sys.stderr)
        return 2
    files, findings = scan_tree(root)
    if files == 0:
        print(f"check-c-style: {root}: no .c or .h file", file=sys.stderr)
        return 2
    for path, ln, why in findings:
        print(f"{path}:{ln}: {why}")
    if findings:
        print(f"check-c-style: {len(findings)} finding(s) in {files} files",
              file=sys.stderr)
        return 1
    print(f"check-c-style: {files} files, no C99 comments or trailing whitespace")
    return 0


def self_test():
    """Plant each fault and each allowed form; the check must sort them."""
    cases = {
        "bad-comment.c": ("int a; // planted\n", 1),
        "bad-line.c": ("// planted\nint b;\n", 1),
        "bad-space.h": ("int c; \n", 1),
        "bad-tab.c": ("int d;\t\n", 1),
        "ok-url.c": ("/* see https://example.org/x */\nint e;\n", 0),
        "ok-string.c": ('const char *f = "a//b";\n', 0),
        "ok-char.c": ("char g = '/'; char h = '\\'';\n", 0),
        "ok-block.c": ("/*\n * x // y\n */\nint i;\n", 0),
        "ok-escape.c": ('const char *j = "\\"//";\n', 0),
    }
    bad = 0
    with tempfile.TemporaryDirectory() as tmp:
        for name, (body, want) in cases.items():
            with open(os.path.join(tmp, name), "w") as f:
                f.write(body)
            got = len(scan_file(os.path.join(tmp, name)))
            if got != want:
                print(f"self-test: {name}: {got} finding(s), want {want}")
                bad += 1
        if run(tmp) != 1:
            print("self-test: a tree with planted faults did not fail")
            bad += 1
    with tempfile.TemporaryDirectory() as tmp:
        if run(tmp) != 2:
            print("self-test: an empty tree did not fail")
            bad += 1
    if run(os.path.join(tempfile.gettempdir(), "check-c-style-none")) != 2:
        print("self-test: a missing directory did not fail")
        bad += 1
    print(f"check-c-style self-test: {len(cases) + 3 - bad} of "
          f"{len(cases) + 3} passed")
    return 1 if bad else 0


def main():
    args = sys.argv[1:]
    if args == ["--self-test"]:
        return self_test()
    if len(args) > 1:
        print(__doc__, file=sys.stderr)
        return 2
    return run(args[0] if args else "hw/femu")


if __name__ == "__main__":
    sys.exit(main())
