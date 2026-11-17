#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Print the release notes of a tag from the changelog, or check its layout.

hw/femu/docs/CHANGELOG.md holds one "## Unreleased (since TAG)" section
first, then one section per release, newest first:

    ## Unreleased (since femu-v11.1.0)       (can be empty)
    ## femu-v11.1.0 (2026-12-01)              (needs at least one line)

Usage:
    release-notes.py TAG          print the section of TAG, without heading
    release-notes.py --check      check the layout
    release-notes.py --self-test
"""

import datetime
import os
import re
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..",
                                    ".."))
CHANGELOG = os.path.join(ROOT, "hw", "femu", "docs", "CHANGELOG.md")
UNRELEASED = re.compile(r"^## Unreleased \(since (femu-v\d+\.\d+\.\d+)\)$")
RELEASE = re.compile(r"^## (femu-v(\d+)\.(\d+)\.(\d+)) \((\d{4}-\d{2}-\d{2})\)$")


def sections(text):
    """(heading, body lines) for each level-two heading, in order."""
    out = []
    fence = None
    for line in text.split("\n"):
        m = re.match(r"^ {0,3}(```+|~~~+)", line)
        if m:
            # a heading inside a fenced block is an example, not a section
            if fence is None:
                fence = m.group(1)[0]
            elif m.group(1)[0] == fence:
                fence = None
        if fence is None and line.startswith("## "):
            out.append([line, []])
        elif out:
            out[-1][1].append(line)
    return out


def git_tag_exists(tag):
    r = subprocess.run(["git", "-C", ROOT, "rev-parse", "-q", "--verify",
                        "refs/tags/" + tag], capture_output=True)
    return r.returncode == 0


def real_date(text):
    try:
        datetime.date.fromisoformat(text)
        return True
    except ValueError:
        return False


def check(text, tag_exists=git_tag_exists):
    problems = []
    secs = sections(text)
    if not secs or not UNRELEASED.match(secs[0][0]):
        problems.append("the first section must be "
                        "'## Unreleased (since femu-vX.Y.Z)'")
    releases = []
    for i, (head, body) in enumerate(secs):
        if i == 0 and UNRELEASED.match(head):
            continue
        m = RELEASE.match(head)
        if not m:
            problems.append("bad heading: %s" % head)
            continue
        # an entry is text; a heading or a comment alone is not one
        if not any(line.strip() and
                   not re.match(r"^ {0,3}#", line) and
                   not re.match(r"^\s*<!--.*-->\s*$", line)
                   for line in body):
            problems.append("%s has no entry" % m.group(1))
        if not real_date(m.group(5)):
            problems.append("%s has no real date: %s" % (m.group(1),
                                                        m.group(5)))
        releases.append((tuple(int(x) for x in m.group(2, 3, 4)),
                         m.group(5), m.group(1)))
    names = [r[2] for r in releases]
    for dup in sorted({n for n in names if names.count(n) > 1}):
        problems.append("%s has two sections" % dup)
    for a, b in zip(releases, releases[1:]):
        if not (a[0] > b[0] and a[1] >= b[1]):
            problems.append("%s must come after %s: newest first" %
                            (b[2], a[2]))
    m = secs and UNRELEASED.match(secs[0][0])
    if m and releases and m.group(1) != releases[0][2]:
        problems.append("Unreleased names %s, but the newest release is %s"
                        % (m.group(1), releases[0][2]))
    if m and not releases and not tag_exists(m.group(1)):
        problems.append("Unreleased names %s, which is not a tag" %
                        m.group(1))
    return problems


def notes(text, tag):
    for head, body in sections(text):
        m = RELEASE.match(head)
        if m and m.group(1) == tag:
            return "\n".join(body).strip("\n") + "\n"
    return None


def self_test():
    good = ("# Changelog\n\nintro\n\n## Unreleased (since femu-v11.1.0)\n\n"
            "## femu-v11.1.0 (2026-12-01)\n\n- new\n\n"
            "## femu-v10.1.0 (2026-06-01)\n\n- old\n")
    cases = [
        ("good, empty Unreleased", good, 0),
        ("no Unreleased", good.replace("## Unreleased (since femu-v11.1.0)"
                                       "\n", ""), 1),
        ("Unreleased not first", good.replace(
            "## Unreleased (since femu-v11.1.0)\n\n", "") +
         "## Unreleased (since femu-v11.1.0)\n", 1),
        ("empty release", good.replace("- new\n", ""), 1),
        ("bad heading", good.replace("(2026-12-01)", "(Dec 1)"), 1),
        # only the version order is wrong: the dates and the Unreleased
        # heading agree with the first section
        ("old first", good.replace("femu-v11.1.0", "femu-v9.0.1"), 1),
        ("numeric order", good.replace("femu-v10.1.0", "femu-v9.0.1"), 0),
        ("Unreleased names an old tag", good.replace("(since femu-v11.1.0)",
                                                     "(since femu-v10.1.0)"),
         1),
        ("no real date", good.replace("2026-12-01", "2026-99-99"), 1),
        ("only a subsection heading", good.replace("- new\n", "### Fixes\n"),
         1),
        ("bad version in Unreleased",
         good.replace("(since femu-v11.1.0)", "(since femu-v...)"), 1),
        ("first release: Unreleased names a tag",
         "## Unreleased (since femu-v9.0.1)\n\n- a\n", 0),
        ("first release: Unreleased names no tag",
         "## Unreleased (since femu-v9.0.2)\n\n- a\n", 1),
        ("a comment is no entry",
         good.replace("- new\n", "<!-- TODO: write notes -->\n"), 1),
        ("an indented heading is no entry",
         good.replace("- new\n", "  ### Fixes\n"), 1),
        ("a heading inside a fenced block",
         good.replace("- old\n", "- old\n\n```\n## Unreleased (since "
                      "femu-v12.0.0)\n```\n"), 0),
        ("two sections of one tag", good.replace("femu-v10.1.0 (2026-06-01)",
                                                 "femu-v11.1.0 (2026-06-01)"),
         1),
    ]
    failed = 0
    for name, text, want in cases:
        got = 1 if check(text, lambda t: t == "femu-v9.0.1") else 0
        failed += got != want
        print("%s %s" % ("ok" if got == want else "FAIL", name))
    ok = notes(good, "femu-v11.1.0") == "\n- new\n".strip("\n") + "\n" and \
        notes(good, "femu-v10.1.0") == "- old\n" and \
        notes(good, "femu-v12.0.0") is None
    failed += not ok
    print("%s notes of a tag" % ("ok" if ok else "FAIL"))
    return 1 if failed else 0


def main(argv):
    if argv == ["--self-test"]:
        return self_test()
    try:
        with open(CHANGELOG) as f:
            text = f.read()
    except OSError as e:
        print("release-notes: %s" % e, file=sys.stderr)
        return 2
    if argv == ["--check"]:
        problems = check(text)
        for p in problems:
            print("release-notes: " + p)
        print("release-notes: %d problem(s)" % len(problems))
        return 1 if problems else 0
    if len(argv) == 1 and not argv[0].startswith("-"):
        body = notes(text, argv[0])
        if not body or not body.strip():
            print("release-notes: no section for %s" % argv[0],
                  file=sys.stderr)
            return 1
        sys.stdout.write(body)
        return 0
    print(__doc__.strip(), file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
