#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check the relative links in FEMU's Markdown documentation.

Every relative link in README.md and hw/femu/docs/**/*.md must name a file or
directory that exists, and a "#fragment" on a Markdown target must name a
heading (or an explicit <a id/name> anchor) in that file. Heading anchors
follow GitHub's rules, so a link that passes here works on github.com.

External links (http:, https:, mailto: and so on) are not fetched.

Exit status: 0 when every link resolves, 1 otherwise.
"""

import argparse
import os
import re
import sys
import urllib.parse

DEFAULT_FILES = ["README.md"]
DEFAULT_DIRS = ["hw/femu/docs"]

FENCE_RE = re.compile(r"^\s{0,3}(`{3,}|~{3,})")
HEADING_RE = re.compile(r"^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$")
INLINE_CODE_RE = re.compile(r"(`+)(.+?)\1")
# [text](target "title") and ![alt](target); text may hold one level of [].
INLINE_LINK_RE = re.compile(
    r"!?\[(?:[^\[\]]|\[[^\[\]]*\])*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
REF_DEF_RE = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s+.*)?$")
HTML_LINK_RE = re.compile(r"""<(?:a|img)\s[^>]*?(?:href|src)\s*=\s*["']([^"']+)["']""",
                          re.IGNORECASE)
HTML_ANCHOR_RE = re.compile(r"""<a\s[^>]*?(?:id|name)\s*=\s*["']([^"']+)["']""",
                            re.IGNORECASE)
SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")


def strip_code(lines):
    """Yield (lineno, text) for lines outside fenced code blocks, with inline
    code spans blanked so links inside them are not checked."""
    fence = None
    for n, line in enumerate(lines, 1):
        m = FENCE_RE.match(line)
        if fence:
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence):
                fence = None
            continue
        if m:
            fence = m.group(1)
            continue
        yield n, INLINE_CODE_RE.sub(lambda c: " " * len(c.group(0)), line)


def slugify(heading):
    """GitHub's heading anchor: plain text, lower case, punctuation other than
    '-' and '_' dropped, spaces turned into '-'."""
    text = INLINE_CODE_RE.sub(lambda c: c.group(2), heading)
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", text)  # links -> text
    text = re.sub(r"<[^>]+>", "", text)                      # inline HTML
    text = text.lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


_anchor_cache = {}


def anchors_of(path):
    if path in _anchor_cache:
        return _anchor_cache[path]
    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    found = set()
    seen = {}
    fence = None
    for line in lines:
        m = FENCE_RE.match(line)
        if fence:
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence):
                fence = None
            continue
        if m:
            fence = m.group(1)
            continue
        h = HEADING_RE.match(line)
        if h:
            slug = slugify(h.group(2))
            k = seen.get(slug, 0)
            seen[slug] = k + 1
            found.add(slug if k == 0 else f"{slug}-{k}")
        for a in HTML_ANCHOR_RE.findall(line):
            found.add(a)
    _anchor_cache[path] = found
    return found


def links_in(path):
    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    for n, line in strip_code(lines):
        for rx in (INLINE_LINK_RE, HTML_LINK_RE):
            for m in rx.finditer(line):
                yield n, m.group(1)
        m = REF_DEF_RE.match(line)
        if m:
            yield n, m.group(1)


def check_link(root, src, target):
    """Return an error string, or None when the link resolves."""
    if SCHEME_RE.match(target) or target.startswith("//"):
        return None
    path_part, _, frag = target.partition("#")
    path_part = urllib.parse.unquote(path_part.split("?", 1)[0])
    if not path_part:
        dest = src
    elif path_part.startswith("/"):
        dest = os.path.join(root, path_part.lstrip("/"))
    else:
        dest = os.path.normpath(os.path.join(os.path.dirname(src), path_part))
    if not os.path.realpath(dest).startswith(os.path.realpath(root) + os.sep):
        return f"points outside the repository: {target}"
    if not os.path.exists(dest):
        return f"no such file: {os.path.relpath(dest, root)}"
    if frag and dest.endswith(".md") and os.path.isfile(dest):
        frag = urllib.parse.unquote(frag)
        if frag not in anchors_of(dest):
            return f"no anchor #{frag} in {os.path.relpath(dest, root)}"
    return None


def collect(root, files, dirs):
    out = []
    for f in files:
        p = os.path.join(root, f)
        if not os.path.isfile(p):
            sys.exit(f"check-doc-links: {f} not found under {root}")
        out.append(p)
    for d in dirs:
        base = os.path.join(root, d)
        if not os.path.isdir(base):
            sys.exit(f"check-doc-links: {d} not found under {root}")
        for dirpath, _, names in os.walk(base):
            out.extend(os.path.join(dirpath, n) for n in sorted(names)
                       if n.endswith(".md"))
    return sorted(set(out))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", default=os.path.normpath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../..")),
        help="repository root (default: derived from this script's path)")
    ap.add_argument("paths", nargs="*",
                    help="Markdown files to check instead of README.md and "
                         "hw/femu/docs/**")
    args = ap.parse_args()
    root = os.path.abspath(args.root)

    if args.paths:
        files = [os.path.abspath(p) for p in args.paths]
    else:
        files = collect(root, DEFAULT_FILES, DEFAULT_DIRS)
    if not files:
        sys.exit("check-doc-links: no Markdown files to check")

    nlinks = 0
    errors = []
    for src in files:
        for n, target in links_in(src):
            nlinks += 1
            err = check_link(root, src, target)
            if err:
                errors.append(f"{os.path.relpath(src, root)}:{n}: {err}")

    for e in errors:
        print(e)
    print(f"check-doc-links: {len(files)} files, {nlinks} links, "
          f"{len(errors)} broken")
    if nlinks == 0:
        print("check-doc-links: found no links at all; the parser is broken")
        return 1
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
