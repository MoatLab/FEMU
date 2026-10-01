#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Render the FEMU mode table from hw/femu/docs/modes.py.

The table goes between the markers

  <!-- modes-table:start -->
  <!-- modes-table:end -->

in README.md and in every Markdown file under hw/femu/docs/ that has them.
Links in the table are written relative to the file that holds it.

Usage:
  gen-mode-table.py            # rewrite the tables
  gen-mode-table.py --check    # verify only

--check exits 1 when a table differs from a fresh rendering, when README.md
has no markers, or when modes.py disagrees with the tree: an enum symbol with
the wrong value, a femu_mode value no entry covers, a launcher that is not in
hw/femu/scripts, or a guide link whose file or heading does not exist.
"""

import argparse
import os
import re
import runpy
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
MODES_PY = os.path.join(ROOT, "hw", "femu", "docs", "modes.py")
NVME_H = os.path.join(ROOT, "hw", "femu", "nvme.h")
SCRIPTS = os.path.join(ROOT, "hw", "femu", "scripts")
START = "<!-- modes-table:start -->"
END = "<!-- modes-table:end -->"
NOTE = ("<!-- Generated from hw/femu/docs/modes.py by "
        "hw/femu/scripts/gen-mode-table.py; edit modes.py, not this table. -->")
FIELDS = ("key", "name", "use", "device", "symbol", "femu_mode", "select",
          "example", "io", "guest_kernel", "guest_tools", "host", "launcher",
          "guide", "guest_check")
IO_TEXT = {
    "rw": "realize, Identify, write and read back",
    "kv": "realize, Identify, store and retrieve",
    "identify": "realize, Identify",
    "none": "realize",
}


def load_modes():
    return runpy.run_path(MODES_PY)["MODES"]


def links_module():
    path = os.path.join(SCRIPTS, "check-doc-links.py")
    return runpy.run_path(path)


def mode_enum():
    """femu_mode symbols with an explicit value in hw/femu/nvme.h."""
    with open(NVME_H, encoding="utf-8") as f:
        text = f.read()
    return {m.group(1): int(m.group(2))
            for m in re.finditer(r"\b(FEMU_\w+_MODE)\s*=\s*(\d+)\s*,", text)}


def rel(target, md_file):
    """A repository path (with #anchor) as a link from md_file."""
    path, _, frag = target.partition("#")
    if frag and os.path.join(ROOT, path) == md_file:
        return "#" + frag
    r = os.path.relpath(os.path.join(ROOT, path), os.path.dirname(md_file))
    return r + ("#" + frag if frag else "")


def cell(text):
    return text.replace("|", "\\|").replace("\n", " ")


def render(modes, md_file):
    rows = [NOTE, "",
            "| Mode or feature | Use it for | Turn it on with | Guest kernel "
            "| Guest tools | Host needs | Launcher | Checked |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for m in modes:
        name = f"[{m['name']}]({rel(m['guide'], md_file)})"
        launcher = f"`{m['launcher']}`" if m["launcher"] else "none"
        checked = f"CI: {IO_TEXT[m['io']]}"
        if m["guest_check"]:
            what, doc = m["guest_check"]
            checked += f"; guest: [{what}]({rel(doc, md_file)})"
        rows.append("| " + " | ".join(cell(c) for c in (
            name, m["use"], m["select"], m["guest_kernel"], m["guest_tools"],
            m["host"], launcher, checked)) + " |")
    return "\n".join(rows)


def validate(modes):
    errors = []
    enum = mode_enum()
    links = links_module()
    seen_keys = set()
    covered = set()
    for m in modes:
        k = m.get("key", "?")
        for f in FIELDS:
            if f not in m:
                errors.append(f"modes.py: {k}: missing field {f}")
        if errors:
            continue
        if k in seen_keys:
            errors.append(f"modes.py: duplicate key {k}")
        seen_keys.add(k)
        if m["io"] not in IO_TEXT:
            errors.append(f"modes.py: {k}: io must be one of {sorted(IO_TEXT)}")
        if m["symbol"] is not None:
            if m["symbol"] not in enum:
                errors.append(f"modes.py: {k}: {m['symbol']} is not a mode "
                              "in hw/femu/nvme.h")
            elif enum[m["symbol"]] != m["femu_mode"]:
                errors.append(f"modes.py: {k}: {m['symbol']} is "
                              f"{enum[m['symbol']]} in hw/femu/nvme.h, not "
                              f"{m['femu_mode']}")
            else:
                covered.add(m["symbol"])
        if m["launcher"] and not os.path.isfile(os.path.join(SCRIPTS, m["launcher"])):
            errors.append(f"modes.py: {k}: no launcher hw/femu/scripts/{m['launcher']}")
        err = links["check_link"](ROOT, os.path.join(ROOT, "README.md"),
                                  "/" + m["guide"])
        if err:
            errors.append(f"modes.py: {k}: guide {err}")
        if m["guest_check"]:
            err = links["check_link"](ROOT, os.path.join(ROOT, "README.md"),
                                      "/" + m["guest_check"][1])
            if err:
                errors.append(f"modes.py: {k}: guest_check {err}")
    for sym in sorted(set(enum) - covered):
        errors.append(f"modes.py: no entry for {sym} = {enum[sym]} "
                      "(hw/femu/nvme.h); add one")
    return errors


def target_files():
    out = [os.path.join(ROOT, "README.md")]
    for dirpath, _, names in os.walk(os.path.join(ROOT, "hw", "femu", "docs")):
        out.extend(os.path.join(dirpath, n) for n in sorted(names)
                   if n.endswith(".md"))
    return out


def splice(text, table, path):
    """Replace what is between the markers, each alone on its line; return
    None when there are none. A marker quoted in prose is not a marker."""
    lines = text.split("\n")
    starts = [i for i, l in enumerate(lines) if l.strip() == START]
    ends = [i for i, l in enumerate(lines) if l.strip() == END]
    if not starts and not ends:
        return None
    if len(starts) != 1 or len(ends) != 1 or starts[0] > ends[0]:
        raise ValueError(f"{path}: needs exactly one {START} line before one "
                         f"{END} line")
    return "\n".join(lines[:starts[0] + 1] + [table] + lines[ends[0]:])


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true",
                    help="fail instead of rewriting a stale table")
    args = ap.parse_args()

    modes = load_modes()
    errors = validate(modes)
    readme = os.path.join(ROOT, "README.md")
    found = []
    for path in target_files():
        with open(path, encoding="utf-8") as f:
            text = f.read()
        try:
            new = splice(text, render(modes, path), os.path.relpath(path, ROOT))
        except ValueError as e:
            errors.append(str(e))
            continue
        if new is None:
            continue
        found.append(path)
        if new == text:
            continue
        if args.check:
            errors.append(f"{os.path.relpath(path, ROOT)}: mode table is stale; "
                          "run hw/femu/scripts/gen-mode-table.py")
        else:
            with open(path, "w", encoding="utf-8") as f:
                f.write(new)
            print(f"wrote {os.path.relpath(path, ROOT)}")
    if readme not in found:
        errors.append(f"README.md: no {START} ... {END} markers")

    for e in errors:
        print(e)
    print(f"gen-mode-table: {len(modes)} entries, {len(found)} tables, "
          f"{len(errors)} errors")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
