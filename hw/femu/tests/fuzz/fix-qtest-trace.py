#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Join each [DMA] tag of a generic fuzz QTEST_LOG trace with its request.

In the fuzzer, qtest logs with a timer that the /dev/null channel freed.
GLib then prints "g_timer_elapsed: assertion 'timer != NULL' failed" on
the same line as the [DMA] tag, so the request goes to the next line.
reorder_fuzzer_qtest_trace.py drops the tag line, and the DMA fill then
comes after the doorbell write that reads it.

    [DMA] x86_64: GLib: g_timer_elapsed: ... failed    -->  [DMA] [R +0.0] write ...
    [R +0.0] write 0x57f9000 0x40 0x05...

Usage: fix-qtest-trace.py IN OUT
Exit 1 when a tag has no request after it. Prints the counts.
"""

import re
import sys

GLIB = re.compile(r"\S*: GLib: [^\n]*?assertion '[^']*' failed")
TAG = re.compile(r"^((?:\[DMA\] |\[DOUBLE-FETCH\] )+)\s*$")
REQ = re.compile(r"^\[R \+")


def main(src, dst):
    lines = [GLIB.sub("", x.rstrip("\n")) for x in open(src, errors="replace")]
    out = []
    tags = joined = lost = 0
    i = 0
    while i < len(lines):
        m = TAG.match(lines[i])
        if m:
            tags += 1
            if i + 1 < len(lines) and REQ.match(lines[i + 1]):
                out.append(m.group(1) + lines[i + 1])
                joined += 1
                i += 2
                continue
            lost += 1
        elif lines[i].startswith("[DMA] "):
            tags += 1
        out.append(lines[i])
        i += 1
    with open(dst, "w") as f:
        f.write("\n".join(out) + "\n")
    print("dma_tags=%d joined=%d lost=%d" % (tags, joined, lost))
    return 1 if lost else 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1], sys.argv[2]))
