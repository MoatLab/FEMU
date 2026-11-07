#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Turn the femu_cqe trace of a FEMU run into a CSV I/O trace.

QEMU's log trace backend writes one line per completion when the
femu_cqe event is on:

  qemu ... -trace femu_cqe -D femu.log          (the log backend)
  femu-trace2csv.py femu.log > io.csv

Each line becomes one CSV row: the ISO 8601 time when QEMU printed one
(-msg timestamp=on), the completion queue, the command ID, the opcode, the
starting LBA, the number of blocks, the status and the modelled time in ns.
The LBA and block count mean something for reads and writes only; for other
commands they are what the request slot last held. Lines of other events
are skipped.

Usage:
  femu-trace2csv.py [LOG]      # stdin when LOG is absent
  femu-trace2csv.py --self-test
"""

import csv
import re
import sys

LINE = re.compile(
    r'^(?:(?P<time>\d{4}-\d\d-\d\dT\S+) )?femu_cqe cq (?P<cq>\d+) '
    r'cid (?P<cid>\d+) opc 0x(?P<opc>[0-9a-f]+) slba (?P<slba>\d+) '
    r'nlb (?P<nlb>\d+) status 0x(?P<status>[0-9a-f]+) '
    r'model (?P<model>-?\d+) ns')
FIELDS = ["time", "cq", "cid", "opcode", "slba", "blocks", "status",
          "model_ns"]


def convert(lines, out):
    w = csv.writer(out)
    w.writerow(FIELDS)
    rows = 0
    for line in lines:
        m = LINE.search(line)
        if not m:
            continue
        w.writerow([m.group("time") or "", m.group("cq"), m.group("cid"),
                    int(m.group("opc"), 16), m.group("slba"),
                    m.group("nlb"), int(m.group("status"), 16),
                    m.group("model")])
        rows += 1
    return rows


def self_test():
    import io
    log = ["2026-11-07T22:00:00.000100Z femu_cqe cq 1 cid 7 opc 0x2 "
           "slba 16 nlb 8 status 0x0 model 52000 ns",
           "femu_io_cmd cid 7 nsid 1 opc 0x2",
           "femu_cqe cq 2 cid 9 opc 0x1 slba 0 nlb 0 status 0x283 "
           "model 0 ns"]
    out = io.StringIO()
    assert convert(log, out) == 2
    got = out.getvalue().splitlines()
    assert got[0] == ",".join(FIELDS), got
    assert got[1] == "2026-11-07T22:00:00.000100Z,1,7,2,16,8,0,52000", got
    assert got[2] == ",2,9,1,0,0,643,0", got
    print("femu-trace2csv: self-test passed")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return 0
    if len(sys.argv) > 2:
        print(__doc__, file=sys.stderr)
        return 2
    src = open(sys.argv[1]) if len(sys.argv) == 2 else sys.stdin
    convert(src, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
