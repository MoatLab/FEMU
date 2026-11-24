#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Turn a FEMU io_trace file into an fio I/O log and a shape report.

A device with io_trace=FILE writes one CSV line per completed I/O command:

  t_submit_ns,t_cqe_ns,sqid,cid,nsid,opcode,slba,nlb,status

This tool checks each line, selects one namespace and then:

  - prints a shape report: command mix, request sizes, queues, depth
    between fetch and CQE, gaps between fetches, bursts and the
    sequential share;
  - with --iolog OUT, writes an fio version 3 I/O log, which
    "fio --read_iolog=OUT" replays with the time of the capture.

Read, Write and Flush commands with status 0 go to the I/O log as read,
write and sync. A Zone Append with status 0 goes as a write at the LBA
where it landed, and the report counts it as a write. The trace holds
no range for Dataset Management, so the tool cannot replay a trim. It
counts each command that it does not replay and prints the counts;
--strict turns a non-zero count into a failure.
That covers each opcode the tool does not know: FEMU writes the commands
of every mode, and a failed command can hold any opcode.

The opcode names are those of the NVM and zoned command sets. The trace
does not hold the command set, so a Read or Write opcode with no range
(a key-value namespace, for example) counts as "other".

A wrong line stops the tool with the line number: a wrong field count, a
field that is not a number or is too wide for its NVMe field, a range on
a command that has none, a CQE time below the fetch time, or a range
past --device-size or past what fio can hold.

Two commands with one fetch time keep the file order, which is the
completion order. The report counts these ties.

Usage:
  femu-trace2fio.py --block-size BYTES [options] TRACE   # "-" is stdin
  femu-trace2fio.py --self-test

Exit status: 0 for success, 1 for a trace that fails a check, 2 for a
usage error.
"""

import argparse
import re
import sys
from collections import namedtuple
from fractions import Fraction

HEADER = "t_submit_ns,t_cqe_ns,sqid,cid,nsid,opcode,slba,nlb,status"

OP_FLUSH = 0x00
OP_WRITE = 0x01
OP_READ = 0x02
OP_DSM = 0x09
OP_APPEND = 0x7d

# FEMU writes a range only for these opcodes (femu-iotrace.c)
RANGED = (0x01, 0x02, 0x05, 0x08, 0x0c, 0x7d)
U64 = (1 << 64) - 1
U32 = (1 << 32) - 1

# the I/O opcodes of the NVM and zoned command sets; another opcode (a
# key-value or Open-Channel command, or a refused one) is named by number
OPCODES = {
    0x00: "flush",
    0x01: "write",
    0x02: "read",
    0x04: "write-uncorrectable",
    0x05: "compare",
    0x08: "write-zeroes",
    0x09: "dsm",
    0x0c: "verify",
    0x0d: "resv-register",
    0x0e: "resv-report",
    0x11: "resv-acquire",
    0x12: "io-mgmt-recv",
    0x15: "resv-release",
    0x18: "cancel",
    0x19: "copy",
    0x1d: "io-mgmt-send",
    0x79: "zone-mgmt-send",
    0x7a: "zone-mgmt-recv",
    0x7d: "zone-append",
}

DEC = re.compile(r"[0-9]{1,20}\Z")
HEX = re.compile(r"0x[0-9a-f]{1,4}\Z")
SIZE = re.compile(r"([0-9]+)([kmgt]?)\Z")

Row = namedtuple("Row", "t_submit t_cqe sqid cid nsid opcode slba nlb "
                        "status line")


class TraceError(Exception):
    """A trace that fails a check; line 0 means the whole file."""

    def __init__(self, line, text):
        super().__init__(text)
        self.line = line
        self.text = text

    def __str__(self):
        if self.line:
            return "line %d: %s" % (self.line, self.text)
        return self.text


def dec(field, name, line, top):
    if not DEC.match(field):
        raise TraceError(line, "%s '%s' is not a decimal number"
                         % (name, field[:32]))
    value = int(field)
    if value > top:
        raise TraceError(line, "%s %d is above %d" % (name, value, top))
    return value


def hexa(field, name, line, top):
    if not HEX.match(field):
        raise TraceError(line, "%s '%s' is not a 0x hex number"
                         % (name, field[:32]))
    value = int(field, 16)
    if value > top:
        raise TraceError(line, "%s 0x%x is above 0x%x" % (name, value, top))
    return value


def opname(opcode):
    return OPCODES.get(opcode, "opcode-0x%02x" % opcode)


def parse_trace(lines):
    """Check each line of an io_trace file and return the rows."""
    rows = []
    seen_header = False
    for line, text in enumerate(lines, 1):
        if not text.endswith("\n"):
            raise TraceError(line, "the line has no newline: the trace is "
                             "cut short; remove this line")
        text = text[:-1]
        if not seen_header:
            if text != HEADER:
                raise TraceError(line, "the first line is not the io_trace "
                                 "header '%s'" % HEADER)
            seen_header = True
            continue
        f = text.split(",")
        if len(f) != 9:
            raise TraceError(line, "%d fields, not 9" % len(f))
        t_submit = dec(f[0], "t_submit_ns", line, (1 << 63) - 1)
        t_cqe = dec(f[1], "t_cqe_ns", line, (1 << 63) - 1)
        sqid = dec(f[2], "sqid", line, 0xffff)
        cid = dec(f[3], "cid", line, 0xffff)
        nsid = dec(f[4], "nsid", line, U32)
        opcode = hexa(f[5], "opcode", line, 0xff)
        status = hexa(f[8], "status", line, 0xffff)
        if t_cqe < t_submit:
            raise TraceError(line, "the time goes backward: t_cqe_ns %d is "
                             "below t_submit_ns %d" % (t_cqe, t_submit))
        if f[6] == "" and f[7] == "":
            slba = nlb = None
        elif f[6] == "" or f[7] == "":
            raise TraceError(line, "half a range: slba '%s', nlb '%s'"
                             % (f[6], f[7]))
        else:
            if opcode not in RANGED:
                raise TraceError(line, "a range on opcode 0x%02x, which "
                                 "has none in an io_trace" % opcode)
            slba = dec(f[6], "slba", line, U64)
            nlb = dec(f[7], "nlb", line, 65536)
            if nlb < 1:
                raise TraceError(line, "nlb %d is not in 1 to 65536" % nlb)
        rows.append(Row(t_submit, t_cqe, sqid, cid, nsid, opcode, slba, nlb,
                        status, line))
    if not seen_header:
        raise TraceError(0, "the trace is empty")
    return rows


def select_namespace(rows, nsid):
    """Return the NSID to use and its rows, in the order of the fetch."""
    if not rows:
        raise TraceError(0, "the trace holds no command")
    if nsid is None:
        nsid = rows[0].nsid
        for r in rows:
            if r.nsid != nsid:
                raise TraceError(r.line, "NSID %d after NSID %d: select one "
                                 "namespace with --nsid" % (r.nsid, nsid))
    rows = [r for r in rows if r.nsid == nsid]
    if not rows:
        raise TraceError(0, "the trace holds no command for NSID %d" % nsid)
    # sorted() is stable, so equal fetch times keep the file order
    return nsid, sorted(rows, key=lambda r: r.t_submit)


def replay_action(r):
    """The fio action of a row, or None and the reason for the skip."""
    if r.status != 0:
        return None, "failed"
    if r.opcode == OP_FLUSH:
        return "sync", None
    if r.opcode in (OP_READ, OP_WRITE, OP_APPEND):
        if r.slba is None:
            return None, OPCODES[r.opcode] + "-no-range"
        if r.opcode == OP_APPEND:
            return "write", None
        return OPCODES[r.opcode], None
    return None, opname(r.opcode)


def convert(rows, block_size, filename, device_size=None,
            time_scale=Fraction(1), lba_scale=Fraction(1)):
    """Return the I/O log lines, the replay counts and the skip counts.

    @rows is one namespace in fetch order. A time scale of 2 halves each
    time stamp. An LBA scale multiplies each first LBA and rounds down.
    """
    t0 = rows[0].t_submit
    out = ["fio version 3 iolog", "0 %s add" % filename,
           "0 %s open" % filename]
    done = {"read": 0, "write": 0, "sync": 0, "append": 0}
    skipped = {}
    usec = 0
    for r in rows:
        action, why = replay_action(r)
        if action is None:
            skipped[why] = skipped.get(why, 0) + 1
            continue
        usec = int((r.t_submit - t0) / (1000 * time_scale))
        if usec > U64:
            raise TraceError(r.line, "time stamp %d us is above what fio "
                             "can hold" % usec)
        if action == "sync":
            offset = length = 0
        else:
            offset = int(r.slba * lba_scale) * block_size
            length = r.nlb * block_size
            if device_size is not None and offset + length > device_size:
                raise TraceError(r.line, "%s of %d bytes at byte %d ends "
                                 "past the device size %d"
                                 % (action, length, offset, device_size))
            # fio reads a 64-bit offset and a 32-bit length
            if offset + length > U64 or length > U32:
                raise TraceError(r.line, "%s of %d bytes at byte %d is "
                                 "above what fio can hold"
                                 % (action, length, offset))
        out.append("%d %s %s %d %d" % (usec, filename, action, offset,
                                       length))
        done[action] += 1
        if r.opcode == OP_APPEND:
            done["append"] += 1
    out.append("%d %s close" % (usec, filename))
    return out, done, skipped


def parse_iolog(lines):
    """Read a version 3 I/O log back: (usec, action, offset, length)."""
    if not lines or lines[0] != "fio version 3 iolog":
        raise ValueError("no version 3 header")
    ios = []
    state = "new"
    name = None
    for text in lines[1:]:
        f = text.split(" ")
        if len(f) == 3:
            step = {("new", "add"): "added", ("added", "open"): "open",
                    ("open", "close"): "closed"}.get((state, f[2]))
            if step is None or (name is not None and f[1] != name):
                raise ValueError("file action out of order: " + text)
            state, name = step, f[1]
        elif len(f) == 5 and state == "open" and f[1] == name:
            ios.append((int(f[0]), f[2], int(f[3]), int(f[4])))
        else:
            raise ValueError("wrong line: " + text)
    if state != "closed":
        raise ValueError("the file is not closed")
    return ios


def ratio(num, den, places):
    """num / den with a fixed number of decimal places, half rounded up."""
    scale = 10 ** places
    q = (2 * num * scale + den) // (2 * den) if den else 0
    return "%d.%0*d" % (q // scale, places, q % scale)


def percent(num, den):
    return ratio(100 * num, den, 1) + "%"


def depth_profile(rows, nbuckets):
    """Commands between fetch and CQE: the maximum, the summed time of all
    commands, the time span, and per time slice (start, maximum, summed
    time, width)."""
    # at one time, a fetch goes before a CQE: a command of 0 ns still
    # counts, and two commands that meet at one time overlap
    events = sorted([(r.t_submit, -1) for r in rows] +
                    [(r.t_cqe, 1) for r in rows])
    events = [(t, -order) for t, order in events]
    t0 = events[0][0]
    span = events[-1][0] - t0
    n = max(1, min(nbuckets, span))

    def edge(b):
        return t0 + -(-span * b // n)

    area = [0] * n
    peak = [0] * n
    depth = top = 0
    prev = t0
    for t, step in events:
        if t > prev:
            b = (prev - t0) * n // span
            while b < n and edge(b) < t:
                lap = min(t, edge(b + 1)) - max(prev, edge(b))
                if lap > 0:
                    area[b] += depth * lap
                    peak[b] = max(peak[b], depth)
                b += 1
            prev = t
        depth += step
        if step > 0:
            top = max(top, depth)
            b = min(n - 1, (t - t0) * n // span) if span else 0
            peak[b] = max(peak[b], depth)
    slices = [(edge(b) - t0, peak[b], area[b], edge(b + 1) - edge(b))
              for b in range(n)]
    return top, sum(area), span, slices


def size_bucket(nbytes):
    b = 1
    while b < nbytes:
        b *= 2
    return b


def burst_sizes(times, burst_gap):
    """The sizes of the runs in sorted @times with no gap above the limit."""
    sizes = [1]
    for a, b in zip(times, times[1:]):
        if b - a > burst_gap:
            sizes.append(1)
        else:
            sizes[-1] += 1
    return sizes


def report(rows, nsid, block_size, nbuckets, burst_gap):
    """The shape report of one namespace, as a list of lines."""
    out = ["trace: %d commands, namespace %d, block size %d"
           % (len(rows), nsid, block_size)]

    kinds = {OP_READ: "read", OP_WRITE: "write", OP_FLUSH: "flush",
             OP_DSM: "trim"}
    mix = {"read": 0, "write": 0, "flush": 0, "trim": 0, "other": 0}
    nbytes = {OP_READ: 0, OP_WRITE: 0}
    sizes = {}
    queues = {}
    last_end = {}
    ranged = {OP_READ: 0, OP_WRITE: 0}
    seq = {OP_READ: 0, OP_WRITE: 0}
    failed = 0
    appends = 0
    for r in rows:
        # a Zone Append writes, at the LBA where it landed
        op = OP_WRITE if r.opcode == OP_APPEND else r.opcode
        kind = kinds.get(op, "other")
        if op in nbytes and r.slba is None:
            # not a Read or Write of the NVM or zoned command set
            kind = "other"
        mix[kind] += 1
        queues.setdefault(r.sqid, []).append(r.t_submit)
        if r.status != 0:
            failed += 1
            continue
        if op not in nbytes or r.slba is None:
            continue
        if r.opcode == OP_APPEND:
            appends += 1
        length = r.nlb * block_size
        nbytes[op] += length
        pair = sizes.setdefault(size_bucket(length), {OP_READ: 0,
                                                      OP_WRITE: 0})
        pair[op] += 1
        ranged[op] += 1
        stream = (r.sqid, op)
        if last_end.get(stream) == r.slba:
            seq[op] += 1
        last_end[stream] = r.slba + r.nlb

    out.append("mix (kind, commands, share):")
    for kind in ("read", "write", "flush", "trim", "other"):
        out.append("  %-5s %d %s" % (kind, mix[kind],
                                     percent(mix[kind], len(rows))))
    out.append("  failed %d" % failed)
    if appends:
        out.append("  zone appends in write %d" % appends)
    out.append("  bytes read %d written %d" % (nbytes[OP_READ],
                                               nbytes[OP_WRITE]))

    out.append("sizes (bytes up to, reads, writes):")
    for size in sorted(sizes):
        out.append("  %d %d %d" % (size, sizes[size][OP_READ],
                                   sizes[size][OP_WRITE]))

    out.append("queues (sqid, commands, share, bursts, largest burst):")
    for sqid in sorted(queues):
        sizes_q = burst_sizes(queues[sqid], burst_gap)
        out.append("  %d %d %s %d %d"
                   % (sqid, len(queues[sqid]),
                      percent(len(queues[sqid]), len(rows)), len(sizes_q),
                      max(sizes_q)))

    top, area, span, slices = depth_profile(rows, nbuckets)
    out.append("depth (fetch to CQE): max %d mean %s over %d ns"
               % (top, ratio(area, span, 2), span))
    out.append("  slices (start_ns, max, mean):")
    for start, peak, part, width in slices:
        out.append("  %d %d %s" % (start, peak, ratio(part, width, 2)))

    gaps = sorted(b.t_submit - a.t_submit for a, b in zip(rows, rows[1:]))
    if gaps:
        def rank(p):
            return gaps[-(-p * len(gaps) // 100) - 1]
        out.append("arrival (gap between fetches, ns): min %d mean %d "
                   "p50 %d p99 %d max %d ties %d"
                   % (gaps[0], sum(gaps) // len(gaps), rank(50), rank(99),
                      gaps[-1], gaps.count(0)))
    else:
        out.append("arrival (gap between fetches, ns): one command, no gap")

    bursts = burst_sizes([r.t_submit for r in rows], burst_gap)
    out.append("bursts (all queues, gap up to %d ns): count %d mean %s "
               "max %d"
               % (burst_gap, len(bursts), ratio(len(rows), len(bursts), 2),
                  max(bursts)))

    out.append("sequential (same queue, same kind): read %d of %d %s, "
               "write %d of %d %s"
               % (seq[OP_READ], ranged[OP_READ],
                  percent(seq[OP_READ], ranged[OP_READ]),
                  seq[OP_WRITE], ranged[OP_WRITE],
                  percent(seq[OP_WRITE], ranged[OP_WRITE])))
    return out


def replay_summary(done, skipped):
    out = ["replay: %d commands (read %d, write %d, sync %d)"
           % (done["read"] + done["write"] + done["sync"], done["read"],
              done["write"], done["sync"])]
    if done.get("append"):
        out.append("  zone appends replayed as write %d" % done["append"])
    if skipped:
        out.append("not replayed: " + ", ".join(
            "%s %d" % (why, skipped[why]) for why in sorted(skipped)))
    else:
        out.append("not replayed: none")
    return out


def size_arg(text):
    m = SIZE.match(text.lower())
    if not m:
        raise argparse.ArgumentTypeError("'%s' is not a size (a number, "
                                         "then k, m, g or t)" % text)
    return int(m.group(1)) << (10 * " kmgt".index(m.group(2) or " "))


def scale_arg(text):
    try:
        value = Fraction(text)
    except (ValueError, ZeroDivisionError):
        value = Fraction(0)
    if value <= 0:
        raise argparse.ArgumentTypeError("'%s' is not a number above 0"
                                         % text)
    return value


def run(lines, opts):
    """Check, report and convert; return the report and the I/O log."""
    rows = parse_trace(lines)
    nsid, rows = select_namespace(rows, opts.nsid)
    iolog, done, skipped = convert(rows, opts.block_size,
                                   opts.filename or "-",
                                   opts.device_size, opts.time_scale,
                                   opts.lba_scale)
    text = report(rows, nsid, opts.block_size, opts.buckets, opts.burst_gap)
    text += replay_summary(done, skipped)
    if opts.strict and skipped:
        raise TraceError(0, "--strict: %d commands are not replayed"
                         % sum(skipped.values()))
    if opts.iolog and not done["read"] + done["write"]:
        # fio refuses an I/O log with no read and no write
        raise TraceError(0, "--iolog: the trace holds no read or write "
                         "to replay")
    return text, iolog


def parser():
    p = argparse.ArgumentParser(
        description="Turn a FEMU io_trace file into an fio I/O log and a "
                    "shape report.")
    p.add_argument("trace", metavar="TRACE",
                   help="the io_trace CSV file; - is stdin")
    p.add_argument("--block-size", type=size_arg, required=True,
                   metavar="BYTES",
                   help="LBA size of the namespace (the trace does not "
                        "hold it), for example 512 or 4k")
    p.add_argument("--nsid", type=int,
                   help="the namespace to use; necessary when the trace "
                        "holds more than one")
    p.add_argument("--device-size", type=size_arg, metavar="BYTES",
                   help="size of the replay target; a range past it is an "
                        "error")
    p.add_argument("--iolog", metavar="OUT",
                   help="write the fio version 3 I/O log to OUT, which "
                        "must not exist")
    p.add_argument("--filename", metavar="PATH",
                   help="device name in the I/O log, for example "
                        "/dev/nvme0n1; necessary with --iolog")
    p.add_argument("--time-scale", type=scale_arg, default=Fraction(1),
                   metavar="F",
                   help="divide each time stamp by F; 2 is twice the "
                        "speed (default 1)")
    p.add_argument("--lba-scale", type=scale_arg, default=Fraction(1),
                   metavar="F",
                   help="multiply each first LBA by F and round down, to "
                        "fit a device of another size (default 1)")
    p.add_argument("--strict", action="store_true",
                   help="fail when a command is not replayed")
    p.add_argument("--buckets", type=int, default=10, metavar="N",
                   help="time slices of the depth profile (default 10)")
    p.add_argument("--burst-gap", type=int, default=1000000, metavar="NS",
                   help="a gap above NS between two fetches starts a new "
                        "burst (default 1000000)")
    return p


def main(argv):
    if argv == ["--self-test"]:
        return self_test()
    p = parser()
    opts = p.parse_args(argv)
    if opts.block_size < 1 or opts.block_size & (opts.block_size - 1):
        p.error("--block-size must be a power of two")
    if opts.device_size is not None and opts.device_size % opts.block_size:
        p.error("--device-size must be a multiple of --block-size")
    if opts.buckets < 1 or opts.burst_gap < 0:
        p.error("--buckets must be above 0 and --burst-gap must not be "
                "negative")
    if opts.nsid is not None and opts.nsid < 1:
        p.error("--nsid must be above 0")
    if opts.filename is not None and (not opts.filename or
                                      re.search(r"\s", opts.filename)):
        p.error("--filename must not be empty or hold white space")
    if opts.iolog and not opts.filename:
        p.error("--iolog needs --filename: the name of the namespace "
                "device in the guest")
    try:
        if opts.trace == "-":
            text, iolog = run(sys.stdin, opts)
        else:
            with open(opts.trace, newline="\n") as src:
                text, iolog = run(src, opts)
        if opts.iolog:
            # like FEMU with io_trace, never write over a file
            with open(opts.iolog, "x") as dst:
                dst.write("\n".join(iolog) + "\n")
    except TraceError as e:
        print("femu-trace2fio: %s: %s" % (opts.trace, e), file=sys.stderr)
        return 1
    except OSError as e:
        print("femu-trace2fio: %s" % e, file=sys.stderr)
        return 2
    print("\n".join(text))
    return 0


# The built-in trace: 512-byte blocks on a 1 MiB device. The file order is
# the completion order, so line 3 holds a fetch that is older than line 2.
GOOD = [
    "1000000,1050000,1,1,1,0x02,0,8,0x0",
    "1002000,1060000,2,1,1,0x02,100,1,0x0",
    "1001000,1070000,1,2,1,0x02,8,8,0x0",
    "1100000,1300000,1,3,1,0x01,64,16,0x0",
    "1101000,1310000,1,4,1,0x01,80,16,0x0",
    "1320000,1330000,1,5,1,0x00,,,0x0",
    "5000000,5010000,2,2,1,0x09,,,0x0",
    "5001000,5002000,2,3,1,0x02,4000,8,0x4080",
    "5003000,5053000,2,4,1,0x02,2040,8,0x0",
]

GOOD_IOLOG = """\
fio version 3 iolog
0 /dev/nvme0n1 add
0 /dev/nvme0n1 open
0 /dev/nvme0n1 read 0 4096
1 /dev/nvme0n1 read 4096 4096
2 /dev/nvme0n1 read 51200 512
100 /dev/nvme0n1 write 32768 8192
101 /dev/nvme0n1 write 40960 8192
320 /dev/nvme0n1 sync 0 0
4003 /dev/nvme0n1 read 1044480 4096
4003 /dev/nvme0n1 close
"""

GOOD_REPORT = """\
trace: 9 commands, namespace 1, block size 512
mix (kind, commands, share):
  read  5 55.6%
  write 2 22.2%
  flush 1 11.1%
  trim  1 11.1%
  other 0 0.0%
  failed 1
  bytes read 12800 written 16384
sizes (bytes up to, reads, writes):
  512 1 0
  4096 3 0
  8192 0 2
queues (sqid, commands, share, bursts, largest burst):
  1 5 55.6% 1 5
  2 4 44.4% 2 3
depth (fetch to CQE): max 3 mean 0.16 over 4053000 ns
  slices (start_ns, max, mean):
  0 3 0.29
  2026500 2 0.03
arrival (gap between fetches, ns): min 1000 mean 500375 p50 1000 p99 \
3680000 max 3680000 ties 0
bursts (all queues, gap up to 1000000 ns): count 2 mean 4.50 max 6
sequential (same queue, same kind): read 1 of 4 25.0%, write 1 of 2 50.0%
replay: 7 commands (read 4, write 2, sync 1)
not replayed: dsm 1, failed 1
"""


def trace_lines(body):
    return [HEADER + "\n"] + [text + "\n" for text in body]


def changed(index, text):
    """The built-in trace with one line replaced (index from 0)."""
    body = list(GOOD)
    body[index] = text
    return trace_lines(body)


def self_test():
    ns = argparse.Namespace
    base = dict(nsid=None, filename="/dev/nvme0n1", iolog=None,
                block_size=512,
                device_size=1 << 20, time_scale=Fraction(1),
                lba_scale=Fraction(1), strict=False, buckets=2,
                burst_gap=1000000)

    # 1. the exact I/O log and report of the built-in trace
    text, iolog = run(trace_lines(GOOD), ns(**base))
    got = "\n".join(iolog) + "\n"
    assert got == GOOD_IOLOG, got
    got = "\n".join(text) + "\n"
    assert got == GOOD_REPORT, got

    # 2. round trip: the I/O log, read back, holds each successful Read,
    # Write and Flush of the trace, found here without the converter
    back = sorted(io[1:] for io in parse_iolog(iolog))
    want = []
    for text in GOOD:
        f = text.split(",")
        if f[8] != "0x0" or f[5] not in ("0x00", "0x01", "0x02"):
            continue
        if f[5] == "0x00":
            want.append(("sync", 0, 0))
        else:
            want.append(("read" if f[5] == "0x02" else "write",
                         int(f[6]) * 512, int(f[7]) * 512))
    assert back == sorted(want) and len(back) == 7, back
    # the order is the fetch order: line 3 of the body goes before line 2
    assert [io[2] for io in parse_iolog(iolog)][:3] == [0, 4096, 51200]
    stamps = [io[0] for io in parse_iolog(iolog)]
    assert stamps == sorted(stamps), stamps

    # 3. the options change the output
    _, fast = run(trace_lines(GOOD), ns(**dict(base,
                                               time_scale=Fraction(2))))
    assert [io[0] for io in parse_iolog(fast)] == [s // 2 for s in stamps]
    _, small = run(trace_lines(GOOD), ns(**dict(base,
                                                lba_scale=Fraction(1, 2))))
    assert [io[2] for io in parse_iolog(small)] == \
        [0, 2048, 25600, 16384, 20480, 0, 522240], small
    _, named = run(trace_lines(GOOD), ns(**dict(base, filename="/dev/x")))
    assert named[1] == "0 /dev/x add", named

    # 4. planted faults: one changed line each, and the line number that
    # the error must name (the header is line 1)
    faults = [
        ("a short line", changed(1, "1002000,1060000,2,1,1,0x02,100,1"),
         3, "8 fields"),
        ("a long line", changed(1, GOOD[1] + ",0"), 3, "10 fields"),
        ("a time that is not a number",
         changed(3, "x100000,1300000,1,3,1,0x01,64,16,0x0"), 5,
         "not a decimal"),
        ("an opcode with no 0x",
         changed(3, "1100000,1300000,1,3,1,01,64,16,0x0"), 5, "not a 0x"),
        ("an opcode wider than one byte",
         changed(6, "5000000,5010000,2,2,1,0x1ee,,,0x0"), 8, "above 0xff"),
        ("a range on a command that has none",
         changed(6, "5000000,5010000,2,2,1,0x09,0,8,0x0"), 8,
         "a range on opcode 0x09"),
        ("a queue ID wider than 16 bits",
         changed(0, "1000000,1050000,65536,1,1,0x02,0,8,0x0"), 2,
         "sqid 65536 is above"),
        ("a number with too many digits",
         changed(0, "1" * 21 + ",1050000,1,1,1,0x02,0,8,0x0"), 2,
         "not a decimal"),
        ("a range past the device",
         changed(8, "5003000,5053000,2,4,1,0x02,2041,8,0x0"), 10,
         "past the device"),
        ("a time that goes backward",
         changed(4, "1101000,1100999,1,4,1,0x01,80,16,0x0"), 6,
         "goes backward"),
        ("half a range",
         changed(0, "1000000,1050000,1,1,1,0x02,0,,0x0"), 2, "half a range"),
        ("a zero block count",
         changed(0, "1000000,1050000,1,1,1,0x02,0,0,0x0"), 2, "nlb 0"),
        ("a second namespace",
         changed(2, "1001000,1070000,1,2,2,0x02,8,8,0x0"), 4, "--nsid"),
        ("a missing header", [text + "\n" for text in GOOD], 1,
         "not the io_trace header"),
        ("a last line cut short",
         trace_lines(GOOD)[:-1] + ["5003000,5053000,2,4"], 10, "cut short"),
        ("an empty file", [], 0, "empty"),
        ("a header with no command", trace_lines([]), 0, "no command"),
    ]
    for name, lines, line, key in faults:
        try:
            run(lines, ns(**base))
        except TraceError as e:
            assert e.line == line and key in e.text, (name, str(e))
        else:
            raise AssertionError("not caught: " + name)

    # 5. controls: the range fault passes with no device size, the second
    # namespace passes with --nsid, and --strict fails the good trace
    by_name = {name: lines for name, lines, _, _ in faults}
    run(by_name["a range past the device"],
        ns(**dict(base, device_size=None)))
    text, _ = run(by_name["a second namespace"], ns(**dict(base, nsid=1)))
    assert text[0].startswith("trace: 8 commands, namespace 1"), text[0]

    # 6. an opcode the tool does not know (FEMU writes those of every
    # mode) is never dropped in silence: the report names it, and
    # --strict fails with its line count
    odd = changed(6, "5000000,5010000,2,2,1,0xee,,,0x0")
    text, _ = run(odd, ns(**base))
    assert text[-1] == "not replayed: failed 1, opcode-0xee 1", text[-1]
    assert "  other 1 11.1%" in text and "  trim  0 0.0%" in text, text
    try:
        run(odd, ns(**dict(base, strict=True)))
    except TraceError as e:
        assert "2 commands are not replayed" in e.text, str(e)
    else:
        raise AssertionError("not caught: an unknown opcode with --strict")
    # a Read opcode with no range is not a read of the NVM command set
    text, _ = run(changed(0, "1000000,1050000,1,1,1,0x02,,,0x0"),
                  ns(**base))
    assert "  read  4 44.4%" in text and "  other 1 11.1%" in text, text
    assert text[-1] == "not replayed: dsm 1, failed 1, read-no-range 1"

    # 7. an offset that fio cannot hold, and a trace with nothing for fio
    try:
        run(changed(8, "5003000,5053000,2,4,1,0x02,%d,8,0x0" % U64),
            ns(**dict(base, device_size=None)))
    except TraceError as e:
        assert e.line == 10 and "above what fio can hold" in e.text, str(e)
    else:
        raise AssertionError("not caught: an offset above 64 bits")
    only_flush = trace_lines([GOOD[5]])
    run(only_flush, ns(**base))
    try:
        run(only_flush, ns(**dict(base, iolog="x")))
    except TraceError as e:
        assert "no read or write" in e.text, str(e)
    else:
        raise AssertionError("not caught: an I/O log with no read or write")

    # 8. two fetches at one time: the report counts the tie, and one
    # command has a depth of 0 over a span of 0
    text, _ = run(trace_lines(["7,9,1,1,1,0x02,0,1,0x0",
                               "7,9,1,2,1,0x02,1,1,0x0"]), ns(**base))
    assert text[-5].endswith("ties 1"), text[-5]
    text, _ = run(trace_lines(["7,7,1,1,1,0x02,0,1,0x0"]), ns(**base))
    assert "depth (fetch to CQE): max 1 mean 0.00 over 0 ns" in text, text
    try:
        run(trace_lines(GOOD), ns(**dict(base, strict=True)))
    except TraceError as e:
        assert "2 commands are not replayed" in e.text, str(e)
    else:
        raise AssertionError("not caught: --strict")

    # 9. Zone Append: a landed range replays as a write and counts in the
    # write bytes, sizes and sequential share; a failed append and an
    # append with no range (an old trace) are not replayed
    zap = trace_lines(["10,20,1,1,1,0x7d,%d,8,0x0" % (1 << 33),
                       "30,40,1,2,1,0x7d,%d,8,0x0" % ((1 << 33) + 8),
                       "50,60,1,3,1,0x7d,4096,8,0x4280",
                       "70,80,1,4,1,0x7d,,,0x7"])
    big = dict(base, device_size=None)
    text, iolog = run(zap, ns(**dict(big, iolog="x")))
    assert [io[1:] for io in parse_iolog(iolog)] == \
        [("write", (1 << 33) * 512, 4096),
         ("write", ((1 << 33) + 8) * 512, 4096)], iolog
    assert "  write 3 75.0%" in text and "  other 1 25.0%" in text, text
    assert "  bytes read 0 written 8192" in text, text
    assert "  zone appends in write 2" in text, text
    assert "  4096 0 2" in text, text
    assert text[-4].endswith("write 1 of 2 50.0%"), text[-4]
    assert text[-3] == "replay: 2 commands (read 0, write 2, sync 0)", text
    assert text[-2] == "  zone appends replayed as write 2", text[-2]
    assert text[-1] == ("not replayed: failed 2"), text[-1]
    old = trace_lines(["10,20,1,1,1,0x7d,,,0x0"])
    text, _ = run(old, ns(**base))
    assert text[-1] == "not replayed: zone-append-no-range 1", text[-1]
    try:
        run(old, ns(**dict(base, strict=True)))
    except TraceError as e:
        assert "1 commands are not replayed" in e.text, str(e)
    else:
        raise AssertionError("not caught: an append with no range, --strict")
    # a Write and an append share one sequential stream per queue; a
    # contiguous command on another queue is not sequential
    mixed = trace_lines(["10,20,1,1,1,0x01,0,8,0x0",
                         "30,40,1,2,1,0x7d,8,8,0x0",
                         "50,60,2,1,1,0x7d,16,8,0x0",
                         "70,80,1,3,1,0x01,16,8,0x0"])
    text, _ = run(mixed, ns(**dict(base, strict=True)))
    assert text[-4].endswith("write 2 of 4 50.0%"), text[-4]
    assert text[-1] == "not replayed: none", text[-1]
    # a range on a Zone Management command is still refused
    try:
        run(trace_lines(["10,20,1,1,1,0x79,0,8,0x0"]), ns(**base))
    except TraceError as e:
        assert "a range on opcode 0x79" in e.text, str(e)
    else:
        raise AssertionError("not caught: a range on opcode 0x79")

    print("femu-trace2fio: self-test passed (%d planted faults caught)"
          % len(faults))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
