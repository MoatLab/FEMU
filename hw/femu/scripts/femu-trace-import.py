#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Turn a public block or cache trace into a FEMU io_trace file.

The output has the format that a device with io_trace=FILE writes:

  t_submit_ns,t_cqe_ns,sqid,cid,nsid,opcode,slba,nlb,status

so femu-trace2fio.py checks it, prints the shape report and writes the
fio I/O log, as for a trace of a live run.

Input formats (--format), with the column order of each:

  msr       MSR Cambridge, SNIA IOTTA:
            Timestamp,Hostname,DiskNumber,Type,Offset,Size,ResponseTime
            filetime (100 ns) times, bytes, Type Read or Write
  alibaba   Alibaba block traces 2020:
            device_id,opcode,offset,length,timestamp
            microseconds, bytes, opcode R or W
  tencent   Tencent CBS, SNIA IOTTA:
            Timestamp,Offset,Size,IOType,VolumeID
            512-byte sectors, IOType 0 read or 1 write; the time unit is
            not confirmed, so --time-unit is necessary
  cachelib  Meta CacheLib key-value cache traces: a header line names the
            columns; key, op, size and key_size are necessary, op_time,
            op_count and usecase are optional. A FIFO log over the device
            gives each object a place. op_time needs --time-unit; with no
            op_time, --rate gives a synthetic clock.

The steps run in this order:

  select one volume (the whole file) --> sort by time, file order for
  equal times --> repeat each line op_count times (cachelib) --> place
  the requests of one time over one time unit (--spread) --> keep the
  window (--duration, then --limit, in requests) --> whole blocks --> fold
  onto the device --> split into commands of at most 65536 blocks and
  4 GiB - 1 bytes

A bad line stops the tool with the line number, unless --max-bad allows
it. The output appears only after a successful run.

Usage:
  femu-trace-import.py --format FMT --block-size BYTES --device-size BYTES
                       [options] --out OUT TRACE     # "-" is stdin
  femu-trace-import.py --format FMT --list-volumes TRACE
  femu-trace-import.py --self-test

Exit status: 0 for success, 1 for a trace that fails a check, 2 for a
usage or file error.
"""

import argparse
import collections
import gzip
import importlib.machinery
import importlib.util
import io
import os
import re
import sys
import tempfile

HEADER = "t_submit_ns,t_cqe_ns,sqid,cid,nsid,opcode,slba,nlb,status"
MAX_NLB = 65536
U32 = (1 << 32) - 1
U64 = (1 << 64) - 1
T_MAX = (1 << 63) - 1

DEC = re.compile(r"[0-9]{1,20}\Z")
NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")
SIZE = re.compile(r"([0-9]+)([kmgt]?)\Z")

# nanoseconds per unit of a trace time
UNITS = {"s": 10 ** 9, "ms": 10 ** 6, "us": 1000, "ns": 1, "filetime": 100}

# column names, for an optional header line
COLUMNS = {
    "msr": "Timestamp,Hostname,DiskNumber,Type,Offset,Size,ResponseTime",
    "alibaba": "device_id,opcode,offset,length,timestamp",
    "tencent": "Timestamp,Offset,Size,IOType,VolumeID",
}
# a unit from a source that I could read; None means --time-unit is
# necessary
DEFAULT_UNIT = {"msr": "filetime", "alibaba": "us", "tencent": None,
                "cachelib": None}
KV_OPS = ("GET", "GET_LEASE", "SET", "DELETE")
KV_NEED = ("key", "op", "size", "key_size")

# one request of a block trace: the time in trace units, the line, the
# volume, "read" or "write", the byte range and the latency in ns or None
Req = collections.namedtuple("Req", "t line vol op offset size lat")
# one line of a key-value trace; key is (usecase, key)
KvReq = collections.namedtuple("KvReq", "t line op key key_size size "
                                        "op_count")


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


def dec(field, name, line):
    if not DEC.match(field):
        raise TraceError(line, "%s '%s' is not a decimal number"
                         % (name, field[:32]))
    value = int(field)
    if value > U64:
        raise TraceError(line, "%s %d is above 64 bits" % (name, value))
    return value


def nfields(f, count, line):
    if len(f) != count:
        raise TraceError(line, "%d fields, not %d" % (len(f), count))


def parse_msr(f, line):
    nfields(f, 7, line)
    t = dec(f[0], "Timestamp", line)
    if not NAME.match(f[1]):
        raise TraceError(line, "Hostname '%s' is not a host name" % f[1][:32])
    disk = dec(f[2], "DiskNumber", line)
    ops = {"Read": "read", "Write": "write"}
    if f[3] not in ops:
        raise TraceError(line, "Type '%s' is not Read or Write" % f[3][:32])
    offset = dec(f[4], "Offset", line)
    size = dec(f[5], "Size", line)
    lat = dec(f[6], "ResponseTime", line) * UNITS["filetime"]
    return Req(t, line, "%s:%d" % (f[1], disk), ops[f[3]], offset, size, lat)


def parse_alibaba(f, line):
    nfields(f, 5, line)
    vol = dec(f[0], "device_id", line)
    ops = {"R": "read", "W": "write"}
    if f[1] not in ops:
        raise TraceError(line, "opcode '%s' is not R or W" % f[1][:32])
    offset = dec(f[2], "offset", line)
    size = dec(f[3], "length", line)
    t = dec(f[4], "timestamp", line)
    return Req(t, line, str(vol), ops[f[1]], offset, size, None)


def parse_tencent(f, line):
    nfields(f, 5, line)
    t = dec(f[0], "Timestamp", line)
    offset = dec(f[1], "Offset", line)
    size = dec(f[2], "Size", line)
    ops = {"0": "read", "1": "write"}
    if f[3] not in ops:
        raise TraceError(line, "IOType '%s' is not 0 or 1" % f[3][:32])
    vol = dec(f[4], "VolumeID", line)
    # the sector of this trace is 512 bytes
    return Req(t, line, str(vol), ops[f[3]], offset * 512, size * 512, None)


BLOCK_PARSERS = {"msr": parse_msr, "alibaba": parse_alibaba,
                 "tencent": parse_tencent}


def kv_columns(text, line):
    """Map each column name of a CacheLib header to its index."""
    names = text.split(",")
    missing = [n for n in KV_NEED if n not in names]
    if missing:
        raise TraceError(line, "the first line is not a CacheLib header "
                         "with the columns %s (missing: %s); the tool "
                         "reads these traces by column name only"
                         % (", ".join(KV_NEED), ", ".join(missing)))
    cols = {}
    for i, name in enumerate(names):
        if name in cols:
            raise TraceError(line, "the header names '%s' twice" % name)
        cols[name] = i
    return cols, len(names)


def parse_kv(f, line, cols, count):
    nfields(f, count, line)
    key = f[cols["key"]]
    if not key:
        raise TraceError(line, "the key is empty")
    op = f[cols["op"]]
    if op not in KV_OPS:
        raise TraceError(line, "op '%s' is not one of %s"
                         % (op[:32], ", ".join(KV_OPS)))
    size = dec(f[cols["size"]], "size", line)
    key_size = dec(f[cols["key_size"]], "key_size", line)
    op_count = 1
    if "op_count" in cols:
        op_count = dec(f[cols["op_count"]], "op_count", line)
        if op_count < 1:
            raise TraceError(line, "op_count 0: a line is one request or "
                             "more")
    t = dec(f[cols["op_time"]], "op_time", line) if "op_time" in cols \
        else None
    # keys of two use cases (tenants) are two objects
    usecase = f[cols["usecase"]] if "usecase" in cols else ""
    return KvReq(t, line, op, (usecase, key), key_size, size, op_count)


class Bad:
    """The bad lines that --max-bad allows, and the first line numbers."""

    def __init__(self, limit):
        self.limit = limit
        self.count = 0
        self.first = []

    def add(self, err):
        self.count += 1
        if self.count > self.limit:
            if self.limit:
                raise TraceError(err.line, "%s (bad line %d, above "
                                 "--max-bad %d)" % (err.text, self.count,
                                                    self.limit))
            raise err
        if len(self.first) < 5:
            self.first.append(err.line)


def read_rows(lines, fmt, bad):
    """Parse each line; a header line is never a bad line."""
    rows = []
    cols = None
    for line, text in enumerate(lines, 1):
        if text.endswith("\n"):
            text = text[:-1]
        if text.endswith("\r"):
            text = text[:-1]
        if line == 1:
            if fmt == "cachelib":
                cols = kv_columns(text, line)
                continue
            if text.lower() == COLUMNS[fmt].lower():
                continue
        try:
            f = text.split(",")
            if fmt == "cachelib":
                rows.append(parse_kv(f, line, *cols))
            else:
                rows.append(BLOCK_PARSERS[fmt](f, line))
        except TraceError as e:
            bad.add(e)
    if fmt == "cachelib" and cols is None:
        raise TraceError(0, "the trace is empty")
    return rows


def norm_volume(text):
    """A volume name as the parsers give it: no leading zeros."""
    if text is None:
        return None
    if DEC.match(text):
        return str(int(text))
    m = re.fullmatch(r"(.*):([0-9]{1,20})", text)
    if m:
        return "%s:%d" % (m.group(1), int(m.group(2)))
    return text


def select_volume(rows, volume):
    """The rows of one volume; with no --volume the file must hold one."""
    if volume is None:
        first = rows[0].vol
        for r in rows:
            if r.vol != first:
                raise TraceError(r.line, "volume %s after volume %s: "
                                 "select one with --volume (see "
                                 "--list-volumes)" % (r.vol, first))
        volume = first
    out = [r for r in rows if r.vol == volume]
    if not out:
        raise TraceError(0, "the trace holds no request for volume %s"
                         % volume)
    return volume, out


def list_volumes(rows):
    vols = {}
    for r in rows:
        v = vols.setdefault(r.vol, [0, 0, 0, 0])
        v[0] += 1
        v[1 if r.op == "read" else 2] += 1
        if r.size:
            v[3] = max(v[3], r.offset + r.size)
    out = ["volumes (volume, requests, reads, writes, largest end byte):"]
    for vol in sorted(vols, key=lambda k: (len(k), k)):
        out.append("  %s %d %d %d %d" % ((vol,) + tuple(vols[vol])))
    return out


def timeline(rows, unit_ns, spread, duration, limit, repeat):
    """Yield (row, time in ns from the first row) in time order.

    @repeat gives the request count of a row. With @spread, the k-th of
    the n requests of one time t gets t + floor(k x unit / n). --duration
    keeps the half-open window [t_first, t_first + duration); --limit then
    keeps the first requests, before any request becomes commands.
    """
    rows = sorted(rows, key=lambda r: r.t)
    t_first = rows[0].t
    top = None if duration is None else \
        t_first + (duration * 10 ** 9 + unit_ns - 1) // unit_ns
    count = 0
    i = 0
    while i < len(rows):
        j = i
        while j < len(rows) and rows[j].t == rows[i].t:
            j += 1
        if top is not None and rows[i].t >= top:
            return
        n = sum(repeat(r) for r in rows[i:j])
        base = (rows[i].t - t_first) * unit_ns
        k = 0
        for r in rows[i:j]:
            for _ in range(repeat(r)):
                if limit is not None and count == limit:
                    return
                t = base + (k * unit_ns // n if spread else 0)
                if t > T_MAX:
                    raise TraceError(r.line, "a time of %d ns is above what "
                                     "an io_trace holds" % t)
                yield r, t
                count += 1
                k += 1
        i = j


def back_count(rows):
    """Rows with a time below the time of the row before, in file order."""
    return sum(1 for a, b in zip(rows, rows[1:]) if b.t < a.t)


def largest_tie(rows):
    times = collections.Counter(r.t for r in rows)
    return max(times.values())


class Folder:
    """Put a block range of the volume on the device: a list of pieces."""

    def __init__(self, mode, device_blocks, volume_blocks):
        self.mode = mode
        self.dev = device_blocks
        self.vol = volume_blocks
        self.moved = 0
        self.wrapped = 0

    def place(self, slba, nlb, line):
        if nlb > self.dev:
            raise TraceError(line, "a range of %d blocks is larger than the "
                             "device (%d blocks)" % (nlb, self.dev))
        if self.mode == "wrap":
            slba %= self.dev
            if slba + nlb > self.dev:
                # the range goes on at block 0, as a modulo map puts it
                self.wrapped += 1
                first = self.dev - slba
                return [(slba, first), (0, nlb - first)]
            return [(slba, nlb)]
        if self.mode == "scale" and self.vol > self.dev:
            slba = slba * self.dev // self.vol
        if slba + nlb > self.dev:
            if self.mode == "none":
                raise TraceError(line, "a range of %d blocks at block %d "
                                 "ends past the device (%d blocks); use "
                                 "--fold or a larger --device-size"
                                 % (nlb, slba, self.dev))
            slba = self.dev - nlb
            self.moved += 1
        return [(slba, nlb)]


class Writer:
    """io_trace lines; a long range becomes several commands."""

    def __init__(self, block_size):
        self.lines = [HEADER]
        self.cid = 0
        self.split = 0
        # femu-trace2fio.py and fio take at most U32 bytes per command
        self.cap = min(MAX_NLB, U32 // block_size)

    def add(self, t, lat, opcode, pieces, line):
        if t + lat > T_MAX:
            raise TraceError(line, "a completion time of %d ns is above "
                             "what an io_trace holds" % (t + lat))
        if len(pieces) > 1 or pieces[0][1] > self.cap:
            self.split += 1
        for slba, nlb in pieces:
            while nlb > 0:
                n = min(nlb, self.cap)
                self.lines.append("%d,%d,1,%d,1,0x%02x,%d,%d,0x0"
                                  % (t, t + lat, self.cid, opcode, slba, n))
                self.cid = (self.cid + 1) % 65536
                slba += n
                nlb -= n


OPCODE = {"read": 0x02, "write": 0x01}
NO_LATENCY = ("latency: none in the trace; t_cqe_ns = t_submit_ns, so the "
              "depth lines of femu-trace2fio.py are not a queue depth")


def convert_block(rows, opts, volume_blocks, volume_from):
    """io_trace lines and the summary for one volume of a block trace."""
    bs = opts.block_size
    unit_ns = UNITS[opts.time_unit]
    dev = opts.device_size // bs
    sized = [r for r in rows if r.size]
    if not sized:
        raise TraceError(0, "no request with a size above 0 to write")
    top = max(-(-(r.offset + r.size) // bs) for r in sized)
    if volume_blocks is None:
        # from the whole volume, before the window, so --limit and
        # --duration do not change the fold
        volume_blocks = top
        volume_from = "the largest end in the volume"
    elif top > volume_blocks:
        r = max(sized, key=lambda r: r.offset + r.size)
        raise TraceError(r.line, "the range ends at block %d, past the "
                         "volume size (%d blocks)" % (top, volume_blocks))
    folder = Folder(opts.fold, dev, volume_blocks)
    w = Writer(bs)
    count = {"read": 0, "write": 0}
    nbytes = {"read": 0, "write": 0}
    used = []
    empty = unaligned = 0
    for r, t in timeline(rows, unit_ns, opts.spread, opts.duration,
                         opts.limit, lambda r: 1):
        used.append(r)
        if r.size == 0:
            empty += 1
            continue
        end = r.offset + r.size
        if end > U64:
            raise TraceError(r.line, "the range ends above 64 bits")
        slba = r.offset // bs
        if r.offset % bs or end % bs:
            unaligned += 1
        pieces = folder.place(slba, -(-end // bs) - slba, r.line)
        w.add(t, r.lat or 0, OPCODE[r.op], pieces, r.line)
        count[r.op] += 1
        nbytes[r.op] += r.size
    if len(w.lines) == 1:
        raise TraceError(0, "no request with a size above 0 in the window")
    out = ["requests: %d of the volume, %d in the window; read %d write "
           "%d, bytes read %d written %d"
           % (len(rows), len(used), count["read"], count["write"],
              nbytes["read"], nbytes["write"]),
           "commands: %d (requests split: %d)" % (len(w.lines) - 1, w.split),
           "changed: size 0 dropped %d, unaligned grown to whole blocks %d"
           % (empty, unaligned)]
    if opts.fold == "none":
        out.append("fold: none")
    else:
        out.append("fold: %s, volume %d blocks (%s), device %d blocks, "
                   "wrapped at the device end %d, moved to end at the "
                   "device end %d"
                   % (opts.fold, volume_blocks, volume_from, dev,
                      folder.wrapped, folder.moved))
    out.append(time_summary(rows, opts, "trace"))
    if rows[0].lat is None:
        out.append(NO_LATENCY)
    else:
        out.append("latency: ResponseTime of the trace, the time on the "
                   "original disk; each piece of a split request has it")
    return w.lines, out


def time_summary(rows, opts, clock):
    return ("time: clock %s, unit %s, out of order %d, largest count at one "
            "time %d, spread %s"
            % (clock, opts.time_unit, back_count(rows), largest_tie(rows),
               "on" if opts.spread else "off"))


class FifoLog:
    """A FIFO log of whole objects over the device.

    Each object has an absolute place in the log, which only grows. The
    device block of a place is the place modulo the device size. An object
    never crosses the device end: the rest of the device is skipped, and
    the skipped space counts as written. A new object of n blocks at place
    P reuses the blocks of each object that starts below P + n - device;
    the log holds objects in place order, so these are at its front.
    """

    def __init__(self, device_blocks):
        self.dev = device_blocks
        self.log = collections.deque()      # [place, nlb, key], oldest first
        self.where = {}                     # key -> its current entry
        self.head = 0
        self.evicted = 0

    def put(self, key, nlb):
        """Store @key; return its device block."""
        if self.head % self.dev + nlb > self.dev:
            self.head += self.dev - self.head % self.dev
        low = self.head + nlb - self.dev
        while self.log and self.log[0][0] < low:
            old = self.log.popleft()
            # an older copy of a key that was stored again or deleted is
            # not the current one: the key stays
            if self.where.get(old[2]) is old:
                del self.where[old[2]]
                self.evicted += 1
        entry = [self.head, nlb, key]
        self.log.append(entry)
        self.where[key] = entry
        self.head += nlb
        return entry[0] % self.dev

    def get(self, key):
        entry = self.where.get(key)
        if entry is None:
            return None
        return entry[0] % self.dev, entry[1]

    def delete(self, key):
        return self.where.pop(key, None) is not None


def convert_kv(rows, opts):
    """io_trace lines and the summary of a key-value trace."""
    bs = opts.block_size
    dev = opts.device_size // bs
    if rows[0].t is None:
        if not opts.rate:
            raise TraceError(0, "the trace has no op_time column: give "
                             "--rate, the lines per second of a synthetic "
                             "clock")
        rows = [r._replace(t=i) for i, r in enumerate(rows)]
        unit_ns = 10 ** 9 // opts.rate
        clock = "synthetic, %d lines per second" % opts.rate
    else:
        if opts.rate:
            raise TraceError(0, "the trace has an op_time column: --rate "
                             "is for a trace with no time")
        unit_ns = UNITS[opts.time_unit]
        clock = "trace"
    cache = FifoLog(dev)
    w = Writer(bs)
    n = collections.Counter()
    for r, t in timeline(rows, unit_ns, opts.spread, opts.duration,
                         opts.limit, lambda r: r.op_count):
        n["requests"] += 1
        if r.op == "SET":
            if r.size == 0:
                # a SET of nothing: the cache keeps what it holds
                n["empty"] += 1
                continue
            nlb = -(-(r.key_size + r.size) // bs)
            if nlb > dev:
                raise TraceError(r.line, "an object of %d blocks is larger "
                                 "than the device (%d blocks)" % (nlb, dev))
            w.add(t, 0, 0x01, [(cache.put(r.key, nlb), nlb)], r.line)
            n["set"] += 1
        elif r.op == "DELETE":
            n["delete"] += 1
            if cache.delete(r.key):
                n["deleted"] += 1
        else:
            # GET and GET_LEASE: the size and cache_hits columns of the
            # trace do not change the model; the stored extent is read
            place = cache.get(r.key)
            if place is None:
                n["miss"] += 1
                continue
            w.add(t, 0, 0x02, [place], r.line)
            n["hit"] += 1
    if len(w.lines) == 1:
        raise TraceError(0, "no SET with a size above 0 in the window")
    out = ["requests: %d lines, %d requests after op_count, %d in the "
           "window" % (len(rows), sum(r.op_count for r in rows),
                       n["requests"]),
           "model: set %d, get hit %d, get miss %d, delete %d (of a "
           "stored key %d), set of size 0 %d, evicted %d, log of %d blocks"
           % (n["set"], n["hit"], n["miss"], n["delete"], n["deleted"],
              n["empty"], cache.evicted, dev),
           "commands: %d (requests split: %d)" % (len(w.lines) - 1, w.split),
           time_summary(rows, opts, clock), NO_LATENCY]
    return w.lines, out


def read_sizes(path, volume):
    """The capacity of @volume in an Alibaba device_size.csv file."""
    found = None
    with open_text(path) as src:
        for line, text in enumerate(src, 1):
            text = text.rstrip("\r\n")
            if line == 1 and text.lower() == "device_id,capacity":
                continue
            f = text.split(",")
            nfields(f, 2, line)
            if str(dec(f[0], "device_id", line)) == volume:
                if found is not None:
                    raise TraceError(line, "%s gives volume %s a size twice"
                                     % (path, volume))
                found = dec(f[1], "capacity", line)
    if not found:
        raise TraceError(0, "%s holds no size above 0 for volume %s"
                         % (path, volume))
    return found


def open_text(path):
    if path == "-":
        return io.TextIOWrapper(sys.stdin.buffer, newline="")
    if path.endswith(".gz"):
        return gzip.open(path, "rt", newline="")
    return open(path, newline="")


def run(lines, opts):
    """Check and convert; return the summary and the io_trace lines."""
    bad = Bad(opts.max_bad)
    rows = read_rows(lines, opts.format, bad)
    head = ["import: format %s, block size %d, device size %d"
            % (opts.format, opts.block_size or 0, opts.device_size or 0)]
    if not rows:
        raise TraceError(0, "the trace holds no request")
    if opts.list_volumes:
        return ["import: format %s" % opts.format] + list_volumes(rows), None
    if opts.format == "cachelib":
        lines_out, text = convert_kv(rows, opts)
    else:
        volume, rows = select_volume(rows, norm_volume(opts.volume))
        head[0] += ", volume %s" % volume
        volume_blocks = volume_from = None
        size = opts.volume_size
        if opts.volume_sizes:
            size = read_sizes(opts.volume_sizes, volume)
            volume_from = opts.volume_sizes
        elif size is not None:
            volume_from = "--volume-size"
        if size is not None:
            volume_blocks = -(-size // opts.block_size)
        lines_out, text = convert_block(rows, opts, volume_blocks,
                                        volume_from)
    text.append("bad lines skipped: %d%s"
                % (bad.count, " (first at %s)"
                   % ", ".join(str(n) for n in bad.first)
                   if bad.first else ""))
    return head + text, lines_out


def publish(path, data):
    """Write @data to a new file at @path, which appears only when whole."""
    folder = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=".femu-trace-import-")
    try:
        with os.fdopen(fd, "w") as dst:
            dst.write(data)
        # link() never replaces a file, like FEMU with io_trace
        os.link(tmp, path)
    finally:
        os.unlink(tmp)


def size_arg(text):
    m = SIZE.match(text.lower())
    if not m:
        raise argparse.ArgumentTypeError("'%s' is not a size (a number, "
                                         "then k, m, g or t)" % text)
    return int(m.group(1)) << (10 * " kmgt".index(m.group(2) or " "))


def count_arg(text):
    if not DEC.match(text) or int(text) < 1:
        raise argparse.ArgumentTypeError("'%s' is not a number above 0"
                                         % text)
    return int(text)


def parser():
    p = argparse.ArgumentParser(
        description="Turn a public block or cache trace into a FEMU "
                    "io_trace file for femu-trace2fio.py.")
    p.add_argument("trace", metavar="TRACE",
                   help="the trace file; .gz is read as gzip; - is stdin")
    p.add_argument("--format", required=True,
                   choices=("msr", "alibaba", "tencent", "cachelib"))
    p.add_argument("--block-size", type=size_arg, metavar="BYTES",
                   help="LBA size of the FEMU namespace, for example 512 "
                        "or 4k")
    p.add_argument("--device-size", type=size_arg, metavar="BYTES",
                   help="size of the FEMU namespace")
    p.add_argument("--out", metavar="OUT",
                   help="the io_trace file to write, which must not exist; "
                        "- is stdout (the summary then goes to stderr)")
    p.add_argument("--volume", metavar="ID",
                   help="the volume to use: HOST:DISK for msr, the device "
                        "ID for alibaba, the VolumeID for tencent")
    p.add_argument("--list-volumes", action="store_true",
                   help="print the volumes and their sizes, write nothing")
    p.add_argument("--fold", choices=("none", "wrap", "scale"),
                   default="none",
                   help="how a volume larger than the device fits: none "
                        "(a range past the device is an error), wrap "
                        "(block modulo the device), scale (block times "
                        "device / volume)")
    p.add_argument("--volume-size", type=size_arg, metavar="BYTES",
                   help="size of the volume, for --fold scale")
    p.add_argument("--volume-sizes", metavar="FILE",
                   help="an Alibaba device_size.csv file, for --fold scale")
    p.add_argument("--time-unit", choices=sorted(UNITS),
                   help="unit of the trace time; necessary for tencent and "
                        "for a cachelib op_time column (default: filetime "
                        "for msr, us for alibaba)")
    p.add_argument("--spread", action="store_true",
                   help="spread the requests of one time over one time "
                        "unit, in file order")
    p.add_argument("--rate", type=count_arg, metavar="N",
                   help="lines per second of a synthetic clock, for a "
                        "cachelib trace with no op_time column")
    p.add_argument("--duration", type=count_arg, metavar="SEC",
                   help="keep the first SEC seconds of the volume")
    p.add_argument("--limit", type=count_arg, metavar="N",
                   help="keep the first N requests of the volume, in time "
                        "order")
    p.add_argument("--max-bad", type=int, default=0, metavar="N",
                   help="skip up to N bad lines and count them (default 0: "
                        "the first bad line is an error); not for cachelib")
    return p


def check_options(p, opts):
    if opts.time_unit is None and opts.format != "cachelib":
        opts.time_unit = DEFAULT_UNIT[opts.format]
        if opts.time_unit is None:
            p.error("--format %s needs --time-unit: the unit of its time "
                    "column is not confirmed" % opts.format)
    if opts.max_bad < 0:
        p.error("--max-bad must not be negative")
    if opts.list_volumes:
        if opts.format == "cachelib":
            p.error("a cachelib trace has no volume")
        return
    if opts.block_size is None or opts.device_size is None or \
            opts.out is None:
        p.error("--block-size, --device-size and --out are necessary")
    bs = opts.block_size
    if bs < 512 or bs & (bs - 1) or bs > U32:
        p.error("--block-size must be a power of two from 512 to 2g")
    if opts.device_size < bs or opts.device_size % bs:
        p.error("--device-size must be a multiple of --block-size")
    if opts.volume_size is not None and opts.volume_sizes:
        p.error("give --volume-size or --volume-sizes, not both")
    if (opts.volume_size is not None or opts.volume_sizes) and \
            opts.fold != "scale":
        p.error("--volume-size and --volume-sizes need --fold scale")
    if opts.volume_size == 0:
        p.error("--volume-size must be above 0")
    if opts.format == "cachelib":
        if opts.volume or opts.fold != "none" or opts.volume_sizes or \
                opts.volume_size is not None:
            p.error("a cachelib trace has no volume and no fold")
        if opts.max_bad:
            p.error("--max-bad is not for cachelib: a skipped line "
                    "changes each later state of the cache model")
        if opts.time_unit is None and not opts.rate:
            p.error("--format cachelib needs --time-unit for op_time, or "
                    "--rate for a trace with no op_time")
        if opts.time_unit is None:
            opts.time_unit = "s"
    elif opts.rate:
        p.error("--rate is for a cachelib trace with no op_time column")


def main(argv):
    if argv == ["--self-test"]:
        return self_test()
    p = parser()
    opts = p.parse_args(argv)
    check_options(p, opts)
    if opts.out not in (None, "-") and os.path.lexists(opts.out):
        print("femu-trace-import: %s exists; the tool never writes over a "
              "file" % opts.out, file=sys.stderr)
        return 2
    try:
        with open_text(opts.trace) as src:
            text, out = run(src, opts)
        if out is not None:
            data = "\n".join(out) + "\n"
            if opts.out == "-":
                sys.stdout.write(data)
            else:
                publish(opts.out, data)
    except TraceError as e:
        print("femu-trace-import: %s: %s" % (opts.trace, e), file=sys.stderr)
        return 1
    except (OSError, UnicodeDecodeError, EOFError) as e:
        print("femu-trace-import: %s" % e, file=sys.stderr)
        return 2
    print("\n".join(text), file=sys.stderr if opts.out == "-" else
          sys.stdout)
    return 0


# Self-test: the fixtures in trace-fixtures/ and the expected output of each

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "trace-fixtures")

MSR_OUT = """\
t_submit_ns,t_cqe_ns,sqid,cid,nsid,opcode,slba,nlb,status
0,100000,1,0,1,0x02,0,8,0x0
500000,550000,1,1,1,0x02,8,8,0x0
1000000,1200000,1,2,1,0x01,16,16,0x0
3000000,3030000,1,3,1,0x01,1,3,0x0
5000000,5900000,1,4,1,0x01,2048,65536,0x0
5000000,5900000,1,5,1,0x01,67584,1,0x0
6000000,6070000,1,6,1,0x02,8192,8,0x0
"""

MSR_SUMMARY = """\
import: format msr, block size 512, device size 67108864, volume usr:0
requests: 7 of the volume, 7 in the window; read 3 write 3, bytes read \
12288 written 33564136
commands: 7 (requests split: 1)
changed: size 0 dropped 1, unaligned grown to whole blocks 1
fold: none
time: clock trace, unit filetime, out of order 1, largest count at one \
time 1, spread off
latency: ResponseTime of the trace, the time on the original disk; each \
piece of a split request has it
bad lines skipped: 0
"""

# (time in us, action, slba, nlb) of the Alibaba fixture, volume 3, on a
# 64 MiB device of 512-byte blocks: the volume is 4 times the device
ALIBABA_WRAP = [(0, 1, 0, 8), (100, 2, 0, 8), (200, 1, 0, 16),
                (300, 2, 131064, 8), (400, 1, 131064, 8), (400, 1, 0, 8)]
ALIBABA_SCALE = [(0, 1, 0, 8), (100, 2, 0, 8), (200, 1, 65536, 16),
                 (300, 2, 131064, 8), (400, 1, 65534, 16)]

TENCENT_4K = [(0, 1, 0, 1), (0, 1, 1, 1), (0, 2, 2, 1),
              (10 ** 9, 2, 0, 2), (10 ** 9, 2, 0, 1)]
TENCENT_512 = [(0, 1, 0, 8), (0, 1, 8, 8), (0, 2, 16, 8),
               (10 ** 9, 2, 7, 2), (10 ** 9, 2, 0, 8)]

S = 10 ** 9
CACHELIB_OUT = [(0, 1, 0, 1), (0, 1, 1, 2),
                (S, 2, 0, 1), (S, 2, 0, 1), (S, 1, 3, 1), (S, 1, 4, 1),
                (2 * S, 1, 0, 2), (2 * S, 2, 4, 1),
                (3 * S, 1, 2, 1), (3 * S, 1, 3, 2),
                (4 * S, 2, 2, 1)]

CACHELIB_SUMMARY = """\
import: format cachelib, block size 4096, device size 24576
requests: 15 lines, 17 requests after op_count, 17 in the window
model: set 7, get hit 4, get miss 4, delete 1 (of a stored key 1), set of \
size 0 1, evicted 2, log of 6 blocks
commands: 11 (requests split: 0)
time: clock trace, unit s, out of order 0, largest count at one time 4, \
spread off
latency: none in the trace; t_cqe_ns = t_submit_ns, so the depth lines of \
femu-trace2fio.py are not a queue depth
bad lines skipped: 0
"""


def load_trace2fio():
    """femu-trace2fio.py, to check the output the way a user's run does."""
    path = os.path.join(HERE, "femu-trace2fio.py")
    loader = importlib.machinery.SourceFileLoader("femu_trace2fio", path)
    spec = importlib.util.spec_from_loader("femu_trace2fio", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def fixture(name):
    with open(os.path.join(FIXTURES, name), newline="") as f:
        return f.readlines()


def options(fmt, **kw):
    unit = {"tencent": "s", "cachelib": "s"}.get(fmt, DEFAULT_UNIT[fmt])
    base = dict(format=fmt, block_size=512, device_size=64 << 20,
                out="-", volume=None, list_volumes=False, fold="none",
                volume_size=None, volume_sizes=None, time_unit=unit,
                spread=False, rate=None, duration=None, limit=None,
                max_bad=0)
    base.update(kw)
    return argparse.Namespace(**base)


def fails(lines, opts, line, key):
    try:
        run(lines, opts)
    except TraceError as e:
        assert e.line == line and key in e.text, (line, key, str(e))
        return
    raise AssertionError("not caught: " + key)


def commands(out):
    """(t_submit_ns, opcode, slba, nlb) of each io_trace line."""
    assert out[0] == HEADER, out[0]
    rows = []
    for text in out[1:]:
        f = text.split(",")
        rows.append((int(f[0]), int(f[5], 16), int(f[6]), int(f[7])))
    return rows


def replay(t2f, out, block_size, device_size):
    """Run femu-trace2fio.py on @out with --strict; return its I/O log."""
    o = argparse.Namespace(nsid=None, filename="/dev/nvme0n1", iolog="x",
                           block_size=block_size, device_size=device_size,
                           time_scale=1, lba_scale=1, strict=True,
                           buckets=2, burst_gap=1000000)
    _, iolog = t2f.run([t + "\n" for t in out], o)
    return t2f.parse_iolog(iolog)


def self_test():
    t2f = load_trace2fio()
    groups = 0

    # 1. MSR: exact output and summary of one volume of two, then the
    # I/O log of femu-trace2fio.py in order: each byte range is unchanged,
    # except the unaligned one, which grows to whole blocks
    msr = fixture("msr.csv")
    text, out = run(msr, options("msr", volume="usr:0"))
    assert "\n".join(out) + "\n" == MSR_OUT, "\n".join(out)
    assert "\n".join(text) + "\n" == MSR_SUMMARY, "\n".join(text)
    ios = replay(t2f, out, 512, 64 << 20)
    assert ios == [(0, "read", 0, 4096), (500, "read", 4096, 4096),
                   (1000, "write", 8192, 8192), (3000, "write", 512, 1536),
                   (5000, "write", 1048576, 33554432),
                   (5000, "write", 1048576 + 33554432, 512),
                   (6000, "read", 4194304, 4096)], ios
    groups += 1

    # 2. volume selection: two volumes and no --volume (the second volume
    # is in line 4), a header line, leading zeros, the volume list, a
    # volume that is not in the file
    fails(msr, options("msr"), 4, "select one with --volume")
    hdr = [COLUMNS["msr"] + "\n"] + msr
    _, out2 = run(hdr, options("msr", volume="usr:00"))
    assert out2 == out, out2
    text, none = run(msr, options("msr", list_volumes=True))
    assert none is None and text[-2:] == ["  usr:0 7 4 3 34603520",
                                          "  usr:1 1 1 0 512"], text
    fails(msr, options("msr", volume="web:0"), 0, "no request for volume")
    groups += 1

    # 3. Alibaba: a volume of 4 times the device and each fold; wrap
    # splits a range at the device end, scale maps the start once
    ali = fixture("alibaba.csv")
    sizes = os.path.join(FIXTURES, "alibaba-sizes.csv")
    fails(ali, options("alibaba", volume="3"), 4, "ends past the device")
    text, wrap = run(ali, options("alibaba", volume="3", fold="wrap"))
    assert commands(wrap) == [(t * 1000, a, s, n)
                              for t, a, s, n in ALIBABA_WRAP], wrap
    assert "wrapped at the device end 1, moved to end at the device " \
        "end 0" in text[4], text
    text, scale = run(ali, options("alibaba", volume="3", fold="scale",
                                   volume_sizes=sizes))
    assert commands(scale) == [(t * 1000, a, s, n)
                               for t, a, s, n in ALIBABA_SCALE], scale
    assert text[4] == ("fold: scale, volume 524288 blocks (%s), device "
                       "131072 blocks, wrapped at the device end 0, moved "
                       "to end at the device end 1" % sizes), text
    # the largest end of the whole volume is the same size here, and
    # --limit does not change it
    _, scale2 = run(ali, options("alibaba", volume="3", fold="scale"))
    assert scale2 == scale, scale2
    _, scale3 = run(ali, options("alibaba", volume="3", fold="scale",
                                 limit=3))
    assert scale3 == scale[:4], scale3
    fails(ali, options("alibaba", volume="3", fold="scale",
                       volume_size=1 << 20), 5, "past the volume size")
    # a range above 65536 blocks: the start maps once, then the range
    # splits, so the second command follows the first
    long = ["3,W,0,33554944,1000\n", "3,W,67108864,33554944,2000\n"]
    _, out = run(long, options("alibaba", fold="scale",
                               volume_size=256 << 20))
    assert commands(out) == [(0, 1, 0, 65536), (0, 1, 65536, 1),
                             (1000000, 1, 32768, 65536),
                             (1000000, 1, 98304, 1)], out
    for o in (wrap, scale):
        replay(t2f, o, 512, 64 << 20)
    groups += 1

    # 4. the fold and split arithmetic, with ratios that are not whole
    # numbers, numbers above 2^53 and the fio length limit
    f = Folder("scale", 100, 300)
    assert [f.place(s, 1, 0) for s in (0, 150, 299)] == \
        [[(0, 1)], [(50, 1)], [(99, 1)]]
    f = Folder("scale", 1 << 40, 1 << 61)
    assert f.place((1 << 60) + 3, 1, 0) == [(1 << 39, 1)]
    f = Folder("wrap", 100, 400)
    assert f.place(398, 4, 0) == [(98, 2), (0, 2)]
    assert f.place(300, 100, 0) == [(0, 100)]
    for mode in ("none", "wrap", "scale"):
        fails_place = Folder(mode, 100, 400)
        try:
            fails_place.place(0, 101, 7)
        except TraceError as e:
            assert e.line == 7 and "larger than the device" in e.text
        else:
            raise AssertionError("not caught: a range above the device")
    w = Writer(512)
    w.add(5, 0, 1, [(0, 3 * MAX_NLB)], 0)
    w.add(6, 0, 1, [(0, MAX_NLB)], 0)
    assert [x.split(",")[6:8] for x in w.lines[1:]] == \
        [["0", "65536"], ["65536", "65536"], ["131072", "65536"],
         ["0", "65536"]] and w.split == 1, w.lines
    w = Writer(65536)
    w.add(5, 0, 1, [(0, MAX_NLB)], 0)
    assert [x.split(",")[6:8] for x in w.lines[1:]] == \
        [["0", "65535"], ["65535", "1"]], w.lines
    groups += 1

    # 5. Tencent: 512-byte sectors on 512-byte and 4 KiB blocks, one range
    # across a 4 KiB edge, an older time later in the file, and --spread
    ten = fixture("tencent.csv")
    _, out = run(ten, options("tencent", volume="1063", block_size=4096))
    assert commands(out) == TENCENT_4K, out
    assert [io[1:] for io in replay(t2f, out, 4096, 64 << 20)] == \
        [("write", 0, 4096), ("write", 4096, 4096), ("read", 8192, 4096),
         ("read", 0, 8192), ("read", 0, 4096)]
    _, out = run(ten, options("tencent", volume="1063"))
    assert commands(out) == TENCENT_512, out
    _, out = run(ten, options("tencent", volume="1063", block_size=4096,
                              spread=True))
    assert [c[0] for c in commands(out)] == \
        [0, 333333333, 666666666, 1000000000, 1500000000], out
    groups += 1

    # 6. CacheLib: key overhead, op_count, misses, GET_LEASE, eviction
    # after the log wraps, a stale copy after SET again and DELETE, a SET
    # of size 0, and two use cases with one key
    kv = fixture("cachelib.csv")
    kvo = options("cachelib", block_size=4096, device_size=24576)
    text, out = run(kv, kvo)
    assert commands(out) == CACHELIB_OUT, out
    assert "\n".join(text) + "\n" == CACHELIB_SUMMARY, "\n".join(text)
    replay(t2f, out, 4096, 24576)
    # --spread counts the requests after op_count: 4 at time 101
    _, out2 = run(kv, options("cachelib", block_size=4096,
                              device_size=24576, spread=True))
    assert [c[0] for c in commands(out2)][:6] == \
        [333333333, 666666666, S, S + S // 4, S + S // 2,
         S + 3 * S // 4], out2
    # --limit counts requests after op_count, misses included
    _, out3 = run(kv, options("cachelib", block_size=4096,
                              device_size=24576, limit=5))
    assert commands(out3) == CACHELIB_OUT[:4], out3
    # the columns in another order give the same result
    names = kv[0].rstrip("\n").split(",")
    perm = list(reversed(range(len(names))))
    moved = [",".join(t.rstrip("\n").split(",")[i] for i in perm) + "\n"
             for t in kv]
    _, out4 = run(moved, kvo)
    assert out4 == out, out4
    # no header, no key_size, a name twice: the tool does not guess
    fails(kv[1:], kvo, 1, "not a CacheLib header")
    drop = names.index("key_size")
    no_ks = [",".join(x for i, x in enumerate(t.rstrip("\n").split(","))
                      if i != drop) + "\n" for t in kv]
    fails(no_ks, kvo, 1, "missing: key_size")
    fails([kv[0].rstrip("\n") + ",key\n"] + kv[1:], kvo, 1,
          "names 'key' twice")
    groups += 1

    # 7. CacheLib 202206: no op_time, so --rate gives a synthetic clock
    old = fixture("cachelib-202206.csv")
    fails(old, options("cachelib", device_size=32768), 0, "give --rate")
    text, out = run(old, options("cachelib", device_size=32768, rate=10))
    assert commands(out) == [(0, 1, 0, 2), (10 ** 8, 2, 0, 2),
                             (10 ** 8, 2, 0, 2), (10 ** 8, 2, 0, 2),
                             (3 * 10 ** 8, 1, 2, 10)], out
    assert "clock synthetic, 10 lines per second" in text[4], text
    fails(kv, options("cachelib", block_size=4096, device_size=24576,
                      rate=10), 0, "--rate is for a trace with no time")
    groups += 1

    # 8. bad lines: one per format, refused, then skipped with --max-bad
    planted = [
        ("msr", msr, 2, "128166372000010000,usr,0,Rd,8192,8192,2000",
         "not Read or Write", dict(volume="usr:0")),
        ("msr", msr, 3, "128166372000005000,usr,0,Read,4096,4096",
         "6 fields, not 7", dict(volume="usr:0")),
        ("msr", msr, 3, "128166372000005000,usr,0,Read,-1,4096,500",
         "not a decimal", dict(volume="usr:0")),
        ("alibaba", ali, 1, "3,W,0,4k,1577808000000000",
         "not a decimal", dict(volume="3", fold="wrap")),
        ("tencent", ten, 2, "1538323200,8,8,2,1063", "not 0 or 1",
         dict(volume="1063", block_size=4096)),
        ("tencent", ten, 2, "", "1 fields, not 5",
         dict(volume="1063", block_size=4096)),
        ("tencent", ten, 2, "1538323200.5,8,8,1,1063", "not a decimal",
         dict(volume="1063", block_size=4096)),
        ("tencent", ten, 2, "1" * 21 + ",8,8,1,1063", "not a decimal",
         dict(volume="1063", block_size=4096)),
    ]
    for fmt, lines, n, text_line, key, kw in planted:
        bad = list(lines)
        bad[n - 1] = text_line + "\n"
        fails(bad, options(fmt, **kw), n, key)
        text, _ = run(bad, options(fmt, max_bad=1, **kw))
        assert text[-1] == "bad lines skipped: 1 (first at %d)" % n, text
        bad2 = list(bad)
        bad2[n] = text_line + "\n"
        fails(bad2, options(fmt, max_bad=1, **kw), n + 1, "above --max-bad")
    for text_line, key in (("100,k1,8,PUT,1,4088,0,0,1,1", "not one of"),
                           ("100,k1,8,SET,0,4088,0,0,1,1", "op_count 0")):
        bad = list(kv)
        bad[3] = text_line + "\n"
        fails(bad, kvo, 4, key)
    groups += 1

    # 9. windows: --duration is half open, --limit keeps the first
    # requests in time order
    _, out = run(msr, options("msr", volume="usr:0", limit=2))
    assert [c[2] for c in commands(out)] == [0, 8], out
    _, out = run(ten, options("tencent", volume="1063", block_size=4096,
                              duration=1))
    assert commands(out) == TENCENT_4K[:3], out
    groups += 1

    # 10. the command line: gzip and stdin give the same file, an
    # existing file is never written over, a failed run leaves no file,
    # and the options that need a confirmed unit or a size fail
    with tempfile.TemporaryDirectory() as tmp:
        gz = os.path.join(tmp, "t.csv.gz")
        with gzip.open(gz, "wt") as f:
            f.writelines(ten)
        dst = os.path.join(tmp, "out.csv")
        base = ["--format", "tencent", "--time-unit", "s", "--volume",
                "1063", "--block-size", "4k", "--device-size", "64m"]
        tail_bad = os.path.join(tmp, "tail-bad.csv")
        with open(tail_bad, "w") as f:
            f.writelines(ten + ["1538323202,0,8,9,1063\n"])
        saved = sys.stdout, sys.stderr, sys.stdin
        sys.stdout = sys.stderr = io.StringIO()
        try:
            assert main(base + ["--out", dst, gz]) == 0
            with open(dst) as f:
                first = f.read()
            assert commands(first.splitlines()) == TENCENT_4K
            assert main(base + ["--out", dst, gz]) == 2
            sys.stdin = io.TextIOWrapper(io.BytesIO("".join(ten).encode()))
            dst2 = os.path.join(tmp, "out2.csv")
            assert main(base + ["--out", dst2, "-"]) == 0
            with open(dst2) as f:
                assert f.read() == first
            dst3 = os.path.join(tmp, "out3.csv")
            assert main(base + ["--out", dst3, tail_bad]) == 1
            assert not os.path.exists(dst3)
            assert sorted(os.listdir(tmp)) == ["out.csv", "out2.csv",
                                               "t.csv.gz", "tail-bad.csv"]
            for argv in (["--format", "tencent", "--block-size", "4k",
                          "--device-size", "64m", "--out", dst3, tail_bad],
                         ["--format", "cachelib", "--block-size", "4k",
                          "--device-size", "64m", "--out", dst3, tail_bad],
                         base + ["--block-size", "3k", "--out", dst3,
                                 tail_bad],
                         base + ["--fold", "wrap", "--volume-size", "1m",
                                 "--out", dst3, tail_bad]):
                try:
                    main(argv)
                except SystemExit as e:
                    assert e.code == 2, argv
                else:
                    raise AssertionError("not refused: %s" % argv)
        finally:
            sys.stdout, sys.stderr, sys.stdin = saved
    groups += 1

    print("femu-trace-import: self-test passed (%d groups, %d planted bad "
          "lines)" % (groups, len(planted) + 2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
