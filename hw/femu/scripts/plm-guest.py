#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Guest side of the Predictable Latency Mode tests. Runs as root.

  plm-guest.py check    [--ctrl CTRL] [--dev DEV] [--need TOOLS]
  plm-guest.py gplm1    [--ctrl CTRL] [--dev DEV]
  plm-guest.py precond  [--dev DEV] [--passes N] [--limit S]
  plm-guest.py tail     [--ctrl CTRL] [--dev DEV] [--cycles N]
                        [--dtwin-ms MS] [--ndwin-ms MS] [--wrate-mib R]
                        [--riops N] [--unit-bytes B] [--guard-ms MS]
                        [--phantom] [--out DIR]
  plm-guest.py dmesg
  plm-guest.py --self-test

CTRL is the controller node (default /dev/nvme0), DEV its namespace 1
(default /dev/nvme0n1). The host (plm-verdict.py) decides each verdict.
This program does the guest steps and prints facts, one "FG key=value
..." line each. The last line is "FG_DONE ok" or "FG_DONE fail <why>".
Exit status: 0 for ok, 1 for a failed step, 2 for a usage or setup
error. gplm1, precond and tail write to DEV.

gplm1 is the guest check of design 6.2. Every admin command whose data
or status it checks goes through NVME_IOCTL_ADMIN_CMD, so no nvme-cli
output is parsed for a check. It also runs the nvme-cli commands of the
guide (2.0 or newer) and records how each ended. On a failed command or
parse it prints the raw bytes or text, up to 4 KiB, as "FG_RAW" lines.
The device must have plm_dtwin_ms well above the run time, so only the
writes end the DTWIN:

  id-ctrl, CNS 04h, Identify NS --> Get 13h (LPE 0) --> refusals
  --> Set 13h LPE=1 --> Get 14h = NDWIN --> Set 14h DTWIN --> log 0Ah
  --> DTWWT units of writes: still DTWIN, DTWWE fell
  --> one more unit: NDWIN, ETYP MVEAT --> logs 0Bh, 0Ah, 0Ah, 0Bh
  --> Set 13h LPE=0 --> PLMW 0, Get 14h refused

tail is one repeat of the read tail experiment of design 6.3. One fio
process runs two jobs: 4 KiB random reads at QD 1 with a latency log,
and a 4 KiB random write stream at a fixed rate. Meanwhile this program
selects the windows through the NVMe ioctl, so no process start adds
time to a window edge:

  NDWIN (ndwin-ms) --> Set 14h DTWIN (may be held) --> log 0Ah: DTWWE
  --> poll log 0Ah (RAE) every 100 ms for dtwin-ms --> Set 14h NDWIN
  --> log 0Ah (no RAE): ETYP of this cycle --> next cycle

Each read goes to the window of its submit time (completion time less
latency). A guard of guard-ms at each window edge is left out. A cycle
is valid when its DTWIN started with DTWWE at least the planned writes
and had no DEAT. Only the reads of valid cycles count. With --phantom
(plm=off) no command is sent, and the same time slots split the reads:
that is the control of the split.
"""
import argparse
import contextlib
import ctypes
import fcntl
import glob
import math
import mmap
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from io import StringIO

OPC_GET_LOG = 0x02
OPC_IDENTIFY = 0x06
OPC_SET_FEAT = 0x09
OPC_GET_FEAT = 0x0A
FID_CFG = 0x13
FID_WIN = 0x14
LID_SET = 0x0A
LID_AGG = 0x0B
PLMW_OFF, PLMW_DT, PLMW_ND = 0, 1, 2
MVEAT = 1 << 14
DEAT = 1 << 15
# struct nvme_passthru_cmd of <linux/nvme_ioctl.h>, 72 bytes
CMD_FMT = "<BBHIIIQQIIIIIIIIII"
NVME_IOCTL_ADMIN_CMD = 0xC0484E41
SC_INVALID_FIELD = 0x02


class StepError(Exception):
    """A guest step failed: FG_DONE fail, exit 1."""


class SetupError(Exception):
    """The guest cannot run the test: FG_DONE fail, exit 2."""


def fact(**kv):
    print("FG " + " ".join("%s=%s" % (k, v) for k, v in kv.items()),
          flush=True)


def run(cmd, limit, check=True):
    """Run a command with a time limit; return (rc, output)."""
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    try:
        raw, _ = p.communicate(timeout=limit)
    except subprocess.TimeoutExpired:
        p.kill()
        try:
            p.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            raise StepError("unkillable-" + os.path.basename(cmd[0]))
        raise StepError("timeout-" + os.path.basename(cmd[0]))
    out = raw.decode(errors="replace")
    if check and p.returncode != 0:
        tail = out.strip().splitlines()[-1:] or [""]
        raise StepError("%s-rc%d %s" % (os.path.basename(cmd[0]),
                                        p.returncode, tail[0][:80]))
    return p.returncode, out


# ---- raw output of a failure ----------------------------------------------

RAW_LIMIT = 4096


def raw(tag, blob):
    """Print up to RAW_LIMIT bytes or characters of BLOB as FG_RAW lines,
    so the next failure shows what the guest got."""
    if isinstance(blob, (bytes, bytearray)):
        b = bytes(blob[:RAW_LIMIT])
        print("FG_RAW %s bytes=%d shown=%d" % (tag, len(blob), len(b)))
        for off in range(0, len(b), 32):
            print("FG_RAW %s +%04x %s" % (tag, off, b[off:off + 32].hex()))
    else:
        t = str(blob)[:RAW_LIMIT]
        print("FG_RAW %s chars=%d shown=%d" % (tag, len(str(blob)), len(t)))
        for line in t.splitlines():
            print("FG_RAW %s | %s" % (tag, line))
    sys.stdout.flush()


# ---- nvme-cli output ------------------------------------------------------

HEX_LINE = re.compile(r"^\s*(?:0x)?([0-9a-fA-F]{4,8}):?(?:\s+(.*))?$")


def hexdump(text, length=None):
    """The bytes of an nvme-cli hex dump. Each line is "OFFS: xx xx ...",
    with or without an ascii column; the ascii column starts with a quote
    or a bar, which ends the byte list. nvme-cli 3.x prints "*" for lines
    that repeat the line before. The next offset, a last offset alone on
    its line, or LENGTH ends the repeat."""
    data = bytearray()
    last = b""
    rep = False
    for line in text.splitlines():
        if line.strip() == "*":
            if not last:
                raise ValueError("hex dump repeat before any line")
            rep = True
            continue
        m = HEX_LINE.match(line)
        if not m:
            continue
        off = int(m.group(1), 16)
        got = []
        for tok in (m.group(2) or "").split():
            if tok[0] in "\"|" or not re.fullmatch(r"[0-9a-fA-F]{2}", tok):
                break
            got.append(int(tok, 16))
            if len(got) == 16:
                break
        if rep:
            if off < len(data) or (off - len(data)) % len(last):
                raise ValueError("hex dump repeat to %#x after %d bytes" %
                                 (off, len(data)))
            data += last * ((off - len(data)) // len(last))
            rep = False
        if off != len(data):
            # a gap or an overlap: not one dump
            raise ValueError("hex dump offset %#x after %d bytes" %
                             (off, len(data)))
        if got:
            data += bytes(got)
            last = bytes(got)
    if rep:
        if length is None or (length - len(data)) % len(last):
            raise ValueError("hex dump ends in a repeat after %d bytes" %
                             len(data))
        data += last * ((length - len(data)) // len(last))
    return bytes(data)


def le(data, lo, n):
    return int.from_bytes(data[lo:lo + n], "little")


def cli_exit(tag, args, limit=60):
    """Run a named nvme-cli command of the guide; its exit status is a
    fact. Its output is shown only when it fails."""
    rc, out = run(["nvme"] + args, limit, check=False)
    if rc:
        raw(tag, out)
    return rc


def cli_log0a(ctrl):
    """The guide's "nvme get-log" of log 0Ah (with RAE), parsed from its
    hex dump: "plmw-N", or why not. Data checks use the ioctl only."""
    rc, out = run(["nvme", "get-log", ctrl, "-i", "0x0a", "-l", "512",
                   "--lsi=1", "--rae"], 60, check=False)
    if rc:
        raw("cli_log0a", out)
        return "rc-%d" % rc
    try:
        d = hexdump(out, 512)
    except ValueError as e:
        raw("cli_log0a", out)
        return "parse-" + str(e).replace(" ", "-")[:60]
    if len(d) != 512:
        raw("cli_log0a", out)
        return "short-%d" % len(d)
    return "plmw-%d" % (d[0] & 0x7)


# ---- the NVMe ioctl -------------------------------------------------------

def pack_cmd(opc, nsid, addr, length, cdw10, cdw11=0, cdw12=0,
             timeout_ms=0):
    return bytearray(struct.pack(CMD_FMT, opc, 0, 0, nsid, 0, 0, 0, addr, 0,
                                 length, cdw10, cdw11, cdw12, 0, 0, 0,
                                 timeout_ms, 0))


def unpack_cmd(cmd):
    """The fields of a struct nvme_passthru_cmd, by name."""
    v = struct.unpack(CMD_FMT, bytes(cmd))
    return {"opcode": v[0], "nsid": v[3], "addr": v[7], "data_len": v[9],
            "cdw10": v[10], "cdw11": v[11], "cdw12": v[12],
            "timeout_ms": v[16], "result": v[17]}


def status_sc(st):
    """SCT and SC (bits 10:0) of the status the ioctl returns; the kernel
    gives bits 15:1 of the CQE status word, so DNR is bit 14."""
    return st & 0x7ff


def get_log_dw(lid, length, lsi=0, rae=False):
    """CDW10 and CDW11 of Get Log Page for LENGTH bytes."""
    numd = length // 4 - 1
    return (lid | (int(rae) << 15) | ((numd & 0xffff) << 16),
            (numd >> 16) | (lsi << 16))


class Ioctl:
    """Admin commands through NVME_IOCTL_ADMIN_CMD on the controller node.
    call() returns (status, dw0, data); status 0 is success."""

    def __init__(self, ctrl):
        self.fd = os.open(ctrl, os.O_RDWR)

    def call(self, opc, cdw10, cdw11=0, cdw12=0, nsid=0, data=None,
             length=0, timeout_ms=0):
        n = len(data) if data is not None else length
        buf = ctypes.create_string_buffer(max(n, 1))
        if data is not None:
            ctypes.memmove(buf, data, n)
        cmd = pack_cmd(opc, nsid, ctypes.addressof(buf) if n else 0, n,
                       cdw10, cdw11, cdw12, timeout_ms)
        try:
            st = fcntl.ioctl(self.fd, NVME_IOCTL_ADMIN_CMD, cmd, True)
        except OSError as e:
            raw("ioctl-opc-%#x" % opc, bytes(cmd))
            raise StepError("ioctl-opc-%#x-%s" % (opc, e.strerror))
        return st, unpack_cmd(cmd)["result"], buf.raw[:n]

    def log0a(self, rae):
        cdw10, cdw11 = get_log_dw(LID_SET, 512, 1, rae)
        st, _, d = self.call(OPC_GET_LOG, cdw10, cdw11, length=512)
        if st:
            raise StepError("log-0a-status-%#x" % st)
        return parse_log0a(d)

    def window(self, wsel, timeout_ms=60000):
        st, _, _ = self.call(OPC_SET_FEAT, FID_WIN, 1, wsel,
                             timeout_ms=timeout_ms)
        return st


class Admin:
    """The admin commands of gplm1, all through the ioctl. Each returns
    (ok, dw0, data, sc); a refused command has ok False and its SCT and
    SC."""

    def __init__(self, ctrl):
        self.io = Ioctl(ctrl)

    def _res(self, st, dw0, data):
        return st == 0, dw0, data, (None if st == 0 else status_sc(st))

    def identify(self, cns, nsid=0, cdw11=0):
        return self._res(*self.io.call(OPC_IDENTIFY, cns, cdw11, nsid=nsid,
                                       length=4096))

    def get_feat(self, fid, cdw11=1, nsid=0, length=0):
        return self._res(*self.io.call(OPC_GET_FEAT, fid, cdw11, nsid=nsid,
                                       length=length))

    def set_feat(self, fid, cdw12, cdw11=1, nsid=0, data=None, limit=60):
        return self._res(*self.io.call(OPC_SET_FEAT, fid, cdw11, cdw12,
                                       nsid=nsid, data=data,
                                       timeout_ms=limit * 1000))

    def get_log(self, lid, length=512, lsi=0, rae=False):
        cdw10, cdw11 = get_log_dw(lid, length, lsi, rae)
        return self._res(*self.io.call(OPC_GET_LOG, cdw10, cdw11,
                                       length=length))


def parse_log0a(d):
    """The fields of log 0Ah (Figure 224) that the tests read."""
    return {"plmw": d[0] & 0x7, "etyp": le(d, 2, 2), "dtwrt": le(d, 32, 8),
            "dtwwt": le(d, 40, 8), "dtwtm": le(d, 48, 8),
            "ntwtmh": le(d, 56, 8), "ntwtml": le(d, 64, 8),
            "dtwre": le(d, 128, 8), "dtwwe": le(d, 136, 8),
            "dtwte": le(d, 144, 8)}


def parse_set_list(d):
    """NUMID and the first entry of an NVM Set List (Figures 332 to 334)."""
    e = d[128:256]
    return {"numid": d[0], "nsetid": le(e, 0, 2), "endgid": le(e, 2, 2),
            "r4krt": le(e, 8, 4), "ows": le(e, 12, 4),
            "tnvmsc": le(e, 16, 8)}


def cfg_bytes(enev):
    """The 512 B of Figure 423 with ENEV and zero thresholds."""
    return struct.pack("<H", enev) + bytes(510)


# ---- device checks --------------------------------------------------------

def blk_name(dev):
    return os.path.basename(os.path.realpath(dev))


def ctrl_check(ctrl):
    """CTRL is a FEMU controller node."""
    name = os.path.basename(ctrl)
    try:
        with open("/sys/class/nvme/%s/model" % name) as f:
            model = f.read().strip()
    except OSError:
        raise SetupError("no-model-" + name)
    if not model.startswith("FEMU"):
        raise SetupError("ctrl-%s-not-femu" % name)
    return name


def dev_check(dev):
    """DEV is a whole disk that nothing mounts, swaps on or holds."""
    name = blk_name(dev)
    sysb = "/sys/block/" + name
    if not os.path.isdir(sysb):
        raise SetupError("not-a-disk-" + name)
    if os.listdir(sysb + "/holders"):
        raise SetupError("has-holders")
    path = "/dev/" + name
    for tab in ("/proc/mounts", "/proc/swaps"):
        with open(tab) as f:
            for line in f:
                if line.split()[:1] and line.split()[0].startswith(path):
                    raise SetupError("in-use-" + tab)
    return name


def dev_bytes(dev):
    with open("/sys/block/%s/size" % blk_name(dev)) as f:
        return int(f.read()) * 512


def lbs(dev):
    with open("/sys/block/%s/queue/logical_block_size" % blk_name(dev)) as f:
        return int(f.read())


NVME_WARN = re.compile(r"nvme.*(timeout|reset|I/O error|abort|failed|"
                       r"error|warn)", re.IGNORECASE)


def nvme_warnings():
    rc, out = run(["dmesg"], 60, check=False)
    return sum(1 for l in out.splitlines() if NVME_WARN.search(l)) \
        if rc == 0 else -1


def read_one(dev):
    """One 4 KiB O_DIRECT read at LBA 0: the namespace still answers."""
    fd = os.open(dev, os.O_RDONLY | os.O_DIRECT)
    m = mmap.mmap(-1, 4096)
    try:
        return "ok" if os.preadv(fd, [m], 0) == 4096 else "short"
    except OSError as e:
        return "errno-%d" % e.errno
    finally:
        m.close()
        os.close(fd)


def write_units(fd, off, unit, count):
    """COUNT writes of UNIT bytes from OFF with O_DIRECT; the next offset."""
    m = mmap.mmap(-1, unit)
    m.write(b"\xa5" * unit)
    try:
        for _ in range(count):
            if os.pwritev(fd, [m], off) != unit:
                raise StepError("short-write-at-%d" % off)
            off += unit
    finally:
        m.close()
    return off


# ---- gplm1 ----------------------------------------------------------------

def need_ok(name, res):
    ok, dw0, data, sc = res
    if not ok:
        print("FG_RAW %s status=%#x dw0=%#x" % (name, sc, dw0 or 0))
        if data:
            raw(name, data)
        raise StepError("%s-sc-%#x" % (name, sc))
    return dw0, data


def refused(name, res):
    """A command that must fail: its status code, as a fact."""
    ok, _, _, sc = res
    fact(**{name: "accepted" if ok else "sc-%#x" % sc})


def log0a_fact(adm, tag, rae):
    _, d = need_ok(tag, adm.get_log(LID_SET, 512, lsi=1, rae=rae))
    v = parse_log0a(d)
    fact(**{tag + "_plmw": v["plmw"], tag + "_etyp": "%#x" % v["etyp"],
            tag + "_dtwwt": v["dtwwt"], tag + "_dtwwe": v["dtwwe"],
            tag + "_dtwtm": v["dtwtm"], tag + "_dtwre": v["dtwre"]})
    return v


def log0b_nument(adm, tag, rae):
    _, d = need_ok(tag, adm.get_log(LID_AGG, 512, rae=rae))
    n = le(d, 0, 8)
    e1 = le(d, 8, 2)
    fact(**{tag + "_nument": n, tag + "_entry": e1,
            tag + "_tail_zero": int(not any(d[10:]))})
    return n


def cmd_gplm1(a):
    adm = Admin(a.ctrl)
    warn0 = nvme_warnings()
    rc, out = run(["nvme", "version"], 30, check=False)
    fact(nvme_version=(out.split()[2] if rc == 0 and len(out.split()) > 2
                       else "-"))

    _, d = need_ok("id_ctrl", adm.identify(1))
    fact(ctratt="%#x" % le(d, 96, 4), oaes="%#x" % le(d, 92, 4),
         nsetidmax=le(d, 338, 2))
    _, d = need_ok("id_set0", adm.identify(4, cdw11=0))
    s = parse_set_list(d)
    fact(set_numid=s["numid"], set_nsetid=s["nsetid"],
         set_endgid=s["endgid"], set_r4krt=s["r4krt"], set_ows=s["ows"],
         set_tnvmsc=s["tnvmsc"])
    _, d2 = need_ok("id_set2", adm.identify(4, cdw11=2))
    fact(set2_numid=d2[0])
    _, d = need_ok("id_ns", adm.identify(0, nsid=1))
    fact(ns_nvmsetid=le(d, 100, 2))
    # the named nvme-cli commands of the guide: exit status only
    for k, args in (("cli_id_nvmset", ["id-nvmset", a.ctrl]),
                    ("cli_pl_log", ["predictable-lat-log", a.ctrl]),
                    ("cli_pl_agg", ["pred-lat-event-agg-log", a.ctrl,
                                    "--rae"])):
        fact(**{k: int(cli_exit(k, args) == 0)})

    dw0, d = need_ok("get13", adm.get_feat(FID_CFG, length=512))
    fact(get13_lpe=dw0, get13_zero=int(len(d) == 512 and not any(d)))
    refused("get14_off", adm.get_feat(FID_WIN))
    refused("get13_nsid1", adm.get_feat(FID_CFG, nsid=1, length=512))
    refused("get13_set0", adm.get_feat(FID_CFG, cdw11=0, length=512))

    need_ok("set13_on", adm.set_feat(FID_CFG, 1, data=cfg_bytes(MVEAT |
                                                                DEAT)))
    dw0, _ = need_ok("get14_nd", adm.get_feat(FID_WIN))
    fact(get14_nd=dw0)
    # the guide's get-log; RAE keeps the events, the value is recorded
    fact(cli_log0a=cli_log0a(a.ctrl))
    refused("set14_wsel0", adm.set_feat(FID_WIN, 0))
    refused("log0a_lsi2", adm.get_log(LID_SET, 512, lsi=2))
    t0 = time.monotonic()
    need_ok("set14_dt", adm.set_feat(FID_WIN, PLMW_DT, limit=120))
    fact(set14_dt_ms=int((time.monotonic() - t0) * 1000))
    dw0, _ = need_ok("get14_dt", adm.get_feat(FID_WIN))
    fact(get14_dt=dw0)
    ent = log0a_fact(adm, "dt_entry", True)

    # DTWWT units of writes: the DTWIN stays; one more ends it (MVEAT)
    unit = s["ows"] or a.unit_bytes
    want = ent["dtwwt"]
    if want <= 0 or (want + 1) * unit > dev_bytes(a.dev):
        raise StepError("dtwwt-%d-units-of-%d-do-not-fit" % (want, unit))
    fact(mv_unit=unit, mv_ows_reported=int(s["ows"] > 0), mv_units=want)
    fd = os.open(a.dev, os.O_WRONLY | os.O_DIRECT)
    try:
        off = write_units(fd, 0, unit, want)
        time.sleep(0.2)
        log0a_fact(adm, "mv_at", True)
        write_units(fd, off, unit, 1)
    finally:
        os.close(fd)
    # the exit follows the completion of the request that passed DTWWT
    for _ in range(20):
        time.sleep(0.1)
        if log0a_fact(adm, "mv_after", True)["plmw"] != PLMW_DT:
            break

    log0b_nument(adm, "agg_rae", True)
    log0a_fact(adm, "read1", False)
    log0a_fact(adm, "read2", False)
    log0b_nument(adm, "agg_after", False)

    need_ok("set13_off", adm.set_feat(FID_CFG, 0, data=cfg_bytes(0)))
    log0a_fact(adm, "off", True)
    refused("get14_lpe0", adm.get_feat(FID_WIN))
    fact(ns_read=read_one(a.dev))
    warn1 = nvme_warnings()
    fact(nvme_warn_new=(warn1 - warn0 if warn0 >= 0 and warn1 >= 0
                        else -1))


# ---- precond --------------------------------------------------------------

FIO_COMMON = ["--direct=1", "--ioengine=libaio", "--group_reporting",
              "--output-format=terse", "--terse-version=3"]


def cmd_precond(a):
    size = dev_bytes(a.dev)
    t0 = time.monotonic()
    run(["fio", "--name=seq", "--filename=" + a.dev, "--rw=write",
         "--bs=128k", "--iodepth=32", "--size=100%"] + FIO_COMMON,
        a.limit)
    t1 = time.monotonic()
    run(["fio", "--name=rand", "--filename=" + a.dev, "--rw=randwrite",
         "--bs=4k", "--iodepth=32", "--norandommap", "--randrepeat=0",
         "--size=100%", "--io_size=%d" % (a.passes * size)] + FIO_COMMON,
        a.limit)
    t2 = time.monotonic()
    fact(precond_bytes=size, precond_passes=a.passes,
         precond_seq_s=int(t1 - t0), precond_rand_s=int(t2 - t1),
         precond_rand_iops=int(a.passes * size / 4096 / max(t2 - t1, 1e-3)))


# ---- tail -----------------------------------------------------------------

def pct(sorted_vals, q):
    """Nearest-rank percentile of a sorted list, or -1 when empty."""
    if not sorted_vals:
        return -1
    k = max(1, math.ceil(q * len(sorted_vals)))
    return sorted_vals[min(k, len(sorted_vals)) - 1]


def read_lat_log(path):
    """(submit_ms, lat_us) of each read in an fio latency log written
    with log_unix_epoch=1: "time_ms, lat_ns, ddir, bs, offset[, prio]"."""
    out = []
    with open(path) as f:
        for line in f:
            p = line.split(",")
            if len(p) < 3 or p[2].strip() != "0":
                continue
            t_ms = int(p[0])
            lat_ns = int(p[1])
            out.append((t_ms - lat_ns / 1e6, lat_ns / 1e3))
    return out


def spans(cycles, guard_ms):
    """The DTWIN and NDWIN spans (ms) whose reads count. Only valid
    cycles count. A DTWIN runs up to its end or the last poll before an
    exit. An NDWIN runs from its start to the next Set 14h DTWIN."""
    dt, nd = [], []
    for c in cycles:
        if not c["valid"]:
            continue
        lo, hi = c["dt0"] + guard_ms, c["dt_end"] - guard_ms
        if hi > lo:
            dt.append((lo, hi))
        lo, hi = c["nd0"] + guard_ms, c["req"] - guard_ms
        if hi > lo:
            nd.append((lo, hi))
    return dt, nd


def judge_cycle(c, planned, phantom):
    """Set reach and valid of a cycle record. The target is reachable
    when the DTWIN started with DTWWE >= the planned writes; a valid
    cycle also has no DEAT. A phantom cycle is always valid."""
    c["planned"] = planned
    c["reach"] = int(phantom or (c["entry_plmw"] == PLMW_DT and
                                 c["dtwwe"] >= planned))
    c["valid"] = int(c["reach"] and not c["deat"])
    return c


def cycle_totals(cycles):
    """The cycle counts of the tail summary."""
    return {"cycles": len(cycles), "valid": sum(c["valid"] for c in cycles),
            "reach": sum(c["reach"] for c in cycles),
            "mveat": sum(c["mveat"] for c in cycles),
            "deat": sum(c["deat"] for c in cycles),
            "deat_reach": sum(c["deat"] and c["reach"] for c in cycles),
            "exits": sum(c["exit"] for c in cycles)}


def split(reads, dt, nd):
    """The read latencies inside the DTWIN spans and the NDWIN spans."""
    def inside(s, sp):
        # spans are few (one per cycle); a scan is fast enough
        return any(lo <= s <= hi for lo, hi in sp)
    a = sorted(l for s, l in reads if inside(s, dt))
    b = sorted(l for s, l in reads if inside(s, nd))
    return a, b


def summary(tag, vals):
    return {tag + "_n": len(vals),
            tag + "_p50_us": "%.1f" % pct(vals, 0.50),
            tag + "_p99_us": "%.1f" % pct(vals, 0.99),
            tag + "_p999_us": "%.1f" % pct(vals, 0.999),
            tag + "_max_us": "%.1f" % (vals[-1] if vals else -1)}


def now_ms():
    return time.time() * 1000.0


def one_cycle(io, i, a, planned):
    """One NDWIN and one DTWIN; returns the cycle record."""
    c = {"i": i, "nd0": now_ms(), "entry_plmw": -1, "dtwwe": -1,
         "mveat": 0, "deat": 0, "exit": 0, "hold_ms": 0}
    time.sleep(a.ndwin_ms / 1000.0)
    c["req"] = now_ms()
    if not a.phantom:
        st = io.window(PLMW_DT)
        if st:
            raise StepError("set14-dtwin-status-%#x" % st)
    c["dt0"] = now_ms()
    c["hold_ms"] = int(c["dt0"] - c["req"])
    end = c["dt0"] + a.dtwin_ms
    c["dt_end"] = end
    if not a.phantom:
        v = io.log0a(True)
        c["entry_plmw"], c["dtwwe"] = v["plmw"], v["dtwwe"]
        last = now_ms()
        while now_ms() < end:
            time.sleep(min(0.1, max(0.0, (end - now_ms()) / 1000.0)))
            v = io.log0a(True)
            if v["plmw"] != PLMW_DT:
                c["exit"] = 1
                c["dt_end"] = last
                break
            last = now_ms()
        if not c["exit"]:
            c["dt_end"] = now_ms()
            st = io.window(PLMW_ND)
            if st:
                raise StepError("set14-ndwin-status-%#x" % st)
        v = io.log0a(False)
        c["mveat"] = int(bool(v["etyp"] & MVEAT))
        c["deat"] = int(bool(v["etyp"] & DEAT))
    else:
        time.sleep(max(0.0, (end - now_ms()) / 1000.0))
        c["dt_end"] = now_ms()
    return judge_cycle(c, planned, a.phantom)


def cmd_tail(a):
    os.makedirs(a.out, exist_ok=True)
    for f in glob.glob(os.path.join(a.out, "rd_lat*.log")):
        os.unlink(f)
    io = None if a.phantom else Ioctl(a.ctrl)
    unit = a.unit_bytes
    if io:
        st, _, d = io.call(OPC_IDENTIFY, 4, 0, length=4096)
        if st:
            raise StepError("cns-04h-status-%#x" % st)
        unit = parse_set_list(d)["ows"] or a.unit_bytes
        st, _, _ = io.call(OPC_SET_FEAT, FID_CFG, 1, 1,
                           data=cfg_bytes(a.enev))
        if st:
            raise StepError("set13-status-%#x" % st)
        st, dw0, _ = io.call(OPC_GET_FEAT, FID_WIN, 1)
        if st or dw0 != PLMW_ND:
            raise StepError("not-ndwin-after-lpe1")
        io.log0a(False)
    wbytes = a.wrate_mib << 20
    planned = math.ceil(wbytes * a.dtwin_ms / 1000.0 / unit)
    warm = 3.0
    runtime = int(warm + a.cycles * (a.dtwin_ms + a.ndwin_ms) / 1000.0
                  + 10)
    pfx = os.path.join(a.out, "rd")
    fio = ["fio", "--filename=" + a.dev, "--direct=1", "--ioengine=libaio",
           "--time_based", "--runtime=%d" % runtime, "--log_unix_epoch=1",
           "--output-format=terse", "--terse-version=3",
           "--name=rd", "--rw=randread", "--bs=4k", "--iodepth=1",
           "--rate_iops=%d" % a.riops, "--rate_process=poisson",
           "--randrepeat=0", "--write_lat_log=" + pfx, "--log_avg_msec=0",
           "--name=wr", "--rw=randwrite", "--bs=4k", "--iodepth=8",
           "--rate=%dk" % (wbytes >> 10), "--norandommap",
           "--randrepeat=0"]
    p = subprocess.Popen(fio, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    cycles = []
    try:
        time.sleep(warm)
        if p.poll() is not None:
            raise StepError("fio-ended-rc%d" % p.returncode)
        for i in range(a.cycles):
            c = one_cycle(io, i, a, planned)
            cycles.append(c)
            print("FGC " + " ".join("%s=%s" % (k, int(v))
                                    for k, v in c.items()), flush=True)
        out, _ = p.communicate(timeout=runtime + 120)
    except BaseException:
        p.kill()
        p.communicate()
        if io and not a.phantom:
            io.window(PLMW_ND)
        raise
    if p.returncode != 0:
        tail = out.decode(errors="replace").strip().splitlines()[-1:]
        raise StepError("fio-rc%d %s" % (p.returncode,
                                         (tail or [""])[0][:80]))
    if io:
        io.call(OPC_SET_FEAT, FID_CFG, 1, 0, data=cfg_bytes(0))
    logs = sorted(glob.glob(pfx + "_lat*.log"))
    if not logs:
        raise StepError("no-latency-log")
    reads = []
    for f in logs:
        reads += read_lat_log(f)
    dt, nd = spans(cycles, a.guard_ms)
    dtv, ndv = split(reads, dt, nd)
    allv = sorted(l for _, l in reads)
    res = {"tail_mode": "phantom" if a.phantom else "plm"}
    res.update(cycle_totals(cycles))
    res.update({"planned": planned, "unit": unit,
                "hold_ms_max": max([c["hold_ms"] for c in cycles] or [0]),
                "reads": len(reads)})
    res.update(summary("dt", dtv))
    res.update(summary("nd", ndv))
    res.update(summary("all", allv))
    fact(**res)


# ---- check, dmesg ---------------------------------------------------------

def nvme_major():
    rc, out = run(["nvme", "version"], 30, check=False)
    m = re.search(r"version\s+(\d+)", out)
    return int(m.group(1)) if rc == 0 and m else -1


def cmd_check(a):
    name = ctrl_check(a.ctrl)
    dev = dev_check(a.dev)
    miss = [t for t in ("nvme", "fio", "dmesg") if shutil.which(t) is None]
    fact(kernel=os.uname().release, ctrl=name, dev=dev, lbs=lbs(a.dev),
         dev_bytes=dev_bytes(a.dev), nvme_major=(nvme_major() if
                                                  "nvme" not in miss
                                                  else -1),
         missing=",".join(miss) or "-")
    for t in filter(None, a.need.split(",")):
        if shutil.which(t) is None:
            raise SetupError("no-tool-" + t)
    if "nvme" in a.need.split(",") and nvme_major() < 2:
        raise SetupError("nvme-cli-before-2.0")


def cmd_dmesg(_a):
    _, out = run(["dmesg"], 60)
    for line in out.splitlines():
        print("FGK " + line)


# ---- self-test ------------------------------------------------------------

def self_test():
    ok = 0
    bad = []

    def want(got, exp, label):
        nonlocal ok
        if got == exp:
            ok += 1
            print("ok %s" % label)
        else:
            bad.append(label)
            print("FAIL %s: want %r, got %r" % (label, exp, got))

    # nvme-cli 2.x hex dump: header row, offsets, an ascii column
    dump = ("Device:nvme0 log_id:0x0a namespace_id:0xffffffff\n"
            "       0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f\n"
            '0000: 01 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 '
            '"...@............"\n'
            '0010: 41 42 43 20 31 32 00 00 00 00 00 00 00 00 00 ff '
            '"ABC 12.........."\n')
    d = hexdump(dump)
    want(len(d), 32, "hexdump 2.x length")
    want((d[0], le(d, 2, 2), d[31]), (1, 0x4000, 0xff), "hexdump 2.x bytes")
    want(hexdump("no dump here\n"), b"", "hexdump none")
    try:
        hexdump("0000: 01 02\n0020: 03\n")
        want("no error", "error", "hexdump gap")
    except ValueError:
        want(1, 1, "hexdump gap")
    # nvme-cli 3.x: "*" for lines that repeat the line before. The d760
    # run failed on this shape: 8 lines, "*", then offset 0100.
    z = " ".join(["00"] * 16)

    def line(off, b):
        return "%04x: %s \"................\"\n" % (off, b)
    d3 = ("          0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f\n" +
          line(0, "02 " + " ".join(["00"] * 15)) +
          "".join(line(o, z) for o in range(0x10, 0x80, 0x10)) + "*\n" +
          line(0x100, "1f " + " ".join(["00"] * 15)) +
          line(0x110, z) + "*\n")
    try:
        hexdump(d3)
        want("no error", "error", "hexdump 3.x repeat at the end, no length")
    except ValueError:
        want(1, 1, "hexdump 3.x repeat at the end, no length")
    d = hexdump(d3, 512)
    want((len(d), d[0], d[0x100], any(d[1:0x100]), any(d[0x101:])),
         (512, 2, 0x1f, False, False), "hexdump 3.x repeat lines")
    d = hexdump(d3 + "0200\n")
    want(len(d), 512, "hexdump 3.x last offset ends the repeat")
    d = hexdump("0000: 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10\n"
                "*\n0x0030: ab |.|\n")
    want((len(d), d[16], d[47], d[48]), (49, 1, 16, 0xab),
         "hexdump 3.x repeat of a non-zero line, 0x offset, bar column")
    try:
        hexdump("0000: " + z + "\n*\n0018: 00\n")
        want("no error", "error", "hexdump repeat to a mid-line offset")
    except ValueError:
        want(1, 1, "hexdump repeat to a mid-line offset")
    # the ioctl decode
    want(struct.calcsize(CMD_FMT), 72, "passthru struct size")
    cmd = pack_cmd(OPC_GET_LOG, 0, 0x1000, 512, 0x7f000a, 1 << 16)
    want((cmd[0], le(cmd, 24, 8), le(cmd, 36, 4), le(cmd, 40, 4),
          le(cmd, 44, 4)), (2, 0x1000, 512, 0x7f000a, 0x10000),
         "passthru field offsets")
    cmd[68:72] = (0xdeadbeef).to_bytes(4, "little")
    u = unpack_cmd(cmd)
    want((u["opcode"], u["addr"], u["data_len"], u["cdw10"], u["cdw11"],
          u["result"]), (2, 0x1000, 512, 0x7f000a, 0x10000, 0xdeadbeef),
         "passthru decode with the result dword")
    want(NVME_IOCTL_ADMIN_CMD, (3 << 30) | (72 << 16) | (ord("N") << 8)
         | 0x41, "ioctl number")
    want((status_sc(0x4002), status_sc(0x0106), status_sc(0x2002)),
         (0x002, 0x106, 0x002), "status: SCT and SC, DNR and M dropped")
    want(get_log_dw(LID_SET, 512, 1, True), (0x7f800a, 0x10000),
         "log 0Ah dwords, LSI 1, RAE")
    want(get_log_dw(LID_AGG, 512), (0x7f000b, 0), "log 0Bh dwords")
    want(get_log_dw(LID_AGG, 1 << 20), (0xffff000b, 3),
         "log dwords with NUMDU")

    class FakeIo:
        def __init__(self, st):
            self.st, self.seen = st, []

        def call(self, opc, cdw10, cdw11=0, cdw12=0, nsid=0, data=None,
                 length=0, timeout_ms=0):
            self.seen.append((opc, cdw10, cdw11, cdw12, nsid,
                              None if data is None else len(data), length,
                              timeout_ms))
            return self.st, 7, bytes(length)

    adm = Admin.__new__(Admin)
    adm.io = FakeIo(0)
    r = adm.identify(4, cdw11=2)
    want((r[0], r[1], len(r[2]), r[3], adm.io.seen[-1]),
         (True, 7, 4096, None, (OPC_IDENTIFY, 4, 2, 0, 0, None, 4096, 0)),
         "admin identify CNS 04h, NVMSETID 2")
    adm.set_feat(FID_WIN, PLMW_DT, limit=120)
    want(adm.io.seen[-1], (OPC_SET_FEAT, FID_WIN, 1, 1, 0, None, 0, 120000),
         "admin Set 14h DTWIN")
    adm.set_feat(FID_CFG, 1, data=cfg_bytes(MVEAT))
    want(adm.io.seen[-1][:6], (OPC_SET_FEAT, FID_CFG, 1, 1, 0, 512),
         "admin Set 13h with its 512 bytes")
    adm.get_log(LID_SET, 512, lsi=2)
    want(adm.io.seen[-1][:3], (OPC_GET_LOG, 0x7f000a, 0x20000),
         "admin log 0Ah LSI 2")
    adm.io = FakeIo(0x4002)
    want(adm.get_feat(FID_WIN)[0::3], (False, 0x002),
         "admin refusal gives SCT and SC")
    buf = StringIO()
    with contextlib.redirect_stdout(buf):
        raw("t", bytes(range(256)) * 20)
        raw("u", "line one\nline two\n")
    out = buf.getvalue().splitlines()
    want((out[0], len([l for l in out if l.startswith("FG_RAW t +")]),
          out[1][:15], out[-1]),
         ("FG_RAW t bytes=5120 shown=4096", 128, "FG_RAW t +0000 ",
          "FG_RAW u | line two"), "raw output is bounded")
    try:
        with contextlib.redirect_stdout(StringIO()):
            need_ok("x", (False, 0, b"\x01", 0x2))
        want("no error", "error", "a failed command raises")
    except StepError as e:
        want(str(e), "x-sc-0x2", "a failed command raises")
    log = bytearray(512)
    log[0] = 1
    log[2:4] = (MVEAT | DEAT).to_bytes(2, "little")
    log[40:48] = (64).to_bytes(8, "little")
    log[136:144] = (63).to_bytes(8, "little")
    v = parse_log0a(bytes(log))
    want((v["plmw"], v["etyp"], v["dtwwt"], v["dtwwe"]),
         (1, MVEAT | DEAT, 64, 63), "log 0Ah fields")
    sl = bytearray(4096)
    sl[0] = 1
    sl[128:130] = (1).to_bytes(2, "little")
    sl[130:132] = (1).to_bytes(2, "little")
    sl[136:140] = (5).to_bytes(4, "little")
    sl[140:144] = (131072).to_bytes(4, "little")
    s = parse_set_list(bytes(sl))
    want((s["numid"], s["nsetid"], s["endgid"], s["r4krt"], s["ows"]),
         (1, 1, 1, 5, 131072), "set list entry")
    c = cfg_bytes(MVEAT)
    want((len(c), c[0], c[1], any(c[2:])), (512, 0, 0x40, False),
         "config structure")
    vals = sorted(float(x) for x in range(1, 1001))
    want((pct(vals, 0.5), pct(vals, 0.99), pct(vals, 0.999)),
         (500.0, 990.0, 999.0), "nearest rank")
    want(pct([], 0.99), -1, "percentile of nothing")
    sm = summary("nd", [45.0, 46.0, 2200000.0])
    want((sm["nd_n"], sm["nd_p50_us"], sm["nd_max_us"]),
         (3, "46.0", "2200000.0"), "summary of a few reads, with the max")
    cyc = [{"valid": 1, "nd0": 0, "req": 1000, "dt0": 1010, "dt_end": 2000},
           {"valid": 0, "nd0": 2000, "req": 3000, "dt0": 3000,
            "dt_end": 4000}]
    dt, nd = spans(cyc, 20)
    want(dt, [(1030, 1980)], "spans: DTWIN of a valid cycle only")
    want(nd, [(20, 980)], "spans: NDWIN of a valid cycle only")
    reads = [(500, 10.0), (1500, 1.0), (990, 99.0), (3500, 50.0),
             (2500, 20.0), (1005, 7.0)]
    a, b = split(reads, dt, nd)
    want((a, b), ([1.0], [10.0]), "split by submit time")
    # each plant breaks one condition of a valid cycle
    good = {"entry_plmw": PLMW_DT, "dtwwe": 64, "deat": 0}
    plants = [("good", {}, (1, 1)),
              ("DTWWE equal to the plan", {"dtwwe": 8}, (1, 1)),
              ("entry not DTWIN", {"entry_plmw": PLMW_ND}, (0, 0)),
              ("DTWWE below the plan", {"dtwwe": 7}, (0, 0)),
              ("DEAT exit", {"deat": 1}, (1, 0))]
    for label, kv, exp in plants:
        c = judge_cycle(dict(good, **kv), 8, False)
        want((c["reach"], c["valid"]), exp, "cycle " + label)
    c = judge_cycle(dict(good, entry_plmw=-1, dtwwe=-1), 8, True)
    want((c["reach"], c["valid"]), (1, 1), "cycle phantom")
    t = cycle_totals([dict(judge_cycle(dict(good, **kv), 8, False),
                           mveat=0, exit=kv.get("deat", 0))
                      for _, kv, _ in plants])
    want((t["cycles"], t["valid"], t["reach"], t["deat"], t["deat_reach"],
          t["exits"]), (5, 2, 3, 1, 1, 1), "cycle totals")
    t = cycle_totals([dict(judge_cycle(dict(good, entry_plmw=PLMW_ND,
                                            deat=1), 8, False),
                           mveat=0, exit=1)])
    want((t["deat"], t["deat_reach"]), (1, 0), "DEAT of an unreachable "
         "target")
    with tempfile.NamedTemporaryFile("w", suffix=".log") as f:
        f.write("1700000000500, 2000000, 0, 4096, 0, 0\n"
                "1700000000600, 3000, 1, 4096, 8192\n"
                "1700000000700, 90000, 0, 4096, 4096\n")
        f.flush()
        r = read_lat_log(f.name)
    want([(round(t, 2), l) for t, l in r],
         [(1700000000498.0, 2000.0), (1700000000699.91, 90.0)],
         "fio latency log, reads only")
    print("plm-guest self-test: %s (%d ok, %d failed)" %
          ("PASS" if not bad else "FAIL", ok, len(bad)))
    return 0 if not bad else 1


CMDS = {"check": cmd_check, "gplm1": cmd_gplm1, "precond": cmd_precond,
        "tail": cmd_tail, "dmesg": cmd_dmesg}


def parse(argv):
    p = argparse.ArgumentParser(prog="plm-guest.py")
    p.add_argument("cmd", choices=sorted(CMDS))
    p.add_argument("--ctrl", default="/dev/nvme0")
    p.add_argument("--dev", default="/dev/nvme0n1")
    p.add_argument("--need", default="")
    p.add_argument("--passes", type=int, default=2)
    p.add_argument("--limit", type=int, default=7200)
    p.add_argument("--cycles", type=int, default=60)
    p.add_argument("--dtwin-ms", type=int, default=1000)
    p.add_argument("--ndwin-ms", type=int, default=1000)
    p.add_argument("--wrate-mib", type=int, default=32)
    p.add_argument("--riops", type=int, default=2000)
    p.add_argument("--unit-bytes", type=int, default=4096)
    p.add_argument("--guard-ms", type=int, default=20)
    p.add_argument("--enev", type=lambda x: int(x, 0), default=0)
    p.add_argument("--phantom", action="store_true")
    p.add_argument("--out", default="/tmp/plm")
    a = p.parse_args(argv)
    if min(a.passes, a.cycles, a.dtwin_ms, a.ndwin_ms, a.wrate_mib,
           a.riops, a.unit_bytes, a.limit) < 1 or a.guard_ms < 0:
        p.error("a count or time below its minimum")
    if a.unit_bytes % 512:
        p.error("--unit-bytes must be a multiple of 512")
    return a


def main(argv):
    if argv == ["--self-test"]:
        return self_test()
    a = parse(argv)
    try:
        if os.geteuid() != 0:
            raise SetupError("not-root")
        if a.cmd != "dmesg":
            ctrl_check(a.ctrl)
            dev_check(a.dev)
        CMDS[a.cmd](a)
    except SetupError as e:
        print("FG_DONE fail setup-%s" % e, flush=True)
        return 2
    except (StepError, OSError) as e:
        print("FG_DONE fail %s" % str(e).replace("\n", " ")[:160],
              flush=True)
        return 1
    print("FG_DONE ok", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
