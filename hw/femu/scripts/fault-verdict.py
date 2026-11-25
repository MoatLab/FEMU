#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Verdicts of the events_file guest tests G1 to G4 (host side).

  fault-verdict.py TEST [--control a|b|fs] [--lies] --guest FILE
                   [--log FILE] [--dmesg FILE] [--host FILE]
                   [--lba L] [--bound S] [--runtime S]
  fault-verdict.py --self-test

TEST is g1, g2, g2e, g3, g4a or g4b. The inputs:

  --guest  the output of fault-guest.py: "FG key=value ..." lines and
           "FGL" checker lines
  --log    the events_log file: one JSON fault record per line. The
           ids must run from 1 to the largest id with no gap; a gap is
           a dropped record, and the evidence is then incomplete
  --dmesg  guest kernel messages; a leading "FGK " is dropped
  --host   "key=value" lines of the host driver: qemu_alive (0 or 1),
           cut (ok or fail), start_step, pre_fio_hang

Output: one line "VERDICT TEST[-control] STATUS reason". STATUS is PASS,
FAIL, INVALID (the run did not test what it must), INCOMPLETE (the
evidence is not complete: run again), BLOCKED (this FEMU build lacks a
feature the test needs), SETUP-ERROR (the guest could not make or mount
the file system) or RECORDED (a result that is kept, not judged).
Exit status: 0 for PASS or RECORDED, 1 for FAIL, 3 for the rest, 2 for
a usage error. A QEMU that ended during a run makes it INVALID.

A control passes when the assertion that it targets fails, and the run
shows positive evidence that it ran as planned. Each rule:

  g1    record M lost after the cut, and the cut evidence names its LBAs;
        a cut that rolled back no lie page makes the run INVALID; the
        file lost M while a raw read of its LBAs finds M: lost through
        metadata (the lie rolled back the inode size or the journal)
  g1 a  no lie line: a confirmed cut and reboot, and record M is there
  g2    fsync(bdev) gives ENODATA, L reads A0, one report record,
        found=self, whose cause is the fail record of the page of L
  g2 a  no wb-fail line: the first fsync gives 0
  g2 b  max_retries=5: a fail record exists, and the first fsync gives 0
  g2e   ext4 fdatasync after an in-place overwrite: RECORDED
  g3    a cut summary in the fsstress window with kept and rolled-back
        pages; then mount, umount and the checker are clean
  g3 fs a cleared root inode: the checker exits with its error code
        (e2fsck 4, or 12 when it aborts; xfs_repair 1) and names the
        root inode
  g4a   dmesg has the timeout of the hung SQID and CID, then a reset;
        fio ends in the bound; the next I/O works; no command stays hung
  g4a a no hang line: dmesg has nvme lines but no timeout; fio ran its
        whole time with exit 0
  g4a b reclaim mutated away: a hang took effect, and the records show
        a command that stays hung
  g4b   dmesg has a CSTS value with CFS set; FEMU then reclaims the
        parked command at the reset; fio ends; the next I/O works
  g4b a the CSTS write mutated away: a cfs took effect, dmesg has nvme
        lines, and no CSTS value has CFS set
"""
import json
import os
import re
import sys
import tempfile

PASS, FAIL, INVALID, INCOMPLETE, BLOCKED, RECORDED, SETUP = (
    "PASS", "FAIL", "INVALID", "INCOMPLETE", "BLOCKED", "RECORDED",
    "SETUP-ERROR")
EXIT = {PASS: 0, RECORDED: 0, FAIL: 1}

TIMEOUT_RE = re.compile(r"I/O (?:tag )?(\d+) (?:\(([0-9a-f]{4})\) )?"
                        r".*?QID (\d+) timeout")
RESET_RE = re.compile(r"reset controller|resetting controller|will reset",
                      re.I)
CSTS_RE = re.compile(r"CSTS=0x([0-9a-fA-F]+)")
NVME_RE = re.compile(r"\bnvme\d*\b")
NVME_CSTS_CFS = 0x2
# the exit codes of the checkers when they find an error and fix nothing:
# e2fsck -n sets bit 4 (FSCK_UNCORRECTED), plus bit 8 when it aborts
FSCK_RC = {"ext4": ("4", "12"), "xfs": ("1",)}


def facts(path):
    """The FG facts of a guest output (a later key wins) and FGL lines."""
    out = {"_fgl": []}
    if not path or not os.path.exists(path):
        return out
    with open(path, errors="replace") as f:
        for line in f:
            if line.startswith("FG_DONE "):
                out["_done"] = line.split(None, 1)[1].strip()
            if line.startswith("FGL "):
                out["_fgl"].append(line[4:].rstrip("\n"))
            if not line.startswith("FG "):
                continue
            for tok in line.split()[1:]:
                if "=" in tok:
                    k, v = tok.split("=", 1)
                    out[k] = v
    return out


def host_facts(path):
    out = {}
    if path and os.path.exists(path):
        with open(path) as f:
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    out[k] = v
    return out


def norm(rec):
    return {k.replace("-", "_"): v for k, v in rec.items()}


def records(log):
    """Records in id order, whether ids 1 to the largest have no gap, and
    the first id that repeats (0 if none).

    The device adds to an existing events_log, and a new run starts its ids
    at 1 again. A repeated id means the log holds an older run, whose
    records could then satisfy a check of this run."""
    recs = {}
    again = 0
    if log and os.path.exists(log):
        with open(log) as f:
            for line in f:
                line = line.strip()
                if line:
                    r = norm(json.loads(line))
                    if r["id"] in recs and not again:
                        again = r["id"]
                    recs[r["id"]] = r
    complete = all(i in recs for i in range(1, max(recs, default=0) + 1))
    return [recs[k] for k in sorted(recs)], complete, again


def find(recs, **want):
    return [r for r in recs if all(r.get(k) == v for k, v in want.items())]


def lba_ranges(text):
    out = []
    for part in (text or "").split(","):
        if "-" in part:
            a, b = part.split("-", 1)
            out.append((int(a), int(b)))
    return out


def dmesg_lines(path):
    if not path or not os.path.exists(path):
        return []
    with open(path, errors="replace") as f:
        return [ln[4:] if ln.startswith("FGK ") else ln for ln in f]


def cut_summary(recs):
    """The last cut summary record (section 7.2), or None."""
    cuts = [r for r in recs if r.get("action") == "power-loss" and
            "rolled_back_pages" in r]
    return cuts[-1] if cuts else None


def rolled_back(recs, cut):
    """(nsid, slba, nlb) ranges that the chunks of @cut roll back."""
    out = []
    for r in recs:
        if r.get("cause") != cut["id"] or "r" not in r:
            continue
        for item in r["r"]:
            # a chunk kind, or a kind per range
            kind = item[3] if len(item) > 3 else r.get("kind")
            if kind == "rolled_back":
                out.append(tuple(item[:3]))
    return out


def v_g1(a, g, h, recs, complete):
    if "g1_acked" not in g:
        return INVALID, "no acked line from the guest"
    rebooted = (g.get("boot_id") and g.get("g1_boot_id") and
                g["boot_id"] != g["g1_boot_id"])
    if h.get("cut") != "ok" and not find(recs, action="power-loss"):
        return INVALID, "no confirmed cut"
    if not rebooted:
        return INVALID, "no confirmed reboot after the cut"
    if g.get("g1_mount") != "ok":
        return INVALID, "the file system did not mount after the cut"
    if a.control == "a":
        if g.get("g1_m_present") == "1":
            return PASS, "no lie: cut and reboot, record M is there"
        return FAIL, "no lie, yet record M is missing or changed"
    present = g.get("g1_m_present") == "1"
    if not find(recs, action="flush-lie", phase="apply", outcome="done"):
        return INVALID, "no lying Flush took effect"
    # the cut record decides first: a drain can empty the buffer before it
    cut = cut_summary(recs)
    if cut is None:
        return INCOMPLETE, "record M %s, but no cut record names its LBAs" % (
            "survived" if present else "lost")
    mine = lba_ranges(g.get("lba"))
    listed = any(ns == 1 and s <= hi and s + n - 1 >= lo
                 for ns, s, n in rolled_back(recs, cut) for lo, hi in mine)
    chunks = [r for r in recs if r.get("cause") == cut["id"] and "r" in r]
    whole = (complete and not cut.get("truncated") and
             len(chunks) == cut.get("chunks", len(chunks)))
    if present and listed:
        return FAIL, "record M survived, yet the cut rolled back its LBAs"
    if cut.get("rolled_back_lie_pages", 1) == 0:
        return INVALID, "not vulnerable: nothing lied was buffered at the " \
            "cut (record M %s)" % ("there" if present else "missing")
    # the file lost M, yet its LBAs hold it: the lie rolled back the
    # inode size or the journal, not the data blocks
    if not present and g.get("g1_raw_m_present") == "1":
        if listed:
            return FAIL, "the cut rolled back the LBAs of record M, yet " \
                "a raw read finds M"
        return PASS, "lost through metadata: the data blocks survived, " \
            "the lie rolled back the file's metadata"
    if listed:
        return PASS, "lost: the cut rolled back the LBAs of record M"
    if not whole:
        return INCOMPLETE, "cut ranges truncated or a record is missing"
    return INVALID, "not vulnerable: the cut ranges miss record M"


def v_g2(a, g, h, recs, complete):
    if "g2_fsync1" not in g:
        return INVALID, "no fsync result from the guest"
    if a.control == "a":
        if g["g2_fsync1"] == "0":
            return PASS, "control a: the first fsync gives 0"
        return FAIL, "control a: the first fsync gives %s" % g["g2_fsync1"]
    fails = find(recs, action="wb-fail", phase="fail")
    if a.control == "b":
        if not fails:
            return INVALID, "control b: no write-back failed"
        if g["g2_fsync1"] == "0":
            return PASS, "control b: a write-back failed, the retry gives 0"
        return FAIL, "control b: the first fsync gives %s" % g["g2_fsync1"]
    why = []
    if g.get("g2_write") != "4096":
        why.append("write=%s" % g.get("g2_write"))
    if g["g2_fsync1"] != "ENODATA":
        why.append("fsync1=%s" % g["g2_fsync1"])
    if g.get("g2_read") != "A0":
        why.append("read=%s" % g.get("g2_read"))
    # a guest fact that fails the test needs no record
    if why:
        return FAIL, ", ".join(why)
    if not complete:
        return INCOMPLETE, "a record id is missing"
    reps = find(recs, action="wb-fail", phase="report")
    if len(reps) != 1:
        why.append("%d report records" % len(reps))
    else:
        rep = reps[0]
        if rep.get("found") != "self":
            why.append("found=%s" % rep.get("found"))
        mine = [r for r in fails if r["id"] == rep.get("cause")]
        if not mine or not (mine[0]["slba"] <= a.lba <
                            mine[0]["slba"] + mine[0]["nlb"]):
            why.append("the report cause is not the fail record of L")
    if why:
        return FAIL, ", ".join(why)
    return PASS, ("fsync ENODATA, L reads A0, one report found=self "
                  "(fsync2=%s)" % g.get("g2_fsync2"))


def v_g2e(a, g, h, recs, complete):
    if "g2e_fdatasync1" not in g:
        return INVALID, "no fdatasync result from the guest"
    return RECORDED, "fdatasync1=%s fdatasync2=%s read=%s reports=%d" % (
        g["g2e_fdatasync1"], g.get("g2e_fdatasync2"), g.get("g2e_read"),
        len(find(recs, action="wb-fail", phase="report")))


def v_g3_control(a, g):
    if "g3_corrupt" not in g:
        return INVALID, "the guest did not corrupt the file system"
    fs = g.get("fs", "")
    rc = g.get("g3_fsck_rc")
    ino = g.get("rootino", "2" if fs == "ext4" else "")
    names = [ln for ln in g["_fgl"]
             if re.search(r"[Rr]oot inode|[Rr]oot directory", ln) or
             (ino and re.search(r"\binode %s\b" % re.escape(ino), ln))]
    if rc in FSCK_RC.get(fs, ()) and names:
        return PASS, "the checker exits %s and names the root inode: %s" % (
            rc, names[0][:80])
    return FAIL, "the checker exits %s (want %s) and names the root inode " \
        "%d times" % (rc, " or ".join(FSCK_RC.get(fs, ("-",))), len(names))


def v_g3(a, g, h, recs, complete):
    # no file system to test: a cause outside FEMU, not a missed cut
    if "g3_mkfs" not in g:
        return SETUP, "g3-mkfs did not finish: %s" % g.get("_done", "-")
    if a.control == "fs":
        return v_g3_control(a, g)
    cut = cut_summary(recs)
    if cut is None:
        if find(recs, action="power-loss"):
            return BLOCKED, ("the power-loss line selected a command, but "
                             "this build writes no cut summary")
        return INVALID, "no cut took place"
    start = int(h.get("start_step", "-1"))
    if g.get("g3_stress_start") != "1" or "g3_stress_end" in g:
        return INVALID, "the cut was not in the fsstress phase"
    if start < 0 or cut.get("step", 0) <= start:
        return INVALID, "the cut step %s is not after the start %s" % (
            cut.get("step"), start)
    if not (cut.get("kept_pages", 0) > 0 and
            cut.get("rolled_back_pages", 0) > 0):
        return INVALID, "kept %s and rolled back %s: both must be above 0" % (
            cut.get("kept_pages"), cut.get("rolled_back_pages"))
    res = "mount=%s fsck_rc=%s kept=%d rolled_back=%d" % (
        g.get("g3_mount"), g.get("g3_fsck_rc"), cut["kept_pages"],
        cut["rolled_back_pages"])
    if a.lies:
        return RECORDED, "with flush-lie: " + res
    if g.get("g3_mount") == "ok" and g.get("g3_fsck_rc") == "0":
        return PASS, "clean: " + res
    return FAIL, "not clean: " + res


def hung_now(recs):
    held = find(recs, action="hang", phase="apply", outcome="done")
    back = find(recs, action="hang", phase="reclaim")
    return len(held) - len(back), held


def io_done(g, bound):
    """fio ended within the bound and the next I/O worked."""
    why = []
    if "g4_fio_rc" not in g:
        why.append("fio did not end")
    elif int(g.get("g4_fio_s", "0")) > bound:
        why.append("fio took %s s" % g["g4_fio_s"])
    if g.get("g4_next_io") != "ok":
        why.append("next I/O %s" % g.get("g4_next_io"))
    return why


def ran_clean(g, lines, runtime):
    """Positive evidence of a control run: nvme lines, a whole fio run."""
    why = []
    if not any(NVME_RE.search(ln) for ln in lines):
        why.append("dmesg has no nvme line")
    if g.get("g4_fio_rc") != "0":
        why.append("fio exit %s" % g.get("g4_fio_rc"))
    if int(g.get("g4_fio_s", "0")) < runtime - 2:
        why.append("fio ran %s s of %d" % (g.get("g4_fio_s", "0"), runtime))
    return why


def v_g4a(a, g, h, recs, complete):
    if h.get("qemu_alive") != "1":
        return INVALID, "QEMU ended or its state is not known"
    lines = dmesg_lines(a.dmesg)
    touts = [(i, m) for i, ln in enumerate(lines)
             for m in [TIMEOUT_RE.search(ln)] if m]
    if a.control == "a":
        why = ran_clean(g, lines, a.runtime) + io_done(g, a.bound)
        if why:
            return INVALID, ", ".join(why)
        if touts:
            return FAIL, "no hang line, yet dmesg has a timeout"
        return PASS, "no hang line: no timeout in dmesg"
    n, held = hung_now(recs)
    if not held:
        return INVALID, "no hang took effect"
    if not complete:
        return INCOMPLETE, "a record id is missing"
    if a.control == "b":
        if n > 0:
            return PASS, "control b: %d commands stay hung" % n
        return FAIL, "control b: every command came back"
    if h.get("pre_fio_hang", "0") != "0":
        return INVALID, "the hang took effect before fio started"
    rec = held[0]
    hit = [i for i, m in touts
           if int(m.group(3)) == rec["sqid"] and
           # the full CID when dmesg gives it, else the tag part
           (int(m.group(2), 16) == rec["cid"] if m.group(2) else
            int(m.group(1)) == rec["cid"] & 0xfff)]
    why = []
    if not hit:
        why.append("no timeout for SQID %d CID %d" % (rec["sqid"],
                                                       rec["cid"]))
    elif not any(RESET_RE.search(ln) for ln in lines[hit[0]:]):
        why.append("no reset after the timeout")
    why += io_done(g, a.bound)
    if n != 0:
        why.append("%d commands stay hung" % n)
    if why:
        return FAIL, ", ".join(why)
    return PASS, "timeout SQID %d CID %d, reset, fio ended, next I/O ok" % (
        rec["sqid"], rec["cid"])


def v_g4b(a, g, h, recs, complete):
    if h.get("qemu_alive") != "1":
        return INVALID, "QEMU ended or its state is not known"
    lines = dmesg_lines(a.dmesg)
    csts = [(i, int(m.group(1), 16)) for i, ln in enumerate(lines)
            for m in [CSTS_RE.search(ln)] if m]
    cfs = [v for i, v in csts if v & NVME_CSTS_CFS]
    if not find(recs, action="cfs", phase="apply", outcome="done"):
        return INVALID, "no cfs took effect"
    if a.control == "a":
        if not any(NVME_RE.search(ln) for ln in lines):
            return INVALID, "dmesg has no nvme line"
        if cfs:
            return FAIL, "the CSTS write is gone, yet dmesg shows CFS"
        return PASS, "control a: no CSTS value with CFS (%d CSTS lines)" % (
            len(csts))
    why = []
    if not cfs:
        why.append("no CSTS value with CFS in dmesg")
    back = find(recs, action="cfs", phase="reclaim")
    if not [r for r in back if r.get("reason") == "reset"]:
        # design 6.7: CC.EN 1 to 0 reclaims it; another path is a finding
        why.append("no reclaim at a reset (reasons: %s)" % (
            ",".join(str(r.get("reason")) for r in back) or "none"))
    why += io_done(g, a.bound)
    if why:
        return FAIL, ", ".join(why)
    return PASS, "CSTS 0x%x with CFS, reset reclaim, fio ended, next I/O ok" % (
        cfs[0])


RULES = {"g1": v_g1, "g2": v_g2, "g2e": v_g2e, "g3": v_g3, "g4a": v_g4a,
         "g4b": v_g4b}


class Args:
    def __init__(self, test, control=None, lies=False, guest=None, log=None,
                 dmesg=None, host=None, lba=0, bound=180, runtime=30):
        self.test = test
        self.control = control
        self.lies = lies
        self.guest = guest
        self.log = log
        self.dmesg = dmesg
        self.host = host
        self.lba = lba
        self.bound = bound
        self.runtime = runtime


def judge(a):
    recs, complete, again = records(a.log)
    if again:
        return INVALID, "the record log is not fresh: id %d repeats" % again
    return RULES[a.test](a, facts(a.guest), host_facts(a.host), recs,
                         complete)


def parse(argv):
    a = Args(argv[0] if argv else "")
    if a.test not in RULES:
        raise ValueError("TEST must be one of %s" % ", ".join(sorted(RULES)))
    i = 1
    while i < len(argv):
        k = argv[i]
        if k == "--lies":
            a.lies = True
            i += 1
            continue
        if i + 1 >= len(argv):
            raise ValueError("%s needs a value" % k)
        v = argv[i + 1]
        if k == "--control" and v in ("a", "b", "fs"):
            a.control = v
        elif k in ("--guest", "--log", "--dmesg", "--host"):
            setattr(a, k[2:], v)
        elif k in ("--lba", "--bound", "--runtime") and v.isdigit():
            setattr(a, k[2:], int(v))
        else:
            raise ValueError("bad option %s %s" % (k, v))
        i += 2
    return a


# ---- self-test: each rule, and a planted fault for each of its checks ----

def _rec(**kv):
    base = {"origin": "sched-cmd", "line": 1, "match": 1, "step": 10,
            "nsid": 1, "sqid": 2, "cid": 17, "opc": 2, "fua": False,
            "slba": 0, "nlb": 0, "outcome": "done"}
    base.update(kv)
    return base


def _case(d, name, test, guest, recs=(), host="", dmesg="", **kw):
    files = {}
    for key, text in (("guest", guest), ("host", host), ("dmesg", dmesg)):
        p = os.path.join(d, "%s.%s" % (name, key))
        with open(p, "w") as f:
            f.write(text)
        files[key] = p
    lp = os.path.join(d, name + ".log")
    with open(lp, "w") as f:
        for i, r in enumerate(recs, 1):
            r = dict(r)
            r.setdefault("id", i)
            f.write(json.dumps(r) + "\n")
    a = Args(test, log=lp, guest=files["guest"], host=files["host"],
             dmesg=files["dmesg"], **kw)
    return judge(a)


def self_test():
    ok = 0
    bad = []

    def want(got, status, label):
        nonlocal ok
        if got[0] == status:
            ok += 1
            print("ok %s: %s %s" % (label, got[0], got[1]))
        else:
            bad.append(label)
            print("FAIL %s: want %s, got %s %s" % (label, status, *got))

    lie = _rec(id=1, action="flush-lie", phase="apply", opc=0)
    cut = {"id": 2, "origin": "qmp", "action": "power-loss",
           "rolled_back_pages": 3, "kept_pages": 0, "chunks": 1,
           "truncated": False, "step": 50, "outcome": "done"}
    chunk = {"id": 3, "cause": 2, "chunk": 0, "kind": "rolled_back",
             "r": [[1, 4096, 8]]}
    up = "FG boot_id=b1\nFG g1_acked=64 lba=4096-4103 sha256=ab\n"
    cut_ok = "cut=ok\n"
    with tempfile.TemporaryDirectory() as d:
        g1 = up + "FG g1_boot_id=b2 g1_mount=ok g1_m_present=0\n"
        kept = up + "FG g1_boot_id=b2 g1_mount=ok g1_m_present=1\n"
        want(_case(d, "g1", "g1", g1, [lie, cut, chunk], cut_ok), PASS,
             "g1 lost")
        want(_case(d, "g1k", "g1", kept, [lie, cut, chunk], cut_ok), FAIL,
             "g1 kept")
        far = dict(chunk, r=[[1, 9000, 8]])
        want(_case(d, "g1n", "g1", g1, [lie, cut, far], cut_ok), INVALID,
             "g1 not listed")
        want(_case(d, "g1t", "g1", g1, [lie, dict(cut, truncated=True), far],
                   cut_ok), INCOMPLETE, "g1 truncated")
        want(_case(d, "g1r", "g1", g1, [lie, cut, dict(far, r=[[1, 4096, 8,
                                                            "rolled_back"]],
                                                          kind=None)],
                   cut_ok), PASS, "g1 kind per range")
        want(_case(d, "g1d", "g1", g1, [lie, cut, chunk, dict(cut)], cut_ok),
             INVALID, "g1 log of an older run")
        want(_case(d, "g1l", "g1", g1, [dict(cut, id=1), dict(chunk, id=2,
                                                            cause=1)],
                   cut_ok), INVALID, "g1 no lie")
        want(_case(d, "g1z", "g1", g1, [lie], cut_ok), INCOMPLETE,
             "g1 no cut record")
        want(_case(d, "g1u", "g1", g1, [lie, cut, chunk]), PASS,
             "g1 cut record only")
        want(_case(d, "g1x", "g1", g1, [lie]), INVALID, "g1 cut failed")
        want(_case(d, "g1b", "g1", g1.replace("b2", "b1"), [lie, cut, chunk],
                   cut_ok), INVALID, "g1 no reboot")
        want(_case(d, "g1a", "g1", kept, host=cut_ok, control="a"), PASS,
             "g1 control")
        want(_case(d, "g1c", "g1", g1, host=cut_ok, control="a"), FAIL,
             "g1 control lost")
        want(_case(d, "g1d", "g1", kept, control="a"), INVALID,
             "g1 control no cut")
        want(_case(d, "g1m", "g1", g1.replace("g1_mount=ok", "g1_mount=fail"),
                   [lie, cut, chunk], cut_ok), INVALID, "g1 mount failed")
        # a drain emptied the buffer before the cut: nothing lied to lose
        empty = dict(cut, rolled_back_pages=0, rolled_back_lie_pages=0,
                     kept_pages=0, chunks=0)
        want(_case(d, "g1e", "g1", kept, [lie, empty], cut_ok), INVALID,
             "g1 empty buffer, M there")
        want(_case(d, "g1f", "g1", g1, [lie, empty], cut_ok), INVALID,
             "g1 empty buffer, M missing")
        lied = dict(cut, rolled_back_lie_pages=3)
        want(_case(d, "g1g", "g1", g1, [lie, lied, chunk], cut_ok), PASS,
             "g1 lie pages rolled back")
        want(_case(d, "g1h", "g1", kept, [lie, lied, chunk], cut_ok), FAIL,
             "g1 lie pages over M, M there")
        want(_case(d, "g1i", "g1", kept, [lie, lied, far], cut_ok), INVALID,
             "g1 lie pages miss M")
        want(_case(d, "g1j", "g1", kept, [lie], cut_ok), INCOMPLETE,
             "g1 M there, no cut record")
        # the file lost M, but a raw read of its LBAs finds it
        raw1 = g1 + "FG g1_raw_m_present=1\n"
        raw0 = g1 + "FG g1_raw_m_present=0\n"
        want(_case(d, "g1p", "g1", raw1, [lie, lied, far], cut_ok), PASS,
             "g1 lost through metadata")
        want(_case(d, "g1q", "g1", raw1, [lie, dict(lied, truncated=True),
                                          far], cut_ok), PASS,
             "g1 metadata, ranges truncated")
        want(_case(d, "g1s", "g1", raw1, [lie, lied, chunk], cut_ok), FAIL,
             "g1 LBAs rolled back, raw M there")
        want(_case(d, "g1v", "g1", raw1, [lie, empty], cut_ok), INVALID,
             "g1 raw M there, no lie pages")
        want(_case(d, "g1w", "g1", raw1, [lie], cut_ok), INCOMPLETE,
             "g1 raw M there, no cut record")
        want(_case(d, "g1y", "g1", raw0, [lie, lied, chunk], cut_ok), PASS,
             "g1 raw M missing, listed")
        want(_case(d, "g1o", "g1", raw0, [lie, dict(lied, truncated=True),
                                          far], cut_ok), INCOMPLETE,
             "g1 raw M missing, truncated")
        want(_case(d, "g1aa", "g1", raw0, [lie, lied, far], cut_ok), INVALID,
             "g1 raw M missing, not listed")
        want(_case(d, "g1ab", "g1", kept + "FG g1_raw_m_present=1\n",
                   [lie, lied, far], cut_ok), INVALID,
             "g1 file M there, raw M there")
        want(_case(d, "g1ac", "g1", raw1, host=cut_ok, control="a"), FAIL,
             "g1 control, file M lost, raw M there")
        # the facts of run d760-426c11-k-fsched: 320 lie pages in 68
        # ranges, 64 listed, none over M; the file has size 0
        run_up = ("FG boot_id=b1\nFG g1_acked=64 lba=263672-263679 "
                  "sha256=ab\n")
        run_g = run_up + ("FG g1_boot_id=b2 g1_mount=ok g1_size=0 "
                          "g1_intact=0 g1_m_present=0 g1_m_sha=-\n")
        run_cut = dict(cut, rolled_back_pages=320, rolled_back_lie_pages=320,
                       truncated=True, chunks=1)
        run_chunk = dict(chunk, r=[[1, 263296, 368]] +
                         [[1, 1000 * k, 8] for k in range(1, 64)])
        want(_case(d, "g1run", "g1", run_g, [lie, run_cut, run_chunk],
                   cut_ok), INCOMPLETE, "g1 run 426c11, no raw read")
        want(_case(d, "g1runr", "g1", run_g + "FG g1_raw_m_present=1\n",
                   [lie, run_cut, run_chunk], cut_ok), PASS,
             "g1 run 426c11, raw M there")

        sel = _rec(id=1, action="wb-fail", phase="select", outcome="selected",
                   opc=1, slba=4096, nlb=8)
        fail = _rec(id=2, action="wb-fail", phase="fail", outcome="old",
                    cause=1, slba=4096, nlb=8, found="command")
        rep = _rec(id=3, action="wb-fail", phase="report", outcome="reported",
                   cause=2, slba=4096, nlb=8, found="self", status=640)
        g2 = "FG g2_write=4096 g2_fsync1=ENODATA g2_fsync2=0 g2_read=A0\n"
        want(_case(d, "g2", "g2", g2, [sel, fail, rep], lba=4100), PASS,
             "g2")
        want(_case(d, "g2w", "g2", g2.replace("=4096", "=2048"),
                   [sel, fail, rep], lba=4100), FAIL, "g2 length")
        want(_case(d, "g2e", "g2", g2.replace("ENODATA", "EIO"),
                   [sel, fail, rep], lba=4100), FAIL, "g2 errno")
        want(_case(d, "g2r", "g2", g2.replace("=A0", "=A1"),
                   [sel, fail, rep], lba=4100), FAIL, "g2 read")
        want(_case(d, "g2p", "g2", g2, [sel, fail, dict(rep,
                                                        found="pending")],
                   lba=4100), FAIL, "g2 found")
        want(_case(d, "g2x", "g2", g2, [sel, fail, rep, dict(rep, id=4)],
                   lba=4100), FAIL, "g2 two reports")
        want(_case(d, "g2l", "g2", g2, [sel, fail, rep], lba=9000), FAIL,
             "g2 other page")
        want(_case(d, "g2q", "g2", g2, [sel, fail, dict(rep, id=5)],
                   lba=4100), INCOMPLETE, "g2 dropped ids")
        want(_case(d, "g2s", "g2", g2.replace("ENODATA", "EIO"),
                   [sel, fail, dict(rep, id=5)], lba=4100), FAIL,
             "g2 errno before a gap")
        want(_case(d, "g2a", "g2", g2.replace("ENODATA", "0"), control="a"),
             PASS, "g2 control a")
        want(_case(d, "g2b", "g2", g2.replace("ENODATA", "0"), [sel, fail],
                   control="b"), PASS, "g2 control b")
        want(_case(d, "g2c", "g2", g2, [sel, fail], control="b"), FAIL,
             "g2 control b red")
        want(_case(d, "g2d", "g2", g2.replace("ENODATA", "0"), [sel],
                   control="b"), INVALID, "g2 control b no fail record")

        pl = {"id": 1, "action": "power-loss", "origin": "sched-cmd",
              "step": 900, "rolled_back_pages": 7, "kept_pages": 3,
              "outcome": "done"}
        g3 = ("FG g3_mkfs=ext4\nFG g3_stress_start=1 seed=1\n"
              "FG g3_mount=ok g3_umount=ok g3_fsck_rc=0 fs=ext4\n")
        hs = "start_step=100\n"
        want(_case(d, "g3", "g3", g3, [pl], host=hs), PASS, "g3")
        want(_case(d, "g3f", "g3", g3.replace("rc=0", "rc=4"), [pl],
                   host=hs), FAIL, "g3 fsck")
        want(_case(d, "g3k", "g3", g3, [dict(pl, kept_pages=0)], host=hs),
             INVALID, "g3 kept 0")
        want(_case(d, "g3w", "g3", g3, [pl], host="start_step=950\n"),
             INVALID, "g3 window")
        want(_case(d, "g3e", "g3", g3 + "FG g3_stress_end=1\n", [pl],
                   host=hs), INVALID, "g3 after fsstress")
        want(_case(d, "g3b", "g3", g3, [_rec(id=1, action="power-loss",
                                              phase="select")], host=hs),
             BLOCKED, "g3 no cut model")
        want(_case(d, "g3l", "g3", g3, [pl], host=hs, lies=True), RECORDED,
             "g3 lies")
        ce = ("FG g3_mkfs=ext4\n"
              "FGL Root inode is not a directory.  Clear? no\n"
              "FG g3_corrupt=clri-root-inode g3_fsck_rc=4 fs=ext4\n")
        cx = ("FG g3_mkfs=xfs mkfs_profile=lts_6.6.conf\n"
              "FGL bad inode format in inode 128\n"
              "FG g3_corrupt=root-inode-mode-0 g3_fsck_rc=1 fs=xfs "
              "rootino=128\n")
        want(_case(d, "g3c", "g3", ce, control="fs"), PASS, "g3 control ext4")
        want(_case(d, "g3x", "g3", cx, control="fs"), PASS, "g3 control xfs")
        want(_case(d, "g3d", "g3", ce.replace("rc=4", "rc=0"), control="fs"),
             FAIL, "g3 control rc 0")
        want(_case(d, "g3n", "g3", ce.replace("Root inode", "Block bitmap"),
                   control="fs"), FAIL, "g3 control other damage")
        want(_case(d, "g3y", "g3", cx.replace("128\n", "129\n", 1),
                   control="fs"), FAIL, "g3 control other inode")
        # e2fsck -n cannot make a new root: pass 3 aborts, 4 + 8
        want(_case(d, "g3a", "g3", ce.replace("rc=4", "rc=12"), control="fs"),
             PASS, "g3 control ext4 abort 12")
        want(_case(d, "g3o", "g3", ce.replace("rc=4", "rc=8"), control="fs"),
             FAIL, "g3 control ext4 rc 8")
        want(_case(d, "g3z", "g3", cx.replace("rc=1", "rc=12"), control="fs"),
             FAIL, "g3 control xfs rc 12")
        nofs = ("FG boot_id=b1 dev=nvme0n1\nFG_DONE ok\n"
               "FGK XFS (nvme0n1): Superblock has unknown features\n"
               "FG_DONE fail setup-mount-rc32 dmesg(1) may have more\n")
        want(_case(d, "g3m", "g3", nofs, host=hs), SETUP,
             "g3 xfs mount failed")
        want(_case(d, "g3q", "g3", nofs, control="fs"), SETUP,
             "g3 control xfs mount failed")

        hang = _rec(id=1, action="hang", phase="apply", sqid=3, cid=0x300c)
        back = _rec(id=2, action="hang", phase="reclaim", outcome="reclaimed",
                    reason="sq-deleted", sqid=3, cid=0x300c)
        g4 = ("FG g4_fio_rc=0 g4_fio_s=40\n"
              "FG g4_next_io=ok g4_ctrl_state=live\n")
        g4c = g4.replace("g4_fio_s=40", "g4_fio_s=30")
        live = "qemu_alive=1\n"
        dm = ("[ 5.1] nvme nvme0: I/O tag 12 (300c) opcode 0x2 (Read) QID 3 "
              "timeout, aborting\n[10.2] nvme nvme0: I/O tag 12 (300c) "
              "opcode 0x2 (Read) QID 3 timeout, reset controller\n")
        old = "[ 5.1] nvme nvme0: I/O 12 QID 3 timeout, reset controller\n"
        quiet = "[ 1.0] nvme nvme0: 4/0/0 default/read/poll queues\n"
        want(_case(d, "g4", "g4a", g4, [hang, back], live, dm), PASS, "g4a")
        want(_case(d, "g4o", "g4a", g4, [hang, back], live, old), PASS,
             "g4a old kernel")
        want(_case(d, "g4q", "g4a", g4, [hang, back], live,
                   dm.replace("QID 3", "QID 4")), FAIL, "g4a qid")
        want(_case(d, "g4t", "g4a", g4, [hang, back], live,
                   dm.replace("(300c)", "(100c)")), FAIL, "g4a full CID")
        want(_case(d, "g4r", "g4a", g4, [hang, back], live,
                   dm.split("\n")[0] + "\n"), FAIL, "g4a no reset")
        want(_case(d, "g4h", "g4a", g4, [hang], live, dm), FAIL,
             "g4a stays hung")
        want(_case(d, "g4f", "g4a", "FG g4_next_io=ok\n", [hang, back], live,
                   dm), FAIL, "g4a fio did not end")
        want(_case(d, "g4p", "g4a", g4, [hang, back],
                   live + "pre_fio_hang=1\n", dm), INVALID, "g4a before fio")
        want(_case(d, "g4d", "g4a", g4, [hang, back], "qemu_alive=0\n", dm),
             INVALID, "g4a QEMU ended")
        want(_case(d, "g4g", "g4a", g4, [hang, dict(back, id=3)], live, dm),
             INCOMPLETE, "g4a dropped ids")
        want(_case(d, "g4ca", "g4a", g4c, [], live, quiet, control="a"),
             PASS, "g4a control a")
        want(_case(d, "g4cx", "g4a", g4c, [], live, quiet + dm,
                   control="a"), FAIL, "g4a control a red")
        want(_case(d, "g4cn", "g4a", g4c, [], live, "", control="a"),
             INVALID, "g4a control a no nvme line")
        want(_case(d, "g4cs", "g4a", g4c.replace("_s=30", "_s=12"), [], live,
                   quiet, control="a"), INVALID, "g4a control a short fio")
        want(_case(d, "g4cr", "g4a", g4c.replace("rc=0", "rc=1"), [], live,
                   quiet, control="a"), INVALID, "g4a control a fio error")
        want(_case(d, "g4cb", "g4a", g4, [hang], live, dm, control="b"),
             PASS, "g4a control b")
        want(_case(d, "g4cc", "g4a", g4, [hang, back], live, dm,
                   control="b"), FAIL, "g4a control b reclaimed")
        want(_case(d, "g4ce", "g4a", g4, [hang], "qemu_alive=0\n", dm,
                   control="b"), INVALID, "g4a control b QEMU ended")

        park = _rec(id=1, action="cfs", phase="apply", sqid=2, cid=5)
        rcl = _rec(id=2, action="cfs", phase="reclaim", outcome="reclaimed",
                   reason="reset", sqid=2, cid=5)
        dmb = ("[ 9.0] nvme nvme0: controller is down; will reset: "
               "CSTS=0x3, PCI_STATUS=0x10\n")
        nocfs = dmb.replace("0x3,", "0x1,")
        want(_case(d, "g5", "g4b", g4, [park, rcl], live, dmb), PASS, "g4b")
        want(_case(d, "g5c", "g4b", g4, [park, rcl], live, nocfs), FAIL,
             "g4b no CFS")
        want(_case(d, "g5r", "g4b", g4, [park], live, dmb), FAIL,
             "g4b no reclaim")
        want(_case(d, "g5s", "g4b", g4, [park, dict(rcl, reason="sq-deleted")],
                   live, dmb), FAIL, "g4b reclaim by another path")
        want(_case(d, "g5f", "g4b", "FG g4_next_io=ok\n", [park, rcl], live,
                   dmb), FAIL, "g4b fio did not end")
        want(_case(d, "g5n", "g4b", g4.replace("=ok", "=EIO"), [park, rcl],
                   live, dmb), FAIL, "g4b next I/O")
        want(_case(d, "g5d", "g4b", g4, [park, rcl], "qemu_alive=0\n", dmb),
             INVALID, "g4b QEMU ended")
        want(_case(d, "g5a", "g4b", g4, [park, rcl], live, nocfs,
                   control="a"), PASS, "g4b control a")
        want(_case(d, "g5b", "g4b", g4, [park, rcl], live, dmb, control="a"),
             FAIL, "g4b control a red")
        want(_case(d, "g5e", "g4b", g4, [park, rcl], live, "", control="a"),
             INVALID, "g4b control a no nvme line")
        want(_case(d, "g5g", "g4b", g4, [], live, nocfs, control="a"),
             INVALID, "g4b control a no cfs")
    print("fault-verdict self-test: %s (%d ok, %d failed)" % (
        "PASS" if not bad else "FAIL", ok, len(bad)))
    return 0 if not bad else 1


def main(argv):
    if argv == ["--self-test"]:
        return self_test()
    try:
        a = parse(argv)
        status, why = judge(a)
    except (ValueError, KeyError, TypeError, OSError) as e:
        print("fault-verdict: %s" % e, file=sys.stderr)
        print(__doc__, file=sys.stderr)
        return 2
    name = a.test + ("-" + a.control if a.control else "") + (
        "-lies" if a.lies else "")
    print("VERDICT %s %s %s" % (name, status, why))
    return EXIT.get(status, 3)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
