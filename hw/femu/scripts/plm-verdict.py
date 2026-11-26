#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Verdicts of the Predictable Latency Mode guest tests (host side).

  plm-verdict.py gplm1 --guest FILE
  plm-verdict.py tail --guest FILE... --control FILE... [--repeats N]
                 [--margin M] [--min-valid V] [--min-reads N]
  plm-verdict.py --self-test

The inputs are the output of plm-guest.py: "FG key=value ..." facts,
"FGC" cycle lines and a last "FG_DONE" line.

Output: the table of the test, then one line "VERDICT TEST STATUS
reason". STATUS is PASS, FAIL, INVALID (the run did not test what it
must), INCOMPLETE (runs are missing: run again) or SETUP-ERROR (the
guest could not run the test). Exit status: 0 for PASS, 1 for FAIL, 3
for the rest, 2 for a usage error.

gplm1 (design 6.2) checks each fact of the guest check: the Identify
bits, the NVM Set List, the refusals, the window changes, and the MVEAT
exit after exactly DTWWT units of writes plus one:

  DTWWT units --> still DTWIN, DTWWE fell --> one unit --> NDWIN, MVEAT
  --> log 0Bh NUMENT 1 --> log 0Ah (no RAE) ETYP MVEAT --> again: 0
  --> log 0Bh NUMENT 0 --> LPE=0: PLMW 0

tail (design 6.3) judges the read tail experiment. Each --guest file
holds one or more repeats with plm=on; each --control file holds the
repeats with plm=off, whose reads the same time slots split:

  1. each plm repeat has at least V (0.9) of its cycles valid: the
     DTWIN started with DTWWE >= the planned writes, with no DEAT
  2. no DEAT in a cycle whose target was reachable (deat_reach = 0)
  3. median DTWIN p99 <= (1 - M) x median NDWIN p99, M = 0.2
  4. median NDWIN p99 - median DTWIN p99 > the run to run spread of
     the DTWIN p99
  5. the control: |DTWIN p99 - NDWIN p99| <= M x NDWIN p99 (medians),
     so the split alone makes no gap
  6. each plm repeat has at least N (1000) DTWIN reads; each control
     repeat has at least N reads in each set of slots
  7. each plm repeat: DTWIN p99.9 < NDWIN p99.9
  8. each plm repeat: DTWIN p99.9 <= (1 - M) x the control p99.9 (the
     median over the control repeats of the DTWIN slots)

Rules 1, 5 and 6 make a run INVALID, rules 2, 3, 4, 7 and 8 make it FAIL.

The NDWIN may have few reads. The held background work runs in one
block when the NDWIN starts, and a read at QD 1 waits for all of it. So
the read stall is the result, and the NDWIN needs no minimum of reads.
Rules 3, 4 and 7 use the NDWIN reads that exist: rules 3 and 4 the
repeats with an NDWIN read, rule 7 each such repeat. With no NDWIN read
in any repeat, rules 3, 4 and 7 do not apply and rule 8 decides. The
NDWIN p99 of one repeat with few stalled reads can be low, so rules 3
and 4 use medians, and the spread of rule 4 is that of the DTWIN p99.

  DTWIN reads >= N --> p99, p99.9 --> rules 3, 4, 7 (vs NDWIN), 8 (vs control)
  NDWIN reads >= 0 --> reported: reads, stall p50 and max, Set 14h hold

For each plm repeat the output gives the NDWIN reads, the NDWIN read
stall (p50 and max) and the longest Set 14h hold (hold_ms_max), which is
the time the held background work ran. Without an nd_max_us fact, the
max is the NDWIN p99.9, which equals it below 1000 reads. The table also
gives p50, and the plm=off p99 over the NDWIN p99.
"""
import argparse
import contextlib
import io
import os
import statistics
import sys
import tempfile

PASS, FAIL, INVALID, INCOMPLETE, SETUP = (
    "PASS", "FAIL", "INVALID", "INCOMPLETE", "SETUP-ERROR")
EXIT = {PASS: 0, FAIL: 1}
MVEAT = 1 << 14
DEAT = 1 << 15


def facts(path):
    """The FG facts of a file as one dict (a later key wins), the list of
    tail summaries, and the FG_DONE line."""
    f, tails, done = {}, [], None
    with open(path, errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line.startswith("FG_DONE"):
                done = line
                continue
            if not line.startswith("FG "):
                continue
            kv = dict(p.split("=", 1) for p in line[3:].split() if "=" in p)
            if "tail_mode" in kv:
                tails.append(kv)
            f.update(kv)
    return f, tails, done


def num(v):
    try:
        return int(v, 0)
    except (TypeError, ValueError):
        try:
            return float(v)
        except (TypeError, ValueError):
            return None


def done_status(done):
    """SETUP-ERROR or FAIL for a guest that did not end ok, else None."""
    if done is None:
        return SETUP, "no FG_DONE line: the guest step did not end"
    if done.startswith("FG_DONE fail setup-"):
        return SETUP, done[len("FG_DONE fail "):]
    if done != "FG_DONE ok":
        return FAIL, "guest step failed: " + done[len("FG_DONE fail "):]
    return None


# ---- gplm1 ----------------------------------------------------------------

def gplm1_rules(f):
    """(name, ok) for each rule of the guest check."""
    g = {k: num(v) for k, v in f.items()}

    def bits(k, mask):
        return g.get(k) is not None and g[k] & mask == mask

    def eq(k, v):
        return g.get(k) == v

    def refused(k):
        return f.get(k) == "sc-0x2"
    return [
        ("ctratt bits 2, 3, 4, 5", bits("ctratt", 0x3c)),
        ("oaes bit 12", bits("oaes", 1 << 12)),
        ("nsetidmax 1", eq("nsetidmax", 1)),
        ("CNS 04h one set, NSETID 1, ENDGID 1",
         eq("set_numid", 1) and eq("set_nsetid", 1) and eq("set_endgid", 1)),
        ("CNS 04h R4KRT > 0", (g.get("set_r4krt") or 0) > 0),
        ("CNS 04h from 2 lists none", eq("set2_numid", 0)),
        ("namespace NVMSETID 1", eq("ns_nvmsetid", 1)),
        ("Get 13h LPE 0", eq("get13_lpe", 0)),
        ("Get 14h refused while disabled", refused("get14_off")),
        ("Get 13h NSID 1 refused", refused("get13_nsid1")),
        ("Get 13h NVMSETID 0 refused", refused("get13_set0")),
        ("Get 14h NDWIN after LPE=1", eq("get14_nd", 2)),
        ("Set 14h WSEL 0 refused", refused("set14_wsel0")),
        ("log 0Ah LSI 2 refused", refused("log0a_lsi2")),
        ("Get 14h DTWIN", eq("get14_dt", 1)),
        ("log 0Ah PLMW 1 at DTWIN entry", eq("dt_entry_plmw", 1)),
        ("DTWWT units: still DTWIN", eq("mv_at_plmw", 1)),
        ("DTWWT units: DTWWE fell",
         g.get("mv_at_dtwwe") is not None and
         g.get("dt_entry_dtwwe") is not None and
         g["mv_at_dtwwe"] < g["dt_entry_dtwwe"]),
        ("one more unit: NDWIN", eq("mv_after_plmw", 2)),
        ("one more unit: ETYP MVEAT, no DEAT",
         bits("mv_after_etyp", MVEAT) and
         not bits("mv_after_etyp", DEAT)),
        ("log 0Bh NUMENT 1, entry set 1",
         eq("agg_rae_nument", 1) and eq("agg_rae_entry", 1)),
        ("log 0Bh past 10 bytes zero", eq("agg_rae_tail_zero", 1)),
        ("log 0Ah read 1 ETYP MVEAT", bits("read1_etyp", MVEAT)),
        ("log 0Ah read 2 ETYP 0", eq("read2_etyp", 0)),
        ("log 0Bh NUMENT 0 after the read", eq("agg_after_nument", 0)),
        ("LPE=0: PLMW 0", eq("off_plmw", 0)),
        ("LPE=0: Get 14h refused", refused("get14_lpe0")),
        ("namespace still reads", f.get("ns_read") == "ok"),
        ("no new nvme kernel warning", eq("nvme_warn_new", 0)),
    ]


def v_gplm1(a):
    f, _, done = facts(a.guest)
    bad = done_status(done)
    rules = gplm1_rules(f)
    for name, ok in rules:
        print("  %-40s %s" % (name, "ok" if ok else "FAIL"))
    for k in ("nvme_version", "set_ows", "mv_unit", "mv_units",
              "set14_dt_ms", "cli_id_nvmset", "cli_pl_log", "cli_pl_agg",
              "get13_zero"):
        print("  %-40s %s" % ("recorded " + k, f.get(k, "-")))
    if bad and bad[0] == SETUP:
        return bad
    failed = [n for n, ok in rules if not ok]
    if bad:
        return FAIL, bad[1] + (" (%d rules fail)" % len(failed))
    if failed:
        return FAIL, "%d of %d rules fail: %s" % (len(failed), len(rules),
                                                   failed[0])
    return PASS, "%d rules hold" % len(rules)


# ---- tail -----------------------------------------------------------------

def load_tails(paths, mode):
    """The tail summaries of MODE from PATHS, and the first bad guest end."""
    out, bad = [], None
    for p in paths:
        _, tails, done = facts(p)
        out += [t for t in tails if t.get("tail_mode") == mode]
        bad = bad or done_status(done)
    return out, bad


def row(t):
    return {k: num(v) for k, v in t.items()}


def table(plm, ctl):
    hdr = ("%-8s %6s %6s %5s %5s %7s %7s %6s %9s %9s %9s %9s %9s %9s" %
           ("run", "cycles", "valid", "deat", "mveat", "reads", "dt_n",
            "nd_n", "dt_p50", "dt_p99", "dt_p999", "nd_p50", "nd_p99",
            "nd_p999"))
    print(hdr)
    for name, rows in (("plm", plm), ("off", ctl)):
        for i, g in enumerate(rows):
            print("%-8s %6s %6s %5s %5s %7s %7s %6s %9s %9s %9s %9s %9s %9s" %
                  ("%s-%d" % (name, i + 1), g.get("cycles"), g.get("valid"),
                   g.get("deat"), g.get("mveat"), g.get("reads"),
                   g.get("dt_n"), g.get("nd_n"),
                   g.get("dt_p50_us"), g.get("dt_p99_us"),
                   g.get("dt_p999_us"), g.get("nd_p50_us"),
                   g.get("nd_p99_us"), g.get("nd_p999_us")))
    print("(latencies in us)")


def v_tail(a):
    plm_t, bad = load_tails(a.guest, "plm")
    ctl_t, bad2 = load_tails(a.control or [], "phantom")
    plm = [row(t) for t in plm_t]
    ctl = [row(t) for t in ctl_t]
    table(plm, ctl)
    stalls(plm)
    for b in (bad, bad2):
        if b and b[0] == SETUP and len(plm) < a.repeats:
            return b
    if len(plm) < a.repeats:
        return INCOMPLETE, "%d of %d plm repeats" % (len(plm), a.repeats)
    if not ctl:
        return INCOMPLETE, "no plm=off control repeat"
    m = a.margin
    # rule 6, then rule 1: the runs must measure what they claim
    for i, g in enumerate(plm):
        if (g.get("dt_n") or 0) < a.min_reads:
            return INVALID, ("plm-%d has under %d DTWIN reads (rule 6)" %
                             (i + 1, a.min_reads))
    for i, g in enumerate(ctl):
        if min(g.get("dt_n") or 0, g.get("nd_n") or 0) < a.min_reads:
            return INVALID, ("off-%d has under %d reads in a set of slots "
                             "(rule 6)" % (i + 1, a.min_reads))
    for i, g in enumerate(plm):
        if (g.get("valid") or 0) < a.min_valid * (g.get("cycles") or 0) \
                or not g.get("cycles"):
            return INVALID, "plm-%d: %s of %s cycles valid (rule 1)" % (
                i + 1, g.get("valid"), g.get("cycles"))
    cdt = statistics.median(g["dt_p99_us"] for g in ctl)
    cnd = statistics.median(g["nd_p99_us"] for g in ctl)
    c999 = statistics.median(g["dt_p999_us"] for g in ctl)
    if abs(cdt - cnd) > m * cnd:
        return INVALID, ("control split shows a gap: %.1f vs %.1f us "
                         "(rule 5)" % (cdt, cnd))
    deat = sum(g.get("deat_reach") or 0 for g in plm)
    if deat:
        return FAIL, "%d DEAT exits with a reachable target (rule 2)" % deat
    dt = [g["dt_p99_us"] for g in plm]
    mdt = statistics.median(dt)
    spread = max(dt) - min(dt)
    # rules 3, 4 and 7 use the repeats with an NDWIN read
    ndr = [g for g in plm if (g.get("nd_n") or 0) > 0]
    print("control p99: DTWIN slots %.1f, NDWIN slots %.1f us; control "
          "p99.9 of the DTWIN slots %.1f us" % (cdt, cnd, c999))
    if ndr:
        mdtn = statistics.median(g["dt_p99_us"] for g in ndr)
        mnd = statistics.median(g["nd_p99_us"] for g in ndr)
        gap = mnd - mdtn
        print("median p99 over %d repeats with NDWIN reads: DTWIN %.1f, "
              "NDWIN %.1f, gap %.1f, DTWIN spread %.1f us" %
              (len(ndr), mdtn, mnd, gap, spread))
        if mdtn > (1 - m) * mnd:
            return FAIL, ("median DTWIN p99 %.1f us is not %d%% below the "
                          "median NDWIN p99 %.1f us (rule 3)" %
                          (mdtn, round(m * 100), mnd))
        if gap <= spread:
            return FAIL, "median gap %.1f us is within the DTWIN spread " \
                "%.1f us (rule 4)" % (gap, spread)
        for i, g in enumerate(plm):
            if (g.get("nd_n") or 0) > 0 and \
                    g["dt_p999_us"] >= g["nd_p999_us"]:
                return FAIL, ("plm-%d: DTWIN p99.9 %.1f us is not below "
                              "NDWIN p99.9 %.1f us (rule 7)" %
                              (i + 1, g["dt_p999_us"], g["nd_p999_us"]))
    else:
        print("no NDWIN read in any repeat: rules 3, 4 and 7 do not apply")
    for i, g in enumerate(plm):
        if g["dt_p999_us"] > (1 - m) * c999:
            return FAIL, ("plm-%d: DTWIN p99.9 %.1f us is not %d%% below "
                          "the control p99.9 %.1f us (rule 8)" %
                          (i + 1, g["dt_p999_us"], round(m * 100), c999))
    worst = max(stall_max(g)[0] for g in plm)
    return PASS, ("DTWIN p99 %.1f us, p99.9 at most %.1f us vs control "
                  "p99.9 %.1f us over %d repeats, no reachable DEAT; "
                  "NDWIN reads %d, longest NDWIN read %.1f us" % (
                      mdt, max(g["dt_p999_us"] for g in plm), c999,
                      len(plm), sum(g.get("nd_n") or 0 for g in plm),
                      worst))


def stall_max(g):
    """The longest NDWIN read of a repeat and how it is known."""
    if g.get("nd_max_us") is not None:
        return g["nd_max_us"], "max"
    n = g.get("nd_n") or 0
    # nearest rank p99.9 is the last read below 1000 reads
    return g.get("nd_p999_us") or -1, ("max" if n < 1000 else ">=p99.9")


def stalls(plm):
    """The NDWIN read stall and the Set 14h hold of each plm repeat."""
    for i, g in enumerate(plm):
        mx, how = stall_max(g)
        print("NDWIN plm-%d: %s reads, read p50 %s us, %s %.1f us; longest "
              "Set 14h hold (held background work) %s ms" %
              (i + 1, g.get("nd_n"), g.get("nd_p50_us"), how, mx,
               g.get("hold_ms_max")))


# ---- self-test ------------------------------------------------------------

GOOD_G1 = """FG nvme_version=2.8
FG ctratt=0x3c oaes=0x1000 nsetidmax=1
FG set_numid=1 set_nsetid=1 set_endgid=1 set_r4krt=4 set_ows=262144
FG set_tnvmsc=1073741824
FG set2_numid=0
FG ns_nvmsetid=1
FG cli_id_nvmset=1
FG cli_pl_log=1
FG cli_pl_agg=1
FG get13_lpe=0 get13_zero=1
FG get14_off=sc-0x2
FG get13_nsid1=sc-0x2
FG get13_set0=sc-0x2
FG get14_nd=2
FG set14_wsel0=sc-0x2
FG log0a_lsi2=sc-0x2
FG set14_dt_ms=3
FG get14_dt=1
FG dt_entry_plmw=1 dt_entry_etyp=0x0 dt_entry_dtwwt=64 dt_entry_dtwwe=64
FG dt_entry_dtwtm=60000 dt_entry_dtwre=1048576
FG mv_unit=262144 mv_ows_reported=1 mv_units=64
FG mv_at_plmw=1 mv_at_etyp=0x0 mv_at_dtwwt=64 mv_at_dtwwe=0 mv_at_dtwtm=60000
FG mv_at_dtwre=1048576
FG mv_after_plmw=2 mv_after_etyp=0x4000 mv_after_dtwwt=64 mv_after_dtwwe=64
FG mv_after_dtwtm=60000 mv_after_dtwre=1048576
FG agg_rae_nument=1 agg_rae_entry=1 agg_rae_tail_zero=1
FG read1_plmw=2 read1_etyp=0x4000 read1_dtwwt=64 read1_dtwwe=64
FG read1_dtwtm=60000 read1_dtwre=1048576
FG read2_plmw=2 read2_etyp=0x0 read2_dtwwt=64 read2_dtwwe=64 read2_dtwtm=60000
FG read2_dtwre=1048576
FG agg_after_nument=0 agg_after_entry=0 agg_after_tail_zero=1
FG off_plmw=0 off_etyp=0x0 off_dtwwt=64 off_dtwwe=0 off_dtwtm=60000
FG off_dtwre=0
FG get14_lpe0=sc-0x2
FG ns_read=ok
FG nvme_warn_new=0
FG_DONE ok
"""


# The tail summaries of the d760 run of 2026-11-26 (plm=on, then plm=off),
# one line per repeat, as plm-guest.py printed them. The held background
# work stalled the few NDWIN reads for 2.2 to 2.7 s.
REAL_PLM = [
    ("FG tail_mode=plm cycles=60 valid=60 reach=60 mveat=0 deat=0 "
     "deat_reach=0 exits=0 planned=8192 unit=4096 hold_ms_max=3111 "
     "reads=264018 dt_n=253432 dt_p50_us=44.9 dt_p99_us=242.5 "
     "dt_p999_us=250.7 nd_n=628 nd_p50_us=45.3 nd_p99_us=251.5 "
     "nd_p999_us=2658669.8 all_n=264018 all_p50_us=44.9 all_p99_us=242.8 "
     "all_p999_us=251.5\n"),
    ("FG tail_mode=plm cycles=60 valid=60 reach=60 mveat=0 deat=0 "
     "deat_reach=0 exits=0 planned=8192 unit=4096 hold_ms_max=2719 "
     "reads=265089 dt_n=256005 dt_p50_us=44.9 dt_p99_us=242.0 "
     "dt_p999_us=250.6 nd_n=9 nd_p50_us=2228474.4 nd_p99_us=2557077.4 "
     "nd_p999_us=2557077.4 all_n=265089 all_p50_us=45.0 all_p99_us=242.4 "
     "all_p999_us=251.3\n"),
    ("FG tail_mode=plm cycles=60 valid=60 reach=60 mveat=0 deat=0 "
     "deat_reach=0 exits=0 planned=8192 unit=4096 hold_ms_max=2626 "
     "reads=264449 dt_n=255128 dt_p50_us=45.0 dt_p99_us=242.4 "
     "dt_p999_us=250.6 nd_n=5 nd_p50_us=2243556.5 nd_p99_us=2244673.2 "
     "nd_p999_us=2244673.2 all_n=264449 all_p50_us=45.0 all_p99_us=242.7 "
     "all_p999_us=251.3\n"),
    ("FG tail_mode=plm cycles=60 valid=60 reach=60 mveat=0 deat=0 "
     "deat_reach=0 exits=0 planned=8192 unit=4096 hold_ms_max=2631 "
     "reads=266016 dt_n=256829 dt_p50_us=44.9 dt_p99_us=242.2 "
     "dt_p999_us=250.7 nd_n=3 nd_p50_us=2227786.8 nd_p99_us=2239151.9 "
     "nd_p999_us=2239151.9 all_n=266016 all_p50_us=44.9 all_p99_us=242.5 "
     "all_p999_us=251.3\n"),
    ("FG tail_mode=plm cycles=60 valid=60 reach=60 mveat=0 deat=0 "
     "deat_reach=0 exits=0 planned=8192 unit=4096 hold_ms_max=2625 "
     "reads=264558 dt_n=255415 dt_p50_us=44.9 dt_p99_us=242.4 "
     "dt_p999_us=250.5 nd_n=4 nd_p50_us=2236993.9 nd_p99_us=2277331.8 "
     "nd_p999_us=2277331.8 all_n=264558 all_p50_us=44.9 all_p99_us=242.8 "
     "all_p999_us=251.2\n"),
]

REAL_OFF = [
    ("FG tail_mode=phantom cycles=60 valid=60 reach=60 mveat=0 deat=0 "
     "deat_reach=0 exits=0 planned=8192 unit=4096 hold_ms_max=0 "
     "reads=142295 dt_n=61354 dt_p50_us=45.1 dt_p99_us=245.9 "
     "dt_p999_us=319973.5 nd_n=65922 nd_p50_us=45.0 nd_p99_us=246.1 "
     "nd_p999_us=319811.6 all_n=142295 all_p50_us=45.1 all_p99_us=246.1 "
     "all_p999_us=319839.3\n"),
    ("FG tail_mode=phantom cycles=60 valid=60 reach=60 mveat=0 deat=0 "
     "deat_reach=0 exits=0 planned=8192 unit=4096 hold_ms_max=0 "
     "reads=144455 dt_n=66185 dt_p50_us=45.1 dt_p99_us=246.0 "
     "dt_p999_us=320051.8 nd_n=58450 nd_p50_us=45.3 nd_p99_us=246.3 "
     "nd_p999_us=320073.9 all_n=144455 all_p50_us=45.1 all_p99_us=246.0 "
     "all_p999_us=320017.3\n"),
    ("FG tail_mode=phantom cycles=60 valid=60 reach=60 mveat=0 deat=0 "
     "deat_reach=0 exits=0 planned=8192 unit=4096 hold_ms_max=0 "
     "reads=139646 dt_n=59088 dt_p50_us=45.1 dt_p99_us=245.9 "
     "dt_p999_us=319901.8 nd_n=59957 nd_p50_us=45.1 nd_p99_us=246.3 "
     "nd_p999_us=319971.2 all_n=139646 all_p50_us=45.1 all_p99_us=246.2 "
     "all_p999_us=319943.6\n"),
    ("FG tail_mode=phantom cycles=60 valid=60 reach=60 mveat=0 deat=0 "
     "deat_reach=0 exits=0 planned=8192 unit=4096 hold_ms_max=0 "
     "reads=140226 dt_n=58785 dt_p50_us=45.2 dt_p99_us=246.4 "
     "dt_p999_us=320212.9 nd_n=61271 nd_p50_us=45.2 nd_p99_us=246.7 "
     "nd_p999_us=320005.9 all_n=140226 all_p50_us=45.2 all_p99_us=246.3 "
     "all_p999_us=320023.4\n"),
    ("FG tail_mode=phantom cycles=60 valid=60 reach=60 mveat=0 deat=0 "
     "deat_reach=0 exits=0 planned=8192 unit=4096 hold_ms_max=0 "
     "reads=138798 dt_n=56112 dt_p50_us=45.2 dt_p99_us=247.0 "
     "dt_p999_us=320010.9 nd_n=60628 nd_p50_us=45.0 nd_p99_us=246.1 "
     "nd_p999_us=319764.0 all_n=138798 all_p50_us=45.1 all_p99_us=246.3 "
     "all_p999_us=319936.8\n"),
]


def tail_line(mode="plm", cycles=60, valid=60, deat=0, deat_reach=0,
              dt=(60.0, 100.0, 200.0), nd=(70.0, 400.0, 900.0), n=5000,
              allp=None, nd_n=None):
    allp = allp or nd
    nd_n = n if nd_n is None else nd_n
    return ("FG tail_mode=%s cycles=%d valid=%d reach=%d mveat=0 deat=%d "
            "deat_reach=%d exits=0 planned=8192 unit=4096 hold_ms_max=2 "
            "reads=240000 dt_n=%d dt_p50_us=%.1f dt_p99_us=%.1f "
            "dt_p999_us=%.1f nd_n=%d nd_p50_us=%.1f nd_p99_us=%.1f "
            "nd_p999_us=%.1f all_n=%d all_p50_us=%.1f all_p99_us=%.1f "
            "all_p999_us=%.1f\n" %
            (mode, cycles, valid, valid, deat, deat_reach, n, dt[0], dt[1],
             dt[2], nd_n, nd[0], nd[1], nd[2], n + nd_n, allp[0], allp[1],
             allp[2]))


class Args:
    def __init__(self, test, guest, control=None):
        self.test = test
        self.guest = guest
        self.control = control
        self.repeats = 3
        self.margin = 0.2
        self.min_valid = 0.9
        self.min_reads = 1000


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

    with tempfile.TemporaryDirectory() as d:
        def put(name, text):
            p = os.path.join(d, name)
            with open(p, "w") as f:
                f.write(text)
            return p

        def g1(text, label, status):
            want(v_gplm1(Args("gplm1", put("g1", text))), status, label)

        g1(GOOD_G1, "gplm1 good", PASS)
        # each plant breaks exactly the rule it names, and every rule
        # has a plant
        plants = [
            ("ctratt=0x3c", "ctratt=0x1c", "ctratt bits 2, 3, 4, 5"),
            ("oaes=0x1000", "oaes=0x0", "oaes bit 12"),
            ("nsetidmax=1", "nsetidmax=2", "nsetidmax 1"),
            ("set_endgid=1", "set_endgid=0",
             "CNS 04h one set, NSETID 1, ENDGID 1"),
            ("set_r4krt=4", "set_r4krt=0", "CNS 04h R4KRT > 0"),
            ("set2_numid=0", "set2_numid=1", "CNS 04h from 2 lists none"),
            ("ns_nvmsetid=1", "ns_nvmsetid=0", "namespace NVMSETID 1"),
            ("get13_lpe=0", "get13_lpe=1", "Get 13h LPE 0"),
            ("get14_off=sc-0x2", "get14_off=sc-0x1",
             "Get 14h refused while disabled"),
            ("get13_nsid1=sc-0x2", "get13_nsid1=accepted",
             "Get 13h NSID 1 refused"),
            ("get13_set0=sc-0x2", "get13_set0=accepted",
             "Get 13h NVMSETID 0 refused"),
            ("get14_nd=2", "get14_nd=1", "Get 14h NDWIN after LPE=1"),
            ("set14_wsel0=sc-0x2", "set14_wsel0=accepted",
             "Set 14h WSEL 0 refused"),
            ("log0a_lsi2=sc-0x2", "log0a_lsi2=accepted",
             "log 0Ah LSI 2 refused"),
            ("FG get14_dt=1\n", "", "Get 14h DTWIN"),
            ("dt_entry_plmw=1", "dt_entry_plmw=2",
             "log 0Ah PLMW 1 at DTWIN entry"),
            ("mv_at_plmw=1", "mv_at_plmw=2", "DTWWT units: still DTWIN"),
            ("mv_at_dtwwe=0", "mv_at_dtwwe=64", "DTWWT units: DTWWE fell"),
            ("mv_after_plmw=2", "mv_after_plmw=1", "one more unit: NDWIN"),
            ("mv_after_etyp=0x4000", "mv_after_etyp=0xc000",
             "one more unit: ETYP MVEAT, no DEAT"),
            ("agg_rae_nument=1", "agg_rae_nument=0",
             "log 0Bh NUMENT 1, entry set 1"),
            ("agg_rae_tail_zero=1", "agg_rae_tail_zero=0",
             "log 0Bh past 10 bytes zero"),
            ("read1_etyp=0x4000", "read1_etyp=0x0",
             "log 0Ah read 1 ETYP MVEAT"),
            ("read2_etyp=0x0", "read2_etyp=0x4000", "log 0Ah read 2 ETYP 0"),
            ("agg_after_nument=0", "agg_after_nument=1",
             "log 0Bh NUMENT 0 after the read"),
            ("off_plmw=0", "off_plmw=2", "LPE=0: PLMW 0"),
            ("get14_lpe0=sc-0x2", "get14_lpe0=accepted",
             "LPE=0: Get 14h refused"),
            ("ns_read=ok", "ns_read=errno-5", "namespace still reads"),
            ("nvme_warn_new=0", "nvme_warn_new=2",
             "no new nvme kernel warning"),
        ]
        names = [n for n, _ in gplm1_rules({})]
        for old, new, rule in plants:
            assert GOOD_G1.count(old) == 1, old
            text = GOOD_G1.replace(old, new)
            g1(text, "gplm1 plant: " + rule, FAIL)
            failed = [n for n, ok in gplm1_rules(facts(put("g1", text))[0])
                      if not ok]
            want((failed, ""), [rule], "gplm1 plant breaks only: " + rule)
        miss = sorted(set(names) - set(r for _, _, r in plants))
        want((miss, ""), [], "gplm1 every rule has a plant")
        g1(GOOD_G1.replace("FG_DONE ok", "FG_DONE fail setup-no-tool-nvme"),
           "gplm1 setup", SETUP)
        g1(GOOD_G1.replace("FG_DONE ok", "FG_DONE fail set14_dt-sc-0x2"),
           "gplm1 step failed", FAIL)
        g1(GOOD_G1.replace("FG_DONE ok\n", ""), "gplm1 no end", SETUP)

        hit = set()

        def tl(plm_lines, ctl_lines, label, status, rule=None, **kw):
            gp = put("p", "".join(plm_lines) + "FG_DONE ok\n")
            cp = None
            if ctl_lines is not None:
                cp = [put("c", "".join(ctl_lines) + "FG_DONE ok\n")]
            a = Args("tail", [gp], cp)
            for k, v in kw.items():
                setattr(a, k, v)
            got = v_tail(a)
            want(got, status, label)
            if rule is not None:
                tag = "(rule %d)" % rule
                want((tag in got[1], ""), True, label + " names " + tag)
                hit.add(rule)

        good = [tail_line(dt=(60, 100 + i, 200), nd=(70, 400 + 5 * i, 900))
                for i in range(3)]
        ctl = [tail_line("phantom", dt=(70, 390, 880), nd=(70, 400, 900),
                         allp=(70, 395, 890))] * 3
        tl(good, ctl, "tail good", PASS)
        tl(good[:2], ctl, "tail two of three repeats", INCOMPLETE)
        tl(good, None, "tail no control", INCOMPLETE)
        tl([tail_line(dt=(60, 390, 600), nd=(70, 400, 900))] * 3, ctl,
           "tail no gap", FAIL, rule=3)
        tl(good[:2] + [tail_line(dt=(60, 390, 600), nd=(70, 400, 900))],
           ctl, "tail one repeat without a gap: the median holds", PASS)
        tl(good[:2] + [tail_line(deat=1, deat_reach=1, valid=59)], ctl,
           "tail reachable DEAT", FAIL, rule=2)
        tl(good[:2] + [tail_line(deat=3, deat_reach=0, valid=57)], ctl,
           "tail unreachable DEAT only", PASS)
        tl(good[:2] + [tail_line(valid=50)], ctl, "tail few valid cycles",
           INVALID, rule=1)
        tl(good[:2] + [tail_line(n=500, nd_n=5000)], ctl,
           "tail few DTWIN reads", INVALID, rule=6)
        tl(good, [tail_line("phantom", nd_n=500)] * 3,
           "tail few reads in a control slot", INVALID, rule=6)
        tl(good[:2] + [tail_line(nd_n=3, nd=(2.2e6, 2.3e6, 2.3e6))], ctl,
           "tail few NDWIN reads", PASS)
        tl([tail_line(nd_n=0, nd=(-1, -1, -1))] * 3, ctl,
           "tail no NDWIN read: rule 8 decides", PASS)
        tl(good[:2] + [tail_line(nd_n=0, nd=(-1, -1, -1))], ctl,
           "tail one repeat with no NDWIN read", PASS)
        tl(good, [tail_line("phantom", dt=(70, 200, 880),
                            nd=(70, 400, 900))] * 3,
           "tail control shows a gap", INVALID, rule=5)
        wide = [tail_line(dt=(60, 100, 500), nd=(70, 400, 900)),
                tail_line(dt=(60, 400, 500), nd=(70, 410, 900)),
                tail_line(dt=(60, 110, 500), nd=(70, 900, 1500))]
        tl(wide, ctl, "tail gap within the DTWIN spread", FAIL, rule=4,
           margin=0.2)
        tl(good, ctl, "tail stricter margin", FAIL, rule=3, margin=0.8)
        tl(good[:2] + [tail_line(dt=(60, 100, 950), nd=(70, 400, 900))],
           ctl, "tail one repeat with a higher DTWIN p99.9", FAIL, rule=7)
        tl(good[:2] + [tail_line(dt=(60, 100, 900), nd=(70, 400, 900))],
           ctl, "tail one repeat with an equal p99.9", FAIL, rule=7)
        tl(good[:2] + [tail_line(dt=(60, 100, 750), nd=(70, 400, 900))],
           ctl, "tail DTWIN p99.9 near the control p99.9", FAIL, rule=8)
        want((sorted(set(range(1, 9)) - hit), ""), [],
             "tail every rule has a plant")
        # the d760 run: the DTWIN rules hold, the NDWIN stall is reported
        rp = [put("rp%d" % i, ln + "\nFG_DONE ok\n")
              for i, ln in enumerate(REAL_PLM)]
        rc = [put("rc%d" % i, ln + "\nFG_DONE ok\n")
              for i, ln in enumerate(REAL_OFF)]
        a = Args("tail", rp, rc)
        a.repeats = 5
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            got = v_tail(a)
        want(got, PASS, "tail d760 run")
        log = buf.getvalue()
        want((all(("NDWIN reads 649" in got[1],
                   "longest NDWIN read 2658669.8 us" in got[1],
                   "NDWIN plm-4: 3 reads, read p50 2227786.8 us, max "
                   "2239151.9 us; longest Set 14h hold (held background "
                   "work) 2631 ms" in log)), ""), True,
             "tail d760 run reports the NDWIN stall")
    print("plm-verdict self-test: %s (%d ok, %d failed)" %
          ("PASS" if not bad else "FAIL", ok, len(bad)))
    return 0 if not bad else 1


def parse(argv):
    p = argparse.ArgumentParser(prog="plm-verdict.py")
    p.add_argument("test", choices=("gplm1", "tail"))
    p.add_argument("--guest", nargs="+", required=True)
    p.add_argument("--control", nargs="+")
    p.add_argument("--repeats", type=int, default=5)
    p.add_argument("--margin", type=float, default=0.2)
    p.add_argument("--min-valid", type=float, default=0.9)
    p.add_argument("--min-reads", type=int, default=1000)
    a = p.parse_args(argv)
    if a.test == "gplm1" and len(a.guest) != 1:
        p.error("gplm1 takes one --guest file")
    if a.test == "gplm1":
        a.guest = a.guest[0]
    if not (0 < a.margin < 1 and 0 < a.min_valid <= 1 and a.repeats > 0):
        p.error("--margin and --min-valid must be in (0, 1]")
    return a


def main(argv):
    if argv == ["--self-test"]:
        return self_test()
    try:
        a = parse(argv)
        status, why = (v_gplm1 if a.test == "gplm1" else v_tail)(a)
    except (ValueError, KeyError, TypeError, OSError) as e:
        print("plm-verdict: %s" % e, file=sys.stderr)
        return 2
    print("VERDICT %s %s %s" % (a.test, status, why))
    return EXIT.get(status, 3)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
