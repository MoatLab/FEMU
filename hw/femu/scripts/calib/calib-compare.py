#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Compare FEMU against a drive, metric by metric, with an interval.

Each side is a dataset folder in the format of calib-dataset.py: per
condition id, replicate runs, each with one fio JSON output per time
block, and a WAF file for the WAF jobs. Both sides go through the same
audit as the fit: the pinned matrix, the split labels, one row per id,
the file hashes and the generated fio job of each id.

Per metric, the error is e = (F - R) / R, with F the FEMU value and R the
drive value. A block bootstrap over the replicates and their blocks
gives a 90% interval of e. The decision is an equivalence rule:

  interval inside [-tol, +tol]  PASS
  interval outside the band     FAIL
  else                          INCONCLUSIVE

A metric is PENDING when the matrix marks its trace pending, and
RATE-LIMITED when the fio rate cap held its operation back on a side.
A metric is NOISY when the drive interval alone is wider than the band,
UNDER-FLOOR when a percentile has fewer than 100 samples above it in a
run (exact arithmetic), SAMPLING when a side lacks the replicates and
blocks of the matrix "sampling" entry, NOT-VALID when a row of either
side is marked not valid (a thermal pause, a saturated emulator),
NOT-AVAILABLE when a side has no qualified WAF counter, and MISSING when
a side lacks it. calib-matrix.json lists the
metrics and tolerances of each family; a metric with no tolerance is
reported only.

The result follows the rules of the design note, section 2.7: INVALID
when a control result is missing or wrong, else FAIL when a required
metric fails, else INCOMPLETE when one is not decidable or a family has
no PASS, else INCONCLUSIVE when one is open, else PASS.

Usage:
    calib-compare.py --drive DIR --femu DIR [--matrix FILE]
                     [--controls FILE] [--lockbox] [--draws N] [--json FILE]
    calib-compare.py --self-test

Exit status: 0 for PASS, 1 for any other result, 2 when an input is
refused (hash, job identity, or a lockbox row without --lockbox).
"""

import argparse
import hashlib
import importlib.util
import json
import os
import random
import subprocess
import sys
import tempfile
from fractions import Fraction

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "calib_dataset", os.path.join(HERE, "calib-dataset.py"))
ds = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ds)
Refused = ds.Refused
load_json = ds.load_json
DEFAULT_MATRIX = os.path.join(HERE, "calib-matrix.json")

PCT_KEY = {
    "p50": "50.000000",
    "p90": "90.000000",
    "p99": "99.000000",
    "p99.9": "99.900000",
    "p99.99": "99.990000",
}
# exact levels: 100000 samples at p99.9 leave exactly 100 above
PCT_LEVEL = {k: Fraction(k[1:]) for k in PCT_KEY}
SAMPLE_FLOOR = 100
CONTROLS = ("C1a", "C1b", "C1c", "C1d", "C2", "C3", "C4", "C5", "C5n")
COVERAGE = (("J2",), ("J3",), ("J7", "J8"), ("J9",), ("T1", "T2"))
UNDECIDED = ("NOISY", "UNDER-FLOOR", "SAMPLING", "NOT-VALID", "MISSING",
             "RATE-LIMITED", "PENDING")


def load_side(matrix_path, dataset, lockbox):
    splits = ("fit", "held") + (("lockbox",) if lockbox else ())
    try:
        return ds.audit(matrix_path, dataset, splits)
    except Refused as e:
        if "lockbox" in str(e) and not lockbox:
            raise Refused(f"{e}; a lockbox row stays unread until the "
                          "owner accepts the profile (--lockbox)")
        raise


# ---------------------------------------------------------------- metrics

def block_value(doc, metric):
    op, _, what = metric.partition(".")
    d = doc["jobs"][0][op]
    if what in PCT_KEY:
        return float(d["clat_ns"]["percentile"][PCT_KEY[what]])
    if what == "iops":
        return float(d["iops"])
    if what == "bw":
        return float(d["bw_bytes"])
    raise ValueError(f"unknown metric {metric}")


def run_blocks(row, metric):
    """Per run, the list of per-block values of @metric."""
    if metric == "waf":
        return [list(r["waf"] or []) for r in row["runs"]]
    if metric.startswith("trace."):
        raise KeyError(metric)
    return [[block_value(b, metric) for b in r["blocks"]]
            for r in row["runs"]]


def samples_above(n, level):
    return n * (1 - level / 100)


def floor_ok(row, metric):
    """Each run needs SAMPLE_FLOOR samples above the percentile."""
    what = metric.partition(".")[2]
    if what not in PCT_LEVEL:
        return True, None
    op = metric.partition(".")[0]
    worst = None
    for r in row["runs"]:
        n = sum(b["jobs"][0][op]["clat_ns"].get("N", 0) for b in r["blocks"])
        above = samples_above(int(n), PCT_LEVEL[what])
        worst = above if worst is None else min(worst, above)
    return worst is not None and worst >= SAMPLE_FLOOR, \
        None if worst is None else float(worst)


def rel_err(f, r):
    return (f - r) / r


def mean(xs):
    return sum(xs) / len(xs)


def resample(runs, rng):
    """One block bootstrap draw: runs with replacement, then blocks."""
    picked = []
    for run in rng.choices(runs, k=len(runs)):
        picked.extend(rng.choices(run, k=len(run)))
    return mean(picked)


def quantile(sorted_xs, q):
    return sorted_xs[int(q * (len(sorted_xs) - 1))]


def decide(lo, hi, tol):
    if lo >= -tol and hi <= tol:
        return "PASS"
    if hi < -tol or lo > tol:
        return "FAIL"
    return "INCONCLUSIVE"


def compare_metric(fr, rr, tol_pct, draws, rng):
    """Verdict of one metric from FEMU runs @fr and drive runs @rr."""
    f0 = mean([x for run in fr for x in run])
    r0 = mean([x for run in rr for x in run])
    es, rs = [], []
    for _ in range(draws):
        f = resample(fr, rng)
        r = resample(rr, rng)
        es.append(rel_err(f, r))
        rs.append(rel_err(resample(rr, rng), r0))
    es.sort()
    rs.sort()
    lo, hi = quantile(es, 0.05), quantile(es, 0.95)
    out = {"e": rel_err(f0, r0), "lo": lo, "hi": hi,
           "drive_lo": quantile(rs, 0.05), "drive_hi": quantile(rs, 0.95),
           "direction": "higher" if f0 > r0 else "lower"}
    if tol_pct is None:
        out["verdict"] = "REPORT"
        return out
    tol = tol_pct / 100.0
    out["tol"] = tol
    if out["drive_hi"] - out["drive_lo"] > 2 * tol:
        out["verdict"] = "NOISY"
    else:
        out["verdict"] = decide(lo, hi, tol)
    return out


def compare(matrix_path, drive_dir, femu_dir, lockbox=False, draws=2000,
            seed=1, controls=None):
    dside = load_side(matrix_path, drive_dir, lockbox)
    fside = load_side(matrix_path, femu_dir, lockbox)
    if dside["side"] != "drive" or fside["side"] != "femu":
        raise Refused(f"sides are {dside['side']} and {fside['side']}; "
                      "expected drive and femu")
    if dside["fio_rate"] != fside["fio_rate"]:
        raise Refused(f"fio rate caps differ: drive '{dside['fio_rate']}', "
                      f"femu '{fside['fio_rate']}'")
    matrix = dside["matrix"]
    drive, femu = dside["rows"], fside["rows"]
    tols = matrix["tolerances_pct"]
    rng = random.Random(seed)
    splits = ("fit", "held") + (("lockbox",) if lockbox else ())
    results = []
    for c in matrix["conditions"]:
        if c["split"] not in splits:
            continue
        for metric, tkey in matrix["families"][c["family"]]["metrics"]:
            tol_pct = tols[tkey]
            rec = {"id": c["id"], "family": c["family"], "split": c["split"],
                   "metric": metric, "tol_pct": tol_pct,
                   "required": tol_pct is not None}
            results.append(rec)
            d, f = drive.get(c["id"]), femu.get(c["id"])
            if any(x and x["pending"] for x in (d, f)):
                rec["verdict"] = "PENDING"
                continue
            # WAF comes from the writes: a write cap holds it back too
            op = "write" if metric == "waf" else metric.partition(".")[0]
            if any(x and op in x["rate_limited"] for x in (d, f)):
                rec["verdict"] = "RATE-LIMITED"
                continue
            if metric == "waf" and any(
                    x["waf_unavailable"] for side in (d, f) if side
                    for x in side["runs"]):
                rec["verdict"] = "NOT-AVAILABLE"
                continue
            if any(x and x["sampling"] != "ok" for x in (d, f)):
                rec["verdict"] = "SAMPLING"
                rec["sampling"] = [d["sampling"] if d else None,
                                   f["sampling"] if f else None]
                continue
            try:
                rr = run_blocks(d, metric) if d else []
                fr = run_blocks(f, metric) if f else []
            except (KeyError, TypeError):
                rr, fr = [], []
            if not rr or not fr or not all(rr) or not all(fr):
                rec["verdict"] = "MISSING"
                continue
            if not (d["valid"] and f["valid"]):
                rec["verdict"] = "NOT-VALID"
                continue
            ok_d, nd = floor_ok(d, metric)
            ok_f, nf = floor_ok(f, metric)
            rec["samples_above"] = [nd, nf]
            if not (ok_d and ok_f):
                rec["verdict"] = "UNDER-FLOOR" if tol_pct is not None \
                    else "REPORT"
                continue
            rec.update(compare_metric(fr, rr, tol_pct, draws, rng))
    return results, overall(results, controls)


def overall(results, controls):
    req = [r for r in results if r["required"]]
    why = []
    if controls is None:
        why.append("controls not given")
    else:
        bad = [c for c in CONTROLS if controls.get(c) != "expected"]
        if bad:
            why.append("controls not as expected: " + ", ".join(bad))
    fails = [r for r in req if r["verdict"] == "FAIL"]
    undecided = [r for r in req if r["verdict"] in UNDECIDED]
    unavailable = [r for r in req if r["verdict"] == "NOT-AVAILABLE"]
    opened = [r for r in req if r["verdict"] == "INCONCLUSIVE"]
    uncovered = [g for g in COVERAGE if not any(
        r["verdict"] == "PASS" for r in req if r["family"] in g)]
    gap = {}
    for s in ("fit", "held"):
        es = [abs(r["e"]) for r in req if r["split"] == s and "e" in r]
        gap[s] = mean(es) if es else None
    if why:
        verdict = "INVALID"
    elif fails:
        verdict = "FAIL"
    elif undecided or uncovered:
        verdict = "INCOMPLETE"
    elif opened:
        verdict = "INCONCLUSIVE"
    else:
        verdict = "PASS"
    return {"verdict": verdict, "why": why, "fail": len(fails),
            "undecided": len(undecided), "inconclusive": len(opened),
            "not_available": len(unavailable),
            "uncovered": ["/".join(g) for g in uncovered],
            "mean_abs_e": gap}


def print_table(results, summary):
    for r in results:
        if "e" in r:
            print(f"{r['id']:24} {r['metric']:12} {r['split']:5} "
                  f"e={r['e'] * 100:+7.2f}% [{r['lo'] * 100:+7.2f}, "
                  f"{r['hi'] * 100:+7.2f}] tol={r['tol_pct']} "
                  f"{r['verdict']}")
        else:
            print(f"{r['id']:24} {r['metric']:12} {r['split']:5} "
                  f"{r['verdict']}")
    print(f"RESULT {summary['verdict']} " + json.dumps(
        {k: v for k, v in summary.items() if k != "verdict"}))


# ---------------------------------------------------------------- self-test

BASE = {"p50": 80000.0, "p90": 100000.0, "p99": 120000.0,
        "p99.9": 200000.0, "p99.99": 400000.0, "iops": 10000.0,
        "bw": 1.0e9}


def synth_side(matrix, out, spec, nrep=3, nblk=10, side="drive",
               rate=ds.DEFAULT_RATE):
    """@spec maps id -> {"scale": {metric: x}, "noise": {metric: amp},
    "n": samples per block, "waf": value, "valid": bool}."""
    dspec = {}
    for cid, sp in spec.items():
        vals = {f"{op}.{k}": base * sp.get("scale", {}).get(f"{op}.{k}", 1.0)
                for op in ("read", "write") for k, base in BASE.items()}
        dspec[cid] = dict(sp, values=vals)
    return ds.synth(matrix, out, dspec, side=side, nrep=nrep, nblk=nblk,
                    rate=rate)


def self_test():
    fails = []

    def check(ok, what):
        print(("ok    " if ok else "FAIL  ") + what)
        if not ok:
            fails.append(what)

    matrix = ds.read_matrix(DEFAULT_MATRIX)
    all_ctl = {c: "expected" for c in CONTROLS}

    def pick(results, cid, metric):
        return [r for r in results if r["id"] == cid
                and r["metric"] == metric][0]

    with tempfile.TemporaryDirectory() as tmp:
        # per-metric cases
        dspec = {
            "J1-randread-4k-qd1": {},
            "J2-randread-4k-qd8": {},
            "J2-randread-4k-qd16": {"noise": {"read.p50": 0.06}},
            "J3-read-16k-qd32": {"noise": {"read.bw": 0.40}},
            "J9-mix70-4k-qd32": {"n": 50},
            "J7-randwrite-4k-a100": {"waf": 3.0},
            "J2-randread-4k-qd2": {},
        }
        fspec = {
            "J1-randread-4k-qd1": {"scale": {"read.p50": 1.05,
                                             "read.p99.9": 2.0}},
            "J2-randread-4k-qd8": {"scale": {"read.iops": 1.10}},
            "J2-randread-4k-qd16": {"scale": {"read.p50": 1.20},
                                    "noise": {"read.p50": 0.06}},
            "J3-read-16k-qd32": {},
            "J9-mix70-4k-qd32": {"n": 50},
            "J7-randwrite-4k-a100": {"waf": 3.06},
            "J2-randread-4k-qd2": {"valid": False},
        }
        d1, f1 = os.path.join(tmp, "d1"), os.path.join(tmp, "f1")
        synth_side(DEFAULT_MATRIX, d1, dspec)
        synth_side(DEFAULT_MATRIX, f1, fspec, side="femu")
        res, summ = compare(DEFAULT_MATRIX, d1, f1, draws=400,
                            controls=all_ctl)
        r = pick(res, "J1-randread-4k-qd1", "read.p50")
        check(r["verdict"] == "PASS" and abs(r["e"] - 0.05) < 0.005,
              f"J1 p50 at +5% PASS (e={r['e'] * 100:+.2f}%)")
        r = pick(res, "J1-randread-4k-qd1", "read.p99")
        check(r["verdict"] == "PASS" and abs(r["e"]) < 0.005,
              f"J1 p99 equal PASS (e={r['e'] * 100:+.2f}%)")
        r = pick(res, "J1-randread-4k-qd1", "read.p99.9")
        check(r["verdict"] == "FAIL" and abs(r["e"] - 1.0) < 0.01
              and r["direction"] == "higher",
              f"J1 p99.9 at 2x FAIL, higher (e={r['e'] * 100:+.2f}%)")
        r = pick(res, "J1-randread-4k-qd1", "read.p99.99")
        check(r["verdict"] == "REPORT", "J1 p99.99 is report only")
        r = pick(res, "J2-randread-4k-qd8", "read.iops")
        check(r["verdict"] == "PASS" and abs(r["e"] - 0.10) < 0.005,
              f"J2 QD8 rate at +10% PASS at 15% (e={r['e'] * 100:+.2f}%)")
        r = pick(res, "J2-randread-4k-qd16", "read.p50")
        check(r["verdict"] == "INCONCLUSIVE" and r["lo"] < 0.20 < r["hi"],
              f"J2 QD16 p50 at +20% INCONCLUSIVE "
              f"([{r['lo'] * 100:+.1f}, {r['hi'] * 100:+.1f}])")
        r = pick(res, "J3-read-16k-qd32", "read.bw")
        check(r["verdict"] == "NOISY", "J3 16K with a wide drive spread "
              "is NOISY")
        r = pick(res, "J9-mix70-4k-qd32", "read.p99")
        above = [round(x, 1) for x in r.get("samples_above") or []]
        check(r["verdict"] == "UNDER-FLOOR",
              f"J9 p99 with {above} samples above is UNDER-FLOOR")
        r = pick(res, "J9-mix70-4k-qd32", "read.p50")
        check(r["verdict"] == "PASS", "J9 p50 with the same runs is "
              "above the floor")
        r = pick(res, "J7-randwrite-4k-a100", "waf")
        check(r["verdict"] == "PASS" and abs(r["e"] - 0.02) < 0.002,
              f"J7 WAF at +2% PASS (e={r['e'] * 100:+.2f}%)")
        r = pick(res, "J2-randread-4k-qd2", "read.p50")
        check(r["verdict"] == "NOT-VALID", "a saturated FEMU row is "
              "NOT-VALID")
        r = pick(res, "J8-randwrite-4k-a93", "waf")
        check(r["verdict"] == "MISSING", "an absent row is MISSING")
        check(summ["verdict"] == "FAIL", "one required FAIL makes the "
              f"result FAIL ({summ['verdict']})")

        # whole-result cases: every required row present
        req = [c["id"] for c in matrix["conditions"]
               if c["split"] in ("fit", "held")]
        full_d = {cid: ({"waf": 2.0} if conds_family(matrix, cid)
                        in ("J7", "J8", "T1", "T2") else {}) for cid in req}
        full_f = {cid: dict(v, scale={m: 1.02 for m in metric_names()},
                            **({"waf": 2.04} if "waf" in v else {}))
                  for cid, v in full_d.items()}
        d2, f2 = os.path.join(tmp, "d2"), os.path.join(tmp, "f2")
        synth_side(DEFAULT_MATRIX, d2, full_d)
        synth_side(DEFAULT_MATRIX, f2, full_f, side="femu")
        res, summ = compare(DEFAULT_MATRIX, d2, f2, draws=200,
                            controls=all_ctl)
        pend = sorted({r["id"] for r in res if r["verdict"] == "PENDING"})
        others = [r for r in res if r["required"] and r["verdict"] != "PASS"
                  and r["verdict"] != "PENDING"]
        check(summ["verdict"] == "INCOMPLETE" and pend == ["T1-alibaba-2020"]
              and not others, "all metrics at +2%, trace pending: "
              f"{summ['verdict']}, PENDING {pend}")

        def refused(drv, fem, what, mpath=DEFAULT_MATRIX):
            try:
                compare(mpath, drv, fem, draws=10, controls=all_ctl)
            except Refused as e:
                check(True, f"{what}: refused ({e})")
                return
            check(False, f"{what}: not refused")

        # 10: a ready trace needs its frozen iolog, volume, window and
        # the replay options that fio really ran
        iolog = (b"fio version 2 iolog\n/dev/x add\n/dev/x open\n"
                 b"/dev/x write 0 4096\n/dev/x read 4096 4096\n"
                 b"/dev/x close\n")
        check(ds.iolog_records(iolog) == 2, "the self-test iolog holds 2 "
              "I/O records")
        replay = {"ioengine": "io_uring", "iodepth": "32",
                  "replay_no_stall": "0", "read_iolog": "iolog.bin"}

        def ready(name, log, rp):
            path = os.path.join(tmp, name)
            mt = json.loads(json.dumps(matrix))
            for c in mt["conditions"]:
                if c["id"] == "T1-alibaba-2020":
                    c["trace"].update(
                        status="ready", volume="v1", window="0-3600",
                        iolog_sha256=hashlib.sha256(log).hexdigest(),
                        replay=rp)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(mt, f)
            return path
        rm = ready("ready.json", iolog, replay)
        tid = "T1-alibaba-2020"
        full_dt = dict(full_d, **{tid: dict(full_d[tid], iolog=iolog)})
        full_ft = dict(full_f, **{tid: dict(full_f[tid], iolog=iolog)})
        d6, f6 = os.path.join(tmp, "d6"), os.path.join(tmp, "f6")
        synth_side(rm, d6, full_dt)
        synth_side(rm, f6, full_ft, side="femu")
        _, summ = compare(rm, d6, f6, draws=200, controls=all_ctl)
        check(summ["verdict"] == "PASS", "the same data with a ready, "
              f"authenticated trace: {summ['verdict']}")
        dn, fn = os.path.join(tmp, "dn"), os.path.join(tmp, "fn")
        synth_side(rm, dn, full_d)
        synth_side(rm, fn, full_f, side="femu")
        refused(dn, fn, "a ready trace row without its iolog file", rm)
        dw, fw = os.path.join(tmp, "dw"), os.path.join(tmp, "fw")
        synth_side(rm, dw, dict(full_d, **{tid: dict(full_d[tid],
                                                     iolog=b"other\n")}))
        synth_side(rm, fw, full_ft, side="femu")
        refused(dw, fw, "a ready trace with another iolog", rm)
        man = load_json(os.path.join(f6, "manifest.json"))
        row = [r for r in man["rows"] if r["id"] == tid][0]
        for blk in row["runs"][0]["blocks"]:
            bp = os.path.join(f6, blk["path"])
            doc = load_json(bp)
            doc["jobs"][0]["job options"].update(rw="randread", iodepth="1")
            with open(bp, "w") as f:
                json.dump(doc, f)
            blk["sha256"] = ds.sha256_file(bp)
        ds.write_manifest(f6, man)
        refused(d6, f6, "a trace replay with rw=randread, QD1", rm)
        # 3 (r4): the replay must select the frozen iolog, with records
        for what, log, rp in (
                ("no read_iolog", iolog,
                 {k: v for k, v in replay.items() if k != "read_iolog"}),
                ("read_iolog of another file", iolog,
                 dict(replay, read_iolog="other.bin")),
                ("an iolog with no I/O record", b"fio version 2 iolog\n",
                 replay)):
            mx = ready(f"ready-{len(what)}.json", log, rp)
            dz = os.path.join(tmp, f"dz{len(what)}")
            fz = os.path.join(tmp, f"fz{len(what)}")
            synth_side(mx, dz, dict(full_d, **{tid: dict(full_d[tid],
                                                         iolog=log)}))
            synth_side(mx, fz, dict(full_f, **{tid: dict(full_f[tid],
                                                         iolog=log)}),
                       side="femu")
            refused(dz, fz, f"a ready trace with {what}", mx)
        fr = f6 + "r"
        synth_side(rm, fr, full_ft, side="femu")
        man = load_json(os.path.join(fr, "manifest.json"))
        row = [r for r in man["rows"] if r["id"] == tid][0]
        for blk in row["runs"][0]["blocks"]:
            bp = os.path.join(fr, blk["path"])
            doc = load_json(bp)
            del doc["jobs"][0]["job options"]["read_iolog"]
            with open(bp, "w") as f:
                json.dump(doc, f)
            blk["sha256"] = ds.sha256_file(bp)
        ds.write_manifest(fr, man)
        refused(d6, fr, "a fio output that ran no read_iolog", rm)
        synth_side(rm, f6 + "x", full_ft, side="femu")
        f6 = f6 + "x"
        man = load_json(os.path.join(f6, "manifest.json"))
        for r in man["rows"]:
            if r["id"] == "T1-alibaba-2020":
                r["trace"]["window"] = "0-7200"
        ds.write_manifest(f6, man)
        try:
            compare(rm, d6, f6, draws=10, controls=all_ctl)
            check(False, "a trace row of another window is refused")
        except Refused as e:
            check(True, f"a trace row of another window is refused ({e})")
        _, summ = compare(DEFAULT_MATRIX, d2, f2, draws=200, controls=None)
        check(summ["verdict"] == "INVALID", "no control results: "
              f"{summ['verdict']}")
        bad = dict(all_ctl, C1b="not red")
        _, summ = compare(DEFAULT_MATRIX, d2, f2, draws=200, controls=bad)
        check(summ["verdict"] == "INVALID", "a control not as expected: "
              f"{summ['verdict']}")

        # refusals
        lb = os.path.join(tmp, "lb")
        synth_side(DEFAULT_MATRIX, lb, {"J9-mix70-4k-qd8": {}},
                   side="femu")
        try:
            compare(DEFAULT_MATRIX, d2, lb, draws=10, controls=all_ctl)
            check(False, "a lockbox row without --lockbox is refused")
        except Refused:
            check(True, "a lockbox row without --lockbox is refused")
        victim = os.path.join(d1, "J1-randread-4k-qd1", "r1", "b01.json")
        with open(victim, "a") as f:
            f.write(" ")
        try:
            compare(DEFAULT_MATRIX, d1, f1, draws=10, controls=all_ctl)
            check(False, "a changed file is refused")
        except Refused:
            check(True, "a changed file is refused")

        # 11: both sides get the audit of the fit
        one = {"J1-randread-4k-qd1": {}}
        d3, f3 = os.path.join(tmp, "d3"), os.path.join(tmp, "f3")
        synth_side(DEFAULT_MATRIX, d3, one)
        synth_side(DEFAULT_MATRIX, f3, one, side="femu")
        mat = os.path.join(tmp, "matrix.json")
        with open(DEFAULT_MATRIX, encoding="utf-8") as f:
            text = f.read()
        with open(mat, "w", encoding="utf-8") as f:
            f.write(text.replace('"qd1_p50": 10', '"qd1_p50": 50'))
        refused(d3, f3, "a dataset of another matrix", mat)
        man = load_json(os.path.join(f3, "manifest.json"))
        man["rows"].append(man["rows"][0])
        ds.write_manifest(f3, man)
        refused(d3, f3, "one id given twice")
        man["rows"].pop()
        man["rows"][0]["split"] = "held"
        ds.write_manifest(f3, man)
        refused(d3, f3, "a fit row relabelled held")
        man["rows"][0]["split"] = "fit"
        ds.write_manifest(f3, man)
        blk = os.path.join(f3, man["rows"][0]["runs"][0]["blocks"][0]["path"])
        doc = load_json(blk)
        doc["jobs"][0]["job options"]["iodepth"] = "2"
        with open(blk, "w") as f:
            json.dump(doc, f)
        man["rows"][0]["runs"][0]["blocks"][0]["sha256"] = ds.sha256_file(blk)
        ds.write_manifest(f3, man)
        refused(d3, f3, "a fio output of another queue depth")
        refused(d3, d3, "two drive sides")

        # 12: 3 x 10 blocks, each block once
        d4, f4 = os.path.join(tmp, "d4"), os.path.join(tmp, "f4")
        synth_side(DEFAULT_MATRIX, d4, one, nrep=1, nblk=1)
        synth_side(DEFAULT_MATRIX, f4, one, nrep=1, nblk=1, side="femu")
        res, summ = compare(DEFAULT_MATRIX, d4, f4, draws=50,
                            controls=all_ctl)
        r = pick(res, "J1-randread-4k-qd1", "read.p50")
        check(r["verdict"] == "SAMPLING", f"one block per side is "
              f"{r['verdict']}, not a zero-width PASS")
        d5, f5 = os.path.join(tmp, "d5"), os.path.join(tmp, "f5")
        synth_side(DEFAULT_MATRIX, d5, one, nrep=2)
        synth_side(DEFAULT_MATRIX, f5, one, side="femu")
        res, _ = compare(DEFAULT_MATRIX, d5, f5, draws=50, controls=all_ctl)
        r = pick(res, "J1-randread-4k-qd1", "read.p50")
        check(r["verdict"] == "SAMPLING", f"2 of 3 drive replicates is "
              f"{r['verdict']}")
        man = load_json(os.path.join(d4, "manifest.json"))
        b0 = man["rows"][0]["runs"][0]["blocks"][0]
        man["rows"][0]["runs"][0]["blocks"] = [b0] * 10
        man["rows"][0]["runs"] = [man["rows"][0]["runs"][0]] * 3
        ds.write_manifest(d4, man)
        refused(d4, f4, "one block given 30 times")

        # 13: a tail regression on a held J2 row fails the result
        r = pick(compare(DEFAULT_MATRIX, d2, f2, draws=50,
                         controls=all_ctl)[0], "J2-randread-4k-qd8",
                 "read.p99.9")
        check(r["required"] and r["verdict"] == "PASS",
              "J2 p99.9 is a required metric")
        tail = os.path.join(tmp, "ftail")
        full_t = dict(full_f)
        full_t["J2-randread-4k-qd8"] = dict(
            full_f["J2-randread-4k-qd8"],
            scale=dict(full_f["J2-randread-4k-qd8"]["scale"],
                       **{"read.p99.9": 3.0}))
        synth_side(DEFAULT_MATRIX, tail, full_t, side="femu")
        _, summ = compare(DEFAULT_MATRIX, d2, tail, draws=200,
                          controls=all_ctl)
        check(summ["verdict"] == "FAIL", "a 3x p99.9 on held J2 QD8 makes "
              f"the result {summ['verdict']}")
        fams = matrix["families"]
        miss = [f for f in fams if f != "J0" and not any(
            m.endswith(".p99.9") for m, _ in fams[f]["metrics"])]
        twr = [f for f in ("T1", "T2") if ["write.p99", "other_p50_p99"]
               not in fams[f]["metrics"]]
        check(not miss and not twr, "every job family has p99.9 and the "
              "traces have write latency")

        # 16: the floor is exact at the boundary
        rowof = lambda n: {"runs": [{"blocks": [{"jobs": [{"read": {
            "clat_ns": {"N": n}}}]}]}]}
        ok_a, na = floor_ok(rowof(100000), "read.p99.9")
        ok_b, nb = floor_ok(rowof(99999), "read.p99.9")
        check(ok_a and not ok_b, f"p99.9 floor: 100000 samples pass "
              f"({na}), 99999 fail ({nb})")
        flt = 100000 * (1.0 - 99.9 / 100.0)
        check(flt < SAMPLE_FLOOR, f"control: float arithmetic gives "
              f"{flt!r} < 100")

        # 7: one rate cap on both sides, recorded in every block
        d7, f7 = os.path.join(tmp, "d7"), os.path.join(tmp, "f7")
        synth_side(DEFAULT_MATRIX, d7, one, rate=",1000000,1000000")
        synth_side(DEFAULT_MATRIX, f7, one, side="femu")
        refused(d7, f7, "fio rate caps of 1e6 and 8e9 B/s")
        man = load_json(os.path.join(f7, "manifest.json"))
        man["fio_rate"] = ",1000000,1000000"
        ds.write_manifest(f7, man)
        refused(d7, f7, "a block whose rate differs from the manifest")
        d8, f8 = os.path.join(tmp, "d8"), os.path.join(tmp, "f8")
        wr = {"J5-write-128k-qd32": {}}
        synth_side(DEFAULT_MATRIX, d8, wr, rate=",1100000000,1100000000")
        synth_side(DEFAULT_MATRIX, f8, wr, side="femu",
                   rate=",1100000000,1100000000")
        r = pick(compare(DEFAULT_MATRIX, d8, f8, draws=50,
                         controls=all_ctl)[0], "J5-write-128k-qd32",
                 "write.bw")
        check(r["verdict"] == "RATE-LIMITED", "1e9 B/s writes under a "
              f"1.1e9 B/s cap are {r['verdict']}")
        d9, f9 = os.path.join(tmp, "d9"), os.path.join(tmp, "f9")
        synth_side(DEFAULT_MATRIX, d9, wr)
        synth_side(DEFAULT_MATRIX, f9, wr, side="femu")
        r = pick(compare(DEFAULT_MATRIX, d9, f9, draws=50,
                         controls=all_ctl)[0], "J5-write-128k-qd32",
                 "write.bw")
        check(r["verdict"] == "PASS", "control: the same writes under the "
              f"8e9 B/s cap are {r['verdict']}")

        refused_rate = os.path.join(tmp, "dsc")
        synth_side(DEFAULT_MATRIX, refused_rate, wr, rate="1000000000")
        synth_side(DEFAULT_MATRIX, refused_rate + "f", wr, side="femu",
                   rate="1000000000")
        refused(refused_rate, refused_rate + "f",
                "a scalar rate 1000000000 (fio applies it to writes too)")

        # 10 (r3): a write cap holds WAF back too
        jw = {"J7-randwrite-4k-a100": {"waf": 2.0,
                                       "scale": {"write.bw": 1.05}}}
        dj, fj = os.path.join(tmp, "dj"), os.path.join(tmp, "fj")
        synth_side(DEFAULT_MATRIX, dj, jw, rate=",1100000000,1100000000")
        synth_side(DEFAULT_MATRIX, fj, jw, side="femu",
                   rate=",1100000000,1100000000")
        r = pick(compare(DEFAULT_MATRIX, dj, fj, draws=50,
                         controls=all_ctl)[0], "J7-randwrite-4k-a100", "waf")
        check(r["verdict"] == "RATE-LIMITED", "WAF of writes at the cap is "
              f"{r['verdict']}")

        # 8 (r3): a row marked not valid on the drive side is not judged
        dv, fv = os.path.join(tmp, "dv"), os.path.join(tmp, "fv")
        synth_side(DEFAULT_MATRIX, dv, {"J1-randread-4k-qd1":
                                        {"valid": False}})
        synth_side(DEFAULT_MATRIX, fv, one, side="femu")
        r = pick(compare(DEFAULT_MATRIX, dv, fv, draws=50,
                         controls=all_ctl)[0], "J1-randread-4k-qd1",
                 "read.p50")
        check(r["verdict"] == "NOT-VALID", "a drive row marked not valid "
              f"is {r['verdict']}")

        # 9 (r3): WAF values must be finite, >= 1 and name their block
        for what, sp in (("-2.0", {"waf_fix": -2.0}),
                         ("NaN", {"waf_fix": float("nan")})):
            dx, fx = os.path.join(tmp, "dx" + what), os.path.join(
                tmp, "fx" + what)
            ws = {"J7-randwrite-4k-a100": dict(sp, waf=2.0)}
            synth_side(DEFAULT_MATRIX, dx, ws)
            synth_side(DEFAULT_MATRIX, fx, ws, side="femu")
            refused(dx, fx, f"WAF values of {what}")
        dk, fk = os.path.join(tmp, "dk"), os.path.join(tmp, "fk")
        ws = {"J7-randwrite-4k-a100": {"waf": 2.0}}
        synth_side(DEFAULT_MATRIX, dk, ws)
        synth_side(DEFAULT_MATRIX, fk, ws, side="femu")
        man = load_json(os.path.join(dk, "manifest.json"))
        ent = man["rows"][0]["runs"][0]["waf"]
        wp = os.path.join(dk, ent["path"])
        doc = load_json(wp)
        doc["waf"][0]["block"], doc["waf"][1]["block"] = \
            doc["waf"][1]["block"], doc["waf"][0]["block"]
        with open(wp, "w") as f:
            json.dump(doc, f)
        ent["sha256"] = ds.sha256_file(wp)
        ds.write_manifest(dk, man)
        refused(dk, fk, "WAF entries of two blocks swapped")

        # 4 (r4): a missing or non-numeric WAF value is input, exit 2
        for what, val in (("missing", None), ("'abc'", "abc"),
                          ("true", True)):
            dm = os.path.join(tmp, f"dm{len(what)}")
            synth_side(DEFAULT_MATRIX, dm, ws)
            man = load_json(os.path.join(dm, "manifest.json"))
            ent = man["rows"][0]["runs"][0]["waf"]
            wp = os.path.join(dm, ent["path"])
            doc = load_json(wp)
            if val is None:
                del doc["waf"][0]["value"]
            else:
                doc["waf"][0]["value"] = val
            with open(wp, "w") as f:
                json.dump(doc, f)
            ent["sha256"] = ds.sha256_file(wp)
            ds.write_manifest(dm, man)
            refused(dm, fk, f"a {what} WAF value")
            rc = subprocess.run(
                [sys.executable, "-I", os.path.abspath(__file__),
                 "--drive", dm, "--femu", fk], capture_output=True,
                text=True, timeout=120)
            check(rc.returncode == 2 and "REFUSED" in rc.stderr,
                  f"the CLI exits {rc.returncode} on a {what} WAF value")

        # 8: one WAF value per fio block
        ws = {"J7-randwrite-4k-a100": {"waf": 2.0, "waf_n": 1}}
        da, fa = os.path.join(tmp, "da"), os.path.join(tmp, "fa")
        synth_side(DEFAULT_MATRIX, da, ws)
        synth_side(DEFAULT_MATRIX, fa, ws, side="femu")
        r = pick(compare(DEFAULT_MATRIX, da, fa, draws=50,
                         controls=all_ctl)[0], "J7-randwrite-4k-a100", "waf")
        check(r["verdict"] == "SAMPLING", "one WAF value per run is "
              f"{r['verdict']}, not a zero-width PASS")

        # 11: a fio output with an error is no evidence
        db, fb = os.path.join(tmp, "db"), os.path.join(tmp, "fb")
        synth_side(DEFAULT_MATRIX, db, one)
        synth_side(DEFAULT_MATRIX, fb, one, side="femu")
        man = load_json(os.path.join(fb, "manifest.json"))
        for run in man["rows"][0]["runs"]:
            for blk in run["blocks"]:
                bp = os.path.join(fb, blk["path"])
                doc = load_json(bp)
                doc["jobs"][0]["error"] = 5
                with open(bp, "w") as f:
                    json.dump(doc, f)
                blk["sha256"] = ds.sha256_file(bp)
        ds.write_manifest(fb, man)
        refused(db, fb, "fio outputs with error 5")

        # a WAF row without a qualified counter is not judged
        wd, wf = os.path.join(tmp, "wd"), os.path.join(tmp, "wf")
        synth_side(DEFAULT_MATRIX, wd, {"J7-randwrite-4k-a100": {}})
        synth_side(DEFAULT_MATRIX, wf, {"J7-randwrite-4k-a100": {"waf": 2.0}},
                   side="femu")
        r = pick(compare(DEFAULT_MATRIX, wd, wf, draws=50,
                         controls=all_ctl)[0], "J7-randwrite-4k-a100", "waf")
        check(r["verdict"] == "NOT-AVAILABLE", "drive WAF unavailable is "
              f"{r['verdict']}")

    print("calib-compare self-test: " + ("FAIL" if fails else "PASS"))
    return 1 if fails else 0


def conds_family(matrix, cid):
    return [c for c in matrix["conditions"] if c["id"] == cid][0]["family"]


def metric_names():
    return [f"{op}.{k}" for op in ("read", "write") for k in BASE]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--drive")
    ap.add_argument("--femu")
    ap.add_argument("--matrix", default=DEFAULT_MATRIX)
    ap.add_argument("--controls", help="JSON map of control id to "
                    "'expected' or another word")
    ap.add_argument("--lockbox", action="store_true")
    ap.add_argument("--draws", type=int, default=2000)
    ap.add_argument("--json", help="write every metric to this file")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    if not a.drive or not a.femu:
        ap.error("--drive and --femu are required")
    try:
        controls = load_json(a.controls) if a.controls else None
        results, summary = compare(a.matrix, a.drive, a.femu, a.lockbox,
                                   a.draws, controls=controls)
    except Refused as e:
        print(f"calib-compare: REFUSED: {e}", file=sys.stderr)
        return 2
    except (OSError, ValueError, KeyError) as e:
        print(f"calib-compare: {e}", file=sys.stderr)
        return 2
    print_table(results, summary)
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump({"results": results, "summary": summary}, f, indent=1)
    return 0 if summary["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
