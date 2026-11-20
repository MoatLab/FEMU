#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Paper models for the FEMU teaching labs (hw/femu/docs/labs/).

The models predict what the labs measure. They are first-order models,
not a copy of the FTL. Each lab page states where a model is known to be
off.

  uniform   WAF of uniform random 4 KiB overwrites on a bbssd device,
            with the two collection thresholds and the 1/8 rule of the
            background pass.
  classes   WAF of a workload with two or more classes of pages, in one
            shared log and in one log per class with the best split of
            the spare lines.
  dftl      miss ratio of the cached mapping table (CMT) of mapping=dftl
            for uniform random access over a working set.

The FIFO log model: a victim line keeps a share u of valid pages, with

    alpha = (1 - u) / (-ln u),   WAF = 1 / (1 - u)

where alpha is the data lines over the lines of the pool. Greedy victim
choice beats FIFO when the fill is low, so the model is high there.

Usage:
    lab-waf-model.py uniform --lines L --fill F [--gc P] [--gc-high P]
                             [--open N]
    lab-waf-model.py classes --pool T --class SHARE:LINES [--class ...]
    lab-waf-model.py dftl --cmt-mb C --ws-mb W [--page-kb 4]
    lab-waf-model.py --self-test
"""

import argparse
import math
import sys

# a background victim needs 1/8 of its pages invalid (bbssd/ftl-line-gc.c)
FLOOR_U = 7 / 8


def alpha_of(u):
    """Data share of the pool at which FIFO victims keep a share u valid."""
    return (1 - u) / (-math.log(u))


def u_of(alpha):
    """Invert alpha_of() by bisection; alpha must be in (0, 1)."""
    lo, hi = 1e-12, 1 - 1e-12
    for _ in range(200):
        mid = (lo + hi) / 2
        if alpha_of(mid) < alpha:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def uniform(lines, fill, gc=75, gc_high=95, opn=1):
    """
    Return (regime, waf, alpha, pool) for uniform random overwrites.

    The background pass keeps (1 - gc/100) x lines free while it can find
    a victim with 1/8 of its pages invalid. When the pool left over is too
    small for that, the free count falls toward the forced threshold and
    the victims sit at the 1/8 limit: WAF 8. When even the forced pool is
    too small, forced collection takes any victim.
    """
    data = fill * lines
    bg_free = int((1 - gc / 100) * lines)
    forced_free = int((1 - gc_high / 100) * lines)
    pool = lines - bg_free - opn
    if pool > 0 and data / pool <= alpha_of(FLOOR_U):
        return "background", 1 / (1 - u_of(data / pool)), data / pool, pool
    pool = lines - forced_free - opn
    if data / pool <= alpha_of(FLOOR_U):
        return "floor", 1 / (1 - FLOOR_U), data / pool, pool
    if data / pool >= 1:
        return "full", math.inf, data / pool, pool
    return "forced", 1 / (1 - u_of(data / pool)), data / pool, pool


def mixed(pool, classes):
    """WAF of one FIFO log that holds every class: classes = [(r, d)]."""
    w = 2.0
    for _ in range(10000):
        nxt = 0.0
        for r, d in classes:
            x = r * pool / (d * w)
            nxt += r / (1 - math.exp(-x))
        if abs(nxt - w) < 1e-12:
            break
        w = (w + nxt) / 2
    return w


def separated(pool, classes, steps=2000):
    """
    Best WAF of one FIFO log per class, over the splits of the pool. Only
    two classes are searched; the split is a grid of `steps` points.
    """
    if len(classes) != 2:
        raise ValueError("separated() takes two classes")
    (r1, d1), (r2, d2) = classes
    best = (math.inf, 0)
    for i in range(1, steps):
        t1 = pool * i / steps
        t2 = pool - t1
        if t1 <= d1 or t2 <= d2:
            continue
        w = r1 / (1 - u_of(d1 / t1)) + r2 / (1 - u_of(d2 / t2))
        best = min(best, (w, t1))
    return best


def dftl(cmt_mb, ws_mb, page_kb=4):
    """Return (tps_cached, mib_per_tp, miss_ratio) for uniform access."""
    page = page_kb * 1024
    tps = int(cmt_mb * 1024 * 1024) // page
    mib_per_tp = (page // 8) * page / (1024 * 1024)
    covered = tps * mib_per_tp
    miss = max(0.0, 1 - covered / ws_mb)
    return tps, mib_per_tp, miss


def self_test():
    bad = 0
    checks = [
        ("alpha at the 1/8 limit", abs(alpha_of(FLOOR_U) - 0.9361) < 1e-3),
        ("u_of inverts alpha_of", abs(u_of(alpha_of(0.6)) - 0.6) < 1e-9),
        # tutorial 02: op_pcent=25, gc_thres_pcent 75 -> WAF 8 (measured 8.017)
        ("floor regime", uniform(128, 0.8, 75)[0] == "floor"),
        # tutorial 02: op_pcent=7 at 90 -> forced (measured 43.9)
        ("forced regime", uniform(128, 100 / 107, 90)[0] == "forced"),
        ("forced WAF", 40 < uniform(128, 100 / 107, 90)[1] < 48),
        ("background regime", uniform(128, 0.8, 95)[0] == "background"),
        ("one class mixed equals uniform",
         abs(mixed(121, [(1.0, 96.8)]) - 1 / (1 - u_of(96.8 / 121))) < 1e-6),
        ("separation does not lose",
         separated(121, [(0.8, 20.0), (0.2, 80.0)])[0] <=
         mixed(121, [(0.8, 20.0), (0.2, 80.0)])),
        ("dftl default covers 2 GiB", dftl(4, 2048)[2] == 0.0),
        ("dftl half covered", abs(dftl(1, 1024)[2] - 0.5) < 1e-9),
    ]
    for name, ok in checks:
        if not ok:
            print(f"self-test: FAIL {name}")
            bad += 1
    print(f"lab-waf-model self-test: {len(checks) - bad} of {len(checks)} passed")
    return 1 if bad else 0


def parse_class(text):
    share, lines = text.split(":")
    return float(share), float(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[1],
                                 formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--self-test", action="store_true")
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("uniform")
    p.add_argument("--lines", type=int, required=True,
                   help="lines of the device (blks_per_pl)")
    p.add_argument("--fill", type=float, required=True,
                   help="namespace share of the NAND, 0 to 1")
    p.add_argument("--gc", type=float, default=75, help="gc_thres_pcent")
    p.add_argument("--gc-high", type=float, default=95,
                   help="gc_thres_pcent_high")
    p.add_argument("--open", type=int, default=1,
                   help="open write pointers (2 with hot_cold_sep)")
    p = sub.add_parser("classes")
    p.add_argument("--pool", type=float, required=True,
                   help="lines of the pool: lines - free kept - open")
    p.add_argument("--class", dest="classes", action="append",
                   type=parse_class, required=True,
                   help="SHARE:LINES, share of the host writes and data lines")
    p = sub.add_parser("dftl")
    p.add_argument("--cmt-mb", type=float, required=True,
                   help="mapping_cache_mb (0 means 4)")
    p.add_argument("--ws-mb", type=float, required=True,
                   help="working set of the access, MiB")
    p.add_argument("--page-kb", type=int, default=4)
    a = ap.parse_args()

    if a.self_test:
        return self_test()
    if a.cmd == "uniform":
        regime, waf, alpha, pool = uniform(a.lines, a.fill, a.gc, a.gc_high,
                                           a.open)
        print(f"regime {regime}  pool {pool} lines  alpha {alpha:.3f}  "
              f"WAF {waf:.2f}")
    elif a.cmd == "classes":
        print(f"one log      WAF {mixed(a.pool, a.classes):.2f}")
        if len(a.classes) == 2:
            w, t1 = separated(a.pool, a.classes)
            print(f"one per class WAF {w:.2f}  (class 1 gets {t1:.1f} lines)")
    elif a.cmd == "dftl":
        tps, per, miss = dftl(a.cmt_mb or 4, a.ws_mb, a.page_kb)
        print(f"CMT {tps} TPs x {per:g} MiB = {tps * per:g} MiB covered  "
              f"miss ratio {miss:.3f}")
    else:
        ap.print_help()
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
