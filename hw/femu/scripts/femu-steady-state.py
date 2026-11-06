#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Find where a series of per-round results reaches steady state.

The rule is the one of the SNIA Solid State Storage Performance Test
Specification: over a window of the last WINDOW rounds (5 by default),

  - the excursion, the largest value minus the smallest, is at most
    EXCURSION percent (20) of the window average, and
  - the slope of the least-squares line, times the window length minus 1,
    is at most SLOPE percent (10) of the window average in size.

A WAF or GC study measured before steady state reports a fresh device,
not the drive the study means. Run one round per fio job (for example 1
minute of random writes), give the per-round values here, and keep only
the rounds after the reported one.

Input: one value per line (blank lines and '#' lines are skipped), a CSV
file with --column N (0-based), or fio JSON outputs (one per round, in
order), from which --metric (default iops, also bw or lat_mean) is the sum
over jobs of the read and write values.

Usage:
    femu-steady-state.py [--window W] [--excursion P] [--slope P]
                         [--column N] [--metric M] [--json] [FILE...]
    femu-steady-state.py --self-test

Exit status: 0 when steady state is reached, 1 when it is not, 2 on an
input error, such as fewer rounds than the window.
"""

import argparse
import json
import sys


def slope(ys):
    """Least-squares slope of ys against 0, 1, ..., len(ys) - 1."""
    n = len(ys)
    mx = (n - 1) / 2.0
    my = sum(ys) / n
    num = sum((i - mx) * (y - my) for i, y in enumerate(ys))
    den = sum((i - mx) ** 2 for i in range(n))
    return num / den


def window_state(ys, excursion, slope_pct):
    """(steady, average, excursion, slope span) for one window."""
    avg = sum(ys) / len(ys)
    exc = max(ys) - min(ys)
    span = abs(slope(ys)) * (len(ys) - 1)
    if avg == 0:
        return (exc == 0 and span == 0, avg, exc, span)
    return (exc <= avg * excursion / 100.0 and
            span <= abs(avg) * slope_pct / 100.0, avg, exc, span)


def first_steady(values, window, excursion, slope_pct):
    """1-based index of the last round of the first steady window, or 0."""
    for end in range(window, len(values) + 1):
        if window_state(values[end - window:end], excursion, slope_pct)[0]:
            return end
    return 0


def fio_value(doc, metric):
    total = 0.0
    for job in doc.get("jobs", []):
        for side in ("read", "write"):
            d = job.get(side, {})
            if metric == "lat_mean":
                total += d.get("lat_ns", {}).get("mean", 0.0)
            else:
                total += float(d.get(metric, 0.0))
    return total


def read_values(paths, column, metric):
    values = []
    sources = paths or ["-"]
    for p in sources:
        f = sys.stdin if p == "-" else open(p, encoding="utf-8")
        text = f.read()
        if p != "-":
            f.close()
        if p.endswith(".json"):
            start = text.find("{")
            values.append(fio_value(json.loads(text[start:]), metric))
            continue
        for line in text.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if column is not None:
                line = line.split(",")[column].strip()
            try:
                values.append(float(line))
            except ValueError:
                if column is not None and not values:
                    continue        # a CSV header
                raise
    return values


def run(a):
    try:
        values = read_values(a.files, a.column, a.metric)
    except (OSError, ValueError, IndexError) as e:
        print(f"femu-steady-state: {e}", file=sys.stderr)
        return 2
    if len(values) < a.window:
        print(f"femu-steady-state: {len(values)} rounds, the window needs "
              f"{a.window}", file=sys.stderr)
        return 2
    end = first_steady(values, a.window, a.excursion, a.slope)
    last = values[-a.window:] if not end else values[end - a.window:end]
    _, avg, exc, span = window_state(last, a.excursion, a.slope)
    out = {
        "rounds": len(values),
        "window": a.window,
        "steady": bool(end),
        "steady_round": end,
        "window_rounds": [end - a.window + 1, end] if end else None,
        "average": avg,
        "excursion_pct": 100.0 * exc / avg if avg else 0.0,
        "slope_pct": 100.0 * span / abs(avg) if avg else 0.0,
    }
    if a.json:
        print(json.dumps(out, indent=1))
    elif end:
        print(f"steady state at round {end} of {len(values)} "
              f"(window {end - a.window + 1} to {end}): average {avg:.6g}, "
              f"excursion {out['excursion_pct']:.1f}%, "
              f"slope {out['slope_pct']:.1f}%")
    else:
        print(f"no steady state in {len(values)} rounds: last window "
              f"average {avg:.6g}, excursion {out['excursion_pct']:.1f}%, "
              f"slope {out['slope_pct']:.1f}%")
    return 0 if end else 1


def self_test():
    bad = 0

    def expect(name, cond):
        nonlocal bad
        if not cond:
            print(f"self-test: {name}")
            bad += 1

    flat = [100.0] * 5
    expect("a flat series is steady at its 5th round",
           first_steady(flat, 5, 20, 10) == 5)
    # a fresh-drive curve: high, falls, then settles
    curve = [500, 420, 330, 250, 190, 160, 150, 148, 151, 149, 150]
    expect("a falling curve settles late",
           first_steady(curve, 5, 20, 10) == 10)
    ramp = [100, 104, 108, 112, 116, 120]
    expect("a steady ramp (slope 16% of the mean) is never steady",
           first_steady(ramp, 5, 20, 10) == 0)
    jumpy = [100, 130, 95, 128, 99, 131]
    expect("a 30% excursion is never steady",
           first_steady(jumpy, 5, 20, 10) == 0)
    expect("the slope of 0..4 is 1", abs(slope([0, 1, 2, 3, 4]) - 1) < 1e-12)
    edge_exc = [90, 110, 100, 100, 100]
    expect("an excursion of exactly 20% passes",
           first_steady(edge_exc, 5, 20, 10) == 5)
    expect("an all-zero series is steady",
           first_steady([0.0] * 5, 5, 20, 10) == 5)
    fio = {"jobs": [{"read": {"iops": 10.0}, "write": {"iops": 5.0}},
                    {"read": {"iops": 1.0}, "write": {"iops": 2.0}}]}
    expect("fio iops sums read and write over jobs",
           fio_value(fio, "iops") == 18.0)
    print(f"femu-steady-state self-test: {8 - bad} of 8 passed")
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("files", nargs="*")
    ap.add_argument("--window", type=int, default=5)
    ap.add_argument("--excursion", type=float, default=20.0)
    ap.add_argument("--slope", type=float, default=10.0)
    ap.add_argument("--column", type=int)
    ap.add_argument("--metric", default="iops",
                    choices=["iops", "bw", "lat_mean"])
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    if a.window < 2:
        ap.error("--window must be 2 or more")
    return run(a)


if __name__ == "__main__":
    sys.exit(main())
