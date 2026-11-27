#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Fit a FEMU NAND profile and device knobs to the fit set of a drive.

The input is a frozen drive dataset in the format of calib-dataset.py:
per condition id of calib-matrix.json, the fio JSON outputs of each
replicate run (one file per time block) and, for J7 and J8, a WAF file.
Each file carries its sha256.

The fit reads only the "fit" rows. calib-dataset.py refuses the input,
with exit 2, when the split could leak or the workload differs: a held
id, a relabelled row, a changed file, another matrix, a fio output or
WAF file of another job, a block given twice, a fio error or another
rate cap. When any J7 or J8 run says "unavailable", no WAF value enters
the fit and op_pcent keeps its prior, as design section 1.4 asks. A row
that reached 90% of the fio rate cap counts as incomplete.

Forward model (all times in ns, P the page size, C channels, D dies):

  L1     = host_ns + fw_read_ns + read_ns + xfer_ns + link(P)
  J1     p50 read latency = L1
  J2     read rate at QD q = min(q / L1, D / read_ns, C / xfer_ns, link)
  J3     read rate of n pages per request at QD32
           = min(32 n / Ln, D / read_ns, C / xfer_ns, link), with
           Ln = L1 - xfer_ns + xfer_ns * ceil(n / C)
  J5     write rate = min(32 n / Lw, D / program_ns, C / xfer_ns, link)
  J7, J8 WAF of uniform random writes with FIFO cleaning:
           WAF = A / (A + W0(-A exp(-A))), A = 1 + r, W0 the principal
           Lambert W branch, r = (a + f) / (1 - f) the spare ratio,
           a = op_pcent / 100 and f the excluded fraction of the span;
           WAF > 1 for every r > 0, and WAF -> 1 as r grows

host_ns, fw_read_ns, fw_write_ns, the link and the channel count are
priors. The fit minimizes the weighted sum of squared log errors, one
weight per family, by a coordinate search in log space. It repeats the
fit for each topology of a small integer set and keeps every topology
whose fit-set errors stay inside the tolerance. Each kept topology gets
one .nprof (the T3.9 profile format, version 1) and one ssd-config.sh
file. A JSON file records each value, its label, its source, its range
over the replicates and the sha256 of every input file.

Usage:
    calib-fit.py --dataset DIR [--matrix FILE] [--priors FILE]
                 [--name NAME] [--date YYYY-MM-DD] --out DIR
    calib-fit.py --self-test

Exit status: 0 when at least one topology fits, 1 when none fits or a
fit row is missing or incomplete, 2 when the input is refused or
unreadable.
"""

import argparse
import contextlib
import datetime
import importlib.util
import io
import json
import math
import os
import re
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "calib_dataset", os.path.join(HERE, "calib-dataset.py"))
ds = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ds)
Refused = ds.Refused
sha256_file = ds.sha256_file
load_json = ds.load_json
DEFAULT_MATRIX = os.path.join(HERE, "calib-matrix.json")

PRIORS = {
    "page_bytes": 4096,
    "nchs": 8,
    "luns_set": [1, 2, 4, 8, 16],
    "host_ns": 0.0,
    "fw_read_ns": 0.0,
    "fw_write_ns": 0.0,
    "link_mbps": 0.0,
    "erase_ns": 2000000,
    "cmd_addr_ns": 0,
    "status_ns": 0,
    "secs_per_pg": 8,
    "pgs_per_blk": 256,
    "gc_thres_pcent": 75,
    "gc_thres_pcent_high": 95,
    "vwc": 0,
    "op_pcent": 7.0,
}

# the labels of the design note, section 1.2
LABELS = {
    "read_ns": ("fitted", "J1 p50 and J2 rate"),
    "xfer_ns": ("fitted", "J3 bandwidth, channel count at its prior"),
    "program_ns": ("fitted", "J5 bandwidth, conditional on the die count"),
    "op_pcent": ("fitted", "J7 and J8 WAF"),
    "dies": ("bounded", "J2 plateau over the topology set"),
    "dram_hit_ns": ("prior", "J4 p50"),
    "fw_read_ns": ("prior", "0 unless the J2 low-QD shape needs it"),
    "fw_write_ns": ("prior", "no write job isolates it"),
    "erase_ns": ("unidentifiable", "prior; report J7 change for x0.5, x2"),
    "cmd_addr_ns": ("prior", "folds into read_ns and program_ns"),
    "status_ns": ("prior", "folds into read_ns and program_ns"),
    "buffer_size": ("bounded", "J4 and a burst test, not in this fit"),
}

FIT_PARAMS = ("read_ns", "xfer_ns", "program_ns", "op_pcent")
BOUNDS = {"read_ns": (100.0, 2.0e9), "xfer_ns": (1.0, 2.0e9),
          "program_ns": (100.0, 2.0e9), "op_pcent": (0.5, 400.0)}
NPROF_KEYS = ("femu_nand_profile", "name", "nand_type", "read_ns",
              "program_ns", "erase_ns", "cmd_addr_ns", "xfer_ns", "status_ns")
INT32_MAX = 2 ** 31 - 1


def size_bytes(s):
    m = re.fullmatch(r"(\d+)([kmg]?)", s.lower())
    if not m:
        raise ValueError(f"bad size '{s}'")
    return int(m.group(1)) * {"": 1, "k": 1024, "m": 1 << 20,
                              "g": 1 << 30}[m.group(2)]


# ---------------------------------------------------------------- input

def audit(matrix_path, dataset):
    """Audit the dataset; return (matrix, fit rows, inputs)."""
    res = ds.audit(matrix_path, dataset, ("fit",))
    return res["matrix"], res["rows"], res["inputs"]


def block_metric(doc, metric):
    op, _, what = metric.partition(".")
    d = doc["jobs"][0][op]
    if what == "p50":
        return float(d["clat_ns"]["percentile"]["50.000000"])
    if what == "iops":
        return float(d["iops"])
    if what == "bw":
        return float(d["bw_bytes"])
    raise ValueError(metric)


FIT_METRIC = {"J1": "read.p50", "J2": "read.iops", "J3": "read.bw",
              "J4": "write.p50", "J5": "write.bw", "J7": "waf", "J8": "waf"}


def run_value(run, metric):
    if metric == "waf":
        return sum(run["waf"]) / len(run["waf"])
    vals = [block_metric(b, metric) for b in run["blocks"]]
    return sum(vals) / len(vals)


def waf_unavailable(rows):
    """Reasons of the fit WAF rows that carry no qualified WAF."""
    return sorted({x["waf_unavailable"] for r in rows.values()
                   for x in r["runs"] if x.get("waf_unavailable")})


def observations(rows, runs=None):
    """Fit observations (id, family, metric, value); @runs picks runs.
    When any WAF run is unavailable, no WAF row gives an observation:
    op_pcent then keeps its prior and nothing else moves it."""
    obs = []
    no_waf = bool(waf_unavailable(rows))
    for cid, r in sorted(rows.items()):
        fam = r["cond"]["family"]
        metric = FIT_METRIC[fam]
        if (metric == "waf" and no_waf) or not r["valid"]:
            continue
        sel = r["runs"] if runs is None else [r["runs"][i] for i in runs
                                              if i < len(r["runs"])]
        if not sel:
            continue
        v = sum(run_value(x, metric) for x in sel) / len(sel)
        obs.append((cid, fam, metric, v))
    return obs


# ---------------------------------------------------------------- model

def lambert_w0(z):
    """Principal branch of Lambert W for -1/e <= z < 0 (Halley steps)."""
    if z <= -1.0 / math.e:
        return -1.0
    # near the branch point the series in p is a good start
    w = -1.0 + math.sqrt(2.0 * (math.e * z + 1.0)) if z < -0.25 else z
    for _ in range(60):
        ew = math.exp(w)
        f = w * ew - z
        nxt = w - f / (ew * (w + 1) - (w + 2) * f / (2 * w + 2))
        if abs(nxt - w) < 1e-15:
            return nxt
        w = nxt
    return w


def waf_model(r):
    """FIFO-cleaning WAF of uniform random writes at spare ratio @r."""
    a = 1.0 + r
    return a / (a + lambert_w0(-a * math.exp(-a)))


def link_ns(p, nbytes):
    return nbytes * 1000.0 / p["link_mbps"] if p["link_mbps"] else 0.0


def rate_caps(p, page_time, nbytes_page):
    """Page rates per ns of the array, the channels and the link."""
    caps = [p["dies"] / page_time]
    if p["xfer_ns"] > 0:
        caps.append(p["nchs"] / p["xfer_ns"])
    if p["link_mbps"]:
        caps.append(p["link_mbps"] * 1e6 / 1e9 / nbytes_page)
    return caps


def l1(p):
    return (p["host_ns"] + p["fw_read_ns"] + p["read_ns"] + p["xfer_ns"]
            + link_ns(p, p["page_bytes"]))


def predict(p, cond, metric):
    pg = p["page_bytes"]
    fio = cond["fio"]
    qd = int(fio["iodepth"])
    if metric == "waf":
        f = 1.0 - cond.get("active_pcent", 100) / 100.0
        return waf_model((p["op_pcent"] / 100.0 + f) / (1.0 - f))
    if metric == "read.p50":
        return l1(p)
    if metric == "write.p50":
        return p["dram_hit_ns"]
    n = max(1, size_bytes(fio["bs"]) // pg)
    xfer_chain = p["xfer_ns"] * math.ceil(n / p["nchs"])
    if metric.startswith("read."):
        lat = l1(p) - p["xfer_ns"] + xfer_chain
        caps = rate_caps(p, p["read_ns"], pg)
    else:
        lat = (p["host_ns"] + p["fw_write_ns"] + p["program_ns"]
               + xfer_chain + link_ns(p, pg))
        caps = rate_caps(p, p["program_ns"], pg)
    pages_per_ns = min([qd * n / lat] + caps)
    if metric.endswith(".iops"):
        return pages_per_ns / n * 1e9
    return pages_per_ns * pg * 1e9


def objective(p, obs, conds, weights):
    s = 0.0
    for cid, fam, metric, v in obs:
        if metric == "write.p50":
            continue
        e = math.log(predict(p, conds[cid], metric) / v)
        s += weights[fam] * e * e
    return s


def golden(fun, lo, hi, iters=80):
    """Minimum of @fun over [lo, hi] in log space."""
    a, b = math.log(lo), math.log(hi)
    g = (math.sqrt(5) - 1) / 2
    c, d = b - g * (b - a), a + g * (b - a)
    fc, fd = fun(math.exp(c)), fun(math.exp(d))
    for _ in range(iters):
        if fc < fd:
            b, d, fd = d, c, fc
            c = b - g * (b - a)
            fc = fun(math.exp(c))
        else:
            a, c, fc = c, d, fd
            d = a + g * (b - a)
            fd = fun(math.exp(d))
    return math.exp((a + b) / 2)


def initial(p, obsd, array_limited=False):
    """Closed-form start, in the order of 06 section 19.

    The read plateau is min(D / read_ns, C / xfer_ns), and J1 gives their
    sum. The plateau can come from the channels or from the dies, so
    @array_limited picks the second reading of the same data.
    """
    pg = p["page_bytes"]
    q = dict(p)
    # a start for a knob whose rows are missing or not valid; the search
    # then has a point to move from, and the missing row is reported
    for k, v in (("read_ns", 50000.0), ("xfer_ns", 10000.0),
                 ("program_ns", 500000.0)):
        q.setdefault(k, v)
    bw = [v for (cid, fam, m, v) in obsd if fam == "J3"]
    lat = [v for (cid, fam, m, v) in obsd if fam == "J1"]
    fixed = q["host_ns"] + q["fw_read_ns"] + link_ns(q, pg)
    if bw and lat and array_limited:
        q["read_ns"] = p["dies"] * pg * 1e9 / max(bw)
        q["xfer_ns"] = max(BOUNDS["xfer_ns"][0],
                           lat[0] - fixed - q["read_ns"])
    elif bw:
        q["xfer_ns"] = p["nchs"] * pg * 1e9 / max(bw)
    if lat and not array_limited:
        q["read_ns"] = max(BOUNDS["read_ns"][0],
                           lat[0] - fixed - q["xfer_ns"])
    wbw = [v for (cid, fam, m, v) in obsd if fam == "J5"]
    if wbw:
        q["program_ns"] = q["dies"] * pg * 1e9 / wbw[0]
    waf = [v for (cid, fam, m, v) in obsd if fam == "J7"]
    if waf and waf[0] > 1.0:
        # waf_model falls as r grows: bisect for the measured value
        lo, hi = BOUNDS["op_pcent"]
        for _ in range(100):
            mid = math.sqrt(lo * hi)
            if waf_model(mid / 100.0) > waf[0]:
                lo = mid
            else:
                hi = mid
        q["op_pcent"] = math.sqrt(lo * hi)
    return q


def fit_topology(base, obs, conds, weights, luns, scale=None,
                 array_limited=False, params=FIT_PARAMS):
    p = dict(base)
    p["luns"] = luns
    p["dies"] = p["nchs"] * luns
    p = initial(p, obs, array_limited)
    for k, f in (scale or {}).items():
        p[k] *= f
    last = objective(p, obs, conds, weights)
    for _ in range(300):
        for k in params:
            lo, hi = BOUNDS[k]

            def f(x, k=k):
                q = dict(p)
                q[k] = x
                return objective(q, obs, conds, weights)
            # a local bracket: the full range can jump to another basin
            best = golden(f, max(lo, p[k] / 4), min(hi, p[k] * 4))
            if f(best) < f(p[k]):
                p[k] = best
        now = objective(p, obs, conds, weights)
        if last - now <= 1e-14:
            break
        last = now
    return p


def errors(p, obs, conds, matrix):
    tol = matrix["tolerances_pct"]
    out = []
    for cid, fam, metric, v in obs:
        pred = predict(p, conds[cid], metric)
        e = (pred - v) / v
        if fam == "J1":
            t = tol["qd1_p50"]
        elif fam == "J2":
            t = tol["sat_rate"]
        elif fam in ("J3", "J5"):
            t = tol["seq_bw"]
        elif fam in ("J7", "J8"):
            t = tol["waf"]
        else:
            t = tol["other_p50_p99"]
        out.append({"id": cid, "metric": metric, "drive": v,
                    "model": pred, "e": e, "tol_pct": t,
                    "inside": abs(e) * 100.0 <= t})
    return out


# ---------------------------------------------------------------- output

def nprof_text(name, p, note):
    vals = {
        "femu_nand_profile": "1", "name": name, "nand_type": "none",
        "read_ns": str(int(round(p["read_ns"]))),
        "program_ns": str(int(round(p["program_ns"]))),
        "erase_ns": str(int(p["erase_ns"])),
        "cmd_addr_ns": str(int(p["cmd_addr_ns"])),
        "xfer_ns": str(int(round(p["xfer_ns"]))),
        "status_ns": str(int(p["status_ns"])),
    }
    lines = [f"; {note}",
             f"; -device femu,femu_mode=1,nand_profile="
             f"hw/femu/profiles/{name}.nprof"]
    lines += [f"{k} = {vals[k]}" for k in NPROF_KEYS]
    return "\n".join(lines) + "\n"


def check_nprof(text):
    """The rules of nand/nand-profile.c, so a bad value fails here first."""
    seen = []
    for line in text.split("\n"):
        line = re.split(r"[;#]", line, maxsplit=1)[0].strip()
        if not line:
            continue
        k, _, v = (s.strip() for s in line.partition("="))
        if k not in NPROF_KEYS or k in seen:
            return f"bad or repeated key {k}"
        if not seen and k != "femu_nand_profile":
            return "first key must be femu_nand_profile"
        seen.append(k)
        if k == "femu_nand_profile" and v != "1":
            return "version must be 1"
        if k == "name" and not 0 < len(v) < 64:
            return "name length"
        if k == "nand_type" and v not in ("none", "slc", "mlc", "tlc", "qlc"):
            return "nand_type"
        if k.endswith("_ns"):
            lo = 1 if k in ("read_ns", "program_ns", "erase_ns") else 0
            if not v.isdigit() or not lo <= int(v) <= INT32_MAX:
                return f"{k} out of range"
    return None if len(seen) == len(NPROF_KEYS) else "missing key"


def conf_text(name, p, note):
    link = int(p["link_mbps"]) if p["link_mbps"] else ""
    return "\n".join(line.rstrip() for line in [
        f"# {note}",
        "# blks_per_pl follows the FEMU capacity (design section 2.6).",
        "",
        "[device]",
        "mode        = bbssd",
        f"nand_profile = hw/femu/profiles/{name}.nprof",
        "",
        "[geometry]",
        f"secs_per_pg = {p['secs_per_pg']}",
        f"pgs_per_blk = {p['pgs_per_blk']}",
        "blks_per_pl =",
        "pls_per_lun = 1",
        f"luns_per_ch = {p['luns']}",
        f"nchs        = {p['nchs']}",
        "",
        "[ftl]",
        f"op_pcent            = {max(1, int(round(p['op_pcent'])))}",
        f"gc_thres_pcent      = {p['gc_thres_pcent']}",
        f"gc_thres_pcent_high = {p['gc_thres_pcent_high']}",
        f"dram_hit_ns         = {int(round(p['dram_hit_ns']))}",
        f"fw_read_ns          = {int(p['fw_read_ns'])}",
        f"fw_write_ns         = {int(p['fw_write_ns'])}",
        f"pcie_bandwidth_mbps = {link}",
        f"vwc                 = {p['vwc']}",
        "",
    ])


def fit_rows(matrix_path, dataset):
    return audit(matrix_path, dataset)[1]


def fit(matrix_path, dataset, priors, priors_sha256=None):
    matrix, rows, inputs = audit(matrix_path, dataset)
    conds = {c["id"]: c for c in matrix["conditions"]}
    need = {c["id"] for c in matrix["conditions"] if c["split"] == "fit"}
    missing = sorted(need - set(rows))
    incomplete = sorted(f"{cid} ({r['sampling']})" for cid, r in rows.items()
                        if r["sampling"] != "ok")
    incomplete += sorted(f"{cid} (marked not valid)"
                         for cid, r in rows.items() if not r["valid"])
    # a row the fio rate cap held back measures the cap, not the drive
    incomplete += sorted(
        f"{cid} (rate limited: {', '.join(r['rate_limited'])})"
        for cid, r in rows.items() if r["rate_limited"])
    weights = {k: v["weight"] for k, v in matrix["families"].items()}
    bad = sorted(set(priors) - set(PRIORS))
    if bad:
        raise ValueError(f"unknown prior keys: {', '.join(bad)}")
    base = dict(PRIORS)
    base.update(priors)
    # without a qualified WAF, op_pcent has no data: keep the prior
    no_waf = waf_unavailable(rows)
    params = tuple(k for k in FIT_PARAMS if not (no_waf and k == "op_pcent"))
    obs = observations(rows)
    j4 = [v for (cid, fam, m, v) in obs if fam == "J4"]
    base["dram_hit_ns"] = j4[0] if j4 else 0.0
    nrep = min(len(r["runs"]) for r in rows.values()) if rows else 0
    topo = []
    for luns in base["luns_set"]:
        p = fit_topology(base, obs, conds, weights, luns, params=params)
        errs = errors(p, obs, conds, matrix)
        reps = [fit_topology(base, observations(rows, [i]), conds, weights,
                             luns, params=params)
                for i in range(nrep)] if nrep > 1 else []
        # the same data read as die limited: a second solution that also
        # fits means the split of time between read_ns and xfer_ns is open
        alt = fit_topology(base, obs, conds, weights, luns,
                           array_limited=True, params=params)
        alt_ok = all(e["inside"] for e in errors(alt, obs, conds, matrix))
        unique = not alt_ok or all(
            abs(alt[k] - p[k]) <= 0.01 * p[k] for k in ("read_ns", "xfer_ns"))
        topo.append({"nchs": p["nchs"], "luns": luns, "params": p,
                     "unique": unique,
                     "other": None if unique else
                     {k: alt[k] for k in ("read_ns", "xfer_ns")},
                     "objective": objective(p, obs, conds, weights),
                     "errors": errs, "kept": all(e["inside"] for e in errs),
                     "range": {k: [min(r[k] for r in reps),
                                   max(r[k] for r in reps)]
                               for k in FIT_PARAMS} if reps else {}})
    return {"matrix": matrix, "inputs": inputs, "missing": missing,
            "incomplete": incomplete, "topologies": topo, "base": base,
            "params": params, "no_waf": no_waf, "priors_in": dict(priors),
            "priors_sha256": priors_sha256}


def write_outputs(res, name, date, out):
    os.makedirs(out, exist_ok=True)
    kept = [t for t in res["topologies"] if t["kept"]]
    man12 = res["inputs"]["manifest.json"][:12]
    files = []
    for t in kept:
        tn = f"{name}-c{t['nchs']}l{t['luns']}"
        note = (f"Fitted by calib-fit.py from dataset {man12}, topology "
                f"{t['nchs']} x {t['luns']}.")
        text = nprof_text(tn, t["params"], note)
        bad = check_nprof(text)
        if bad:
            raise ValueError(f"{tn}.nprof: {bad}")
        for ext, body in ((".nprof", text),
                          (".conf", conf_text(tn, t["params"], note))):
            with open(os.path.join(out, tn + ext), "w",
                      encoding="utf-8") as f:
                f.write(body)
            files.append(tn + ext)
    dies = sorted(t["nchs"] * t["luns"] for t in kept)
    values = {}
    for k, (label, src) in LABELS.items():
        ent = {"label": label, "from": src}
        if k in ("read_ns", "xfer_ns") and not all(t["unique"]
                                                    for t in kept):
            ent["label"] = "bounded"
            ent["from"] = src + "; a die limited reading also fits"
        if k == "op_pcent" and res["no_waf"]:
            ent = {"label": "prior", "value": res["base"]["op_pcent"],
                   "from": "no qualified WAF: " + "; ".join(res["no_waf"])}
        elif k in res["params"] and kept:
            ent["value"] = {f"c{t['nchs']}l{t['luns']}": t["params"][k]
                            for t in kept}
            ent["interval"] = {f"c{t['nchs']}l{t['luns']}": t["range"].get(k)
                               for t in kept}
        elif k == "dies":
            ent["value"] = dies
        elif k in res["base"]:
            ent["value"] = res["base"][k]
        values[k] = ent
    doc = {"calib_fit": 1, "name": name, "date": date,
           "inputs": res["inputs"], "missing_fit_rows": res["missing"],
           "incomplete_fit_rows": res["incomplete"],
           "priors": {"file_sha256": res["priors_sha256"],
                      "given": res["priors_in"],
                      "effective": {k: res["base"][k] for k in PRIORS}},
           "fitted": list(res["params"]),
           "values": values,
           "topologies": [{"nchs": t["nchs"], "luns": t["luns"],
                           "kept": t["kept"], "objective": t["objective"],
                           "read_xfer_unique": t["unique"],
                           "read_xfer_other": t["other"],
                           "errors": t["errors"]}
                          for t in res["topologies"]],
           "files": files}
    path = os.path.join(out, f"calib-{name}-{date}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1, sort_keys=True)
    return path, files


# ---------------------------------------------------------------- self-test

TRUTH = {"read_ns": 45000.0, "xfer_ns": 20000.0, "program_ns": 1000000.0,
         "op_pcent": 12.0, "luns": 4}


def synth_dataset(matrix_path, out, truth, ids=None, nrep=3, nblk=10,
                  waf="model", no_waf=(), rate=ds.DEFAULT_RATE):
    """Write a drive dataset made by the forward model at @truth."""
    matrix = ds.read_matrix(matrix_path)
    p = dict(PRIORS)
    p.update(truth)
    p["dies"] = p["nchs"] * p["luns"]
    p["dram_hit_ns"] = 15000.0
    spec = {}
    for c in matrix["conditions"]:
        if ids is None and c["split"] != "fit":
            continue
        if ids is not None and c["id"] not in ids:
            continue
        metric = FIT_METRIC.get(c["family"])
        if metric is None:
            continue
        v = predict(p, c, metric)
        if metric == "waf":
            w = v if waf == "model" else waf
            spec[c["id"]] = {"values": {"write.iops": 1000.0},
                             "waf": "unavailable" if c["id"] in no_waf
                             else w}
        else:
            spec[c["id"]] = {"values": {metric: v}}
    return ds.synth(matrix_path, out, spec, nrep=nrep, nblk=nblk, rate=rate)


write_manifest = ds.write_manifest


def self_test():
    fails = []

    def check(ok, what):
        print(("ok    " if ok else "FAIL  ") + what)
        if not ok:
            fails.append(what)

    def expect_refused(d, what, matrix=DEFAULT_MATRIX):
        try:
            fit(matrix, d, {})
        except Refused as e:
            check(True, f"C3 {what}: refused ({e})")
            return
        check(False, f"C3 {what}: not refused")

    with tempfile.TemporaryDirectory() as tmp:
        good = os.path.join(tmp, "good")
        man = synth_dataset(DEFAULT_MATRIX, good, TRUTH)
        res = fit(DEFAULT_MATRIX, good, {})
        check(not res["missing"], "the dataset holds every fit row")
        kept = {t["luns"]: t for t in res["topologies"] if t["kept"]}
        check(TRUTH["luns"] in kept, "the true topology is kept")
        check(1 not in kept, "a topology far below plateau x read_ns "
              "dies is dropped")
        w2 = max(abs(e["e"]) for e in kept[2]["errors"]) if 2 in kept else 0
        check(w2 > 0.01, "a topology just below it is kept only by the "
              f"tolerance (worst |e| {w2 * 100:.1f}%)")
        check(len(kept) > 1, "the die count is bounded, not unique "
              f"(kept luns {sorted(kept)})")
        t = kept.get(TRUTH["luns"])
        for k in FIT_PARAMS:
            got = t["params"][k] if t else float("nan")
            err = abs(got - TRUTH[k]) / TRUTH[k]
            check(err < 0.01, f"{k} recovered: {got:.1f} against "
                  f"{TRUTH[k]:.1f} ({err * 100:.3f}%)")
        # the search itself, from a start far from the closed form
        obs = observations(fit_rows(DEFAULT_MATRIX, good))
        conds = {c["id"]: c for c in res["matrix"]["conditions"]}
        weights = {k: v["weight"] for k, v in
                   res["matrix"]["families"].items()}
        far = fit_topology(res["base"], obs, conds, weights, TRUTH["luns"],
                           scale={"read_ns": 1.3, "xfer_ns": 0.8,
                                  "program_ns": 2.0, "op_pcent": 0.5})
        worst = max(abs(far[k] - TRUTH[k]) / TRUTH[k] for k in FIT_PARAMS)
        check(worst < 0.01, "the search recovers the profile from a start "
              f"off by up to 2x (worst {worst * 100:.3f}%)")
        check(t is not None and t["unique"],
              "read_ns and xfer_ns have one solution for these data")

        # the same plateau with read_ns 60000 also fits a die limited
        # reading (read_ns 80000, xfer_ns near 0): the fit must say so
        amb = os.path.join(tmp, "ambiguous")
        synth_dataset(DEFAULT_MATRIX, amb, dict(TRUTH, read_ns=60000.0))
        ra = fit(DEFAULT_MATRIX, amb, {})
        ta = [x for x in ra["topologies"] if x["luns"] == TRUTH["luns"]][0]
        check(ta["kept"] and not ta["unique"],
              "control: a second solution is reported, read_ns "
              f"{(ta['other'] or {}).get('read_ns', 0):.0f}")
        check(abs(res["base"]["dram_hit_ns"] - 15000.0) < 1.0,
              "dram_hit_ns prior taken from the J4 p50")
        out = os.path.join(tmp, "out")
        path, files = write_outputs(res, "selftest-ref", "2026-01-01", out)
        check(len(files) == 2 * len(kept), f"wrote {len(files)} files")
        with open(os.path.join(out, f"selftest-ref-c8l{TRUTH['luns']}.nprof"),
                  encoding="utf-8") as f:
            text = f.read()
        check(check_nprof(text) is None, "the .nprof passes the loader rules")
        check("erase_ns = 2000000" in text,
              "erase_ns stays at its prior (unidentifiable)")
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
        check(doc["values"]["erase_ns"]["label"] == "unidentifiable" and
              doc["values"]["fw_write_ns"]["label"] == "prior",
              "unconstrained knobs keep their labels")
        check(len(doc["inputs"]) == 2 + sum(
            len(r["runs"]) * 10 + sum("waf" in x for x in r["runs"])
            for r in man["rows"]), "the fit records every input hash")
        bad = text.replace("read_ns = ", "read_ns = -")
        check(check_nprof(bad) is not None, "control: a bad .nprof fails")

        # C3: each tampered input must be refused with exit 2
        held = os.path.join(tmp, "held")
        m = synth_dataset(DEFAULT_MATRIX, held, TRUTH,
                          ids=set(r["id"] for r in man["rows"])
                          | {"J2-randread-4k-qd8"})
        expect_refused(held, "held id in the input")

        relab = os.path.join(tmp, "relabel")
        m = synth_dataset(DEFAULT_MATRIX, relab, TRUTH,
                          ids=set(r["id"] for r in man["rows"])
                          | {"J2-randread-4k-qd8"})
        for r in m["rows"]:
            if r["id"] == "J2-randread-4k-qd8":
                r["split"] = "fit"
        write_manifest(relab, m)
        expect_refused(relab, "held row relabelled fit")

        swap = os.path.join(tmp, "swap")
        m = synth_dataset(DEFAULT_MATRIX, swap, TRUTH,
                          ids=set(r["id"] for r in man["rows"])
                          | {"J2-randread-4k-qd8"})
        src = [r for r in m["rows"] if r["id"] == "J2-randread-4k-qd8"][0]
        m["rows"] = [r for r in m["rows"] if r["id"] != src["id"]]
        for r in m["rows"]:
            if r["id"] == "J2-randread-4k-qd4":
                r["runs"] = src["runs"]
        write_manifest(swap, m)
        expect_refused(swap, "held data filed under a fit id")

        hashd = os.path.join(tmp, "hash")
        m = synth_dataset(DEFAULT_MATRIX, hashd, TRUTH)
        victim = os.path.join(hashd, m["rows"][0]["runs"][0]["blocks"][0]
                              ["path"])
        with open(victim, "a") as f:
            f.write(" ")
        expect_refused(hashd, "changed dataset file")

        mat = os.path.join(tmp, "matrix.json")
        with open(DEFAULT_MATRIX, encoding="utf-8") as f:
            text = f.read()
        with open(mat, "w", encoding="utf-8") as f:
            f.write(text.replace('"J4": {"weight": 0.5',
                                 '"J4": {"weight": 0.6'))
        expect_refused(good, "dataset built against another matrix", mat)

        rc = main_args(["--dataset", relab, "--out", os.path.join(tmp, "o2")])
        check(rc == 2, f"C3 command line exit status is {rc}")

        # 10: the fio output must come from the generated job, and a WAF
        # file must belong to its id and run
        fit_ids = set(r["id"] for r in man["rows"])
        size = os.path.join(tmp, "size")
        m = synth_dataset(DEFAULT_MATRIX, size, TRUTH)
        row = [r for r in m["rows"] if r["id"].startswith("J8")][0]
        for blk in row["runs"][0]["blocks"]:
            bp = os.path.join(size, blk["path"])
            doc = load_json(bp)
            doc["jobs"][0]["job options"]["size"] = "100%"
            with open(bp, "w") as f:
                json.dump(doc, f)
            blk["sha256"] = sha256_file(bp)
        write_manifest(size, m)
        expect_refused(size, "a block of another span (size swap)")
        glob = os.path.join(tmp, "glob")
        m = synth_dataset(DEFAULT_MATRIX, glob, TRUTH)
        blk = m["rows"][0]["runs"][0]["blocks"][0]
        bp = os.path.join(glob, blk["path"])
        doc = load_json(bp)
        doc["global options"]["iodepth_batch"] = "16"
        with open(bp, "w") as f:
            json.dump(doc, f)
        blk["sha256"] = sha256_file(bp)
        write_manifest(glob, m)
        expect_refused(glob, "an extra common fio option")
        wswap = os.path.join(tmp, "wafswap")
        m = synth_dataset(DEFAULT_MATRIX, wswap, TRUTH)
        row = [r for r in m["rows"] if r["id"].startswith("J7")][0]
        row["runs"][0]["waf"], row["runs"][1]["waf"] = \
            row["runs"][1]["waf"], row["runs"][0]["waf"]
        write_manifest(wswap, m)
        expect_refused(wswap, "WAF files of two runs swapped")
        wnone = os.path.join(tmp, "wafnone")
        m = synth_dataset(DEFAULT_MATRIX, wnone, TRUTH)
        ent = [r for r in m["rows"] if r["id"].startswith("J7")][0][
            "runs"][0]["waf"]
        wp = os.path.join(wnone, ent["path"])
        doc = load_json(wp)
        del doc["waf"][0]["value"]
        with open(wp, "w") as f:
            json.dump(doc, f)
        ent["sha256"] = sha256_file(wp)
        write_manifest(wnone, m)
        expect_refused(wnone, "a WAF entry with no value")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = main_args(["--dataset", wnone, "--out",
                            os.path.join(tmp, "wafnone-out")])
        check(rc == 2 and "REFUSED" in err.getvalue(),
              f"C3 the CLI exits {rc} on a WAF entry with no value")
        dup = os.path.join(tmp, "dup")
        m = synth_dataset(DEFAULT_MATRIX, dup, TRUTH)
        m["rows"][0]["runs"][0]["blocks"][1] = \
            m["rows"][0]["runs"][0]["blocks"][0]
        write_manifest(dup, m)
        expect_refused(dup, "one block given twice")
        fh = os.path.join(tmp, "fiohash")
        m = synth_dataset(DEFAULT_MATRIX, fh, TRUTH)
        m["rows"][0]["fio_sha256"] = "0" * 64
        write_manifest(fh, m)
        expect_refused(fh, "fio_sha256 of a row differs")

        # 12: fewer blocks than the matrix asks is not a fit
        short = os.path.join(tmp, "short")
        synth_dataset(DEFAULT_MATRIX, short, TRUTH, nblk=9)
        rs = fit(DEFAULT_MATRIX, short, {})
        check(len(rs["incomplete"]) == len(fit_ids),
              f"9 of 10 blocks: {len(rs['incomplete'])} rows incomplete")
        rc = main_args(["--dataset", short, "--out", os.path.join(tmp, "o3")])
        check(rc == 1, f"incomplete sampling exits {rc}")

        # 14: no qualified WAF keeps op_pcent at its prior
        nw = os.path.join(tmp, "nowaf")
        synth_dataset(DEFAULT_MATRIX, nw, TRUTH, waf="unavailable")
        rn = fit(DEFAULT_MATRIX, nw, {})
        tn = [x for x in rn["topologies"] if x["luns"] == TRUTH["luns"]][0]
        check("op_pcent" not in rn["params"] and
              tn["params"]["op_pcent"] == PRIORS["op_pcent"] and
              not any(e["metric"] == "waf" for e in tn["errors"]),
              "WAF unavailable: op_pcent stays at the prior "
              f"{tn['params']['op_pcent']}")
        pn, _ = write_outputs(rn, "nowaf", "2026-01-01",
                              os.path.join(tmp, "onw"))
        with open(pn, encoding="utf-8") as f:
            lab = json.load(f)["values"]["op_pcent"]["label"]
        check(lab == "prior", f"WAF unavailable: op_pcent label is {lab}")

        # 9: J7 available and J8 unavailable: no WAF moves op_pcent
        mx = os.path.join(tmp, "mixwaf")
        synth_dataset(DEFAULT_MATRIX, mx, TRUTH,
                      no_waf={"J8-randwrite-4k-a72"})
        rm = fit(DEFAULT_MATRIX, mx, {})
        tm = [x for x in rm["topologies"] if x["luns"] == TRUTH["luns"]][0]
        check(tm["params"]["op_pcent"] == PRIORS["op_pcent"] and
              not any(e["metric"] == "waf" for e in tm["errors"]),
              "mixed WAF: op_pcent stays at the prior "
              f"{tm['params']['op_pcent']}, no WAF error rows")
        allw = [x for x in res["topologies"] if x["luns"] == TRUTH["luns"]][0]
        check(abs(allw["params"]["op_pcent"] - PRIORS["op_pcent"]) > 1,
              "control: with both WAF rows op_pcent moves to "
              f"{allw['params']['op_pcent']:.1f}")

        # 8 (r3): a row marked not valid gives no observation
        nv = os.path.join(tmp, "notvalid")
        m = synth_dataset(DEFAULT_MATRIX, nv, TRUTH)
        for r in m["rows"]:
            if r["id"] == "J1-randread-4k-qd1":
                r["valid"] = False
        write_manifest(nv, m)
        rv = fit(DEFAULT_MATRIX, nv, {})
        used = {o[0] for o in observations(fit_rows(DEFAULT_MATRIX, nv))}
        check("J1-randread-4k-qd1 (marked not valid)" in rv["incomplete"]
              and "J1-randread-4k-qd1" not in used,
              "a J1 row marked not valid is incomplete and unused")

        # 7: a row that ran into the fio rate cap is not a fit row
        rl = os.path.join(tmp, "ratelim")
        synth_dataset(DEFAULT_MATRIX, rl, TRUTH, rate=",140000000,140000000")
        rr = fit(DEFAULT_MATRIX, rl, {})
        lim = [x for x in rr["incomplete"] if "rate limited" in x]
        check(lim and all("J5" in x for x in lim),
              f"131 MB/s writes at a 140 MB/s cap: {len(lim)} rate "
              "limited rows (J5)")

        # 15: the WAF model stays above 1 and falls toward 1
        ws = [waf_model(r) for r in (0.01, 0.07, 0.28, 1.0, 4.0, 20.0)]
        check(all(w > 1.0 for w in ws) and
              all(a > b for a, b in zip(ws, ws[1:])) and ws[-1] < 1.01,
              "WAF model > 1, falls with spare, near 1 at r=20 "
              f"({ws[0]:.2f} .. {ws[-1]:.4f})")
        z = -1.07 * math.exp(-1.07)
        w0 = lambert_w0(z)
        check(abs(w0 * math.exp(w0) - z) < 1e-12 and w0 > -1.0,
              f"W0 solves w e^w = z on the principal branch ({w0:.6f})")
        old = (1.0 + 20.0) / (2.0 * 20.0)
        check(old < 1.0, f"control: the old model gives {old:.3f} < 1 "
              "at r=20")

        # 18: the output records the priors file and the effective priors
        pf = os.path.join(tmp, "priors.json")
        with open(pf, "w") as f:
            json.dump({"fw_read_ns": 3000.0}, f)
        po = os.path.join(tmp, "opri")
        rc = main_args(["--dataset", good, "--out", po, "--priors", pf,
                        "--name", "pri", "--date", "2026-01-01"])
        with open(os.path.join(po, "calib-pri-2026-01-01.json"),
                  encoding="utf-8") as f:
            pri = json.load(f)["priors"]
        check(rc in (0, 1) and pri["file_sha256"] == sha256_file(pf) and
              pri["effective"]["fw_read_ns"] == 3000.0,
              "the JSON records the priors hash and fw_read_ns 3000")
        with open(pf, "w") as f:
            json.dump({"fw_raed_ns": 3000.0}, f)
        rc = main_args(["--dataset", good, "--out", po, "--priors", pf])
        check(rc == 2, f"control: an unknown prior key exits {rc}")

    print("calib-fit self-test: " + ("FAIL" if fails else "PASS"))
    return 1 if fails else 0


def main_args(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dataset", help="folder with manifest.json")
    ap.add_argument("--matrix", default=DEFAULT_MATRIX)
    ap.add_argument("--priors", help="JSON file of prior values")
    ap.add_argument("--name", default="ref1")
    ap.add_argument("--date", default=datetime.date.today().isoformat())
    ap.add_argument("--out")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if not a.dataset or not a.out:
        ap.error("--dataset and --out are required")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,40}", a.name):
        ap.error("--name: lower case letters, digits and '-'")
    try:
        priors = load_json(a.priors) if a.priors else {}
        res = fit(a.matrix, a.dataset, priors,
                  sha256_file(a.priors) if a.priors else None)
    except Refused as e:
        print(f"calib-fit: REFUSED: {e}", file=sys.stderr)
        return 2
    except (OSError, ValueError, KeyError) as e:
        print(f"calib-fit: {e}", file=sys.stderr)
        return 2
    for t in res["topologies"]:
        worst = max(abs(e["e"]) for e in t["errors"]) if t["errors"] else 0
        print(f"topology {t['nchs']} x {t['luns']}: "
              f"{'kept' if t['kept'] else 'dropped'}, worst |e| "
              f"{worst * 100:.2f}%")
    if res["missing"] or res["incomplete"]:
        print("calib-fit: missing or incomplete fit rows: " +
              ", ".join(res["missing"] + res["incomplete"]), file=sys.stderr)
        return 1
    path, files = write_outputs(res, a.name, a.date, a.out)
    print(f"wrote {path} and {len(files)} profile files")
    return 0 if files else 1


if __name__ == "__main__":
    sys.exit(main_args(sys.argv[1:]))
