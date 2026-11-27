#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Read and audit a calibration dataset; shared by calib-fit.py and
calib-compare.py. Not a command.

A dataset folder holds manifest.json:

  {"calib_dataset": 1, "side": "drive" or "femu",
   "matrix_sha256": sha256 of calib-matrix.json,
   "fio_rate": the --rate value given to fio, e.g. ",8000000000,8000000000",
   "rows": [{"id": ..., "split": ..., "fio_sha256": ...,
             "valid": true, "runs": [
               {"blocks": [{"path": ..., "sha256": ...}, ...],
                "waf": {"path": ..., "sha256": ...}}]}]}

Each block is the fio JSON output of one time block. A WAF file is
{"id": ID, "run": N, "waf": [{"block": PATH, "value": V}, ...]}, one
entry per fio block of the run, in order, PATH the manifest path of that
block; or {"id": ID, "run": N, "unavailable": "why"}. A row of a ready
trace also holds "trace" (the matrix trace entry) and "iolog" ({"path",
"sha256"} of the frozen iolog file).

audit() raises Refused when the input could leak or mix workloads:

  - another matrix, a split label that differs from the matrix, a split
    the caller does not read, a repeated id;
  - a file whose sha256 differs, a block given twice in one row;
  - a fio output whose job name, job options or common options differ
    from the generated job of its id; a row whose fio_sha256 differs;
  - a WAF file of another id or run, a WAF entry of another fio block,
    or a WAF value that is missing, not a number, not finite or below 1;
  - a fio output with a nonzero error, or a rate other than "fio_rate";
  - a fio rate other than three comma fields ("R,W,T", each may be
    empty), since fio lets a short form apply to more operations;
  - a trace row whose iolog file, volume, window or replay options
    differ from a ready trace of the matrix, or whose fio output ran
    other options than the matrix replay options;
  - a ready trace whose replay options do not hold read_iolog with the
    file name of the frozen iolog, or whose iolog has no I/O record.

audit() does not refuse, but marks:

  - "sampling": incomplete when the runs, the blocks or the WAF values
    per run differ from the matrix "sampling" entry;
  - "rate_limited": the operations whose bandwidth in a block reached
    90% of the fio rate cap, so the cap and not the device set them;
  - "pending": the status of a trace the matrix marks pending;
  - "valid": false when the producer marked the row not valid (a
    thermal pause, a saturated emulator); no tool uses such a row.
"""

import hashlib
import json
import math
import os
import re

FIO_PCT = (("p50", "50.000000"), ("p90", "90.000000"), ("p99", "99.000000"),
           ("p99.9", "99.900000"), ("p99.99", "99.990000"))
# fio adds these to its global options: the expanded target and the cap;
# the cap is checked on its own against the manifest
FIO_RUNTIME_KEYS = ("filename", "rate")
WAF_FAMILIES = ("J7", "J8", "T1", "T2")
FIO_OPS = ("read", "write", "trim")
RATE_SHARE = 0.9
TRACE_KEYS = ("iolog_sha256", "volume", "window", "replay")
DEFAULT_RATE = ",8000000000,8000000000"


def rate_caps(rate):
    """Bytes per second per operation of a fio --rate value; 0 = none."""
    # fio applies a value to the operations after it when fewer than
    # three fields are given; only the explicit form is unambiguous
    if not re.fullmatch(r"\d*,\d*,\d*", rate or ""):
        raise Refused(f"fio_rate '{rate}' is not of the form R,W,T")
    parts = rate.split(",")
    return {op: int(v) if v else 0 for op, v in zip(FIO_OPS, parts)}


class Refused(Exception):
    """The input breaks the split, the hashes or the job binding."""


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_matrix(path):
    """The matrix document; its leading // lines (the SPDX tag) are not JSON."""
    with open(path, encoding="utf-8") as f:
        lines = f.read().split("\n")
    while lines and lines[0].startswith("//"):
        lines.pop(0)
    return json.loads("\n".join(lines))


def load_json(path):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    # fio may print notes before the JSON document
    return json.loads(text[text.find("{"):])


def check_fio(cond, matrix, doc):
    """A fio output must come from the generated job of its id."""
    cid = cond["id"]
    jobs = doc.get("jobs", [])
    if len(jobs) != 1:
        raise Refused(f"{cid}: expected one fio job, got {len(jobs)}")
    job = jobs[0]
    if job.get("jobname") != cid:
        raise Refused(f"{cid}: fio job name is '{job.get('jobname')}'")
    if int(job.get("error", 0)) != 0:
        raise Refused(f"{cid}: fio reports error {job.get('error')}")
    if str(doc.get("global options", {}).get("rate")) != matrix["_rate"]:
        raise Refused(f"{cid}: fio rate "
                      f"'{doc.get('global options', {}).get('rate')}', the "
                      f"manifest says '{matrix['_rate']}'")
    if "fio" in cond:
        want_opts = cond["fio"]
    elif str(cond["trace"].get("status")) == "ready":
        want_opts = {k: str(v) for k, v in cond["trace"]["replay"].items()}
        if "read_iolog" not in job.get("job options", {}):
            raise Refused(f"{cid}: fio ran no read_iolog, so no replay")
    else:
        return      # a pending trace stays PENDING; nothing to bind yet
    opts = {k: str(v) for k, v in job.get("job options", {}).items()}
    if opts != want_opts:
        diff = sorted(set(opts.items()) ^ set(want_opts.items()))
        raise Refused(f"{cid}: fio job options differ: {diff[:4]}")
    glob = {k: str(v) for k, v in doc.get("global options", {}).items()}
    want = dict(matrix["fio_common"], write_hist_log=cid)
    for k in FIO_RUNTIME_KEYS:
        glob.pop(k, None)
        want.pop(k, None)
    if glob != want:
        diff = sorted(set(glob.items()) ^ set(want.items()))
        raise Refused(f"{cid}: fio global options differ: {diff[:4]}")


def waf_values(cid, r, ents, paths):
    """WAF values of one run; entry k must name fio block k."""
    out = []
    for k, e in enumerate(ents):
        if not isinstance(e, dict) or k >= len(paths) or \
                e.get("block") != paths[k]:
            raise Refused(f"{cid}: run {r}: WAF entry {k + 1} is not for "
                          "fio block " + (paths[k] if k < len(paths)
                                          else "(none)"))
        v = e.get("value")
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            raise Refused(f"{cid}: run {r}: WAF entry {k + 1} (block "
                          f"{paths[k]}) has no numeric value: {v!r}")
        v = float(v)
        if not math.isfinite(v) or v < 1.0:
            raise Refused(f"{cid}: run {r}: WAF value {v} is not a finite "
                          "value >= 1")
        out.append(v)
    return out


IOLOG_OPS = ("read", "write", "trim", "sync", "datasync")


def iolog_records(data):
    """I/O records of a fio iolog of version 2 or 3; 0 when it is not
    one. A version 3 line starts with a time stamp."""
    lines = data.decode("utf-8", "replace").splitlines()
    if not lines or lines[0] not in ("fio version 2 iolog",
                                     "fio version 3 iolog"):
        return 0
    at = 1 if lines[0].endswith("2 iolog") else 2
    return sum(1 for ln in lines[1:]
               if len(ln.split()) > at and ln.split()[at] in IOLOG_OPS)


def audit(matrix_path, dataset, splits):
    """Return {"matrix", "rows", "inputs", "side"}; raise Refused."""
    matrix = read_matrix(matrix_path)
    conds = {c["id"]: c for c in matrix["conditions"]}
    man_path = os.path.join(dataset, "manifest.json")
    man = load_json(man_path)
    inputs = {"manifest.json": sha256_file(man_path),
              "calib-matrix.json": sha256_file(matrix_path)}
    if man.get("calib_dataset") != 1:
        raise Refused("manifest: calib_dataset must be 1")
    if man.get("matrix_sha256") != inputs["calib-matrix.json"]:
        raise Refused("manifest: built against another matrix")
    if "fio_rate" not in man:
        raise Refused("manifest: no fio_rate")
    caps = rate_caps(str(man["fio_rate"]))
    matrix["_rate"] = str(man["fio_rate"])
    samp = matrix.get("sampling", {})
    rows = {}
    for row in man.get("rows", []):
        cid = row.get("id")
        c = conds.get(cid)
        if c is None:
            raise Refused(f"{cid}: not a matrix id")
        if row.get("split") != c["split"]:
            raise Refused(f"{cid}: labelled {row.get('split')}, the matrix "
                          f"says {c['split']}")
        if c["split"] not in splits:
            raise Refused(f"{cid}: the matrix marks it {c['split']}; "
                          f"this tool reads {', '.join(splits)} rows only")
        if cid in rows:
            raise Refused(f"{cid}: given twice")
        if "fio" in c and row.get("fio_sha256") != \
                matrix.get("fio_sha256", {}).get(cid):
            raise Refused(f"{cid}: fio_sha256 differs from the matrix")
        pending = None
        if "trace" in c:
            status = str(c["trace"].get("status", ""))
            want = {k: c["trace"].get(k) for k in TRACE_KEYS}
            if status.startswith("pending"):
                pending = status
            elif status != "ready" or None in want.values():
                raise Refused(f"{cid}: the matrix trace is not ready")
            elif row.get("trace") != want:
                raise Refused(f"{cid}: trace iolog, volume, window or "
                              "replay options differ from the matrix")
            else:
                ent = row.get("iolog") or {}
                try:
                    with open(os.path.join(dataset, ent["path"]), "rb") as f:
                        data = f.read()
                except (KeyError, OSError):
                    raise Refused(f"{cid}: the frozen iolog file is missing")
                got = hashlib.sha256(data).hexdigest()
                if got != want["iolog_sha256"] or got != ent.get("sha256"):
                    raise Refused(f"{cid}: iolog sha256 {got[:12]} differs "
                                  "from the matrix")
                # fio must replay this file: the options name it, and it
                # holds I/O; a hash alone does not show a replay
                name = os.path.basename(ent["path"])
                rp = want["replay"] if isinstance(want["replay"], dict) \
                    else {}
                if str(rp.get("read_iolog")) != name:
                    raise Refused(f"{cid}: the replay options must hold "
                                  f"read_iolog={name}, the frozen iolog")
                if iolog_records(data) == 0:
                    raise Refused(f"{cid}: the frozen iolog holds no I/O "
                                  "record")
                inputs[ent["path"]] = got
        seen = set()
        runs = []
        for r, run in enumerate(row.get("runs", []), 1):
            ents = list(run.get("blocks", []))
            if c["family"] in WAF_FAMILIES:
                if "waf" not in run:
                    raise Refused(f"{cid}: run {r} has no waf entry")
                ents.append(run["waf"])
            for ent in ents:
                got = sha256_file(os.path.join(dataset, ent["path"]))
                if got != ent.get("sha256"):
                    raise Refused(f"{cid}: {ent['path']} has sha256 "
                                  f"{got[:12]}, the manifest says "
                                  f"{str(ent.get('sha256'))[:12]}")
                if ent["path"] in seen or got in seen:
                    raise Refused(f"{cid}: {ent['path']} is given twice")
                seen.update((ent["path"], got))
                inputs[ent["path"]] = got
            blocks = [load_json(os.path.join(dataset, b["path"]))
                      for b in run.get("blocks", [])]
            for b in blocks:
                check_fio(c, matrix, b)
            waf = unavailable = None
            if "waf" in run:
                w = load_json(os.path.join(dataset, run["waf"]["path"]))
                if w.get("id") != cid or w.get("run") != r:
                    raise Refused(f"{cid}: WAF file of {w.get('id')} run "
                                  f"{w.get('run')} in run {r}")
                if "unavailable" in w:
                    unavailable = str(w["unavailable"])
                else:
                    waf = waf_values(cid, r, w["waf"],
                                     [b["path"] for b in run["blocks"]])
            runs.append({"blocks": blocks, "waf": waf,
                         "waf_unavailable": unavailable})
        nrep, nblk = samp.get("replicates"), samp.get("blocks")
        # each WAF value belongs to one fio block of the same run
        full = len(runs) == nrep and all(
            len(r["blocks"]) == nblk and
            (r["waf"] is None or len(r["waf"]) == nblk) for r in runs)
        limited = sorted({op for r in runs for b in r["blocks"]
                          for op in FIO_OPS if caps[op] and
                          float(b["jobs"][0].get(op, {}).get("bw_bytes", 0))
                          >= RATE_SHARE * caps[op]})
        rows[cid] = {"cond": c, "runs": runs, "valid": row.get("valid", True),
                     "pending": pending, "rate_limited": limited,
                     "sampling": "ok" if full else
                     f"incomplete: {len(runs)} runs of "
                     f"{[len(r['blocks']) for r in runs]} blocks and "
                     f"{[len(r['waf'] or []) for r in runs]} WAF values, "
                     f"the matrix asks {nrep} of {nblk}"}
    return {"matrix": matrix, "rows": rows, "inputs": inputs,
            "side": man.get("side"), "fio_rate": matrix["_rate"],
            "rate_caps": caps}


# ---------------------------------------------------------------- synthetic

def fio_doc(matrix, cond, vals, n, stamp=0, rate=DEFAULT_RATE):
    """A fio JSON output of one block of @cond with @vals per metric."""
    job = {"jobname": cond["id"]}
    if "fio" in cond:
        job["job options"] = dict(cond["fio"])
    elif cond["trace"].get("replay"):
        job["job options"] = {k: str(v) for k, v in
                              cond["trace"]["replay"].items()}
    for op in ("read", "write", "trim"):
        job[op] = {"iops": vals.get(f"{op}.iops", 0.0),
                   "bw_bytes": int(round(vals.get(f"{op}.bw", 0))),
                   "clat_ns": {"N": n, "percentile": {
                       key: int(round(vals.get(f"{op}.{k}", 0)))
                       for k, key in FIO_PCT}}}
    glob = dict(matrix["fio_common"], write_hist_log=cond["id"],
                filename="/proc/self/fd/3", rate=rate)
    return {"fio version": "fio-3.36", "timestamp": stamp,
            "global options": glob, "jobs": [job]}


def synth(matrix_path, out, spec, side="drive", nrep=3, nblk=10,
          rate=DEFAULT_RATE):
    """Write a dataset. @spec maps id -> {"values": {metric: v},
    "noise": {metric: amp}, "n": samples per block, "waf": v or
    "unavailable", "valid": bool}. Each block varies by a zero-mean
    pattern of +-amp; each run adds a small offset."""
    matrix = read_matrix(matrix_path)
    conds = {c["id"]: c for c in matrix["conditions"]}
    rows = []
    for cid, sp in spec.items():
        c = conds[cid]
        runs = []
        for r in range(nrep):
            blocks = []
            for b in range(nblk):
                vals = {}
                for m, v in sp.get("values", {}).items():
                    amp = sp.get("noise", {}).get(m, 0.004)
                    k = ((b % 5) - 2) / 2.0 * amp + (r - 1) * amp / 4
                    vals[m] = v * (1 + k)
                rel = f"{cid}/r{r + 1}/b{b + 1:02d}.json"
                path = os.path.join(out, rel)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w") as f:
                    json.dump(fio_doc(matrix, c, vals, sp.get("n", 200000),
                                      1000 * r + b, rate), f)
                blocks.append({"path": rel, "sha256": sha256_file(path)})
            run = {"blocks": blocks}
            if c["family"] in WAF_FAMILIES:
                rel = f"{cid}/r{r + 1}/waf.json"
                w = sp.get("waf", "unavailable")
                amp = sp.get("noise", {}).get("waf", 0.004)
                doc = {"id": cid, "run": r + 1}
                if w == "unavailable":
                    doc["unavailable"] = "no qualified counter"
                else:
                    doc["waf"] = [{"block": blocks[b]["path"],
                                   "value": sp.get("waf_fix") or
                                   w * (1 + ((b % 5) - 2) / 2.0 * amp)}
                                  for b in range(sp.get("waf_n", nblk))]
                with open(os.path.join(out, rel), "w") as f:
                    json.dump(doc, f)
                run["waf"] = {"path": rel,
                              "sha256": sha256_file(os.path.join(out, rel))}
            runs.append(run)
        row = {"id": cid, "split": c["split"], "runs": runs,
               "valid": sp.get("valid", True)}
        if "fio" in c:
            row["fio_sha256"] = matrix["fio_sha256"][cid]
        if "trace" in c:
            row["trace"] = {k: c["trace"].get(k) for k in TRACE_KEYS}
            if "iolog" in sp:
                rel = f"{cid}/iolog.bin"
                with open(os.path.join(out, rel), "wb") as f:
                    f.write(sp["iolog"])
                row["iolog"] = {"path": rel, "sha256":
                                sha256_file(os.path.join(out, rel))}
        rows.append(row)
    man = {"calib_dataset": 1, "side": side, "fio_rate": rate,
           "matrix_sha256": sha256_file(matrix_path), "rows": rows}
    write_manifest(out, man)
    return man


def write_manifest(d, man):
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "manifest.json"), "w") as f:
        json.dump(man, f, indent=1)
