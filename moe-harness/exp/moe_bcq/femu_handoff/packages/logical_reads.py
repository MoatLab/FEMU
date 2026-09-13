#!/usr/bin/env python3
"""Validate a trace and resolve it to file extents, NOT SSD page addresses.

One cold demand set per forward/layer; deduplicate prefix planes within the set.
For A, keep EVERY used precision's scale set, even if a higher tier is present.
"""
import argparse
import json
import math
from collections import defaultdict
from pathlib import Path

from bundle import SCHEMA, sha256, write_json


def demand(manifest, event, scales_resident=True):
    catalog = defaultdict(list)
    for p in manifest["projections"]:
        if p["layer"] == event["layer"]:
            catalog[p["expert"]].append(p)
    wanted = defaultdict(set)
    positions = event["token_positions"]
    assert len(positions) == len(set(positions))
    assert len(positions) == len(event["input_ids"]) == len(event["selected_experts"]) == len(event["precision_bits"])
    assert len(positions) == len(event["gate_scores"])
    assert event["batch_size"] == 1
    assert positions == sorted(positions) and all(type(x) is int and x >= 0 for x in positions)
    for es, bs, gs in zip(event["selected_experts"], event["precision_bits"], event["gate_scores"]):
        assert len(es) == len(bs) == len(gs) == manifest["model_config"]["num_experts_per_tok"]
        assert len(es) == len(set(es))
        assert all(math.isfinite(g) and g >= 0 for g in gs)
        for expert, bits in zip(es, bs):
            assert expert in catalog and bits in manifest["supported_bits"]
            wanted[expert].add(bits)
    extents = []
    for expert, precisions in sorted(wanted.items()):
        for p in catalog[expert]:
            for j, e in enumerate(p["planes"][:max(precisions)], 1):
                extents.append(dict(projection_id=p["id"], kind="plane", plane=j, **e))
            if not scales_resident:
                for b in sorted(precisions) if manifest["scale_mode"] == "per_precision" else [4]:
                    take = b if manifest["scale_mode"] == "per_precision" else max(precisions)
                    for j, e in enumerate(p["scales"][str(b)][:take], 1):
                        extents.append(dict(projection_id=p["id"], kind="scale", scale_set=b, column=j, **e))
    return extents


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("bundle", type=Path)
    p.add_argument("--trace", default="smoke")
    p.add_argument("--scales", choices=["resident", "on_demand"], default="resident")
    a = p.parse_args()
    mpath = a.bundle / "manifest.json"
    m = json.loads(mpath.read_text())
    tdir = a.bundle / "traces" / a.trace
    meta = json.loads((tdir / "trace_meta.json").read_text())
    assert m["schema"] == meta["schema"] == SCHEMA
    assert meta["manifest_sha256"] == sha256(mpath)
    for name, info in meta["files"].items():
        assert sha256(tdir / name) == info["sha256"]
    out = tdir / f"reads_{a.scales}.jsonl"
    expected, total, last = 0, 0, None
    layers_seen = []
    frame_info = None
    with (tdir / "logical_trace.jsonl").open() as f, out.open("x") as dst:
        for line in f:
            e = json.loads(line)
            assert e["event_id"] == expected
            assert e["phase"] in ("prefill", "decode", "teacher_forced")
            if e["phase"] == "decode":
                assert len(e["input_ids"]) == 1
            order = (e["forward_id"], e["layer"])
            assert last is None or order > last
            if last is None or last[0] != e["forward_id"]:
                assert e["forward_id"] == (0 if last is None else last[0] + 1)
                if last is not None:
                    assert layers_seen == m["totals"]["layers"], "Incomplete forward"
                layers_seen = []
                frame_info = (e["request_id"], e["phase"], e["token_positions"], e["input_ids"])
            assert frame_info == (e["request_id"], e["phase"], e["token_positions"], e["input_ids"])
            layers_seen.append(e["layer"])
            last = order
            extents = demand(m, e, a.scales == "resident")
            nbytes = sum(x["nbytes"] for x in extents)
            dst.write(json.dumps(dict(event_id=expected, forward_id=e["forward_id"],
                layer=e["layer"], request_id=e["request_id"], phase=e["phase"],
                demand_bytes=nbytes, extents=extents), separators=(",", ":")) + "\n")
            expected += 1
            total += nbytes
    assert expected == meta["events"]
    assert layers_seen == m["totals"]["layers"], "Incomplete final forward"
    write_json(tdir / f"reads_{a.scales}_summary.json", dict(events=expected,
        cold_demand_bytes=total, scales=a.scales, sha256=sha256(out),
        semantics="Deduplicated within forward/layer; no reuse across events. No LBA/page rounding/timing."))
    print(f"{expected} events, {total} logical bytes, scales={a.scales}")


if __name__ == "__main__":
    main()
