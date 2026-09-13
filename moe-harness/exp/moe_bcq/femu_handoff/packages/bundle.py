#!/usr/bin/env python3
"""Portable, unpadded routed-BCQ payloads. No CUDA dependency."""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import hashlib
import json
import re
from pathlib import Path

import numpy as np

SCHEMA = "moe-bcq-handoff-v1"
ROUTED = re.compile(r"^model\.layers\.(\d+)\.mlp\.experts\.(\d+)\.(gate|up|down)_proj\.qweight$")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(8 << 20), b""):
            h.update(b)
    return h.hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def emit(f, tensor, dtype):
    arr = np.asarray(tensor.numpy(), dtype=dtype, order="C")
    data = arr.tobytes()
    rec = dict(file=Path(f.name).name, offset=f.tell(), nbytes=len(data),
               dtype=np.dtype(dtype).str, shape=list(arr.shape),
               sha256=hashlib.sha256(data).hexdigest())
    f.write(data)
    return rec


def export(state_path, model_dir, arm, out):
    import torch
    torch.set_num_threads(2)
    out, model_dir, state_path = Path(out), Path(model_dir), Path(state_path)
    out.mkdir(parents=True, exist_ok=False)
    config = json.loads((model_dir / "config.json").read_text())
    state = torch.load(state_path, map_location="cpu", weights_only=True, mmap=True)
    keys = [(ROUTED.fullmatch(k), k) for k in state if ROUTED.fullmatch(k)]
    keys.sort(key=lambda t: (int(t[0][1]), int(t[0][2]), t[0][3]))
    if not keys:
        raise ValueError("No routed expert qweight tensors")
    manifest = dict(schema=SCHEMA, model=model_dir.name, arm=arm,
                    scale_mode="per_precision" if arm == "A" else "shared_alpha4_prefix",
                    supported_bits=[2, 3, 4], source_state=dict(name=state_path.name,
                    sha256=sha256(state_path)), model_config=config,
                    source_config_sha256=sha256(model_dir / "config.json"),
                    mre_steps="not inferred from tensor data; see source quantization report",
                    exporter_sha256=sha256(__file__), byte_order="little", padding_bytes=0,
                    beta="implicit_zero_verified", bias="absent_verified",
                    native_qweight_order=["input_word32", "plane", "output"],
                    plane_order=["input_word32", "output"],
                    scale_column_order=["input_group", "output"],
                    bit_encoding="bit t of word k is input 32*k+t; 0=-1, 1=+1",
                    placement="unassigned: file offsets are NOT LBA or NAND pages",
                    projections=[])
    with (out / "planes.bin").open("xb") as pf, (out / "scales.bin").open("xb") as sf:
        for m, key in keys:
            prefix = key.removesuffix("qweight")
            q = state[key]
            a4 = state[prefix + "alpha_4"]
            assert q.dtype == torch.int32 and q.ndim == 3 and q.shape[1] == 4
            i, o = q.shape[0] * 32, q.shape[2]
            assert a4.dtype == torch.float16 and a4.shape[1:] == (4, o)
            assert i % a4.shape[0] == 0
            g = i // a4.shape[0]
            assert g % 32 == 0
            assert prefix + "bias" not in state, "Nonzero/explicit bias needs schema extension"
            use = [2, 3, 4] if arm == "A" else [4]
            for p in use:
                a, b = state[prefix + f"alpha_{p}"], state[prefix + f"beta_{p}"]
                assert a.shape == (i // g, p, o) and a.dtype == torch.float16
                assert torch.isfinite(a).all(), f"Invalid alpha: {prefix}"
                assert b.shape == (i // g, o) and torch.count_nonzero(b) == 0, prefix
            rec = dict(id=prefix.rstrip("."), layer=int(m[1]), expert=int(m[2]),
                       projection=m[3] + "_proj", weight_shape_out_in=[o, i],
                       group_size=g, planes=[], scales={})
            for j in range(4):
                rec["planes"].append(emit(pf, q[:, j, :], "<i4"))
            for p in use:
                a = state[prefix + f"alpha_{p}"]
                rec["scales"][str(p)] = [emit(sf, a[:, j, :], "<f2") for j in range(p)]
            manifest["projections"].append(rec)
    manifest["payloads"] = {name: dict(nbytes=(out / name).stat().st_size,
                                      sha256=sha256(out / name))
                            for name in ("planes.bin", "scales.bin")}
    manifest["totals"] = dict(projections=len(keys),
        experts=len({(p["layer"], p["expert"]) for p in manifest["projections"]}),
        layers=sorted({p["layer"] for p in manifest["projections"]}),
        **{k.replace(".bin", "_bytes"): v["nbytes"] for k, v in manifest["payloads"].items()})
    # Completeness is derived from the original checkpoint's index, not a Qwen constant.
    index_path = model_dir / "model.safetensors.index.json"
    manifest["source_weight_index_sha256"] = sha256(index_path)
    index = json.loads(index_path.read_text())["weight_map"]
    expected = {k.removesuffix(".weight") for k in index
                if ROUTED.fullmatch(k.removesuffix(".weight") + ".qweight")}
    assert expected == {p["id"] for p in manifest["projections"]}, "Incomplete routed export"
    write_json(out / "manifest.json", manifest)
    print(json.dumps(manifest["totals"]), flush=True)
    return manifest


def read_extent(root, extent):
    path = Path(root) / extent["file"]
    with path.open("rb") as f:
        f.seek(extent["offset"])
        data = f.read(extent["nbytes"])
    if hashlib.sha256(data).hexdigest() != extent["sha256"]:
        raise ValueError(f"Extent checksum mismatch: {extent}")
    return np.frombuffer(data, dtype=extent["dtype"]).reshape(extent["shape"])


def restore_projection(root, rec, bits, scale_mode):
    """Restore native qweight/alpha layout; only the requested prefix is read."""
    planes = [read_extent(root, e) for e in rec["planes"][:bits]]
    key = str(bits) if scale_mode == "per_precision" else "4"
    scales = [read_extent(root, e) for e in rec["scales"][key][:bits]]
    return np.stack(planes, axis=1), np.stack(scales, axis=1)


def validate(root, state_path=None):
    root = Path(root)
    m = json.loads((root / "manifest.json").read_text())
    assert m["schema"] == SCHEMA
    for name, info in m["payloads"].items():
        assert (root / name).stat().st_size == info["nbytes"]
        assert sha256(root / name) == info["sha256"], name
    # Exact extent coverage: neither overlaps nor unreported holes are permitted.
    positions = {"planes.bin": 0, "scales.bin": 0}
    ids = set()
    with ExitStack() as stack:
        streams = {k: stack.enter_context((root / k).open("rb")) for k in positions}
        for rec in m["projections"]:
            assert rec["id"] not in ids
            ids.add(rec["id"])
            o, i = rec["weight_shape_out_in"]
            assert len(rec["planes"]) == 4 and i % rec["group_size"] == 0
            assert set(rec["scales"]) == ({"2", "3", "4"} if m["scale_mode"] == "per_precision" else {"4"})
            for e in rec["planes"]:
                assert e["shape"] == [i//32, o] and e["dtype"] == "<i4"
            for p, columns in rec["scales"].items():
                assert len(columns) == int(p)
                for e in columns:
                    assert e["shape"] == [i//rec["group_size"], o] and e["dtype"] == "<f2"
            for e in rec["planes"] + [e for v in rec["scales"].values() for e in v]:
                assert e["offset"] == positions[e["file"]]
                assert e["nbytes"] == int(np.prod(e["shape"])) * np.dtype(e["dtype"]).itemsize
                data = streams[e["file"]].read(e["nbytes"])
                assert hashlib.sha256(data).hexdigest() == e["sha256"], rec["id"]
                positions[e["file"]] += e["nbytes"]
    assert all(positions[k] == v["nbytes"] for k, v in m["payloads"].items())
    checked = []
    if state_path:
        import torch
        assert sha256(state_path) == m["source_state"]["sha256"]
        state = torch.load(state_path, map_location="cpu", weights_only=True, mmap=True)
        # First/middle/last expert, all three projections and all precisions.
        experts = sorted({(r["layer"], r["expert"]) for r in m["projections"]})
        sample = {experts[0], experts[len(experts)//2], experts[-1]}
        for rec in m["projections"]:
            if (rec["layer"], rec["expert"]) not in sample:
                continue
            for bits in (2, 3, 4):
                q, a = restore_projection(root, rec, bits, m["scale_mode"])
                prefix = rec["id"] + "."
                ap = bits if m["arm"] == "A" else 4
                assert np.array_equal(q, state[prefix + "qweight"][:, :bits, :].numpy())
                assert np.array_equal(a, state[prefix + f"alpha_{ap}"][:, :bits, :].numpy())
            checked.append(rec["id"])
    result = dict(payload_checksums="passed", extent_coverage="passed", extent_checksums="passed",
                  source_roundtrip_projections=checked, precisions=[2, 3, 4],
                  note="Byte/tensor validation; does not measure FEMU or GPU inference latency")
    # A receiver without the source checkpoint must not erase the sender's
    # roundtrip evidence or change a checksummed package during verification.
    if state_path:
        write_json(root / "validation.json", result)
    print(json.dumps(result), flush=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("export")
    e.add_argument("--state", required=True)
    e.add_argument("--model", required=True)
    e.add_argument("--arm", choices=["A", "B", "C"], required=True)
    e.add_argument("--output", required=True)
    v = sub.add_parser("validate")
    v.add_argument("bundle")
    v.add_argument("--state")
    a = p.parse_args()
    if a.cmd == "export":
        export(a.state, a.model, a.arm, a.output)
        validate(a.output, a.state)
    else:
        validate(a.bundle, a.state)


if __name__ == "__main__":
    main()
