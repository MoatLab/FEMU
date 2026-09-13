#!/usr/bin/env python3
"""Map routed BCQ planes and shared scale columns to aligned QLC LBAs.

The mapping assumes a freshly reset FEMU device is filled sequentially from
LPN 0.  Under that contract, allocation ordinal equals LPN and the closed-form
FEMU channel->LUN->page write pointer determines the physical page class.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import defaultdict
from dataclasses import asdict, dataclass
from itertools import zip_longest
from pathlib import Path

from bundle import SCHEMA, sha256, write_json


LAYOUT_SCHEMA = "moe-bcq-qlc-aligned-layout-v1"
MAPPED_SCHEMA = "moe-bcq-mapped-layer-reads-v1"
PROJECTION_ORDER = ("gate_proj", "up_proj", "down_proj")


@dataclass(frozen=True)
class Geometry:
    sector_bytes: int = 512
    sectors_per_page: int = 32
    pages_per_block: int = 512
    blocks_per_plane: int = 1024
    planes_per_lun: int = 1
    luns_per_channel: int = 4
    channels: int = 2
    op_percent: int = 7
    pairing_profile: str = "patched-512"

    @property
    def page_bytes(self):
        return self.sector_bytes * self.sectors_per_page

    @property
    def parallel_luns(self):
        return self.channels * self.luns_per_channel * self.planes_per_lun

    @property
    def line_pages(self):
        return self.pages_per_block * self.parallel_luns

    @property
    def raw_bytes(self):
        return self.line_pages * self.blocks_per_plane * self.page_bytes

    @property
    def exposed_bytes_nominal(self):
        return self.raw_bytes * (100 - self.op_percent) // 100

    def validate(self):
        if self.sector_bytes <= 0 or self.sectors_per_page <= 0:
            raise ValueError("Sector/page geometry must be positive")
        if self.pages_per_block != 512 or self.pairing_profile != "patched-512":
            raise ValueError("This mapper requires the patched 512-row FEMU QLC pairing table")
        if self.pages_per_block % 8 or self.parallel_luns <= 0:
            raise ValueError("Unsupported FEMU geometry")


def qlc_class(page_in_block):
    """Expected init_qlc_page_pairing class after the rows-1 fix."""
    if not 0 <= page_in_block < 512:
        raise ValueError(page_in_block)
    if page_in_block <= 5:
        return 0
    if page_in_block <= 7:
        return 1
    return (page_in_block % 8) // 2


# Which QLC class slot each bit-plane tier is placed in. A policy is a
# permutation of the four slots, so every policy allocates exactly the same
# pages, the same fragments and the same NVMe commands -- only the physical page
# class under each plane changes. That is what makes the comparison controlled:
# the placement is the single variable, with byte layout and command structure
# held fixed. A baseline built by packing sequentially instead would also change
# the request pattern and confound the two.
def slot_for(tier, expert_ordinal, policy):
    if policy == "aligned":
        # B1 on the fastest class, B4 on the slowest. B1/B2 are read on every
        # expert selection; B4 only for the top tier.
        return tier
    if policy == "inverted":
        # The worst case: the always-read planes on the slowest pages.
        return 3 - tier
    if policy == "rotated":
        # Class-oblivious control. Each expert shifts the permutation by one, so
        # across experts every tier meets every class equally often and the
        # read-frequency skew buys nothing.
        return (tier + expert_ordinal) % 4
    raise ValueError(f"Unknown placement policy: {policy}")


PLACEMENT_POLICIES = ("aligned", "inverted", "rotated")


def item_key(kind, projection_id, index, scale_set=4):
    if kind == "plane":
        return f"{projection_id}/B{index}"
    return f"{projection_id}/alpha{scale_set}/C{index}"


def canonical_hash(value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(data).hexdigest()


def group_catalog(manifest):
    grouped = defaultdict(dict)
    for rec in manifest["projections"]:
        key = (rec["layer"], rec["expert"])
        if rec["projection"] in grouped[key]:
            raise ValueError(f"Duplicate projection: {key} {rec['projection']}")
        grouped[key][rec["projection"]] = rec
    for key, projections in grouped.items():
        if set(projections) != set(PROJECTION_ORDER):
            raise ValueError(f"Expected gate/up/down projections for {key}")
    return [(key, grouped[key]) for key in sorted(grouped)]


def usable_cycle_base_lpn(cycle_index, geom):
    """Each usable 8-page cycle contains class 0/1/2/3 slots."""
    cycles_per_block = (geom.pages_per_block - 8) // 8
    block, within = divmod(cycle_index, cycles_per_block)
    page = 8 + 8 * within
    return block * geom.line_pages + page * geom.parallel_luns


def target_fragments(source, item, tier, slot, expert_cycle, cursor_pages, geom):
    """Place one source extent in same-class slots, returning page-padded fragments."""
    slot_pages = 2 * geom.parallel_luns
    remaining = source["nbytes"]
    source_delta = 0
    fragments = []
    while remaining:
        cycle_delta, within = divmod(cursor_pages, slot_pages)
        room_pages = slot_pages - within
        take = min(remaining, room_pages * geom.page_bytes)
        allocated_pages = math.ceil(take / geom.page_bytes)
        base = usable_cycle_base_lpn(expert_cycle + cycle_delta, geom)
        target_lpn = base + slot * slot_pages + within
        for page_delta in range(allocated_pages):
            physical_page = ((target_lpn + page_delta) // geom.parallel_luns) % geom.pages_per_block
            if qlc_class(physical_page) != slot:
                raise AssertionError((item, tier, slot, target_lpn, physical_page))
        fragments.append(dict(source_offset=source["offset"] + source_delta,
                              source_nbytes=take, target_lpn=target_lpn,
                              target_offset=target_lpn * geom.page_bytes,
                              lba_start=target_lpn * geom.sectors_per_page,
                              sector_count=math.ceil(take / geom.sector_bytes),
                              allocated_pages=allocated_pages,
                              allocated_bytes=allocated_pages * geom.page_bytes,
                              page_class=slot))
        remaining -= take
        source_delta += take
        cursor_pages += allocated_pages
    return fragments, cursor_pages


def make_extent_map(bundle, manifest, geom, policy="aligned"):
    if manifest["schema"] != SCHEMA:
        raise ValueError("Unsupported bundle schema")
    if manifest["scale_mode"] != "shared_alpha4_prefix":
        raise ValueError("v1 QLC mapper expects shared alpha4-prefix scales")
    if policy not in PLACEMENT_POLICIES:
        raise ValueError(f"Unknown placement policy: {policy}")
    geom.validate()
    groups = group_catalog(manifest)
    slot_pages = 2 * geom.parallel_luns
    entries = []
    seen = set()
    cycles_per_expert = None
    for expert_ordinal, ((layer, expert), projections) in enumerate(groups):
        # All four tiers must consume identical page positions to preserve pairing.
        layouts = []
        for tier in range(4):
            sources = []
            for projection in PROJECTION_ORDER:
                rec = projections[projection]
                sources.append(("plane", rec, rec["planes"][tier]))
            for projection in PROJECTION_ORDER:
                rec = projections[projection]
                sources.append(("scale", rec, rec["scales"]["4"][tier]))
            layouts.append(sources)
        allocated_shape = [sum(math.ceil(src["nbytes"] / geom.page_bytes)
                               for _, _, src in sources) for sources in layouts]
        if len(set(allocated_shape)) != 1:
            raise ValueError(f"Tier allocation mismatch for layer={layer}, expert={expert}")
        need_cycles = math.ceil(allocated_shape[0] / slot_pages)
        if cycles_per_expert is None:
            cycles_per_expert = need_cycles
        elif cycles_per_expert != need_cycles:
            raise ValueError("v1 requires a uniform expert footprint")
        expert_cycle = expert_ordinal * cycles_per_expert
        for tier, sources in enumerate(layouts):
            cursor = 0
            for kind, rec, src in sources:
                index = tier + 1
                key = item_key(kind, rec["id"], index)
                if key in seen:
                    raise ValueError(f"Duplicate item: {key}")
                seen.add(key)
                slot = slot_for(tier, expert_ordinal, policy)
                fragments, cursor = target_fragments(src, key, tier, slot,
                                                     expert_cycle, cursor, geom)
                entries.append(dict(item_id=key, kind=kind, layer=layer,
                    expert=expert, projection=rec["projection"],
                    projection_id=rec["id"], plane=(index if kind == "plane" else None),
                    scale_set=(4 if kind == "scale" else None),
                    column=(index if kind == "scale" else None),
                    source_file=src["file"], source_offset=src["offset"],
                    nbytes=src["nbytes"], source_sha256=src["sha256"],
                    dtype=src["dtype"], shape=src["shape"], tier=tier,
                    target_class=slot,
                    allocated_bytes=sum(f["allocated_bytes"] for f in fragments),
                    fragments=fragments))
            if cursor != allocated_shape[tier]:
                raise AssertionError("Allocation cursor mismatch")
    used_cycles = len(groups) * cycles_per_expert
    cycles_per_block = (geom.pages_per_block - 8) // 8
    blocks_used = math.ceil(used_cycles / cycles_per_block)
    image_pages = blocks_used * geom.line_pages
    image_bytes = image_pages * geom.page_bytes
    if image_bytes > geom.exposed_bytes_nominal:
        raise ValueError(f"Layout needs {image_bytes} bytes, nominal exposed capacity is "
                         f"{geom.exposed_bytes_nominal} bytes")
    data_bytes = sum(e["nbytes"] for e in entries)
    allocated_bytes = sum(e["allocated_bytes"] for e in entries)
    return dict(schema=LAYOUT_SCHEMA, policy="qlc_aligned_expert_plane_major",
                placement_policy=policy,
                placement_slots={f"B{t+1}": slot_for(t, 0, policy) for t in range(4)},
                mapping_contract="fresh FEMU; sequential full fill from LPN 0; no intervening writes",
                scale_policy="alpha4 column j shares QLC class j-1 with Bj",
                projection_order=list(PROJECTION_ORDER), geometry=asdict(geom),
                cycles_per_block=cycles_per_block, cycles_per_expert=cycles_per_expert,
                experts=len(groups), entries=entries,
                totals=dict(image_pages=image_pages, image_bytes=image_bytes,
                            blocks_used=blocks_used, data_bytes=data_bytes,
                            page_allocated_data_bytes=allocated_bytes,
                            filler_bytes=image_bytes-data_bytes,
                            payload_fraction=data_bytes/image_bytes))


def source_matches(read, entry):
    expected = dict(file=entry["source_file"], offset=entry["source_offset"],
                    nbytes=entry["nbytes"], dtype=entry["dtype"], shape=entry["shape"],
                    sha256=entry["source_sha256"])
    return all(read.get(k) == v for k, v in expected.items())


def coalesce_commands(mapped, max_io_bytes, group_id):
    commands = []
    for frag in sorted(mapped, key=lambda x: x["lba_start"]):
        if frag["nbytes"] % 512:
            raise ValueError("Mapped fragment is not sector aligned")
        if (commands and commands[-1]["lba_start"] + commands[-1]["sector_count"] == frag["lba_start"]
                and commands[-1]["page_class"] == frag["page_class"]
                and commands[-1]["nbytes"] + frag["nbytes"] <= max_io_bytes):
            cmd = commands[-1]
            cmd["sector_count"] += frag["sector_count"]
            cmd["nbytes"] += frag["nbytes"]
            if frag["item_id"] not in cmd["item_ids"]:
                cmd["item_ids"].append(frag["item_id"])
        else:
            commands.append(dict(command_id=f"{group_id}:{len(commands)}",
                lba_start=frag["lba_start"], sector_count=frag["sector_count"],
                nbytes=frag["nbytes"], page_class=frag["page_class"],
                item_ids=[frag["item_id"]], operation="read"))
    return commands


def map_layer_reads(layer_reads, output_path, extent_map, max_io_bytes):
    catalog = {e["item_id"]: e for e in extent_map["entries"]}
    groups = commands = command_bytes = items = fragments = 0
    with Path(layer_reads).open() as src, Path(output_path).open("x") as dst:
        for line in src:
            group = json.loads(line)
            mapped = []
            for read in group["reads"]:
                entry = catalog.get(read["item_id"])
                if entry is None or not source_matches(read, entry):
                    raise ValueError(f"Read does not match manifest: {read['item_id']}")
                for fragment_index, frag in enumerate(entry["fragments"]):
                    mapped.append(dict(item_id=entry["item_id"], kind=entry["kind"],
                        projection_id=entry["projection_id"], plane=entry["plane"],
                        scale_set=entry["scale_set"], column=entry["column"],
                        fragment_index=fragment_index, source_file=entry["source_file"],
                        source_offset=frag["source_offset"], image_offset=frag["target_offset"],
                        nbytes=frag["source_nbytes"], lba_start=frag["lba_start"],
                        sector_count=frag["sector_count"], page_class=frag["page_class"],
                        operation="read"))
            cmds = coalesce_commands(mapped, max_io_bytes, group["group_id"])
            out = {k: v for k, v in group.items() if k != "reads"}
            out.update(schema=MAPPED_SCHEMA, mapped_fragments=mapped, commands=cmds,
                       mapped_fragment_count=len(mapped), command_count=len(cmds),
                       command_bytes=sum(c["nbytes"] for c in cmds))
            dst.write(json.dumps(out, separators=(",", ":")) + "\n")
            groups += 1
            items += len(group["reads"])
            fragments += len(mapped)
            commands += len(cmds)
            command_bytes += sum(c["nbytes"] for c in cmds)
    return dict(groups=groups, items=items, fragments=fragments, commands=commands,
                command_bytes=command_bytes, max_io_bytes=max_io_bytes,
                recommended_queue_depth=32)


def plan(bundle, layer_reads, output, geom, max_io_bytes, policy="aligned"):
    bundle, layer_reads, output = Path(bundle), Path(layer_reads), Path(output)
    output.mkdir(parents=True, exist_ok=False)
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    extent_map = make_extent_map(bundle, manifest, geom, policy)
    extent_map.update(source_manifest_sha256=sha256(manifest_path),
                      layout_spec_sha256=canonical_hash({k: v for k, v in extent_map.items()
                                                         if k != "entries"}))
    extent_path = output / "extent_map.json"
    write_json(extent_path, extent_map)
    mapped_path = output / "mapped_reads.jsonl"
    replay = map_layer_reads(layer_reads, mapped_path, extent_map, max_io_bytes)
    try:
        portable_reads = layer_reads.relative_to(bundle).as_posix()
    except ValueError:
        portable_reads = str(layer_reads)
    summary = dict(schema=LAYOUT_SCHEMA, status="planned_not_materialized",
        source_bundle=bundle.name, source_manifest_sha256=sha256(manifest_path),
        source_layer_reads=portable_reads, source_layer_reads_sha256=sha256(layer_reads),
        mapper_sha256=sha256(__file__),
        extent_map_sha256=sha256(extent_path), mapped_reads_sha256=sha256(mapped_path),
        policy=extent_map["policy"], placement_policy=policy,
        placement_slots=extent_map["placement_slots"],
        geometry=extent_map["geometry"],
        totals=extent_map["totals"], replay_input=replay,
        validation_required=["fresh device and zero host writes", "sequential fill from LPN 0",
                             "FEMU WRITE-log PPA/page-class match", "read-back byte equality"],
        warning="pgs_per_blk=512 requires the FEMU QLC pairing rows-1 fix")
    write_json(output / "layout_summary.json", summary)
    return summary


def validate_layout(bundle, layer_reads, layout):
    bundle, layer_reads, layout = Path(bundle), Path(layer_reads), Path(layout)
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    extent_path, mapped_path = layout / "extent_map.json", layout / "mapped_reads.jsonl"
    extent_map = json.loads(extent_path.read_text())
    summary = json.loads((layout / "layout_summary.json").read_text())
    if extent_map["schema"] != LAYOUT_SCHEMA or summary["schema"] != LAYOUT_SCHEMA:
        raise ValueError("Layout schema mismatch")
    if extent_map["source_manifest_sha256"] != sha256(manifest_path):
        raise ValueError("Manifest checksum mismatch")
    if summary["extent_map_sha256"] != sha256(extent_path):
        raise ValueError("Extent-map checksum mismatch")
    if summary["mapped_reads_sha256"] != sha256(mapped_path):
        raise ValueError("Mapped-trace checksum mismatch")
    if summary["source_layer_reads_sha256"] != sha256(layer_reads):
        raise ValueError("Layer-read checksum mismatch")
    geom = Geometry(**extent_map["geometry"])
    geom.validate()

    expected = {}
    for rec in manifest["projections"]:
        for index, source in enumerate(rec["planes"], 1):
            expected[item_key("plane", rec["id"], index)] = source
        for index, source in enumerate(rec["scales"]["4"], 1):
            expected[item_key("scale", rec["id"], index)] = source
    entries = {entry["item_id"]: entry for entry in extent_map["entries"]}
    if len(entries) != len(extent_map["entries"]) or set(entries) != set(expected):
        raise ValueError("Extent-map catalog is incomplete or duplicated")

    allocated = []
    class_allocated_pages = [0, 0, 0, 0]
    data_bytes = allocated_bytes = 0
    for key, entry in entries.items():
        source = expected[key]
        if not (entry["source_offset"] == source["offset"]
                and entry["nbytes"] == source["nbytes"]
                and entry["source_sha256"] == source["sha256"]
                and entry["dtype"] == source["dtype"]
                and entry["shape"] == source["shape"]):
            raise ValueError(f"Source metadata mismatch: {key}")
        cursor = source["offset"]
        item_bytes = 0
        for frag in entry["fragments"]:
            if frag["source_offset"] != cursor or frag["target_offset"] % geom.page_bytes:
                raise ValueError(f"Fragment alignment/continuity mismatch: {key}")
            if frag["lba_start"] * geom.sector_bytes != frag["target_offset"]:
                raise ValueError(f"LBA mismatch: {key}")
            if frag["sector_count"] * geom.sector_bytes != frag["source_nbytes"]:
                raise ValueError(f"Sector count mismatch: {key}")
            if frag["page_class"] != entry["target_class"]:
                raise ValueError(f"Class metadata mismatch: {key}")
            for page_delta in range(frag["allocated_pages"]):
                lpn = frag["target_lpn"] + page_delta
                page = (lpn // geom.parallel_luns) % geom.pages_per_block
                if page < 8 or qlc_class(page) != entry["target_class"]:
                    raise ValueError(f"Physical QLC class mismatch: {key}, LPN {lpn}")
            start = frag["target_offset"]
            end = start + frag["allocated_bytes"]
            allocated.append((start, end, key))
            class_allocated_pages[entry["target_class"]] += frag["allocated_pages"]
            cursor += frag["source_nbytes"]
            item_bytes += frag["source_nbytes"]
            allocated_bytes += frag["allocated_bytes"]
        if item_bytes != source["nbytes"]:
            raise ValueError(f"Fragment byte coverage mismatch: {key}")
        data_bytes += item_bytes
    allocated.sort()
    for previous, current in zip(allocated, allocated[1:]):
        if previous[1] > current[0]:
            raise ValueError(f"Overlapping targets: {previous[2]}, {current[2]}")
    totals = extent_map["totals"]
    if allocated and allocated[-1][1] > totals["image_bytes"]:
        raise ValueError("Target exceeds image")
    if (data_bytes != totals["data_bytes"] or allocated_bytes != totals["page_allocated_data_bytes"]
            or totals["filler_bytes"] != totals["image_bytes"] - data_bytes):
        raise ValueError("Layout byte totals mismatch")
    if len(set(class_allocated_pages)) != 1:
        raise ValueError("B/alpha tiers do not have symmetric allocated footprints")

    groups = original_items = mapped_fragments = commands = command_bytes = 0
    with layer_reads.open() as source, mapped_path.open() as mapped:
        for original_line, mapped_line in zip_longest(source, mapped):
            if original_line is None or mapped_line is None:
                raise ValueError("Mapped trace group count mismatch")
            original, result = json.loads(original_line), json.loads(mapped_line)
            if result["schema"] != MAPPED_SCHEMA or result["group_id"] != original["group_id"]:
                raise ValueError("Mapped group identity mismatch")
            expected_fragments = []
            for read in original["reads"]:
                entry = entries[read["item_id"]]
                if not source_matches(read, entry):
                    raise ValueError(f"Trace source mismatch: {read['item_id']}")
                for fragment_index, frag in enumerate(entry["fragments"]):
                    expected_fragments.append((entry["item_id"], fragment_index,
                                               frag["lba_start"], frag["sector_count"],
                                               frag["source_nbytes"], frag["page_class"]))
            actual_fragments = [(x["item_id"], x["fragment_index"], x["lba_start"],
                                 x["sector_count"], x["nbytes"], x["page_class"])
                                for x in result["mapped_fragments"]]
            if actual_fragments != expected_fragments:
                raise ValueError(f"Mapped fragments mismatch in group {original['group_id']}")
            if sum(c["nbytes"] for c in result["commands"]) != sum(r["nbytes"] for r in original["reads"]):
                raise ValueError(f"Command byte mismatch in group {original['group_id']}")
            for command in result["commands"]:
                if command["nbytes"] != command["sector_count"] * geom.sector_bytes:
                    raise ValueError("Non-sector command")
            groups += 1
            original_items += len(original["reads"])
            mapped_fragments += len(result["mapped_fragments"])
            commands += len(result["commands"])
            command_bytes += sum(c["nbytes"] for c in result["commands"])
    replay = summary["replay_input"]
    observed = dict(groups=groups, items=original_items, fragments=mapped_fragments,
                    commands=commands, command_bytes=command_bytes)
    if any(replay[k] != v for k, v in observed.items()):
        raise ValueError("Mapped-trace totals mismatch")
    report = dict(passed=True, schema=LAYOUT_SCHEMA, catalog_items=len(entries),
        allocated_ranges=len(allocated), class_allocated_pages=class_allocated_pages,
        mapped_trace=observed,
        checks=["complete plane and scale catalog", "source metadata equality",
                "fragment source coverage", "target non-overlap and image bound",
                "patched-512 QLC class for every allocated page", "symmetric tier footprint",
                "mapped group and fragment equality", "command byte conservation",
                "source and output checksums"])
    write_json(layout / "layout_validation.json", report)
    return report


def materialize(bundle, layout, image):
    bundle, layout, image = Path(bundle), Path(layout), Path(image)
    extent_map = json.loads((layout / "extent_map.json").read_text())
    manifest_path = bundle / "manifest.json"
    if extent_map["source_manifest_sha256"] != sha256(manifest_path):
        raise ValueError("Bundle manifest changed")
    segments = []
    for entry in extent_map["entries"]:
        for frag in entry["fragments"]:
            segments.append((frag["target_offset"], frag["source_offset"],
                             frag["source_nbytes"], entry))
    segments.sort()
    cursor = 0
    fill = b"\xA5" * (8 << 20)
    image_hash = hashlib.sha256()
    with image.open("xb") as dst:
        for target, source, nbytes, entry in segments:
            if target < cursor:
                raise ValueError("Overlapping target extents")
            gap = target - cursor
            while gap:
                block = fill[:min(gap, len(fill))]
                dst.write(block); image_hash.update(block); gap -= len(block)
            with (bundle / entry["source_file"]).open("rb") as src:
                src.seek(source)
                data = src.read(nbytes)
            if len(data) != nbytes:
                raise ValueError("Short source read")
            dst.write(data); image_hash.update(data)
            cursor = target + nbytes
        total = extent_map["totals"]["image_bytes"]
        while cursor < total:
            block = fill[:min(total-cursor, len(fill))]
            dst.write(block); image_hash.update(block); cursor += len(block)
    report = dict(image=str(image), nbytes=cursor, sha256=image_hash.hexdigest(),
                  extent_map_sha256=sha256(layout / "extent_map.json"))
    write_json(Path(str(image) + ".json"), report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    pp = sub.add_parser("plan")
    pp.add_argument("bundle", type=Path)
    pp.add_argument("--layer-reads", type=Path, required=True)
    pp.add_argument("--output", type=Path, required=True)
    pp.add_argument("--max-io-bytes", type=int, default=4 << 20)
    pp.add_argument("--policy", choices=PLACEMENT_POLICIES, default="aligned",
                    help="which QLC class each bit-plane tier is placed on; "
                         "the default reproduces the original layout byte for byte")
    mp = sub.add_parser("materialize")
    mp.add_argument("bundle", type=Path)
    mp.add_argument("layout", type=Path)
    mp.add_argument("--image", type=Path, required=True)
    vp = sub.add_parser("validate")
    vp.add_argument("bundle", type=Path)
    vp.add_argument("--layer-reads", type=Path, required=True)
    vp.add_argument("layout", type=Path)
    args = parser.parse_args()
    if args.command == "plan":
        result = plan(args.bundle, args.layer_reads, args.output, Geometry(),
                      args.max_io_bytes, args.policy)
    elif args.command == "materialize":
        result = materialize(args.bundle, args.layout, args.image)
    else:
        result = validate_layout(args.bundle, args.layer_reads, args.layout)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
