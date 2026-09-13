#!/usr/bin/env python3
"""Compile mapped layer-read JSONL into a validated little-endian replay stream."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import tempfile
from collections import Counter
from pathlib import Path

from bundle import sha256, write_json


MAGIC = b"MBQRPL1\0"
VERSION = 1
SECTOR_BYTES = 512
DIRECT_ALIGNMENT = 4096
PHASES = {"prefill": 0, "decode": 1, "teacher_forced": 2}
HEADER = struct.Struct("<8s8I4Q32s32s")
GROUP = struct.Struct("<QqQiBBHII")
COMMAND = struct.Struct("<QIB3x")


def raw_digest(hex_value):
    value = bytes.fromhex(hex_value)
    if len(value) != 32:
        raise ValueError("Expected SHA256 hex digest")
    return value


def compile_trace(layout, output, queue_depth=32, max_command_bytes=4 << 20):
    layout, output = Path(layout), Path(output)
    if output.exists() or Path(str(output) + ".json").exists():
        raise FileExistsError(output)
    if not 1 <= queue_depth <= 4096:
        raise ValueError("queue depth must be in [1, 4096]")
    summary_path = layout / "layout_summary.json"
    mapped_path = layout / "mapped_reads.jsonl"
    extent_path = layout / "extent_map.json"
    validation_path = layout / "layout_validation.json"
    summary = json.loads(summary_path.read_text())
    validation = json.loads(validation_path.read_text())
    if (summary.get("schema") != "moe-bcq-qlc-aligned-layout-v1"
            or validation.get("schema") != summary["schema"]
            or validation.get("passed") is not True):
        raise ValueError("Layout validation is absent or did not pass")
    if summary["extent_map_sha256"] != sha256(extent_path):
        raise ValueError("extent_map checksum mismatch")
    if summary["mapped_reads_sha256"] != sha256(mapped_path):
        raise ValueError("mapped_reads checksum mismatch")
    if summary["geometry"]["sector_bytes"] != SECTOR_BYTES:
        raise ValueError("v1 replayer requires 512-byte sectors")
    if max_command_bytes != summary["replay_input"]["max_io_bytes"]:
        raise ValueError("Compiler max command size differs from layout plan")

    request_indices = {}
    request_groups = Counter()
    phase_groups = Counter()
    group_count = command_count = total_bytes = max_end_byte = 0
    previous_group = None
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w+b", dir=output.parent, prefix=output.name+".",
                                         suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(b"\0" * HEADER.size)
            with mapped_path.open() as source:
                for line in source:
                    record = json.loads(line)
                    gid = record["group_id"]
                    if gid != group_count or record["schema"] != "moe-bcq-mapped-layer-reads-v1":
                        raise ValueError(f"Unexpected group/schema at {group_count}")
                    reset = bool(record["cache_reset"])
                    release = record["release_after_group_id"]
                    if reset:
                        if release is not None:
                            raise ValueError(f"Reset group {gid} has a dependency")
                    elif release != previous_group:
                        raise ValueError(f"Broken group dependency at {gid}")
                    phase = record["phase"]
                    if phase not in PHASES:
                        raise ValueError(f"Unknown phase: {phase}")
                    request_id = record["request_id"]
                    if request_id not in request_indices:
                        request_indices[request_id] = len(request_indices)
                    commands = record["commands"]
                    if len(commands) != record["command_count"]:
                        raise ValueError(f"Command count mismatch in group {gid}")
                    stream.write(GROUP.pack(gid, -1 if release is None else release,
                        record["forward_id"], record["layer"], PHASES[phase], int(reset), 0,
                        len(commands), request_indices[request_id]))
                    group_bytes = 0
                    for local_index, command in enumerate(commands):
                        if command["command_id"] != f"{gid}:{local_index}":
                            raise ValueError(f"Command identity mismatch: {command['command_id']}")
                        lba, sectors = command["lba_start"], command["sector_count"]
                        nbytes, page_class = command["nbytes"], command["page_class"]
                        if (command["operation"] != "read" or not isinstance(lba, int)
                                or not isinstance(sectors, int) or lba < 0
                                or lba > (1 << 64) - 1 or sectors <= 0
                                or sectors > (1 << 32) - 1):
                            raise ValueError(f"Invalid read command: {command}")
                        if nbytes != sectors * SECTOR_BYTES or nbytes > max_command_bytes:
                            raise ValueError(f"Invalid read size: {command['command_id']}")
                        if ((lba * SECTOR_BYTES) % DIRECT_ALIGNMENT
                                or nbytes % DIRECT_ALIGNMENT):
                            raise ValueError(f"O_DIRECT alignment violation: {command['command_id']}")
                        if page_class not in range(4):
                            raise ValueError(f"Invalid QLC class: {page_class}")
                        stream.write(COMMAND.pack(lba, sectors, page_class))
                        group_bytes += nbytes
                        command_count += 1
                        total_bytes += nbytes
                        max_end_byte = max(max_end_byte, (lba + sectors) * SECTOR_BYTES)
                    if group_bytes != record["command_bytes"]:
                        raise ValueError(f"Byte mismatch in group {gid}")
                    request_groups[request_id] += 1
                    phase_groups[phase] += 1
                    previous_group = gid
                    group_count += 1
            replay = summary["replay_input"]
            if (group_count != replay["groups"] or command_count != replay["commands"]
                    or total_bytes != replay["command_bytes"]):
                raise ValueError("Compiled totals differ from layout summary")
            stream.seek(0)
            stream.write(HEADER.pack(MAGIC, VERSION, HEADER.size, SECTOR_BYTES,
                DIRECT_ALIGNMENT, queue_depth, max_command_bytes, GROUP.size, COMMAND.size,
                group_count, command_count, total_bytes, max_end_byte,
                raw_digest(summary["extent_map_sha256"]), raw_digest(summary["mapped_reads_sha256"])))
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.link(temporary, output)
        temporary.unlink()
        temporary = None
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()

    metadata = dict(schema="moe-bcq-replay-binary-v1", magic=MAGIC.rstrip(b"\0").decode(),
        version=VERSION, byte_order="little", binary_file=output.name,
        binary_sha256=sha256(output), binary_bytes=output.stat().st_size,
        layout_directory=layout.name, layout_summary_sha256=sha256(summary_path),
        layout_validation_sha256=sha256(validation_path),
        extent_map_sha256=summary["extent_map_sha256"],
        mapped_reads_sha256=summary["mapped_reads_sha256"],
        sector_bytes=SECTOR_BYTES, direct_alignment=DIRECT_ALIGNMENT,
        default_queue_depth=queue_depth, max_command_bytes=max_command_bytes,
        record_bytes=dict(header=HEADER.size, group=GROUP.size, command=COMMAND.size),
        totals=dict(groups=group_count, commands=command_count,
                    command_bytes=total_bytes, max_end_byte=max_end_byte),
        phase_groups=dict(phase_groups),
        requests=[dict(index=index, request_id=request_id,
                       groups=request_groups[request_id])
                  for request_id, index in request_indices.items()],
        semantics="Groups are barriers. Replayer uses rolling QD within a group; empty groups remain.")
    write_json(Path(str(output) + ".json"), metadata)
    return metadata


def inspect_trace(path):
    path = Path(path)
    with path.open("rb") as stream:
        raw = stream.read(HEADER.size)
        if len(raw) != HEADER.size:
            raise ValueError("Truncated header")
        values = HEADER.unpack(raw)
        (magic, version, header_bytes, sector_bytes, alignment, default_qd,
         max_command_bytes, group_bytes, command_bytes, groups, commands,
         total_bytes, max_end_byte, layout_hash, mapped_hash) = values
        if (magic != MAGIC or version != VERSION or header_bytes != HEADER.size
                or group_bytes != GROUP.size or command_bytes != COMMAND.size
                or sector_bytes != SECTOR_BYTES or alignment < sector_bytes
                or not default_qd or not max_command_bytes):
            raise ValueError("Binary header mismatch")
        seen_commands = seen_bytes = seen_max_end = 0
        previous_group = -1
        for expected_group in range(groups):
            raw = stream.read(GROUP.size)
            if len(raw) != GROUP.size:
                raise ValueError("Truncated group")
            gid, release, forward, layer, phase, reset, reserved, count, request = GROUP.unpack(raw)
            if (gid != expected_group or phase not in PHASES.values() or reserved
                    or (reset and release != -1)
                    or (not reset and release != previous_group)):
                raise ValueError("Invalid group record")
            for _ in range(count):
                raw = stream.read(COMMAND.size)
                if len(raw) != COMMAND.size:
                    raise ValueError("Truncated command")
                lba, sectors, page_class = COMMAND.unpack(raw)
                size, offset = sectors * sector_bytes, lba * sector_bytes
                if (not sectors or page_class > 3 or size > max_command_bytes
                        or offset % alignment or size % alignment):
                    raise ValueError("Invalid command record")
                seen_commands += 1
                seen_bytes += size
                seen_max_end = max(seen_max_end, offset + size)
            previous_group = gid
        if (stream.read(1) or seen_commands != commands or seen_bytes != total_bytes
                or seen_max_end != max_end_byte):
            raise ValueError("Binary length/totals mismatch")
    return dict(groups=groups, commands=commands, command_bytes=total_bytes,
                max_end_byte=max_end_byte, default_queue_depth=default_qd,
                max_command_bytes=max_command_bytes, sector_bytes=sector_bytes,
                direct_alignment=alignment, extent_map_sha256=layout_hash.hex(),
                mapped_reads_sha256=mapped_hash.hex(), binary_sha256=sha256(path))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    cp = sub.add_parser("compile")
    cp.add_argument("layout", type=Path)
    cp.add_argument("--output", type=Path, required=True)
    cp.add_argument("--queue-depth", type=int, default=32)
    cp.add_argument("--max-command-bytes", type=int, default=4 << 20)
    ip = sub.add_parser("inspect")
    ip.add_argument("trace", type=Path)
    args = parser.parse_args()
    result = (compile_trace(args.layout, args.output, args.queue_depth, args.max_command_bytes)
              if args.command == "compile" else inspect_trace(args.trace))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
