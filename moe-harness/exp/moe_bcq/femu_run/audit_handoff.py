#!/usr/bin/env python3
"""Read-only audit of the supplied Qwen binary and saved FEMU evidence.

Run from the repository root. This does not boot FEMU or touch a device.
"""
import collections
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import struct


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def audit(root):
    layout = root / 'exp/moe_bcq/femu_handoff/packages/qwen_C/layouts/qlc_aligned_epm_aif_2ch4lun'
    runs = root / 'runs/femu'
    binary = layout / 'replay_qd32.bin'
    header = struct.Struct('<8s8I4Q32s32s')
    group = struct.Struct('<QqQiBBHII')
    command = struct.Struct('<QIB3x')
    pages = [0] * 4
    floor_pages = [0] * 4
    sizes = collections.Counter()
    commands = byte_count = class_mismatches = 0
    with binary.open('rb') as stream, (layout / 'mapped_reads.jsonl').open() as mapped:
        h = header.unpack(stream.read(header.size))
        assert h[0] == b'MBQRPL1\0' and h[3] == 512
        assert h[-2].hex() == digest(layout / 'extent_map.json')
        assert h[-1].hex() == digest(layout / 'mapped_reads.jsonl')
        for expected in range(h[9]):
            g = group.unpack(stream.read(group.size))
            source = json.loads(next(mapped))
            assert g[0] == expected == source['group_id']
            assert g[7] == len(source['commands'])
            for source_command in source['commands']:
                lba, sectors, klass = command.unpack(stream.read(command.size))
                assert (lba, sectors, klass) == (source_command['lba_start'],
                    source_command['sector_count'], source_command['page_class'])
                first, last = lba // 32, (lba + sectors - 1) // 32
                pages[klass] += last - first + 1
                floor_pages[klass] += sectors // 32
                sizes[sectors * 512] += 1
                commands += 1
                byte_count += sectors * 512
                for lpn in range(first, last + 1):
                    pg = lpn // 8 % 512
                    actual_class = 0 if pg < 6 else 1 if pg < 8 else pg % 8 // 2
                    class_mismatches += actual_class != klass
        assert stream.read() == b'' and mapped.read() == ''
    assert commands == h[10] and byte_count == h[11]
    assert class_mismatches == 0

    marker = runs / 'map2.console.log'
    pattern = re.compile(r'\[WRITE\] lpn=(\d+) -> ch=(\d+) lun=(\d+) pl=(\d+) blk=(\d+) pg=(\d+)')
    rows = [tuple(map(int, m.groups())) for m in pattern.finditer(marker.read_text())]
    # Absolute PPA equality is meaningful for the first fresh-device prefix.
    prefix = [r for r in rows if r[0] < 4096]
    prefix_mismatches = sum((ch, lun, pl, blk, pg) !=
        (lpn % 2, lpn // 2 % 4, 0, lpn // 4096, lpn // 8 % 512)
        for lpn, ch, lun, pl, blk, pg in prefix)
    assert len(prefix) == 4096 and prefix_mismatches == 0
    # Split into continuous LPN runs; these are observations, not inferred
    # command boundaries. Later probes deliberately start at different LBAs.
    sequences = []
    for row in rows:
        if not sequences or row[0] not in (sequences[-1][-1][0], sequences[-1][-1][0] + 1):
            sequences.append([])
        sequences[-1].append(row)
    phys = lambda r: r[4] * 4096 + r[5] * 8 + r[2] * 2 + r[1]
    sequence_reports = []
    for seq in sequences:
        counts = collections.Counter(r[0] for r in seq)
        extra = len(seq) - len(counts)
        advance_extra = phys(seq[-1]) - phys(seq[0]) - (seq[-1][0] - seq[0][0])
        assert advance_extra == extra
        sequence_reports.append(dict(first_lpn=seq[0][0], last_lpn=seq[-1][0],
            write_records=len(seq), duplicate_programs=extra,
            extra_physical_slots=advance_extra,
            duplicate_lpn_mod32=dict(collections.Counter(k % 32 for k, v in counts.items() if v > 1))))

    saved_counters = {}
    for path in sorted(runs.glob('*qlc_counts.csv*')):
        values = [0] * 4
        for row in csv.DictReader(io.StringIO(''.join(
                line for line in path.read_text().splitlines(True) if not line.startswith('#')))):
            values[int(row['page_class'])] += int(row['n_read'])
        saved_counters[path.name] = dict(sha256=digest(path), pages=values,
            total=sum(values), matches_replay_prediction=values == pages)

    return dict(binary=dict(sha256=digest(binary), groups=h[9], commands=commands,
        host_read_bytes=byte_count, expected_nand_page_reads=pages,
        total_nand_page_reads=sum(pages), incorrect_floor_counts=floor_pages,
        command_size_histogram=dict(sorted(sizes.items())), max_command_bytes=max(sizes),
        mapper_class_mismatches=class_mismatches, binary_matches_mapped_jsonl=True),
        marker_log=dict(sha256=digest(marker), fresh_prefix_records=len(prefix),
            fresh_prefix_ppa_mismatches=prefix_mismatches, sequences=sequence_reports),
        saved_counters=saved_counters,
        limitations=['No new FEMU run; audit uses saved files only.',
            'WRITE markers show program allocation, not NVMe command boundaries or Linux segment counts.',
            '256 KiB fill still requires queue-limit and actual PPA verification on each configuration.'])


if __name__ == '__main__':
    print(json.dumps(audit(Path.cwd()), indent=2))
