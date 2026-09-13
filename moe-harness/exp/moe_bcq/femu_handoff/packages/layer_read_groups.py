#!/usr/bin/env python3
"""Layer demand groups and byte-capacity LRU misses, before SSD address mapping.

Cache granularity: (projection, plane). All demands in one layer are protected
before eviction. A miss is admitted on completion; no next group is processed
until the present group has completed its reads and compute (untimed barriers).
"""
import argparse
import json
from collections import Counter, OrderedDict
from pathlib import Path

from bundle import SCHEMA, sha256, write_json
from logical_reads import demand
import online_cache


def item_key(e):
    if e['kind'] == 'plane':
        return f"{e['projection_id']}/B{e['plane']}"
    if e['kind'] == 'scale':
        return f"{e['projection_id']}/alpha{e['scale_set']}/C{e['column']}"
    raise ValueError(f"Unknown extent kind: {e['kind']}")


class LayerLRU:
    def __init__(self, capacity_bytes):
        if capacity_bytes <= 0:
            raise ValueError("Capacity must be positive")
        self.capacity = capacity_bytes
        self.items = OrderedDict()
        self.used = 0

    def clear(self):
        self.items.clear()
        self.used = 0

    def serve(self, extents):
        wanted = OrderedDict((item_key(e), e) for e in extents)
        if len(wanted) != len(extents):
            raise ValueError("Duplicate item in layer demand")
        if sum(e['nbytes'] for e in extents) > self.capacity:
            raise ValueError("Layer working set exceeds cache capacity; define a streaming schedule first")
        for key, e in wanted.items():
            if key in self.items and self.items[key] != e['nbytes']:
                raise ValueError("Cache item size changed")
        hits = [k for k in wanted if k in self.items]
        misses = [dict(item_id=k, **e) for k, e in wanted.items() if k not in self.items]
        miss_bytes = sum(e['nbytes'] for e in misses)
        before = self.used
        evicted = []
        # Decide every hit before insertion; never evict a current-layer demand.
        for key in list(self.items):
            if self.used + miss_bytes <= self.capacity:
                break
            if key not in wanted:
                size = self.items.pop(key)
                self.used -= size
                evicted.append(dict(item_id=key, nbytes=size))
        assert self.used + miss_bytes <= self.capacity
        # Stable tie break within a layer; not an assertion of GPU expert order.
        for key in sorted(wanted):
            size = wanted[key]['nbytes']
            if key in self.items:
                del self.items[key]
            else:
                self.used += size
            self.items[key] = size
        hit_bytes = sum(wanted[k]['nbytes'] for k in hits)
        assert hit_bytes + miss_bytes == sum(e['nbytes'] for e in extents)
        assert self.used == before - sum(e['nbytes'] for e in evicted) + miss_bytes
        assert self.used <= self.capacity
        return dict(hit_item_ids=hits, hit_bytes=hit_bytes, misses=misses,
                    miss_bytes=miss_bytes, evictions=evicted,
                    cache_bytes_before=before, cache_bytes_after=self.used)


def build(bundle, trace_name, capacity_bytes, scales='resident'):
    bundle = Path(bundle)
    trace = bundle / 'traces' / trace_name
    mpath = bundle / 'manifest.json'
    manifest = json.loads(mpath.read_text())
    meta = json.loads((trace / 'trace_meta.json').read_text())
    assert manifest['schema'] == meta['schema'] == SCHEMA
    assert meta['manifest_sha256'] == sha256(mpath)
    assert meta['state_sha256'] == manifest['source_state']['sha256']
    assert meta['mode'] == 'generate', 'Keep teacher-forced workloads separate'
    assert meta['phase_policies'] == dict(prefill='w4', decode='gated_mixed', teacher_forced='gated_mixed')
    for filename, info in meta['files'].items():
        assert sha256(trace / filename) == info['sha256']
    assert scales in ('resident', 'on_demand')
    suffix = '' if scales == 'resident' else '_scales_on_demand'
    out = trace / f'layer_groups_lru_{capacity_bytes}B{suffix}'
    # If the collector ran a cache beside the model, this derivation has to
    # reproduce it group for group. That is the only check on the cache itself:
    # the FEMU counters agree with the mapper, but the mapper's input is this
    # file, so a cache that misses wrongly is replayed wrongly and consistently.
    record = trace / 'online_cache.jsonl'
    online, online_rows = None, {}
    if record.exists():
        header, online_rows = online_cache.load(record)
        assert header['manifest_sha256'] == meta['manifest_sha256']
        if header['scales'] == scales and capacity_bytes in header['capacities']:
            online = str(capacity_bytes)
        else:
            online_rows = {}
    out.mkdir(exist_ok=False)
    cache = LayerLRU(capacity_bytes)
    previous_request, previous_forward, previous_layer = None, -1, None
    previous_group = None
    seen_requests = set()
    frame_info = None
    next_position = None
    phases = {'prefill': Counter(), 'decode': Counter()}
    request_stats = {}
    peak = 0
    groups = 0
    verified = 0
    source = trace / 'logical_trace.jsonl'
    with source.open() as src, (out / 'layer_demands.jsonl').open('x') as df, (out / 'layer_reads.jsonl').open('x') as rf:
        for line in src:
            event = json.loads(line)
            gid = event['event_id']
            rid = event['request_id']
            phase = event['phase']
            fid, layer = event['forward_id'], event['layer']
            assert gid == groups and phase in phases
            new_forward = fid != previous_forward
            reset = rid != previous_request
            if new_forward:
                assert fid == previous_forward + 1
                if previous_layer is not None:
                    assert previous_layer == manifest['totals']['layers'][-1]
                assert layer == manifest['totals']['layers'][0]
                frame_info = (rid, phase, event['input_ids'], event['token_positions'])
                if reset:
                    assert rid not in seen_requests and phase == 'prefill'
                    assert event['token_positions'] == list(range(len(event['input_ids'])))
                    seen_requests.add(rid)
                    cache.clear()
                    previous_group = None
                    next_position = len(event['input_ids'])
                    request_stats[rid] = {'prefill': Counter(), 'decode': Counter()}
                else:
                    assert phase == 'decode' and event['token_positions'] == [next_position]
                    assert len(event['input_ids']) == 1
                    next_position += 1
            else:
                assert not reset and frame_info == (rid, phase, event['input_ids'], event['token_positions'])
                order = manifest['totals']['layers']
                assert layer == order[order.index(previous_layer) + 1]
            if phase == 'prefill':
                assert all(b == 4 for row in event['precision_bits'] for b in row)
            extents = demand(manifest, event, scales_resident=(scales == 'resident'))
            result = cache.serve(extents)
            common = dict(group_id=gid, request_id=rid, forward_id=fid, layer=layer,
                          phase=phase, batch_size=event['batch_size'],
                          token_positions=event['token_positions'], cache_reset=reset,
                          release_after_group_id=previous_group,
                          barrier='all reads and compute of this group precede next group',
                          demand_items=len(extents), demand_bytes=sum(e['nbytes'] for e in extents))
            df.write(json.dumps(dict(**common, demands=[dict(item_id=item_key(e), **e) for e in extents]), separators=(',', ':'))+'\n')
            misses = result.pop('misses')
            reads = [dict(read_id=f'{gid}:{j}', **e, lba_start=None, sector_count=None,
                          address_status='unmapped', operation='read') for j, e in enumerate(misses)]
            if online is not None:
                row = online_rows[gid]
                assert row['p'] == phase
                observed = dict(zip(online_cache.ROW_FIELDS, row['c'][online]))
                derived = dict(miss_items=len(reads), miss_bytes=result['miss_bytes'],
                               hit_bytes=result['hit_bytes'],
                               evicted_items=len(result['evictions']),
                               evicted_bytes=sum(e['nbytes'] for e in result['evictions']),
                               used_after=result['cache_bytes_after'],
                               miss_digest=online_cache.digest(sorted(m['item_id'] for m in misses)))
                if [len(extents), common['demand_bytes']] != row['d'] or observed != derived:
                    raise AssertionError(f'Online cache disagrees at group {gid}: '
                                         f'observed {row["d"]} {observed} vs derived '
                                         f'{[len(extents), common["demand_bytes"]]} {derived}')
                verified += 1
            rf.write(json.dumps(dict(**common, **result, reads=reads), separators=(',', ':'))+'\n')
            stat = dict(groups=1, demand_items=len(extents), hit_items=len(result['hit_item_ids']),
                        miss_items=len(reads), demand_bytes=common['demand_bytes'],
                        hit_bytes=result['hit_bytes'], miss_bytes=result['miss_bytes'],
                        evicted_items=len(result['evictions']), evicted_bytes=sum(e['nbytes'] for e in result['evictions']),
                        all_hit_groups=int(not reads))
            phases[phase].update(stat)
            request_stats[rid][phase].update(stat)
            peak = max(peak, cache.used)
            previous_request, previous_forward, previous_layer = rid, fid, layer
            previous_group = gid
            groups += 1
    assert groups == meta['events'] and previous_layer == manifest['totals']['layers'][-1]
    if online is not None:
        assert verified == groups == len(online_rows), 'Online record does not cover every group'
        check = dict(status='verified', origin=header['origin'], groups=verified,
                     record_sha256=sha256(record),
                     implementation=('online_cache.py ReferenceLRU, run in-process during GPU execution'
                                     if header['origin'] == 'in_process' else
                                     'online_cache.py ReferenceLRU, replayed from the trace file; '
                                     'checks the cache logic, not the trace'),
                     covers='per-group miss count, miss/hit bytes, eviction count and bytes, '
                            'occupancy, and a digest of which items missed')
    elif record.exists():
        check = dict(status='not_applicable', groups=0,
                     reason=f'record holds scales={header["scales"]} capacities={header["capacities"]}')
    else:
        check = dict(status='absent', groups=0,
                     reason='trace was collected before the in-process cache existed; '
                            'this derivation is unchecked')
    summary = dict(schema='moe-layer-read-groups-v1', groups=groups, requests=len(seen_requests),
        model=manifest['model'], arm=manifest['arm'], phase_policies=meta['phase_policies'],
        cache=dict(policy='LRU', capacity_bytes=capacity_bytes, granularity='projection-plane',
                   recency='whole layer; ties use lexicographic item_id', reset='each request; prefill retained for decode',
                   protected='all demanded items until layer completion', peak_payload_bytes=peak,
                   prefetch=False, admission='all misses on completion before next layer'),
        scales=scales, online_check=check,
        resident_scales_bytes=(manifest['totals']['scales_bytes'] if scales == 'resident' else 0),
        budget_note=('Cache capacity is plane payload only; scales are additional.' if scales == 'resident'
                     else 'Planes and requested scale columns share this cache capacity.')
                    + ' Python index, allocator, GPU working buffers and transport staging not modeled.',
        xpu_policy='no persistent routed-weight cache; current call working data only',
        timing='barrier order only; no timestamps or compute/transfer latency',
        mapping=dict(status='pending', layout_sha256=None, sector_bytes=None,
                     note='Source offsets are NOT LBA. Map to actual image extents before FEMU replay.'),
        phase_stats=phases, request_stats=request_stats, source_manifest_sha256=sha256(mpath),
        source_trace_sha256=sha256(source), source_meta_sha256=sha256(trace / 'trace_meta.json'),
        builder_sha256=sha256(__file__), files={name:dict(sha256=sha256(out/name), nbytes=(out/name).stat().st_size)
                                              for name in ['layer_demands.jsonl','layer_reads.jsonl']})
    write_json(out / 'summary.json', summary)
    print(json.dumps(dict(output=str(out), groups=groups, phase_stats=phases)), flush=True)
    return summary


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('bundle', type=Path)
    p.add_argument('--trace', default='prefill_w4_decode_mixed_v1')
    p.add_argument('--cache-bytes', type=int, default=2*1024**3)
    p.add_argument('--scales', choices=['resident', 'on_demand'], default='resident')
    a = p.parse_args()
    build(a.bundle, a.trace, a.cache_bytes, a.scales)


if __name__ == '__main__':
    main()
