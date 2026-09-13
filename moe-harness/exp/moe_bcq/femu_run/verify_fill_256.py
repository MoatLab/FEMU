#!/usr/bin/env python3
"""Run the isolated, pre-provisioned verify256 VM; preserve each snapshot.

Requires seed-verify256-20260910.iso and its private root overlay. Never uses
the existing femu-map VM. Results/output paths are exclusive.
"""
import csv
import hashlib
import io
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / 'runs/femu/verify256_20260910'
NAME = 'femu-verify256-20260910'
IMAGE = 'sha256:a91a26ae90eb2f193e1d98b8b180f587fcb463c418a76a7f56360e1cfb9453b5'
EXPECTED = [420294, 420294, 315822, 237450]
SSH = ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=accept-new',
       '-o', 'ConnectTimeout=5', '-p', '2223', 'femu@localhost']


def run(args, timeout=120):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=timeout).stdout


def save(path, data):
    with path.open('xb') as stream:
        stream.write(data)


def remote(command, timeout=120):
    return run(SSH + [command], timeout)


def counts(raw):
    values = [0] * 4
    lines = ''.join(x for x in raw.decode().splitlines(True) if not x.startswith('#'))
    for row in csv.DictReader(io.StringIO(lines)):
        values[int(row['page_class'])] += int(row['n_read'])
    return values


def snapshot(directory, stem):
    # Must be called after successful guest completion and before another probe.
    raw = (OUT / 'counter.live.csv').read_bytes()
    save(directory / (stem + '.qlc.csv'), raw)
    return counts(raw)


def verify_groups(records, summary):
    assert len(records) == summary['groups'] == 1536
    assert sum(g['command_count'] for g in records) == summary['commands'] == 130090
    assert sum(g['requested_bytes'] for g in records) == summary['requested_bytes'] == 22608650240
    assert sum(g['group_io_ns'] for g in records) == summary['sum_group_io_ns']
    previous_complete = 0
    for index, g in enumerate(records):
        assert g['group_id'] == index and g['group_ready_ns'] >= previous_complete
        assert g['peak_outstanding'] <= 32
        if g['command_count']:
            assert g['first_submit_ns'] >= g['group_ready_ns']
            assert g['last_complete_ns'] >= g['last_submit_ns']
        else:
            assert g['first_submit_ns'] is None and g['group_io_ns'] == 0
        previous_complete = g['last_complete_ns']


def main():
    env = dict(FEMU_IMAGE='/guest/femu-root-verify256-20260910.qcow2',
        FEMU_MEMORY='8G', FEMU_CPUS='6', FEMU_NAND_CELL_TYPE='4',
        FEMU_SSD_SIZE_MB='65536', FEMU_SECTORS_PER_PAGE='32',
        FEMU_PAGES_PER_BLOCK='512', FEMU_BLOCKS_PER_PLANE='1024',
        FEMU_PLANES_PER_LUN='1', FEMU_LUNS_PER_CHANNEL='4', FEMU_CHANNELS='2',
        FEMU_EXTRA_DEVICE_OPTS='op_pcent=7',
        FEMU_QLC_STATS_PATH='/data/verify256_20260910/counter.live.csv',
        FEMU_QMP_SOCKET='/data/verify256_20260910/qmp.sock',
        FEMU_EXTRA_DRIVES='file=/guest/seed-verify256-20260910.iso,if=virtio,format=raw,readonly=on;'
        'file=/data/images/qwen_C.img,if=virtio,format=raw,readonly=on')
    save(OUT / 'configuration.json', json.dumps(dict(image=IMAGE, env=env,
        fill_bytes=262144, expected_counts=EXPECTED), indent=2).encode())
    cmd = ['docker', 'run', '-d', '--name', NAME, '--device', '/dev/kvm',
           '--cap-add', 'IPC_LOCK', '--ulimit', 'memlock=-1:-1',
           '-p', '127.0.0.1:2223:2222',
           '-v', '/data01/kwkim02/images:/guest',
           '-v', str(ROOT / 'runs/femu') + ':/data']
    for key, value in env.items():
        cmd.extend(['-e', key + '=' + value])
    cmd.extend([IMAGE, 'bbssd'])
    boot_reports = []
    launched = False
    try:
        for boot in (1, 2):
            directory = OUT / f'boot{boot}'
            directory.mkdir(exist_ok=False)
            print(f'boot{boot}: starting fresh FEMU SSD', flush=True)
            if boot == 1:
                run(cmd)
                launched = True
            else:
                run(['docker', 'start', NAME])
            for attempt in range(120):
                try:
                    remote('sudo test -x /root/guest_fill.sh && sudo test -f /root/replay.bin', 10)
                    break
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                    time.sleep(2)
            else:
                raise RuntimeError('guest SSH/cloud-init did not become ready')
            save(directory / 'container.json', run(['docker', 'inspect', NAME]))
            save(directory / 'guest_trace_sha256.txt', remote('sudo sha256sum /root/replay.bin'))
            print(f'boot{boot}: sequential 256 KiB fill + complete read-back', flush=True)
            fill = remote('sudo bash /root/guest_fill.sh', 1200)
            save(directory / 'fill.log', fill)
            expected_sha = json.loads((ROOT / 'runs/femu/images/qwen_C.img.json').read_text())['sha256']
            assert fill.count(expected_sha.encode()) == 2 and b'read-back OK' in fill
            print(f'boot{boot}: read-back passed', flush=True)
            reports = []
            for repeat in (1, 2, 3):
                stem = f'replay{repeat}'
                guest = f'/dev/shm/verify_boot{boot}_{stem}'
                # Exclusive output paths and checked exit prevent stale success.
                result = remote(f'sudo replay_v1 --trace /root/replay.bin --device /dev/nvme0n1 '
                    f'--controller /dev/nvme0 --qd 32 --group-log {guest}.groups.jsonl '
                    f'--summary {guest}.summary.json', 300)
                save(directory / (stem + '.stdout'), result)
                actual = snapshot(directory, stem)
                summary_raw = remote(f'sudo cat {guest}.summary.json')
                groups_raw = remote(f'sudo cat {guest}.groups.jsonl')
                save(directory / (stem + '.summary.json'), summary_raw)
                save(directory / (stem + '.groups.jsonl'), groups_raw)
                summary = json.loads(summary_raw)
                verify_groups([json.loads(line) for line in groups_raw.splitlines()], summary)
                assert actual == EXPECTED, (boot, repeat, actual)
                reports.append(dict(repeat=repeat, counts=actual, group_io_ns=summary['sum_group_io_ns']))
                print(f'boot{boot} {stem}: exact class counts, group_io={summary["sum_group_io_ns"]/1e9:.3f}s', flush=True)
            matrix = []
            # Covers all 471040 LPNs in the image, including filler.
            for klass in range(4):
                result = remote(f'sudo class_confusion /dev/nvme0n1 /dev/nvme0 {klass} 471040', 180)
                save(directory / f'class{klass}.stdout', result)
                row = snapshot(directory, f'class{klass}')
                n = int(result.decode().split('reads=')[1].strip())
                assert sum(row) == n and row[klass] == n, row
                matrix.append(row)
                print(f'boot{boot}: class {klass} full-image check passed ({n} pages)', flush=True)
            boot_reports.append(dict(boot=boot, repeats=reports, full_image_confusion=matrix))
            run(['docker', 'stop', '-t', '15', NAME], 60)
            save(directory / 'console.log', run(['docker', 'logs', NAME]))
        report = dict(passed=True, boots=boot_reports, image_sha256=expected_sha)
        save(OUT / 'verification.json', json.dumps(report, indent=2).encode())
        print('PASS: two fresh boots, six replays, two full-image class checks', flush=True)
    finally:
        if launched:
            subprocess.run(['docker', 'stop', '-t', '10', NAME], stdout=subprocess.DEVNULL, timeout=30)
            if not (OUT / 'console.final.log').exists():
                save(OUT / 'console.final.log', run(['docker', 'logs', NAME]))


if __name__ == '__main__':
    main()
