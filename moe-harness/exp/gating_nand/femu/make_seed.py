#!/usr/bin/env python3
"""Build a cloud-init seed ISO that runs a program in the guest and exits.

FEMU's own scripts expect a VM you SSH into over slirp. This host has no libslirp,
so FEMU is built without it and the guest has no network at all: nothing can be
installed and nothing can be copied in after boot. Everything the run needs -- the
binary, its shared library, the trace -- is embedded here, gzip+base64, and the
results come back over the serial console.

    python3 make_seed.py -o ~/images/seed.iso \
        --file /usr/local/bin/replay=../../../build/guest/replay:0755 \
        --file /usr/local/lib/liburing.so.2=$CONDA/lib/liburing.so.2.14 \
        --file /root/objects.csv=<objects.csv> \
        --file /root/stream.csv=<stream.csv> \
        --run "LD_LIBRARY_PATH=/usr/local/lib /usr/local/bin/replay /dev/nvme0n1 0 /root/objects.csv /root/stream.csv"
"""

import argparse
import base64
import gzip
import io
import sys
from pathlib import Path

import pycdlib

HEAD = """#cloud-config
password: femu
chpasswd: {{ expire: False }}
ssh_pwauth: true
users:
  - name: femu
    plain_text_passwd: femu
    lock_passwd: false
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
{keys}write_files:
{files}runcmd:
  - [ sh, -c, "echo '==={tag}-START===' > /dev/ttyS0" ]
{cmds}  - [ sh, -c, "echo '==={tag}-DONE===' > /dev/ttyS0" ]
"""


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("-o", "--output", type=Path, required=True)
    p.add_argument("--file", action="append", default=[], metavar="GUEST=HOST[:MODE]",
                   help="embed HOST at GUEST, default mode 0644")
    p.add_argument("--run", action="append", default=[],
                   help="shell command; stdout and stderr go to the serial console")
    p.add_argument("--ssh-key", type=Path, default=None,
                   help="public key authorised for the femu user. The serial "
                        "console is one-shot: it runs what the seed says and "
                        "nothing more. A key turns each further question into "
                        "an ssh command instead of another boot and refill.")
    p.add_argument("--tag", default="RUN", help="marker wrapping the output")
    p.add_argument("--instance-id", default="femu-01")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    blocks = []
    for spec in args.file:
        guest, _, rest = spec.partition("=")
        host, _, mode = rest.partition(":")
        data = gzip.compress(Path(host).read_bytes())
        blocks.append(
            f"  - path: {guest}\n"
            f"    permissions: '{mode or '0644'}'\n"
            f"    encoding: gz+b64\n"
            f"    content: {base64.b64encode(data).decode()}\n")
    cmds = "".join(f'  - [ sh, -c, "{c} > /dev/ttyS0 2>&1" ]\n' for c in args.run)
    keys = ""
    if args.ssh_key:
        keys = "    ssh_authorized_keys:\n      - {}\n".format(
            args.ssh_key.read_text().strip())
    user = HEAD.format(files="".join(blocks), cmds=cmds, tag=args.tag,
                       keys=keys).encode()
    meta = f"instance-id: {args.instance_id}\nlocal-hostname: femu\n".encode()

    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, joliet=3, vol_ident="cidata", rock_ridge="1.09")
    for data, path, rr, jol in ((user, "/USERDATA.;1", "user-data", "/user-data"),
                                (meta, "/METADATA.;1", "meta-data", "/meta-data")):
        iso.add_fp(io.BytesIO(data), len(data), path, rr_name=rr, joliet_path=jol)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    iso.write(str(args.output))
    iso.close()
    print(f"{args.output}  ({args.output.stat().st_size:,} bytes, "
          f"{len(args.file)} files, {len(args.run)} commands)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
