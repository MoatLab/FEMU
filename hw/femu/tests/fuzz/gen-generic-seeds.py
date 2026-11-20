#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Write seed inputs for the FEMU targets of QEMU's generic fuzzer.

The generic fuzzer reads an input as records split by the 4 bytes "FUZZ".
The first byte of a record picks the operation and the rest are its
arguments (tests/qtest/fuzz/generic_fuzz.c). A DMA pattern fills guest
memory when the controller reads it. With x-fuzz the controller reads each
submission queue entry when the doorbell rings, so each command gets its
own patterns just before its doorbell write:

    write AQA, ASQ, ACQ          register region 0, 32-bit writes
    pattern: zeros               the admin CQ and SQ, mapped at CC.EN
    write CC, read CSTS
    per command:
      clear patterns
      pattern 0: the 64-byte SQE  read at the SQ0 tail doorbell write
      pattern 1: data             what the command reads from the host
      write SQ0 tail, CQ0 head

The admin commands follow the opcode list and the valid defaults of the
admin-fuzz qtest (femu_test_admin_fuzz in hw/femu/tests/qtest/femu-test.c).

Usage:
    gen-generic-seeds.py --target {nossd,bbssd,zns,cmb} --out DIR
    gen-generic-seeds.py --control DIR    trigger/ and near/ seeds,
                                          control.dict with the key, and
                                          enable.prefix for femu-nossd
    gen-generic-seeds.py --self-test
"""

import argparse
import os
import struct
import sys
import tempfile

SEP = b"FUZZ"

# operation numbers of generic_fuzz.c (enum cmds)
OP_READ = 2
OP_WRITE = 3
OP_PCI_READ = 4
OP_PCI_WRITE = 5
OP_ADD_DMA_PATTERN = 7
OP_CLEAR_DMA_PATTERNS = 8
OP_CLOCK_STEP = 9
OP_COUNT = 10

# access sizes of op_read and op_write
BYTE, WORD, LONG, QUAD = 0, 1, 2, 3

# matched regions in address order (libqos maps them in that order)
REG = 0          # nvme: registers and doorbells
CMB = 1          # nvme-cmb, femu-cmb target only

# the x-fuzz-control key (FEMU_FUZZ_CONTROL_KEY in hw/femu/nvme.h)
CONTROL_KEY = 0x3cc3a55a
# CDW15 of the near seed. Its 4 bytes occur once in the seed, so when
# libFuzzer copies the key over the compared bytes, it writes CDW15.
CONTROL_NEAR = 0x6b1d7e29

# guest addresses, in RAM and clear of the legacy hole below 1 MiB
ASQ = 0x200000
ACQ = 0x201000
DATA = 0x202000
DATA2 = 0x203000
IOCQ = 0x204000
IOSQ = 0x205000
DBS = 0x206000
EIS = 0x207000
# where libqos maps the CMB of femu-cmb: 0xe0000000 plus 4 MiB alignment
CMB_ADDR = 0xe0400000

QENTRIES = 8
CC_ENABLE = 0x00460001

# admin opcodes of the admin-fuzz qtest
ADM = {
    "delete_sq": 0x00, "create_sq": 0x01, "get_log": 0x02,
    "delete_cq": 0x04, "create_cq": 0x05, "identify": 0x06,
    "abort": 0x08, "set_feat": 0x09, "get_feat": 0x0a, "aer": 0x0c,
    "ns_mgmt": 0x0d, "fw_commit": 0x10, "fw_download": 0x11,
    "self_test": 0x14, "ns_attach": 0x15, "keep_alive": 0x18,
    "dir_send": 0x19, "dir_recv": 0x1a, "dbbuf": 0x7c, "format": 0x80,
    "sec_send": 0x81, "sec_recv": 0x82, "sanitize": 0x84, "debug": 0xee,
}


def rec(op, payload=b""):
    return bytes([op]) + payload


def mmio_write(offset, value, size=LONG, region=REG):
    return rec(OP_WRITE, struct.pack("<BBxxIQ", size, region, offset, value))


def mmio_read(offset, size=LONG, region=REG):
    return rec(OP_READ, struct.pack("<BBxxI", size, region, offset))


def pci_write(offset, value, size=LONG):
    return rec(OP_PCI_WRITE, struct.pack("<BBBxI", size, 0, offset, value))


def pci_read(offset, size=LONG):
    return rec(OP_PCI_READ, struct.pack("<BBB", size, 0, offset))


def pattern(data, index=0, stride=0):
    return rec(OP_ADD_DMA_PATTERN, struct.pack("<BB", index, stride) + data)


def cmd(opcode, nsid=0, prp1=DATA, prp2=0, cdw10=0, cdw11=0, cdw12=0,
        cdw13=0, cdw14=0, cdw15=0, cid=0):
    """One 64-byte submission queue entry."""
    return struct.pack("<BBHIIIQQQIIIIII", opcode, 0, cid, nsid, 0, 0, 0,
                       prp1, prp2, cdw10, cdw11, cdw12, cdw13, cdw14,
                       cdw15)


def data_pattern():
    return bytes((i * 37 + 11) & 0xff for i in range(64))


def admin_queue():
    aqa = (QENTRIES - 1) << 16 | (QENTRIES - 1)
    return [mmio_write(0x24, aqa),
            mmio_write(0x28, ASQ), mmio_write(0x2c, 0),
            mmio_write(0x30, ACQ), mmio_write(0x34, 0)]


def admin_seed(cmds, after=()):
    """Records that enable the controller and run the admin commands."""
    assert cmds
    out = admin_queue()
    out += [pattern(bytes(16)), mmio_write(0x14, CC_ENABLE), mmio_read(0x1c)]
    for i, c in enumerate(cmds, 1):
        sqe = c if isinstance(c, bytes) else cmd(**c)
        assert len(sqe) == 64
        out += [rec(OP_CLEAR_DMA_PATTERNS), pattern(sqe),
                pattern(data_pattern()),
                mmio_write(0x1000, i % QENTRIES),
                mmio_write(0x1004, i % QENTRIES)]
    out += [mmio_read(0x1c)] + list(after)
    return out


def ident(cns, nsid=0, cdw11=0, cdw15=0):
    return dict(opcode=ADM["identify"], nsid=nsid, cdw10=cns, cdw11=cdw11,
                cdw15=cdw15)


def log(lid, numd=0x3ff, nsid=0xffffffff, lsp=0):
    return dict(opcode=ADM["get_log"], nsid=nsid,
                cdw10=numd << 16 | lsp << 8 | lid)


def get_feat(fid, sel=0, nsid=0):
    return dict(opcode=ADM["get_feat"], nsid=nsid, cdw10=sel << 8 | fid)


def set_feat(fid, value=0, nsid=0):
    return dict(opcode=ADM["set_feat"], nsid=nsid, cdw10=fid, cdw11=value)


def create_io(qsize=QENTRIES):
    return [dict(opcode=ADM["create_cq"], prp1=IOCQ,
                 cdw10=(qsize - 1) << 16 | 1, cdw11=1),
            dict(opcode=ADM["create_sq"], prp1=IOSQ,
                 cdw10=(qsize - 1) << 16 | 1, cdw11=1 << 16 | 1)]


def abort_storm():
    """
    A full 4096-entry admin queue of Aborts, sent with one doorbell write.

    Each Abort counts the Aborts queued behind it. A count that walks the
    whole queue costs depth squared reads, and under the fuzzer's DMA hook
    the replay runs past -timeout=25. The count must stop past ACL.
    """
    depth = 4096
    asq, acq = 0x200000, 0x240000      # 256 KiB SQ, then the 64 KiB CQ
    abort = cmd(ADM["abort"], prp1=0, cdw10=0xffff << 16, cid=1)
    return [mmio_write(0x24, (depth - 1) << 16 | (depth - 1)),
            mmio_write(0x28, asq), mmio_write(0x2c, 0),
            mmio_write(0x30, acq), mmio_write(0x34, 0),
            pattern(abort), mmio_write(0x14, CC_ENABLE), mmio_read(0x1c),
            mmio_write(0x1000, depth - 1), mmio_read(0x1c)]


def seeds(target):
    """(name, records) pairs for one target."""
    out = []
    regs = [mmio_read(off) for off in range(0, 0x40, 4)]
    regs += [mmio_read(0, QUAD), mmio_read(0x1000), mmio_read(0x1004)]
    out.append(("regs-read", regs))
    out.append(("regs-bad-cc", admin_queue() + [
        mmio_write(0x14, 0x00460001 | 0xf << 7),   # MPS beyond CAP
        mmio_read(0x1c), mmio_write(0x14, 0),
        mmio_write(0x14, 0x00440001),               # SQES too small
        mmio_read(0x1c), mmio_write(0x14, 0),
        mmio_write(0x0c, 0xffffffff), mmio_write(0x10, 0xffffffff)]))
    out.append(("shutdown", admin_seed([ident(1)], after=[
        mmio_write(0x14, CC_ENABLE | 1 << 14), mmio_read(0x1c),
        rec(OP_CLOCK_STEP), mmio_read(0x1c), mmio_write(0x14, 0),
        mmio_read(0x1c)])))
    out.append(("identify-a", admin_seed([
        ident(1), ident(0, nsid=1), ident(2), ident(3, nsid=1),
        ident(5, nsid=1), ident(6), ident(0x1c)])))
    out.append(("identify-b", admin_seed([
        ident(0x08, nsid=1), ident(0x10), ident(0x11, nsid=1),
        ident(0x12), ident(0x13), ident(0x14), ident(0x16)])))
    out.append(("logs-a", admin_seed([
        log(0x01), log(0x02), log(0x03), log(0x04), log(0x05),
        log(0x06), log(0x07)])))
    out.append(("logs-b", admin_seed([
        log(0x0c), log(0x0d, lsp=1), log(0x0f), log(0x80), log(0xc0),
        log(0x02, numd=0x7f, nsid=1), log(0xff, numd=0xffff)])))
    out.append(("features-get", admin_seed([
        get_feat(f) for f in (0x01, 0x02, 0x04, 0x05, 0x07, 0x08, 0x0b)])))
    out.append(("features-get-b", admin_seed([
        get_feat(0x0e), get_feat(0x16), get_feat(0x06),
        get_feat(0x09, nsid=1), get_feat(0x0a), get_feat(0x04, sel=1),
        get_feat(0x07, sel=3)])))
    out.append(("features-set", admin_seed([
        set_feat(0x07, 0x00010001), set_feat(0x04, 0x0160),
        set_feat(0x0b, 0x1ff), set_feat(0x08, 0x0101),
        set_feat(0x06, 1), dict(opcode=ADM["set_feat"], cdw10=0x0e),
        dict(opcode=ADM["set_feat"], cdw10=0x16)])))
    out.append(("io-queues", admin_seed(create_io(), after=[
        mmio_write(0x1008, 1), mmio_write(0x100c, 0),
        mmio_write(0x1008, QENTRIES)])))
    out.append(("io-queues-delete", admin_seed(create_io() + [
        dict(opcode=ADM["delete_sq"], cdw10=1),
        dict(opcode=ADM["delete_cq"], cdw10=1),
        dict(opcode=ADM["delete_cq"], cdw10=2)])))
    out.append(("abort-aer", admin_seed([
        dict(opcode=ADM["aer"]), dict(opcode=ADM["abort"], cdw10=0),
        dict(opcode=ADM["keep_alive"]), dict(opcode=ADM["self_test"],
                                              nsid=0xffffffff, cdw10=1),
        dict(opcode=ADM["self_test"], cdw10=0xf), dict(opcode=ADM["debug"])])))
    out.append(("abort-storm", abort_storm()))
    out.append(("firmware", admin_seed([
        dict(opcode=ADM["fw_download"], cdw10=0x3ff, cdw11=0),
        dict(opcode=ADM["fw_download"], cdw10=0x3ff, cdw11=0x400),
        dict(opcode=ADM["fw_commit"], cdw10=1 << 3 | 1),
        dict(opcode=ADM["fw_commit"], cdw10=3 << 3 | 2),
        log(0x03)])))
    out.append(("format-sanitize", admin_seed([
        dict(opcode=ADM["format"], nsid=1, cdw10=0),
        dict(opcode=ADM["sanitize"], cdw10=2),
        log(0x81), dict(opcode=ADM["ns_attach"], nsid=1, cdw10=0),
        dict(opcode=ADM["ns_mgmt"], cdw10=0)])))
    out.append(("security-directive", admin_seed([
        dict(opcode=ADM["sec_recv"], cdw10=0x00 << 24, cdw11=0x1000),
        dict(opcode=ADM["sec_send"], cdw10=0x01 << 24 | 1 << 8,
             cdw11=0x200),
        dict(opcode=ADM["dir_recv"], nsid=1, cdw10=0x3ff, cdw11=1),
        dict(opcode=ADM["dir_send"], nsid=1, cdw10=0x3ff, cdw11=1),
        dict(opcode=ADM["dbbuf"], prp1=DBS, prp2=EIS)])))
    out.append(("prp-list", admin_seed([
        dict(opcode=ADM["get_log"], nsid=0xffffffff, prp1=DATA + 0x800,
             prp2=DATA2, cdw10=0x7ff << 16 | 0x02),
        dict(opcode=ADM["identify"], prp1=DATA + 1, cdw10=1),
        dict(opcode=ADM["identify"], prp1=0, cdw10=1)])))
    # the MSI-X table follows the CMB when there is one
    tbl = CMB + 1 if target == "cmb" else CMB
    out.append(("msix-pci", [
        pci_read(0x00), pci_read(0x04), pci_read(0x10), pci_read(0x34),
        pci_write(0x04, 0x0406), pci_read(0x40, BYTE),
        mmio_write(0, 0xfee00000, LONG, tbl),
        mmio_write(8, 0x4021, LONG, tbl), mmio_write(12, 0, LONG, tbl),
        mmio_read(0, LONG, tbl + 1)]))
    if target == "zns":
        out.append(("zns", admin_seed([
            ident(5, nsid=1, cdw11=2 << 24), ident(6, cdw11=2 << 24),
            log(0xbf, nsid=1), get_feat(0x7e), ident(0x1c),
            ident(0x07, cdw11=2 << 24)])))
    if target == "bbssd":
        out.append(("bbssd", admin_seed([
            log(0x02, nsid=1), log(0xc0), log(0xc1),
            dict(opcode=ADM["format"], nsid=1, cdw10=1 << 9),
            log(0x02, nsid=1)])))
    if target == "cmb":
        out.append(("cmb", [
            mmio_read(0x38), mmio_read(0x3c),
            mmio_write(0, 0x1122334455667788, QUAD, CMB),
            mmio_read(0, QUAD, CMB), mmio_write(0x3ffff8, 1, LONG, CMB),
            # the last CMB byte, by a byte access (cmb-last-byte qtest)
            mmio_write(0x3fffff, 0xff, BYTE, CMB),
            mmio_read(0x3fffff, BYTE, CMB)]
            + admin_seed([dict(opcode=ADM["identify"], prp1=CMB_ADDR,
                               cdw10=1),
                          dict(opcode=ADM["get_log"], prp1=CMB_ADDR,
                               nsid=0xffffffff, cdw10=0x3ff << 16 | 2)])))
    return out


def control_seed(cdw15):
    """
    One Identify Controller and its doorbell. x-fuzz-control enables the
    controller at each reset, with AQA 7/7, ASQ and ACQ as here.
    """
    return [pattern(cmd(**ident(1, cdw15=cdw15))), mmio_write(0x1000, 1)]


def control_prefix():
    """
    The enable writes that x-fuzz-control does at each reset. Put before a
    control input, they give femu-nossd the same setup without the plant.
    """
    aqa = (QENTRIES - 1) << 16 | (QENTRIES - 1)
    return encode([mmio_write(0x24, aqa), mmio_write(0x28, ASQ),
                   mmio_write(0x30, ACQ),
                   mmio_write(0x14, CC_ENABLE)]) + SEP


def control_seeds():
    """The trigger hits the planted overflow; the near seed is one dword off."""
    return {"trigger": control_seed(CONTROL_KEY),
            "near": control_seed(CONTROL_NEAR)}


def control_dict():
    """A libFuzzer dictionary with the control key as its one word."""
    key = struct.pack("<I", CONTROL_KEY)
    return 'key="%s"\n' % "".join("\\x%02x" % b for b in key)


def encode(records):
    for r in records:
        if not r or SEP in r:
            raise ValueError("a record is empty or holds the separator")
    data = SEP.join(records)
    # the fuzzer splits on SEP: it must get back exactly these records
    if data.split(SEP) != list(records):
        raise ValueError("records do not split back")
    for r in records:
        if r[0] % OP_COUNT != r[0]:
            raise ValueError("operation byte out of range")
    return data


def write_dir(path, named):
    os.makedirs(path, exist_ok=True)
    for i, (name, records) in enumerate(named):
        with open(os.path.join(path, "seed-%02d-%s" % (i, name)), "wb") as f:
            f.write(encode(records))


def self_test():
    with tempfile.TemporaryDirectory() as d:
        for t in ("nossd", "bbssd", "zns", "cmb"):
            write_dir(os.path.join(d, t), seeds(t))
            if len(os.listdir(os.path.join(d, t))) < 15:
                print("self-test: too few seeds for %s" % t)
                return 1
        c = control_seeds()
        trig = encode(c["trigger"])
        near = encode(c["near"])
        key = struct.pack("<I", CONTROL_KEY)
        if key not in trig or key in near or len(trig) != len(near):
            print("self-test: the trigger and near seeds differ wrongly")
            return 1
        if control_dict() != 'key="\\x5a\\xa5\\xc3\\x3c"\n':
            print("self-test: the control dictionary is wrong")
            return 1
        pre = control_prefix()
        if (pre + trig).split(SEP)[4:] != trig.split(SEP) or \
                CONTROL_KEY.to_bytes(4, "little") in pre:
            print("self-test: the enable prefix does not join a seed")
            return 1
        # short, so few inputs the fuzzer keeps lose the path to the plant
        if len(near) > 96:
            print("self-test: the near seed has %d bytes" % len(near))
            return 1
        if near.count(struct.pack("<I", CONTROL_NEAR)) != 1:
            print("self-test: the near CDW15 is not unique in the seed")
            return 1
        # one dword apart, so a compare-guided mutation can find the key
        diff = sum(a != b for a, b in zip(trig, near))
        if diff == 0 or diff > 4:
            print("self-test: trigger and near differ in %d bytes" % diff)
            return 1
        try:
            encode([b"\x03FUZZ"])
        except ValueError:
            pass
        else:
            print("self-test: a record with the separator was accepted")
            return 1
    print("gen-generic-seeds: self-test passed")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--target", choices=["nossd", "bbssd", "zns", "cmb"])
    ap.add_argument("--out")
    ap.add_argument("--control")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    if a.control:
        c = control_seeds()
        write_dir(os.path.join(a.control, "trigger"),
                  [("trigger", c["trigger"])])
        write_dir(os.path.join(a.control, "near"), [("near", c["near"])])
        with open(os.path.join(a.control, "control.dict"), "w") as f:
            f.write(control_dict())
        with open(os.path.join(a.control, "enable.prefix"), "wb") as f:
            f.write(control_prefix())
        return 0
    if not a.target or not a.out:
        ap.error("--target and --out, --control or --self-test")
    write_dir(a.out, seeds(a.target))
    return 0


if __name__ == "__main__":
    sys.exit(main())
