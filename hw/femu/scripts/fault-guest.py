#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Guest side of the events_file fault tests G1 to G4. Runs as root.

  fault-guest.py check      --dev DEV
  fault-guest.py g1-setup   --dev DEV --mnt DIR
  fault-guest.py g1-write   --dev DEV --mnt DIR --records M
  fault-guest.py g1-check   --dev DEV --mnt DIR --records M --sha HEX
                            [--ranges A-B,...]
  fault-guest.py g2-raw     --dev DEV --lba L --phase before|run [--retries N]
  fault-guest.py g2-ext4-setup --dev DEV --mnt DIR
  fault-guest.py g2-ext4-run   --dev DEV --mnt DIR [--retries N]
  fault-guest.py g3-mkfs    --dev DEV --mnt DIR --fs ext4|xfs
  fault-guest.py g3-stress  --mnt DIR --seed S --seconds T [--fsstress PATH]
  fault-guest.py g3-check   --dev DEV --mnt DIR --fs ext4|xfs
  fault-guest.py g3-corrupt --dev DEV --mnt DIR --fs ext4|xfs
  fault-guest.py g4-prep    --dev DEV --timeout-s S
  fault-guest.py g4-fio     --dev DEV --runtime S --limit S
  fault-guest.py dmesg

The host (fault-verdict.py) decides each verdict. This program only does
the guest steps and prints facts, one "FG key=value ..." line each. The
last line is "FG_DONE ok" or "FG_DONE fail <why>". Exit status: 0 for ok,
1 for a failed step, 2 for a usage or setup error.

DEV must be a namespace of a FEMU controller that nothing mounts or
holds; every subcommand checks that first. The tests write to DEV and
make file systems on it.

  G1: setup (real Flush) --> host starts flush-lie --> append records
      1..M, fsync each --> "acked" line: LBAs and hash of record M
      --> wait until the device sees no I/O for 10 s --> host cuts power
      --> reboot --> g1-check: is record M there with its hash? Do
      its LBAs hold M, read raw from DEV?
  G2: A0 at LBA L, fsync --> host starts wb-fail on L --> A1 at L,
      fsync(bdev) twice, read L back with O_DIRECT
  G3: mkfs, mount --> host starts the cut --> fsstress until the cut
      --> reboot --> mount (log recovery), umount, e2fsck -fn or
      xfs_repair -n
  G4: short I/O timeout --> fio random reads --> the host reads dmesg
"""
import argparse
import errno
import fcntl
import hashlib
import mmap
import os
import shutil
import struct
import subprocess
import sys
import time

REC = 4096                      # bytes of one G1 record, one fs block
FS_IOC_FIEMAP = 0xC020660B
FIEMAP_FLAG_SYNC = 1
MAX_EXTENTS = 32
# mkfs writes the inode tables and the journal now. With lazy init,
# ext4lazyinit zeroes them after the mount with Write Zeroes, and each
# Write Zeroes drains the device buffer inside the test window.
MKFS_EXT4 = ["mkfs.ext4", "-F", "-q", "-E",
             "lazy_itable_init=0,lazy_journal_init=0"]
# A guest xfsprogs newer than its kernel turns on features that kernel
# cannot mount (rc 32, "unknown incompatible features"). xfsprogs ships
# one profile for each LTS kernel, with only what that kernel knows,
# under PREFIX/share/xfsprogs/mkfs of the mkfs.xfs that runs.
XFS_LTS_DIRS = ("/usr/local/share/xfsprogs/mkfs", "/usr/share/xfsprogs/mkfs")
# incompat features of a new mkfs.xfs: the dry-run key, the option that
# turns it off, the first kernel that mounts it
XFS_NEW = (("exchange=1", ["-i", "exchange=0"], (6, 10)),
           ("parent=1", ["-n", "parent=0"], (6, 12)))


class StepError(Exception):
    """A guest step failed: FG_DONE fail, exit 1."""


class SetupError(Exception):
    """The guest cannot run the test: FG_DONE fail, exit 2."""


def fact(**kv):
    print("FG " + " ".join("%s=%s" % (k, v) for k, v in kv.items()),
          flush=True)


def run(cmd, limit, check=True):
    """Run a command with a time limit; return (rc, output)."""
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    try:
        raw, _ = p.communicate(timeout=limit)
    except subprocess.TimeoutExpired:
        p.kill()
        # a process in D state ignores SIGKILL: the wait is bounded too
        try:
            p.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            raise StepError("unkillable-" + os.path.basename(cmd[0]))
        raise StepError("timeout-" + os.path.basename(cmd[0]))
    out = raw.decode(errors="replace")
    if check and p.returncode != 0:
        tail = out.strip().splitlines()[-1:] or [""]
        raise StepError("%s-rc%d %s" % (os.path.basename(cmd[0]),
                                        p.returncode, tail[0][:80]))
    return p.returncode, out


def blk_name(dev):
    return os.path.basename(os.path.realpath(dev))


def dev_check(dev):
    """DEV is a FEMU namespace that nothing mounts, swaps on or holds."""
    name = blk_name(dev)
    sysb = "/sys/block/" + name
    if not os.path.isdir(sysb):
        raise SetupError("not-a-disk-" + name)
    ctrl = os.path.basename(os.path.realpath(sysb + "/device"))
    try:
        with open("/sys/class/nvme/%s/model" % ctrl) as f:
            model = f.read().strip()
    except OSError:
        raise SetupError("no-model-" + ctrl)
    if not model.startswith("FEMU"):
        raise SetupError("ctrl-%s-not-femu" % ctrl)
    if os.listdir(sysb + "/holders"):
        raise SetupError("has-holders")
    return name, ctrl


def not_in_use(dev):
    path = "/dev/" + blk_name(dev)
    for tab in ("/proc/mounts", "/proc/swaps"):
        with open(tab) as f:
            for line in f:
                if line.split()[:1] and line.split()[0].startswith(path):
                    raise SetupError("in-use-" + tab)


def boot_id():
    with open("/proc/sys/kernel/random/boot_id") as f:
        return f.read().strip()


def lbs(dev):
    with open("/sys/block/%s/queue/logical_block_size" % blk_name(dev)) as f:
        return int(f.read())


def io_counts(dev):
    """Completed writes and flushes of DEV (Documentation/block/stat)."""
    with open("/sys/block/%s/stat" % blk_name(dev)) as f:
        v = [int(x) for x in f.read().split()]
    return (v[4], v[15] if len(v) > 15 else 0)


def set_retries(n):
    if n is None:
        return
    with open("/sys/module/nvme_core/parameters/max_retries", "w") as f:
        f.write("%d\n" % n)
    with open("/sys/module/nvme_core/parameters/max_retries") as f:
        got = int(f.read())
    if got != n:
        raise SetupError("max-retries-%d" % got)
    fact(max_retries=got)


def g1_record(i):
    body = hashlib.sha256(b"femu-g1-%d" % i).digest() * (REC // 32)
    head = b"FEMU-G1 record %08d\n" % i
    return head + body[len(head):]


def fiemap(fd, off, length):
    """Physical byte extents of [off, off + length) of an open file."""
    hdr = struct.pack("=QQIIII", off, length, FIEMAP_FLAG_SYNC, 0,
                      MAX_EXTENTS, 0)
    buf = bytearray(hdr + b"\0" * (56 * MAX_EXTENTS))
    fcntl.ioctl(fd, FS_IOC_FIEMAP, buf, True)
    nr = struct.unpack_from("=I", buf, 20)[0]
    out = []
    for k in range(nr):
        lo, phys, ln = struct.unpack_from("=QQQ", buf, 32 + 56 * k)
        # the part of the extent inside the asked range
        a = max(lo, off)
        b = min(lo + ln, off + length)
        if a < b:
            out.append((phys + (a - lo), b - a))
    return out


def mount(dev, mnt, opts):
    os.makedirs(mnt, exist_ok=True)
    run(["mount", "-o", opts, dev, mnt], 300)


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def quiet(dev, need=10, limit=120):
    """Wait until DEV completes no write or flush for NEED seconds."""
    end = time.monotonic() + limit
    last = io_counts(dev)
    since = time.monotonic()
    while time.monotonic() < end:
        time.sleep(1)
        cur = io_counts(dev)
        if cur != last:
            last = cur
            since = time.monotonic()
        elif time.monotonic() - since >= need:
            return int(time.monotonic() - since)
    raise StepError("no-quiet-period")


def cmd_g1_setup(a):
    run(MKFS_EXT4 + [a.dev], 300)
    mount(a.dev, a.mnt, "noatime,commit=600")
    path = os.path.join(a.mnt, "g1.dat")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    os.fsync(fd)
    os.close(fd)
    fsync_dir(a.mnt)
    fact(g1_setup="ok", lbs=lbs(a.dev))


def cmd_g1_write(a):
    path = os.path.join(a.mnt, "g1.dat")
    fd = os.open(path, os.O_WRONLY | os.O_APPEND)
    try:
        for i in range(1, a.records + 1):
            rec = g1_record(i)
            n = os.write(fd, rec)
            if n != REC:
                raise StepError("short-write-%d-%d" % (i, n))
            os.fsync(fd)
        ext = fiemap(fd, (a.records - 1) * REC, REC)
    finally:
        os.close(fd)
    if not ext:
        raise StepError("no-extent-for-record-M")
    b = lbs(a.dev)
    ranges = ",".join("%d-%d" % (p // b, (p + ln) // b - 1) for p, ln in ext)
    sha = hashlib.sha256(g1_record(a.records)).hexdigest()
    fact(g1_acked=a.records, lba=ranges, sha256=sha, rec_bytes=REC)
    fact(g1_quiet=quiet(a.dev))


def raw_read(dev, ranges):
    """The bytes of the LBA @ranges ("A-B,C-D") of @dev, read with
    O_DIRECT, so the page cache cannot answer for the device."""
    b = lbs(dev)
    out = b""
    fd = os.open(dev, os.O_RDONLY | os.O_DIRECT)
    try:
        for part in ranges.split(","):
            lo, hi = (int(x) for x in part.split("-", 1))
            m = mmap.mmap(-1, (hi - lo + 1) * b)
            try:
                got = os.preadv(fd, [m], lo * b)
                out += m[:got]
            finally:
                m.close()
    finally:
        os.close(fd)
    return out


def raw_m(a):
    """1 when the LBAs of record M hold M, 0 when not, "-" with no
    ranges. A missing file with M on the media points at metadata."""
    if not a.ranges:
        return "-"
    try:
        data = raw_read(a.dev, a.ranges)
    except OSError:
        return "err"
    return int(len(data) == REC and
               hashlib.sha256(data).hexdigest() == a.sha)


def cmd_g1_check(a):
    try:
        mount(a.dev, a.mnt, "noatime")
    except StepError as e:
        fact(g1_boot_id=boot_id(), g1_mount="fail", g1_m_present=0,
             why=str(e).replace(" ", "_"))
        fact(g1_raw_m_present=raw_m(a))
        return
    path = os.path.join(a.mnt, "g1.dat")
    size = os.path.getsize(path) if os.path.exists(path) else -1
    present = 0
    sha = "-"
    intact = 0
    if size >= 0:
        with open(path, "rb") as f:
            for i in range(1, a.records + 1):
                rec = f.read(REC)
                if len(rec) == REC and rec == g1_record(i):
                    intact += 1
            f.seek((a.records - 1) * REC)
            rec = f.read(REC)
            if len(rec) == REC:
                sha = hashlib.sha256(rec).hexdigest()
                present = int(sha == a.sha)
    run(["umount", a.mnt], 120, check=False)
    fact(g1_boot_id=boot_id(), g1_mount="ok", g1_size=size, g1_intact=intact,
         g1_m_present=present, g1_m_sha=sha)
    fact(g1_raw_m_present=raw_m(a))


def aligned(data):
    m = mmap.mmap(-1, len(data))
    m.write(data)
    return m


def pattern(tag):
    return (tag.encode() * REC)[:REC]


def errname(e):
    return errno.errorcode.get(e, str(e))


def cmd_g2_raw(a):
    b = lbs(a.dev)
    off = a.lba * b
    fd = os.open(a.dev, os.O_RDWR | os.O_DIRECT)
    try:
        if a.phase == "before":
            n = os.pwrite(fd, aligned(pattern("A0")), off)
            os.fsync(fd)
            fact(g2_before=n, lba=a.lba, lbs=b)
            return
        set_retries(a.retries)
        n = os.pwrite(fd, aligned(pattern("A1")), off)
        res = []
        for _ in range(2):
            try:
                os.fsync(fd)
                res.append("0")
            except OSError as e:
                res.append(errname(e.errno))
        m = mmap.mmap(-1, REC)
        got = os.preadv(fd, [m], off)
        data = m[:got]
        read = ("A0" if data == pattern("A0") else
                "A1" if data == pattern("A1") else "other")
        fact(g2_write=n, g2_fsync1=res[0], g2_fsync2=res[1], g2_read=read,
             lba=a.lba)
    finally:
        os.close(fd)


def cmd_g2_ext4_setup(a):
    run(MKFS_EXT4 + [a.dev], 300)
    mount(a.dev, a.mnt, "noatime,commit=600")
    path = os.path.join(a.mnt, "g2.dat")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    os.write(fd, pattern("B0"))
    os.fsync(fd)
    ext = fiemap(fd, 0, REC)
    os.close(fd)
    fsync_dir(a.mnt)
    b = lbs(a.dev)
    fact(g2e_setup="ok", lba=",".join("%d-%d" % (p // b, (p + n) // b - 1)
                                      for p, n in ext))
    fact(g2e_quiet=quiet(a.dev, need=5))


def cmd_g2_ext4_run(a):
    set_retries(a.retries)
    path = os.path.join(a.mnt, "g2.dat")
    fd = os.open(path, os.O_WRONLY)
    os.pwrite(fd, pattern("B1"), 0)
    res = []
    for _ in range(2):
        try:
            os.fdatasync(fd)
            res.append("0")
        except OSError as e:
            res.append(errname(e.errno))
    os.close(fd)
    with open("/proc/sys/vm/drop_caches", "w") as f:
        f.write("3\n")
    fd = os.open(path, os.O_RDONLY | os.O_DIRECT)
    m = mmap.mmap(-1, REC)
    got = os.preadv(fd, [m], 0)
    os.close(fd)
    data = m[:got]
    read = ("B0" if data == pattern("B0") else
            "B1" if data == pattern("B1") else "other")
    fact(g2e_fdatasync1=res[0], g2e_fdatasync2=res[1], g2e_read=read)


def version(text):
    """(major, minor) at the start of @text, or None."""
    parts = text.split(".")
    try:
        return int(parts[0]), int(parts[1].split("-")[0])
    except (IndexError, ValueError):
        return None


def xfs_profile(release, names):
    """The lts_X.Y.conf of @names for kernel @release: the highest
    version not above it, or None."""
    kern = version(release)
    best = None
    for n in names:
        if not (n.startswith("lts_") and n.endswith(".conf")):
            continue
        v = version(n[4:-5])
        if v and kern and v <= kern and (best is None or v > best[0]):
            best = (v, n)
    return best[1] if best else None


def xfs_dirs(mk):
    """The profile dirs: the one of the prefix of @mk first."""
    own = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(mk))),
                       "share", "xfsprogs", "mkfs")
    return [own] + [d for d in XFS_LTS_DIRS if d != own]


def xfs_dry(mk, opts, dev):
    """(ok, output) of a mkfs.xfs dry run: -N writes nothing."""
    rc, out = run([mk, "-N", "-f"] + opts + [dev], 120, check=False)
    return rc == 0, out


def xfs_opts(mk, dev):
    """(options, profile) for a mkfs.xfs that the running kernel mounts."""
    release = os.uname().release
    opts, prof = [], "-"
    for d in xfs_dirs(mk):
        try:
            names = os.listdir(d)
        except OSError:
            continue
        n = xfs_profile(release, names)
        if n and xfs_dry(mk, ["-c", "options=" + os.path.join(d, n)], dev)[0]:
            prof = os.path.join(d, n)
            opts = ["-c", "options=" + prof]
            break
    # a profile older than the mkfs.xfs, or none: turn off each new
    # feature that the dry run shows and this kernel does not know
    kern = version(release) or (0, 0)
    ok, out = xfs_dry(mk, opts, dev)
    for key, off, since in XFS_NEW if ok else ():
        if kern < since and key in out and xfs_dry(mk, opts + off, dev)[0]:
            opts += off
    return opts, prof


def mkfs(fs, dev):
    """Make @fs on @dev, and print the command and the profile."""
    if fs == "ext4":
        cmd, prof = MKFS_EXT4 + [dev], "-"
    else:
        mk = shutil.which("mkfs.xfs") or "mkfs.xfs"
        opts, prof = xfs_opts(mk, dev)
        cmd = [mk, "-f", "-q"] + opts + [dev]
    # no spaces in a fact value: the host splits FG lines on them
    fact(mkfs_fs=fs, mkfs_profile=prof, mkfs_cmd=",".join(cmd))
    run(cmd, 300)
    return prof


def dmesg_tail(n=20):
    """The last kernel lines, as FGK lines: why a mount failed."""
    rc, out = run(["dmesg"], 60, check=False)
    for line in out.splitlines()[-n:] if rc == 0 else []:
        print("FGK " + line, flush=True)


def cmd_g3_mkfs(a):
    # no file system to test is a setup error: the host makes no verdict
    try:
        prof = mkfs(a.fs, a.dev)
    except StepError as e:
        raise SetupError(str(e))
    try:
        mount(a.dev, a.mnt, "noatime")
    except StepError as e:
        dmesg_tail()
        raise SetupError(str(e))
    os.makedirs(os.path.join(a.mnt, "s"), exist_ok=True)
    fsync_dir(a.mnt)
    fact(g3_mkfs=a.fs, mkfs_profile=prof)


def cmd_g3_stress(a):
    tool = a.fsstress
    if not (os.path.isfile(tool) and os.access(tool, os.X_OK)):
        raise SetupError("no-fsstress-" + tool)
    d = os.path.join(a.mnt, "s")
    fact(g3_stress_start=1, seed=a.seed)
    end = time.monotonic() + a.seconds
    rounds = 0
    while time.monotonic() < end:
        left = max(5, int(end - time.monotonic()))
        try:
            p = subprocess.run([tool, "-d", d, "-n", "2000", "-p", "4",
                                "-s", str(a.seed + rounds)],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=left)
        except subprocess.TimeoutExpired:
            break
        rounds += 1
        if p.returncode != 0:
            # a cut makes the fs fail; the host knows when it cut
            fact(g3_stress_rc=p.returncode, rounds=rounds)
            return
    fact(g3_stress_end=1, rounds=rounds)


def fsck_cmd(fs, dev):
    if fs == "ext4":
        return ["e2fsck", "-fn", dev]
    return ["xfs_repair", "-n", dev]


def cmd_g3_check(a):
    try:
        mount(a.dev, a.mnt, "noatime")
        mounted = "ok"
    except StepError:
        mounted = "fail"
        dmesg_tail()
    if mounted == "ok":
        rc, _ = run(["umount", a.mnt], 120, check=False)
        if rc != 0:
            fact(g3_mount=mounted, g3_umount="fail")
            raise StepError("umount")
    rc, out = run(fsck_cmd(a.fs, a.dev), 1200, check=False)
    for line in out.strip().splitlines()[-5:]:
        print("FGL " + line, flush=True)
    fact(g3_mount=mounted, g3_umount="ok" if mounted == "ok" else "-",
         g3_fsck_rc=rc, fs=a.fs)


def cmd_g3_corrupt(a):
    run(["umount", a.mnt], 120, check=False)
    not_in_use(a.dev)
    if a.fs == "ext4":
        # the root directory inode: e2fsck must find it cleared
        run(["debugfs", "-w", "-R", "clri <2>", a.dev], 120)
        what = "clri-root-inode"
        ino = "2"
    else:
        _, out = run(["xfs_db", "-r", "-c", "sb 0", "-c", "p rootino",
                      a.dev], 120)
        ino = out.strip().split("=")[-1].strip()
        if not ino.isdigit():
            raise StepError("no-rootino")
        # a mode of 0 on the root inode: xfs_repair -n must report it
        run(["xfs_db", "-x", "-c", "inode " + ino, "-c",
             "write core.mode 0", a.dev], 120)
        what = "root-inode-mode-0"
    rc, out = run(fsck_cmd(a.fs, a.dev), 1200, check=False)
    # the host looks for the root inode in the whole checker output
    for line in out.strip().splitlines()[:400]:
        print("FGL " + line, flush=True)
    fact(g3_corrupt=what, g3_fsck_rc=rc, fs=a.fs, rootino=ino)


def cmd_g4_prep(a):
    """nvme_core io_timeout, then a rebind so the new queues take it."""
    name, ctrl = dev_check(a.dev)
    param = "/sys/module/nvme_core/parameters/io_timeout"
    with open(param) as f:
        old = int(f.read())
    with open(param, "w") as f:
        f.write("%d\n" % a.timeout_s)
    pci = os.path.realpath("/sys/class/nvme/%s/device" % ctrl)
    addr = os.path.basename(pci)
    drv = os.path.basename(os.path.realpath(pci + "/driver"))
    if drv != "nvme":
        raise SetupError("driver-" + drv)
    # clear before the rebind: its nvme lines show that this guest drove
    # the FEMU controller, also in a run with no fault
    run(["dmesg", "-C"], 30)
    with open("/sys/bus/pci/drivers/nvme/unbind", "w") as f:
        f.write(addr)
    with open("/sys/bus/pci/drivers/nvme/bind", "w") as f:
        f.write(addr)
    q = "/sys/block/%s/queue/io_timeout" % name
    end = time.monotonic() + 60
    while not os.path.exists(q) and time.monotonic() < end:
        time.sleep(1)
    with open(q) as f:
        got = int(f.read())
    if got != a.timeout_s * 1000:
        raise SetupError("io-timeout-%d-ms" % got)
    dev_check(a.dev)
    fact(g4_io_timeout_ms=got, was_s=old)


def cmd_g4_fio(a):
    t0 = time.monotonic()
    fact(g4_fio_start=1)
    rc, out = run(["fio", "--name=g4", "--filename=" + a.dev,
                   "--rw=randread", "--bs=4k", "--iodepth=16",
                   "--ioengine=libaio", "--direct=1", "--time_based",
                   "--runtime=%d" % a.runtime, "--size=256M",
                   "--output-format=terse"], a.limit, check=False)
    fact(g4_fio_rc=rc, g4_fio_s=int(time.monotonic() - t0))
    # the next I/O after the fault: one 4 KiB O_DIRECT read
    fd = os.open(a.dev, os.O_RDONLY | os.O_DIRECT)
    m = mmap.mmap(-1, REC)
    try:
        got = os.preadv(fd, [m], 0)
        nxt = "ok" if got == REC else "short"
    except OSError as e:
        nxt = errname(e.errno)
    finally:
        os.close(fd)
    _, ctrl = dev_check(a.dev)
    with open("/sys/class/nvme/%s/state" % ctrl) as f:
        state = f.read().strip()
    fact(g4_next_io=nxt, g4_ctrl_state=state)


def cmd_dmesg(_a):
    _, out = run(["dmesg"], 60)
    for line in out.splitlines():
        print("FGK " + line)


def cmd_check(a):
    name, ctrl = dev_check(a.dev)
    not_in_use(a.dev)
    tools = ["mkfs.ext4", "e2fsck", "debugfs", "mkfs.xfs", "xfs_repair",
             "xfs_db", "fio", "dmesg"]
    miss = [t for t in tools if shutil.which(t) is None]
    fact(boot_id=boot_id(), kernel=os.uname().release, dev=name, ctrl=ctrl,
         lbs=lbs(a.dev),
         missing=",".join(miss) or "-")
    # a tool the test needs: a program name or an absolute path
    for t in filter(None, a.need.split(",")):
        found = (os.access(t, os.X_OK) if t.startswith("/") else
                 shutil.which(t) is not None)
        if not found:
            raise SetupError("no-tool-" + os.path.basename(t))


CMDS = {
    "check": cmd_check, "g1-setup": cmd_g1_setup, "g1-write": cmd_g1_write,
    "g1-check": cmd_g1_check, "g2-raw": cmd_g2_raw,
    "g2-ext4-setup": cmd_g2_ext4_setup, "g2-ext4-run": cmd_g2_ext4_run,
    "g3-mkfs": cmd_g3_mkfs, "g3-stress": cmd_g3_stress,
    "g3-check": cmd_g3_check, "g3-corrupt": cmd_g3_corrupt,
    "g4-prep": cmd_g4_prep, "g4-fio": cmd_g4_fio, "dmesg": cmd_dmesg,
}
# subcommands that run while DEV holds the test file system
MOUNTED = ("g1-write", "g2-ext4-run", "g3-stress", "g3-corrupt")


def parse(argv):
    p = argparse.ArgumentParser(prog="fault-guest.py")
    p.add_argument("cmd", choices=sorted(CMDS))
    p.add_argument("--dev", default="/dev/nvme0n1")
    p.add_argument("--mnt", default="/mnt/femu-fault")
    p.add_argument("--records", type=int, default=64)
    p.add_argument("--sha", default="")
    p.add_argument("--lba", type=int, default=0)
    p.add_argument("--ranges", default="")
    p.add_argument("--phase", choices=("before", "run"), default="run")
    p.add_argument("--retries", type=int)
    p.add_argument("--fs", choices=("ext4", "xfs"), default="ext4")
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--seconds", type=int, default=240)
    p.add_argument("--need", default="")
    p.add_argument("--fsstress", default="/opt/xfstests/ltp/fsstress")
    p.add_argument("--timeout-s", type=int, default=5)
    p.add_argument("--runtime", type=int, default=30)
    p.add_argument("--limit", type=int, default=180)
    a = p.parse_args(argv)
    if a.records < 1 or a.lba < 0 or a.seconds < 1 or a.runtime < 1:
        p.error("a count or time below its minimum")
    for part in a.ranges.split(",") if a.ranges else []:
        lo, _, hi = part.partition("-")
        if not (lo.isdigit() and hi.isdigit() and int(lo) <= int(hi)):
            p.error("--ranges wants A-B[,C-D...]")
    return a


def main(argv):
    a = parse(argv)
    try:
        if os.geteuid() != 0:
            raise SetupError("not-root")
        if a.cmd != "dmesg":
            dev_check(a.dev)
            if a.cmd not in MOUNTED:
                not_in_use(a.dev)
        CMDS[a.cmd](a)
    except SetupError as e:
        print("FG_DONE fail setup-%s" % e, flush=True)
        return 2
    except (StepError, OSError) as e:
        print("FG_DONE fail %s" % str(e).replace("\n", " ")[:160],
              flush=True)
        return 1
    print("FG_DONE ok", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
