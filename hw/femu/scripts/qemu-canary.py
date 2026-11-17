#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Merge FEMU with a newer QEMU, for the QEMU canary.

    qemu-canary.py [--base REV] FEMU_REV QEMU_REV OUTDIR

FEMU is a QEMU tree with FEMU changes. The base is the QEMU release that
FEMU_REV holds (v + its VERSION file), unless --base names it. The script
runs a three-way merge of the trees (base, FEMU_REV, QEMU_REV), with no
common history needed, and writes:

    OUTDIR/report.txt   one line per conflict, then RESULT=green or red
    OUTDIR/src/         the merged tree, when the result is green

Only the paths in NOT_SHIPPED and VENDORED follow FEMU policy; a conflict
on any other path makes the result red. The script uses no network: the
repository must hold the three revisions.
Exit status: 0 green, 1 red, 2 a setup error.

    qemu-canary.py --self-test
"""

import argparse
import fnmatch
import os
import subprocess
import sys
import tempfile

# QEMU files that FEMU does not ship. A QEMU change to one of them is not
# merged. Any other file that FEMU removes conflicts as usual.
NOT_SHIPPED = [
    ".b4-config", ".dir-locals.el", ".editorconfig", ".exrc", ".gdbinit",
    ".git-blame-ignore-revs", ".gitattributes", ".gitmodules", ".gitpublish",
    ".mailmap", ".patchew.yml", ".readthedocs.yml", ".travis.yml",
    ".github/workflows/lockdown.yml", ".gitlab-ci.yml", ".gitlab-ci.d/*",
    ".gitlab-map-*", ".gitlab/*",
    # prebuilt linux-user vDSO images; FEMU builds no linux-user target
    "linux-user/*/vdso*.so",
    "tests/docker/dockerfiles/debian-microblaze-cross.d/build-toolchain.sh",
]
# QEMU submodules that FEMU ships as plain directories (the gitlinks of
# QEMU 11.1.3). A new QEMU submodule is not on the list.
VENDORED = [
    "roms/QemuMacDrivers", "roms/SLOF", "roms/edk2", "roms/ipxe",
    "roms/openbios", "roms/opensbi", "roms/qboot", "roms/qemu-palcode",
    "roms/seabios", "roms/seabios-hppa", "roms/skiboot", "roms/u-boot",
    "roms/u-boot-sam460ex", "roms/vbootrom", "tests/lcitool/libvirt-ci",
]


class SetupError(Exception):
    pass


def match(path, patterns):
    return any(fnmatch.fnmatchcase(path, p) for p in patterns)


def dec(b):
    return b.decode("utf-8", "surrogateescape")


def enc(s):
    return s.encode("utf-8", "surrogateescape")


# checkout settings that keep each blob, mode and symlink as Git stores it
EXPORT_CONFIG = ["-c", "core.symlinks=true", "-c", "core.autocrlf=false",
                 "-c", "core.eol=lf", "-c", "core.safecrlf=false"]


def git(*args, env=None, check=True, data=None):
    r = subprocess.run(["git", *args], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, env=env, input=data)
    if check and r.returncode != 0:
        raise SetupError("git %s: %s" % (" ".join(args), dec(r.stderr)))
    return r


def entry(rev, path):
    """(mode, type) of path at rev, or None."""
    out = git("ls-tree", "-z", rev, "--", ":(literal)" + path).stdout
    for rec in out.split(b"\0"):
        if not rec:
            continue
        meta, name = rec.split(b"\t", 1)
        if dec(name) == path:
            mode, kind, _ = dec(meta).split(" ")
            return mode, kind
    return None


def parse(out):
    """The tree and the messages of `merge-tree -z --name-only`."""
    parts = out.split(b"\0")
    tree = dec(parts[0])
    i = 1
    while i < len(parts) and parts[i]:      # conflicted paths
        i += 1
    i += 1
    msgs = []
    # Git 2.43 can print plain advice text after the last record; the
    # records before it are kept, and the caller reports the text.
    while i < len(parts) and parts[i] and parts[i].isdigit():
        n = int(parts[i])
        paths = [dec(p) for p in parts[i + 1:i + 1 + n]]
        kind = dec(parts[i + 1 + n])
        text = dec(parts[i + 2 + n])
        msgs.append((kind, paths, text))
        i += 3 + n
    rest = dec(b"\0".join(parts[i:])).strip("\0\n ")
    return tree, msgs, rest


def classify(msgs, base, femu, qemu):
    """Split the conflicts into policy ones (with paths to drop) and red."""
    policy, red, drop = [], [], []
    moved = set()
    for kind, paths, text in msgs:
        if kind != "CONFLICT (file/directory)":
            continue
        # paths: the path, and "path~REV", where the merge moved QEMU's entry
        pair = sorted(paths, key=len)
        orig, away = (pair + [None, None])[:2]
        q = entry(qemu, orig)
        f = entry(femu, orig)
        if (len(paths) == 2 and away.startswith(orig + "~") and
                orig in VENDORED and
                q and q[0] == "160000" and f and f[1] == "tree"):
            policy.append((kind, orig))
            moved.add(away)
            drop.append(away)
        else:
            red.append((kind, ", ".join(paths)))
    for kind, paths, text in msgs:
        if kind in ("Auto-merging", "CONFLICT (file/directory)"):
            continue
        if kind == "CONFLICT (modify/delete)" and len(paths) == 1:
            p = paths[0]
            if p in moved:
                continue
            if (match(p, NOT_SHIPPED) and entry(femu, p) is None and
                    entry(base, p) is not None):
                policy.append((kind, p))
                drop.append(p)
                continue
        red.append((kind, ", ".join(paths)))
    return policy, red, drop


def index_env(d):
    return dict(os.environ, GIT_INDEX_FILE=os.path.join(d, "index"))


def resolve(tree, drop):
    """tree without the dropped paths; touches no work tree."""
    with tempfile.TemporaryDirectory() as d:
        env = index_env(d)
        git("read-tree", tree, env=env)
        if drop:
            git("update-index", "--force-remove", "-z", "--stdin", env=env,
                data=b"".join(enc(p) + b"\0" for p in drop))
        return dec(git("write-tree", env=env).stdout).strip()


def gitlinks(tree):
    out = git("ls-tree", "-r", "-z", tree).stdout
    links = []
    for rec in out.split(b"\0"):
        if rec.startswith(b"160000 "):
            links.append(dec(rec.split(b"\t", 1)[1]))
    return links


def export(tree, dest):
    """Every blob and symlink of tree under dest, with its mode."""
    with tempfile.TemporaryDirectory() as d:
        env = index_env(d)
        git("read-tree", tree, env=env)
        git(*EXPORT_CONFIG, "checkout-index", "-a",
            "--prefix=" + dest.rstrip("/") + "/", env=env)


def run(base, femu, qemu, outdir):
    # paths in the tree are relative to the top, so work from there
    outdir = os.path.abspath(outdir)
    top = dec(git("rev-parse", "--show-toplevel").stdout).strip()
    os.chdir(top)
    os.makedirs(outdir, exist_ok=True)
    report = os.path.join(outdir, "report.txt")
    with open(report, "w") as f:
        f.write("RESULT=setup-error\n")
    for rev in (femu, qemu):
        git("rev-parse", "--verify", "-q", rev + "^{commit}")
    if base is None:
        base = "v" + dec(git("show", femu + ":VERSION").stdout).strip()
    git("rev-parse", "--verify", "-q", base + "^{commit}")
    r = git("merge-tree", "--write-tree", "-z", "--name-only",
            "--merge-base=" + base, femu, qemu, check=False)
    with open(os.path.join(outdir, "merge-tree.out"), "wb") as f:
        f.write(r.stdout + r.stderr)
    if r.returncode not in (0, 1):
        raise SetupError("merge-tree: " + dec(r.stderr))
    try:
        tree, msgs, rest = parse(r.stdout)
    except (ValueError, IndexError) as e:
        # Git 2.43 can print plain advice text after the last record
        raise SetupError("cannot parse merge-tree output (%s); "
                         "see merge-tree.out" % e)
    policy, red, drop = classify(msgs, base, femu, qemu)
    lines = ["BASE=" + base,
             "FEMU=" + dec(git("rev-parse", femu).stdout).strip(),
             "QEMU=" + dec(git("rev-parse", qemu).stdout).strip()]
    lines += ["POLICY %s %s" % c for c in policy]
    lines += ["CONFLICT %s %s" % c for c in red]
    if rest:
        lines.append("NOTE merge-tree printed text after its records; "
                     "see merge-tree.out")
    if red:
        lines.append("RESULT=red")
    else:
        merged = resolve(tree, drop)
        lines.append("TREE=" + merged)
        # a submodule left in the tree is not built; name each one
        lines += ["GITLINK %s (not checked out)" % p
                  for p in gitlinks(merged)]
        export(merged, os.path.join(outdir, "src"))
        lines.append("RESULT=green")
    with open(report, "w") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 1 if red else 0


def self_test():
    """Build small trees and check each conflict kind."""
    with tempfile.TemporaryDirectory() as d:
        os.chdir(d)
        git("init", "-q")
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
                   GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")

        def commit(files, subs=()):
            e = index_env(d)
            idx = e["GIT_INDEX_FILE"]
            if os.path.exists(idx):
                os.unlink(idx)
            for path, val in files.items():
                mode, text = val if isinstance(val, tuple) else ("100644", val)
                oid = git("hash-object", "-w", "--stdin", env=e,
                          data=text.encode()).stdout.decode().strip()
                git("update-index", "--add", "--cacheinfo",
                    "%s,%s,%s" % (mode, oid, path), env=e)
            for sub, oid in subs:
                git("update-index", "--add", "--cacheinfo",
                    "160000,%s,%s" % (oid, sub), env=e)
            t = git("write-tree", env=e).stdout.decode().strip()
            return git("commit-tree", t, "-m", "c",
                       env=env).stdout.decode().strip()

        VENDORED.append("roms/fw")
        g1, g2 = "1" * 40, "2" * 40
        base = {"VERSION": "1.0\n", "a.c": "1\n2\n3\n", ".mailmap": "x\n",
                "list": "a\nb\nc\n", "src.c": "s\n", "my file": "m\n"}
        b = commit(base, [("roms/fw", g1), ("other", g1)])
        femu = dict(base, **{"a.c": "1\n2\n3\nfemu\n", "roms/fw/x.c": "v\n",
                             ".gitattributes": "attr.txt export-ignore\n",
                             "attr.txt": "kept\n",
                             "hw/femu/f.c": "f\n", "run.sh": ("100755", "r\n"),
                             "link": ("120000", "a.c")})
        del femu[".mailmap"]
        del femu["src.c"]
        f = commit(femu, [("other", g1)])
        up = dict(base, **{"a.c": "0\n1\n2\n3\n", ".mailmap": "y\n"})
        q = commit(up, [("roms/fw", g2), ("other", g1)])
        cases = [("green", f, q, 0, None)]
        f2 = commit(dict(femu, list="a\nF\nc\n"), [("other", g1)])
        q2 = commit(dict(up, list="a\nB\nc\n"), [("roms/fw", g2), ("other", g1)])
        cases.append(("content", f2, q2, 1, "list"))
        q3 = commit(dict(up, **{"hw/femu/f.c": "upstream\n"}),
                    [("roms/fw", g2), ("other", g1)])
        cases.append(("add/add", f, q3, 1, "hw/femu/f.c"))
        # FEMU removes a source file that is not on the policy list
        q4 = commit(dict(up, **{"src.c": "fix\n"}),
                    [("roms/fw", g2), ("other", g1)])
        cases.append(("source removed", f, q4, 1, "src.c"))
        # a submodule that is not on the vendored list
        f5 = commit(dict(femu, **{"other/y.c": "y\n"}))
        q5 = commit(up, [("roms/fw", g2), ("other", g2)])
        cases.append(("not vendored", f5, q5, 1, None))
        bad = 0
        for name, frev, qrev, want, path in cases:
            out = os.path.join(d, "out " + name)
            with open(os.devnull, "w") as null:
                old = sys.stdout
                sys.stdout = null
                try:
                    got = run(b, frev, qrev, out)
                finally:
                    sys.stdout = old
            ok = got == want
            report = open(os.path.join(out, "report.txt")).read()
            if path:
                ok = ok and report.count("\nCONFLICT ") == 1 and \
                    report.count(" " + path + "\n") == 1
            if name == "green" and ok:
                src = os.path.join(out, "src")
                want = {"VERSION": "1.0\n", "a.c": "0\n1\n2\n3\nfemu\n",
                        "list": "a\nb\nc\n", "my file": "m\n",
                        "roms/fw/x.c": "v\n", "hw/femu/f.c": "f\n",
                        "run.sh": "r\n", "attr.txt": "kept\n",
                        ".gitattributes": "attr.txt export-ignore\n"}
                got = {}
                for root, dirs, files in os.walk(src):
                    for fn in files:
                        full = os.path.join(root, fn)
                        rel = os.path.relpath(full, src)
                        if not os.path.islink(full):
                            got[rel] = open(full).read()
                ok = (got == want and
                      os.access(os.path.join(src, "run.sh"), os.X_OK) and
                      not any(os.access(os.path.join(src, k), os.X_OK)
                              for k in want if k != "run.sh") and
                      os.readlink(os.path.join(src, "link")) == "a.c" and
                      "POLICY CONFLICT (modify/delete) .mailmap\n" in report
                      and "POLICY CONFLICT (file/directory) roms/fw\n" in report
                      and "GITLINK other " in report and "~" not in report)
            print("%s %s" % ("ok" if ok else "FAIL", name))
            bad += not ok
        return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--base")
    ap.add_argument("revs", nargs="*")
    a = ap.parse_args()
    try:
        if a.self_test:
            return self_test()
        if len(a.revs) != 3:
            ap.error("need FEMU_REV QEMU_REV OUTDIR")
        return run(a.base, *a.revs)
    except SetupError as e:
        print("qemu-canary: setup error: %s" % e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
