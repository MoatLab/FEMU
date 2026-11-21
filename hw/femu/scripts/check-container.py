#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Check the FEMU container files against each other and against CI.

Rules:
  digest      each FROM of an outside image has a tag and an @sha256 digest
  packages    the image installs the CI build list (ci.yml, job build, step
              "Install dependencies") without ccache, plus EXTRAS, and
              nothing else
  snapshot    ARG UBUNTU_SNAPSHOT has a default of the form YYYYMMDDTHHMMSSZ,
              and the RUN that installs the CI list writes it to APT::Snapshot
              in /etc/apt/apt.conf.d before its last apt-get update
  devcontainer  .devcontainer/devcontainer.json loads as JSON once its
              whole-line // comments are dropped, builds the
              Containerfile from the repository root at stage deps, and does
              not pass /dev/kvm
  ignore      .dockerignore leaves out .git and the build trees

Usage:
    check-container.py [--root DIR]
    check-container.py --self-test
"""

import json
import os
import re
import shutil
import sys
import tempfile

CONTAINERFILE = "hw/femu/container/Containerfile"
DEVCONTAINER = ".devcontainer/devcontainer.json"
DOCKERIGNORE = ".dockerignore"
CI = ".github/workflows/ci.yml"

# In CI only: the image keeps no compiler cache.
CI_ONLY = {"ccache"}
# In the image only, each for a reason in getting-started/container.md.
EXTRAS = {"ca-certificates", "git", "python3", "python3-venv", "libdw-dev",
          "libnuma-dev", "sudo"}
IGNORED = {".git", "build", "build-*", "**/*.qcow2"}
STAGE = "deps"


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def logical_lines(text):
    """Containerfile lines with continuations joined and comments dropped."""
    out = []
    cur = ""
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        if line.endswith("\\"):
            cur += line[:-1] + " "
            continue
        cur += line
        if cur.strip():
            out.append(cur.strip())
        cur = ""
    if cur.strip():
        out.append(cur.strip())
    return out


def install_packages(command):
    """Package names of every apt or apt-get install in a shell command."""
    names = set()
    for m in re.finditer(r"\bapt(?:-get)?\s+install\b([^&;|]*)", command):
        names.update(t for t in m.group(1).split() if not t.startswith("-"))
    return names


def ci_packages(text):
    """Packages of the "Install dependencies" step of the build job."""
    job = re.search(r"^  build:\n(.*?)(?=^  \S)", text, re.M | re.S)
    if not job:
        return None
    step = re.search(r"- name: Install dependencies\n\s+run: \|\n(.*?)"
                     r"(?=^\s+- name:)", job.group(1), re.M | re.S)
    if not step:
        return None
    return install_packages(step.group(1).replace("\\\n", " "))


def check_tree(root):
    """Return a list of (rule, message) for the tree at root."""
    problems = []
    cf_path = os.path.join(root, CONTAINERFILE)
    lines = logical_lines(read(cf_path))

    stages = []
    for line in lines:
        m = re.match(r"FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?$",
                     line, re.I)
        if not m:
            continue
        image, stage = m.group(1), m.group(2)
        if image not in stages and not re.fullmatch(
                r"[\w.\-/]+:[\w.\-]+@sha256:[0-9a-f]{64}", image):
            problems.append(("digest", "FROM %s has no tag and digest" % image))
        if stage:
            stages.append(stage)
    if not stages:
        problems.append(("digest", "%s names no stage" % CONTAINERFILE))

    image_pkgs = set()
    for line in lines:
        if line.upper().startswith("RUN "):
            image_pkgs |= install_packages(line)
    ci = ci_packages(read(os.path.join(root, CI)))
    if ci is None:
        problems.append(("packages", "no Install dependencies step in the "
                         "build job of %s" % CI))
    else:
        want = (ci - CI_ONLY) | EXTRAS
        for name in sorted(want - image_pkgs):
            problems.append(("packages", "the image does not install " + name))
        for name in sorted(image_pkgs - want):
            problems.append(("packages", "the image installs %s, which is in "
                             "neither the CI list nor EXTRAS" % name))

    snap = [m.group(1) for m in (re.match(r"ARG\s+UBUNTU_SNAPSHOT=(\S*)$", x)
                                 for x in lines) if m]
    if len(snap) != 1 or not re.fullmatch(r"\d{8}T\d{6}Z", snap[0]):
        problems.append(("snapshot", "ARG UBUNTU_SNAPSHOT needs one default "
                         "of the form YYYYMMDDTHHMMSSZ, found %r" % snap))
    main = [x for x in lines if x.upper().startswith("RUN ")
            and "libglib2.0-dev" in install_packages(x)]
    use = re.compile(r'echo "APT::Snapshot \\"\$\{?UBUNTU_SNAPSHOT\}?\\";" '
                     r'> /etc/apt/apt\.conf\.d/\S+')
    m = use.search(main[0]) if len(main) == 1 else None
    if not m:
        problems.append(("snapshot", "the RUN that installs the CI list does "
                         "not write UBUNTU_SNAPSHOT to APT::Snapshot"))
    else:
        rest = main[0][m.end():]
        inst = re.search(r"apt-get install[^&;|]*libglib2\.0-dev", rest)
        if not inst or "apt-get update" not in rest[:inst.start()]:
            problems.append(("snapshot", "no apt-get update between the "
                             "APT::Snapshot setting and the install"))

    dc_path = os.path.join(root, DEVCONTAINER)
    try:
        # devcontainer.json is JSON with comments; only whole-line // comments
        # are allowed here, so json can parse the rest
        dc = json.loads("\n".join(x for x in read(dc_path).splitlines()
                                   if not x.lstrip().startswith("//")))
    except (OSError, ValueError) as e:
        problems.append(("devcontainer", "%s: %s" % (DEVCONTAINER, e)))
    else:
        base = os.path.dirname(dc_path)
        build = dc.get("build", {})
        df = os.path.realpath(os.path.join(base, build.get("dockerfile", "")))
        ctx = os.path.realpath(os.path.join(base, build.get("context", ".")))
        if df != os.path.realpath(cf_path):
            problems.append(("devcontainer", "build.dockerfile is not "
                             + CONTAINERFILE))
        if ctx != os.path.realpath(root):
            problems.append(("devcontainer", "build.context is not the "
                             "repository root"))
        if build.get("target") != STAGE or STAGE not in stages:
            problems.append(("devcontainer", "build.target %r is not stage "
                             "%s of %s" % (build.get("target"), STAGE,
                                           CONTAINERFILE)))
        if any("/dev/kvm" in str(a) for a in dc.get("runArgs", [])):
            problems.append(("devcontainer", "runArgs pass /dev/kvm, so the "
                             "container does not open on a host without KVM"))

    try:
        ignored = {x.strip() for x in read(os.path.join(root, DOCKERIGNORE))
                   .splitlines() if x.strip() and not x.startswith("#")}
    except OSError as e:
        problems.append(("ignore", str(e)))
    else:
        for name in sorted(IGNORED - ignored):
            problems.append(("ignore", "%s does not leave out %s"
                             % (DOCKERIGNORE, name)))
    return problems


def report(problems):
    for rule, msg in problems:
        print("FAIL %s: %s" % (rule, msg))
    return 1 if problems else 0


def self_test(root):
    """Plant one fault per rule in a copy; each must fire alone."""
    def edit(rel, old, new):
        def apply(tree):
            path = os.path.join(tree, rel)
            text = read(path)
            if old not in text:
                raise SystemExit("self-test: %r not in %s" % (old, rel))
            with open(path, "w", encoding="utf-8") as f:
                f.write(text.replace(old, new, 1))
        return apply

    cases = [
        ("digest", edit(CONTAINERFILE, "@sha256:", "@sha256:x")),
        ("digest", edit(CONTAINERFILE, "ubuntu:24.04@", "ubuntu@")),
        ("packages", edit(CONTAINERFILE, " libaio-dev ", " ")),
        ("packages", edit(CONTAINERFILE, " sudo ", " sudo curl ")),
        ("packages", edit(CI, "flex bison ccache", "flex bison ccache bc")),
        ("snapshot", edit(CONTAINERFILE, "UBUNTU_SNAPSHOT=2", "UBUNTU_SNAPSHOT=x2")),
        ("devcontainer", edit(DEVCONTAINER, '"target": "deps"',
                              '"target": "nostage"')),
        ("devcontainer", edit(DEVCONTAINER, '"name": "FEMU",',
                              '"name": "FEMU", "runArgs": ["--device=/dev/kvm"],')),
        ("devcontainer", edit(DEVCONTAINER, "{", "{,")),
        ("devcontainer", edit(DEVCONTAINER, '"target": "deps"',
                              '"target": "femu"')),
        ("snapshot", edit(CONTAINERFILE, '"APT::Snapshot', '"APT::Other')),
        ("snapshot", edit(CONTAINERFILE, '"$UBUNTU_SNAPSHOT\\";"',
                          '"20261101T000000Z\\";"')),
        ("snapshot", edit(CONTAINERFILE, "fi && \\\n    apt-get update && ",
                          "fi && \\\n    ")),
        ("ignore", edit(DOCKERIGNORE, "**/*.qcow2\n", "")),
        ("devcontainer", edit(DEVCONTAINER, '"context": ".."', '"context": "."')),
        ("ignore", edit(DOCKERIGNORE, "\n.git\n", "\n")),
    ]
    failed = 0
    with tempfile.TemporaryDirectory() as tmp:
        clean = os.path.join(tmp, "clean")
        for rel in (CONTAINERFILE, DEVCONTAINER, DOCKERIGNORE, CI):
            os.makedirs(os.path.dirname(os.path.join(clean, rel)) or clean,
                        exist_ok=True)
            shutil.copy(os.path.join(root, rel), os.path.join(clean, rel))
        got = check_tree(clean)
        if got:
            print("self-test: the clean copy fails: %s" % got)
            failed += 1
        for i, (rule, plant) in enumerate(cases):
            tree = os.path.join(tmp, "case%d" % i)
            shutil.copytree(clean, tree)
            plant(tree)
            rules = {r for r, _ in check_tree(tree)}
            if rules != {rule}:
                print("self-test: case %d wants only %s, got %s"
                      % (i, rule, sorted(rules)))
                failed += 1
    print("self-test: %d cases, %d failed" % (len(cases) + 1, failed))
    return 1 if failed else 0


def main(argv):
    root = os.path.realpath(os.path.join(os.path.dirname(__file__), "../../.."))
    if argv[:1] == ["--self-test"] and len(argv) == 1:
        return self_test(root)
    if argv[:1] == ["--root"] and len(argv) == 2:
        root = argv[1]
    elif argv:
        print(__doc__.strip())
        return 2
    rc = report(check_tree(root))
    if rc == 0:
        print("container files: ok")
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
