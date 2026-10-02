#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check that the command lines in FEMU's documentation work.

Every fenced code block in README.md and hw/femu/docs/**/*.md is classified
by the HTML comment on the line before it, or else by its info string:

  <!-- femu-example: NAME [; option: value ...] -->
      Tested. The block holds a QEMU command line, -device/-object/-M
      options, or one run-*.sh launcher; blank lines separate independent
      examples in one block. "..." stands for elided options and is dropped,
      and lines that run run-guest-ssh.sh (commands for the booted guest)
      are skipped.
      Options:
        device: TYPE,OPTS   the block lists key=value properties of this
                            device, one or more per line; the whole block
                            is then one example
        io: rw|kv|identify|none   override what the I/O test does
        allow-warning: TEXT       a warning the example may print
  <!-- femu-untested: REASON -->
      Not tested; REASON says why (at least three words).
  ```sh
      Shell commands that do not start FEMU (git, apt, configure, commands
      inside the guest). Allowed untagged.
  ```bash, ```shell, ```console, ```zsh
      Must carry one of the two comments above, or be changed to sh.
  any other info string, or none
      Output, configuration files, code. Allowed untagged.

An untagged block of any kind fails if it starts FEMU: if, outside shell
comments, it runs qemu-system-* as a command, passes -device femu*, or names
a run-*.sh launcher other than run-guest-ssh.sh.

Each femu-example (and each entry's example in hw/femu/docs/modes.py) is
then run in two stages:

  1. QEMU starts with the example's devices under `-accel qtest -S` (q35
     unless the example names a machine). Every -device is kept, in its
     place on the command line, so a guest disk or NIC that the machine
     cannot plug where it lands fails here. The backends they need are
     replaced by stand-ins: each -drive by a null block device with the same
     id and interface, each -netdev and -net user by user networking with no
     forwarded ports. Options that need a guest or a host resource
     (-enable-kvm, -cpu, -qmp, -m) are dropped. QMP must report every femu, femu-subsys
     and femu-cxl-ssd the example creates, query-pci must list each femu as
     an NVMe controller, and QEMU must print nothing on stderr except
     FEMU's informational "[FEMU] Log:" lines, the memory-pinning notice
     (the run lowers RLIMIT_MEMLOCK so it never pins) and the example's
     allow-warning text. Any QEMU warning or "[FEMU] Err:" line fails.
  2. For examples with an NVMe controller, the FEMU qtest doc-examples case
     (hw/femu/tests/qtest/femu-test.c) starts the FEMU devices and what they
     need (the -device types in KEEP_DEVICES and every -object), enables each
     controller, sends Identify, and does one write and read back (or a
     key-value store and retrieve) on namespace 1.

A run-*.sh example is run with stand-ins for sudo and QEMU that record the
command line the launcher builds, so it is the launcher's real options that
are tested.

Usage:
  check-doc-examples.py --lint                       # tags only, no binary
  check-doc-examples.py --qemu Q --qos-test T        # lint, then run all
  check-doc-examples.py --qemu Q --qos-test T --only NAME
  check-doc-examples.py --list                       # print what would run

Exit status: 0 when every block is tagged correctly and every example passes.
"""

import argparse
import json
import os
import re
import resource
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
SCRIPTS = os.path.join(ROOT, "hw", "femu", "scripts")
MODES_PY = os.path.join(ROOT, "hw", "femu", "docs", "modes.py")
QOS_PATH = "/x86_64/pc/i440FX-pcihost/pci-bus-pc/pci-bus/femu/femu-tests/doc-examples"

FENCE_RE = re.compile(r"^(\s{0,3})(`{3,}|~{3,})\s*([^`\s]*)")
TAG_RE = re.compile(r"^\s*<!--\s*femu-(example|untested)\s*:\s*(.*?)\s*-->\s*$")
TAGGED_LANGS = {"bash", "shell", "console", "zsh"}
LAUNCHER_RE = re.compile(r"\brun-(?!guest-ssh)[\w-]+\.sh\b")
DEVICE_FEMU_RE = re.compile(r"(^|\s)-device\s+femu")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*$")
PROP_RE = re.compile(r"^[A-Za-z_][\w.-]*=\S*$")
ENV_RE = re.compile(r"^[A-Za-z_]\w*=")
# The notice backend/dram.c prints when it cannot lock the device memory. The
# run lowers RLIMIT_MEMLOCK, so every NVMe example prints it.
PIN_NOTICE = re.compile(r"cannot pin the \d+ MiB memory backend")
# -drive keys that say where the disk is attached rather than what backs it
DRIVE_KEEP = ("if", "id", "index", "bus", "unit", "media")
# FEMU's informational messages (femu_log, the FDP setup log); they report
# what the device built, not a problem with the options.
INFO_LINE = re.compile(r"^\[FEMU\] (Log|FDP-Log): ")

# QEMU options and whether they take an argument
OPT_ARG = {
    "-device", "-object", "-machine", "-M", "-m", "-accel", "-cpu", "-smp",
    "-name", "-drive", "-net", "-netdev", "-nic", "-qmp", "-serial",
    "-monitor", "-D", "-d", "-kernel", "-initrd", "-append", "-global", "-L",
    "-bios", "-numa", "-chardev", "-hda", "-hdb", "-cdrom", "-boot",
    "-display", "-vga", "-mem-path", "-fsdev", "-virtfs", "-pidfile",
    "-trace", "-smbios", "-rtc", "-k", "-usbdevice", "-mon", "-blockdev",
    "-overcommit", "-sandbox", "-runas", "-run-with", "-msg",
}
OPT_FLAG = {
    "-enable-kvm", "-nographic", "-S", "-daemonize", "-snapshot",
    "-no-reboot", "-no-shutdown", "-nodefaults", "-mem-prealloc", "-s",
    "-no-user-config", "-full-screen",
}
# -device types the I/O stage keeps; the others belong to the guest
KEEP_DEVICES = {"femu", "femu-subsys", "femu-cxl-ssd", "pxb-cxl", "cxl-rp",
                "cxl-upstream", "cxl-downstream"}
COUNTED = ("femu", "femu-subsys", "femu-cxl-ssd")
MODE_IO = None


class Block:
    def __init__(self, path, line, lang, tag, text):
        self.path = path
        self.line = line
        self.lang = lang
        self.tag = tag          # (kind, rest) or None
        self.text = text

    def where(self):
        return f"{os.path.relpath(self.path, ROOT)}:{self.line}"


class Example:
    def __init__(self, name, where, argv=None, script=None, env=None,
                 script_args=None, io=None, allow=None):
        self.name = name
        self.where = where
        self.argv = argv or []
        self.script = script
        self.env = env or {}
        self.script_args = script_args or []
        self.io = io
        self.allow = allow or []


def doc_files():
    out = [os.path.join(ROOT, "README.md")]
    for dirpath, _, names in os.walk(os.path.join(ROOT, "hw", "femu", "docs")):
        out.extend(os.path.join(dirpath, n) for n in sorted(names)
                   if n.endswith(".md"))
    return sorted(out)


def blocks_in(path):
    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    i = 0
    prev = None     # last non-blank line before a fence
    while i < len(lines):
        m = FENCE_RE.match(lines[i])
        if not m:
            if lines[i].strip():
                prev = lines[i]
            i += 1
            continue
        indent, fence, lang = m.group(1), m.group(2), m.group(3).lower()
        start = i
        body = []
        i += 1
        while i < len(lines):
            close = FENCE_RE.match(lines[i])
            if (close and close.group(2)[0] == fence[0]
                    and len(close.group(2)) >= len(fence)
                    and not close.group(3)):
                break
            body.append(lines[i][len(indent):] if lines[i].startswith(indent)
                        else lines[i])
            i += 1
        t = TAG_RE.match(prev) if prev is not None else None
        yield Block(path, start + 1, lang,
                    (t.group(1), t.group(2)) if t else None, "\n".join(body))
        prev = None
        i += 1


def strip_comments(text):
    """Drop shell comments, so prose about a launcher does not count as
    running it."""
    return "\n".join(re.sub(r"(^|\s)#.*$", "", line)
                     for line in text.split("\n"))


def starts_femu(text):
    """What in a block starts FEMU, or None: a QEMU binary as the command of
    a shell segment, a -device femu option, or a run-*.sh launcher."""
    text = re.sub(r"\\\n", " ", strip_comments(text))
    for line in text.split("\n"):
        m = DEVICE_FEMU_RE.search(line) or LAUNCHER_RE.search(line)
        if m:
            return m.group(0).strip()
        for seg in re.split(r"\|\|?|;|&&|\$\(|`", line):
            toks = seg.split()
            while toks and (toks[0] in ("sudo", "env", "exec", "time")
                            or ENV_RE.match(toks[0])):
                toks.pop(0)
            if toks and os.path.basename(toks[0]).startswith("qemu-system-"):
                return toks[0]
    return None


def lint(blocks):
    errors = []
    names = {}
    for b in blocks:
        starts = starts_femu(b.text)
        if b.tag is None:
            if b.lang in TAGGED_LANGS:
                errors.append(f"{b.where()}: untagged ```{b.lang} block; tag it "
                              "<!-- femu-example: NAME --> or <!-- femu-untested: "
                              "REASON -->, or use ```sh for commands that do not "
                              "start FEMU")
            elif starts:
                errors.append(f"{b.where()}: block starts FEMU "
                              f"({starts!r}) but is not tagged "
                              "femu-example or femu-untested")
            continue
        kind, rest = b.tag
        if kind == "untested":
            if len(rest.split()) < 3:
                errors.append(f"{b.where()}: femu-untested needs a reason of at "
                              "least three words")
            continue
        name = rest.split(";", 1)[0].strip()
        if not NAME_RE.match(name):
            errors.append(f"{b.where()}: example name {name!r} must be lower "
                          "case letters, digits, '-' and '.'")
        elif name in names:
            errors.append(f"{b.where()}: example name {name} is also used at "
                          f"{names[name]}")
        names[name] = b.where()
    return errors


def parse_options(rest, where):
    parts = [p.strip() for p in rest.split(";")]
    opts = {"allow": []}
    for p in parts[1:]:
        if not p:
            continue
        key, sep, val = p.partition(":")
        key, val = key.strip(), val.strip()
        if not sep or not val:
            raise ValueError(f"{where}: option {p!r} is not KEY: VALUE")
        if key == "device":
            opts["device"] = val
        elif key == "io":
            if val not in ("rw", "kv", "identify", "none"):
                raise ValueError(f"{where}: io must be rw, kv, identify or none")
            opts["io"] = val
        elif key == "allow-warning":
            opts["allow"].append(val)
        else:
            raise ValueError(f"{where}: unknown option {key!r}")
    return parts[0], opts


def drop_ellipsis_device(value):
    """Remove '...' elements from a -device/-object option string. A doubled
    comma is an escaped comma inside a value, not a separator."""
    parts = re.split(r"(?<!,),(?!,)", value)
    return ",".join(p for p in parts if p.strip() != "...")


def examples_from_block(b):
    name, opts = parse_options(b.tag[1], b.where())
    text = re.sub(r"\\\n", " ", b.text)
    groups = [[]]
    for line in text.split("\n"):
        # a property list is one device however it is spaced out
        if not line.strip() and "device" not in opts:
            if groups[-1]:
                groups.append([])
            continue
        groups[-1].append(line)
    groups = [g for g in groups if g]
    out = []
    for n, group in enumerate(groups):
        ex_name = name if len(groups) == 1 else f"{name}.{n + 1}"
        ex = Example(ex_name, b.where(), io=opts.get("io"),
                     allow=list(opts["allow"]))
        props = []
        for line in group:
            try:
                toks = shlex.split(line, comments=True)
            except ValueError as e:
                raise ValueError(f"{b.where()}: cannot parse {line!r}: {e}")
            if toks and toks[0] == "$":
                toks = toks[1:]
            toks = [t for t in toks if t != "..."]
            if not toks:
                continue
            if "device" in opts and all(PROP_RE.match(t) for t in toks):
                props += toks
                continue
            env = {}
            while toks and (toks[0] in ("sudo", "env") or ENV_RE.match(toks[0])):
                t = toks.pop(0)
                if ENV_RE.match(t):
                    k, _, v = t.partition("=")
                    env[k] = v
            if not toks:
                raise ValueError(f"{b.where()}: {line!r} sets variables and "
                                 "runs nothing")
            base = os.path.basename(toks[0])
            if base == "run-guest-ssh.sh":
                continue    # acts on the booted guest, not on the command line
            if base.startswith("qemu-system-"):
                ex.argv += toks[1:]
            elif LAUNCHER_RE.fullmatch(base):
                if ex.script:
                    raise ValueError(f"{b.where()}: one launcher per example")
                if not os.path.isfile(os.path.join(SCRIPTS, base)):
                    raise ValueError(f"{b.where()}: no launcher "
                                     f"hw/femu/scripts/{base}")
                ex.script = base
                ex.env.update(env)
                ex.script_args = toks[1:]
            elif toks[0].startswith("-"):
                ex.argv += toks
            else:
                raise ValueError(f"{b.where()}: {line.strip()!r} is not a QEMU "
                                 "command line, QEMU options, a run-*.sh "
                                 "launcher" + (" or key=value properties"
                                               if "device" in opts else ""))
        if props:
            ex.argv += ["-device", ",".join([opts["device"]] + props)]
        elif "device" in opts:
            ex.argv += ["-device", opts["device"]]
        out.append(ex)
    return out


def examples_from_modes():
    out = []
    for m in __import__("runpy").run_path(MODES_PY)["MODES"]:
        allow = [m["allow_warning"]] if m.get("allow_warning") else []
        out.append(Example(f"modes.{m['key']}", "hw/femu/docs/modes.py",
                           argv=shlex.split(m["example"]), io=m["io"],
                           allow=allow))
    return out


def capture_launcher(ex, tmp):
    """Run a run-*.sh launcher with sudo and QEMU replaced by recorders and
    return the QEMU arguments it would have used."""
    bindir = os.path.join(tmp, "bin")
    os.makedirs(bindir, exist_ok=True)
    out = os.path.join(tmp, "argv")
    recorder = ("#!/bin/bash\n"
                "for a in \"$@\"; do printf '%s\\0' \"$a\"; done > \"$FEMU_ARGV_OUT\"\n")
    sudo = ("#!/bin/bash\n"
            "while [[ $# -gt 0 && $1 == *=* ]]; do export \"$1\"; shift; done\n"
            "exec \"$@\"\n")
    for path, text in ((os.path.join(tmp, "qemu-system-x86_64"), recorder),
                       (os.path.join(bindir, "sudo"), sudo)):
        with open(path, "w") as f:
            f.write(text)
        os.chmod(path, 0o755)
    image = os.path.join(tmp, "guest.qcow2")
    open(image, "w").close()
    env = dict(os.environ)
    env.update({"PATH": bindir + os.pathsep + env.get("PATH", ""),
                "HOME": tmp, "OSIMGF": image, "IMGDIR": tmp,
                "FEMU_ARGV_OUT": out,
                "QEMU": os.path.join(tmp, "qemu-system-x86_64")})
    env.update(ex.env)
    # the guest image is not part of what is tested
    env["OSIMGF"] = image
    proc = subprocess.run(["bash", os.path.join(SCRIPTS, ex.script)]
                          + ex.script_args, cwd=tmp, env=env,
                          capture_output=True, text=True, timeout=60)
    if not os.path.exists(out):
        raise RuntimeError(f"{ex.script} did not start QEMU (exit "
                           f"{proc.returncode}): {proc.stdout}{proc.stderr}")
    with open(out) as f:
        return [a for a in f.read().split("\0")[:-1]]


def split_opts(val):
    """Split a QEMU option string at single commas; ',,' is an escaped comma."""
    return re.split(r"(?<!,),(?!,)", val)


def stand_in(opt, val):
    """The backend option realize() uses in place of a guest disk or network:
    the same id and attachment, with nothing on the host behind it."""
    parts = split_opts(val)
    if opt == "-drive":
        keep = [p for p in parts if p.split("=", 1)[0] in DRIVE_KEEP]
        return ["-drive", ",".join(keep + ["driver=null-co", "read-zeroes=on"])]
    if opt == "-netdev":
        ids = [p for p in parts[1:] if p.startswith("id=")]
        return ["-netdev", ",".join(["user"] + ids)]
    if opt == "-net" and parts[0] == "user":
        return ["-net", "user"]
    if opt == "-net":
        return ["-net", val]
    return []


def reduce_argv(argv, where):
    """Return the options for the realize stage (every device, backends
    replaced by stand-ins) and for the I/O stage (FEMU devices and what they
    need), the FEMU device counts, and each controller's I/O mode."""
    machine = []
    kept = []
    full = []
    counts = {t: 0 for t in COUNTED}
    modes = []
    i = 0
    while i < len(argv):
        opt = argv[i]
        if opt.startswith("--"):
            opt = opt[1:]
        if opt in OPT_FLAG:
            i += 1
            continue
        if opt not in OPT_ARG:
            raise ValueError(f"{where}: unknown QEMU option {argv[i]!r}; add it "
                             "to OPT_ARG or OPT_FLAG in check-doc-examples.py")
        if i + 1 >= len(argv):
            raise ValueError(f"{where}: {argv[i]} needs an argument")
        val = argv[i + 1]
        i += 2
        if opt in ("-machine", "-M"):
            val = ",".join(p for p in split_opts(val)
                           if not p.startswith("accel="))
            if val:
                machine += ["-machine", val]
        elif opt == "-device":
            val = drop_ellipsis_device(val)
            driver = val.split(",", 1)[0]
            if driver.startswith("driver="):
                driver = driver[len("driver="):]
            for p in split_opts(val)[1:]:
                key = p.split("=", 1)[0]
                if key.startswith("x-"):
                    raise ValueError(f"{where}: {key} is a test-only property; "
                                     "documentation must not use it")
            full += ["-device", val]
            if driver not in KEEP_DEVICES:
                continue
            if driver in counts:
                counts[driver] += 1
            if driver == "femu":
                modes.append(femu_io(val))
            kept += ["-device", val]
        elif opt == "-object":
            kept += ["-object", drop_ellipsis_device(val)]
            full += ["-object", drop_ellipsis_device(val)]
        elif opt == "-global" and val.startswith("femu"):
            kept += ["-global", val]
            full += ["-global", val]
        elif opt in ("-drive", "-netdev", "-net"):
            full += stand_in(opt, val)
    if not machine or not machine[1].split(",")[0] or "=" in machine[1].split(",")[0]:
        machine = ["-machine", "q35"] + machine
    return machine + full, machine + kept, counts, modes


def femu_io(val):
    """What the I/O stage can do with a femu controller, from its options."""
    global MODE_IO
    if MODE_IO is None:
        MODE_IO = {}
        for m in __import__("runpy").run_path(MODES_PY)["MODES"]:
            if m["symbol"] is not None:
                MODE_IO.setdefault(m["femu_mode"], m["io"])
    props = dict(p.split("=", 1) if "=" in p else (p, "on")
                 for p in re.split(r"(?<!,),(?!,)", val)[1:])
    first = props.get("namespace_modes", "").replace(",,", ",").split(",")[0]
    by_name = {"nossd": 2, "bbssd": 1, "znssd": 3, "ocssd": 0, "csd": 4,
               "kvssd": 5}
    try:
        mode = by_name[first] if first in by_name else int(props.get("femu_mode", 2))
    except ValueError:
        return "rw"
    return MODE_IO.get(mode, "rw")


def no_pin(_=None):
    resource.setrlimit(resource.RLIMIT_MEMLOCK, (64 * 1024, 64 * 1024))


def realize(qemu, args, counts, allow, timeout):
    """Stage 1: start under qtest, confirm the devices over QMP, and refuse
    any unexpected stderr. Returns a list of problems."""
    argv = [qemu] + args + ["-accel", "qtest", "-qtest", "null",
                            "-display", "none", "-nodefaults", "-S",
                            "-qmp", "stdio"]
    cmds = [{"execute": "qmp_capabilities"},
            {"execute": "query-pci"},
            {"execute": "qom-list", "arguments": {"path": "/machine/peripheral"}},
            {"execute": "qom-list",
             "arguments": {"path": "/machine/peripheral-anon"}},
            {"execute": "quit"}]
    text = "".join(json.dumps(c) + "\n" for c in cmds)
    try:
        proc = subprocess.run(argv, input=text, capture_output=True, text=True,
                              timeout=timeout, preexec_fn=no_pin)
    except subprocess.TimeoutExpired:
        return [f"QEMU did not finish within {timeout} s"]
    problems = []
    replies = []
    for line in proc.stdout.splitlines():
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if "return" in msg or "error" in msg:
            replies.append(msg)
    bad = [line for line in proc.stderr.splitlines() if line.strip()
           and not PIN_NOTICE.search(line) and not INFO_LINE.match(line)
           and not any(a in line for a in allow)]
    if bad:
        problems.append("stderr: " + " | ".join(bad))
    if len(replies) < 4 or any("error" in r for r in replies[:4]):
        problems.append(f"QEMU exited with {proc.returncode} before answering "
                        "QMP" if len(replies) < 4 else
                        f"QMP error: {[r for r in replies if 'error' in r]}")
        return problems
    nvme = 0

    # Devices behind a bridge the firmware has not numbered (every CXL root
    # port under -S) are not listed, so only NVMe controllers are counted
    # here; QOM above already proved every device was created.
    def walk(devs):
        nonlocal nvme
        for d in devs:
            if d.get("class_info", {}).get("class") == 0x0108:
                nvme += 1
            bridge = d.get("pci_bridge", {})
            walk(bridge.get("devices", []))
    for bus in replies[1]["return"]:
        walk(bus["devices"])
    seen = {t: 0 for t in COUNTED}
    for r in replies[2:4]:
        for child in r["return"]:
            m = re.fullmatch(r"child<(.+)>", child.get("type", ""))
            if m and m.group(1) in seen:
                seen[m.group(1)] += 1
    for t in COUNTED:
        if seen[t] != counts[t]:
            problems.append(f"{counts[t]} {t} on the command line, "
                            f"{seen[t]} created")
    if nvme != counts["femu"]:
        problems.append(f"query-pci lists {nvme} NVMe controllers, expected "
                        f"{counts['femu']}")
    return problems


def run_io(qos_test, qemu, name, ios, args, timeout):
    """Stage 2: the qtest doc-examples case on one example. Returns a list of
    problems."""
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write(f"{name}\t{','.join(ios)}\t{shlex.join(args)}\n")
        spec = f.name
    env = dict(os.environ, QTEST_QEMU_BINARY=os.path.abspath(qemu),
               FEMU_DOC_EXAMPLES=spec)
    try:
        proc = subprocess.run([qos_test, "--tap", "-m", "quick", "-p", QOS_PATH],
                              env=env, capture_output=True, text=True,
                              timeout=timeout, preexec_fn=no_pin)
    except subprocess.TimeoutExpired:
        return [f"I/O test did not finish within {timeout} s"]
    finally:
        os.unlink(spec)
    out = proc.stdout + proc.stderr
    if proc.returncode == 0 and re.search(rf"^# doc-example {re.escape(name)}: ok$",
                                          out, re.MULTILINE):
        return []
    return [f"I/O test failed (exit {proc.returncode}): {out.strip()[-1500:]}"]


def collect(files, with_modes, only):
    """Parse the files; return (blocks, examples, tagging errors)."""
    blocks = [b for p in files for b in blocks_in(p)]
    errors = lint(blocks)
    examples = []
    for b in blocks:
        if b.tag and b.tag[0] == "example":
            try:
                examples += examples_from_block(b)
            except ValueError as e:
                errors.append(str(e))
    if with_modes:
        examples += examples_from_modes()
    if not blocks:
        errors.append("found no code blocks at all; the parser is broken")
    if only:
        examples = [e for e in examples if e.name in only]
        missing = set(only) - {e.name for e in examples}
        errors += [f"no example named {n}" for n in sorted(missing)]
    return blocks, examples, errors


def run_examples(examples, args, quiet=False):
    """Run both stages; return a list of (example, problems) failures."""
    failures = []
    cases = []
    with tempfile.TemporaryDirectory(prefix="femu-doc-") as tmp:
        for ex in examples:
            try:
                argv = ex.argv
                if ex.script:
                    argv = capture_launcher(ex, os.path.join(tmp, ex.name)) + ex.argv
                full, qargs, counts, ios = reduce_argv(argv, ex.where)
            except (ValueError, RuntimeError, subprocess.TimeoutExpired) as e:
                failures.append((ex, [str(e)]))
                continue
            if ex.io:
                ios = [ex.io] * len(ios)
            if args.list:
                print(f"{ex.name} ({ex.where}): io={','.join(ios) or 'none'}\n"
                      f"    realize: {shlex.join(full)}\n"
                      f"    I/O:     {shlex.join(qargs)}")
                continue
            problems = realize(args.qemu, full, counts, ex.allow, args.timeout)
            if problems:
                failures.append((ex, problems))
            elif counts["femu"] and any(io != "none" for io in ios):
                cases.append((ex, ios, qargs))
            elif not quiet:
                print(f"ok   {ex.name}: realize")
    for ex, ios, qargs in cases:
        problems = run_io(args.qos_test, args.qemu, ex.name, ios, qargs,
                          args.timeout)
        if problems:
            failures.append((ex, problems))
        elif not quiet:
            print(f"ok   {ex.name}: realize, I/O ({','.join(ios)})")
    return failures


# Planted mistakes the checker must catch, each with the text its report has
# to contain, and one example that must pass. A checker that stops catching
# any of them fails --self-test instead of passing every document.
SELF_TEST = [
    ("untagged-command", "```bash\n./run-blackbox.sh\n```\n",
     "untagged ```bash block"),
    ("untagged-launch", "```\n-device femu,femu_mode=1\n```\n",
     "block starts FEMU"),
    ("sh-runs-qemu", "```sh\nsudo ./qemu-system-x86_64 -M q35\n```\n",
     "block starts FEMU"),
    ("short-reason", "<!-- femu-untested: later -->\n```bash\nls\n```\n",
     "at least three words"),
    ("misspelled-property",
     "<!-- femu-example: st-misspelled -->\n```sh\n"
     "-device femu,femu_mode=1,devsz_mb=1024,gc_thres_pcnt=75\n```\n",
     "Property 'femu.gc_thres_pcnt' not found"),
    ("invalid-value",
     "<!-- femu-example: st-invalid -->\n```sh\n"
     "-device femu,femu_mode=9\n```\n",
     "femu_mode must be"),
    ("warning-only",
     "<!-- femu-example: st-warning -->\n```sh\n"
     "-machine q35,cxl=on -object memory-backend-ram,id=m,size=256M "
     "-device pxb-cxl,id=cxl.0,bus=pcie.0,bus_nr=52 "
     "-device cxl-rp,id=rp0,bus=cxl.0,chassis=0,slot=0 "
     "-device femu-cxl-ssd,bus=rp0,volatile-memdev=m,der=cylon,"
     "cylon-kernel-ack=on "
     "-M cxl-fmw.0.targets.0=cxl.0,cxl-fmw.0.size=256M\n```\n",
     "FEMU CXL DER unavailable"),
    ("io-only",
     "<!-- femu-example: st-io; io: kv -->\n```sh\n"
     "-device femu,femu_mode=1,devsz_mb=1024\n```\n",
     "I/O test failed"),
    ("test-only-property",
     "<!-- femu-example: st-test-only -->\n```sh\n"
     "-device femu,femu_mode=2,x-ns-test=on\n```\n",
     "test-only property"),
    ("cxl-nic-without-bus",
     "<!-- femu-example: st-cxl-nic -->\n```sh\n"
     "-machine q35,cxl=on -object memory-backend-ram,id=m,size=256M "
     "-device pxb-cxl,id=cxl.0,bus=pcie.0,bus_nr=52 "
     "-device cxl-rp,id=rp0,bus=cxl.0,chassis=0,slot=0 "
     "-device femu-cxl-ssd,bus=rp0,volatile-memdev=m "
     "-M cxl-fmw.0.targets.0=cxl.0,cxl-fmw.0.size=256M "
     "-netdev user,id=net0,hostfwd=tcp::8080-:22 "
     "-device virtio-net-pci,netdev=net0\n```\n",
     "Only PCI/PCIe bridges can be plugged into pxb-cxl"),
    ("missing-backend",
     "<!-- femu-example: st-no-drive -->\n```sh\n"
     "-device femu,femu_mode=1,devsz_mb=1024 "
     "-device virtio-blk-pci,drive=nothere\n```\n",
     "nothere"),
    ("passes",
     "<!-- femu-example: st-good -->\n```sh\n"
     "-device femu,femu_mode=1,devsz_mb=1024\n```\n",
     None),
    ("passes-with-guest-devices",
     "<!-- femu-example: st-good-cxl -->\n```sh\n"
     "-machine q35,cxl=on -object memory-backend-ram,id=m,size=256M "
     "-device pxb-cxl,id=cxl.0,bus=pcie.0,bus_nr=52 "
     "-device cxl-rp,id=rp0,bus=cxl.0,chassis=0,slot=0 "
     "-device femu-cxl-ssd,bus=rp0,volatile-memdev=m "
     "-M cxl-fmw.0.targets.0=cxl.0,cxl-fmw.0.size=256M "
     "-drive file=guest.qcow2,if=none,format=qcow2,id=hd0 "
     "-device virtio-blk-pci,drive=hd0,bus=pcie.0 "
     "-netdev user,id=net0,hostfwd=tcp::8080-:22 "
     "-device virtio-net-pci,netdev=net0,bus=pcie.0\n```\n",
     None),
]


def self_test(args):
    bad = []
    with tempfile.TemporaryDirectory(prefix="femu-doc-self-") as tmp:
        for name, body, want in SELF_TEST:
            path = os.path.join(tmp, name + ".md")
            with open(path, "w") as f:
                f.write(f"# {name}\n\n{body}")
            _, examples, errors = collect([path], False, [])
            failures = run_examples(examples, args, quiet=True)
            report = "\n".join(errors + [p for _, ps in failures for p in ps])
            if want is None:
                ok = not report
            else:
                ok = want in report
            print(f"{'ok  ' if ok else 'FAIL'} self-test {name}"
                  + ("" if ok else f": expected {want or 'a pass'}, got "
                     f"{report or 'a pass'}"))
            if not ok:
                bad.append(name)
    print(f"check-doc-examples: self-test {len(SELF_TEST) - len(bad)}/"
          f"{len(SELF_TEST)}")
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--lint", action="store_true",
                    help="check the tags only; needs no binary")
    ap.add_argument("--list", action="store_true",
                    help="print each example and the options it runs with")
    ap.add_argument("--self-test", action="store_true",
                    help="run planted mistakes and require each to fail")
    ap.add_argument("--qemu", help="qemu-system-x86_64 to test with")
    ap.add_argument("--qos-test", help="tests/qtest/qos-test for the I/O stage")
    ap.add_argument("--only", action="append", default=[],
                    help="run only the named example (repeatable)")
    ap.add_argument("--timeout", type=int, default=60,
                    help="seconds allowed for one QEMU start (default 60)")
    ap.add_argument("paths", nargs="*",
                    help="Markdown files instead of README.md and hw/femu/docs/**")
    args = ap.parse_args()
    if not (args.lint or args.list or args.qemu):
        ap.error("give --lint, --list, or --qemu")
    if args.qemu and not args.qos_test and not args.lint:
        ap.error("--qemu needs --qos-test for the I/O stage")
    if args.self_test:
        return self_test(args)

    files = [os.path.abspath(p) for p in args.paths] or doc_files()
    blocks, examples, errors = collect(files, not args.paths, args.only)
    ntagged = sum(1 for b in blocks if b.tag)
    print(f"check-doc-examples: {len(files)} files, {len(blocks)} code blocks, "
          f"{ntagged} tagged, {len(examples)} examples")
    for e in errors:
        print(e)
    if args.lint:
        print(f"check-doc-examples: {len(errors)} errors")
        return 1 if errors else 0

    failures = run_examples(examples, args)
    if args.list:
        return 0
    for ex, problems in failures:
        print(f"FAIL {ex.name} ({ex.where}):")
        for p in problems:
            print(f"    {p}")
    print(f"check-doc-examples: {len(examples)} examples, {len(failures)} "
          f"failed, {len(errors)} tagging errors")
    return 1 if failures or errors else 0


if __name__ == "__main__":
    sys.exit(main())
