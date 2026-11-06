#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check a FEMU configuration without booting a guest.

femu-config-check.py starts qemu-system-x86_64 with the given options under
-accel qtest, with no guest, and reports one of two results:

  options --> QEMU realizes the devices?
                no  --> FEMU's refusal from stderr          exit 1
                yes --> enable each controller (qtest),
                        Identify, query-femu
                        --> derived configuration          exit 0

The configuration is the one after the controller is enabled, as a guest
driver leaves it: geometry, capacity, over-provisioning, line or reclaim
unit size, the mode of each namespace, the NAND bus timing, and every
warning QEMU printed. Options that need a host resource or a guest image
are dropped or replaced (KVM, -cpu, monitors, disks, networks); the report
lists each one.

Usage:
  femu-config-check.py -device femu,femu_mode=1,devsz_mb=1024
  femu-config-check.py "femu,femu_mode=3"           # a bare -device value
  femu-config-check.py --json -- -device femu-subsys,id=s,fdp=on \\
      -device femu,femu_mode=1,subsys=s
  femu-config-check.py --manifest run.json -device femu,femu_mode=1
  femu-config-check.py --self-test --qemu BUILD/qemu-system-x86_64

--manifest FILE also writes an experiment manifest: the report, the host,
the QEMU build, and each property of each femu device with its value and
its source:

  qom-get value --> named in the -device option? --> "given"
                --> equal to the class default?   --> "default"
                --> else                          --> "derived" (realize set it)

Exit status: 0 the configuration works, 1 QEMU or the controller refused
it, 2 the check itself failed (no binary, timeout, protocol error).
"""

import datetime
import hashlib
import importlib.util
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(HERE, filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# QMP, the qtest NVMe driver and the report helpers
stat = _load("femu_stat", "femu-stat.py")

# A fault the self-test plants to prove that a check can fail
FAULT = ""

MODES = {0: "ocssd", 1: "bbssd", 2: "nossd", 3: "znssd", 4: "csd", 5: "kvssd"}
CSI_NAMES = {0: "NVM", 1: "key-value", 2: "zoned"}
# FEMU's informational lines, and the notice of an unpinned memory backend
INFO_LINE = re.compile(r"^\[FEMU\] (Log|FDP-Log): ")
PIN_NOTICE = re.compile(r"cannot pin the \d+ MiB memory backend")
# A QEMU error about the configuration: QEMU names the option that failed
# ("qemu-system-x86_64: -device femu,...: "), a property, or the machine.
CONFIG_ERROR = re.compile(r"^\S*qemu-system-\S+: (-[\w-]+ |.*Property '|"
                          r".*Parameter '|.*unsupported machine type|"
                          r".*[Mm]achine type )")
WARNING = re.compile(r"^\S*qemu-system-\S+: (.*: )?warning: ")

# options dropped because they need a host resource, a guest or a monitor
DROP_ARG = {"-accel", "-cpu", "-qmp", "-monitor", "-mon",
            "-serial", "-parallel", "-display", "-vga", "-pidfile", "-kernel",
            "-initrd", "-append", "-hda", "-hdb", "-hdc", "-hdd", "-cdrom",
            "-boot", "-D", "-d", "-nic", "-qtest", "-qtest-log", "-runas",
            "-run-with", "-daemonize"}
DROP_FLAG = {"-enable-kvm", "-nographic", "-S", "-snapshot", "-no-reboot",
             "-no-shutdown", "-nodefaults", "-s", "-daemonize"}
DRIVE_KEEP = ("if", "id", "index", "bus", "unit", "media")


class Refused(Exception):
    """QEMU or the controller refused the configuration."""


def split_opts(val: str) -> List[str]:
    """Split a QEMU option string at single commas; ',,' is an escaped comma."""
    return re.split(r"(?<!,),(?!,)", val)


def normalize(args: List[str]) -> Tuple[List[str], List[str]]:
    """The options to start under qtest, and a note for each change."""
    out: List[str] = []
    notes: List[str] = []
    i = 0
    while i < len(args):
        opt = args[i]
        key = opt[1:] if opt.startswith("--") else opt
        val = args[i + 1] if i + 1 < len(args) else None
        if key in DROP_FLAG:
            notes.append(f"dropped {opt}")
            i += 1
        elif key in DROP_ARG:
            notes.append(f"dropped {opt} {val or ''}".rstrip())
            i += 2
        elif key in ("-machine", "-M") and val is not None:
            parts = [p for p in split_opts(val) if not p.startswith("accel=")]
            if len(parts) != len(split_opts(val)):
                notes.append("dropped accel= from -machine")
            if parts:
                out += ["-machine", ",".join(parts)]
            i += 2
        elif key == "-drive" and val is not None:
            keep = [p for p in split_opts(val)
                    if p.split("=", 1)[0] in DRIVE_KEEP]
            out += ["-drive", ",".join(keep + ["driver=null-co",
                                               "read-zeroes=on"])]
            notes.append(f"replaced -drive {val} by a null block device")
            i += 2
        elif key == "-chardev" and val is not None:
            # keep what the devices on it need: its id, and mux= to share it
            keep = [p for p in split_opts(val)
                    if p.startswith(("id=", "mux="))]
            out += ["-chardev", ",".join(["null"] + keep)]
            notes.append(f"replaced -chardev {val} by a null backend")
            i += 2
        elif key == "-netdev" and val is not None:
            ids = [p for p in split_opts(val) if p.startswith("id=")]
            out += ["-netdev", ",".join(["user"] + ids)]
            notes.append(f"replaced -netdev {val} by user networking")
            i += 2
        else:
            out.append(opt)
            i += 1
    return out, notes


def classify_stderr(text: str) -> Tuple[List[str], List[str], List[str]]:
    """Split QEMU's stderr into errors, warnings and informational lines."""
    errors, warnings, info = [], [], []
    for line in text.splitlines():
        if not line.strip() or PIN_NOTICE.search(line):
            continue
        if INFO_LINE.match(line):
            info.append(line)
        elif WARNING.match(line):
            warnings.append(line)
        elif CONFIG_ERROR.match(line) or line.startswith("[FEMU] Err"):
            errors.append(line)
        else:
            warnings.append(line)
    return errors, warnings, info


def nsid_list(data: Optional[bytes]) -> List[int]:
    out = []
    if data:
        for i in range(0, 4096, 4):
            nsid = int.from_bytes(data[i:i + 4], "little")
            if not nsid:
                break
            out.append(nsid)
    return out


def namespace_csi(ctrl, nsid: int) -> int:
    """The command set of a namespace, from its descriptor list."""
    data = ctrl.identify(0x03, nsid)
    i = 0
    while data and i + 4 <= len(data) and data[i]:
        kind, length = data[i], data[i + 1]
        if kind == 4 and length >= 1:
            return data[i + 4]
        i += 4 + length
    return 0


def identify_namespace(ctrl, nsid: int) -> Dict[str, Any]:
    csi = namespace_csi(ctrl, nsid)
    out: Dict[str, Any] = {"command-set": CSI_NAMES.get(csi, f"CSI {csi}")}
    if csi in (0, 2):
        data = ctrl.identify(0x00, nsid)
        if data is None:
            out["identify-error"] = "Identify Namespace refused"
            return out
        nsze = int.from_bytes(data[0:8], "little")
        flbas = data[26]
        fmt = (flbas & 0xf) | (((flbas >> 5) & 3) << 4)
        if FAULT == "wrong-lbaf":
            fmt += 1
        ds = data[128 + 4 * fmt + 2]
        lba = 1 << ds if ds else 0
        out.update({"lba-size": lba, "lba-count": nsze,
                    "capacity-bytes": nsze * lba,
                    "metadata-bytes": int.from_bytes(
                        data[128 + 4 * fmt:130 + 4 * fmt], "little")})
    elif csi == 1:
        data = ctrl.identify(0x05, nsid, csi=1)
        if data is None:
            out["identify-error"] = "key-value Identify Namespace refused"
            return out
        out["capacity-bytes"] = int.from_bytes(data[0:8], "little")
    return out


def identify_controller(ctrl) -> Dict[str, Any]:
    data = ctrl.identify(0x01)
    if data is None:
        return {"identify-error": "Identify Controller refused"}
    text = lambda a, b: data[a:b].decode("ascii", "replace").strip()
    return {"model": text(24, 64), "firmware": text(64, 72),
            "mdts": data[77], "namespaces-supported":
            int.from_bytes(data[516:520], "little")}


def mode_names(qmp, path: str) -> Dict[int, str]:
    """The boot mode of each namespace, from the device properties. Used
    only where query-femu gives no mode."""
    try:
        mode = MODES.get(qmp.execute("qom-get", {"path": path,
                                                 "property": "femu_mode"}))
        modes = qmp.execute("qom-get", {"path": path,
                                        "property": "namespace_modes"}) or ""
        count = qmp.execute("qom-get", {"path": path,
                                        "property": "namespaces"})
    except stat.QmpError:
        return {}
    listed = [m for m in modes.replace(",,", ",").split(",") if m] \
        if modes else []
    return {i + 1: (listed[i] if i < len(listed) else mode)
            for i in range(count)}


def derive(ns: Dict[str, Any], ident: Dict[str, Any]) -> Dict[str, Any]:
    """The figures that follow from the query-femu and Identify replies."""
    out: Dict[str, Any] = {}
    geo = ns.get("geometry")
    cap = ident.get("capacity-bytes")
    if geo:
        raw = (geo["channels"] * geo["luns-per-channel"]
               * geo["planes-per-lun"] * geo["blocks-per-plane"]
               * geo["pages-per-block"] * geo["page-size"])
        out["raw-bytes"] = raw
        out["line-bytes"] = geo["pages-per-line"] * geo["page-size"]
        if cap:
            out["op-percent"] = round((raw / cap - 1) * 100, 2)
    fdp = ns.get("fdp")
    if fdp and geo:
        out["unit-bytes"] = fdp["pages-per-unit"] * geo["page-size"]
    if "zone-size" in ns and ns.get("lba-size"):
        out["zone-bytes"] = ns["zone-size"] * ns["lba-size"]
        out["zone-capacity-bytes"] = ns["zone-capacity"] * ns["lba-size"]
    return out


def shared_op(namespaces: List[Dict[str, Any]]) -> None:
    """FDP namespaces of a controller share one FTL: OP is over their sum."""
    owners: Dict[int, int] = {}
    for e in namespaces:
        owner = e.get("fdp", {}).get("ftl-nsid")
        if owner is not None and e.get("capacity-bytes"):
            owners[owner] = owners.get(owner, 0) + e["capacity-bytes"]
    for e in namespaces:
        owner = e.get("fdp", {}).get("ftl-nsid")
        if owner in owners and e.get("raw-bytes") and FAULT != "op-each":
            e["op-percent"] = round((e["raw-bytes"] / owners[owner] - 1)
                                    * 100, 2)


def check(qemu: str, args: List[str], timeout: float = 60.0,
          records: bool = False) -> Tuple[int, Dict[str, Any]]:
    """Run the check. Returns the exit status and the report. One argument
    with spaces is split as a shell would; a first argument that does not
    start with '-' is the value of a -device option."""
    if len(args) == 1 and re.search(r"\s", args[0]):
        args = shlex.split(args[0])
    if args and not args[0].startswith("-"):
        args = ["-device", args[0]] + args[1:]
    qargs, notes = normalize(args)
    if not any(a in ("-machine", "-M") for a in qargs):
        qargs = ["-machine", "pc"] + qargs
    report: Dict[str, Any] = {"qemu": qemu, "arguments": qargs,
                              "substitutions": notes}
    tmp = tempfile.mkdtemp(prefix="femu-config-check-")
    q = None
    try:
        q = stat.QemuUnderQtest(qemu, qargs, tmp, timeout=timeout)
        if q.exited:
            rc = q.wait_exit(timeout)
            errors, warnings, info = classify_stderr(q.stderr())
            report.update({"result": "refused", "qemu-exit": rc,
                           "errors": errors, "warnings": warnings,
                           "info": info})
            # a signal is a crash, not a refusal
            if (errors or FAULT == "ignore-exit") and rc > 0:
                if FAULT == "ignore-exit":
                    report["result"] = "accepted"
                    return 0, report
                return 1, report
            report["result"] = "check-error"
            report["error"] = (f"QEMU exited with {rc} and gave no "
                               "configuration error: "
                               + " | ".join(warnings + errors))
            return 2, report
        report["result"] = "accepted"
        given = None
        if records:
            given = given_by_path(q.qmp, qargs, report)
        report = inspect(q, report, given)
        if report.get("not-reached"):
            report["result"] = "incomplete"
            report["error"] = ("QEMU accepted the configuration, but this "
                               "check enables controllers on PCI bus 0 "
                               "only and could not inspect "
                               + ", ".join(report["not-reached"]))
            return 2, report
        return 0, report
    except Refused as e:
        report.update({"result": "refused", "errors": [str(e)]})
        return 1, report
    except (stat.ToolError, stat.QmpError, stat.NvmeError, OSError) as e:
        report.update({"result": "check-error", "error": str(e)})
        return 2, report
    finally:
        if q is not None:
            q.close()
            if report.get("result") in ("accepted", "incomplete"):
                errors, warnings, info = classify_stderr(q.stderr())
                report["warnings"], report["info"] = errors + warnings, info
        shutil.rmtree(tmp, ignore_errors=True)


def inspect(q, report: Dict[str, Any],
            given: Optional[Dict[str, Optional[Dict[str, str]]]] = None
            ) -> Dict[str, Any]:
    """Enable the controllers, then read Identify and query-femu. With
    GIVEN (from given_by_path()), also record each femu property."""
    qmp = q.qmp
    mem = stat.GuestMemory.of(qmp)
    if FAULT == "skip-enable":
        ctrls, missed = {}, stat.find_devices(qmp)
    else:
        try:
            ctrls, missed = stat.enable_bus0(qmp, q.qt, mem)
        except stat.NvmeError as e:
            raise Refused(str(e))
    devices: List[Dict[str, Any]] = []
    report["devices"] = devices
    for path in stat.find_devices(qmp):
        dev: Dict[str, Any] = {"path": path}
        ctrl = ctrls.get(path)
        idents: Dict[int, Dict[str, Any]] = {}
        if ctrl is not None:
            f = ctrl.pci
            dev["pci"] = f"{f.bus:02x}:{f.slot:02x}.{f.func}"
            dev["enable"] = ctrl.settings
            dev["controller"] = identify_controller(ctrl)
            active = nsid_list(ctrl.identify(0x02))
            allocated = nsid_list(ctrl.identify(0x10))
            dev["detached-nsids"] = [n for n in allocated if n not in active]
            for nsid in active:
                idents[nsid] = identify_namespace(ctrl, nsid)
        else:
            dev["note"] = ("not on PCI bus 0, so not enabled; a bbssd "
                           "namespace then reports no FTL state")
        sample = stat.Sampler(qmp, [path]).sample()["devices"][path]
        dev["mode"] = sample.get("mode")
        if "error" in sample:
            dev["query-error"] = sample["error"]
        boot_modes = mode_names(qmp, path)
        if dev["mode"] is None:
            try:
                dev["mode"] = MODES.get(qmp.execute(
                    "qom-get", {"path": path, "property": "femu_mode"}))
            except stat.QmpError:
                pass
        by_nsid = {ns.get("nsid"): ns for ns in sample.get("namespaces", [])}
        namespaces = []
        for nsid in sorted(set(idents) | set(by_nsid)):
            ns = by_nsid.get(nsid, {})
            ident = idents.get(nsid, {})
            entry: Dict[str, Any] = {"nsid": nsid,
                                     "mode": ns.get("mode")
                                     or boot_modes.get(nsid)}
            entry.update(ident)
            if "error" in ns:
                entry["query-error"] = ns["error"]
            for key in ("geometry", "line-counts", "lba-size", "zone-size",
                        "zone-capacity", "max-open", "max-active"):
                if key in ns:
                    entry[key if key != "lba-size" else "zoned-lba-size"] = \
                        ns[key]
            if "zone-counts" in ns:
                entry["zones"] = ns["zone-counts"].get("total")
            if "fdp" in ns:
                fdp = ns["fdp"]
                entry["fdp"] = {
                    "reclaim-groups": fdp.get("reclaim-groups"),
                    "units-per-group": fdp.get("units-per-group"),
                    "pages-per-unit": fdp.get("pages-per-unit"),
                    "handles": [h.get("type") for h in fdp.get("handles", [])],
                    "unit-counts": fdp.get("unit-counts"),
                    "placement-handles": fdp.get("placement-handles"),
                    "ftl-nsid": fdp.get("ftl-nsid"),
                    # the dies of each reclaim group
                    "groups": [{k: g.get(k) for k in (
                        "id", "first-channel", "channels", "first-lun",
                        "luns")} for g in fdp.get("groups", [])]}
                if FAULT == "groups-one":
                    entry["fdp"]["groups"] = entry["fdp"]["groups"][:1]
                if FAULT == "phl-first" and namespaces and \
                        "fdp" in namespaces[0]:
                    entry["fdp"]["placement-handles"] = \
                        namespaces[0]["fdp"]["placement-handles"]
            if "media" in ns:
                entry["media"] = stat.media_summary(ns["media"])
            if "lsm" in ns:
                lsm = ns["lsm"]
                entry["kv-index"] = {
                    "kind": "lsm",
                    "memtable-capacity": lsm.get("memtable-capacity"),
                    "size-ratio": lsm.get("size-ratio"),
                    "pinned-levels": lsm.get("pinned-levels"),
                    "records-per-page": lsm.get("records-per-page"),
                    "levels": len(lsm.get("levels", []))}
            if "media" in ns and ns.get("mode") == "kvssd":
                # kv_pack=off leaves the member out
                entry["kv-pack"] = {
                    "on": "pack" in ns,
                    "record-header-bytes":
                        ns.get("pack", {}).get("record-header-bytes")}
            entry.update(derive(ns, ident))
            namespaces.append(entry)
        shared_op(namespaces)
        dev["namespaces"] = namespaces
        devices.append(dev)
        if given is not None:
            property_records(qmp, path, given.get(path), dev)
    report["not-reached"] = missed
    return report


# --------------------------------------------------------------------------
# Manifest

def qemu_opts(text: str) -> List[Tuple[str, str]]:
    """Split a QEMU option string as QemuOpts does: a single comma ends an
    element and ",," is a literal comma."""
    parts, cur, i = [], [], 0
    while i < len(text):
        if text[i] == ",":
            if text[i + 1:i + 2] == ",":
                cur.append(",")
                i += 2
                continue
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(text[i])
        i += 1
    parts.append("".join(cur))
    out = []
    for n, part in enumerate(parts):
        if "=" in part:
            key, _, val = part.partition("=")
        elif n == 0:
            key, val = "driver", part
        elif part.startswith("no"):
            key, val = part[2:], "off"
        else:
            key, val = part, "on"
        out.append((key, val))
    return out


def device_options(qargs: List[str]) -> List[Dict[str, str]]:
    """The properties of each femu -device option, as QEMU creates them:
    the key=value options in command line order, then the JSON ones.
    Names stay as given. The first id= wins, as in QEMU; for the other
    keys, the last one wins."""
    legacy, js = [], []
    for i, a in enumerate(qargs[:-1]):
        if a not in ("-device", "--device"):
            continue
        val = qargs[i + 1]
        if val.lstrip().startswith("{"):
            try:
                obj = json.loads(val)
            except ValueError:
                continue
            if obj.get("driver") == "femu":
                js.append({k: json.dumps(v) if not isinstance(v, str) else v
                           for k, v in obj.items() if k != "driver"})
            continue
        kv: Dict[str, str] = {}
        driver = None
        for key, v in qemu_opts(val):
            if key == "driver":
                driver = v
            elif key == "id":
                kv.setdefault("id", v)
            else:
                kv[key] = v
        if driver == "femu":
            legacy.append(kv)
    return legacy + js


def given_by_path(qmp, qargs: List[str], report: Dict[str, Any]
                  ) -> Dict[str, Optional[Dict[str, str]]]:
    """Map each femu QOM path to the properties given for it, or to None
    when they cannot be known. A device with id= is /machine/peripheral/ID.
    QEMU numbers the anonymous devices in creation order, so the anonymous
    femu options match them in order, but only when the counts agree."""
    opts = device_options(qargs)
    paths = stat.find_devices(qmp)
    anon = sorted((p for p in paths if "/peripheral-anon/" in p),
                  key=lambda p: int(re.sub(r"\D", "", p.rsplit("/", 1)[1])
                                    or 0))
    out: Dict[str, Optional[Dict[str, str]]] = {p: None for p in paths}
    named = [kv for kv in opts if "id" in kv]
    unnamed = [kv for kv in opts if "id" not in kv]
    for kv in named:
        path = f"/machine/peripheral/{kv['id']}"
        if path in out:
            out[path] = {k: v for k, v in kv.items() if k != "id"}
    if len(unnamed) == len(anon):
        for path, kv in zip(anon, unnamed):
            out[path] = kv
    elif anon:
        report.setdefault("notes", []).append(
            f"{len(anon)} anonymous femu devices but {len(unnamed)} options "
            "without id=; their given properties are unknown")
    return out


def property_records(qmp, path: str, given: Optional[Dict[str, str]],
                     dev: Dict[str, Any]) -> None:
    """Record each property of the femu device at PATH in DEV: value,
    default and source. A failed read is recorded, and what was read so
    far stays in DEV."""
    out: List[Dict[str, Any]] = []
    dev["properties"] = out
    try:
        props = qmp.execute("qom-list-properties", {"typename": "femu"})
    except (stat.QmpError, stat.ToolError) as e:
        dev["properties-error"] = str(e)
        return
    for p in sorted(props, key=lambda p: p["name"]):
        name = p["name"]
        if name.startswith("x-") or p.get("type", "").startswith(
                ("child<", "link<")):
            continue
        rec: Dict[str, Any] = {"name": name, "type": p.get("type")}
        out.append(rec)
        try:
            rec["value"] = qmp.execute("qom-get",
                                       {"path": path, "property": name})
        except stat.QmpError as e:
            rec["error"] = str(e)
            continue
        except stat.ToolError as e:
            rec["error"] = str(e)
            dev["properties-error"] = str(e)
            return
        if "default-value" in p:
            rec["default"] = p["default-value"]
        if given is None:
            rec["source"] = "unknown"
        elif name in given and FAULT != "records-no-given":
            rec["source"] = "given"
            rec["given"] = given[name]
        elif ("default" in rec and rec["value"] == rec["default"]) or \
                ("default" not in rec and rec["value"] in (None, "")):
            rec["source"] = "default"
        else:
            rec["source"] = "derived"


def _read(path: str) -> str:
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ""


def host_context() -> Dict[str, Any]:
    """The host facts that change emulated timing."""
    u = platform.uname()
    cpu = re.search(r"^model name\s*:\s*(.+)$", _read("/proc/cpuinfo"),
                    re.MULTILINE)
    mem = re.search(r"^MemTotal:\s*(\d+)", _read("/proc/meminfo"),
                    re.MULTILINE)
    nodes = [d for d in os.listdir("/sys/devices/system/node")
             if re.fullmatch(r"node\d+", d)] \
        if os.path.isdir("/sys/devices/system/node") else []
    scaling = _read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
    return {"hostname": u.node, "kernel": u.release, "machine": u.machine,
            "cpu-model": cpu.group(1).strip() if cpu else None,
            "cpus": os.cpu_count(),
            "mem-kib": int(mem.group(1)) if mem else None,
            "numa-nodes": len(nodes),
            "cpufreq-scaling": scaling.strip() or None,
            "python": platform.python_version()}


def build_context(qemu: str) -> Dict[str, Any]:
    """The QEMU binary and the source tree this tool came from."""
    out: Dict[str, Any] = {"qemu": os.path.abspath(qemu)}
    try:
        h = hashlib.sha256()
        with open(qemu, "rb") as f:
            for block in iter(lambda: f.read(1 << 20), b""):
                h.update(block)
        out["qemu-sha256"] = h.hexdigest()
        ver = subprocess.run([qemu, "--version"], capture_output=True,
                             text=True, timeout=30)
        out["qemu-version"] = (ver.stdout.splitlines() or [""])[0]
    except (OSError, subprocess.SubprocessError) as e:
        out["qemu-error"] = str(e)
    # the checkout of this tool, which may differ from the QEMU build
    for key, cmd in (("tool-commit", ["rev-parse", "HEAD"]),
                     ("tool-dirty", ["status", "--porcelain",
                                       "--untracked-files=no"])):
        try:
            r = subprocess.run(["git", "-C", HERE] + cmd, capture_output=True,
                               text=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            break
        if r.returncode != 0:
            break
        out[key] = r.stdout.strip() if key == "tool-commit" else \
            bool(r.stdout.strip())
    return out


def manifest(qemu: str, code: int, report: Dict[str, Any]
             ) -> Dict[str, Any]:
    return {"manifest": 1,
            "created": datetime.datetime.now(datetime.timezone.utc)
            .isoformat(timespec="seconds"),
            "exit": code, "host": host_context(),
            "build": build_context(qemu), "report": report}


def write_manifest(path: str, data: Dict[str, Any]) -> None:
    """Write PATH whole or not at all."""
    tmp = f"{path}.tmp{os.getpid()}"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=1, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)


# --------------------------------------------------------------------------
# Text view

def size(n: Optional[int]) -> str:
    return stat.fmt_bytes(n) if n is not None else "?"


def report_text(code: int, r: Dict[str, Any]) -> str:
    lines = []
    if code == 1:
        lines.append("femu-config-check: REFUSED")
        lines += ["  " + e for e in r.get("errors", [])]
    elif code == 2:
        lines.append(f"femu-config-check: CHECK ERROR: {r.get('error')}")
        lines += ["  " + e for e in r.get("errors", [])]
    else:
        lines.append("femu-config-check: accepted")
    for d in r.get("devices", []):
        lines.append(f"device {d['path']}  {d.get('mode') or '?'}"
                     + (f"  PCI {d['pci']}" if "pci" in d else ""))
        c = d.get("controller", {})
        if c.get("model"):
            lines.append(f"  controller: {c['model']}, enabled with "
                         f"{d.get('enable')}")
        if d.get("note"):
            lines.append(f"  note: {d['note']}")
        if d.get("query-error"):
            lines.append(f"  query-femu: {d['query-error']}")
        if d.get("detached-nsids"):
            lines.append("  allocated, not attached: nsid "
                         + ", ".join(map(str, d["detached-nsids"])))
        for ns in d.get("namespaces", []):
            head = f"  ns {ns['nsid']} {ns.get('mode') or '?'}"
            if ns.get("command-set"):
                head += f", {ns['command-set']} command set"
            if ns.get("capacity-bytes") is not None:
                head += f": {size(ns['capacity-bytes'])}"
                if ns.get("lba-size"):
                    head += (f" ({ns['lba-count']} blocks of "
                             f"{ns['lba-size']} B)")
            lines.append(head)
            pad = "    "
            g = ns.get("geometry")
            if g:
                lines.append(
                    pad + f"NAND: {g['channels']} channels x "
                    f"{g['luns-per-channel']} LUNs x {g['planes-per-lun']} "
                    f"planes x {g['blocks-per-plane']} blocks x "
                    f"{g['pages-per-block']} pages x {g['page-size']} B = "
                    f"{size(ns.get('raw-bytes'))}")
            if "op-percent" in ns:
                lines.append(pad + f"over-provisioning: {ns['op-percent']}% "
                             "(NAND / capacity - 1)")
            lc = ns.get("line-counts")
            if lc:
                lines.append(pad + f"lines: {lc['total']} of "
                             f"{size(ns.get('line-bytes'))}, free "
                             f"{lc['free']}, spare {lc['spare']}"
                             + (f", reserve {lc['reserve']}"
                                if "reserve" in lc else ""))
            fdp = ns.get("fdp")
            if fdp:
                lines.append(
                    pad + f"FDP: {fdp['reclaim-groups']} reclaim groups x "
                    f"{fdp['units-per-group']} units of "
                    f"{size(ns.get('unit-bytes'))}, {len(fdp['handles'])} "
                    f"handles ({', '.join(sorted(set(fdp['handles'])))})")
                groups = fdp.get("groups") or []
                if len(groups) > 1:
                    for g in groups:
                        c0, l0 = g["first-channel"], g["first-lun"]
                        lines.append(
                            pad + f"reclaim group {g['id']}: channels "
                            f"{c0}-{c0 + g['channels'] - 1}, LUNs "
                            f"{l0}-{l0 + g['luns'] - 1}")
                phl = fdp.get("placement-handles")
                if phl is not None:
                    shared = (f", FTL of namespace {fdp['ftl-nsid']}"
                              if fdp.get("ftl-nsid") not in (None, ns["nsid"])
                              else "")
                    lines.append(pad + "placement handles: "
                                 + ", ".join(f"{i}->RUH {h}"
                                             for i, h in enumerate(phl))
                                 + shared)
            if "zones" in ns:
                lines.append(
                    pad + f"zones: {ns['zones']} of "
                    f"{size(ns.get('zone-bytes'))}, capacity "
                    f"{size(ns.get('zone-capacity-bytes'))}, max open "
                    f"{ns.get('max-open')}, max active {ns.get('max-active')}")
            ki = ns.get("kv-index")
            if ki:
                lines.append(
                    pad + f"KV index: {ki['kind']}, memtable "
                    f"{ki['memtable-capacity']} keys, size ratio "
                    f"{ki['size-ratio']}, {ki['pinned-levels']} pinned "
                    f"levels, {ki['records-per-page']} records a meta page, "
                    f"{ki['levels']} levels now")
            kp = ns.get("kv-pack")
            if kp:
                lines.append(
                    pad + "KV value packing: " + (
                        f"on, {kp['record-header-bytes']} byte record header"
                        if kp["on"] else "off, whole pages for each value"))
            if ns.get("media"):
                lines.append(pad + "media: " + stat.media_text(ns["media"]))
            for key in ("query-error", "identify-error"):
                if ns.get(key):
                    lines.append(pad + f"{key.split('-')[0]}: {ns[key]}")
    for key, title in (("warnings", "warning"), ("substitutions", "changed")):
        for w in r.get(key, []):
            lines.append(f"{title}: {w}")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Self-test

SMALL_BB = ("femu_mode=1,devsz_mb=32,nchs=2,luns_per_ch=2,blks_per_pl=64,"
            "pgs_per_blk=64")


class ConfigSelfTest(stat.SelfTest):
    def control(self, name: str, fault: str, run) -> None:
        """Plant a fault in this tool and require the check to fail."""
        global FAULT
        FAULT = fault
        try:
            caught = not run()
        finally:
            FAULT = ""
        self.check(f"control {name}: the check fails with {fault}", caught,
                   "the check still passed")


def parser_checks(t) -> None:
    """The option parser against QemuOpts rules; no QEMU needed."""
    t.check("options: ',,' is a comma, a single comma ends the element",
            qemu_opts("femu,serial=a,,,nchs=2,id=m") ==
            [("driver", "femu"), ("serial", "a,"), ("nchs", "2"),
             ("id", "m")])
    t.check("options: bare flag is on, no-prefix is off",
            qemu_opts("femu,foo,nobar") ==
            [("driver", "femu"), ("foo", "on"), ("bar", "off")])
    opts = device_options([
        "-device", "driver=femu,acpi-index=7,id=first,id=last",
        "--device", "femu,nchs=4", "-device", "virtio-blk-pci,drive=x",
        "-device", '{"driver": "femu", "nchs": 2}'])
    t.check("options: driver= and --device, dashes kept, first id wins, "
            "JSON last",
            opts == [{"acpi-index": "7", "id": "first"}, {"nchs": "4"},
                     {"nchs": "2"}], str(opts))


def self_test(qemu: str) -> int:
    t = ConfigSelfTest(qemu)
    start = time.monotonic()
    me = os.path.abspath(__file__)
    parser_checks(t)

    def ns1(r: Dict[str, Any]) -> Dict[str, Any]:
        devs = r.get("devices") or [{}]
        return (devs[0].get("namespaces") or [{}])[0]

    def bbssd_ok() -> bool:
        code, r = check(qemu, ["-device", f"femu,{SMALL_BB}"])
        ns = ns1(r)
        return (code == 0 and ns.get("mode") == "bbssd"
                and ns.get("geometry", {}).get("channels") == 2
                and ns.get("capacity-bytes") == 32 << 20
                and ns.get("lba-size") == 512
                and ns.get("raw-bytes") == 2 * 2 * 64 * 64 * 4096
                and ns.get("line-bytes") == 2 * 2 * 64 * 4096
                and ns.get("op-percent") == 100.0)
    t.check("bbssd: geometry, capacity, OP and line size", bbssd_ok(),
            json.dumps(check(qemu, ["-device", f"femu,{SMALL_BB}"])[1])[:600])
    t.control("enable", "skip-enable", bbssd_ok)
    t.control("LBA format", "wrong-lbaf", bbssd_ok)

    def records_ok(opts: str) -> bool:
        code, r = check(qemu, ["-device", f"femu,{opts}"], records=True)
        dev = (r.get("devices") or [{}])[0]
        props = {p["name"]: p for p in dev.get("properties", [])}
        nchs = props.get("nchs", {})
        gc = props.get("gc_thres_pcent", {})
        return (code == 0 and nchs.get("source") == "given"
                and nchs.get("value") == 2 and gc.get("source") == "default"
                and gc.get("value") == 75 and "given" not in r)
    for opts in (f"id=m0,{SMALL_BB}", SMALL_BB):
        t.check(f"property sources ({opts.split(',')[0]})",
                records_ok(opts), "")
    t.control("property sources", "records-no-given",
              lambda: records_ok(SMALL_BB))

    code, r = check(qemu, ["-device", "femu,femu_mode=1,nchs=2,luns_per_ch=2,"
                           "blks_per_pl=64,pgs_per_blk=64,op_pcent=25"])
    ns = ns1(r)
    t.check("bbssd op_pcent=25: OP near 25 %",
            code == 0 and abs(ns.get("op-percent", 0) - 25) < 1, str(ns))

    code, r = check(qemu, ["-device", "femu-subsys,id=s0,nqn=s0,fdp=on,"
                           "fdp.nruh=4", "-device",
                           f"femu,{SMALL_BB},subsys=s0"])
    ns = ns1(r)
    t.check("fdp: reclaim units and handles",
            code == 0 and ns.get("fdp", {}).get("handles", []) ==
            ["persistently-isolated"] * 4
            and ns.get("unit-bytes") == ns.get("line-bytes")
            and not r.get("warnings"), json.dumps(r)[:600])

    def fdp_two_ok() -> bool:
        code, r = check(qemu, ["-device", "femu-subsys,id=s0,nqn=s0,fdp=on,"
                               "fdp.nruh=4", "-device",
                               f"femu,{SMALL_BB},subsys=s0,namespaces=2,"
                               "namespace_phls=0:1,,1:2"])
        nss = (r.get("devices") or [{}])[0].get("namespaces") or []
        return (code == 0 and len(nss) == 2
                and [n.get("fdp", {}).get("placement-handles") for n in nss]
                == [[0, 1], [1, 2]]
                and all(n["fdp"].get("ftl-nsid") == 1 for n in nss)
                # 64 MiB of NAND behind 2 x 16 MiB: one FTL, 100 % OP
                and all(n.get("op-percent") == 100.0 for n in nss)
                and "placement handles: 0->RUH 1, 1->RUH 2, FTL of "
                    "namespace 1" in report_text(code, r))
    t.check("fdp: two namespaces, a placement handle list each",
            fdp_two_ok())

    def fdp_groups_ok() -> bool:
        # four groups of two LUNs of one channel; a unit is a quarter line
        code, r = check(qemu, ["-device", "femu-subsys,id=s0,nqn=s0,fdp=on,"
                               "fdp.nruh=4,fdp.nrg=4", "-device",
                               "femu,femu_mode=1,devsz_mb=8,nchs=2,"
                               "luns_per_ch=4,blks_per_pl=64,pgs_per_blk=64,"
                               "lba_index=3,subsys=s0"])
        ns = ns1(r)
        gs = ns.get("fdp", {}).get("groups", [])
        return (code == 0 and ns.get("fdp", {}).get("reclaim-groups") == 4
                and [(g["first-channel"], g["first-lun"], g["luns"])
                     for g in gs] == [(0, 0, 2), (0, 2, 2), (1, 0, 2),
                                      (1, 2, 2)]
                and ns.get("unit-bytes") * 4 == ns.get("line-bytes")
                and "reclaim group 3: channels 1-1, LUNs 2-3"
                    in report_text(code, r))
    t.check("fdp: four reclaim groups and their dies", fdp_groups_ok())
    t.control("fdp reclaim groups", "groups-one", fdp_groups_ok)

    for props, want in (
            ("fdp.nrg=0", "fdp.nrg must be non-zero"),
            ("fdp.nrg=129", "fdp.nrg (129) must not exceed 128"),
            ("fdp.nruh=16367", "fdp.nruh (16367) must not exceed 16366"),
            ("fdp.nrg=3", "fdp.nrg (3) must divide nchs (2)")):
        code, r = check(qemu, ["-device", "femu-subsys,id=s0,nqn=s0,fdp=on,"
                               "fdp.nruh=4," + props, "-device",
                               f"femu,{SMALL_BB},lba_index=3,subsys=s0"])
        t.check(f"refused: {props}", code == 1 and any(
            want in e for e in r.get("errors", [])), json.dumps(r)[:400])
    t.control("fdp placement handle lists", "phl-first", fdp_two_ok)
    t.control("fdp shared over-provisioning", "op-each", fdp_two_ok)

    code, r = check(qemu, ["femu,femu_mode=3,devsz_mb=64"])
    ns = ns1(r)
    t.check("zns: zones, zoned command set, bare -device value",
            code == 0 and ns.get("command-set") == "zoned"
            and ns.get("zones", 0) > 0 and ns.get("zone-bytes", 0) > 0,
            json.dumps(r)[:600])

    code, r = check(qemu, ["-device", "femu,femu_mode=2,devsz_mb=64"])
    ns = ns1(r)
    t.check("nossd: capacity from Identify, query-femu error noted",
            code == 0 and ns.get("mode") == "nossd"
            and ns.get("capacity-bytes") == 64 << 20
            and "nossd" in ns.get("query-error", ""), json.dumps(r)[:600])

    code, r = check(qemu, ["-device", "femu,femu_mode=5,devsz_mb=64"])
    ns = ns1(r)
    t.check("kvssd: key-value capacity and media timing",
            code == 0 and ns.get("command-set") == "key-value"
            and ns.get("capacity-bytes", 0) > 0 and "media" in ns
            and "kv-index" not in ns, json.dumps(r)[:600])
    t.check("kvssd: value packing on by default",
            ns.get("kv-pack", {}).get("on") is True
            and "KV value packing: on, 32 byte" in report_text(code, r),
            json.dumps(r)[:600])

    code, r = check(qemu, ["-device", "femu,femu_mode=5,devsz_mb=64,"
                           "kv_pack=off"])
    ns = ns1(r)
    t.check("kvssd with kv_pack=off: whole pages",
            code == 0 and ns.get("kv-pack", {}).get("on") is False
            and "KV value packing: off" in report_text(code, r),
            json.dumps(r)[:600])

    code, r = check(qemu, ["-device", "femu,femu_mode=5,devsz_mb=64,"
                           "kv_index=lsm,kv_lsm_size_ratio=4"])
    ns = ns1(r)
    t.check("kvssd with kv_index=lsm: the index and its knobs",
            code == 0 and ns.get("kv-index", {}).get("size-ratio") == 4
            and ns["kv-index"].get("memtable-capacity") == 1024
            and "KV index: lsm" in report_text(code, r), json.dumps(r)[:600])

    def refused_ok() -> bool:
        code, r = check(qemu, ["-device", "femu,femu_mode=9"])
        return code == 1 and any("femu_mode must be" in e
                                 for e in r.get("errors", []))
    t.check("refused: femu_mode=9 exits 1 with FEMU's message", refused_ok())
    t.control("refusal", "ignore-exit", refused_ok)
    code, r = check(qemu, ["-device", "femu,femu_mode=1,gc_thres_pcnt=75"])
    t.check("refused: a misspelled property exits 1",
            code == 1 and any("gc_thres_pcnt" in e for e in r["errors"]),
            json.dumps(r)[:400])
    code, r = check(qemu, ["-machine", "q35", "-device",
                           "pcie-root-port,id=rp", "-device",
                           "femu,bus=rp,femu_mode=2,devsz_mb=64"])
    t.check("a controller behind a bridge: incomplete, exit 2",
            code == 2 and r.get("result") == "incomplete", json.dumps(r)[:400])
    code, r = check(qemu, ["-m", "1M", "-device",
                           "femu,femu_mode=2,devsz_mb=64,serial=x"])
    t.check("1 MiB of RAM: queues in low memory; a warning is reported",
            code == 0 and ns1(r).get("capacity-bytes") == 64 << 20
            and any("serial has no effect" in w for w in r["warnings"]),
            json.dumps(r)[:600])
    code, r = check(qemu, ["-chardev", "socket,id=c0,path=/nonexistent,"
                           "server=on,wait=on", "-device",
                           "isa-serial,chardev=c0", "-device",
                           "femu,femu_mode=2,devsz_mb=64"])
    t.check("a chardev a device uses: replaced by a null backend",
            code == 0 and "null backend" in r["substitutions"][0],
            json.dumps(r)[:400])
    code, r = check(qemu, ["-chardev", "id=c1,backend=null,mux=on", "-device",
                           "isa-serial,chardev=c1", "-device",
                           "isa-serial,chardev=c1", "-netdev",
                           "id=n0,type=user,hostfwd=tcp::1-:22", "-device",
                           "e1000,netdev=n0", "-device",
                           "femu,femu_mode=2,devsz_mb=64"])
    t.check("backends whose id comes first keep their id, and mux=on",
            code == 0 and len(r["substitutions"]) == 2, json.dumps(r)[:400])
    code, r = check(qemu, ["-machine", "nonesuch", "-device", "femu"])
    t.check("refused: an unknown machine exits 1", code == 1,
            json.dumps(r)[:400])
    tmp = tempfile.mkdtemp(prefix="femu-config-check-mem-")
    try:
        capped = os.path.join(tmp, "qemu-system-x86_64")
        with open(capped, "w") as f:
            f.write("#!/bin/sh\nulimit -v 3145728\nexec %s \"$@\"\n"
                    % shlex.quote(os.path.abspath(qemu)))
        os.chmod(capped, 0o755)
        code, r = check(capped, ["-device", "femu,femu_mode=2,devsz_mb=8192"])
        t.check("refused: a backend the host cannot allocate exits 1",
                code == 1 and any("cannot allocate the 8192 MiB" in e
                                  for e in r.get("errors", [])),
                json.dumps(r)[:400])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    tmp = tempfile.mkdtemp(prefix="femu-config-check-crash-")
    try:
        crash = os.path.join(tmp, "qemu-system-x86_64")
        with open(crash, "w") as f:
            f.write("#!/bin/sh\necho 'qemu-system-x86_64: -device femu: "
                    "warning: x' >&2\nkill -ABRT $$\n")
        os.chmod(crash, 0o755)
        code, r = check(crash, ["femu"])
        t.check("a QEMU that dies of a signal: check error, exit 2",
                code == 2, json.dumps(r)[:400])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    code, r = check(os.path.join(HERE, "no-such-qemu"), ["femu"])
    t.check("check error: no binary exits 2", code == 2, json.dumps(r)[:300])

    code, r = check(qemu, ["-enable-kvm", "-cpu", "host", "-m", "512",
                           "-drive", "file=guest.qcow2,if=none,id=hd0",
                           "-device", "virtio-blk-pci,drive=hd0",
                           "-device", "femu,femu_mode=2,devsz_mb=64"])
    t.check("a full command line: host options dropped, disk replaced",
            code == 0 and len(r["substitutions"]) == 3, json.dumps(r)[:600])

    for argv, want, needle in (
            (["--json", "--qemu", qemu, "--", "-device",
              f"femu,{SMALL_BB}"], 0, '"result": "accepted"'),
            (["--qemu", qemu, "-device femu,femu_mode=9"], 1, "REFUSED"),
            (["--qemu", qemu, "femu,femu_mode=3,devsz_mb=64"], 0,
             "zoned command set")):
        proc = subprocess.run([sys.executable, "-I", me] + argv,
                              capture_output=True, text=True, timeout=120)
        shown = [a for a in argv if a not in (qemu, "--qemu")]
        t.check(f"CLI {shlex.join(shown)}: exit {want}",
                proc.returncode == want and needle in proc.stdout,
                f"exit {proc.returncode}: {proc.stdout[-400:]}"
                f"{proc.stderr[-400:]}")
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "m.json")
        proc = subprocess.run([sys.executable, "-I", me, "--qemu", qemu,
                               "--manifest", out, f"femu,{SMALL_BB}"],
                              capture_output=True, text=True, timeout=120)
        try:
            with open(out) as f:
                m = json.load(f)
        except (OSError, ValueError) as e:
            m = {"error": str(e)}
        t.check("CLI --manifest: host, build and sources written",
                proc.returncode == 0 and m.get("exit") == 0
                and m.get("host", {}).get("kernel")
                and len(m.get("build", {}).get("qemu-sha256", "")) == 64
                and m["report"]["devices"][0]["properties"],
                json.dumps(m)[:400] + proc.stderr[-300:])
    print(f"femu-config-check: self-test {t.passed}/"
          f"{t.passed + len(t.failed)} in {time.monotonic() - start:.1f} s")
    return 1 if t.failed else 0


# --------------------------------------------------------------------------

USAGE = """\
usage: femu-config-check.py [--json] [--manifest FILE] [--qemu QEMU]
                            [--timeout SEC] [--] QEMU-OPTIONS...
       femu-config-check.py --self-test [--qemu QEMU]

QEMU-OPTIONS are -device, -object, -machine and other QEMU options, given
as arguments or as one quoted string. A first argument that does not start
with '-' is the value of one -device option.

options:
  --json         print the report as one JSON object
  --manifest FILE  also write the report, the host, the build and the
                 source of each femu property value to FILE (JSON)
  --qemu QEMU    qemu-system-x86_64 to run (default ./qemu-system-x86_64,
                 else build-femu/qemu-system-x86_64 in this source tree)
  --timeout SEC  seconds allowed for QEMU to start (default 60)
  --self-test    start QEMU on known configurations and check this tool
  -h, --help     show this help

Exit status: 0 accepted, 1 refused, 2 the check itself failed.
"""


def default_qemu() -> str:
    for path in ("./qemu-system-x86_64",
                 os.path.join(HERE, "..", "..", "..", "build-femu",
                              "qemu-system-x86_64")):
        if os.access(path, os.X_OK):
            return os.path.abspath(path)
    return "./qemu-system-x86_64"


def main(argv: List[str]) -> int:
    as_json = selftest = False
    qemu = None
    mfile = None
    timeout = 60.0
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-h", "--help"):
            print(USAGE, end="")
            return 0
        if a == "--json":
            as_json = True
        elif a == "--self-test":
            selftest = True
        elif a in ("--qemu", "--timeout", "--manifest"):
            if i + 1 >= len(argv):
                print(f"femu-config-check: {a} needs a value", file=sys.stderr)
                return 2
            if a == "--qemu":
                qemu = argv[i + 1]
            elif a == "--manifest":
                mfile = argv[i + 1]
            else:
                try:
                    timeout = float(argv[i + 1])
                except ValueError:
                    print("femu-config-check: --timeout takes seconds",
                          file=sys.stderr)
                    return 2
            i += 1
        elif a == "--":
            i += 1
            break
        else:
            break
        i += 1
    rest = argv[i:]
    qemu = qemu or default_qemu()
    if os.sep not in qemu:
        qemu = shutil.which(qemu) or qemu
    if selftest:
        return self_test(qemu)
    if not rest:
        print(USAGE, end="", file=sys.stderr)
        return 2
    code, report = check(qemu, rest, timeout, records=mfile is not None)
    if mfile:
        try:
            write_manifest(mfile, manifest(qemu, code, report))
        except OSError as e:
            print(f"femu-config-check: cannot write {mfile}: {e}",
                  file=sys.stderr)
            return 2
    print(json.dumps(report) if as_json else report_text(code, report))
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
