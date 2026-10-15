#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Show the live FTL counters of a running FEMU VM, like top.

femu-stat.py connects to the QMP socket of a running QEMU, finds every femu
device, and polls the QMP commands query-femu and query-femu-stages:

  QMP socket --> query-femu {path}         per namespace counters and state
             --> query-femu-stages {path}  I/O stage histograms (io_stages=on)
             --> this sample - last sample --> view or one JSON line

For each namespace it shows what the reply holds: host, NAND, GC and pad
pages with their change over the interval, WAF since the device started and
over the interval, page and erase rates, line or reclaim unit counts, zone
counts, and the NAND bus timing. A counter it does not know is shown under
its QMP name. With io_stages=on it shows, per stage, the commands, mean and
p50/p99 over the interval, and the largest time since the counts were last
reset. It never resets the counts.

Rates use the measured time between two samples. The first sample has no
interval. A counter that goes down starts a new baseline for that group of
counters (namespace, stages or FDP handle).

Usage:
  femu-stat.py SOCKET                     # refresh every second, like top
  femu-stat.py SOCKET --once              # one sample, since start
  femu-stat.py SOCKET --json --count 10   # one JSON object per line
  femu-stat.py --self-test --qemu BUILD/qemu-system-x86_64

SOCKET is a Unix socket path or HOST:PORT of a QMP server, for example
-qmp unix:/tmp/femu-qmp.sock,server=on,wait=off on the QEMU command line.

Exit status: 0 on success, 1 when the self-test fails, 2 on a usage or
connection error.
"""

import argparse
import json
import math
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

# A fault the self-test plants to prove that a check can fail. Empty in
# normal use.
FAULT = ""

NBUCKETS = 40
COUNTER_ORDER = ("host-write-pages", "nand-write-pages", "gc-write-pages",
                 "pad-write-pages", "block-erases")
# counters that the reply leaves out while they are zero
ZERO_WHEN_ABSENT = ("pad-write-pages",)
SHORT = {"host-write-pages": "host", "nand-write-pages": "nand",
         "gc-write-pages": "gc", "pad-write-pages": "pad",
         "block-erases": "erases"}
MAX_NSID = 256


class QmpError(Exception):
    """A QMP command returned an error."""

    def __init__(self, desc: str, cls: str = "GenericError"):
        super().__init__(desc)
        self.desc = desc
        self.cls = cls


class ToolError(Exception):
    """The tool cannot go on: no connection, no device, bad arguments."""


# --------------------------------------------------------------------------
# QMP client

class QmpClient:
    """QMP over a stream socket: the greeting, qmp_capabilities, and
    commands matched to their replies by id. Events are skipped."""

    def __init__(self, sock: socket.socket, timeout: float = 30.0):
        self.sock = sock
        self.sock.settimeout(timeout)
        self.file = sock.makefile("rwb")
        self.next_id = 0
        greeting = self._read()
        if not isinstance(greeting, dict) or \
                not isinstance(greeting.get("QMP"), dict):
            raise ToolError(f"not a QMP server: {greeting!r}")
        self.execute("qmp_capabilities")

    @classmethod
    def connect(cls, address: str, timeout: float = 30.0) -> "QmpClient":
        """Connect to a Unix socket path, or to HOST:PORT."""
        host, sep, port = address.rpartition(":")
        try:
            if sep and port.isdigit() and not os.path.exists(address):
                sock = socket.create_connection((host or "localhost",
                                                 int(port)), timeout)
            else:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect(address)
        except OSError as e:
            raise ToolError(f"cannot connect to QMP at {address}: {e}")
        return cls(sock, timeout)

    def _read(self) -> Dict[str, Any]:
        try:
            line = self.file.readline()
        except (OSError, socket.timeout) as e:
            raise ToolError(f"QMP connection failed: {e}")
        if not line:
            raise ToolError("QMP connection closed")
        try:
            return json.loads(line)
        except ValueError:
            raise ToolError(f"QMP sent something that is not JSON: {line!r}")

    def execute(self, cmd: str, args: Optional[Dict[str, Any]] = None) -> Any:
        self.next_id += 1
        msg: Dict[str, Any] = {"execute": cmd, "id": self.next_id}
        if args:
            msg["arguments"] = args
        try:
            self.file.write(json.dumps(msg).encode() + b"\n")
            self.file.flush()
        except OSError as e:
            raise ToolError(f"QMP connection failed: {e}")
        while True:
            reply = self._read()
            if not isinstance(reply, dict):
                raise ToolError(f"QMP sent a reply that is not an object: "
                                f"{reply!r}")
            if "event" in reply or reply.get("id") != self.next_id:
                continue
            if "error" in reply:
                err = reply["error"] if isinstance(reply["error"], dict) \
                    else {}
                raise QmpError(err.get("desc", "?"), err.get("class", "?"))
            return reply.get("return")

    def close(self) -> None:
        try:
            self.file.close()
            self.sock.close()
        except OSError:
            pass


# --------------------------------------------------------------------------
# Sampling

def find_devices(qmp: QmpClient) -> List[str]:
    """QOM paths of every femu device."""
    paths = []
    for parent in ("/machine/peripheral", "/machine/peripheral-anon"):
        try:
            children = qmp.execute("qom-list", {"path": parent})
        except QmpError:
            continue
        for child in children:
            if child.get("type") == "child<femu>":
                paths.append(f"{parent}/{child['name']}")
    return paths


class Sampler:
    """Reads one sample of every device. A device whose whole query fails
    (a nossd namespace, a namespace on a CXL medium, a bbssd namespace of a
    controller not yet enabled) is read namespace by namespace. The nsids
    are the ones --ns gives, else the attached ones, found again every
    REPROBE samples and after one goes away."""

    REPROBE = 10

    def __init__(self, qmp: QmpClient, paths: List[str],
                 nsids: Optional[List[int]] = None):
        self.qmp = qmp
        self.paths = paths
        self.nsids = nsids
        self.known: Dict[str, List[int]] = {}
        self.age: Dict[str, int] = {}

    def _query(self, path: str, nsid: Optional[int] = None) -> Dict[str, Any]:
        args: Dict[str, Any] = {"path": path}
        if nsid is not None:
            args["nsid"] = nsid
        return self.qmp.execute("query-femu", args)

    def _probe(self, path: str) -> List[int]:
        found = []
        for nsid in range(1, MAX_NSID + 1):
            try:
                self._query(path, nsid)
            except QmpError as e:
                if "is not attached" in e.desc:
                    continue
            found.append(nsid)
        return found

    def _nsids(self, path: str) -> List[int]:
        if self.nsids:
            return self.nsids
        age = self.age.get(path, 0)
        if path not in self.known or age >= self.REPROBE:
            self.known[path] = self._probe(path)
            age = 0
        self.age[path] = age + 1
        return self.known[path]

    def _device(self, path: str) -> Dict[str, Any]:
        dev: Dict[str, Any] = {"path": path, "namespaces": []}
        first_error = None
        if not self.nsids:
            try:
                reply = self._query(path)
                if FAULT == "skip-fallback":
                    raise QmpError("planted")
                dev["mode"] = reply.get("mode")
                dev["namespaces"] = reply.get("namespaces", [])
                return dev
            except QmpError as e:
                first_error = e.desc
                if FAULT == "skip-fallback":
                    dev["error"] = first_error
                    return dev
        for nsid in self._nsids(path):
            try:
                r = self._query(path, nsid)
                dev.setdefault("mode", r.get("mode"))
                dev["namespaces"] += r.get("namespaces", [])
            except QmpError as e:
                if "is not attached" in e.desc:
                    self.known.pop(path, None)
                    if not self.nsids:
                        continue
                dev["namespaces"].append({"nsid": nsid, "error": e.desc})
        if not dev["namespaces"] and first_error:
            dev["error"] = first_error
        return dev

    def sample(self) -> Dict[str, Any]:
        devices = {}
        for path in self.paths:
            dev = self._device(path)
            try:
                dev["stages"] = self.qmp.execute("query-femu-stages",
                                                 {"path": path})
            except QmpError as e:
                dev["stages-error"] = e.desc
            devices[path] = dev
        return {"time": time.time(), "mono": time.monotonic(),
                "devices": devices}


# --------------------------------------------------------------------------
# Report: one sample against the one before it

def percentile(buckets: List[int], p: float) -> Optional[Tuple[int, Optional[int]]]:
    """The bucket that holds percentile p (0 to 1) of the commands: its
    lowest and highest time in ns, highest None for the last bucket, which
    also holds every longer time. None when no command was counted."""
    total = sum(buckets)
    if total <= 0:
        return None
    rank = max(1, math.ceil(p * total))
    seen = 0
    for i, n in enumerate(buckets):
        seen += n
        if seen >= rank:
            if FAULT == "bucket-shift":
                i = min(i + 1, NBUCKETS - 1)
            low = 0 if i == 0 else 1 << i
            high = None if i == NBUCKETS - 1 else (1 << (i + 1)) - 1
            return low, high
    return None


def stage_report(cur: Dict[str, Any],
                 prev: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Per stage figures over the interval, or since the last reset when
    there is no usable earlier sample."""
    out: Dict[str, Any] = {"window": "interval", "stages": []}
    prev_by = {s["stage"]: s for s in (prev or {}).get("stages", [])}
    use_prev = prev is not None
    for s in cur.get("stages", []):
        p = prev_by.get(s["stage"])
        if p is None or s["count"] < p["count"] or \
                s["sum-ns"] < p["sum-ns"] or s["max-ns"] < p["max-ns"] or any(
                a < b for a, b in zip(s["buckets"], p["buckets"])):
            use_prev = False
    if not use_prev:
        out["window"] = "since-reset"
    for s in cur.get("stages", []):
        p = prev_by.get(s["stage"]) if use_prev else None
        buckets = list(s["buckets"])
        count, total = s["count"], s["sum-ns"]
        if p is not None:
            buckets = [a - b for a, b in zip(buckets, p["buckets"])]
            count -= p["count"]
            total -= p["sum-ns"]
        entry: Dict[str, Any] = {
            "stage": s["stage"], "count": count,
            "mean-ns": total / count if count > 0 else None,
            "max-ns-since-reset": s["max-ns"]}
        for name, q in (("p50", 0.5), ("p99", 0.99)):
            r = percentile(buckets, q)
            high = r[1] if r else None
            if r and (high is None or high > s["max-ns"]) and \
                    s["max-ns"] >= r[0]:
                # no time in the window is above the largest time counted
                high = s["max-ns"]
            entry[f"{name}-ns-low"] = r[0] if r else None
            entry[f"{name}-ns-high"] = high
        out["stages"].append(entry)
    return out


def counter_values(counters: Dict[str, Any]) -> Dict[str, int]:
    """The integer counters of a counters member, known ones first."""
    host_key = "gc-write-pages" if FAULT == "counter-key" else "host-write-pages"
    out: Dict[str, int] = {}
    for key in COUNTER_ORDER:
        src = host_key if key == "host-write-pages" else key
        if src in counters:
            out[key] = counters[src]
        elif key in ZERO_WHEN_ABSENT:
            out[key] = 0
    for key, val in counters.items():
        if key not in out and key != "waf" and isinstance(val, int) \
                and not isinstance(val, bool):
            out[key] = val
    return out


def waf_of(host: int, nand: int, gc: int, pad: int) -> Optional[float]:
    return (nand + gc + pad) / host if host > 0 else None


def namespace_report(ns: Dict[str, Any], prev: Optional[Dict[str, Any]],
                     elapsed: Optional[float]) -> Dict[str, Any]:
    """Everything the namespace reply holds, with interval changes. It goes
    by the members present, so a mode it does not know still shows."""
    out: Dict[str, Any] = {"nsid": ns.get("nsid"), "mode": ns.get("mode")}
    if "error" in ns:
        out["error"] = ns["error"]
        return out
    if isinstance(ns.get("counters"), dict):
        cur = counter_values(ns["counters"])
        old = counter_values(prev["counters"]) \
            if prev and isinstance(prev.get("counters"), dict) else None
        baseline = "ok" if old is not None else "new"
        if old is not None and any(cur[k] < old.get(k, 0) for k in cur):
            baseline, old = "reset", None
        if FAULT == "no-interval" and old is not None:
            old = {k: 0 for k in cur}
        counters = {}
        for k, v in cur.items():
            d = v - old.get(k, 0) if old is not None else None
            counters[k] = {"total": v, "interval": d}
            if d is not None and elapsed:
                counters[k]["per-s"] = d / elapsed
        out["counters"] = counters
        out["baseline"] = baseline
        out["waf"] = ns["counters"].get("waf")

        def get(k: str, which: str) -> int:
            return (counters.get(k) or {}).get(which) or 0
        out["interval-waf"] = None if old is None else waf_of(
            get("host-write-pages", "interval"),
            get("nand-write-pages", "interval"),
            get("gc-write-pages", "interval"),
            get("pad-write-pages", "interval"))
    for key in ("geometry", "line-counts", "zone-counts"):
        if isinstance(ns.get(key), dict):
            out[key] = ns[key]
    for key in ("lba-size", "zone-size", "zone-capacity", "max-open",
                "max-active"):
        if key in ns:
            out[key] = ns[key]
    if isinstance(ns.get("fdp"), dict):
        out["fdp"] = fdp_report(ns["fdp"], prev.get("fdp") if prev else None)
    if isinstance(ns.get("media"), dict):
        out["media"] = media_summary(ns["media"])
    if isinstance(ns.get("lsm"), dict):
        out["lsm"] = lsm_report(ns["lsm"], prev.get("lsm") if prev else None)
    if isinstance(ns.get("pack"), dict):
        out["pack"] = pack_report(ns["pack"],
                                  prev.get("pack") if prev else None)
    other = {k: v for k, v in ns.items()
             if k not in ("nsid", "mode", "counters", "geometry",
                          "line-counts", "zone-counts", "fdp", "media",
                          "lines", "zones", "offset", "next-offset",
                          "lba-size", "zone-size", "zone-capacity",
                          "max-open", "max-active")
             and isinstance(v, (int, float, str, bool))}
    if other:
        out["other"] = other
    return out


def fdp_report(fdp: Dict[str, Any],
               prev: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {k: fdp[k] for k in ("reclaim-groups", "groups",
                                               "units-per-group",
                                               "pages-per-unit", "unit-counts",
                                               "placement-handles", "ftl-nsid")
                           if k in fdp}
    if FAULT == "phl-skip":
        out.pop("placement-handles", None)
    if FAULT == "groups-skip":
        out.pop("groups", None)
    old = {h["id"]: h for h in (prev or {}).get("handles", [])}
    handles = []
    for h in fdp.get("handles", []):
        entry = {"id": h.get("id"), "type": h.get("type"),
                 "host-bytes": h.get("host-bytes"),
                 "media-bytes": h.get("media-bytes")}
        o = old.get(h.get("id"))
        if o is not None and h["host-bytes"] >= o["host-bytes"] \
                and h["media-bytes"] >= o["media-bytes"]:
            dh = h["host-bytes"] - o["host-bytes"]
            dm = h["media-bytes"] - o["media-bytes"]
            entry["interval-host-bytes"] = dh
            entry["interval-media-bytes"] = dm
            entry["interval-waf"] = dm / dh if dh else None
        handles.append(entry)
    out["handles"] = handles
    return out


LSM_COUNTERS = ("flushes", "compactions", "dropped-records",
                "reinserted-keys", "probe-read-pages", "scan-read-pages",
                "compaction-read-pages", "compaction-program-pages",
                "gc-read-pages", "gc-meta-pages", "gc-stale-value-pages")


def lsm_report(lsm: Dict[str, Any],
               prev: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """The LSM index of a kv_index=lsm namespace: its shape, and each
    counter with its change since the sample before."""
    out = {k: v for k, v in lsm.items()
           if k not in LSM_COUNTERS and k != "levels"}
    out["levels"] = [dict(lv) for lv in lsm.get("levels", [])]
    counters = {}
    for k in LSM_COUNTERS:
        if k not in lsm:
            continue
        old = prev.get(k) if prev and FAULT != "lsm-no-prev" else None
        d = lsm[k] - old if old is not None and lsm[k] >= old else None
        counters[k] = {"total": lsm[k], "interval": d}
    out["counters"] = counters
    return out


def lsm_text(lsm: Dict[str, Any], pad: str) -> List[str]:
    lines = [pad + f"lsm: memtable {lsm.get('memtable-keys')}/"
             f"{lsm.get('memtable-capacity')}, ratio {lsm.get('size-ratio')}, "
             f"pinned {lsm.get('pinned-levels')}, device DRAM "
             f"{fmt_bytes(lsm.get('device-dram-bytes'))}, meta flash "
             f"{fmt_bytes(lsm.get('meta-flash-bytes'))}"]
    levels = lsm.get("levels", [])
    if levels:
        lines.append(pad + "levels: " + ", ".join(
            f"L{lv['level']} {lv['records']} rec {lv['pages']} pg"
            + (" pinned" if lv.get("pinned") else "") for lv in levels))
    cs = lsm.get("counters", {})
    if cs:
        lines.append(pad + "lsm counters: " + "  ".join(
            f"{k} {c['total']}"
            + (f" (+{c['interval']})" if c.get("interval") is not None
               else "") for k, c in cs.items()))
    return lines


PACK_COUNTERS = ("packed-pages", "packed-values", "pad-bytes",
                 "early-programs", "dropped-pages", "buffer-reads",
                 "gc-moved-values", "gc-stale-values", "host-bytes")


def pack_report(pack: Dict[str, Any],
                prev: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """The value packing of a kvssd namespace: the open page and the
    packed pages now, and each counter with its change since the sample
    before."""
    out = {k: v for k, v in pack.items() if k not in PACK_COUNTERS}
    counters = {}
    for k in PACK_COUNTERS:
        if k not in pack:
            continue
        old = prev.get(k) if prev and FAULT != "pack-no-prev" else None
        d = pack[k] - old if old is not None and pack[k] >= old else None
        counters[k] = {"total": pack[k], "interval": d}
    out["counters"] = counters
    return out


def pack_text(pack: Dict[str, Any], pad: str) -> List[str]:
    lines = [pad + f"pack: open page {pack.get('open-values')} values "
             f"{fmt_bytes(pack.get('open-bytes'))}, flash "
             f"{pack.get('flash-pages')} pages "
             f"{fmt_bytes(pack.get('flash-live-bytes'))} live, header "
             f"{pack.get('record-header-bytes')} B"]
    cs = pack.get("counters", {})
    if cs:
        lines.append(pad + "pack counters: " + "  ".join(
            f"{k} {c['total']}"
            + (f" (+{c['interval']})" if c.get("interval") is not None
               else "") for k, c in cs.items()))
    return lines


def media_summary(m: Dict[str, Any]) -> Dict[str, Any]:
    """The few media timing members that tell the bus models apart."""
    keys = ("staged-bus", "onfi-profile", "onfi-mode", "sca", "cache-read",
            "page-transfer-ns", "read-command-ns", "program-command-ns",
            "erase-command-ns", "status-ns")
    return {k: m[k] for k in keys if k in m}


def build_report(cur: Dict[str, Any],
                 prev: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    elapsed = cur["mono"] - prev["mono"] if prev else None
    report: Dict[str, Any] = {
        "time": time.strftime("%Y-%m-%dT%H:%M:%S",
                              time.localtime(cur["time"])),
        "elapsed-s": elapsed, "devices": []}
    for path, dev in cur["devices"].items():
        pdev = prev["devices"].get(path) if prev else None
        d: Dict[str, Any] = {"path": path, "mode": dev.get("mode")}
        if "error" in dev:
            d["error"] = dev["error"]
        pns = {ns.get("nsid"): ns for ns in (pdev or {}).get("namespaces", [])}
        d["namespaces"] = [namespace_report(ns, pns.get(ns.get("nsid")), elapsed)
                           for ns in dev.get("namespaces", [])]
        if "stages" in dev:
            pst = pdev.get("stages") if pdev else None
            d["stages"] = stage_report(dev["stages"], pst)
        else:
            d["stages-error"] = dev.get("stages-error")
        report["devices"].append(d)
    return report


# --------------------------------------------------------------------------
# Text view

def fmt_ns(ns: Optional[float]) -> str:
    if ns is None:
        return "-"
    for unit, scale in (("s", 1e9), ("ms", 1e6), ("us", 1e3)):
        if ns >= scale:
            return f"{ns / scale:.1f}{unit}"
    return f"{ns:.0f}ns"


def fmt_rate(v: Optional[float]) -> str:
    return "-" if v is None else f"{v:.1f}"


def fmt_bytes(n: Optional[int]) -> str:
    if n is None:
        return "-"
    for unit, scale in (("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)):
        if n >= scale:
            return f"{n / scale:.1f}{unit}"
    return f"{n}B"


def fmt_pct(low: Optional[int], high: Optional[int]) -> str:
    if low is None:
        return "-"
    if high is None:
        return ">=" + fmt_ns(low)
    return "<=" + fmt_ns(high)


def media_text(m: Dict[str, Any]) -> str:
    if not m.get("staged-bus"):
        bus = "bus phases not charged"
    else:
        bus = "bus phases charged"
    parts = [bus]
    if m.get("onfi-profile"):
        parts.append(f"ONFI mode {m.get('onfi-mode')}")
    if m.get("sca"):
        parts.append("SCA")
    if m.get("cache-read"):
        parts.append("cache read")
    if m.get("staged-bus"):
        parts.append(f"page transfer {fmt_ns(m.get('page-transfer-ns'))}")
        parts.append(f"read command {fmt_ns(m.get('read-command-ns'))}")
        parts.append(f"program command {fmt_ns(m.get('program-command-ns'))}")
    return ", ".join(parts)


def namespace_text(ns: Dict[str, Any]) -> List[str]:
    head = f"  ns {ns.get('nsid')} {ns.get('mode') or '?'}"
    if "error" in ns:
        return [f"{head}: {ns['error']}"]
    pad = " " * 4
    lines = [head]
    counters = ns.get("counters")
    if counters:
        names = [(SHORT.get(k, k), c) for k, c in counters.items()]
        lines.append(pad + "total:    " + "  ".join(
            f"{n} {c['total']}" for n, c in names))
        if any(c.get("interval") is not None for _, c in names):
            rates = [f"{n} {c['per-s']:.1f}/s" for n, c in names
                     if "per-s" in c and n not in ("nand", "pad")]
            lines.append(pad + "interval: " + "  ".join(
                f"{n} +{c['interval']}" for n, c in names)
                + (f"  ({', '.join(rates)})" if rates else ""))
        waf = ns.get("waf")
        iwaf = ns.get("interval-waf")
        extra = " (counters went down: new baseline)" \
            if ns.get("baseline") == "reset" else ""
        lines.append(pad + "WAF: " + ("-" if waf is None else f"{waf:.3f}")
                     + " since start, "
                     + ("-" if iwaf is None else f"{iwaf:.3f}")
                     + " interval" + extra)
    lc = ns.get("line-counts")
    if lc:
        lines.append(pad + f"lines: free {lc.get('free')} of {lc.get('total')}"
                     f", victim {lc.get('victim')}, full {lc.get('full')}"
                     f", retired {lc.get('retired')}, spare {lc.get('spare')}"
                     + (f", reserve {lc['reserve']}" if "reserve" in lc
                        else ""))
    fdp = ns.get("fdp")
    if fdp:
        uc = fdp.get("unit-counts", {})
        lines.append(pad + f"reclaim units: free {uc.get('free')} of "
                     f"{uc.get('total')}, open {uc.get('open')}, "
                     f"victim {uc.get('victim')}, full {uc.get('full')}")
        # a reclaim group is a set of dies: whole channels or LUNs of one
        groups = fdp.get("groups", [])
        if len(groups) > 1:
            for g in groups:
                c0, l0 = g["first-channel"], g["first-lun"]
                lines.append(pad + f"reclaim group {g['id']}: channels "
                             f"{c0}-{c0 + g['channels'] - 1}, LUNs "
                             f"{l0}-{l0 + g['luns'] - 1}, free units "
                             f"{g['free-units']}")
        phl = fdp.get("placement-handles")
        if phl is not None:
            # every FDP namespace of a controller shares one FTL
            owner = fdp.get("ftl-nsid")
            lines.append(pad + "placement handles: "
                         + ", ".join(f"{i}->RUH {h}" for i, h in enumerate(phl))
                         + (f" (FTL and counters of namespace {owner})"
                            if owner not in (None, ns.get("nsid")) else ""))
        for h in fdp.get("handles", []):
            s = (f"handle {h['id']}: host {fmt_bytes(h['host-bytes'])}, "
                 f"media {fmt_bytes(h['media-bytes'])}")
            if "interval-host-bytes" in h:
                w = h.get("interval-waf")
                s += (f", interval +{fmt_bytes(h['interval-host-bytes'])}"
                      f" WAF {'-' if w is None else f'{w:.3f}'}")
            lines.append(pad + s)
    zc = ns.get("zone-counts")
    if zc:
        order = ("empty", "implicitly-open", "explicitly-open", "closed",
                 "full", "read-only", "offline")
        lines.append(pad + "zones: " + ", ".join(
            f"{k} {zc[k]}" for k in order if k in zc)
            + f" of {zc.get('total')}; max open {ns.get('max-open')}"
            f", max active {ns.get('max-active')}")
    if ns.get("other"):
        lines.append(pad + "other: " + ", ".join(
            f"{k} {v}" for k, v in ns["other"].items()))
    if ns.get("lsm"):
        lines += lsm_text(ns["lsm"], pad)
    if ns.get("pack"):
        lines += pack_text(ns["pack"], pad)
    if ns.get("media"):
        lines.append(pad + "media: " + media_text(ns["media"]))
    return lines


def stages_text(st: Dict[str, Any]) -> List[str]:
    title = ("interval" if st["window"] == "interval"
             else "since the counts were reset")
    lines = [f"  stages ({title}):",
             f"    {'stage':<11}{'count':>9}{'mean':>10}{'p50':>12}"
             f"{'p99':>12}{'max*':>10}"]
    for s in st["stages"]:
        lines.append(f"    {s['stage']:<11}{s['count']:>9}"
                     f"{fmt_ns(s['mean-ns']):>10}"
                     f"{fmt_pct(s['p50-ns-low'], s['p50-ns-high']):>12}"
                     f"{fmt_pct(s['p99-ns-low'], s['p99-ns-high']):>12}"
                     f"{fmt_ns(s['max-ns-since-reset']):>10}")
    lines.append("    * max since the counts were reset; p50 and p99 are "
                 "bucket bounds")
    return lines


def report_text(report: Dict[str, Any], source: str) -> str:
    el = report["elapsed-s"]
    lines = [f"femu-stat  {report['time']}  "
             + ("first sample, totals since start" if el is None
                else f"interval {el:.2f} s") + f"  {source}"]
    if not report["devices"]:
        lines.append("no femu device")
    for d in report["devices"]:
        lines.append(f"{d['path']}  {d.get('mode') or ''}".rstrip())
        if "error" in d:
            lines.append(f"  query-femu: {d['error']}")
        for ns in d["namespaces"]:
            lines += namespace_text(ns)
        if "stages" in d:
            lines += stages_text(d["stages"])
        elif d.get("stages-error"):
            lines.append(f"  stages: {d['stages-error']}")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# qtest harness: QEMU without a guest, driven over the qtest protocol

class Qtest:
    """The qtest text protocol: one command per line, "OK ..." back."""

    def __init__(self, sock: socket.socket, timeout: float = 30.0):
        sock.settimeout(timeout)
        self.file = sock.makefile("rw")
        self.sock = sock

    def cmd(self, line: str) -> List[str]:
        self.file.write(line + "\n")
        self.file.flush()
        while True:
            reply = self.file.readline()
            if not reply:
                raise ToolError(f"qtest connection closed after {line!r}")
            words = reply.split()
            if words and words[0] == "IRQ":
                continue
            if not words or words[0] != "OK":
                raise ToolError(f"qtest {line!r} failed: {reply.strip()}")
            return words[1:]

    def outl(self, port: int, val: int) -> None:
        self.cmd(f"outl 0x{port:x} 0x{val:x}")

    def inl(self, port: int) -> int:
        return int(self.cmd(f"inl 0x{port:x}")[0], 16)

    def writel(self, addr: int, val: int) -> None:
        self.cmd(f"writel 0x{addr:x} 0x{val:x}")

    def writeq(self, addr: int, val: int) -> None:
        self.cmd(f"writeq 0x{addr:x} 0x{val:x}")

    def readl(self, addr: int) -> int:
        return int(self.cmd(f"readl 0x{addr:x}")[0], 16)

    def readq(self, addr: int) -> int:
        return int(self.cmd(f"readq 0x{addr:x}")[0], 16)

    def memwrite(self, addr: int, data: bytes) -> None:
        self.cmd(f"write 0x{addr:x} {len(data)} 0x{data.hex()}")

    def memread(self, addr: int, size: int) -> bytes:
        return bytes.fromhex(self.cmd(f"read 0x{addr:x} {size}")[0][2:])

    def memset(self, addr: int, size: int, val: int = 0) -> None:
        self.cmd(f"memset 0x{addr:x} {size} {val}")

    def close(self) -> None:
        try:
            self.file.close()
            self.sock.close()
        except OSError:
            pass


# PCI configuration mechanism 1, as on pc and q35
PCI_ADDR, PCI_DATA = 0xcf8, 0xcfc
MMIO_BASE, MMIO_LIMIT = 0xe0000000, 0xfec00000
NVME_CLASS = 0x010802
QSIZE = 64


class NvmeError(Exception):
    """The controller refused to come ready or failed a command."""


class PciFunction:
    def __init__(self, qt: Qtest, bus: int, slot: int, func: int):
        self.qt, self.bus, self.slot, self.func = qt, bus, slot, func

    def _addr(self, reg: int) -> int:
        return (0x80000000 | (self.bus << 16) | (self.slot << 11)
                | (self.func << 8) | reg)

    def read(self, reg: int) -> int:
        self.qt.outl(PCI_ADDR, self._addr(reg))
        return self.qt.inl(PCI_DATA)

    def write(self, reg: int, val: int) -> None:
        self.qt.outl(PCI_ADDR, self._addr(reg))
        self.qt.outl(PCI_DATA, val)

    @property
    def devfn(self) -> int:
        return (self.slot << 3) | self.func


def scan_bus0(qt: Qtest) -> List[PciFunction]:
    """Every NVMe controller function on PCI bus 0."""
    found = []
    for slot in range(32):
        for func in range(8):
            f = PciFunction(qt, 0, slot, func)
            vid = f.read(0) & 0xffff
            if vid == 0xffff:
                if func == 0:
                    break
                continue
            if f.read(0x08) >> 8 == NVME_CLASS:
                found.append(f)
            if func == 0 and not (f.read(0x0c) >> 16) & 0x80:
                break
    return found


class GuestMemory:
    """A bump allocator over guest RAM: above 1 MiB, or in low memory when
    the machine has less than 4 MiB."""

    def __init__(self, start: int = 0x100000, end: int = 0x4000000):
        self.next, self.end = start, end

    @classmethod
    def of(cls, qmp: QmpClient) -> "GuestMemory":
        ram = qmp.execute("query-memory-size-summary")["base-memory"]
        if ram < 4 << 20:
            return cls(0x20000, min(ram, 0x9f000))
        return cls(0x100000, min(ram, 0x4000000))

    def alloc(self, size: int, align: int = 4096) -> int:
        addr = (self.next + align - 1) & ~(align - 1)
        if addr + size > self.end:
            raise ToolError("the check ran out of guest memory")
        self.next = addr + size
        return addr


class NvmeController:
    """Enough of an NVMe host driver to enable a controller, send admin
    commands, and write pages through one I/O queue pair whose completions
    are polled. It picks the settings a host would: the smallest memory
    page the controller takes and every command set it offers."""

    def __init__(self, qt: Qtest, pci: PciFunction, mem: GuestMemory,
                 mmio_next: List[int]):
        self.qt, self.pci, self.mem = qt, pci, mem
        lo_orig = pci.read(0x10)
        pci.write(0x10, 0xffffffff)
        lo = pci.read(0x10)
        is64 = (lo >> 1) & 3 == 2
        hi = 0xffffffff
        if is64:
            pci.write(0x14, 0xffffffff)
            hi = pci.read(0x14)
        size = ((~(((hi << 32) | (lo & ~0xf)) & 0xffffffffffffffff))
                & 0xffffffffffffffff) + 1
        base = (mmio_next[0] + size - 1) & ~(size - 1)
        if base + size > MMIO_LIMIT:
            raise ToolError("no room to map another NVMe register space")
        mmio_next[0] = base + size
        pci.write(0x10, base | (lo_orig & 0xf))
        if is64:
            pci.write(0x14, 0)
        pci.write(0x04, pci.read(0x04) | 0x6)  # memory space, bus master
        self.regs = base
        self.cap = qt.readq(base)
        self.dstrd = (self.cap >> 32) & 0xf
        self.mpsmin = (self.cap >> 48) & 0xf
        self.page = 1 << (12 + self.mpsmin)
        self.css = 6 if (self.cap >> 37) & 0xff & (1 << 6) else 0
        self.cid = 0
        self.queues: Dict[int, Dict[str, int]] = {}
        self.settings = ""

    def _doorbell(self, qid: int, cq: bool) -> int:
        return self.regs + 0x1000 + (2 * qid + int(cq)) * (4 << self.dstrd)

    def _new_queue(self, qid: int) -> None:
        sq = self.mem.alloc(QSIZE * 64, self.page)
        cq = self.mem.alloc(QSIZE * 16, self.page)
        self.qt.memset(sq, QSIZE * 64)
        self.qt.memset(cq, QSIZE * 16)
        self.queues[qid] = {"sq": sq, "cq": cq, "tail": 0, "head": 0,
                            "phase": 1}

    def enable(self, timeout: float = 10.0) -> None:
        self._new_queue(0)
        q = self.queues[0]
        self.qt.writel(self.regs + 0x24, ((QSIZE - 1) << 16) | (QSIZE - 1))
        self.qt.writeq(self.regs + 0x28, q["sq"])
        self.qt.writeq(self.regs + 0x30, q["cq"])
        cc = (4 << 20) | (6 << 16) | (self.mpsmin << 7) | (self.css << 4) | 1
        self.settings = (f"CC 0x{cc:x} ({self.page} B memory page, "
                         f"command sets {'all' if self.css == 6 else 'NVM'}"
                         f"), admin queues of {QSIZE} entries")
        self.qt.writel(self.regs + 0x14, cc)
        deadline = time.monotonic() + timeout
        while True:
            csts = self.qt.readl(self.regs + 0x1c)
            if csts & 2:
                raise NvmeError("the controller reported a fatal status "
                                f"when enabled with {self.settings}")
            if csts & 1:
                return
            if time.monotonic() > deadline:
                raise NvmeError("the controller did not come ready within "
                                f"{timeout:.0f} s")
            time.sleep(0.001)

    def submit(self, qid: int, cmd: bytearray,
               timeout: float = 10.0) -> Tuple[int, int]:
        """Send one command and wait for its completion. Returns the status
        without the phase bit, and dword 0."""
        q = self.queues[qid]
        cid = self.cid
        self.cid = (self.cid + 1) & 0xffff
        struct.pack_into("<H", cmd, 2, cid)
        self.qt.memwrite(q["sq"] + q["tail"] * 64, bytes(cmd))
        q["tail"] = (q["tail"] + 1) % QSIZE
        self.qt.writel(self._doorbell(qid, False), q["tail"])
        slot = q["cq"] + q["head"] * 16
        deadline = time.monotonic() + timeout
        while True:
            entry = self.qt.memread(slot, 16)
            if struct.unpack_from("<H", entry, 14)[0] & 1 == q["phase"]:
                # the entry lands field by field: wait until two reads agree
                if self.qt.memread(slot, 16) == entry:
                    break
            if time.monotonic() > deadline:
                raise NvmeError(f"no completion for opcode 0x{cmd[0]:02x} "
                                f"within {timeout:.0f} s")
            time.sleep(0.0005)
        q["head"] = (q["head"] + 1) % QSIZE
        if q["head"] == 0:
            q["phase"] ^= 1
        self.qt.writel(self._doorbell(qid, True), q["head"])
        result = struct.unpack_from("<I", entry, 0)[0]
        got, status = struct.unpack_from("<HH", entry, 12)
        if got != cid:
            raise NvmeError(f"completion for command {got}, expected {cid}")
        return status >> 1, result

    @staticmethod
    def command(opcode: int, nsid: int = 0, prp1: int = 0, cdw10: int = 0,
                cdw11: int = 0, cdw12: int = 0) -> bytearray:
        cmd = bytearray(64)
        cmd[0] = opcode
        struct.pack_into("<I", cmd, 4, nsid)
        struct.pack_into("<Q", cmd, 24, prp1)
        struct.pack_into("<III", cmd, 40, cdw10, cdw11, cdw12)
        return cmd

    def admin(self, opcode: int, **kw: int) -> Tuple[int, int]:
        return self.submit(0, self.command(opcode, **kw))

    def identify(self, cns: int, nsid: int = 0, csi: int = 0) -> Optional[bytes]:
        """One Identify data structure, or None when it is refused."""
        buf = self.mem.alloc(4096, self.page)
        status, _ = self.admin(0x06, nsid=nsid, prp1=buf, cdw10=cns,
                               cdw11=csi << 24)
        if status & 0x7ff:
            return None
        return self.qt.memread(buf, 4096)

    def create_io_queues(self, qid: int = 1) -> None:
        self._new_queue(qid)
        q = self.queues[qid]
        status, _ = self.admin(0x05, prp1=q["cq"],
                               cdw10=((QSIZE - 1) << 16) | qid, cdw11=1)
        if status & 0x7ff:
            raise NvmeError(f"Create I/O CQ failed with status 0x{status:x}")
        status, _ = self.admin(0x01, prp1=q["sq"],
                               cdw10=((QSIZE - 1) << 16) | qid,
                               cdw11=(qid << 16) | 1)
        if status & 0x7ff:
            raise NvmeError(f"Create I/O SQ failed with status 0x{status:x}")

    def write(self, nsid: int, slba: int, nlb: int, buf: int,
              qid: int = 1) -> int:
        status, _ = self.submit(qid, self.command(0x01, nsid=nsid, prp1=buf,
                                                  cdw10=slba & 0xffffffff,
                                                  cdw11=slba >> 32,
                                                  cdw12=nlb - 1))
        return status & 0x7ff


def no_pin() -> None:
    """Keep the device from pinning its memory backend, as
    check-doc-examples.py does: the check needs no stable latency."""
    import resource
    _, hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)
    low = 64 * 1024 if hard == resource.RLIM_INFINITY else min(64 * 1024,
                                                                  hard)
    resource.setrlimit(resource.RLIMIT_MEMLOCK, (low, low))


class QemuUnderQtest:
    """qemu-system-x86_64 under -accel qtest with no guest. QMP and qtest
    connect to sockets this process listens on, as libqtest does; with
    qmp_server, QEMU also serves QMP on its own socket for another client.

      this process --listen--> qtest.sock <--connect-- QEMU
      this process --listen--> qmp.sock   <--connect-- QEMU
      other client --connect-> qmp-server.sock <--listen-- QEMU
    """

    def __init__(self, qemu: str, args: List[str], tmpdir: str,
                 qmp_server: bool = False, timeout: float = 30.0):
        self.tmpdir = tmpdir
        qt_path = os.path.join(tmpdir, "qtest.sock")
        qmp_path = os.path.join(tmpdir, "qmp.sock")
        self.server_path = os.path.join(tmpdir, "qmp-server.sock")
        listeners = []
        for path in (qt_path, qmp_path):
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.bind(path)
            s.listen(1)
            s.settimeout(0.2)
            listeners.append(s)
        argv = [qemu] + args + [
            "-accel", "qtest", "-nodefaults", "-display", "none",
            "-qtest", f"unix:{qt_path}", "-qtest-log", "/dev/null",
            "-chardev", f"socket,path={qmp_path},id=femu-check-qmp",
            "-mon", "chardev=femu-check-qmp,mode=control"]
        if qmp_server:
            argv += ["-qmp", f"unix:{self.server_path},server=on,wait=off"]
        self.argv = argv
        self.stderr_path = os.path.join(tmpdir, "stderr.txt")
        self.stderr_file = open(self.stderr_path, "w")
        self.qt: Optional[Qtest] = None
        self.qmp: Optional[QmpClient] = None
        self.proc: Optional[subprocess.Popen] = None
        try:
            self._start(argv, listeners, timeout)
        except BaseException:
            for s in listeners:
                s.close()
            self.close()
            raise

    def _start(self, argv: List[str], listeners: List[socket.socket],
               timeout: float) -> None:
        try:
            self.proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                         stdout=subprocess.DEVNULL,
                                         stderr=self.stderr_file,
                                         preexec_fn=no_pin)
        except (OSError, subprocess.SubprocessError) as e:
            raise ToolError(f"cannot run {argv[0]}: {e}")
        conns: List[Optional[socket.socket]] = [None, None]
        deadline = time.monotonic() + timeout
        try:
            while None in conns:
                for i, s in enumerate(listeners):
                    if conns[i] is None:
                        try:
                            conns[i] = s.accept()[0]
                        except socket.timeout:
                            pass
                if None in conns and self.proc.poll() is not None:
                    break
                if time.monotonic() > deadline:
                    raise ToolError(f"QEMU did not connect within {timeout} s")
        finally:
            for s in listeners:
                s.close()
        if None in conns:
            for c in conns:
                if c is not None:
                    c.close()
            self.exited = True
            return
        self.exited = False
        self.qt = Qtest(conns[0], timeout)
        try:
            self.qmp = QmpClient(conns[1], timeout)
        except ToolError:
            # QEMU connects before it realizes the devices, and closes when
            # realize fails
            conns[1].close()
            self.exited = True

    def wait_exit(self, timeout: float = 30.0) -> int:
        try:
            return self.proc.wait(timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            return self.proc.wait()

    def stderr(self) -> str:
        if not self.stderr_file.closed:
            self.stderr_file.flush()
        with open(self.stderr_path) as f:
            return f.read()

    def close(self) -> None:
        if self.proc is None:
            self.stderr_file.close()
            return
        if self.qmp is not None and self.proc.poll() is None:
            try:
                self.qmp.execute("quit")
            except (QmpError, ToolError):
                pass
        for c in (self.qmp, self.qt):
            if c is not None:
                c.close()
        if self.proc.poll() is None and self.qmp is None:
            self.proc.kill()
        if self.proc.poll() is None:
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.stderr_file.close()


def enable_bus0(qmp: QmpClient, qt: Qtest, mem: GuestMemory
                ) -> Tuple[Dict[str, NvmeController], List[str]]:
    """Enable every femu controller on PCI bus 0. Returns the controllers by
    QOM path, and the femu devices it could not reach."""
    funcs = {f.devfn: f for f in scan_bus0(qt)}
    mmio_next = [MMIO_BASE]
    ctrls: Dict[str, NvmeController] = {}
    missed = []
    for path in find_devices(qmp):
        bus = qmp.execute("qom-get", {"path": path, "property": "parent_bus"})
        devfn = qmp.execute("qom-get", {"path": path, "property": "addr"})
        if not re.fullmatch(r"/machine/(i440fx|q35)/pcie?\.0", str(bus)) \
                or devfn not in funcs:
            missed.append(path)
            continue
        ctrl = NvmeController(qt, funcs[devfn], mem, mmio_next)
        ctrl.enable()
        ctrls[path] = ctrl
    return ctrls, missed


# --------------------------------------------------------------------------
# Self-test

class SelfTest:
    def __init__(self, qemu: str):
        self.qemu = qemu
        self.failed: List[str] = []
        self.passed = 0

    def check(self, name: str, ok: bool, detail: str = "") -> bool:
        print(f"{'ok  ' if ok else 'FAIL'} {name}"
              + ("" if ok or not detail else f": {detail}"))
        if ok:
            self.passed += 1
        else:
            self.failed.append(name)
        return ok

    def control(self, name: str, fault: str, run) -> None:
        """Plant a fault and require the check it targets to fail."""
        global FAULT
        FAULT = fault
        try:
            caught = not run()
        except Exception as e:  # a crash counts as caught, but say so
            caught = True
            print(f"     ({fault} raised {type(e).__name__}: {e})")
        finally:
            FAULT = ""
        self.check(f"control {name}: the check fails with {fault}", caught,
                   "the check still passed")


def write_pages(ctrl: NvmeController, nsid: int, first: int, count: int,
                lba_size: int = 512, page: int = 4096) -> bool:
    """One single-page write command per page, from page `first` on."""
    buf = ctrl.mem.alloc(page, ctrl.page)
    ctrl.qt.memwrite(buf, bytes((i * 7) & 0xff for i in range(page)))
    per = page // lba_size
    return all(ctrl.write(nsid, (first + i) * per, per, buf) == 0
               for i in range(count))


def wait_stage_count(qmp: QmpClient, path: str, want: int,
                     timeout: float = 10.0) -> bool:
    """Stages are counted after the completion is posted, so wait for them."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        st = qmp.execute("query-femu-stages", {"path": path})
        total = [s for s in st["stages"] if s["stage"] == "total"]
        if total and total[0]["count"] >= want:
            return True
        time.sleep(0.01)
    return False


def one_ns(report: Dict[str, Any], nsid: int = 1) -> Dict[str, Any]:
    for d in report["devices"]:
        for ns in d["namespaces"]:
            if ns.get("nsid") == nsid:
                return ns
    return {}


def counter(ns: Dict[str, Any], key: str, which: str) -> Any:
    return ns.get("counters", {}).get(key, {}).get(which)


SMALL_BB = ("femu_mode=1,devsz_mb=32,nchs=2,luns_per_ch=2,blks_per_pl=64,"
            "pgs_per_blk=64")


def selftest_bbssd(t: SelfTest, tmp: str) -> None:
    script = os.path.abspath(__file__)
    q = QemuUnderQtest(t.qemu, ["-machine", "pc", "-device",
                                f"femu,id=femu0,{SMALL_BB},io_stages=on"],
                       tmp, qmp_server=True)
    try:
        if not t.check("bbssd: QEMU starts", not q.exited, q.stderr()):
            return
        ctrls, _ = enable_bus0(q.qmp, q.qt, GuestMemory.of(q.qmp))
        ctrl = ctrls["/machine/peripheral/femu0"]
        ctrl.create_io_queues()
        sampler = Sampler(q.qmp, find_devices(q.qmp))
        t.check("bbssd: 16 pages written", write_pages(ctrl, 1, 0, 16))
        wait_stage_count(q.qmp, "/machine/peripheral/femu0", 16)
        s0 = sampler.sample()
        t.check("bbssd: 48 more pages written", write_pages(ctrl, 1, 16, 48))
        wait_stage_count(q.qmp, "/machine/peripheral/femu0", 64)
        s1 = sampler.sample()

        def counters_ok() -> bool:
            ns = one_ns(build_report(s1, s0))
            return (counter(ns, "host-write-pages", "interval") == 48
                    and counter(ns, "host-write-pages", "total") == 64)
        t.check("bbssd: host pages +48 over the interval, 64 in total",
                counters_ok(), json.dumps(one_ns(build_report(s1, s0)))[:400])
        t.control("host pages", "counter-key", counters_ok)
        t.control("interval", "no-interval", counters_ok)

        rep = build_report(s1, s0)
        ns = one_ns(rep)
        t.check("bbssd: WAF since start and over the interval",
                ns.get("waf") is not None and ns.get("interval-waf") is not None
                and abs(ns["interval-waf"] - waf_of(
                    48, counter(ns, "nand-write-pages", "interval"),
                    counter(ns, "gc-write-pages", "interval"), 0)) < 1e-9,
                str(ns))
        t.check("bbssd: line counts", ns.get("line-counts", {}).get("total") == 64,
                str(ns.get("line-counts")))
        t.check("bbssd: media timing", "staged-bus" in ns.get("media", {}))

        def stages_ok() -> bool:
            st = build_report(s1, s0)["devices"][0]["stages"]
            tot = [s for s in st["stages"] if s["stage"] == "total"][0]
            return (st["window"] == "interval" and tot["count"] == 48
                    and tot["p50-ns-low"] is not None
                    and tot["p50-ns-low"] <= tot["max-ns-since-reset"])
        t.check("bbssd: stage total counts 48 commands over the interval",
                stages_ok(), json.dumps(rep["devices"][0].get("stages"))[:400])
        text = report_text(rep, "self-test")
        t.check("bbssd: text view", all(s in text for s in (
            "ns 1 bbssd", "total:    host 64", "interval: host +48",
            "WAF: 1.000", "lines: free",
            "stages (interval)")), text)

        # the CLI, end to end, on the socket QEMU serves
        env = dict(os.environ)
        proc = subprocess.run([sys.executable, "-I", script, "--json",
                               "--once", q.server_path],
                              capture_output=True, text=True, timeout=60,
                              env=env)
        try:
            cli = json.loads(proc.stdout.splitlines()[0])
            cli_ns = one_ns(cli)
            ok = (proc.returncode == 0
                  and counter(cli_ns, "host-write-pages", "total") == 64
                  and counter(cli_ns, "host-write-pages", "interval") is None)
        except (ValueError, IndexError):
            ok = False
        t.check("bbssd: CLI --once --json", ok,
                f"exit {proc.returncode}: {proc.stdout[:300]}{proc.stderr[:300]}")
        proc = subprocess.run([sys.executable, "-I", script, "--count", "2",
                               "--interval", "0.2", q.server_path],
                              capture_output=True, text=True, timeout=60)
        t.check("bbssd: CLI text, two samples",
                proc.returncode == 0 and proc.stdout.count("femu-stat  ") == 2
                and "first sample" in proc.stdout
                and re.search(r"interval \d+\.\d\d s", proc.stdout)
                and "interval: host +0" in proc.stdout,
                f"exit {proc.returncode}: {proc.stdout[-400:]}{proc.stderr}")
    finally:
        q.close()


def selftest_modes(t: SelfTest, tmp: str) -> None:
    """FDP, ZNS, a nossd and bbssd pair, and a key-value namespace."""
    cases = [
        ("fdp", ["-device", "femu-subsys,id=fdp0,nqn=fdp0,fdp=on,fdp.nruh=4",
                 "-device", f"femu,id=femu0,{SMALL_BB},subsys=fdp0"]),
        ("fdp2", ["-device", "femu-subsys,id=fdp0,nqn=fdp0,fdp=on,fdp.nruh=4",
                  "-device", f"femu,id=femu0,{SMALL_BB},subsys=fdp0,"
                  "namespaces=2,namespace_phls=0:1,,1:2"]),
        # two reclaim groups of one channel each; a group holds the namespace
        ("fdp-rg2", ["-device", "femu-subsys,id=fdp0,nqn=fdp0,fdp=on,"
                     "fdp.nruh=4,fdp.nrg=2",
                     "-device", "femu,id=femu0,femu_mode=1,devsz_mb=16,nchs=2,"
                     "luns_per_ch=2,blks_per_pl=64,pgs_per_blk=64,lba_index=3,"
                     "subsys=fdp0"]),
        ("zns", ["-device", "femu,id=femu0,femu_mode=3,devsz_mb=64"]),
        ("mixed", ["-device", f"femu,id=femu0,{SMALL_BB},namespaces=2,"
                   "namespace_modes=nossd,,bbssd"]),
        ("kvssd", ["-device", "femu,id=femu0,femu_mode=5,devsz_mb=256"]),
        ("kvssd-lsm", ["-device", "femu,id=femu0,femu_mode=5,devsz_mb=64,"
                       "kv_index=lsm,kv_lsm_memtable_keys=16"]),
        ("not-enabled", ["-device", f"femu,id=femu0,{SMALL_BB},namespaces=2,"
                         "namespace_modes=bbssd,,znssd"]),
    ]
    for name, args in cases:
        d = os.path.join(tmp, name)
        os.mkdir(d)
        q = QemuUnderQtest(t.qemu, ["-machine", "pc"] + args, d)
        try:
            if not t.check(f"{name}: QEMU starts", not q.exited, q.stderr()):
                continue
            if name == "not-enabled":
                for nsids in (None, [2]):
                    rep = build_report(Sampler(q.qmp, find_devices(q.qmp),
                                               nsids).sample(), None)
                    t.check(f"not enabled, --ns {nsids}: the zoned namespace "
                            "still shows",
                            one_ns(rep, 2).get("zone-counts", {}).get("total",
                                                                      0) > 0
                            and (nsids or "not enabled" in one_ns(
                                rep, 1).get("error", "")), json.dumps(rep)[:400])
                continue
            ctrls, _ = enable_bus0(q.qmp, q.qt, GuestMemory.of(q.qmp))
            ctrl = ctrls["/machine/peripheral/femu0"]
            ctrl.create_io_queues()
            sampler = Sampler(q.qmp, find_devices(q.qmp))
            s0 = sampler.sample()
            nsid = 2 if name in ("mixed", "fdp2") else 1
            if not name.startswith("kvssd"):
                t.check(f"{name}: 16 pages written",
                        write_pages(ctrl, nsid, 0, 16,
                                    4096 if name == "fdp-rg2" else 512))
            s1 = sampler.sample()
            rep = build_report(s1, s0)
            ns = one_ns(rep, nsid)
            text = report_text(rep, "self-test")
            if name == "fdp":
                h0 = ns.get("fdp", {}).get("handles", [{}])[0]
                t.check("fdp: unit counts and handle 0 bytes over the interval",
                        ns["fdp"].get("unit-counts", {}).get("total", 0) > 0
                        and h0.get("interval-host-bytes") == 16 * 4096
                        and "reclaim units: free" in text, json.dumps(ns)[:400])
            elif name == "fdp2":
                # placement handle 0 of namespace 2 is handle 1
                hs = {h["id"]: h for h in ns.get("fdp", {}).get("handles", [])}
                t.check("fdp2: namespace 2's list, its write on handle 1, "
                        "and the shared FTL",
                        ns.get("fdp", {}).get("placement-handles") == [1, 2]
                        and one_ns(rep, 1).get("fdp", {}).get(
                            "placement-handles") == [0, 1]
                        and hs.get(1, {}).get("interval-host-bytes")
                        == 16 * 4096
                        and hs.get(0, {}).get("interval-host-bytes") == 0
                        and "placement handles: 0->RUH 1, 1->RUH 2 (FTL and "
                            "counters of namespace 1)" in text, text)
                t.control("placement handle list", "phl-skip",
                          lambda: one_ns(build_report(s1, s0), 2).get(
                              "fdp", {}).get("placement-handles") == [1, 2])
            elif name == "fdp-rg2":
                gs = ns.get("fdp", {}).get("groups", [])
                t.check("fdp-rg2: two groups of one channel each, and the 16 "
                        "pages in the report",
                        [(g["first-channel"], g["channels"], g["luns"])
                         for g in gs] == [(0, 1, 2), (1, 1, 2)]
                        and "reclaim group 1: channels 1-1, LUNs 0-1" in text,
                        text)
                t.control("reclaim groups", "groups-skip",
                          lambda: len(one_ns(build_report(s1, s0), 1).get(
                              "fdp", {}).get("groups", [])) == 2)
            elif name == "zns":
                zc = ns.get("zone-counts", {})
                t.check("zns: one zone open after the writes",
                        zc.get("implicitly-open") == 1 and zc.get("total", 0) > 0
                        and "zones: empty" in text, str(zc))
            elif name == "mixed":
                t.check("mixed: nossd namespace 1 shows its error, bbssd "
                        "namespace 2 its counters",
                        "error" in one_ns(rep, 1)
                        and counter(ns, "host-write-pages", "interval") == 16
                        and "ns 1 nossd" not in text and "ns 2 bbssd" in text,
                        text)
                t.control("per-namespace fallback", "skip-fallback",
                          lambda: counter(one_ns(build_report(
                              sampler.sample(), s1), 2),
                              "host-write-pages", "total") == 16)
            elif name == "kvssd":
                t.check("kvssd: media timing and value packing",
                        "media" in ns and "counters" not in ns
                        and "lsm" not in ns and "media: bus" in text
                        and ns.get("pack", {}).get("record-header-bytes")
                        == 32 and "pack: open page 0 values" in text, text)
            elif name == "kvssd-lsm":
                t.check("kvssd with kv_index=lsm: the index line",
                        ns.get("lsm", {}).get("memtable-capacity") == 16
                        and "lsm: memtable 0/16" in text
                        and "media: bus" in text, text)
        finally:
            q.close()


def selftest_synthetic(t: SelfTest) -> None:
    """Replies QEMU does not produce today: a mode and a counter this tool
    does not know, and the edges of the stage buckets."""
    def dev(ns: Dict[str, Any], stages: Optional[Dict[str, Any]] = None,
            mono: float = 0.0) -> Dict[str, Any]:
        d: Dict[str, Any] = {"path": "/x", "mode": "future",
                             "namespaces": [ns]}
        if stages:
            d["stages"] = stages
        return {"time": 0.0, "mono": mono, "devices": {"/x": d}}
    ns0 = {"nsid": 1, "mode": "futuressd", "state": "ready",
           "counters": {"host-write-pages": 10, "nand-write-pages": 10,
                        "gc-write-pages": 0, "block-erases": 0,
                        "read-reclaim-pages": 3}}
    ns1 = json.loads(json.dumps(ns0))
    ns1["counters"].update({"host-write-pages": 20, "nand-write-pages": 25,
                            "read-reclaim-pages": 5, "pad-write-pages": 1})
    rep = build_report(dev(ns1, mono=2.0), dev(ns0))
    text = report_text(rep, "synthetic")
    ns = one_ns(rep)
    t.check("unknown mode and counter: shown, no crash",
            counter(ns, "read-reclaim-pages", "interval") == 2
            and ns.get("other") == {"state": "ready"}
            and "read-reclaim-pages +2" in text
            and "read-reclaim-pages 1.0/s" in text
            and abs(ns["interval-waf"] - 1.6) < 1e-9, text)
    lsm0 = {"nsid": 1, "mode": "kvssd",
            "lsm": {"memtable-keys": 3, "memtable-capacity": 16,
                    "size-ratio": 2, "pinned-levels": 1,
                    "device-dram-bytes": 2048, "meta-flash-bytes": 8192,
                    "levels": [{"level": 1, "records": 32, "pages": 1,
                                "capacity": 32, "pinned": True},
                               {"level": 2, "records": 64, "pages": 2,
                                "capacity": 64, "pinned": False}],
                    "flushes": 6, "probe-read-pages": 10}}
    lsm1 = json.loads(json.dumps(lsm0))
    lsm1["lsm"].update({"flushes": 8, "probe-read-pages": 15})
    def lsm_ok() -> bool:
        lrep = one_ns(build_report(dev(lsm1, mono=2.0), dev(lsm0)))
        ltext = report_text(build_report(dev(lsm1, mono=2.0), dev(lsm0)),
                            "synthetic")
        return (lrep["lsm"]["counters"]["flushes"]["interval"] == 2
                and lrep["lsm"]["counters"]["probe-read-pages"]["interval"]
                == 5 and "L2 64 rec 2 pg" in ltext
                and "flushes 8 (+2)" in ltext
                and "lsm: memtable 3/16" in ltext)
    t.check("kv_index=lsm: levels and counter intervals shown", lsm_ok())
    t.control("lsm counter interval", "lsm-no-prev", lsm_ok)
    pk0 = {"nsid": 1, "mode": "kvssd",
           "pack": {"record-header-bytes": 32, "open-bytes": 264,
                    "open-values": 2, "flash-pages": 3,
                    "flash-live-bytes": 9000, "packed-pages": 3,
                    "host-bytes": 9500}}
    pk1 = json.loads(json.dumps(pk0))
    pk1["pack"].update({"packed-pages": 5, "host-bytes": 16000})
    def pack_ok() -> bool:
        prep = build_report(dev(pk1, mono=2.0), dev(pk0))
        ptext = report_text(prep, "synthetic")
        pc = one_ns(prep)["pack"]["counters"]
        return (pc["packed-pages"]["interval"] == 2
                and pc["host-bytes"]["interval"] == 6500
                and "pack: open page 2 values" in ptext
                and "packed-pages 5 (+2)" in ptext)
    t.check("kv_pack: open page and counter intervals shown", pack_ok())
    t.control("pack counter interval", "pack-no-prev", pack_ok)
    reset = build_report(dev(ns0, mono=4.0), dev(ns1, mono=2.0))
    t.check("counters that go down start a new baseline",
            one_ns(reset).get("baseline") == "reset"
            and counter(one_ns(reset), "host-write-pages", "interval") is None)

    def buckets(**at: int) -> List[int]:
        b = [0] * NBUCKETS
        for k, v in at.items():
            b[int(k[1:])] = v
        return b

    def edges_ok() -> bool:
        return (percentile(buckets(b0=1), 0.5) == (0, 1)
                and percentile(buckets(b10=99, b39=1), 0.99) == (1024, 2047)
                and percentile(buckets(b10=98, b39=2), 0.99) == (1 << 39, None)
                and percentile(buckets(), 0.5) is None)
    t.check("percentile bucket edges: 0 ns, overflow, empty", edges_ok())
    t.control("percentile", "bucket-shift", edges_ok)
    st = {"stages": [{"stage": "total", "count": 4, "sum-ns": 4000,
                      "max-ns": 2000, "buckets": buckets(b9=4)}]}
    st2 = {"stages": [{"stage": "total", "count": 1, "sum-ns": 10,
                       "max-ns": 10, "buckets": buckets(b3=1)}]}
    rep = build_report(dev(ns0, st2, 1.0), dev(ns0, st))
    t.check("stage counts that go down are shown since the reset",
            rep["devices"][0]["stages"]["window"] == "since-reset"
            and rep["devices"][0]["stages"]["stages"][0]["count"] == 1)
    # a reset, then more commands than before, but faster ones
    st3 = {"stages": [{"stage": "total", "count": 5, "sum-ns": 3100,
                       "max-ns": 1100, "buckets": buckets(b9=5)}]}
    rep = build_report(dev(ns0, st3, 1.0), dev(ns0, st))
    t.check("a stage sum that goes down is a reset, never a negative mean",
            rep["devices"][0]["stages"]["window"] == "since-reset"
            and rep["devices"][0]["stages"]["stages"][0]["mean-ns"] == 620)


def self_test(qemu: str) -> int:
    if not os.access(qemu, os.X_OK):
        print(f"femu-stat: {qemu} is not an executable", file=sys.stderr)
        return 2
    t = SelfTest(qemu)
    start = time.monotonic()
    selftest_synthetic(t)
    tmp = tempfile.mkdtemp(prefix="femu-stat-")
    try:
        os.mkdir(os.path.join(tmp, "bbssd"))
        selftest_bbssd(t, os.path.join(tmp, "bbssd"))
        selftest_modes(t, tmp)
    except (ToolError, NvmeError, QmpError) as e:
        t.check("self-test ran to the end", False, str(e))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"femu-stat: self-test {t.passed}/{t.passed + len(t.failed)} in "
          f"{time.monotonic() - start:.1f} s")
    return 1 if t.failed else 0


# --------------------------------------------------------------------------

def parse_ns(text: str) -> List[int]:
    try:
        out = sorted({int(x) for x in text.split(",") if x.strip()})
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a list of nsids")
    if not out or out[0] < 1:
        raise argparse.ArgumentTypeError("nsids start at 1")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        epilog="Exit status: 0 success, 1 self-test failure, 2 usage or "
               "connection error.")
    ap.add_argument("socket", nargs="?",
                    help="QMP socket: a Unix socket path or HOST:PORT")
    ap.add_argument("--interval", type=float, default=1.0,
                    help="seconds between samples (default 1)")
    ap.add_argument("--count", type=int, default=0,
                    help="stop after this many samples (default: run until "
                         "interrupted)")
    ap.add_argument("--once", action="store_true",
                    help="one sample, with totals since start")
    ap.add_argument("--json", action="store_true",
                    help="print one JSON object per sample on one line")
    ap.add_argument("--ns", type=parse_ns,
                    help="comma-separated nsids to show (default all)")
    ap.add_argument("--path", action="append", default=[],
                    help="QOM path of a femu device to show (repeatable; "
                         "default every femu device)")
    ap.add_argument("--self-test", action="store_true",
                    help="start QEMU under qtest and check this tool")
    ap.add_argument("--qemu", help="qemu-system-x86_64 for --self-test")
    args = ap.parse_args()

    if args.self_test:
        if not args.qemu:
            ap.error("--self-test needs --qemu")
        return self_test(args.qemu)
    if not args.socket:
        ap.error("give the QMP socket")
    if args.interval <= 0 or args.count < 0:
        ap.error("--interval must be positive and --count not negative")
    count = 1 if args.once else args.count

    try:
        qmp = QmpClient.connect(args.socket)
        found = find_devices(qmp)
        if not found:
            raise ToolError("no femu device in this QEMU")
        for p in args.path:
            if p not in found:
                raise ToolError(f"no femu device at {p}; femu devices: "
                                + ", ".join(found))
        paths = args.path or found
        sampler = Sampler(qmp, paths, args.ns)
        prev = None
        n = 0
        tty = sys.stdout.isatty() and not args.json and count != 1
        while True:
            t0 = time.monotonic()
            cur = sampler.sample()
            report = build_report(cur, prev)
            if args.json:
                print(json.dumps(report), flush=True)
            else:
                text = report_text(report, args.socket)
                print(("\x1b[H\x1b[2J" + text) if tty else
                      (("\n" if n else "") + text), flush=True)
            prev = cur
            n += 1
            if count and n >= count:
                return 0
            time.sleep(max(0.0, args.interval - (time.monotonic() - t0)))
    except ToolError as e:
        print(f"femu-stat: {e}", file=sys.stderr)
        return 2
    except QmpError as e:
        print(f"femu-stat: QMP error: {e.desc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
