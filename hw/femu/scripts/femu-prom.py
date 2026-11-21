#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Export the FTL counters of a running FEMU VM to Prometheus.

femu-prom.py connects to the QMP socket of a running QEMU, as femu-stat.py
does, and serves the query-femu counters of every femu device in the
Prometheus text format:

  Prometheus --GET /metrics--> femu-prom.py --query-femu {path}--> QEMU
             <--text format--               <--counters, line counts--

Each scrape reads the device again, so the values are as fresh as the
scrape. Counters (pages, erases) are monotonic; WAF and the line counts are
gauges. Each series has the labels device (the QOM path) and nsid.

With --source query-stats, one QMP query-stats call (target femu) gives
the same series for every device, and femu_namespace_generation. That
call does not wait for the FTL thread. It reads a copy that the FTL
thread makes between two requests: about once a millisecond while the
device is busy, and at once when it goes quiet.

  --source query-femu  (default)   one query per device, waits for the FTL
  --source query-stats             one call for all devices, no wait

A namespace that shares the FTL of another (ftl-nsid) gets the series of
that FTL, as query-femu reports them; a sum over namespaces then counts
that FTL more than once. A namespace that query-stats leaves out (its
copy stayed busy) has no series in that scrape, and femu_scrape_errors
does not count it. When femu_namespace_generation changes, the namespace
was created again and its counters started from 0.

Usage:
  femu-prom.py SOCKET [--port 9813] [--bind 127.0.0.1] [--source S]
  femu-prom.py SOCKET --once        # one exposition to stdout
  femu-prom.py --self-test          # render canned replies, no QEMU

SOCKET is a Unix socket path or HOST:PORT of a QMP server, for example
-qmp unix:/tmp/femu-qmp.sock,server=on,wait=off on the QEMU command line.
"""

import argparse
import importlib.machinery
import importlib.util
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

COUNTERS = {
    "host-write-pages": "pages the host wrote",
    "nand-write-pages": "host pages programmed to NAND",
    "gc-write-pages": "pages garbage collection moved",
    "pad-write-pages": "pages programmed with pad data",
    "map-write-pages": "translation pages programmed",
    "map-read-pages": "translation pages read",
    "block-erases": "block erases",
    "idle-write-back-pages": "buffered pages written back while idle",
}
LINES = ("free", "victim", "full", "retired", "spare", "total")


def _load_stat():
    """femu-stat.py, for its QMP client and device discovery."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "femu-stat.py")
    loader = importlib.machinery.SourceFileLoader("femu_stat", path)
    spec = importlib.util.spec_from_loader("femu_stat", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _name(key):
    return "femu_" + key.replace("-", "_")


def render(replies, errors=0):
    """The text exposition of @replies: (device path, query-femu reply).
    @errors counts the namespaces no query could read."""
    out = ["# HELP femu_scrape_errors namespaces this scrape could not read",
           "# TYPE femu_scrape_errors gauge",
           "femu_scrape_errors %d" % errors]
    rows = {}
    for path, reply in replies:
        for ns in reply.get("namespaces", []):
            labels = 'device="%s",nsid="%s"' % (path, ns.get("nsid"))
            ctr = ns.get("counters", {})
            for key in COUNTERS:
                if key in ctr:
                    rows.setdefault(_name(key) + "_total", []).append(
                        "%s{%s} %d" % (_name(key) + "_total", labels,
                                       ctr[key]))
            if "waf" in ctr:
                rows.setdefault("femu_waf", []).append(
                    "femu_waf{%s} %.6f" % (labels, ctr["waf"]))
            if "generation" in ns:
                rows.setdefault("femu_namespace_generation", []).append(
                    "femu_namespace_generation{%s} %d" %
                    (labels, ns["generation"]))
            for key in LINES:
                if key in ns.get("line-counts", {}):
                    rows.setdefault("femu_lines", []).append(
                        'femu_lines{%s,state="%s"} %d' %
                        (labels, key, ns["line-counts"][key]))
    for key, help_text in COUNTERS.items():
        name = _name(key) + "_total"
        if name in rows:
            out.append("# HELP %s %s" % (name, help_text))
            out.append("# TYPE %s counter" % name)
            out.extend(rows[name])
    if "femu_waf" in rows:
        out.append("# HELP femu_waf write amplification since the start")
        out.append("# TYPE femu_waf gauge")
        out.extend(rows["femu_waf"])
    if "femu_namespace_generation" in rows:
        out.append("# HELP femu_namespace_generation changes when the "
                   "namespace is created again")
        out.append("# TYPE femu_namespace_generation gauge")
        out.extend(rows["femu_namespace_generation"])
    if "femu_lines" in rows:
        out.append("# HELP femu_lines lines in each state")
        out.append("# TYPE femu_lines gauge")
        out.extend(rows["femu_lines"])
    return "\n".join(out) + "\n"


# the parts of the query-femu WAF: media pages over host pages
WAF_PARTS = ("nand-write-pages", "gc-write-pages", "map-write-pages",
             "pad-write-pages", "parity-write-pages")


def from_stats(results):
    """The query-femu shaped replies of a query-stats @results list. WAF
    comes from the raw page counts with the query-femu formula, so both
    sources give the same text."""
    devices = {}
    for res in results:
        if res.get("provider") != "femu":
            continue
        vals = {st["name"]: st["value"] for st in res.get("stats", [])}
        nsid = vals.get("nsid", 0)
        if not nsid:
            continue        # the controller: no namespace series
        ctr = {k: vals[k] for k in COUNTERS if k in vals}
        host = vals.get("host-write-pages", 0)
        if host:
            ctr["waf"] = float(sum(vals.get(k, 0) for k in WAF_PARTS)) / host
        lines = {k: vals[k + "-lines"] for k in LINES if k + "-lines" in vals}
        ns = {"nsid": nsid, "counters": ctr, "ftl-nsid": vals.get("ftl-nsid")}
        if "generation" in vals:
            ns["generation"] = vals["generation"]
        if lines:
            ns["line-counts"] = lines
        devices.setdefault(res.get("qom-path"), {})[nsid] = ns
    replies = []
    for path, nss in devices.items():
        out = []
        for nsid in sorted(nss):
            ns = nss[nsid]
            owner = nss.get(ns.pop("ftl-nsid"))
            if owner:       # a shared FTL: the series of its owner
                ns["counters"] = owner["counters"]
                if "line-counts" in owner:
                    ns["line-counts"] = owner["line-counts"]
            out.append(ns)
        replies.append((path, {"namespaces": out}))
    return replies


def scrape_stats(stat, address):
    """One query-stats call for every device."""
    qmp = stat.QmpClient.connect(address)
    try:
        results = qmp.execute("query-stats", {
            "target": "femu", "providers": [{"provider": "femu"}]})
        return render(from_stats(results))
    finally:
        qmp.close()


def scrape(stat, address):
    """One query per device; when one namespace cannot be read (a NoSSD
    namespace, say), one query per namespace instead, as femu-stat.py
    does, so the others still appear."""
    qmp = stat.QmpClient.connect(address)
    errors = 0
    try:
        replies = []
        for path in stat.find_devices(qmp):
            try:
                replies.append((path, qmp.execute("query-femu",
                                                  {"path": path})))
                continue
            except stat.QmpError:
                pass
            merged = {"namespaces": []}
            for nsid in range(1, stat.MAX_NSID + 1):
                try:
                    r = qmp.execute("query-femu", {"path": path,
                                                   "nsid": nsid})
                except stat.QmpError as e:
                    if "is not attached" not in e.desc:
                        errors += 1
                    continue
                merged["namespaces"].extend(r.get("namespaces", []))
            replies.append((path, merged))
        return render(replies, errors)
    finally:
        qmp.close()


def self_test():
    reply = {"namespaces": [{
        "nsid": 1,
        "counters": {"host-write-pages": 30, "nand-write-pages": 32,
                     "gc-write-pages": 8, "block-erases": 3,
                     "waf": 40.0 / 30},
        "line-counts": {"free": 10, "victim": 1, "full": 2, "retired": 0,
                        "spare": 0, "total": 13}}]}
    text = render([("/machine/peripheral/femu0", reply)])
    want = ['femu_host_write_pages_total{device="/machine/peripheral/femu0",'
            'nsid="1"} 30',
            "# TYPE femu_nand_write_pages_total counter",
            'femu_waf{device="/machine/peripheral/femu0",nsid="1"} 1.333333',
            'femu_lines{device="/machine/peripheral/femu0",nsid="1",'
            'state="free"} 10']
    for w in want:
        assert w in text, (w, text)
    assert "femu_pad_write_pages_total" not in text, text
    assert "femu_idle_write_back_pages_total" not in text, text
    assert "femu_scrape_errors 0" in text, text

    # the same namespace through query-stats gives the same text
    path = "/machine/peripheral/femu0"
    results = [
        {"provider": "femu", "qom-path": path, "stats": [
            {"name": "nsid", "value": 0},
            {"name": "host-write-commands", "value": 7}]},
        {"provider": "femu", "qom-path": path, "stats": [
            {"name": "nsid", "value": 1},
            {"name": "generation", "value": 0},
            {"name": "page-size", "value": 4096},
            {"name": "host-write-pages", "value": 30},
            {"name": "nand-write-pages", "value": 32},
            {"name": "gc-write-pages", "value": 8},
            {"name": "block-erases", "value": 3},
            {"name": "waf", "value": 1333}]
            + [{"name": k + "-lines", "value": v} for k, v in
               reply["namespaces"][0]["line-counts"].items()]},
        {"provider": "kvm", "stats": [{"name": "nsid", "value": 9}]}]
    got = render(from_stats(results))
    gen = 'femu_namespace_generation{device="%s",nsid="1"} 0' % path
    assert gen in got, got

    def strip(t):
        return "\n".join(x for x in t.split("\n")
                         if "femu_namespace_generation" not in x)
    assert strip(got) == text, (got, text)

    # a second namespace on the same FTL gets the series of namespace 1
    shared = dict(reply["namespaces"][0], nsid=2)
    text2 = render([(path, {"namespaces": [reply["namespaces"][0], shared]})])
    results.insert(2, {"provider": "femu", "qom-path": path, "stats": [
        {"name": "nsid", "value": 2}, {"name": "page-size", "value": 4096},
        {"name": "ftl-nsid", "value": 1},
        {"name": "ns-host-write-pages", "value": 5}]})
    got = render(from_stats(results))
    assert strip(got) == text2, (got, text2)
    for idle in (24, 0):
        reply["namespaces"][0]["counters"]["idle-write-back-pages"] = idle
        text = render([("/machine/peripheral/femu0", reply)])
        w = ('femu_idle_write_back_pages_total{device="/machine/peripheral/'
             'femu0",nsid="1"} %d' % idle)
        assert w in text, (w, text)
    print("femu-prom: self-test passed")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("socket", nargs="?")
    ap.add_argument("--port", type=int, default=9813)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--source", choices=("query-femu", "query-stats"),
                    default="query-femu")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        self_test()
        return 0
    if not args.socket:
        ap.error("SOCKET is required")
    stat = _load_stat()
    read = scrape_stats if args.source == "query-stats" else scrape
    if args.once:
        sys.stdout.write(read(stat, args.socket))
        return 0

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != "/metrics":
                self.send_error(404)
                return
            try:
                body = read(stat, args.socket).encode()
            except Exception as e:  # report and keep serving
                self.send_error(503, str(e))
                return
            self.send_response(200)
            self.send_header("Content-Type",
                             "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    HTTPServer((args.bind, args.port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
