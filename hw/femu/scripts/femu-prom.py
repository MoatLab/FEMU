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

Usage:
  femu-prom.py SOCKET [--port 9813] [--bind 127.0.0.1]
  femu-prom.py SOCKET --once        # one exposition to stdout
  femu-prom.py --self-test          # render a canned reply, no QEMU

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
    if "femu_lines" in rows:
        out.append("# HELP femu_lines lines in each state")
        out.append("# TYPE femu_lines gauge")
        out.extend(rows["femu_lines"])
    return "\n".join(out) + "\n"


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
        "counters": {"host-write-pages": 40, "nand-write-pages": 48,
                     "gc-write-pages": 8, "block-erases": 3, "waf": 1.4},
        "line-counts": {"free": 10, "victim": 1, "full": 2, "retired": 0,
                        "spare": 0, "total": 13}}]}
    text = render([("/machine/peripheral/femu0", reply)])
    want = ['femu_host_write_pages_total{device="/machine/peripheral/femu0",'
            'nsid="1"} 40',
            "# TYPE femu_nand_write_pages_total counter",
            'femu_waf{device="/machine/peripheral/femu0",nsid="1"} 1.400000',
            'femu_lines{device="/machine/peripheral/femu0",nsid="1",'
            'state="free"} 10']
    for w in want:
        assert w in text, (w, text)
    assert "femu_pad_write_pages_total" not in text, text
    assert "femu_scrape_errors 0" in text, text
    print("femu-prom: self-test passed")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("socket", nargs="?")
    ap.add_argument("--port", type=int, default=9813)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        self_test()
        return 0
    if not args.socket:
        ap.error("SOCKET is required")
    stat = _load_stat()
    if args.once:
        sys.stdout.write(scrape(stat, args.socket))
        return 0

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != "/metrics":
                self.send_error(404)
                return
            try:
                body = scrape(stat, args.socket).encode()
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
