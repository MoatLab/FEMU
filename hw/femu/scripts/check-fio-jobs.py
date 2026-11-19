#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check that each fio job under hw/femu/scripts/fio has a fixed rate limit.

The job files there give a workload shape for a study of the SSD model.
They do not measure the speed of the emulator, so no job may run
unthrottled. For each job, and for each direction that its rw= option
uses (read, write, trim), this check needs a "rate" or "rate_iops" value
above zero. An option of a [global] section counts for the jobs after it,
and an empty field of "rate=,8m" keeps the value from before, as in fio.

This is a policy for the files of this folder, stricter than fio. The
check also fails:
  - a limit that is not a plain number with an optional k, m or g, or
    that is too large for fio (fio then wraps it to zero);
  - "rate" and "rate_iops" together in one job: fio refuses the pair;
  - "rate_iops" as the only limit of a job with mixed request sizes
    (bssplit, bsrange): an old fio then counts bytes of the smallest
    size, so the limit is not a command rate;
  - "include", and the replay options (read_iolog, replay_*): the first
    can change a limit from another file, and a replay does not use the
    rate options;
  - a line that is not "[name]", "option" or "option=value";
  - a file with no job.

The check reads a file. It cannot see options on the fio command line.

Usage:
  check-fio-jobs.py [FILE...]    # default: the *.fio files next to it
  check-fio-jobs.py --self-test

Exit status: 0 when each job has a limit, 1 otherwise, 2 for a usage
error.
"""

import copy
import glob
import os
import re
import sys

DIRECTIONS = {
    "read": ("read",),
    "randread": ("read",),
    "write": ("write",),
    "randwrite": ("write",),
    "rw": ("read", "write"),
    "readwrite": ("read", "write"),
    "randrw": ("read", "write"),
    "trim": ("trim",),
    "randtrim": ("trim",),
    "trimwrite": ("trim", "write"),
    "randtrimwrite": ("trim", "write"),
}
ORDER = ("read", "write", "trim")
NUMBER = re.compile(r"([0-9]{1,15})([kmg]?)\Z")
SECTION = re.compile(r"\[([^\]]+)\]")
OPTION = re.compile(r"([a-z0-9_]+)(?:=(.*))?\Z")
ALIASES = {"readwrite": "rw", "blocksize_range": "bsrange"}
MIXED_SIZE = ("bssplit", "bsrange")
REFUSED = ("include", "read_iolog", "replay_no_stall", "replay_time_scale",
           "replay_redirect", "replay_scale", "replay_align", "replay_skip",
           "merge_blktrace_file")
# fio holds rate_iops in 32 bits; keep each byte rate far below 64 bits
TOP = {"rate": 1 << 40, "rate_iops": (1 << 32) - 1}


def limit(value, name):
    """The number of one field of a rate option."""
    m = NUMBER.match(value)
    if not m:
        raise ValueError("%s '%s' is not a plain number with an optional "
                         "k, m or g" % (name, value))
    number = int(m.group(1)) << (10 * " kmg".index(m.group(2) or " "))
    if number > TOP[name]:
        raise ValueError("%s '%s' is too large" % (name, value))
    return number


def set_rate(rates, name, value):
    """Apply a fio "read,write,trim" value. A value with no comma after it
    also sets the directions that follow; an empty field keeps the value
    from before."""
    fields = [f.strip() for f in value.split(",")]
    if len(fields) > 3:
        raise ValueError("more than three fields in '%s'" % value)
    for i, d in enumerate(ORDER):
        field = fields[i] if i < len(fields) else fields[-1]
        if i >= len(fields) and len(fields) > 1 and not fields[-1]:
            continue
        if field:
            rates[d] = limit(field, name)


def check_job(opts):
    """Return the reason a job has no fixed limit, or None."""
    mode = opts.get("rw", "read").split(":")[0]
    if mode not in DIRECTIONS:
        return "unknown rw=%s" % mode
    for key in REFUSED:
        if key in opts:
            return "the option %s is not allowed here" % key
    rate = opts["rate"]
    iops = opts["rate_iops"]
    if any(rate.values()) and any(iops.values()):
        return "rate and rate_iops together: fio refuses the pair"
    for d in DIRECTIONS[mode]:
        if not rate[d] and not iops[d]:
            return "no rate or rate_iops limit for %s" % d
        if not rate[d] and any(k in opts for k in MIXED_SIZE):
            return ("rate_iops is the only limit for %s, with mixed "
                    "request sizes" % d)
    return None


def check_text(text):
    """Return the job count and a list of (job, reason) for one file."""
    zero = dict.fromkeys(ORDER, 0)
    defaults = {"rate": dict(zero), "rate_iops": dict(zero)}
    jobs = []
    current = None
    name = "-"
    for number, raw in enumerate(text.splitlines(), 1):
        # fio drops a comment at the end of a line too
        line = re.split(r"[#;]", raw, maxsplit=1)[0].strip()
        if not line:
            continue
        m = SECTION.match(line)
        if m:
            name = m.group(1).strip()
            if name == "global":
                current = defaults
            else:
                current = copy.deepcopy(defaults)
                jobs.append((name, current))
            continue
        m = OPTION.match(line)
        if not m:
            return 0, [(name, "line %d is not an option: '%s'"
                        % (number, line))]
        if current is None:
            return 0, [("-", "an option before the first section")]
        key = ALIASES.get(m.group(1), m.group(1))
        value = (m.group(2) or "").strip()
        if key in ("rate", "rate_iops"):
            try:
                set_rate(current[key], key, value)
            except ValueError as e:
                return 0, [(name, "line %d: %s" % (number, e))]
        else:
            current[key] = value
    if not jobs:
        return 0, [("-", "no job")]
    bad = []
    for name, opts in jobs:
        why = check_job(opts)
        if why:
            bad.append((name, why))
    return len(jobs), bad


def self_test():
    good = """
# a comment
[global]
ioengine=io_uring_cmd
rate=16m ; a comment after an option
[a]
rw=read
[b]
rw=randwrite:32
rate=,8m
[c] # a comment after a section
rw=randrw
rate=0
rate_iops=100,200
[d]
rw=randread
bssplit=512/50:4k/50
rate=1m
[e]
rw=randrw
rate=,2m
"""
    assert check_text(good) == (5, []), check_text(good)

    # each planted file has one fault, and the reason must name it
    planted = [
        ("no rate option", "[a]\nrw=randread\n", "no rate or rate_iops"),
        ("a rate in a [global] after the job",
         "[a]\nrw=read\n[global]\nrate=1m\n", "no rate or rate_iops"),
        ("a rate for the other direction",
         "[a]\nrw=read\nrate=,16m\n", "limit for read"),
        ("a rate for one direction of two",
         "[a]\nrw=randrw\nrate_iops=100,\n", "limit for write"),
        ("a zero rate", "[global]\nrate=0\n[a]\nrw=write\n",
         "limit for write"),
        ("a zero rate after a good rate",
         "[global]\nrate=1m\n[a]\nrw=read\nrate=0\n", "limit for read"),
        ("a rate from the environment",
         "[a]\nrw=read\nrate=${RATE}\n", "not a plain number"),
        ("rate_iops with mixed sizes",
         "[a]\nrw=randread\nbssplit=512/50:4k/50\nrate_iops=300\n",
         "mixed request sizes"),
        ("a job after a good job",
         "[a]\nrw=read\nrate=1m\n[b]\nrw=read\n", "no rate or rate_iops"),
        ("a job behind a section with a comment",
         "[a]\nrate=1m\n[b] # second job\nrw=read\n",
         "no rate or rate_iops"),
        ("a rate that is not a number", "[a]\nrate=fast\n",
         "not a plain number"),
        ("a rate_iops that wraps to zero in fio",
         "[a]\nrate_iops=4294967296\n", "too large"),
        ("a rate that wraps to zero in fio",
         "[a]\nrate=18014398509481984k\n", "not a plain number"),
        ("rate and rate_iops together",
         "[global]\nrate=1m\n[a]\nrate_iops=100\n", "refuses the pair"),
        ("the readwrite alias after rw",
         "[global]\nrw=read\nrate=1m,0,0\n[a]\nreadwrite=write\n",
         "limit for write"),
        ("an include", "[a]\nrate=1m\ninclude other.inc\n",
         "not an option"),
        ("a replay job",
         "[a]\nrate=1m\nread_iolog=t.iolog\nreplay_no_stall=1\n",
         "read_iolog is not allowed"),
        ("an unknown rw", "[a]\nrw=sideways\nrate=1m\n", "unknown rw"),
        ("no job", "[global]\nrate=1m\n", "no job"),
    ]
    for name, text, key in planted:
        _, bad = check_text(text)
        assert len(bad) == 1 and key in bad[0][1], (name, bad)
    # the faults in a second job name that job, not the first
    for name in ("a job after a good job",
                 "a job behind a section with a comment"):
        text = [p[1] for p in planted if p[0] == name][0]
        assert check_text(text)[1][0][0] == "b", name

    print("check-fio-jobs: self-test passed (%d planted faults caught)"
          % len(planted))
    return 0


def main(argv):
    if argv == ["--self-test"]:
        return self_test()
    if any(a.startswith("-") for a in argv):
        print(__doc__, file=sys.stderr)
        return 2
    here = os.path.dirname(os.path.abspath(__file__))
    files = argv or sorted(glob.glob(os.path.join(here, "fio", "*.fio")))
    if not files:
        print("check-fio-jobs: no job file found", file=sys.stderr)
        return 1
    total = 0
    failed = False
    for path in files:
        try:
            with open(path) as f:
                count, bad = check_text(f.read())
        except OSError as e:
            print("check-fio-jobs: %s" % e, file=sys.stderr)
            return 2
        total += count
        for job, why in bad:
            print("%s: job %s: %s" % (path, job, why), file=sys.stderr)
            failed = True
    if failed:
        return 1
    print("check-fio-jobs: %d jobs in %d files, each with a rate limit"
          % (total, len(files)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
