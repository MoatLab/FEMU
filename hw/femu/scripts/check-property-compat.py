#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Check that each change of a device property between two commits has a record.

The input is hw/femu/docs/reference/properties.snapshot at each commit, which
gen-property-docs.py writes from the binary. A property that goes away, or
whose type, default or kind changes, needs records in
hw/femu/docs/reference/interface-changes.list at the new commit:

    KIND DEVICE PROPERTY OLD NEW RELEASE  # what changed, for people

KIND is remove, type, default or kind (found by this check), or deprecate
or behavior (written by people; this check cannot find them). OLD and NEW
are compact JSON values; "-" stands for no value. RELEASE is "unreleased"
or the femu-vX.Y.Z tag of the release that ships the change.

A change from A to B over a range of commits needs a chain of records
A to X to B of its kind. A push accepts records of releases that have no
tag yet; a release accepts only records that name it. A remove record
needs a deprecate record from a published release that already held it,
and two minor releases from that release to the removal. Properties
named "x-" carry no promise.

Usage:
    check-property-compat.py OLD NEW
    check-property-compat.py --release TAG --published FILE
        FILE lists the published release tags, one per line
    check-property-compat.py --self-test

Exit status: 0 compatible or LEGACY (OLD has no snapshot), 1 a change
without a record or a bad record, 2 a ref or a file that cannot be read.
"""

import json
import os
import re
import subprocess
import sys
import tempfile

SNAPSHOT = "hw/femu/docs/reference/properties.snapshot"
RECORDS = "hw/femu/docs/reference/interface-changes.list"
FOUND = ("remove", "type", "default", "kind")
KINDS = FOUND + ("deprecate", "behavior")
PROP_KINDS = ("static", "runtime")
TAG = re.compile(r"^femu-v(\d+)\.(\d+)\.(\d+)$")
NAME = re.compile(r"^[A-Za-z0-9_.,-]+$")


class SetupError(Exception):
    pass


def git(*args):
    r = subprocess.run(["git", *args], capture_output=True, text=True)
    return r.returncode, r.stdout


def commit_of(ref):
    rc, out = git("rev-parse", "-q", "--verify", ref + "^{commit}")
    if rc:
        raise SetupError("cannot resolve %s to a commit" % ref)
    return out.strip()


def tag_exists(tag):
    return git("rev-parse", "-q", "--verify", "refs/tags/" + tag)[0] == 0


def read_at(ref, path):
    """File text at a commit, or None when its tree has no such path."""
    c = commit_of(ref)
    rc, out = git("ls-tree", "-z", "--name-only", c, "--", path)
    if rc:
        raise SetupError("cannot read the tree of %s" % ref)
    if path not in out.split("\0"):
        return None
    rc, out = git("show", "%s:%s" % (c, path))
    if rc:
        raise SetupError("cannot read %s at %s" % (path, ref))
    return out


def no_duplicates(pairs):
    keys = [k for k, _ in pairs]
    dup = sorted({k for k in keys if keys.count(k) > 1})
    if dup:
        raise ValueError("duplicate key %s" % dup[0])
    return dict(pairs)


def load_snapshot(text, where):
    try:
        doc = json.loads(text, object_pairs_hook=no_duplicates)
    except ValueError as e:
        raise SetupError("%s: %s" % (where, e))
    if not isinstance(doc, dict) or doc.get("format") != 1 or \
            not isinstance(doc.get("devices"), dict) or not doc["devices"]:
        raise SetupError("%s: not a format 1 snapshot" % where)
    for dev, props in doc["devices"].items():
        if not isinstance(props, dict) or not props:
            raise SetupError("%s: device %s has no properties" %
                             (where, dev))
        for name, p in props.items():
            if not isinstance(p, dict) or set(p) != {"type", "default",
                                                     "kind"} or \
                    not isinstance(p["type"], str) or \
                    p["kind"] not in PROP_KINDS:
                raise SetupError("%s: %s %s needs type, default and kind" %
                                 (where, dev, name))
    return doc["devices"]


def val(v):
    return "-" if v is None else json.dumps(v, separators=(",", ":"))


def no_constant(name):
    raise ValueError("%s is not JSON" % name)


def take_value(line, i):
    """One OLD or NEW value at line[i:]: "-" or a strict JSON value."""
    dec = json.JSONDecoder(parse_constant=no_constant,
                           object_pairs_hook=no_duplicates)
    if line.startswith("-", i) and (i + 1 == len(line) or
                                    line[i + 1].isspace()):
        return "-", i + 1
    v, end = dec.raw_decode(line, i)
    return val(v), end


def parse_line(line):
    """The six fields and the text of one record line, or None."""
    m = re.match(r"\s*(\S+)\s+(\S+)\s+(\S+)\s+", line)
    if not m or m.group(1) not in KINDS or not NAME.match(m.group(2)) or \
            not NAME.match(m.group(3)):
        return None
    i = m.end()
    try:
        old, i = take_value(line, i)
        if i >= len(line) or not line[i].isspace():
            return None
        i = len(line) - len(line[i:].lstrip())
        new, i = take_value(line, i)
    except ValueError:
        return None
    m2 = re.match(r"\s+(\S+)\s+#\s*(\S.*)$", line[i:])
    if not m2:
        return None
    rel = m2.group(1)
    if rel != "unreleased" and not TAG.match(rel):
        return None
    if m.group(1) == "remove" and new != "-":
        return None
    return (m.group(1), m.group(2), m.group(3), old, new, rel)


def parse_records(text):
    """Records and the problems in their lines."""
    recs, problems, seen = [], [], set()
    for n, line in enumerate(text.split("\n"), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        rec = parse_line(line)
        if rec is None:
            problems.append("record line %d: need KIND DEVICE PROPERTY OLD "
                            "NEW RELEASE  # text: %s" % (n, line.strip()))
            continue
        if rec in seen:
            problems.append("record line %d repeats an earlier record" % n)
        seen.add(rec)
        recs.append(rec)
    return recs, problems


def changes(old, new):
    """(kind, device, property, old, new) for each change OLD to NEW."""
    out = []
    for dev in sorted(old):
        for name in sorted(old[dev]):
            if name.startswith("x-"):
                continue
            a = old[dev][name]
            b = new.get(dev, {}).get(name)
            if b is None:
                out.append(("remove", dev, name, val(a["type"]), "-"))
                continue
            for field in ("type", "default", "kind"):
                if a[field] != b[field]:
                    out.append((field, dev, name, val(a[field]),
                                val(b[field])))
    return out


def chained(recs, kind, dev, name, a, b):
    """True when records of KIND lead from A to B for DEV NAME."""
    step = {}
    for r in recs:
        if r[:3] == (kind, dev, name):
            step.setdefault(r[3], set()).add(r[4])
    seen, todo = {a}, [a]
    while todo:
        for nxt in step.get(todo.pop(), ()):
            if nxt == b:
                return True
            if nxt not in seen:
                seen.add(nxt)
                todo.append(nxt)
    return False


def minor(tag):
    m = TAG.match(tag)
    return (int(m.group(1)), int(m.group(2)))


class History:
    """What the check knows about tags and released record files."""

    def tag_exists(self, tag):
        return tag_exists(tag)

    def records_at(self, tag):
        text = read_at("refs/tags/" + tag, RECORDS)
        return parse_records(text or "")[0]

    def is_ancestor(self, tag, release):
        rc, _ = git("merge-base", "--is-ancestor", commit_of(tag),
                    commit_of(release))
        if rc not in (0, 1):
            raise SetupError("cannot test %s against %s" % (tag, release))
        return rc == 0


def deprecation_problems(r, recs, hist, release, published):
    """Problems of one remove record R with the deprecation rule."""
    dev, name = r[1], r[2]
    good = None
    for d in recs:
        if d[0] != "deprecate" or d[1:3] != (dev, name) or \
                not TAG.match(d[5]) or not hist.tag_exists(d[5]):
            continue
        if release and (d[5] not in published or
                        not hist.is_ancestor(d[5], release)):
            continue
        if d in hist.records_at(d[5]):
            good = d[5]
    if good is None:
        return ["remove %s %s: no deprecate record that a released "
                "version holds" % (dev, name)]
    if not release:
        return []
    # only releases on the history of this one count
    later = {minor(t) for t in published
             if TAG.match(t) and minor(good) < minor(t) <= minor(release)
             and hist.tag_exists(t) and hist.is_ancestor(t, release)}
    later.add(minor(release))
    if len([m for m in later if m > minor(good)]) < 2:
        return ["remove %s %s: deprecated in %s; it must work in one more "
                "minor release first" % (dev, name, good)]
    return []


def compare(old, new, recs, old_recs, hist, release=None, published=(),
            old_ref=None):
    """Problems for the changes OLD to NEW under the records.

    RECS are the records at NEW, OLD_RECS those at OLD. A push accepts
    the records that are unreleased, and the records new in the range
    whose release does not already hold OLD. A release accepts the
    records that name it.
    """
    problems = []
    added = [r for r in recs if r not in old_recs]
    if release:
        allowed = [r for r in recs if r[5] == release]
        for r in recs:
            if r[5] == "unreleased":
                problems.append("%s %s %s is still unreleased; name %s" %
                                (r[0], r[1], r[2], release))
        for r in added:
            if r[5] not in ("unreleased", release):
                problems.append("%s %s %s: a new record names %s, not %s" %
                                (r[0], r[1], r[2], r[5], release))
    else:
        def fresh(r):
            # a release that already holds OLD cannot ship this change
            return not hist.tag_exists(r[5]) or old_ref is None or \
                not hist.is_ancestor(r[5], old_ref)
        allowed = [r for r in recs if r[5] == "unreleased" or
                   (r in added and fresh(r))]
    for kind, dev, name, a, b in changes(old, new):
        if kind == "remove":
            # the record names the last type; a chain of type records
            # leads there from the type at OLD
            ok = any(r[:3] == (kind, dev, name) and
                     (r[3] == a or
                      chained(allowed, "type", dev, name, a, r[3]))
                     for r in allowed)
        else:
            ok = chained(allowed, kind, dev, name, a, b)
        if not ok:
            problems.append("%s %s %s %s -> %s has no record; add\n    "
                            "%s %s %s %s %s unreleased  # <what users see>"
                            % (kind, dev, name, a, b, kind, dev, name, a, b))
    # each remove record in scope follows the deprecation rule, also when
    # no snapshot difference shows the removal (a LEGACY base)
    for r in allowed:
        if r[0] == "remove":
            problems += deprecation_problems(r, recs, hist, release,
                                             published)
    return problems


def version(tag):
    return tuple(int(x) for x in TAG.match(tag).groups())


def release_base(tag, published):
    """The newest published release older than TAG, on its history."""
    head = commit_of(tag)
    best = None
    for t in published:
        if t == tag or version(t) >= version(tag):
            continue
        if not tag_exists(t):
            raise SetupError("published release %s has no local tag" % t)
        rc, _ = git("merge-base", "--is-ancestor", commit_of(t), head)
        if rc not in (0, 1):
            raise SetupError("cannot test %s against %s" % (t, tag))
        if rc == 0 and (best is None or version(t) > version(best)):
            best = t
    return best


def run(old_ref, new_ref, hist, release=None, published=()):
    new_text = read_at(new_ref, SNAPSHOT)
    if new_text is None:
        raise SetupError("%s has no %s" % (new_ref, SNAPSHOT))
    new = load_snapshot(new_text, "%s:%s" % (new_ref, SNAPSHOT))
    recs, problems = parse_records(read_at(new_ref, RECORDS) or "")
    old_recs = parse_records(read_at(old_ref, RECORDS) or "")[0] \
        if old_ref else []
    old_text = read_at(old_ref, SNAPSHOT) if old_ref else None
    if old_text is None:
        print("LEGACY %s has no property snapshot; nothing to compare" %
              (old_ref or "the release before %s" % new_ref))
        old = new
    else:
        old = load_snapshot(old_text, "%s:%s" % (old_ref, SNAPSHOT))
    problems += compare(old, new, recs, old_recs, hist, release, published,
                        old_ref)
    for p in problems:
        print("check-property-compat: " + p)
    print("check-property-compat: %s..%s: %d change(s), %d problem(s)" %
          (old_ref, new_ref, len(changes(old, new)), len(problems)))
    return 1 if problems else 0


class FakeHistory(History):
    def __init__(self, tags, records, off=()):
        self.tags = set(tags)
        self.records = records
        self.off = set(off)

    def is_ancestor(self, tag, release):
        return tag not in self.off

    def tag_exists(self, tag):
        return tag in self.tags

    def records_at(self, tag):
        return parse_records(self.records.get(tag, ""))[0]


def self_test():
    base = {"femu": {"oncs": {"type": "uint16", "default": 20,
                              "kind": "static"},
                     "serial": {"type": "str", "default": None,
                                "kind": "static"},
                     "x-test": {"type": "bool", "default": False,
                                "kind": "static"}},
            "femu-subsys": {"ns_mgmt": {"type": "bool", "default": False,
                                        "kind": "static"}}}

    def edit(fn):
        d = json.loads(json.dumps(base))
        fn(d)
        return d

    def recs(text):
        r, p = parse_records(text)
        assert not p, p
        return r

    gone = edit(lambda d: d["femu"].pop("serial"))
    dflt = edit(lambda d: d["femu"]["oncs"].update(default=413))
    typ = edit(lambda d: d["femu"]["oncs"].update(type="uint32"))
    xgone = edit(lambda d: d["femu"].pop("x-test"))
    sub = edit(lambda d: d["femu-subsys"].pop("ns_mgmt"))
    twice = edit(lambda d: d["femu"]["oncs"].update(default=500))
    d413 = "default femu oncs 20 413 unreleased  # Copy on\n"
    dep = "deprecate femu serial - - femu-v10.1.0  # use x\n"
    rm = "remove femu serial \"str\" - unreleased  # gone\n"
    tags = ["femu-v10.1.0", "femu-v10.2.0", "femu-v11.1.0"]
    hist = FakeHistory(tags, {"femu-v10.1.0": dep})
    nodep = FakeHistory(tags, {})
    cases = [
        ("no change", base, base, "", None, hist, 0),
        ("removal without a record", base, gone, "", None, hist, 1),
        ("default change without a record", base, dflt, "", None, hist, 1),
        ("type change without a record", base, typ, "", None, hist, 1),
        ("default change with its record", base, dflt, d413, None, hist, 0),
        ("type change with its record", base, typ,
         "type femu oncs \"uint16\" \"uint32\" unreleased  # wider\n",
         None, hist, 0),
        ("second change, only the first record", dflt, twice, d413, None,
         hist, 1),
        ("two changes in one range, a chain of records", base, twice,
         d413 + "default femu oncs 413 500 unreleased  # more\n", None,
         hist, 0),
        ("a chain that ends at another value", base, twice, d413, None,
         hist, 1),
        ("a record of a release that has a tag", base, dflt,
         d413.replace("unreleased", "femu-v10.2.0"), None, hist, 1),
        ("a record new in the range, its tag made later", base, dflt,
         d413.replace("unreleased", "femu-v10.2.0"), None,
         FakeHistory(tags, {"femu-v10.1.0": dep}, off={"femu-v10.2.0"}), 0),
        ("an old record of a released change", base, dflt,
         d413.replace("unreleased", "femu-v10.2.0"), None,
         FakeHistory(tags, {"femu-v10.1.0": dep}, off={"femu-v10.2.0"}),
         1, d413.replace("unreleased", "femu-v10.2.0")),
        ("removal with the wrong old type", base, gone,
         dep + rm.replace('"str"', '"uint16"'), None, hist, 1),
        ("removal after a type change, both recorded", base,
         edit(lambda d: d["femu"].pop("serial")),
         dep + 'type femu serial "str" "strList" unreleased  # x\n' +
         rm.replace('"str"', '"strList"'), None, hist, 0),
        ("release: deprecation on another branch", base, gone,
         dep + rm.replace("unreleased", "femu-v11.1.0"), "femu-v11.1.0",
         FakeHistory(tags, {"femu-v10.1.0": dep}, off={"femu-v10.1.0"}),
         1, dep),
        ("release: the middle release is on another branch", base, gone,
         dep + rm.replace("unreleased", "femu-v11.1.0"), "femu-v11.1.0",
         FakeHistory(tags, {"femu-v10.1.0": dep}, off={"femu-v10.2.0"}),
         1, dep),
        ("release: a new record names another tag", base, base,
         "behavior femu oncs - - femu-v99.0.0  # x\n", "femu-v11.1.0",
         hist, 1),
        ("release: a remove record, no change seen (LEGACY)", base, base,
         rm.replace("unreleased", "femu-v11.1.0"), "femu-v11.1.0", hist, 1),
        ("x- removal", base, xgone, "", None, hist, 0),
        ("record for the other device", base, sub,
         "remove femu ns_mgmt \"bool\" - unreleased  # x\n", None, hist, 1),
        ("removal without a deprecation", base, gone, rm, None, hist, 1),
        ("removal, deprecation not released", base, gone,
         rm + "deprecate femu serial - - unreleased  # x\n", None, hist, 1),
        ("removal, the release never held the deprecation", base, gone,
         dep + rm, None, nodep, 1),
        ("removal after a released deprecation", base, gone, dep + rm,
         None, hist, 0),
        ("release: a record still unreleased", base, gone, dep + rm,
         "femu-v11.1.0", hist, 1),
        ("release: an unreleased behavior record", base, base,
         "behavior femu oncs - - unreleased  # x\n", "femu-v11.1.0",
         hist, 1),
        ("release: one minor release after the deprecation", base, gone,
         dep + rm.replace("unreleased", "femu-v10.2.0"),
         "femu-v10.2.0", hist, 1, dep),
        ("release: two minor releases after the deprecation", base, gone,
         dep + rm.replace("unreleased", "femu-v11.1.0"),
         "femu-v11.1.0", hist, 0, dep),
        ("release: an old record of the same change", base, dflt,
         d413.replace("unreleased", "femu-v10.1.0") +
         d413.replace("unreleased", "femu-v11.1.0"), "femu-v11.1.0",
         hist, 0, d413.replace("unreleased", "femu-v10.1.0")),
        ("release: only an old record of the same change", base, dflt,
         d413.replace("unreleased", "femu-v10.1.0"), "femu-v11.1.0",
         hist, 1),
    ]
    failed = 0
    for c in cases:
        name, old, new, text, rel, h, want = c[:7]
        old_text = c[7] if len(c) > 7 else ""
        got = 1 if compare(old, new, recs(text), recs(old_text), h, rel,
                           tags, "OLD") else 0
        failed += got != want
        print("%s %s" % ("ok" if got == want else "FAIL", name))
    good = ["default femu serial \"a#b\" \"c d\" unreleased  # quoted",
            "default femu oncs 20\t413 unreleased  # a tab",
            "default femu oncs 20 413 femu-v11.1.0  # x"]
    bad = ["default femu oncs 20 413 unreleased",
           "default femu oncs 20 413 unreleased  #",
           "default femu oncs 20 413 next  # x",
           "rename femu oncs 20 413 unreleased  # x",
           "default femu oncs INVALID INVALID unreleased  # x",
           "default femu oncs NaN Infinity unreleased  # x",
           "default femu oncs {\"a\":1,\"a\":2} 1 unreleased  # x",
           "remove femu oncs \"uint16\" 999 unreleased  # x",
           "default femu oncs 20 413 unreleased  # a\n" * 2]
    for text in good:
        ok = not parse_records(text)[1]
        failed += not ok
        print("%s record parses: %s" % ("ok" if ok else "FAIL", text[:40]))
    for text in bad:
        ok = bool(parse_records(text)[1])
        failed += not ok
        print("%s record refused: %s" % ("ok" if ok else "FAIL",
                                         text.strip()[:40]))
    ok = parse_records(good[0])[0][0][3:5] == ('"a#b"', '"c d"')
    failed += not ok
    print("%s quoted values kept" % ("ok" if ok else "FAIL"))
    one = '{"type": "str", "default": null, "kind": "static"}'
    for name, text in [("empty snapshot", '{"format": 1, "devices": {}}'),
                       ("device without properties",
                        '{"format": 1, "devices": {"femu": {}}}'),
                       ("other format", '{"format": 2, "devices": '
                        '{"femu": {"a": %s}}}' % one),
                       ("a list", "[1]"),
                       ("not JSON", "| `oncs` |"),
                       ("duplicate property", '{"format": 1, "devices": '
                        '{"femu": {"a": %s, "a": %s}}}' % (one, one)),
                       ("missing field", '{"format": 1, "devices": '
                        '{"femu": {"a": {"type": "str"}}}}'),
                       ("bad kind", '{"format": 1, "devices": {"femu": '
                        '{"a": {"type": "str", "default": null, '
                        '"kind": "other"}}}}')]:
        try:
            load_snapshot(text, "test")
            ok = False
        except SetupError:
            ok = True
        failed += not ok
        print("%s %s" % ("ok" if ok else "FAIL", name))
    # git: LEGACY base, a bad ref, a bad new snapshot, the release base
    with tempfile.TemporaryDirectory() as d:
        cwd = os.getcwd()
        os.chdir(d)
        try:
            env = ["-c", "user.name=t", "-c", "user.email=t@t"]

            def commit(msg, tag=None):
                subprocess.run(["git", "add", "-A"], check=True)
                subprocess.run(["git", *env, "commit", "-q",
                                "--allow-empty", "-m", msg], check=True)
                if tag:
                    subprocess.run(["git", "tag", tag], check=True)

            subprocess.run(["git", "init", "-q"], check=True)
            commit("old", "femu-v9.0.1")
            os.makedirs(os.path.dirname(SNAPSHOT))
            with open(SNAPSHOT, "w") as f:
                json.dump({"format": 1, "devices": base}, f)
            commit("new", "femu-v99.0.0")
            commit("next", "femu-v10.1.0")
            commit("head", "femu-v11.1.0")
            h = History()
            checks = [
                ("LEGACY base", lambda: run("HEAD~3", "HEAD", h) == 0),
                ("release base: newest older published",
                 lambda: release_base("femu-v11.1.0",
                                      ["femu-v9.0.1", "femu-v99.0.0",
                                       "femu-v10.1.0"]) == "femu-v10.1.0"),
                ("release base: an unpublished tag is no base",
                 lambda: release_base("femu-v11.1.0", ["femu-v9.0.1"])
                 == "femu-v9.0.1"),
            ]
            for name, fn in checks:
                ok = fn()
                failed += not ok
                print("%s %s" % ("ok" if ok else "FAIL", name))
            with open(SNAPSHOT, "w") as f:
                f.write("{")
            commit("broken")
            try:
                release_base("femu-v11.1.0", ["femu-v10.9.0"])
                ok = False
            except SetupError:
                ok = True
            failed += not ok
            print("%s release base: a published tag missing here" %
                  ("ok" if ok else "FAIL"))
            for name, args in [("missing ref", ("0" * 40, "HEAD")),
                               ("bad new snapshot, LEGACY base",
                                ("HEAD~4", "HEAD"))]:
                try:
                    run(*args, h)
                    ok = False
                except SetupError:
                    ok = True
                failed += not ok
                print("%s %s" % ("ok" if ok else "FAIL", name))
        finally:
            os.chdir(cwd)
    return 1 if failed else 0


def main(argv):
    try:
        if argv == ["--self-test"]:
            return self_test()
        if len(argv) == 4 and argv[0] == "--release" and \
                argv[2] == "--published":
            tag = argv[1]
            if not TAG.match(tag):
                raise SetupError("%s is not femu-vX.Y.Z" % tag)
            try:
                with open(argv[3]) as f:
                    published = [t for t in f.read().split() if TAG.match(t)]
            except OSError as e:
                raise SetupError(str(e))
            base = release_base(tag, published)
            return run(base, tag, History(), tag, published)
        if len(argv) == 2:
            return run(argv[0], argv[1], History())
        print(__doc__.strip(), file=sys.stderr)
        return 2
    except SetupError as e:
        print("check-property-compat: %s" % e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
