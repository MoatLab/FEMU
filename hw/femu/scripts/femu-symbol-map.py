#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Map the FEMU symbols of an old revision to their names at a new revision.

A fork of an old FEMU release calls functions, uses structs and fields, and
sets -device properties that may now have another name or another file.
This script reads both revisions from git and prints, for each old
definition, what became of it:

  same       the name exists at NEW in the same file (shown with --all)
  moved      the name exists at NEW in another file
  redefined  (functions only) the name exists at NEW with other parameter
             types or another return type: a new function, not a move
  default    (properties only) the name exists, with another default
  value      (enum constants only) the name exists, with another value
  candidate  the name is gone; the commit that removed its definition
             added a similar name (the note gives the score), or a field
             of the same name exists in another struct
  removed    the name is gone and no candidate was found
  split      (files only) the functions of the old file now live in more
             than one file at NEW

Kinds: file, func, struct, field (STRUCT.FIELD, STRUCT.MEMBER.FIELD for a
named nested member), enum (constants), macro (#define names) and prop
(-device properties from DEFINE_PROP_*). A name defined in more than one
old file (two static helpers, for example) gives one line per definition.

Each output line has seven tab-separated columns: kind, old name, status,
new name, file at NEW, commit and note. The commit is the one that
"git show" explains:

  removed, candidate  the newest commit in OLD..NEW that took away more
                      definitions of the name than it added; comments do
                      not count, and a note "lead" marks a commit found
                      only from the bare name
  file moved, split   the commit that deleted the old path
  default             the first commit that changed the default

Property defaults and enum values are compared as numbers when the
script can work them out from the enum constants and #define values of
the same tree, and as text otherwise.

The parser is a set of regular expressions, not a C compiler: it finds
definitions at the start of a line, in the QEMU coding style. "same"
means that the name and the file survived, not that the code still
works the same way. A "candidate" line is a lead for a person to check.

Usage:
  femu-symbol-map.py OLD NEW [--kind K,K] [--all] [--json] [--summary]
                     [--touched A..B] [--old-path P] [--new-path P] [-C DIR]
  femu-symbol-map.py --self-test

OLD and NEW are any git revisions, for example femu-v9.0.1 and
origin/master. --touched A..B keeps only the old names that the changed
lines of "git diff A..B" use (with the function that git names in each
hunk header), and the old files that it changes or includes. With A the
release a fork started from and B the fork, it gives a short list to
start from. A hunk header can name the wrong function, and a change to a
macro body or a build file names no symbol, so read the whole fork diff
too. --old-path defaults to hw/femu, or to hw/block/femu when OLD
has no hw/femu (femu-v5.2 and femu-v5.2.1). --new-path defaults to
hw/femu. The docs, tests, scripts, tools and profiles folders are left
out.

Exit status: 0 on success, 1 when a revision or a path does not exist.
"""

import argparse
import ast
import difflib
import json
import operator
import os
import re
import shutil
import subprocess
import sys
import tempfile

KINDS = ("file", "func", "struct", "field", "enum", "macro", "prop")
SKIP_DIRS = ("docs", "tests", "scripts", "tools", "profiles", "UPSTREAMING")
SOURCE_RE = re.compile(r"\.(c|h|inc)$")
KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "do",
            "else", "case", "defined", "typeof", "__attribute__"}
TYPE_WORDS = {"const", "volatile", "unsigned", "signed", "struct", "union",
              "enum", "static", "inline", "extern", "register", "restrict"}
MIN_SCORE = 0.6
MAX_HOMES = 3


def git(repo, *args, check=True):
    """Run git in @repo and return its standard output as text."""
    r = subprocess.run(["git", "-C", repo] + list(args),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       text=True, errors="replace")
    if check and r.returncode != 0:
        raise RuntimeError("git %s: %s" % (" ".join(args), r.stderr.strip()))
    return r.stdout


def has_path(repo, rev, path):
    return git(repo, "ls-tree", "-d", "--name-only", rev, path,
               check=False).strip() == path


def source_files(repo, rev, path):
    """Return the C sources under @path at @rev, without the skipped dirs."""
    out = git(repo, "ls-tree", "-r", "--name-only", rev, "--", path)
    files = []
    for f in out.splitlines():
        rel = f[len(path) + 1:]
        if rel.split("/", 1)[0] in SKIP_DIRS:
            continue
        if SOURCE_RE.search(f):
            files.append(f)
    return files


def read_blobs(repo, rev, files):
    """Return {file: text} for @files at @rev, in one git cat-file call."""
    if not files:
        return {}
    req = "".join("%s:%s\n" % (rev, f) for f in files).encode()
    r = subprocess.run(["git", "-C", repo, "cat-file", "--batch"],
                       input=req, stdout=subprocess.PIPE, check=True)
    data = r.stdout
    out = {}
    pos = 0
    for f in files:
        nl = data.index(b"\n", pos)
        header = data[pos:nl].split()
        size = int(header[2])
        out[f] = data[nl + 1:nl + 1 + size].decode("utf-8", "replace")
        pos = nl + 1 + size + 1
    return out


COMMENT_RE = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\\n])*"', re.S)


def strip_comments(text, keep_strings=False):
    """Blank out comments (and string bodies), but keep the line count."""
    def blank(m):
        s = m.group(0)
        if s.startswith('"'):
            return s if keep_strings else '""'
        return re.sub(r"[^\n]", " ", s)
    return COMMENT_RE.sub(blank, text)


def strip_line_comments(line):
    """Remove the comment parts of one diff line, open or closed."""
    line = re.sub(r"/\*.*?\*/", " ", line)
    line = re.sub(r"//.*", "", line)
    line = re.sub(r"/\*.*", "", line)
    if line.lstrip().startswith("*"):
        return ""
    return line


def match_close(text, i, open_ch, close_ch):
    """Return the index after the bracket that closes the one at @i."""
    depth = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def split_top(text, sep=","):
    """Split @text at @sep outside brackets and strings."""
    parts, depth, cur, quote = [], 0, [], False
    for c in text:
        if c == '"':
            quote = not quote
        elif not quote and c in "([{":
            depth += 1
        elif not quote and c in ")]}":
            depth -= 1
        if c == sep and depth == 0 and not quote:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    parts.append("".join(cur))
    return parts


# ------------------------------------------------------------------ values

BINOPS = {ast.BitOr: operator.or_, ast.BitAnd: operator.and_,
          ast.BitXor: operator.xor, ast.LShift: operator.lshift,
          ast.RShift: operator.rshift, ast.Add: operator.add,
          ast.Sub: operator.sub, ast.Mult: operator.mul,
          ast.FloorDiv: operator.floordiv, ast.Div: operator.floordiv,
          ast.Mod: operator.mod}
UNOPS = {ast.USub: operator.neg, ast.UAdd: operator.pos,
         ast.Invert: operator.invert}


def eval_int(expr, consts):
    """Return the integer value of a C constant expression, or None."""
    if expr is None:
        return None
    text = re.sub(r"\b(0[xX][0-9a-fA-F]+|\d+)[uUlL]+\b", r"\1", expr.strip())
    text = re.sub(r"\(\s*(?:u?int\d+_t|unsigned|int|long|size_t)\s*\)", "",
                  text)
    text = text.replace("/", "//").replace("////", "//")
    try:
        tree = ast.parse(text, mode="eval")
    except SyntaxError:
        return None

    def walk(n):
        if isinstance(n, ast.Expression):
            return walk(n.body)
        if isinstance(n, ast.Constant) and isinstance(n.value, int):
            return n.value
        if isinstance(n, ast.Name):
            v = consts.get(n.id)
            if v is None:
                raise ValueError(n.id)
            return v
        if isinstance(n, ast.BinOp) and type(n.op) in BINOPS:
            return BINOPS[type(n.op)](walk(n.left), walk(n.right))
        if isinstance(n, ast.UnaryOp) and type(n.op) in UNOPS:
            return UNOPS[type(n.op)](walk(n.operand))
        raise ValueError(type(n).__name__)
    try:
        return walk(tree)
    except (ValueError, ZeroDivisionError, TypeError, OverflowError):
        return None


def norm(text):
    return " ".join(text.split()) if text else None


# ------------------------------------------------------------------ parsing

FUNC_START = re.compile(r"^(?![ \t#}{])[^\n;=(]*?\b([A-Za-z_]\w*)\s*\(", re.M)
ATTR = r"(?:QEMU_PACKED|QEMU_ALIGNED\s*\([^)]*\))"
STRUCT_START = re.compile(
    r"^(typedef\s+)?(struct|union)\s+(?:%s\s+)*(\w+)?\s*(?:%s\s*)*\{"
    % (ATTR, ATTR), re.M)
STRUCT_TAIL = re.compile(r"\s*(?:%s\s*)*(\w+)?" % ATTR)
ENUM_START = re.compile(r"^(?:typedef\s+)?enum\s*(\w+)?\s*\{", re.M)
MACRO_RE = re.compile(r"^#\s*define\s+([A-Za-z_]\w*)(\(?)[ \t]*(.*)$", re.M)
PROP_START = re.compile(r"\bDEFINE_PROP_\w+\s*\(")


def param_types(params):
    """Normalize a parameter list to its types, without parameter names."""
    out = []
    for p in split_top(params):
        p = norm(p) or ""
        p = re.sub(r"\[[^\]]*\]", "*", p)
        fp = re.match(r"(.*)\(\s*\*\s*\w*\s*\)\s*(\(.*\))$", p)
        if fp:
            out.append("%s(*)%s" % (fp.group(1).strip(),
                                    param_types(fp.group(2)[1:-1])))
            continue
        words = re.findall(r"\w+|\*+|\.\.\.", p)
        if len(words) > 1 and re.match(r"\w+$", words[-1]) and \
                words[-1] not in TYPE_WORDS and \
                not (len(words) == 2 and words[0] in TYPE_WORDS):
            words = words[:-1]
        out.append(" ".join(words))
    return "(%s)" % ", ".join(out)


def parse_funcs(code):
    """Return [(name, signature)] for each function definition."""
    out = []
    for m in FUNC_START.finditer(code):
        name = m.group(1)
        if name in KEYWORDS:
            continue
        end = match_close(code, m.end() - 1, "(", ")")
        rest = code[end:end + 200].lstrip()
        if not rest.startswith("{"):
            continue
        head = code[m.start():m.end() - 1]
        ret = re.sub(r"\b(static|inline|extern|QEMU_\w+)\b", "",
                     head[:head.rfind(name)])
        sig = "%s %s" % (norm(ret) or "", param_types(code[m.end():end - 1]))
        out.append((name, sig.strip()))
    return out


def members(body, prefix=""):
    """Return the member names of a struct @body, nested ones qualified."""
    names = []
    i, n, start = 0, len(body), 0
    while i < n:
        c = body[i]
        if c == "{":
            end = match_close(body, i, "{", "}")
            semi = body.find(";", end)
            semi = n if semi < 0 else semi
            decl = norm(body[end:semi]) or ""
            inner = members(body[i + 1:end - 1])
            dm = re.match(r"(\w+)", decl)
            if dm:
                sub = prefix + dm.group(1)
                names.append(sub)
                names.extend("%s.%s" % (sub, x) for x in inner)
            else:
                names.extend(prefix + x for x in inner)
            i = start = semi + 1
            continue
        if c == ";":
            names.extend(prefix + x for x in plain_members(body[start:i]))
            start = i + 1
        i += 1
    return names


def plain_members(decl):
    decl = decl.strip()
    if not decl or decl.startswith("#"):
        return []
    fp = re.search(r"\(\s*\*\s*(\w+)\s*\)\s*\(", decl)
    if fp:
        return [fp.group(1)]
    out = []
    for part in split_top(decl):
        m = re.search(r"(\w+)\s*(?:\[[^\]]*\]\s*)*(?::\s*\w+)?\s*$",
                      part.strip())
        if m and m.group(1) not in KEYWORDS and m.group(1) not in TYPE_WORDS:
            out.append(m.group(1))
    return out


def parse_structs(code):
    out = {}
    for m in STRUCT_START.finditer(code):
        start = m.end() - 1
        end = match_close(code, start, "{", "}")
        tail = STRUCT_TAIL.match(code, end)
        name = (tail.group(1) if m.group(1) and tail and tail.group(1)
                else m.group(3))
        if name:
            out[name] = members(code[start + 1:end - 1])
    return out


def parse_enums(code, consts):
    """Return [(name, value)]; @consts gains each value it can work out."""
    out = []
    for m in ENUM_START.finditer(code):
        start = m.end() - 1
        end = match_close(code, start, "{", "}")
        prev = None
        for item in split_top(code[start + 1:end - 1]):
            em = re.match(r"\s*([A-Za-z_]\w*)\s*(?:=\s*(.+?))?\s*$", item,
                          re.S)
            if not em:
                continue
            expr = norm(em.group(2))
            if expr is None:
                expr = "0" if prev is None else "(%s) + 1" % prev
            v = eval_int(expr, consts)
            value = str(v) if v is not None else expr
            if v is not None:
                consts[em.group(1)] = v
            out.append((em.group(1), value))
            prev = value
    return out


def parse_props(text):
    """Return [(name, default text)] for each DEFINE_PROP_* line."""
    out = []
    code = strip_comments(text, keep_strings=True)
    for m in PROP_START.finditer(code):
        end = match_close(code, m.end() - 1, "(", ")")
        args = [norm(a) for a in split_top(code[m.end():end - 1])]
        if not args or not args[0] or not args[0].startswith('"'):
            continue
        name = args[0].strip('"')
        dflt = args[3] if len(args) > 3 else None
        out.append((name, dflt))
    return out


class Tree:
    """The definitions of one revision: {kind: {name: [(file, extra)]}}."""

    def __init__(self, repo, rev, path):
        self.files = source_files(repo, rev, path)
        self.sym = {k: {} for k in KINDS}
        self.path = path
        self.consts = {}
        for f in self.files:
            self.sym["file"][f] = [(f, None)]
        blobs = read_blobs(repo, rev, self.files)
        codes = {f: strip_comments(t) for f, t in blobs.items()}
        bodies = {}
        for f, code in codes.items():
            for name, paren, body in MACRO_RE.findall(code):
                self.put("macro", name, f)
                if not paren:
                    bodies.setdefault(name, body)
        self.resolve_macros(bodies)
        for f, code in codes.items():
            for name, sig in parse_funcs(code):
                self.put("func", name, f, sig)
            for name, fields in parse_structs(code).items():
                self.put("struct", name, f)
                for fld in fields:
                    self.put("field", "%s.%s" % (name, fld), f)
            for name, value in parse_enums(code, self.consts):
                self.put("enum", name, f, value)
        self.resolve_macros(bodies)
        for f, text in blobs.items():
            for name, dflt in parse_props(text):
                self.put("prop", name, f, dflt)

    def resolve_macros(self, bodies, rounds=3):
        """Give each object-like macro its value, when it is a constant."""
        for _ in range(rounds):
            for name, body in bodies.items():
                if name not in self.consts:
                    v = eval_int(body, self.consts)
                    if v is not None:
                        self.consts[name] = v

    def put(self, kind, name, f, extra=None):
        entries = self.sym[kind].setdefault(name, [])
        if all(e[0] != f for e in entries):
            entries.append((f, extra))

    def value(self, expr):
        v = eval_int(expr, self.consts)
        return v if v is not None else norm(expr)


def decl_regex(kind, name):
    """A line that defines @name of @kind, after its comments are gone."""
    w = re.escape(name.rsplit(".", 1)[-1])
    if kind == "func":
        return r"^(?![ \t#]).*\b%s\s*\(" % w
    if kind == "struct":
        return r"\b(?:struct|union)\s+%s\s*\{|^\}\s*(?:%s\s*)*%s\s*;" % (
            w, ATTR, w)
    if kind == "field":
        return (r"^\s+[^(;]*\b%s\s*(?:\[[^\]]*\]\s*)*(?::\s*\w+\s*)?[;,]"
                r"|\(\s*\*\s*%s\s*\)" % (w, w))
    if kind == "enum":
        return r"^\s*%s\s*(?:=|,|$)" % w
    if kind == "macro":
        return r"^#\s*define\s+%s\b" % w
    if kind == "prop":
        return r'"%s"' % w
    return r"\b%s\b" % w


class History:
    """The patches of OLD..NEW under the paths, newest commit first."""

    def __init__(self, repo, old, new, paths):
        out = git(repo, "log", "-p", "--no-renames", "-U3",
                  "--format=@@commit %h %s", "%s..%s" % (old, new), "--",
                  *paths)
        self.commits = []
        cur = hunk = None
        for line in out.splitlines():
            if line.startswith("@@commit "):
                h, _, subj = line[9:].partition(" ")
                cur = {"hash": h, "subject": subj, "plus": [], "minus": [],
                       "hunks": []}
                self.commits.append(cur)
                hunk = None
            elif cur is None or line.startswith(("+++", "---", "diff ",
                                                 "index ")):
                continue
            elif line.startswith("@@"):
                hunk = ([], [])
                cur["hunks"].append(hunk)
            elif hunk is None:
                continue
            elif line.startswith("+"):
                cur["plus"].append(strip_line_comments(line[1:]))
                hunk[1].append(line[1:])
            elif line.startswith("-"):
                cur["minus"].append(strip_line_comments(line[1:]))
                hunk[0].append(line[1:])
            elif line.startswith(" "):
                hunk[0].append(line[1:])
                hunk[1].append(line[1:])
        for c in self.commits:
            c["plus_text"] = "\n".join(c["plus"])
            c["minus_text"] = "\n".join(c["minus"])
            c["hunks"] = [("\n".join(b), "\n".join(a))
                          for b, a in c["hunks"] if b != a]

    def default_change(self, prop, old_value, tree):
        """Return the oldest commit that moved @prop off @old_value."""
        quoted = '"%s"' % prop
        for c in reversed(self.commits):
            for before, after in c["hunks"]:
                if quoted not in before:
                    continue
                was = [tree.value(d) for n, d in parse_props(before)
                       if n == prop]
                now = [tree.value(d) for n, d in parse_props(after)
                       if n == prop]
                if old_value in was and now and old_value not in now:
                    return c
        return None

    def removal(self, kind, name):
        """Return (commit, exact) for the newest removal of @name."""
        rx = re.compile(decl_regex(kind, name), re.M)
        word = leaf(kind, name)
        for c in self.commits:
            if word not in c["minus_text"]:
                continue
            gone = len(rx.findall(c["minus_text"]))
            if gone and gone > len(rx.findall(c["plus_text"])):
                return c, True
        wx = re.compile(r"(?<![\w])" + re.escape(word) + r"(?![\w])")
        for c in self.commits:
            if word in c["minus_text"] and \
                    len(wx.findall(c["minus_text"])) > \
                    len(wx.findall(c["plus_text"])):
                return c, False
        return None, False


def leaf(kind, name):
    """The word a diff names: a field without its struct, a file base."""
    if kind == "field":
        return name.rsplit(".", 1)[1]
    if kind == "file":
        return os.path.basename(name)
    if kind == "prop":
        return '"%s"' % name
    return name


def best_candidate(name, cands):
    best, score = None, 0.0
    for c in cands:
        s = difflib.SequenceMatcher(None, name, c).ratio()
        if s > score:
            best, score = c, s
    return best, score


def record(kind, name, **kw):
    rec = {"kind": kind, "old": name, "status": "same", "new": name,
           "file": None, "commit": None, "subject": None, "note": None}
    rec.update(kw)
    return rec


def pick_home(entries, ofile, file_map):
    """Choose the NEW definition that continues the one in @ofile."""
    want = file_map.get(ofile, ofile)
    for e in entries:
        if e[0] in (ofile, want):
            return e, None
    if len(entries) == 1:
        return entries[0], None
    near = [e for e in entries
            if os.path.dirname(e[0]) == os.path.dirname(want)]
    if len(near) == 1:
        return near[0], None
    return entries[0], "also in " + ",".join(e[0] for e in entries[1:])


def set_commit(rec, c, exact):
    if c:
        rec["commit"], rec["subject"] = c["hash"], c["subject"]
        if not exact:
            rec["note"] = "lead" if not rec["note"] else rec["note"] + "; lead"


def map_kind(kind, old, new, hist, file_map, struct_map):
    """Yield one record per old definition of @kind."""
    olds, news = old.sym[kind], new.sym[kind]
    added = [n for n in news if n not in olds]
    for name in sorted(olds):
        many = len(olds[name]) > 1
        for ofile, oextra in olds[name]:
            others = {e[0] for e in olds[name]} - {ofile}
            rec = map_one(kind, name, ofile, oextra, old, new, hist,
                          file_map, struct_map, added, others)
            if rec is None:
                continue
            if many:
                rec["note"] = "; ".join(x for x in ("old " + ofile,
                                                    rec["note"]) if x)
            yield rec


def added_by(c, kind, added):
    """The names in @added that commit @c defines; cached per kind."""
    cache = c.setdefault("added", {})
    if kind not in cache:
        words = set(re.findall(r"\w+", c["plus_text"]))
        cache[kind] = [a for a in added
                       if leaf(kind, a).strip('"') in words and
                       re.search(decl_regex(kind, a), c["plus_text"], re.M)]
    return cache[kind]


def map_one(kind, name, ofile, oextra, old, new, hist, file_map, struct_map,
            added, others=()):
    news = new.sym[kind]
    nname = name
    note = None
    if kind == "field":
        sname, fld = name.split(".", 1)
        home = struct_map.get(sname, sname)
        if home is None:
            return None
        nname = "%s.%s" % (home, fld)
        if home != sname:
            note = "struct %s is now %s" % (sname, home)
    if nname in news:
        entries = [e for e in news[nname]
                   if file_map.get(e[0], e[0]) not in others and
                   e[0] not in others] or news[nname]
        (nfile, nextra), also = pick_home(entries, ofile, file_map)
        rec = record(kind, name, new=nname, file=nfile, note=note or also)
        # a move of the whole FEMU folder (hw/block/femu) is not a move
        if kind != "prop" and nfile != new.path + ofile[len(old.path):]:
            rec["status"] = "moved"
        if kind == "field" and nname != name:
            rec["status"] = "moved"
        if kind == "func" and oextra != nextra:
            rec["status"] = "redefined"
            rec["note"] = "%s -> %s" % (oextra, nextra)
        if kind == "prop":
            ov, nv = old.value(oextra), new.value(nextra)
            if ov != nv:
                rec["status"] = "default"
                rec["note"] = "default %s -> %s" % (norm(oextra),
                                                    norm(nextra))
                c = hist.default_change(name, ov, old) if hist else None
                set_commit(rec, c, True)
        if kind == "enum" and oextra != nextra:
            rec["status"] = "value"
            rec["note"] = "value %s -> %s" % (oextra, nextra)
        return rec
    rec = record(kind, name, status="removed", new=None, note=note)
    c, exact = hist.removal(kind, name) if hist else (None, False)
    set_commit(rec, c, exact)
    cand = None
    if c:
        pool = added_by(c, kind, added)
        if kind == "field":
            pool = [a.split(".", 1)[1] for a in pool
                    if a.startswith(home + ".")]
            cand, score = best_candidate(fld, pool)
            cand = cand and "%s.%s" % (home, cand)
        else:
            cand, score = best_candidate(name, pool)
        if cand and score >= MIN_SCORE:
            rec.update(status="candidate", new=cand,
                       file=news[cand][0][0],
                       note="; ".join(x for x in (rec["note"],
                                                  "score %.2f" % score) if x))
            return rec
    if kind == "field":
        homes = sorted(n for n in news
                       if n.rsplit(".", 1)[-1] == fld.rsplit(".", 1)[-1])
        if 0 < len(homes) <= MAX_HOMES:
            rec.update(status="candidate", new=",".join(homes),
                       file=news[homes[0]][0][0],
                       note="; ".join(x for x in (
                           rec["note"], "same field name in another struct")
                           if x))
    return rec


def follow_renames(repo, oldrev, newrev, path, new_files, hops=5):
    """Follow @path through the commits that renamed it, one at a time."""
    for _ in range(hops):
        out = git(repo, "log", "--reverse", "--no-renames", "--diff-filter=D",
                  "--format=%H", "%s..%s" % (oldrev, newrev), "--",
                  path).split()
        if not out:
            return None
        status = git(repo, "show", "-M25%", "--name-status", "--format=",
                     out[0])
        nxt = None
        for line in status.splitlines():
            parts = line.split("\t")
            if parts[0].startswith("R") and len(parts) == 3 and \
                    parts[1] == path:
                nxt = parts[2]
        if nxt is None:
            return None
        if nxt in new_files:
            return nxt
        path = nxt
    return None


def map_files(old, new, repo, oldrev, newrev):
    """Map old files: by git rename detection, then by where funcs went."""
    renames = {}
    out = git(repo, "diff", "-M40%", "--name-status", oldrev, newrev, "--",
              old.path, new.path)
    for line in out.splitlines():
        parts = line.split("\t")
        if parts[0].startswith("R") and len(parts) == 3:
            renames[parts[1]] = parts[2]
    homes = {}
    for fn, entries in old.sym["func"].items():
        if fn not in new.sym["func"]:
            continue
        nfiles = [e[0] for e in new.sym["func"][fn]]
        for ofile, _ in entries:
            if len(entries) == 1 or ofile in nfiles:
                homes.setdefault(ofile, set()).update(
                    [ofile] if ofile in nfiles else nfiles[:1])
    records = []
    file_map = {}
    for f in sorted(old.sym["file"]):
        rec = record("file", f, new=f, file=f)
        target = f if f in new.sym["file"] else renames.get(f)
        if target is None and f.startswith(old.path + "/"):
            moved = new.path + f[len(old.path):]
            if moved in new.sym["file"]:
                target = moved
        if target is None:
            target = follow_renames(repo, oldrev, newrev, f, new.sym["file"])
        if target is None:
            same = [n for n in new.sym["file"]
                    if os.path.basename(n) == os.path.basename(f)]
            if len(same) == 1:
                target = same[0]
        there = sorted(homes.get(f, ()))
        if target:
            file_map[f] = target
            rec.update(new=target, file=target)
            if target != new.path + f[len(old.path):]:
                rec["status"] = "moved"
            if len(there) > 1:
                rec.update(status="split", new=",".join(there))
        elif there:
            rec.update(status="split" if len(there) > 1 else "moved",
                       new=",".join(there), file=there[0])
            file_map[f] = there[0]
        else:
            rec.update(status="removed", new=None, file=None)
        if rec["status"] != "same" and target != f:
            out = git(repo, "log", "-1", "--no-renames", "--diff-filter=D",
                      "--format=%h %s", "%s..%s" % (oldrev, newrev), "--",
                      f).strip()
            if out:
                rec["commit"], _, rec["subject"] = out.partition(" ")
        records.append(rec)
    return records, file_map


def build_map(repo, oldrev, newrev, old_path=None, new_path="hw/femu",
              kinds=KINDS):
    for rev in (oldrev, newrev):
        git(repo, "rev-parse", "--verify", "-q", rev + "^{commit}")
    if old_path is None:
        old_path = "hw/femu" if has_path(repo, oldrev, "hw/femu") \
            else "hw/block/femu"
    for rev, p in ((oldrev, old_path), (newrev, new_path)):
        if not has_path(repo, rev, p):
            raise RuntimeError("%s has no %s" % (rev, p))
    old = Tree(repo, oldrev, old_path)
    new = Tree(repo, newrev, new_path)
    hist = History(repo, oldrev, newrev, sorted({old_path, new_path}))
    records, file_map = map_files(old, new, repo, oldrev, newrev)
    if "file" not in kinds:
        records = []
    struct_map = {}
    for kind in KINDS:
        if kind == "file":
            continue
        recs = list(map_kind(kind, old, new, hist, file_map, struct_map))
        if kind == "struct":
            for r in recs:
                struct_map.setdefault(r["old"], r["new"])
        if kind in kinds:
            records.extend(recs)
    return records


def print_text(records, show_all, out=sys.stdout):
    for r in records:
        if r["status"] == "same" and not show_all:
            continue
        cols = [r["kind"], r["old"], r["status"], r["new"] or "-",
                r["file"] or "-", r["commit"] or "-"]
        tail = []
        if r["note"]:
            tail.append(r["note"])
        if r["subject"]:
            tail.append(r["subject"])
        out.write("\t".join(cols + ["; ".join(tail) or "-"]) + "\n")


def touched_words(repo, rng):
    """Return the names on the changed lines of "git diff RANGE", and the
    paths that it changes."""
    if ".." not in rng:
        raise RuntimeError("--touched needs a range A..B, not %s" % rng)
    rng = rng.replace("...", "..")
    out = git(repo, "diff", "-U0", rng)
    words = set()
    for line in out.splitlines():
        if line.startswith("@@"):
            # git names the function around the hunk after the second @@
            words.update(re.findall(r"[A-Za-z_]\w*", line.split("@@", 2)[-1]))
        elif line.startswith(("+", "-")) and \
                not line.startswith(("+++", "---")):
            words.update(re.findall(r"[A-Za-z_][\w.-]*\w|[A-Za-z_]", line))
            words.update(re.findall(r"[A-Za-z_]\w*", line))
            words.update(re.findall(r'"([^"\s]+)"', line))
    for path in git(repo, "diff", "--name-only", rng).split():
        words.add(path)
    return words


def keep_touched(records, words):
    """Keep the records whose old name a changed line uses."""
    bases = {os.path.basename(w) for w in words}
    out = []
    for r in records:
        if r["kind"] == "file":
            base = os.path.basename(r["old"])
            if r["old"] in words or base in bases or \
                    base.rsplit(".", 1)[0] in words:
                out.append(r)
            continue
        if leaf(r["kind"], r["old"]).strip('"') in words:
            out.append(r)
    return out


def summary(records):
    count = {}
    for r in records:
        key = (r["kind"], r["status"])
        count[key] = count.get(key, 0) + 1
    return count


# ---------------------------------------------------------------- self-test

FIXTURE = {
    "hw/femu/ftl.c": """\
#include "ftl.h"
#define FTL_PAGES 4

struct line {
    int id;
    int vpc;
    int ipc;
    /* int ipc; */
};

static void clear_line(struct line *l)
{
    l->ipc = 0;
}

struct zone {
    int id;
    int wp;
};

struct ppa {
    union {
        struct {
            uint64_t blk : 16;
            uint64_t ch  : 7;
        } g;
        uint64_t ppa;
    };
};

static inline int get_ch(struct ssd *ssd)
{
    return 0;
}

static void ssd_init_lines(struct ssd *ssd)
{
}

uint64_t ssd_write(struct ssd *ssd, NvmeRequest *req)
{
    return 0;
}

static int do_gc(struct ssd *ssd, bool force)
{
    return 0;
}
""",
    "hw/femu/zns.c": """\
static inline int get_ch(struct zns *zns)
{
    return 1;
}

static uint16_t zns_read(FemuCtrl *n, NvmeRequest *req)
{
    return 0;
}
""",
    "hw/femu/nvme.h": """\
static inline bool BBSSD(FemuCtrl *n)
{
    return true;
}

enum { FEMU_OCSSD_MODE = 0, FEMU_BBSSD_MODE = 1, FEMU_SMARTSSD_MODE, };
enum { SHIFT_A = (1 << 2), SHIFT_B };
#define FEMU_DEF_MODE FEMU_OCSSD_MODE
""",
    "hw/femu/femu.c": """\
static Property femu_props[] = {
    DEFINE_PROP_UINT32("devsz_mb", FemuCtrl, memsz, 1024),
    DEFINE_PROP_UINT8("lnum_ch", FemuCtrl, oc.num_ch, 1),
    DEFINE_PROP_UINT8("femu_mode", FemuCtrl, femu_mode, FEMU_DEF_MODE),
    DEFINE_PROP_UINT32("shift_p", FemuCtrl, sp, (1 << 4)),
    DEFINE_PROP_UINT32("wide_p", FemuCtrl, wp,
                       4),
    DEFINE_PROP_END_OF_LIST(),
};

typedef struct QEMU_PACKED OcCmd {
    uint8_t opcode;
    uint16_t cid;
} OcCmd;
""",
    "hw/femu/old-util.c": """\
#include "mem-backend.h"
struct helper_state {
    int busy;
};

void old_helper(void)
{
}
""",
    "hw/femu/mem-backend.h": "void mem_init(void);\n",
    "hw/femu/timing.c": """\
int64_t set_latency(FemuCtrl *n)
{
    /* the channel and chip timing of OCSSD 1.2 */
    int64_t lat = 0;
    lat += 1;
    lat += 2;
    return lat;
}
""",
}

GC_FN = ("\nstatic int do_gc(struct ssd *ssd, bool force)\n"
         "{\n    return 0;\n}\n")

# (subject, [(path, old text or None to create, new text or None to delete)])
STEPS = [
    ("femu: move GC out of ftl.c", [
        ("hw/femu/ftl.c", GC_FN, "\n"),
        ("hw/femu/ftl-gc.c", None, GC_FN),
        ("hw/femu/notes.h", None, "/* old_helper: none */\n")]),
    ("femu: give the line init a clearer name", [
        ("hw/femu/ftl.c", "ssd_init_lines", "ssd_init_line_lists")]),
    ("femu: drop the invalid page count", [
        ("hw/femu/ftl.c", "    int ipc;\n", "")]),
    ("femu: drop the zone id", [
        ("hw/femu/ftl.c", "    int id;\n    int wp;\n", "    int wp;\n")]),
    ("femu: drop a stale comment", [
        ("hw/femu/ftl.c", "    /* int ipc; */\n", "")]),
    ("femu: stop clearing the old count", [
        ("hw/femu/ftl.c", "    l->ipc = 0;\n", "")]),
    ("femu: rename lnum_ch and raise the default size", [
        ("hw/femu/femu.c", '"lnum_ch"', '"lnum_chs"'),
        ("hw/femu/femu.c", "memsz, 1024", "memsz, 4096")]),
    ("femu: widen wide_p", [
        ("hw/femu/femu.c", "                       4),",
         "                       8),")]),
    ("femu: name the default mode", [
        ("hw/femu/nvme.h", "#define FEMU_DEF_MODE FEMU_OCSSD_MODE\n", ""),
        ("hw/femu/femu.c", "FEMU_DEF_MODE", "FEMU_OCSSD_MODE")]),
    ("femu/ocssd: name the command struct after its mode", [
        ("hw/femu/femu.c", "OcCmd", "Oc12Cmd"),
        ("hw/femu/femu.c", "OcCmd", "Oc12Cmd"),
        ("hw/femu/nvme.h", "FEMU_SMARTSSD_MODE",
         "FEMU_CSD_MODE = 2, FEMU_SMARTSSD_MODE"),
        ("hw/femu/nvme.h", "(1 << 2)", "(1 << 3)")]),
    ("femu/zns: time reads in the zone FTL", [
        ("hw/femu/zns.c", "static uint16_t zns_read(FemuCtrl *n,",
         "static uint64_t zns_read(struct zns_ssd *zns,"),
        ("hw/femu/zns.c", "static inline int get_ch(struct zns *zns)\n"
         "{\n    return 1;\n}\n\n", ""),
        ("hw/femu/zftl.c", None,
         "static inline int get_ch(struct zns *zns)\n{\n    return 1;\n}\n")]),
    ("femu/ocssd: move the timing model", [
        ("hw/femu/timing.c", "", None),
        ("hw/femu/oc-timing.c", None, None)]),
    ("femu: remove the old helper", [
        ("hw/femu/old-util.c", "", None),
        ("hw/femu/mem-backend.h", "", None)]),
    ("femu: reword a note", [
        ("hw/femu/notes.h", "none", "none left")]),
]


def apply_step(root, changes, saved):
    for path, old, new in changes:
        full = os.path.join(root, path)
        if old is None:
            text = new if new is not None else saved.pop()
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w") as f:
                f.write(text)
        elif new is None:
            with open(full) as f:
                saved.append(f.read())
            os.remove(full)
        else:
            with open(full) as f:
                text = f.read()
            if old not in text:
                raise RuntimeError("fixture: %r not in %s" % (old, path))
            with open(full, "w") as f:
                f.write(text.replace(old, new, 1))


def self_test():
    tmp = tempfile.mkdtemp(prefix="femu-symbol-map-")
    try:
        env = ["-c", "user.name=t", "-c", "user.email=t@example.com",
               "-c", "commit.gpgsign=false"]
        git(tmp, "init", "-q")
        apply_step(tmp, [(p, None, t) for p, t in FIXTURE.items()], [])
        git(tmp, "add", "-A")
        git(tmp, *env, "commit", "-q", "-m", "old")
        git(tmp, "tag", "old")
        hashes = {}
        for subject, changes in STEPS:
            apply_step(tmp, changes, [])
            git(tmp, "add", "-A")
            git(tmp, *env, "commit", "-q", "-m", subject)
            hashes[subject] = git(tmp, "rev-parse", "--short", "HEAD").strip()
        git(tmp, "switch", "-q", "-c", "fork", "old")
        apply_step(tmp, [
            ("hw/femu/ftl.c", "uint64_t ssd_write(struct ssd *ssd, "
             "NvmeRequest *req)\n{\n    return 0;",
             "uint64_t ssd_write(struct ssd *ssd, NvmeRequest *req)\n{\n"
             "    return 1;"),
            ("hw/femu/zns.c", "static inline", '#include "mem-backend.h"\n'
             "static inline")], [])
        git(tmp, *env, "commit", "-q", "-am", "fork: change the write path")
        git(tmp, "switch", "-q", "-")
        recs = build_map(tmp, "old", "HEAD")
        bad = 0
        words = touched_words(tmp, "old..fork")
        kept = {(r["kind"], r["old"]) for r in keep_touched(recs, words)}
        for key, want_in in ((("func", "ssd_write"), True),
                             (("func", "do_gc"), False),
                             (("file", "hw/femu/mem-backend.h"), True),
                             (("file", "hw/femu/zns.c"), True),
                             (("file", "hw/femu/timing.c"), False)):
            if (key in kept) != want_in:
                print("FAIL --touched: %s %s" %
                      (key, "missing" if want_in else "kept"))
                bad += 1
        got = {}
        for r in recs:
            got.setdefault((r["kind"], r["old"]), []).append(r)
        want = [
            # kind, old, status, new, subject of the commit (None: no commit)
            ("func", "ssd_write", "same", "ssd_write", None),
            ("func", "do_gc", "moved", "do_gc", None),
            ("func", "BBSSD", "same", "BBSSD", None),
            ("func", "set_latency", "moved", "set_latency", None),
            ("func", "zns_read", "redefined", "zns_read", None),
            ("func", "ssd_init_lines", "candidate", "ssd_init_line_lists",
             "femu: give the line init a clearer name"),
            ("func", "old_helper", "removed", None,
             "femu: remove the old helper"),
            ("field", "line.ipc", "removed", None,
             "femu: drop the invalid page count"),
            ("field", "zone.id", "candidate", "line.id",
             "femu: drop the zone id"),
            ("field", "line.vpc", "same", "line.vpc", None),
            ("field", "ppa.ppa", "same", "ppa.ppa", None),
            ("field", "ppa.g.ch", "same", "ppa.g.ch", None),
            ("prop", "lnum_ch", "candidate", "lnum_chs",
             "femu: rename lnum_ch and raise the default size"),
            ("prop", "devsz_mb", "default", "devsz_mb",
             "femu: rename lnum_ch and raise the default size"),
            ("prop", "wide_p", "default", "wide_p", "femu: widen wide_p"),
            ("prop", "shift_p", "same", "shift_p", None),
            ("prop", "femu_mode", "same", "femu_mode", None),
            ("enum", "FEMU_BBSSD_MODE", "same", "FEMU_BBSSD_MODE", None),
            ("enum", "FEMU_SMARTSSD_MODE", "value", "FEMU_SMARTSSD_MODE",
             None),
            ("enum", "SHIFT_B", "value", "SHIFT_B", None),
            ("macro", "FTL_PAGES", "same", "FTL_PAGES", None),
            ("macro", "FEMU_DEF_MODE", "removed", None,
             "femu: name the default mode"),
            ("struct", "line", "same", "line", None),
            ("struct", "OcCmd", "candidate", "Oc12Cmd",
             "femu/ocssd: name the command struct after its mode"),
            ("field", "OcCmd.cid", "moved", "Oc12Cmd.cid", None),
            ("struct", "helper_state", "removed", None,
             "femu: remove the old helper"),
            ("file", "hw/femu/ftl.c", "split",
             "hw/femu/ftl-gc.c,hw/femu/ftl.c", None),
            ("file", "hw/femu/timing.c", "moved", "hw/femu/oc-timing.c",
             "femu/ocssd: move the timing model"),
            ("file", "hw/femu/old-util.c", "removed", None,
             "femu: remove the old helper"),
        ]
        by_hash = {h: s for s, h in hashes.items()}
        for kind, name, status, new, subject in want:
            rs = got.get((kind, name))
            if not rs or len(rs) != 1:
                print("FAIL %s %s: %d records" % (kind, name, len(rs or [])))
                bad += 1
                continue
            r = rs[0]
            have = (r["status"], r["new"], by_hash.get(r["commit"]))
            if have != (status, new, subject):
                print("FAIL %s %s: got %s, want %s" %
                      (kind, name, have, (status, new, subject)))
                bad += 1
        notes = (
            (("enum", "FEMU_SMARTSSD_MODE"), "value 2 -> 3"),
            (("enum", "SHIFT_B"), "value 5 -> 9"),
            (("prop", "devsz_mb"), "default 1024 -> 4096"),
        )
        for key, note in notes:
            if got.get(key, [{}])[0].get("note") != note:
                print("FAIL %s note: %s" % (key, got.get(key)))
                bad += 1
        chs = sorted((r["status"], r["file"]) for r in got.get(
            ("func", "get_ch"), []))
        if chs != [("moved", "hw/femu/zftl.c"), ("same", "hw/femu/ftl.c")]:
            print("FAIL func get_ch: %s" % chs)
            bad += 1
        if ("field", "helper_state.busy") in got:
            print("FAIL a field of a removed struct was listed")
            bad += 1
        try:
            build_map(tmp, "old", "HEAD", new_path="hw/none")
            print("FAIL a missing path was accepted")
            bad += 1
        except RuntimeError:
            pass
        total = len(want) + len(notes) + 8
        print("self-test: %d of %d checks failed" % (bad, total))
        return 1 if bad else 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("old", nargs="?", help="old revision, e.g. femu-v9.0.1")
    ap.add_argument("new", nargs="?", help="new revision, e.g. origin/master")
    ap.add_argument("-C", dest="repo", default=".", help="git repository")
    ap.add_argument("--old-path", help="FEMU folder at OLD")
    ap.add_argument("--new-path", default="hw/femu", help="FEMU folder at NEW")
    ap.add_argument("--kind", default=",".join(KINDS),
                    help="comma-separated kinds: " + ",".join(KINDS))
    ap.add_argument("--all", action="store_true",
                    help="also print the symbols that did not change")
    ap.add_argument("--json", action="store_true", help="print JSON")
    ap.add_argument("--touched", metavar="A..B",
                    help="keep only the old names that \"git diff A..B\" "
                    "uses, for example the commits of a fork")
    ap.add_argument("--summary", action="store_true",
                    help="print only the count of each kind and status")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    if not args.old or not args.new:
        ap.error("OLD and NEW are required")
    kinds = tuple(k for k in args.kind.split(",") if k)
    unknown = [k for k in kinds if k not in KINDS]
    if unknown:
        ap.error("unknown kind: %s" % ",".join(unknown))
    try:
        recs = build_map(args.repo, args.old, args.new, args.old_path,
                         args.new_path, kinds)
        if args.touched:
            recs = keep_touched(recs, touched_words(args.repo, args.touched))
    except (RuntimeError, subprocess.CalledProcessError) as e:
        print("femu-symbol-map: %s" % e, file=sys.stderr)
        return 1
    if args.summary:
        for (kind, status), n in sorted(summary(recs).items()):
            print("%s\t%s\t%d" % (kind, status, n))
    elif args.json:
        json.dump([r for r in recs if args.all or r["status"] != "same"],
                  sys.stdout, indent=1)
        print()
    else:
        print_text(recs, args.all)
    return 0


if __name__ == "__main__":
    sys.exit(main())
