#!/usr/bin/env python3

##
##  Copyright(c) 2019-2023 Qualcomm Innovation Center, Inc. All Rights Reserved.
##
##  This program is free software; you can redistribute it and/or modify
##  it under the terms of the GNU General Public License as published by
##  the Free Software Foundation; either version 2 of the License, or
##  (at your option) any later version.
##
##  This program is distributed in the hope that it will be useful,
##  but WITHOUT ANY WARRANTY; without even the implied warranty of
##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##  GNU General Public License for more details.
##
##  You should have received a copy of the GNU General Public License
##  along with this program; if not, see <http://www.gnu.org/licenses/>.
##

import sys
import re
import string

behdict = {}          # tag ->behavior
semdict = {}          # tag -> semantics
attribdict = {}       # tag -> attributes
macros = {}           # macro -> macro information...
attribinfo = {}       # Register information and misc
tags = []             # list of all tags
overrides = {}        # tags with helper overrides
idef_parser_enabled = {} # tags enabled for idef-parser

# We should do this as a hash for performance,
# but to keep order let's keep it as a list.
def uniquify(seq):
    seen = set()
    seen_add = seen.add
    return [x for x in seq if x not in seen and not seen_add(x)]

regre = re.compile(
    r"((?<!DUP)[MNORCPQXSGVZA])([stuvwxyzdefg]+)([.]?[LlHh]?)(\d+S?)")
immre = re.compile(r"[#]([rRsSuUm])(\d+)(?:[:](\d+))?")
reg_or_immre = \
    re.compile(r"(((?<!DUP)[MNRCOPQXSGVZA])([stuvwxyzdefg]+)" + \
                "([.]?[LlHh]?)(\d+S?))|([#]([rRsSuUm])(\d+)[:]?(\d+)?)")
relimmre = re.compile(r"[#]([rR])(\d+)(?:[:](\d+))?")
absimmre = re.compile(r"[#]([sSuUm])(\d+)(?:[:](\d+))?")

finished_macros = set()

def expand_macro_attribs(macro,allmac_re):
    if macro.key not in finished_macros:
        # Get a list of all things that might be macros
        l = allmac_re.findall(macro.beh)
        for submacro in l:
            if not submacro: continue
            if not macros[submacro]:
                raise Exception("Couldn't find macro: <%s>" % l)
            macro.attribs |= expand_macro_attribs(
                macros[submacro], allmac_re)
            finished_macros.add(macro.key)
    return macro.attribs

# When qemu needs an attribute that isn't in the imported files,
# we'll add it here.
def add_qemu_macro_attrib(name, attrib):
    macros[name].attribs.add(attrib)

immextre = re.compile(r'f(MUST_)?IMMEXT[(]([UuSsRr])')

def is_cond_jump(tag):
    if tag == 'J2_rte':
        return False
    if ('A_HWLOOP0_END' in attribdict[tag] or
        'A_HWLOOP1_END' in attribdict[tag]):
        return False
    return \
        re.compile(r"(if.*fBRANCH)|(if.*fJUMPR)").search(semdict[tag]) != None

def is_cond_call(tag):
    return re.compile(r"(if.*fCALL)").search(semdict[tag]) != None

def calculate_attribs():
    add_qemu_macro_attrib('fREAD_PC', 'A_IMPLICIT_READS_PC')
    add_qemu_macro_attrib('fTRAP', 'A_IMPLICIT_READS_PC')
    add_qemu_macro_attrib('fWRITE_P0', 'A_WRITES_PRED_REG')
    add_qemu_macro_attrib('fWRITE_P1', 'A_WRITES_PRED_REG')
    add_qemu_macro_attrib('fWRITE_P2', 'A_WRITES_PRED_REG')
    add_qemu_macro_attrib('fWRITE_P3', 'A_WRITES_PRED_REG')
    add_qemu_macro_attrib('fSET_OVERFLOW', 'A_IMPLICIT_WRITES_USR')
    add_qemu_macro_attrib('fSET_LPCFG', 'A_IMPLICIT_WRITES_USR')
    add_qemu_macro_attrib('fLOAD', 'A_SCALAR_LOAD')
    add_qemu_macro_attrib('fSTORE', 'A_SCALAR_STORE')

    # Recurse down macros, find attributes from sub-macros
    macroValues = list(macros.values())
    allmacros_restr = "|".join(set([ m.re.pattern for m in macroValues ]))
    allmacros_re = re.compile(allmacros_restr)
    for macro in macroValues:
        expand_macro_attribs(macro,allmacros_re)
    # Append attributes to all instructions
    for tag in tags:
        for macname in allmacros_re.findall(semdict[tag]):
            if not macname: continue
            macro = macros[macname]
            attribdict[tag] |= set(macro.attribs)
    # Figure out which instructions write predicate registers
    tagregs = get_tagregs()
    for tag in tags:
        regs = tagregs[tag]
        for regtype, regid, toss, numregs in regs:
            if regtype == "P" and is_written(regid):
                attribdict[tag].add('A_WRITES_PRED_REG')
    # Mark conditional jumps and calls
    #     Not all instructions are properly marked with A_CONDEXEC
    for tag in tags:
        if is_cond_jump(tag) or is_cond_call(tag):
            attribdict[tag].add('A_CONDEXEC')

def SEMANTICS(tag, beh, sem):
    #print tag,beh,sem
    behdict[tag] = beh
    semdict[tag] = sem
    attribdict[tag] = set()
    tags.append(tag)        # dicts have no order, this is for order

def ATTRIBUTES(tag, attribstring):
    attribstring = \
        attribstring.replace("ATTRIBS","").replace("(","").replace(")","")
    if not attribstring:
        return
    attribs = attribstring.split(",")
    for attrib in attribs:
        attribdict[tag].add(attrib.strip())

class Macro(object):
    __slots__ = ['key','name', 'beh', 'attribs', 're']
    def __init__(self, name, beh, attribs):
        self.key = name
        self.name = name
        self.beh = beh
        self.attribs = set(attribs)
        self.re = re.compile("\\b" + name + "\\b")

def MACROATTRIB(macname,beh,attribstring):
    attribstring = attribstring.replace("(","").replace(")","")
    if attribstring:
        attribs = attribstring.split(",")
    else:
        attribs = []
    macros[macname] = Macro(macname,beh,attribs)

def compute_tag_regs(tag):
    return uniquify(regre.findall(behdict[tag]))

def compute_tag_immediates(tag):
    return uniquify(immre.findall(behdict[tag]))

##
##  tagregs is the main data structure we'll use
##  tagregs[tag] will contain the registers used by an instruction
##  Within each entry, we'll use the regtype and regid fields
##      regtype can be one of the following
##          C                control register
##          N                new register value
##          P                predicate register
##          R                GPR register
##          M                modifier register
##          Q                HVX predicate vector
##          V                HVX vector register
##          O                HVX new vector register
##      regid can be one of the following
##          d, e             destination register
##          dd               destination register pair
##          s, t, u, v, w    source register
##          ss, tt, uu, vv   source register pair
##          x, y             read-write register
##          xx, yy           read-write register pair
##
def get_tagregs():
    return dict(zip(tags, list(map(compute_tag_regs, tags))))

def get_tagimms():
    return dict(zip(tags, list(map(compute_tag_immediates, tags))))

def is_pair(regid):
    return len(regid) == 2

def is_single(regid):
    return len(regid) == 1

def is_written(regid):
    return regid[0] in "dexy"

def is_writeonly(regid):
    return regid[0] in "de"

def is_read(regid):
    return regid[0] in "stuvwxy"

def is_readwrite(regid):
    return regid[0] in "xy"

def is_scalar_reg(regtype):
    return regtype in "RPC"

def is_hvx_reg(regtype):
    return regtype in "VQ"

def is_old_val(regtype, regid, tag):
    return regtype+regid+'V' in semdict[tag]

def is_new_val(regtype, regid, tag):
    return regtype+regid+'N' in semdict[tag]

def need_slot(tag):
    if (('A_CONDEXEC' in attribdict[tag] and
         'A_JUMP' not in attribdict[tag]) or
        'A_STORE' in attribdict[tag] or
        'A_LOAD' in attribdict[tag]):
        return 1
    else:
        return 0

def need_part1(tag):
    return re.compile(r"fPART1").search(semdict[tag])

def need_ea(tag):
    return re.compile(r"\bEA\b").search(semdict[tag])

def need_PC(tag):
    return 'A_IMPLICIT_READS_PC' in attribdict[tag]

def helper_needs_next_PC(tag):
    return 'A_CALL' in attribdict[tag]

def need_pkt_has_multi_cof(tag):
    return 'A_COF' in attribdict[tag]

def need_condexec_reg(tag, regs):
    if 'A_CONDEXEC' in attribdict[tag]:
        for regtype, regid, toss, numregs in regs:
            if is_writeonly(regid) and not is_hvx_reg(regtype):
                return True
    return False

def skip_qemu_helper(tag):
    return tag in overrides.keys()

def is_tmp_result(tag):
    return ('A_CVI_TMP' in attribdict[tag] or
            'A_CVI_TMP_DST' in attribdict[tag])

def is_new_result(tag):
    return ('A_CVI_NEW' in attribdict[tag])

def is_idef_parser_enabled(tag):
    return tag in idef_parser_enabled

def imm_name(immlett):
    return "%siV" % immlett

def read_semantics_file(name):
    eval_line = ""
    for line in open(name, 'rt').readlines():
        if not line.startswith("#"):
            eval_line += line
            if line.endswith("\\\n"):
                eval_line.rstrip("\\\n")
            else:
                eval(eval_line.strip())
                eval_line = ""

def read_attribs_file(name):
    attribre = re.compile(r'DEF_ATTRIB\(([A-Za-z0-9_]+), ([^,]*), ' +
            r'"([A-Za-z0-9_\.]*)", "([A-Za-z0-9_\.]*)"\)')
    for line in open(name, 'rt').readlines():
        if not attribre.match(line):
            continue
        (attrib_base,descr,rreg,wreg) = attribre.findall(line)[0]
        attrib_base = 'A_' + attrib_base
        attribinfo[attrib_base] = {'rreg':rreg, 'wreg':wreg, 'descr':descr}

def read_overrides_file(name):
    overridere = re.compile("#define fGEN_TCG_([A-Za-z0-9_]+)\(.*")
    for line in open(name, 'rt').readlines():
        if not overridere.match(line):
            continue
        tag = overridere.findall(line)[0]
        overrides[tag] = True

def read_idef_parser_enabled_file(name):
    global idef_parser_enabled
    with open(name, "r") as idef_parser_enabled_file:
        lines = idef_parser_enabled_file.read().strip().split("\n")
        idef_parser_enabled = set(lines)
