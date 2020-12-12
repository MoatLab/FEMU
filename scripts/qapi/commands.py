"""
QAPI command marshaller generator

Copyright IBM, Corp. 2011
Copyright (C) 2014-2018 Red Hat, Inc.

Authors:
 Anthony Liguori <aliguori@us.ibm.com>
 Michael Roth <mdroth@linux.vnet.ibm.com>
 Markus Armbruster <armbru@redhat.com>

This work is licensed under the terms of the GNU GPL, version 2.
See the COPYING file in the top-level directory.
"""

from typing import (
    Dict,
    List,
    Optional,
    Set,
)

from .common import c_name, mcgen
from .gen import (
    QAPIGenC,
    QAPIGenCCode,
    QAPISchemaModularCVisitor,
    build_params,
    ifcontext,
)
from .schema import (
    QAPISchema,
    QAPISchemaFeature,
    QAPISchemaObjectType,
    QAPISchemaType,
)
from .source import QAPISourceInfo


def gen_command_decl(name: str,
                     arg_type: Optional[QAPISchemaObjectType],
                     boxed: bool,
                     ret_type: Optional[QAPISchemaType]) -> str:
    return mcgen('''
%(c_type)s qmp_%(c_name)s(%(params)s);
''',
                 c_type=(ret_type and ret_type.c_type()) or 'void',
                 c_name=c_name(name),
                 params=build_params(arg_type, boxed, 'Error **errp'))


def gen_call(name: str,
             arg_type: Optional[QAPISchemaObjectType],
             boxed: bool,
             ret_type: Optional[QAPISchemaType]) -> str:
    ret = ''

    argstr = ''
    if boxed:
        assert arg_type
        argstr = '&arg, '
    elif arg_type:
        assert not arg_type.variants
        for memb in arg_type.members:
            if memb.optional:
                argstr += 'arg.has_%s, ' % c_name(memb.name)
            argstr += 'arg.%s, ' % c_name(memb.name)

    lhs = ''
    if ret_type:
        lhs = 'retval = '

    ret = mcgen('''

    %(lhs)sqmp_%(c_name)s(%(args)s&err);
    error_propagate(errp, err);
''',
                c_name=c_name(name), args=argstr, lhs=lhs)
    if ret_type:
        ret += mcgen('''
    if (err) {
        goto out;
    }

    qmp_marshal_output_%(c_name)s(retval, ret, errp);
''',
                     c_name=ret_type.c_name())
    return ret


def gen_marshal_output(ret_type: QAPISchemaType) -> str:
    return mcgen('''

static void qmp_marshal_output_%(c_name)s(%(c_type)s ret_in,
                                QObject **ret_out, Error **errp)
{
    Visitor *v;

    v = qobject_output_visitor_new(ret_out);
    if (visit_type_%(c_name)s(v, "unused", &ret_in, errp)) {
        visit_complete(v, ret_out);
    }
    visit_free(v);
    v = qapi_dealloc_visitor_new();
    visit_type_%(c_name)s(v, "unused", &ret_in, NULL);
    visit_free(v);
}
''',
                 c_type=ret_type.c_type(), c_name=ret_type.c_name())


def build_marshal_proto(name: str) -> str:
    return ('void qmp_marshal_%s(QDict *args, QObject **ret, Error **errp)'
            % c_name(name))


def gen_marshal_decl(name: str) -> str:
    return mcgen('''
%(proto)s;
''',
                 proto=build_marshal_proto(name))


def gen_marshal(name: str,
                arg_type: Optional[QAPISchemaObjectType],
                boxed: bool,
                ret_type: Optional[QAPISchemaType]) -> str:
    have_args = boxed or (arg_type and not arg_type.is_empty())

    ret = mcgen('''

%(proto)s
{
    Error *err = NULL;
    bool ok = false;
    Visitor *v;
''',
                proto=build_marshal_proto(name))

    if ret_type:
        ret += mcgen('''
    %(c_type)s retval;
''',
                     c_type=ret_type.c_type())

    if have_args:
        ret += mcgen('''
    %(c_name)s arg = {0};
''',
                     c_name=arg_type.c_name())

    ret += mcgen('''

    v = qobject_input_visitor_new(QOBJECT(args));
    if (!visit_start_struct(v, NULL, NULL, 0, errp)) {
        goto out;
    }
''')

    if have_args:
        ret += mcgen('''
    if (visit_type_%(c_arg_type)s_members(v, &arg, errp)) {
        ok = visit_check_struct(v, errp);
    }
''',
                     c_arg_type=arg_type.c_name())
    else:
        ret += mcgen('''
    ok = visit_check_struct(v, errp);
''')

    ret += mcgen('''
    visit_end_struct(v, NULL);
    if (!ok) {
        goto out;
    }
''')

    ret += gen_call(name, arg_type, boxed, ret_type)

    ret += mcgen('''

out:
    visit_free(v);
''')

    ret += mcgen('''
    v = qapi_dealloc_visitor_new();
    visit_start_struct(v, NULL, NULL, 0, NULL);
''')

    if have_args:
        ret += mcgen('''
    visit_type_%(c_arg_type)s_members(v, &arg, NULL);
''',
                     c_arg_type=arg_type.c_name())

    ret += mcgen('''
    visit_end_struct(v, NULL);
    visit_free(v);
''')

    ret += mcgen('''
}
''')
    return ret


def gen_register_command(name: str,
                         success_response: bool,
                         allow_oob: bool,
                         allow_preconfig: bool,
                         coroutine: bool) -> str:
    options = []

    if not success_response:
        options += ['QCO_NO_SUCCESS_RESP']
    if allow_oob:
        options += ['QCO_ALLOW_OOB']
    if allow_preconfig:
        options += ['QCO_ALLOW_PRECONFIG']
    if coroutine:
        options += ['QCO_COROUTINE']

    if not options:
        options = ['QCO_NO_OPTIONS']

    ret = mcgen('''
    qmp_register_command(cmds, "%(name)s",
                         qmp_marshal_%(c_name)s, %(opts)s);
''',
                name=name, c_name=c_name(name),
                opts=" | ".join(options))
    return ret


def gen_registry(registry: str, prefix: str) -> str:
    ret = mcgen('''

void %(c_prefix)sqmp_init_marshal(QmpCommandList *cmds)
{
    QTAILQ_INIT(cmds);

''',
                c_prefix=c_name(prefix, protect=False))
    ret += registry
    ret += mcgen('''
}
''')
    return ret


class QAPISchemaGenCommandVisitor(QAPISchemaModularCVisitor):
    def __init__(self, prefix: str):
        super().__init__(
            prefix, 'qapi-commands',
            ' * Schema-defined QAPI/QMP commands', None, __doc__)
        self._regy = QAPIGenCCode(None)
        self._visited_ret_types: Dict[QAPIGenC, Set[QAPISchemaType]] = {}

    def _begin_user_module(self, name: str) -> None:
        self._visited_ret_types[self._genc] = set()
        commands = self._module_basename('qapi-commands', name)
        types = self._module_basename('qapi-types', name)
        visit = self._module_basename('qapi-visit', name)
        self._genc.add(mcgen('''
#include "qemu/osdep.h"
#include "qapi/visitor.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qobject-output-visitor.h"
#include "qapi/qobject-input-visitor.h"
#include "qapi/dealloc-visitor.h"
#include "qapi/error.h"
#include "%(visit)s.h"
#include "%(commands)s.h"

''',
                             commands=commands, visit=visit))
        self._genh.add(mcgen('''
#include "%(types)s.h"

''',
                             types=types))

    def visit_end(self) -> None:
        self._add_system_module('init', ' * QAPI Commands initialization')
        self._genh.add(mcgen('''
#include "qapi/qmp/dispatch.h"

void %(c_prefix)sqmp_init_marshal(QmpCommandList *cmds);
''',
                             c_prefix=c_name(self._prefix, protect=False)))
        self._genc.preamble_add(mcgen('''
#include "qemu/osdep.h"
#include "%(prefix)sqapi-commands.h"
#include "%(prefix)sqapi-init-commands.h"
''',
                                      prefix=self._prefix))
        self._genc.add(gen_registry(self._regy.get_content(), self._prefix))

    def visit_command(self,
                      name: str,
                      info: QAPISourceInfo,
                      ifcond: List[str],
                      features: List[QAPISchemaFeature],
                      arg_type: Optional[QAPISchemaObjectType],
                      ret_type: Optional[QAPISchemaType],
                      gen: bool,
                      success_response: bool,
                      boxed: bool,
                      allow_oob: bool,
                      allow_preconfig: bool,
                      coroutine: bool) -> None:
        if not gen:
            return
        # FIXME: If T is a user-defined type, the user is responsible
        # for making this work, i.e. to make T's condition the
        # conjunction of the T-returning commands' conditions.  If T
        # is a built-in type, this isn't possible: the
        # qmp_marshal_output_T() will be generated unconditionally.
        if ret_type and ret_type not in self._visited_ret_types[self._genc]:
            self._visited_ret_types[self._genc].add(ret_type)
            with ifcontext(ret_type.ifcond,
                           self._genh, self._genc, self._regy):
                self._genc.add(gen_marshal_output(ret_type))
        with ifcontext(ifcond, self._genh, self._genc, self._regy):
            self._genh.add(gen_command_decl(name, arg_type, boxed, ret_type))
            self._genh.add(gen_marshal_decl(name))
            self._genc.add(gen_marshal(name, arg_type, boxed, ret_type))
            self._regy.add(gen_register_command(name, success_response,
                                                allow_oob, allow_preconfig,
                                                coroutine))


def gen_commands(schema: QAPISchema,
                 output_dir: str,
                 prefix: str) -> None:
    vis = QAPISchemaGenCommandVisitor(prefix)
    schema.visit(vis)
    vis.write(output_dir)
