#!/usr/bin/env python3
# Copyright 2016-2017 The Meson development team

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import typing as T
import stat
import subprocess
import re
import json
import tempfile
import textwrap
import os
import shutil
import sys
import unittest
import platform
import pickle
import functools
import io
import operator
import threading
import urllib.error
import urllib.request
import zipfile
import hashlib
from itertools import chain
from unittest import mock
from configparser import ConfigParser
from contextlib import contextmanager
from glob import glob
from pathlib import (PurePath, Path)
from distutils.dir_util import copy_tree
import typing as T

import mesonbuild.mlog
import mesonbuild.depfile
import mesonbuild.dependencies.base
import mesonbuild.compilers
import mesonbuild.envconfig
import mesonbuild.environment
import mesonbuild.mesonlib
import mesonbuild.coredata
import mesonbuild.modules.gnome
from mesonbuild.interpreter import Interpreter, ObjectHolder
from mesonbuild.ast import AstInterpreter
from mesonbuild.mesonlib import (
    BuildDirLock, LibType, MachineChoice, PerMachine, Version, is_windows,
    is_osx, is_cygwin, is_dragonflybsd, is_openbsd, is_haiku, is_sunos,
    windows_proof_rmtree, python_command, version_compare, split_args,
    quote_arg, relpath, is_linux
)
from mesonbuild.environment import detect_ninja
from mesonbuild.mesonlib import MesonException, EnvironmentException
from mesonbuild.dependencies import PkgConfigDependency, ExternalProgram
import mesonbuild.dependencies.base
from mesonbuild.build import Target, ConfigurationData
import mesonbuild.modules.pkgconfig

from mesonbuild.mtest import TAPParser, TestResult

from run_tests import (
    Backend, FakeBuild, FakeCompilerOptions,
    ensure_backend_detects_changes, exe_suffix, get_backend_commands,
    get_builddir_target_args, get_fake_env, get_fake_options, get_meson_script,
    run_configure_inprocess, run_mtest_inprocess
)


URLOPEN_TIMEOUT = 5

@contextmanager
def chdir(path: str):
    curdir = os.getcwd()
    os.chdir(path)
    yield
    os.chdir(curdir)


def get_dynamic_section_entry(fname, entry):
    if is_cygwin() or is_osx():
        raise unittest.SkipTest('Test only applicable to ELF platforms')

    try:
        raw_out = subprocess.check_output(['readelf', '-d', fname],
                                          universal_newlines=True)
    except FileNotFoundError:
        # FIXME: Try using depfixer.py:Elf() as a fallback
        raise unittest.SkipTest('readelf not found')
    pattern = re.compile(entry + r': \[(.*?)\]')
    for line in raw_out.split('\n'):
        m = pattern.search(line)
        if m is not None:
            return m.group(1)
    return None # The file did not contain the specified entry.

def get_soname(fname):
    return get_dynamic_section_entry(fname, 'soname')

def get_rpath(fname):
    return get_dynamic_section_entry(fname, r'(?:rpath|runpath)')

def is_tarball():
    if not os.path.isdir('docs'):
        return True
    return False

def is_ci():
    if 'CI' in os.environ:
        return True
    return False

def is_pull():
    # Travis
    if os.environ.get('TRAVIS_PULL_REQUEST', 'false') != 'false':
        return True
    # Azure
    if 'SYSTEM_PULLREQUEST_ISFORK' in os.environ:
        return True
    return False

def _git_init(project_dir):
    subprocess.check_call(['git', 'init'], cwd=project_dir, stdout=subprocess.DEVNULL)
    subprocess.check_call(['git', 'config',
                           'user.name', 'Author Person'], cwd=project_dir)
    subprocess.check_call(['git', 'config',
                           'user.email', 'teh_coderz@example.com'], cwd=project_dir)
    subprocess.check_call('git add *', cwd=project_dir, shell=True,
                          stdout=subprocess.DEVNULL)
    subprocess.check_call(['git', 'commit', '-a', '-m', 'I am a project'], cwd=project_dir,
                          stdout=subprocess.DEVNULL)

@functools.lru_cache()
def is_real_gnu_compiler(path):
    '''
    Check if the gcc we have is a real gcc and not a macOS wrapper around clang
    '''
    if not path:
        return False
    out = subprocess.check_output([path, '--version'], universal_newlines=True, stderr=subprocess.STDOUT)
    return 'Free Software Foundation' in out

def skipIfNoExecutable(exename):
    '''
    Skip this test if the given executable is not found.
    '''
    def wrapper(func):
        @functools.wraps(func)
        def wrapped(*args, **kwargs):
            if shutil.which(exename) is None:
                raise unittest.SkipTest(exename + ' not found')
            return func(*args, **kwargs)
        return wrapped
    return wrapper

def skipIfNoPkgconfig(f):
    '''
    Skip this test if no pkg-config is found, unless we're on CI.
    This allows users to run our test suite without having
    pkg-config installed on, f.ex., macOS, while ensuring that our CI does not
    silently skip the test because of misconfiguration.

    Note: Yes, we provide pkg-config even while running Windows CI
    '''
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        if not is_ci() and shutil.which('pkg-config') is None:
            raise unittest.SkipTest('pkg-config not found')
        return f(*args, **kwargs)
    return wrapped

def skipIfNoPkgconfigDep(depname):
    '''
    Skip this test if the given pkg-config dep is not found, unless we're on CI.
    '''
    def wrapper(func):
        @functools.wraps(func)
        def wrapped(*args, **kwargs):
            if not is_ci() and shutil.which('pkg-config') is None:
                raise unittest.SkipTest('pkg-config not found')
            if not is_ci() and subprocess.call(['pkg-config', '--exists', depname]) != 0:
                raise unittest.SkipTest('pkg-config dependency {} not found.'.format(depname))
            return func(*args, **kwargs)
        return wrapped
    return wrapper

def skip_if_no_cmake(f):
    '''
    Skip this test if no cmake is found, unless we're on CI.
    This allows users to run our test suite without having
    cmake installed on, f.ex., macOS, while ensuring that our CI does not
    silently skip the test because of misconfiguration.
    '''
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        if not is_ci() and shutil.which('cmake') is None:
            raise unittest.SkipTest('cmake not found')
        return f(*args, **kwargs)
    return wrapped

def skip_if_not_language(lang):
    def wrapper(func):
        @functools.wraps(func)
        def wrapped(*args, **kwargs):
            try:
                env = get_fake_env()
                f = getattr(env, 'detect_{}_compiler'.format(lang))
                f(MachineChoice.HOST)
            except EnvironmentException:
                raise unittest.SkipTest('No {} compiler found.'.format(lang))
            return func(*args, **kwargs)
        return wrapped
    return wrapper

def skip_if_env_set(key):
    '''
    Skip a test if a particular env is set, except when running under CI
    '''
    def wrapper(func):
        @functools.wraps(func)
        def wrapped(*args, **kwargs):
            old = None
            if key in os.environ:
                if not is_ci():
                    raise unittest.SkipTest('Env var {!r} set, skipping'.format(key))
                old = os.environ.pop(key)
            try:
                return func(*args, **kwargs)
            finally:
                if old is not None:
                    os.environ[key] = old
        return wrapped
    return wrapper

def skip_if_not_base_option(feature):
    """Skip tests if The compiler does not support a given base option.

    for example, ICC doesn't currently support b_sanitize.
    """
    def actual(f):
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            env = get_fake_env()
            cc = env.detect_c_compiler(MachineChoice.HOST)
            if feature not in cc.base_options:
                raise unittest.SkipTest(
                    '{} not available with {}'.format(feature, cc.id))
            return f(*args, **kwargs)
        return wrapped
    return actual


@contextmanager
def temp_filename():
    '''A context manager which provides a filename to an empty temporary file.

    On exit the file will be deleted.
    '''

    fd, filename = tempfile.mkstemp()
    os.close(fd)
    try:
        yield filename
    finally:
        try:
            os.remove(filename)
        except OSError:
            pass

@contextmanager
def no_pkgconfig():
    '''
    A context manager that overrides shutil.which and ExternalProgram to force
    them to return None for pkg-config to simulate it not existing.
    '''
    old_which = shutil.which
    old_search = ExternalProgram._search

    def new_search(self, name, search_dir):
        if name == 'pkg-config':
            return [None]
        return old_search(self, name, search_dir)

    def new_which(cmd, *kwargs):
        if cmd == 'pkg-config':
            return None
        return old_which(cmd, *kwargs)

    shutil.which = new_which
    ExternalProgram._search = new_search
    try:
        yield
    finally:
        shutil.which = old_which
        ExternalProgram._search = old_search


class InternalTests(unittest.TestCase):

    def test_version_number(self):
        searchfunc = mesonbuild.environment.search_version
        self.assertEqual(searchfunc('foobar 1.2.3'), '1.2.3')
        self.assertEqual(searchfunc('1.2.3'), '1.2.3')
        self.assertEqual(searchfunc('foobar 2016.10.28 1.2.3'), '1.2.3')
        self.assertEqual(searchfunc('2016.10.28 1.2.3'), '1.2.3')
        self.assertEqual(searchfunc('foobar 2016.10.128'), '2016.10.128')
        self.assertEqual(searchfunc('2016.10.128'), '2016.10.128')
        self.assertEqual(searchfunc('2016.10'), '2016.10')
        self.assertEqual(searchfunc('2016.10 1.2.3'), '1.2.3')
        self.assertEqual(searchfunc('oops v1.2.3'), '1.2.3')
        self.assertEqual(searchfunc('2016.oops 1.2.3'), '1.2.3')
        self.assertEqual(searchfunc('2016.x'), 'unknown version')


    def test_mode_symbolic_to_bits(self):
        modefunc = mesonbuild.mesonlib.FileMode.perms_s_to_bits
        self.assertEqual(modefunc('---------'), 0)
        self.assertEqual(modefunc('r--------'), stat.S_IRUSR)
        self.assertEqual(modefunc('---r-----'), stat.S_IRGRP)
        self.assertEqual(modefunc('------r--'), stat.S_IROTH)
        self.assertEqual(modefunc('-w-------'), stat.S_IWUSR)
        self.assertEqual(modefunc('----w----'), stat.S_IWGRP)
        self.assertEqual(modefunc('-------w-'), stat.S_IWOTH)
        self.assertEqual(modefunc('--x------'), stat.S_IXUSR)
        self.assertEqual(modefunc('-----x---'), stat.S_IXGRP)
        self.assertEqual(modefunc('--------x'), stat.S_IXOTH)
        self.assertEqual(modefunc('--S------'), stat.S_ISUID)
        self.assertEqual(modefunc('-----S---'), stat.S_ISGID)
        self.assertEqual(modefunc('--------T'), stat.S_ISVTX)
        self.assertEqual(modefunc('--s------'), stat.S_ISUID | stat.S_IXUSR)
        self.assertEqual(modefunc('-----s---'), stat.S_ISGID | stat.S_IXGRP)
        self.assertEqual(modefunc('--------t'), stat.S_ISVTX | stat.S_IXOTH)
        self.assertEqual(modefunc('rwx------'), stat.S_IRWXU)
        self.assertEqual(modefunc('---rwx---'), stat.S_IRWXG)
        self.assertEqual(modefunc('------rwx'), stat.S_IRWXO)
        # We could keep listing combinations exhaustively but that seems
        # tedious and pointless. Just test a few more.
        self.assertEqual(modefunc('rwxr-xr-x'),
                         stat.S_IRWXU |
                         stat.S_IRGRP | stat.S_IXGRP |
                         stat.S_IROTH | stat.S_IXOTH)
        self.assertEqual(modefunc('rw-r--r--'),
                         stat.S_IRUSR | stat.S_IWUSR |
                         stat.S_IRGRP |
                         stat.S_IROTH)
        self.assertEqual(modefunc('rwsr-x---'),
                         stat.S_IRWXU | stat.S_ISUID |
                         stat.S_IRGRP | stat.S_IXGRP)

    def test_compiler_args_class_none_flush(self):
        cc = mesonbuild.compilers.CCompiler([], 'fake', False, MachineChoice.HOST, mock.Mock())
        a = cc.compiler_args(['-I.'])
        #first we are checking if the tree construction deduplicates the correct -I argument
        a += ['-I..']
        a += ['-I./tests/']
        a += ['-I./tests2/']
        #think this here as assertion, we cannot apply it, otherwise the CompilerArgs would already flush the changes:
        # assertEqual(a, ['-I.', '-I./tests2/', '-I./tests/', '-I..', '-I.'])
        a += ['-I.']
        a += ['-I.', '-I./tests/']
        self.assertEqual(a, ['-I.', '-I./tests/', '-I./tests2/', '-I..'])

        #then we are checking that when CompilerArgs already have a build container list, that the deduplication is taking the correct one
        a += ['-I.', '-I./tests2/']
        self.assertEqual(a, ['-I.', '-I./tests2/', '-I./tests/', '-I..'])

    def test_compiler_args_class_d(self):
        d = mesonbuild.compilers.DCompiler([], 'fake', MachineChoice.HOST, 'info', 'arch', False, None)
        # check include order is kept when deduplicating
        a = d.compiler_args(['-Ifirst', '-Isecond', '-Ithird'])
        a += ['-Ifirst']
        self.assertEqual(a, ['-Ifirst', '-Isecond', '-Ithird'])

    def test_compiler_args_class(self):
        cc = mesonbuild.compilers.CCompiler([], 'fake', False, MachineChoice.HOST, mock.Mock())
        # Test that empty initialization works
        a = cc.compiler_args()
        self.assertEqual(a, [])
        # Test that list initialization works
        a = cc.compiler_args(['-I.', '-I..'])
        self.assertEqual(a, ['-I.', '-I..'])
        # Test that there is no de-dup on initialization
        self.assertEqual(cc.compiler_args(['-I.', '-I.']), ['-I.', '-I.'])

        ## Test that appending works
        a.append('-I..')
        self.assertEqual(a, ['-I..', '-I.'])
        a.append('-O3')
        self.assertEqual(a, ['-I..', '-I.', '-O3'])

        ## Test that in-place addition works
        a += ['-O2', '-O2']
        self.assertEqual(a, ['-I..', '-I.', '-O3', '-O2', '-O2'])
        # Test that removal works
        a.remove('-O2')
        self.assertEqual(a, ['-I..', '-I.', '-O3', '-O2'])
        # Test that de-dup happens on addition
        a += ['-Ifoo', '-Ifoo']
        self.assertEqual(a, ['-Ifoo', '-I..', '-I.', '-O3', '-O2'])

        # .extend() is just +=, so we don't test it

        ## Test that addition works
        # Test that adding a list with just one old arg works and yields the same array
        a = a + ['-Ifoo']
        self.assertEqual(a, ['-Ifoo', '-I..', '-I.', '-O3', '-O2'])
        # Test that adding a list with one arg new and one old works
        a = a + ['-Ifoo', '-Ibaz']
        self.assertEqual(a, ['-Ifoo', '-Ibaz', '-I..', '-I.', '-O3', '-O2'])
        # Test that adding args that must be prepended and appended works
        a = a + ['-Ibar', '-Wall']
        self.assertEqual(a, ['-Ibar', '-Ifoo', '-Ibaz', '-I..', '-I.', '-O3', '-O2', '-Wall'])

        ## Test that reflected addition works
        # Test that adding to a list with just one old arg works and yields the same array
        a = ['-Ifoo'] + a
        self.assertEqual(a, ['-Ibar', '-Ifoo', '-Ibaz', '-I..', '-I.', '-O3', '-O2', '-Wall'])
        # Test that adding to a list with just one new arg that is not pre-pended works
        a = ['-Werror'] + a
        self.assertEqual(a, ['-Ibar', '-Ifoo', '-Ibaz', '-I..', '-I.', '-Werror', '-O3', '-O2', '-Wall'])
        # Test that adding to a list with two new args preserves the order
        a = ['-Ldir', '-Lbah'] + a
        self.assertEqual(a, ['-Ibar', '-Ifoo', '-Ibaz', '-I..', '-I.', '-Ldir', '-Lbah', '-Werror', '-O3', '-O2', '-Wall'])
        # Test that adding to a list with old args does nothing
        a = ['-Ibar', '-Ibaz', '-Ifoo'] + a
        self.assertEqual(a, ['-Ibar', '-Ifoo', '-Ibaz', '-I..', '-I.', '-Ldir', '-Lbah', '-Werror', '-O3', '-O2', '-Wall'])

        ## Test that adding libraries works
        l = cc.compiler_args(['-Lfoodir', '-lfoo'])
        self.assertEqual(l, ['-Lfoodir', '-lfoo'])
        # Adding a library and a libpath appends both correctly
        l += ['-Lbardir', '-lbar']
        self.assertEqual(l, ['-Lbardir', '-Lfoodir', '-lfoo', '-lbar'])
        # Adding the same library again does nothing
        l += ['-lbar']
        self.assertEqual(l, ['-Lbardir', '-Lfoodir', '-lfoo', '-lbar'])

        ## Test that 'direct' append and extend works
        l = cc.compiler_args(['-Lfoodir', '-lfoo'])
        self.assertEqual(l, ['-Lfoodir', '-lfoo'])
        # Direct-adding a library and a libpath appends both correctly
        l.extend_direct(['-Lbardir', '-lbar'])
        self.assertEqual(l, ['-Lfoodir', '-lfoo', '-Lbardir', '-lbar'])
        # Direct-adding the same library again still adds it
        l.append_direct('-lbar')
        self.assertEqual(l, ['-Lfoodir', '-lfoo', '-Lbardir', '-lbar', '-lbar'])
        # Direct-adding with absolute path deduplicates
        l.append_direct('/libbaz.a')
        self.assertEqual(l, ['-Lfoodir', '-lfoo', '-Lbardir', '-lbar', '-lbar', '/libbaz.a'])
        # Adding libbaz again does nothing
        l.append_direct('/libbaz.a')
        self.assertEqual(l, ['-Lfoodir', '-lfoo', '-Lbardir', '-lbar', '-lbar', '/libbaz.a'])

    def test_compiler_args_class_gnuld(self):
        ## Test --start/end-group
        linker = mesonbuild.linkers.GnuDynamicLinker([], MachineChoice.HOST, 'fake', '-Wl,', [])
        gcc = mesonbuild.compilers.GnuCCompiler([], 'fake', False, MachineChoice.HOST, mock.Mock(), linker=linker)
        ## Ensure that the fake compiler is never called by overriding the relevant function
        gcc.get_default_include_dirs = lambda: ['/usr/include', '/usr/share/include', '/usr/local/include']
        ## Test that 'direct' append and extend works
        l = gcc.compiler_args(['-Lfoodir', '-lfoo'])
        self.assertEqual(l.to_native(copy=True), ['-Lfoodir', '-Wl,--start-group', '-lfoo', '-Wl,--end-group'])
        # Direct-adding a library and a libpath appends both correctly
        l.extend_direct(['-Lbardir', '-lbar'])
        self.assertEqual(l.to_native(copy=True), ['-Lfoodir', '-Wl,--start-group', '-lfoo', '-Lbardir', '-lbar', '-Wl,--end-group'])
        # Direct-adding the same library again still adds it
        l.append_direct('-lbar')
        self.assertEqual(l.to_native(copy=True), ['-Lfoodir', '-Wl,--start-group', '-lfoo', '-Lbardir', '-lbar', '-lbar', '-Wl,--end-group'])
        # Direct-adding with absolute path deduplicates
        l.append_direct('/libbaz.a')
        self.assertEqual(l.to_native(copy=True), ['-Lfoodir', '-Wl,--start-group', '-lfoo', '-Lbardir', '-lbar', '-lbar', '/libbaz.a', '-Wl,--end-group'])
        # Adding libbaz again does nothing
        l.append_direct('/libbaz.a')
        self.assertEqual(l.to_native(copy=True), ['-Lfoodir', '-Wl,--start-group', '-lfoo', '-Lbardir', '-lbar', '-lbar', '/libbaz.a', '-Wl,--end-group'])
        # Adding a non-library argument doesn't include it in the group
        l += ['-Lfoo', '-Wl,--export-dynamic']
        self.assertEqual(l.to_native(copy=True), ['-Lfoo', '-Lfoodir', '-Wl,--start-group', '-lfoo', '-Lbardir', '-lbar', '-lbar', '/libbaz.a', '-Wl,--end-group', '-Wl,--export-dynamic'])
        # -Wl,-lfoo is detected as a library and gets added to the group
        l.append('-Wl,-ldl')
        self.assertEqual(l.to_native(copy=True), ['-Lfoo', '-Lfoodir', '-Wl,--start-group', '-lfoo', '-Lbardir', '-lbar', '-lbar', '/libbaz.a', '-Wl,--export-dynamic', '-Wl,-ldl', '-Wl,--end-group'])

    def test_compiler_args_remove_system(self):
        ## Test --start/end-group
        linker = mesonbuild.linkers.GnuDynamicLinker([], MachineChoice.HOST, 'fake', '-Wl,', [])
        gcc = mesonbuild.compilers.GnuCCompiler([], 'fake', False, MachineChoice.HOST, mock.Mock(), linker=linker)
        ## Ensure that the fake compiler is never called by overriding the relevant function
        gcc.get_default_include_dirs = lambda: ['/usr/include', '/usr/share/include', '/usr/local/include']
        ## Test that 'direct' append and extend works
        l = gcc.compiler_args(['-Lfoodir', '-lfoo'])
        self.assertEqual(l.to_native(copy=True), ['-Lfoodir', '-Wl,--start-group', '-lfoo', '-Wl,--end-group'])
        ## Test that to_native removes all system includes
        l += ['-isystem/usr/include', '-isystem=/usr/share/include', '-DSOMETHING_IMPORTANT=1', '-isystem', '/usr/local/include']
        self.assertEqual(l.to_native(copy=True), ['-Lfoodir', '-Wl,--start-group', '-lfoo', '-Wl,--end-group', '-DSOMETHING_IMPORTANT=1'])

    def test_string_templates_substitution(self):
        dictfunc = mesonbuild.mesonlib.get_filenames_templates_dict
        substfunc = mesonbuild.mesonlib.substitute_values
        ME = mesonbuild.mesonlib.MesonException

        # Identity
        self.assertEqual(dictfunc([], []), {})

        # One input, no outputs
        inputs = ['bar/foo.c.in']
        outputs = []
        ret = dictfunc(inputs, outputs)
        d = {'@INPUT@': inputs, '@INPUT0@': inputs[0],
             '@PLAINNAME@': 'foo.c.in', '@BASENAME@': 'foo.c'}
        # Check dictionary
        self.assertEqual(ret, d)
        # Check substitutions
        cmd = ['some', 'ordinary', 'strings']
        self.assertEqual(substfunc(cmd, d), cmd)
        cmd = ['@INPUT@.out', 'ordinary', 'strings']
        self.assertEqual(substfunc(cmd, d), [inputs[0] + '.out'] + cmd[1:])
        cmd = ['@INPUT0@.out', '@PLAINNAME@.ok', 'strings']
        self.assertEqual(substfunc(cmd, d),
                         [inputs[0] + '.out'] + [d['@PLAINNAME@'] + '.ok'] + cmd[2:])
        cmd = ['@INPUT@', '@BASENAME@.hah', 'strings']
        self.assertEqual(substfunc(cmd, d),
                         inputs + [d['@BASENAME@'] + '.hah'] + cmd[2:])
        cmd = ['@OUTPUT@']
        self.assertRaises(ME, substfunc, cmd, d)

        # One input, one output
        inputs = ['bar/foo.c.in']
        outputs = ['out.c']
        ret = dictfunc(inputs, outputs)
        d = {'@INPUT@': inputs, '@INPUT0@': inputs[0],
             '@PLAINNAME@': 'foo.c.in', '@BASENAME@': 'foo.c',
             '@OUTPUT@': outputs, '@OUTPUT0@': outputs[0], '@OUTDIR@': '.'}
        # Check dictionary
        self.assertEqual(ret, d)
        # Check substitutions
        cmd = ['some', 'ordinary', 'strings']
        self.assertEqual(substfunc(cmd, d), cmd)
        cmd = ['@INPUT@.out', '@OUTPUT@', 'strings']
        self.assertEqual(substfunc(cmd, d),
                         [inputs[0] + '.out'] + outputs + cmd[2:])
        cmd = ['@INPUT0@.out', '@PLAINNAME@.ok', '@OUTPUT0@']
        self.assertEqual(substfunc(cmd, d),
                         [inputs[0] + '.out', d['@PLAINNAME@'] + '.ok'] + outputs)
        cmd = ['@INPUT@', '@BASENAME@.hah', 'strings']
        self.assertEqual(substfunc(cmd, d),
                         inputs + [d['@BASENAME@'] + '.hah'] + cmd[2:])

        # One input, one output with a subdir
        outputs = ['dir/out.c']
        ret = dictfunc(inputs, outputs)
        d = {'@INPUT@': inputs, '@INPUT0@': inputs[0],
             '@PLAINNAME@': 'foo.c.in', '@BASENAME@': 'foo.c',
             '@OUTPUT@': outputs, '@OUTPUT0@': outputs[0], '@OUTDIR@': 'dir'}
        # Check dictionary
        self.assertEqual(ret, d)

        # Two inputs, no outputs
        inputs = ['bar/foo.c.in', 'baz/foo.c.in']
        outputs = []
        ret = dictfunc(inputs, outputs)
        d = {'@INPUT@': inputs, '@INPUT0@': inputs[0], '@INPUT1@': inputs[1]}
        # Check dictionary
        self.assertEqual(ret, d)
        # Check substitutions
        cmd = ['some', 'ordinary', 'strings']
        self.assertEqual(substfunc(cmd, d), cmd)
        cmd = ['@INPUT@', 'ordinary', 'strings']
        self.assertEqual(substfunc(cmd, d), inputs + cmd[1:])
        cmd = ['@INPUT0@.out', 'ordinary', 'strings']
        self.assertEqual(substfunc(cmd, d), [inputs[0] + '.out'] + cmd[1:])
        cmd = ['@INPUT0@.out', '@INPUT1@.ok', 'strings']
        self.assertEqual(substfunc(cmd, d), [inputs[0] + '.out', inputs[1] + '.ok'] + cmd[2:])
        cmd = ['@INPUT0@', '@INPUT1@', 'strings']
        self.assertEqual(substfunc(cmd, d), inputs + cmd[2:])
        # Many inputs, can't use @INPUT@ like this
        cmd = ['@INPUT@.out', 'ordinary', 'strings']
        self.assertRaises(ME, substfunc, cmd, d)
        # Not enough inputs
        cmd = ['@INPUT2@.out', 'ordinary', 'strings']
        self.assertRaises(ME, substfunc, cmd, d)
        # Too many inputs
        cmd = ['@PLAINNAME@']
        self.assertRaises(ME, substfunc, cmd, d)
        cmd = ['@BASENAME@']
        self.assertRaises(ME, substfunc, cmd, d)
        # No outputs
        cmd = ['@OUTPUT@']
        self.assertRaises(ME, substfunc, cmd, d)
        cmd = ['@OUTPUT0@']
        self.assertRaises(ME, substfunc, cmd, d)
        cmd = ['@OUTDIR@']
        self.assertRaises(ME, substfunc, cmd, d)

        # Two inputs, one output
        outputs = ['dir/out.c']
        ret = dictfunc(inputs, outputs)
        d = {'@INPUT@': inputs, '@INPUT0@': inputs[0], '@INPUT1@': inputs[1],
             '@OUTPUT@': outputs, '@OUTPUT0@': outputs[0], '@OUTDIR@': 'dir'}
        # Check dictionary
        self.assertEqual(ret, d)
        # Check substitutions
        cmd = ['some', 'ordinary', 'strings']
        self.assertEqual(substfunc(cmd, d), cmd)
        cmd = ['@OUTPUT@', 'ordinary', 'strings']
        self.assertEqual(substfunc(cmd, d), outputs + cmd[1:])
        cmd = ['@OUTPUT@.out', 'ordinary', 'strings']
        self.assertEqual(substfunc(cmd, d), [outputs[0] + '.out'] + cmd[1:])
        cmd = ['@OUTPUT0@.out', '@INPUT1@.ok', 'strings']
        self.assertEqual(substfunc(cmd, d), [outputs[0] + '.out', inputs[1] + '.ok'] + cmd[2:])
        # Many inputs, can't use @INPUT@ like this
        cmd = ['@INPUT@.out', 'ordinary', 'strings']
        self.assertRaises(ME, substfunc, cmd, d)
        # Not enough inputs
        cmd = ['@INPUT2@.out', 'ordinary', 'strings']
        self.assertRaises(ME, substfunc, cmd, d)
        # Not enough outputs
        cmd = ['@OUTPUT2@.out', 'ordinary', 'strings']
        self.assertRaises(ME, substfunc, cmd, d)

        # Two inputs, two outputs
        outputs = ['dir/out.c', 'dir/out2.c']
        ret = dictfunc(inputs, outputs)
        d = {'@INPUT@': inputs, '@INPUT0@': inputs[0], '@INPUT1@': inputs[1],
             '@OUTPUT@': outputs, '@OUTPUT0@': outputs[0], '@OUTPUT1@': outputs[1],
             '@OUTDIR@': 'dir'}
        # Check dictionary
        self.assertEqual(ret, d)
        # Check substitutions
        cmd = ['some', 'ordinary', 'strings']
        self.assertEqual(substfunc(cmd, d), cmd)
        cmd = ['@OUTPUT@', 'ordinary', 'strings']
        self.assertEqual(substfunc(cmd, d), outputs + cmd[1:])
        cmd = ['@OUTPUT0@', '@OUTPUT1@', 'strings']
        self.assertEqual(substfunc(cmd, d), outputs + cmd[2:])
        cmd = ['@OUTPUT0@.out', '@INPUT1@.ok', '@OUTDIR@']
        self.assertEqual(substfunc(cmd, d), [outputs[0] + '.out', inputs[1] + '.ok', 'dir'])
        # Many inputs, can't use @INPUT@ like this
        cmd = ['@INPUT@.out', 'ordinary', 'strings']
        self.assertRaises(ME, substfunc, cmd, d)
        # Not enough inputs
        cmd = ['@INPUT2@.out', 'ordinary', 'strings']
        self.assertRaises(ME, substfunc, cmd, d)
        # Not enough outputs
        cmd = ['@OUTPUT2@.out', 'ordinary', 'strings']
        self.assertRaises(ME, substfunc, cmd, d)
        # Many outputs, can't use @OUTPUT@ like this
        cmd = ['@OUTPUT@.out', 'ordinary', 'strings']
        self.assertRaises(ME, substfunc, cmd, d)

    def test_needs_exe_wrapper_override(self):
        config = ConfigParser()
        config['binaries'] = {
            'c': '\'/usr/bin/gcc\'',
        }
        config['host_machine'] = {
            'system': '\'linux\'',
            'cpu_family': '\'arm\'',
            'cpu': '\'armv7\'',
            'endian': '\'little\'',
        }
        # Can not be used as context manager because we need to
        # open it a second time and this is not possible on
        # Windows.
        configfile = tempfile.NamedTemporaryFile(mode='w+', delete=False)
        configfilename = configfile.name
        config.write(configfile)
        configfile.flush()
        configfile.close()
        opts = get_fake_options()
        opts.cross_file = (configfilename,)
        env = get_fake_env(opts=opts)
        detected_value = env.need_exe_wrapper()
        os.unlink(configfilename)

        desired_value = not detected_value
        config['properties'] = {
            'needs_exe_wrapper': 'true' if desired_value else 'false'
        }

        configfile = tempfile.NamedTemporaryFile(mode='w+', delete=False)
        configfilename = configfile.name
        config.write(configfile)
        configfile.close()
        opts = get_fake_options()
        opts.cross_file = (configfilename,)
        env = get_fake_env(opts=opts)
        forced_value = env.need_exe_wrapper()
        os.unlink(configfilename)

        self.assertEqual(forced_value, desired_value)

    def test_listify(self):
        listify = mesonbuild.mesonlib.listify
        # Test sanity
        self.assertEqual([1], listify(1))
        self.assertEqual([], listify([]))
        self.assertEqual([1], listify([1]))
        # Test flattening
        self.assertEqual([1, 2, 3], listify([1, [2, 3]]))
        self.assertEqual([1, 2, 3], listify([1, [2, [3]]]))
        self.assertEqual([1, [2, [3]]], listify([1, [2, [3]]], flatten=False))
        # Test flattening and unholdering
        holder1 = ObjectHolder(1)
        self.assertEqual([holder1], listify(holder1))
        self.assertEqual([holder1], listify([holder1]))
        self.assertEqual([holder1, 2], listify([holder1, 2]))
        self.assertEqual([holder1, 2, 3], listify([holder1, 2, [3]]))

    def test_unholder(self):
        unholder = mesonbuild.mesonlib.unholder

        holder1 = ObjectHolder(1)
        holder3 = ObjectHolder(3)
        holders = [holder1, holder3]

        self.assertEqual(1, unholder(holder1))
        self.assertEqual([1], unholder([holder1]))
        self.assertEqual([1, 3], unholder(holders))

    def test_extract_as_list(self):
        extract = mesonbuild.mesonlib.extract_as_list
        # Test sanity
        kwargs = {'sources': [1, 2, 3]}
        self.assertEqual([1, 2, 3], extract(kwargs, 'sources'))
        self.assertEqual(kwargs, {'sources': [1, 2, 3]})
        self.assertEqual([1, 2, 3], extract(kwargs, 'sources', pop=True))
        self.assertEqual(kwargs, {})

        # Test unholding
        holder3 = ObjectHolder(3)
        kwargs = {'sources': [1, 2, holder3]}
        self.assertEqual(kwargs, {'sources': [1, 2, holder3]})

        # flatten nested lists
        kwargs = {'sources': [1, [2, [3]]]}
        self.assertEqual([1, 2, 3], extract(kwargs, 'sources'))

    def test_pkgconfig_module(self):
        dummystate = mock.Mock()
        dummystate.subproject = 'dummy'
        _mock = mock.Mock(spec=mesonbuild.dependencies.ExternalDependency)
        _mock.pcdep = mock.Mock()
        _mock.pcdep.name = "some_name"
        _mock.version_reqs = []
        _mock = mock.Mock(held_object=_mock)

        # pkgconfig dependency as lib
        deps = mesonbuild.modules.pkgconfig.DependenciesHelper(dummystate, "thislib")
        deps.add_pub_libs([_mock])
        self.assertEqual(deps.format_reqs(deps.pub_reqs), "some_name")

        # pkgconfig dependency as requires
        deps = mesonbuild.modules.pkgconfig.DependenciesHelper(dummystate, "thislib")
        deps.add_pub_reqs([_mock])
        self.assertEqual(deps.format_reqs(deps.pub_reqs), "some_name")

    def _test_all_naming(self, cc, env, patterns, platform):
        shr = patterns[platform]['shared']
        stc = patterns[platform]['static']
        shrstc = shr + tuple([x for x in stc if x not in shr])
        stcshr = stc + tuple([x for x in shr if x not in stc])
        p = cc.get_library_naming(env, LibType.SHARED)
        self.assertEqual(p, shr)
        p = cc.get_library_naming(env, LibType.STATIC)
        self.assertEqual(p, stc)
        p = cc.get_library_naming(env, LibType.PREFER_STATIC)
        self.assertEqual(p, stcshr)
        p = cc.get_library_naming(env, LibType.PREFER_SHARED)
        self.assertEqual(p, shrstc)
        # Test find library by mocking up openbsd
        if platform != 'openbsd':
            return
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, 'libfoo.so.6.0'), 'w') as f:
                f.write('')
            with open(os.path.join(tmpdir, 'libfoo.so.5.0'), 'w') as f:
                f.write('')
            with open(os.path.join(tmpdir, 'libfoo.so.54.0'), 'w') as f:
                f.write('')
            with open(os.path.join(tmpdir, 'libfoo.so.66a.0b'), 'w') as f:
                f.write('')
            with open(os.path.join(tmpdir, 'libfoo.so.70.0.so.1'), 'w') as f:
                f.write('')
            found = cc.find_library_real('foo', env, [tmpdir], '', LibType.PREFER_SHARED)
            self.assertEqual(os.path.basename(found[0]), 'libfoo.so.54.0')

    def test_find_library_patterns(self):
        '''
        Unit test for the library search patterns used by find_library()
        '''
        unix_static = ('lib{}.a', '{}.a')
        msvc_static = ('lib{}.a', 'lib{}.lib', '{}.a', '{}.lib')
        # This is the priority list of pattern matching for library searching
        patterns = {'openbsd': {'shared': ('lib{}.so', '{}.so', 'lib{}.so.[0-9]*.[0-9]*', '{}.so.[0-9]*.[0-9]*'),
                                'static': unix_static},
                    'linux': {'shared': ('lib{}.so', '{}.so'),
                              'static': unix_static},
                    'darwin': {'shared': ('lib{}.dylib', 'lib{}.so', '{}.dylib', '{}.so'),
                               'static': unix_static},
                    'cygwin': {'shared': ('cyg{}.dll', 'cyg{}.dll.a', 'lib{}.dll',
                                          'lib{}.dll.a', '{}.dll', '{}.dll.a'),
                               'static': ('cyg{}.a',) + unix_static},
                    'windows-msvc': {'shared': ('lib{}.lib', '{}.lib'),
                                     'static': msvc_static},
                    'windows-mingw': {'shared': ('lib{}.dll.a', 'lib{}.lib', 'lib{}.dll',
                                                 '{}.dll.a', '{}.lib', '{}.dll'),
                                      'static': msvc_static}}
        env = get_fake_env()
        cc = env.detect_c_compiler(MachineChoice.HOST)
        if is_osx():
            self._test_all_naming(cc, env, patterns, 'darwin')
        elif is_cygwin():
            self._test_all_naming(cc, env, patterns, 'cygwin')
        elif is_windows():
            if cc.get_argument_syntax() == 'msvc':
                self._test_all_naming(cc, env, patterns, 'windows-msvc')
            else:
                self._test_all_naming(cc, env, patterns, 'windows-mingw')
        elif is_openbsd():
            self._test_all_naming(cc, env, patterns, 'openbsd')
        else:
            self._test_all_naming(cc, env, patterns, 'linux')
            env.machines.host.system = 'openbsd'
            self._test_all_naming(cc, env, patterns, 'openbsd')
            env.machines.host.system = 'darwin'
            self._test_all_naming(cc, env, patterns, 'darwin')
            env.machines.host.system = 'cygwin'
            self._test_all_naming(cc, env, patterns, 'cygwin')
            env.machines.host.system = 'windows'
            self._test_all_naming(cc, env, patterns, 'windows-mingw')

    @skipIfNoPkgconfig
    def test_pkgconfig_parse_libs(self):
        '''
        Unit test for parsing of pkg-config output to search for libraries

        https://github.com/mesonbuild/meson/issues/3951
        '''
        def create_static_lib(name):
            if not is_osx():
                name.open('w').close()
                return
            src = name.with_suffix('.c')
            out = name.with_suffix('.o')
            with src.open('w') as f:
                f.write('int meson_foobar (void) { return 0; }')
            subprocess.check_call(['clang', '-c', str(src), '-o', str(out)])
            subprocess.check_call(['ar', 'csr', str(name), str(out)])

        with tempfile.TemporaryDirectory() as tmpdir:
            pkgbin = ExternalProgram('pkg-config', command=['pkg-config'], silent=True)
            env = get_fake_env()
            compiler = env.detect_c_compiler(MachineChoice.HOST)
            env.coredata.compilers.host = {'c': compiler}
            env.coredata.compiler_options.host['c']['link_args'] = FakeCompilerOptions()
            p1 = Path(tmpdir) / '1'
            p2 = Path(tmpdir) / '2'
            p1.mkdir()
            p2.mkdir()
            # libfoo.a is in one prefix
            create_static_lib(p1 / 'libfoo.a')
            # libbar.a is in both prefixes
            create_static_lib(p1 / 'libbar.a')
            create_static_lib(p2 / 'libbar.a')
            # Ensure that we never statically link to these
            create_static_lib(p1 / 'libpthread.a')
            create_static_lib(p1 / 'libm.a')
            create_static_lib(p1 / 'libc.a')
            create_static_lib(p1 / 'libdl.a')
            create_static_lib(p1 / 'librt.a')

            def fake_call_pkgbin(self, args, env=None):
                if '--libs' not in args:
                    return 0, '', ''
                if args[0] == 'foo':
                    return 0, '-L{} -lfoo -L{} -lbar'.format(p2.as_posix(), p1.as_posix()), ''
                if args[0] == 'bar':
                    return 0, '-L{} -lbar'.format(p2.as_posix()), ''
                if args[0] == 'internal':
                    return 0, '-L{} -lpthread -lm -lc -lrt -ldl'.format(p1.as_posix()), ''

            old_call = PkgConfigDependency._call_pkgbin
            old_check = PkgConfigDependency.check_pkgconfig
            PkgConfigDependency._call_pkgbin = fake_call_pkgbin
            PkgConfigDependency.check_pkgconfig = lambda x, _: pkgbin
            # Test begins
            try:
                kwargs = {'required': True, 'silent': True}
                foo_dep = PkgConfigDependency('foo', env, kwargs)
                self.assertEqual(foo_dep.get_link_args(),
                                 [(p1 / 'libfoo.a').as_posix(), (p2 / 'libbar.a').as_posix()])
                bar_dep = PkgConfigDependency('bar', env, kwargs)
                self.assertEqual(bar_dep.get_link_args(), [(p2 / 'libbar.a').as_posix()])
                internal_dep = PkgConfigDependency('internal', env, kwargs)
                if compiler.get_argument_syntax() == 'msvc':
                    self.assertEqual(internal_dep.get_link_args(), [])
                else:
                    link_args = internal_dep.get_link_args()
                    for link_arg in link_args:
                        for lib in ('pthread', 'm', 'c', 'dl', 'rt'):
                            self.assertNotIn('lib{}.a'.format(lib), link_arg, msg=link_args)
            finally:
                # Test ends
                PkgConfigDependency._call_pkgbin = old_call
                PkgConfigDependency.check_pkgconfig = old_check
                # Reset dependency class to ensure that in-process configure doesn't mess up
                PkgConfigDependency.pkgbin_cache = {}
                PkgConfigDependency.class_pkgbin = PerMachine(None, None)

    def test_version_compare(self):
        comparefunc = mesonbuild.mesonlib.version_compare_many
        for (a, b, result) in [
                ('0.99.beta19', '>= 0.99.beta14', True),
        ]:
            self.assertEqual(comparefunc(a, b)[0], result)

        for (a, b, op) in [
                # examples from https://fedoraproject.org/wiki/Archive:Tools/RPM/VersionComparison
                ("1.0010", "1.9", operator.gt),
                ("1.05", "1.5", operator.eq),
                ("1.0", "1", operator.gt),
                ("2.50", "2.5", operator.gt),
                ("fc4", "fc.4", operator.eq),
                ("FC5", "fc4", operator.lt),
                ("2a", "2.0", operator.lt),
                ("1.0", "1.fc4", operator.gt),
                ("3.0.0_fc", "3.0.0.fc", operator.eq),
                # from RPM tests
                ("1.0", "1.0", operator.eq),
                ("1.0", "2.0", operator.lt),
                ("2.0", "1.0", operator.gt),
                ("2.0.1", "2.0.1", operator.eq),
                ("2.0", "2.0.1", operator.lt),
                ("2.0.1", "2.0", operator.gt),
                ("2.0.1a", "2.0.1a", operator.eq),
                ("2.0.1a", "2.0.1", operator.gt),
                ("2.0.1", "2.0.1a", operator.lt),
                ("5.5p1", "5.5p1", operator.eq),
                ("5.5p1", "5.5p2", operator.lt),
                ("5.5p2", "5.5p1", operator.gt),
                ("5.5p10", "5.5p10", operator.eq),
                ("5.5p1", "5.5p10", operator.lt),
                ("5.5p10", "5.5p1", operator.gt),
                ("10xyz", "10.1xyz", operator.lt),
                ("10.1xyz", "10xyz", operator.gt),
                ("xyz10", "xyz10", operator.eq),
                ("xyz10", "xyz10.1", operator.lt),
                ("xyz10.1", "xyz10", operator.gt),
                ("xyz.4", "xyz.4", operator.eq),
                ("xyz.4", "8", operator.lt),
                ("8", "xyz.4", operator.gt),
                ("xyz.4", "2", operator.lt),
                ("2", "xyz.4", operator.gt),
                ("5.5p2", "5.6p1", operator.lt),
                ("5.6p1", "5.5p2", operator.gt),
                ("5.6p1", "6.5p1", operator.lt),
                ("6.5p1", "5.6p1", operator.gt),
                ("6.0.rc1", "6.0", operator.gt),
                ("6.0", "6.0.rc1", operator.lt),
                ("10b2", "10a1", operator.gt),
                ("10a2", "10b2", operator.lt),
                ("1.0aa", "1.0aa", operator.eq),
                ("1.0a", "1.0aa", operator.lt),
                ("1.0aa", "1.0a", operator.gt),
                ("10.0001", "10.0001", operator.eq),
                ("10.0001", "10.1", operator.eq),
                ("10.1", "10.0001", operator.eq),
                ("10.0001", "10.0039", operator.lt),
                ("10.0039", "10.0001", operator.gt),
                ("4.999.9", "5.0", operator.lt),
                ("5.0", "4.999.9", operator.gt),
                ("20101121", "20101121", operator.eq),
                ("20101121", "20101122", operator.lt),
                ("20101122", "20101121", operator.gt),
                ("2_0", "2_0", operator.eq),
                ("2.0", "2_0", operator.eq),
                ("2_0", "2.0", operator.eq),
                ("a", "a", operator.eq),
                ("a+", "a+", operator.eq),
                ("a+", "a_", operator.eq),
                ("a_", "a+", operator.eq),
                ("+a", "+a", operator.eq),
                ("+a", "_a", operator.eq),
                ("_a", "+a", operator.eq),
                ("+_", "+_", operator.eq),
                ("_+", "+_", operator.eq),
                ("_+", "_+", operator.eq),
                ("+", "_", operator.eq),
                ("_", "+", operator.eq),
                # other tests
                ('0.99.beta19', '0.99.beta14', operator.gt),
                ("1.0.0", "2.0.0", operator.lt),
                (".0.0", "2.0.0", operator.lt),
                ("alpha", "beta", operator.lt),
                ("1.0", "1.0.0", operator.lt),
                ("2.456", "2.1000", operator.lt),
                ("2.1000", "3.111", operator.lt),
                ("2.001", "2.1", operator.eq),
                ("2.34", "2.34", operator.eq),
                ("6.1.2", "6.3.8", operator.lt),
                ("1.7.3.0", "2.0.0", operator.lt),
                ("2.24.51", "2.25", operator.lt),
                ("2.1.5+20120813+gitdcbe778", "2.1.5", operator.gt),
                ("3.4.1", "3.4b1", operator.gt),
                ("041206", "200090325", operator.lt),
                ("0.6.2+git20130413", "0.6.2", operator.gt),
                ("2.6.0+bzr6602", "2.6.0", operator.gt),
                ("2.6.0", "2.6b2", operator.gt),
                ("2.6.0+bzr6602", "2.6b2x", operator.gt),
                ("0.6.7+20150214+git3a710f9", "0.6.7", operator.gt),
                ("15.8b", "15.8.0.1", operator.lt),
                ("1.2rc1", "1.2.0", operator.lt),
        ]:
            ver_a = Version(a)
            ver_b = Version(b)
            if op is operator.eq:
                for o, name in [(op, 'eq'), (operator.ge, 'ge'), (operator.le, 'le')]:
                    self.assertTrue(o(ver_a, ver_b), '{} {} {}'.format(ver_a, name, ver_b))
            if op is operator.lt:
                for o, name in [(op, 'lt'), (operator.le, 'le'), (operator.ne, 'ne')]:
                    self.assertTrue(o(ver_a, ver_b), '{} {} {}'.format(ver_a, name, ver_b))
                for o, name in [(operator.gt, 'gt'), (operator.ge, 'ge'), (operator.eq, 'eq')]:
                    self.assertFalse(o(ver_a, ver_b), '{} {} {}'.format(ver_a, name, ver_b))
            if op is operator.gt:
                for o, name in [(op, 'gt'), (operator.ge, 'ge'), (operator.ne, 'ne')]:
                    self.assertTrue(o(ver_a, ver_b), '{} {} {}'.format(ver_a, name, ver_b))
                for o, name in [(operator.lt, 'lt'), (operator.le, 'le'), (operator.eq, 'eq')]:
                    self.assertFalse(o(ver_a, ver_b), '{} {} {}'.format(ver_a, name, ver_b))

    def test_msvc_toolset_version(self):
        '''
        Ensure that the toolset version returns the correct value for this MSVC
        '''
        env = get_fake_env()
        cc = env.detect_c_compiler(MachineChoice.HOST)
        if cc.get_argument_syntax() != 'msvc':
            raise unittest.SkipTest('Test only applies to MSVC-like compilers')
        toolset_ver = cc.get_toolset_version()
        self.assertIsNotNone(toolset_ver)
        # Visual Studio 2015 and older versions do not define VCToolsVersion
        # TODO: ICL doesn't set this in the VSC2015 profile either
        if cc.id == 'msvc' and int(''.join(cc.version.split('.')[0:2])) < 1910:
            return
        if 'VCToolsVersion' in os.environ:
            vctools_ver = os.environ['VCToolsVersion']
        else:
            self.assertIn('VCINSTALLDIR', os.environ)
            # See https://devblogs.microsoft.com/cppblog/finding-the-visual-c-compiler-tools-in-visual-studio-2017/
            vctools_ver = (Path(os.environ['VCINSTALLDIR']) / 'Auxiliary' / 'Build' / 'Microsoft.VCToolsVersion.default.txt').read_text()
        self.assertTrue(vctools_ver.startswith(toolset_ver),
                        msg='{!r} does not start with {!r}'.format(vctools_ver, toolset_ver))

    def test_split_args(self):
        split_args = mesonbuild.mesonlib.split_args
        join_args = mesonbuild.mesonlib.join_args
        if is_windows():
            test_data = [
                # examples from https://docs.microsoft.com/en-us/cpp/c-language/parsing-c-command-line-arguments
                (r'"a b c" d e', ['a b c', 'd', 'e'], True),
                (r'"ab\"c" "\\" d', ['ab"c', '\\', 'd'], False),
                (r'a\\\b d"e f"g h', [r'a\\\b', 'de fg', 'h'], False),
                (r'a\\\"b c d', [r'a\"b', 'c', 'd'], False),
                (r'a\\\\"b c" d e', [r'a\\b c', 'd', 'e'], False),
                # other basics
                (r'""', [''], True),
                (r'a b c d "" e', ['a', 'b', 'c', 'd', '', 'e'], True),
                (r"'a b c' d e", ["'a", 'b', "c'", 'd', 'e'], True),
                (r"'a&b&c' d e", ["'a&b&c'", 'd', 'e'], True),
                (r"a & b & c d e", ['a', '&', 'b', '&', 'c', 'd', 'e'], True),
                (r"'a & b & c d e'", ["'a", '&', 'b', '&', 'c', 'd', "e'"], True),
                ('a  b\nc\rd \n\re', ['a', 'b', 'c', 'd', 'e'], False),
                # more illustrative tests
                (r'cl test.cpp /O1 /Fe:test.exe', ['cl', 'test.cpp', '/O1', '/Fe:test.exe'], True),
                (r'cl "test.cpp /O1 /Fe:test.exe"', ['cl', 'test.cpp /O1 /Fe:test.exe'], True),
                (r'cl /DNAME=\"Bob\" test.cpp', ['cl', '/DNAME="Bob"', 'test.cpp'], False),
                (r'cl "/DNAME=\"Bob\"" test.cpp', ['cl', '/DNAME="Bob"', 'test.cpp'], True),
                (r'cl /DNAME=\"Bob, Alice\" test.cpp', ['cl', '/DNAME="Bob,', 'Alice"', 'test.cpp'], False),
                (r'cl "/DNAME=\"Bob, Alice\"" test.cpp', ['cl', '/DNAME="Bob, Alice"', 'test.cpp'], True),
                (r'cl C:\path\with\backslashes.cpp', ['cl', r'C:\path\with\backslashes.cpp'], True),
                (r'cl C:\\path\\with\\double\\backslashes.cpp', ['cl', r'C:\\path\\with\\double\\backslashes.cpp'], True),
                (r'cl "C:\\path\\with\\double\\backslashes.cpp"', ['cl', r'C:\\path\\with\\double\\backslashes.cpp'], False),
                (r'cl C:\path with spaces\test.cpp', ['cl', r'C:\path', 'with', r'spaces\test.cpp'], False),
                (r'cl "C:\path with spaces\test.cpp"', ['cl', r'C:\path with spaces\test.cpp'], True),
                (r'cl /DPATH="C:\path\with\backslashes test.cpp', ['cl', r'/DPATH=C:\path\with\backslashes test.cpp'], False),
                (r'cl /DPATH=\"C:\\ends\\with\\backslashes\\\" test.cpp', ['cl', r'/DPATH="C:\\ends\\with\\backslashes\"', 'test.cpp'], False),
                (r'cl /DPATH="C:\\ends\\with\\backslashes\\" test.cpp', ['cl', '/DPATH=C:\\\\ends\\\\with\\\\backslashes\\', 'test.cpp'], False),
                (r'cl "/DNAME=\"C:\\ends\\with\\backslashes\\\"" test.cpp', ['cl', r'/DNAME="C:\\ends\\with\\backslashes\"', 'test.cpp'], True),
                (r'cl "/DNAME=\"C:\\ends\\with\\backslashes\\\\"" test.cpp', ['cl', r'/DNAME="C:\\ends\\with\\backslashes\\ test.cpp'], False),
                (r'cl "/DNAME=\"C:\\ends\\with\\backslashes\\\\\"" test.cpp', ['cl', r'/DNAME="C:\\ends\\with\\backslashes\\"', 'test.cpp'], True),
            ]
        else:
            test_data = [
                (r"'a b c' d e", ['a b c', 'd', 'e'], True),
                (r"a/b/c d e", ['a/b/c', 'd', 'e'], True),
                (r"a\b\c d e", [r'abc', 'd', 'e'], False),
                (r"a\\b\\c d e", [r'a\b\c', 'd', 'e'], False),
                (r'"a b c" d e', ['a b c', 'd', 'e'], False),
                (r'"a\\b\\c\\" d e', ['a\\b\\c\\', 'd', 'e'], False),
                (r"'a\b\c\' d e", ['a\\b\\c\\', 'd', 'e'], True),
                (r"'a&b&c' d e", ['a&b&c', 'd', 'e'], True),
                (r"a & b & c d e", ['a', '&', 'b', '&', 'c', 'd', 'e'], False),
                (r"'a & b & c d e'", ['a & b & c d e'], True),
                (r"abd'e f'g h", [r'abde fg', 'h'], False),
                ('a  b\nc\rd \n\re', ['a', 'b', 'c', 'd', 'e'], False),

                ('g++ -DNAME="Bob" test.cpp', ['g++', '-DNAME=Bob', 'test.cpp'], False),
                ("g++ '-DNAME=\"Bob\"' test.cpp", ['g++', '-DNAME="Bob"', 'test.cpp'], True),
                ('g++ -DNAME="Bob, Alice" test.cpp', ['g++', '-DNAME=Bob, Alice', 'test.cpp'], False),
                ("g++ '-DNAME=\"Bob, Alice\"' test.cpp", ['g++', '-DNAME="Bob, Alice"', 'test.cpp'], True),
            ]

        for (cmd, expected, roundtrip) in test_data:
            self.assertEqual(split_args(cmd), expected)
            if roundtrip:
                self.assertEqual(join_args(expected), cmd)

    def test_quote_arg(self):
        split_args = mesonbuild.mesonlib.split_args
        quote_arg = mesonbuild.mesonlib.quote_arg
        if is_windows():
            test_data = [
                ('', '""'),
                ('arg1', 'arg1'),
                ('/option1', '/option1'),
                ('/Ovalue', '/Ovalue'),
                ('/OBob&Alice', '/OBob&Alice'),
                ('/Ovalue with spaces', r'"/Ovalue with spaces"'),
                (r'/O"value with spaces"', r'"/O\"value with spaces\""'),
                (r'/OC:\path with spaces\test.exe', r'"/OC:\path with spaces\test.exe"'),
                ('/LIBPATH:C:\\path with spaces\\ends\\with\\backslashes\\', r'"/LIBPATH:C:\path with spaces\ends\with\backslashes\\"'),
                ('/LIBPATH:"C:\\path with spaces\\ends\\with\\backslashes\\\\"', r'"/LIBPATH:\"C:\path with spaces\ends\with\backslashes\\\\\""'),
                (r'/DMSG="Alice said: \"Let\'s go\""', r'"/DMSG=\"Alice said: \\\"Let\'s go\\\"\""'),
            ]
        else:
            test_data = [
                ('arg1', 'arg1'),
                ('--option1', '--option1'),
                ('-O=value', '-O=value'),
                ('-O=Bob&Alice', "'-O=Bob&Alice'"),
                ('-O=value with spaces', "'-O=value with spaces'"),
                ('-O="value with spaces"', '\'-O=\"value with spaces\"\''),
                ('-O=/path with spaces/test', '\'-O=/path with spaces/test\''),
                ('-DMSG="Alice said: \\"Let\'s go\\""', "'-DMSG=\"Alice said: \\\"Let'\"'\"'s go\\\"\"'"),
            ]

        for (arg, expected) in test_data:
            self.assertEqual(quote_arg(arg), expected)
            self.assertEqual(split_args(expected)[0], arg)

    def test_depfile(self):
        for (f, target, expdeps) in [
                # empty, unknown target
                ([''], 'unknown', set()),
                # simple target & deps
                (['meson/foo.o  : foo.c   foo.h'], 'meson/foo.o', set({'foo.c', 'foo.h'})),
                (['meson/foo.o: foo.c foo.h'], 'foo.c', set()),
                # get all deps
                (['meson/foo.o: foo.c foo.h',
                  'foo.c: gen.py'], 'meson/foo.o', set({'foo.c', 'foo.h', 'gen.py'})),
                (['meson/foo.o: foo.c foo.h',
                  'foo.c: gen.py'], 'foo.c', set({'gen.py'})),
                # linue continuation, multiple targets
                (['foo.o \\', 'foo.h: bar'], 'foo.h', set({'bar'})),
                (['foo.o \\', 'foo.h: bar'], 'foo.o', set({'bar'})),
                # \\ handling
                (['foo: Program\\ F\\iles\\\\X'], 'foo', set({'Program Files\\X'})),
                # $ handling
                (['f$o.o: c/b'], 'f$o.o', set({'c/b'})),
                (['f$$o.o: c/b'], 'f$o.o', set({'c/b'})),
                # cycles
                (['a: b', 'b: a'], 'a', set({'a', 'b'})),
                (['a: b', 'b: a'], 'b', set({'a', 'b'})),
        ]:
            d = mesonbuild.depfile.DepFile(f)
            deps = d.get_all_dependencies(target)
            self.assertEqual(deps, expdeps)

    def test_log_once(self):
        f = io.StringIO()
        with mock.patch('mesonbuild.mlog.log_file', f), \
                mock.patch('mesonbuild.mlog._logged_once', set()):
            mesonbuild.mlog.log_once('foo')
            mesonbuild.mlog.log_once('foo')
            actual = f.getvalue().strip()
            self.assertEqual(actual, 'foo', actual)

    def test_log_once_ansi(self):
        f = io.StringIO()
        with mock.patch('mesonbuild.mlog.log_file', f), \
                mock.patch('mesonbuild.mlog._logged_once', set()):
            mesonbuild.mlog.log_once(mesonbuild.mlog.bold('foo'))
            mesonbuild.mlog.log_once(mesonbuild.mlog.bold('foo'))
            actual = f.getvalue().strip()
            self.assertEqual(actual.count('foo'), 1, actual)

            mesonbuild.mlog.log_once('foo')
            actual = f.getvalue().strip()
            self.assertEqual(actual.count('foo'), 1, actual)

            f.truncate()

            mesonbuild.mlog.warning('bar', once=True)
            mesonbuild.mlog.warning('bar', once=True)
            actual = f.getvalue().strip()
            self.assertEqual(actual.count('bar'), 1, actual)

    def test_sort_libpaths(self):
        sort_libpaths = mesonbuild.dependencies.base.sort_libpaths
        self.assertEqual(sort_libpaths(
            ['/home/mesonuser/.local/lib', '/usr/local/lib', '/usr/lib'],
            ['/home/mesonuser/.local/lib/pkgconfig', '/usr/local/lib/pkgconfig']),
            ['/home/mesonuser/.local/lib', '/usr/local/lib', '/usr/lib'])
        self.assertEqual(sort_libpaths(
            ['/usr/local/lib', '/home/mesonuser/.local/lib', '/usr/lib'],
            ['/home/mesonuser/.local/lib/pkgconfig', '/usr/local/lib/pkgconfig']),
            ['/home/mesonuser/.local/lib', '/usr/local/lib', '/usr/lib'])
        self.assertEqual(sort_libpaths(
            ['/usr/lib', '/usr/local/lib', '/home/mesonuser/.local/lib'],
            ['/home/mesonuser/.local/lib/pkgconfig', '/usr/local/lib/pkgconfig']),
            ['/home/mesonuser/.local/lib', '/usr/local/lib', '/usr/lib'])
        self.assertEqual(sort_libpaths(
            ['/usr/lib', '/usr/local/lib', '/home/mesonuser/.local/lib'],
            ['/home/mesonuser/.local/lib/pkgconfig', '/usr/local/libdata/pkgconfig']),
            ['/home/mesonuser/.local/lib', '/usr/local/lib', '/usr/lib'])

    def test_dependency_factory_order(self):
        b = mesonbuild.dependencies.base
        with tempfile.TemporaryDirectory() as tmpdir:
            with chdir(tmpdir):
                env = get_fake_env()

                f = b.DependencyFactory(
                    'test_dep',
                    methods=[b.DependencyMethods.PKGCONFIG, b.DependencyMethods.CMAKE]
                )
                actual = [m() for m in f(env, MachineChoice.HOST, {'required': False})]
                self.assertListEqual([m.type_name for m in actual], ['pkgconfig', 'cmake'])

                f = b.DependencyFactory(
                    'test_dep',
                    methods=[b.DependencyMethods.CMAKE, b.DependencyMethods.PKGCONFIG]
                )
                actual = [m() for m in f(env, MachineChoice.HOST, {'required': False})]
                self.assertListEqual([m.type_name for m in actual], ['cmake', 'pkgconfig'])

    def test_validate_json(self) -> None:
        """Validate the json schema for the test cases."""
        try:
            from jsonschema import validate, ValidationError
        except ImportError:
            if is_ci():
                raise
            raise unittest.SkipTest('Python jsonschema module not found.')

        with Path('data/test.schema.json').open() as f:
            schema = json.load(f)

        errors = []  # type: T.Tuple[str, Exception]
        for p in Path('test cases').glob('**/test.json'):
            with p.open() as f:
                try:
                    validate(json.load(f), schema=schema)
                except ValidationError as e:
                    errors.append((p.resolve(), e))

        for f, e in errors:
            print('Failed to validate: "{}"'.format(f))
            print(str(e))

        self.assertFalse(errors)

@unittest.skipIf(is_tarball(), 'Skipping because this is a tarball release')
class DataTests(unittest.TestCase):

    def test_snippets(self):
        hashcounter = re.compile('^ *(#)+')
        snippet_dir = Path('docs/markdown/snippets')
        self.assertTrue(snippet_dir.is_dir())
        for f in snippet_dir.glob('*'):
            self.assertTrue(f.is_file())
            if f.parts[-1].endswith('~'):
                continue
            if f.suffix == '.md':
                in_code_block = False
                with f.open() as snippet:
                    for line in snippet:
                        if line.startswith('    '):
                            continue
                        if line.startswith('```'):
                            in_code_block = not in_code_block
                        if in_code_block:
                            continue
                        m = re.match(hashcounter, line)
                        if m:
                            self.assertEqual(len(m.group(0)), 2, 'All headings in snippets must have two hash symbols: ' + f.name)
                self.assertFalse(in_code_block, 'Unclosed code block.')
            else:
                if f.name != 'add_release_note_snippets_here':
                    self.assertTrue(False, 'A file without .md suffix in snippets dir: ' + f.name)

    def test_compiler_options_documented(self):
        '''
        Test that C and C++ compiler options and base options are documented in
        Builtin-Options.md. Only tests the default compiler for the current
        platform on the CI.
        '''
        md = None
        with open('docs/markdown/Builtin-options.md', encoding='utf-8') as f:
            md = f.read()
        self.assertIsNotNone(md)
        env = get_fake_env()
        # FIXME: Support other compilers
        cc = env.detect_c_compiler(MachineChoice.HOST)
        cpp = env.detect_cpp_compiler(MachineChoice.HOST)
        for comp in (cc, cpp):
            for opt in comp.get_options().keys():
                self.assertIn(opt, md)
            for opt in comp.base_options:
                self.assertIn(opt, md)
        self.assertNotIn('b_unknown', md)

    @staticmethod
    def _get_section_content(name, sections, md):
        for section in sections:
            if section and section.group(1) == name:
                try:
                    next_section = next(sections)
                    end = next_section.start()
                except StopIteration:
                    end = len(md)
                # Extract the content for this section
                return md[section.end():end]
        raise RuntimeError('Could not find "{}" heading'.format(name))

    def test_builtin_options_documented(self):
        '''
        Test that universal options and base options are documented in
        Builtin-Options.md.
        '''
        from itertools import tee
        md = None
        with open('docs/markdown/Builtin-options.md', encoding='utf-8') as f:
            md = f.read()
        self.assertIsNotNone(md)

        found_entries = set()
        sections = re.finditer(r"^## (.+)$", md, re.MULTILINE)
        # Extract the content for this section
        content = self._get_section_content("Universal options", sections, md)
        subsections = tee(re.finditer(r"^### (.+)$", content, re.MULTILINE))
        subcontent1 = self._get_section_content("Directories", subsections[0], content)
        subcontent2 = self._get_section_content("Core options", subsections[1], content)
        for subcontent in (subcontent1, subcontent2):
            # Find the option names
            options = set()
            # Match either a table row or a table heading separator: | ------ |
            rows = re.finditer(r"^\|(?: (\w+) .* | *-+ *)\|", subcontent, re.MULTILINE)
            # Skip the header of the first table
            next(rows)
            # Skip the heading separator of the first table
            next(rows)
            for m in rows:
                value = m.group(1)
                # End when the `buildtype` table starts
                if value is None:
                    break
                options.add(value)
            self.assertEqual(len(found_entries & options), 0)
            found_entries |= options

        self.assertEqual(found_entries, set([
            *mesonbuild.coredata.builtin_options.keys(),
            *mesonbuild.coredata.builtin_options_per_machine.keys()
        ]))

        # Check that `buildtype` table inside `Core options` matches how
        # setting of builtin options behaves
        #
        # Find all tables inside this subsection
        tables = re.finditer(r"^\| (\w+) .* \|\n\| *[-|\s]+ *\|$", subcontent2, re.MULTILINE)
        # Get the table we want using the header of the first column
        table = self._get_section_content('buildtype', tables, subcontent2)
        # Get table row data
        rows = re.finditer(r"^\|(?: (\w+)\s+\| (\w+)\s+\| (\w+) .* | *-+ *)\|", table, re.MULTILINE)
        env = get_fake_env()
        for m in rows:
            buildtype, debug, opt = m.groups()
            if debug == 'true':
                debug = True
            elif debug == 'false':
                debug = False
            else:
                raise RuntimeError('Invalid debug value {!r} in row:\n{}'.format(debug, m.group()))
            env.coredata.set_builtin_option('buildtype', buildtype)
            self.assertEqual(env.coredata.builtins['buildtype'].value, buildtype)
            self.assertEqual(env.coredata.builtins['optimization'].value, opt)
            self.assertEqual(env.coredata.builtins['debug'].value, debug)

    def test_cpu_families_documented(self):
        with open("docs/markdown/Reference-tables.md", encoding='utf-8') as f:
            md = f.read()
        self.assertIsNotNone(md)

        sections = re.finditer(r"^## (.+)$", md, re.MULTILINE)
        content = self._get_section_content("CPU families", sections, md)
        # Find the list entries
        arches = [m.group(1) for m in re.finditer(r"^\| (\w+) +\|", content, re.MULTILINE)]
        # Drop the header
        arches = set(arches[1:])
        self.assertEqual(arches, set(mesonbuild.environment.known_cpu_families))

    def test_markdown_files_in_sitemap(self):
        '''
        Test that each markdown files in docs/markdown is referenced in sitemap.txt
        '''
        with open("docs/sitemap.txt", encoding='utf-8') as f:
            md = f.read()
        self.assertIsNotNone(md)
        toc = list(m.group(1) for m in re.finditer(r"^\s*(\w.*)$", md, re.MULTILINE))
        markdownfiles = [f.name for f in Path("docs/markdown").iterdir() if f.is_file() and f.suffix == '.md']
        exceptions = ['_Sidebar.md']
        for f in markdownfiles:
            if f not in exceptions:
                self.assertIn(f, toc)

    def test_vim_syntax_highlighting(self):
        '''
        Ensure that vim syntax highlighting files were updated for new
        functions in the global namespace in build files.
        '''
        env = get_fake_env()
        interp = Interpreter(FakeBuild(env), mock=True)
        with open('data/syntax-highlighting/vim/syntax/meson.vim') as f:
            res = re.search(r'syn keyword mesonBuiltin(\s+\\\s\w+)+', f.read(), re.MULTILINE)
            defined = set([a.strip() for a in res.group().split('\\')][1:])
            self.assertEqual(defined, set(chain(interp.funcs.keys(), interp.builtin.keys())))

    @unittest.skipIf(is_pull(), 'Skipping because this is a pull request')
    def test_json_grammar_syntax_highlighting(self):
        '''
        Ensure that syntax highlighting JSON grammar written by TingPing was
        updated for new functions in the global namespace in build files.
        https://github.com/TingPing/language-meson/
        '''
        env = get_fake_env()
        interp = Interpreter(FakeBuild(env), mock=True)
        url = 'https://raw.githubusercontent.com/TingPing/language-meson/master/grammars/meson.json'
        try:
            # Use a timeout to avoid blocking forever in case the network is
            # slow or unavailable in a weird way
            r = urllib.request.urlopen(url, timeout=URLOPEN_TIMEOUT)
        except urllib.error.URLError as e:
            # Skip test when network is not available, such as during packaging
            # by a distro or Flatpak
            if not isinstance(e, urllib.error.HTTPError):
                raise unittest.SkipTest('Network unavailable')
            # Don't fail the test if github is down, but do fail if 4xx
            if e.code >= 500:
                raise unittest.SkipTest('Server error ' + str(e.code))
            raise e
        # On Python 3.5, we must decode bytes to string. Newer versions don't require that.
        grammar = json.loads(r.read().decode('utf-8', 'surrogatepass'))
        for each in grammar['patterns']:
            if 'name' in each and each['name'] == 'support.function.builtin.meson':
                # The string is of the form: (?x)\\b(func1|func2|...\n)\\b\\s*(?=\\() and
                # we convert that to [func1, func2, ...] without using regex to parse regex
                funcs = set(each['match'].split('\\b(')[1].split('\n')[0].split('|'))
            if 'name' in each and each['name'] == 'support.variable.meson':
                # \\b(builtin1|builtin2...)\\b
                builtin = set(each['match'].split('\\b(')[1].split(')\\b')[0].split('|'))
        self.assertEqual(builtin, set(interp.builtin.keys()))
        self.assertEqual(funcs, set(interp.funcs.keys()))

    def test_all_functions_defined_in_ast_interpreter(self):
        '''
        Ensure that the all functions defined in the Interpreter are also defined
        in the AstInterpreter (and vice versa).
        '''
        env = get_fake_env()
        interp = Interpreter(FakeBuild(env), mock=True)
        astint = AstInterpreter('.', '', '')
        self.assertEqual(set(interp.funcs.keys()), set(astint.funcs.keys()))

    def test_mesondata_is_up_to_date(self):
        from mesonbuild.mesondata import mesondata
        err_msg = textwrap.dedent('''

            ###########################################################
            ###        mesonbuild.mesondata is not up-to-date       ###
            ###  Please regenerate it by running tools/gen_data.py  ###
            ###########################################################

        ''')

        root_dir = Path(__file__).resolve().parent
        mesonbuild_dir = root_dir / 'mesonbuild'

        data_dirs = mesonbuild_dir.glob('**/data')
        data_files = []  # type: T.List[T.Tuple(str, str)]

        for i in data_dirs:
            for p in i.iterdir():
                data_files += [(p.relative_to(mesonbuild_dir).as_posix(), hashlib.sha256(p.read_bytes()).hexdigest())]

        from pprint import pprint
        current_files = set(mesondata.keys())
        scanned_files = set([x[0] for x in data_files])

        self.assertSetEqual(current_files, scanned_files, err_msg + 'Data files were added or removed\n')
        errors = []
        for i in data_files:
            if mesondata[i[0]].sha256sum != i[1]:
                errors += [i[0]]

        self.assertListEqual(errors, [], err_msg + 'Files were changed')

class BasePlatformTests(unittest.TestCase):
    prefix = '/usr'
    libdir = 'lib'

    def setUp(self):
        super().setUp()
        self.maxDiff = None
        src_root = os.path.dirname(__file__)
        src_root = os.path.join(os.getcwd(), src_root)
        self.src_root = src_root
        # Get the backend
        # FIXME: Extract this from argv?
        self.backend = getattr(Backend, os.environ.get('MESON_UNIT_TEST_BACKEND', 'ninja'))
        self.meson_args = ['--backend=' + self.backend.name]
        self.meson_native_file = None
        self.meson_cross_file = None
        self.meson_command = python_command + [get_meson_script()]
        self.setup_command = self.meson_command + self.meson_args
        self.mconf_command = self.meson_command + ['configure']
        self.mintro_command = self.meson_command + ['introspect']
        self.wrap_command = self.meson_command + ['wrap']
        self.rewrite_command = self.meson_command + ['rewrite']
        # Backend-specific build commands
        self.build_command, self.clean_command, self.test_command, self.install_command, \
            self.uninstall_command = get_backend_commands(self.backend)
        # Test directories
        self.common_test_dir = os.path.join(src_root, 'test cases/common')
        self.vala_test_dir = os.path.join(src_root, 'test cases/vala')
        self.framework_test_dir = os.path.join(src_root, 'test cases/frameworks')
        self.unit_test_dir = os.path.join(src_root, 'test cases/unit')
        self.rewrite_test_dir = os.path.join(src_root, 'test cases/rewrite')
        self.linuxlike_test_dir = os.path.join(src_root, 'test cases/linuxlike')
        # Misc stuff
        self.orig_env = os.environ.copy()
        if self.backend is Backend.ninja:
            self.no_rebuild_stdout = ['ninja: no work to do.', 'samu: nothing to do']
        else:
            # VS doesn't have a stable output when no changes are done
            # XCode backend is untested with unit tests, help welcome!
            self.no_rebuild_stdout = ['UNKNOWN BACKEND {!r}'.format(self.backend.name)]

        self.builddirs = []
        self.new_builddir()

    def change_builddir(self, newdir):
        self.builddir = newdir
        self.privatedir = os.path.join(self.builddir, 'meson-private')
        self.logdir = os.path.join(self.builddir, 'meson-logs')
        self.installdir = os.path.join(self.builddir, 'install')
        self.distdir = os.path.join(self.builddir, 'meson-dist')
        self.mtest_command = self.meson_command + ['test', '-C', self.builddir]
        self.builddirs.append(self.builddir)

    def new_builddir(self):
        if not is_cygwin():
            # Keep builddirs inside the source tree so that virus scanners
            # don't complain
            newdir = tempfile.mkdtemp(dir=os.getcwd())
        else:
            # But not on Cygwin because that breaks the umask tests. See:
            # https://github.com/mesonbuild/meson/pull/5546#issuecomment-509666523
            newdir = tempfile.mkdtemp()
        # In case the directory is inside a symlinked directory, find the real
        # path otherwise we might not find the srcdir from inside the builddir.
        newdir = os.path.realpath(newdir)
        self.change_builddir(newdir)

    def _print_meson_log(self):
        log = os.path.join(self.logdir, 'meson-log.txt')
        if not os.path.isfile(log):
            print("{!r} doesn't exist".format(log))
            return
        with open(log, 'r', encoding='utf-8') as f:
            print(f.read())

    def tearDown(self):
        for path in self.builddirs:
            try:
                windows_proof_rmtree(path)
            except FileNotFoundError:
                pass
        os.environ.clear()
        os.environ.update(self.orig_env)
        super().tearDown()

    def _run(self, command, *, workdir=None, override_envvars=None):
        '''
        Run a command while printing the stdout and stderr to stdout,
        and also return a copy of it
        '''
        # If this call hangs CI will just abort. It is very hard to distinguish
        # between CI issue and test bug in that case. Set timeout and fail loud
        # instead.
        if override_envvars is None:
            env = None
        else:
            env = os.environ.copy()
            env.update(override_envvars)

        p = subprocess.run(command, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, env=env,
                           universal_newlines=True, cwd=workdir, timeout=60 * 5)
        print(p.stdout)
        if p.returncode != 0:
            if 'MESON_SKIP_TEST' in p.stdout:
                raise unittest.SkipTest('Project requested skipping.')
            raise subprocess.CalledProcessError(p.returncode, command, output=p.stdout)
        return p.stdout

    def init(self, srcdir, *,
             extra_args=None,
             default_args=True,
             inprocess=False,
             override_envvars=None,
             workdir=None):
        self.assertPathExists(srcdir)
        if extra_args is None:
            extra_args = []
        if not isinstance(extra_args, list):
            extra_args = [extra_args]
        args = [srcdir, self.builddir]
        if default_args:
            args += ['--prefix', self.prefix]
            if self.libdir:
                args += ['--libdir', self.libdir]
            if self.meson_native_file:
                args += ['--native-file', self.meson_native_file]
            if self.meson_cross_file:
                args += ['--cross-file', self.meson_cross_file]
        self.privatedir = os.path.join(self.builddir, 'meson-private')
        if inprocess:
            try:
                if override_envvars is not None:
                    old_envvars = os.environ.copy()
                    os.environ.update(override_envvars)
                (returncode, out, err) = run_configure_inprocess(self.meson_args + args + extra_args)
                if override_envvars is not None:
                    os.environ.clear()
                    os.environ.update(old_envvars)
                if 'MESON_SKIP_TEST' in out:
                    raise unittest.SkipTest('Project requested skipping.')
                if returncode != 0:
                    self._print_meson_log()
                    print('Stdout:\n')
                    print(out)
                    print('Stderr:\n')
                    print(err)
                    raise RuntimeError('Configure failed')
            except Exception:
                self._print_meson_log()
                raise
            finally:
                # Close log file to satisfy Windows file locking
                mesonbuild.mlog.shutdown()
                mesonbuild.mlog.log_dir = None
                mesonbuild.mlog.log_file = None
        else:
            try:
                out = self._run(self.setup_command + args + extra_args, override_envvars=override_envvars, workdir=workdir)
            except unittest.SkipTest:
                raise unittest.SkipTest('Project requested skipping: ' + srcdir)
            except Exception:
                self._print_meson_log()
                raise
        return out

    def build(self, target=None, *, extra_args=None, override_envvars=None):
        if extra_args is None:
            extra_args = []
        # Add arguments for building the target (if specified),
        # and using the build dir (if required, with VS)
        args = get_builddir_target_args(self.backend, self.builddir, target)
        return self._run(self.build_command + args + extra_args, workdir=self.builddir, override_envvars=override_envvars)

    def clean(self, *, override_envvars=None):
        dir_args = get_builddir_target_args(self.backend, self.builddir, None)
        self._run(self.clean_command + dir_args, workdir=self.builddir, override_envvars=override_envvars)

    def run_tests(self, *, inprocess=False, override_envvars=None):
        if not inprocess:
            self._run(self.test_command, workdir=self.builddir, override_envvars=override_envvars)
        else:
            if override_envvars is not None:
                old_envvars = os.environ.copy()
                os.environ.update(override_envvars)
            try:
                run_mtest_inprocess(['-C', self.builddir])
            finally:
                if override_envvars is not None:
                    os.environ.clear()
                    os.environ.update(old_envvars)

    def install(self, *, use_destdir=True, override_envvars=None):
        if self.backend is not Backend.ninja:
            raise unittest.SkipTest('{!r} backend can\'t install files'.format(self.backend.name))
        if use_destdir:
            destdir = {'DESTDIR': self.installdir}
            if override_envvars is None:
                override_envvars = destdir
            else:
                override_envvars.update(destdir)
        self._run(self.install_command, workdir=self.builddir, override_envvars=override_envvars)

    def uninstall(self, *, override_envvars=None):
        self._run(self.uninstall_command, workdir=self.builddir, override_envvars=override_envvars)

    def run_target(self, target, *, override_envvars=None):
        '''
        Run a Ninja target while printing the stdout and stderr to stdout,
        and also return a copy of it
        '''
        return self.build(target=target, override_envvars=override_envvars)

    def setconf(self, arg, will_build=True):
        if not isinstance(arg, list):
            arg = [arg]
        if will_build:
            ensure_backend_detects_changes(self.backend)
        self._run(self.mconf_command + arg + [self.builddir])

    def wipe(self):
        windows_proof_rmtree(self.builddir)

    def utime(self, f):
        ensure_backend_detects_changes(self.backend)
        os.utime(f)

    def get_compdb(self):
        if self.backend is not Backend.ninja:
            raise unittest.SkipTest('Compiler db not available with {} backend'.format(self.backend.name))
        try:
            with open(os.path.join(self.builddir, 'compile_commands.json')) as ifile:
                contents = json.load(ifile)
        except FileNotFoundError:
            raise unittest.SkipTest('Compiler db not found')
        # If Ninja is using .rsp files, generate them, read their contents, and
        # replace it as the command for all compile commands in the parsed json.
        if len(contents) > 0 and contents[0]['command'].endswith('.rsp'):
            # Pretend to build so that the rsp files are generated
            self.build(extra_args=['-d', 'keeprsp', '-n'])
            for each in contents:
                # Extract the actual command from the rsp file
                compiler, rsp = each['command'].split(' @')
                rsp = os.path.join(self.builddir, rsp)
                # Replace the command with its contents
                with open(rsp, 'r', encoding='utf-8') as f:
                    each['command'] = compiler + ' ' + f.read()
        return contents

    def get_meson_log(self):
        with open(os.path.join(self.builddir, 'meson-logs', 'meson-log.txt')) as f:
            return f.readlines()

    def get_meson_log_compiler_checks(self):
        '''
        Fetch a list command-lines run by meson for compiler checks.
        Each command-line is returned as a list of arguments.
        '''
        log = self.get_meson_log()
        prefix = 'Command line:'
        cmds = [l[len(prefix):].split() for l in log if l.startswith(prefix)]
        return cmds

    def get_meson_log_sanitychecks(self):
        '''
        Same as above, but for the sanity checks that were run
        '''
        log = self.get_meson_log()
        prefix = 'Sanity check compiler command line:'
        cmds = [l[len(prefix):].split() for l in log if l.startswith(prefix)]
        return cmds

    def introspect(self, args):
        if isinstance(args, str):
            args = [args]
        out = subprocess.check_output(self.mintro_command + args + [self.builddir],
                                      universal_newlines=True)
        return json.loads(out)

    def introspect_directory(self, directory, args):
        if isinstance(args, str):
            args = [args]
        out = subprocess.check_output(self.mintro_command + args + [directory],
                                      universal_newlines=True)
        try:
            obj = json.loads(out)
        except Exception as e:
            print(out)
            raise e
        return obj

    def assertPathEqual(self, path1, path2):
        '''
        Handles a lot of platform-specific quirks related to paths such as
        separator, case-sensitivity, etc.
        '''
        self.assertEqual(PurePath(path1), PurePath(path2))

    def assertPathListEqual(self, pathlist1, pathlist2):
        self.assertEqual(len(pathlist1), len(pathlist2))
        worklist = list(zip(pathlist1, pathlist2))
        for i in worklist:
            if i[0] is None:
                self.assertEqual(i[0], i[1])
            else:
                self.assertPathEqual(i[0], i[1])

    def assertPathBasenameEqual(self, path, basename):
        msg = '{!r} does not end with {!r}'.format(path, basename)
        # We cannot use os.path.basename because it returns '' when the path
        # ends with '/' for some silly reason. This is not how the UNIX utility
        # `basename` works.
        path_basename = PurePath(path).parts[-1]
        self.assertEqual(PurePath(path_basename), PurePath(basename), msg)

    def assertReconfiguredBuildIsNoop(self):
        'Assert that we reconfigured and then there was nothing to do'
        ret = self.build()
        self.assertIn('The Meson build system', ret)
        if self.backend is Backend.ninja:
            for line in ret.split('\n'):
                if line in self.no_rebuild_stdout:
                    break
            else:
                raise AssertionError('build was reconfigured, but was not no-op')
        elif self.backend is Backend.vs:
            # Ensure that some target said that no rebuild was done
            # XXX: Note CustomBuild did indeed rebuild, because of the regen checker!
            self.assertIn('ClCompile:\n  All outputs are up-to-date.', ret)
            self.assertIn('Link:\n  All outputs are up-to-date.', ret)
            # Ensure that no targets were built
            self.assertNotRegex(ret, re.compile('ClCompile:\n [^\n]*cl', flags=re.IGNORECASE))
            self.assertNotRegex(ret, re.compile('Link:\n [^\n]*link', flags=re.IGNORECASE))
        elif self.backend is Backend.xcode:
            raise unittest.SkipTest('Please help us fix this test on the xcode backend')
        else:
            raise RuntimeError('Invalid backend: {!r}'.format(self.backend.name))

    def assertBuildIsNoop(self):
        ret = self.build()
        if self.backend is Backend.ninja:
            self.assertIn(ret.split('\n')[-2], self.no_rebuild_stdout)
        elif self.backend is Backend.vs:
            # Ensure that some target of each type said that no rebuild was done
            # We always have at least one CustomBuild target for the regen checker
            self.assertIn('CustomBuild:\n  All outputs are up-to-date.', ret)
            self.assertIn('ClCompile:\n  All outputs are up-to-date.', ret)
            self.assertIn('Link:\n  All outputs are up-to-date.', ret)
            # Ensure that no targets were built
            self.assertNotRegex(ret, re.compile('CustomBuild:\n [^\n]*cl', flags=re.IGNORECASE))
            self.assertNotRegex(ret, re.compile('ClCompile:\n [^\n]*cl', flags=re.IGNORECASE))
            self.assertNotRegex(ret, re.compile('Link:\n [^\n]*link', flags=re.IGNORECASE))
        elif self.backend is Backend.xcode:
            raise unittest.SkipTest('Please help us fix this test on the xcode backend')
        else:
            raise RuntimeError('Invalid backend: {!r}'.format(self.backend.name))

    def assertRebuiltTarget(self, target):
        ret = self.build()
        if self.backend is Backend.ninja:
            self.assertIn('Linking target {}'.format(target), ret)
        elif self.backend is Backend.vs:
            # Ensure that this target was rebuilt
            linkre = re.compile('Link:\n [^\n]*link[^\n]*' + target, flags=re.IGNORECASE)
            self.assertRegex(ret, linkre)
        elif self.backend is Backend.xcode:
            raise unittest.SkipTest('Please help us fix this test on the xcode backend')
        else:
            raise RuntimeError('Invalid backend: {!r}'.format(self.backend.name))

    @staticmethod
    def get_target_from_filename(filename):
        base = os.path.splitext(filename)[0]
        if base.startswith(('lib', 'cyg')):
            return base[3:]
        return base

    def assertBuildRelinkedOnlyTarget(self, target):
        ret = self.build()
        if self.backend is Backend.ninja:
            linked_targets = []
            for line in ret.split('\n'):
                if 'Linking target' in line:
                    fname = line.rsplit('target ')[-1]
                    linked_targets.append(self.get_target_from_filename(fname))
            self.assertEqual(linked_targets, [target])
        elif self.backend is Backend.vs:
            # Ensure that this target was rebuilt
            linkre = re.compile(r'Link:\n  [^\n]*link.exe[^\n]*/OUT:".\\([^"]*)"', flags=re.IGNORECASE)
            matches = linkre.findall(ret)
            self.assertEqual(len(matches), 1, msg=matches)
            self.assertEqual(self.get_target_from_filename(matches[0]), target)
        elif self.backend is Backend.xcode:
            raise unittest.SkipTest('Please help us fix this test on the xcode backend')
        else:
            raise RuntimeError('Invalid backend: {!r}'.format(self.backend.name))

    def assertPathExists(self, path):
        m = 'Path {!r} should exist'.format(path)
        self.assertTrue(os.path.exists(path), msg=m)

    def assertPathDoesNotExist(self, path):
        m = 'Path {!r} should not exist'.format(path)
        self.assertFalse(os.path.exists(path), msg=m)


class AllPlatformTests(BasePlatformTests):
    '''
    Tests that should run on all platforms
    '''

    def test_default_options_prefix(self):
        '''
        Tests that setting a prefix in default_options in project() works.
        Can't be an ordinary test because we pass --prefix to meson there.
        https://github.com/mesonbuild/meson/issues/1349
        '''
        testdir = os.path.join(self.common_test_dir, '90 default options')
        self.init(testdir, default_args=False)
        opts = self.introspect('--buildoptions')
        for opt in opts:
            if opt['name'] == 'prefix':
                prefix = opt['value']
        self.assertEqual(prefix, '/absoluteprefix')

    def test_do_conf_file_preserve_newlines(self):

        def conf_file(in_data, confdata):
            with temp_filename() as fin:
                with open(fin, 'wb') as fobj:
                    fobj.write(in_data.encode('utf-8'))
                with temp_filename() as fout:
                    mesonbuild.mesonlib.do_conf_file(fin, fout, confdata, 'meson')
                    with open(fout, 'rb') as fobj:
                        return fobj.read().decode('utf-8')

        confdata = {'VAR': ('foo', 'bar')}
        self.assertEqual(conf_file('@VAR@\n@VAR@\n', confdata), 'foo\nfoo\n')
        self.assertEqual(conf_file('@VAR@\r\n@VAR@\r\n', confdata), 'foo\r\nfoo\r\n')

    def test_do_conf_file_by_format(self):
        def conf_str(in_data, confdata, vformat):
            (result, missing_variables, confdata_useless) = mesonbuild.mesonlib.do_conf_str(in_data, confdata, variable_format = vformat)
            return '\n'.join(result)

        def check_formats(confdata, result):
            self.assertEqual(conf_str(['#mesondefine VAR'], confdata, 'meson'), result)
            self.assertEqual(conf_str(['#cmakedefine VAR ${VAR}'], confdata, 'cmake'), result)
            self.assertEqual(conf_str(['#cmakedefine VAR @VAR@'], confdata, 'cmake@'), result)

        confdata = ConfigurationData()
        # Key error as they do not exists
        check_formats(confdata, '/* #undef VAR */\n')

        # Check boolean
        confdata.values = {'VAR': (False, 'description')}
        check_formats(confdata, '#undef VAR\n')
        confdata.values = {'VAR': (True, 'description')}
        check_formats(confdata, '#define VAR\n')

        # Check string
        confdata.values = {'VAR': ('value', 'description')}
        check_formats(confdata, '#define VAR value\n')

        # Check integer
        confdata.values = {'VAR': (10, 'description')}
        check_formats(confdata, '#define VAR 10\n')

        # Check multiple string with cmake formats
        confdata.values = {'VAR': ('value', 'description')}
        self.assertEqual(conf_str(['#cmakedefine VAR xxx @VAR@ yyy @VAR@'], confdata, 'cmake@'), '#define VAR xxx value yyy value\n')
        self.assertEqual(conf_str(['#define VAR xxx @VAR@ yyy @VAR@'], confdata, 'cmake@'), '#define VAR xxx value yyy value')
        self.assertEqual(conf_str(['#cmakedefine VAR xxx ${VAR} yyy ${VAR}'], confdata, 'cmake'), '#define VAR xxx value yyy value\n')
        self.assertEqual(conf_str(['#define VAR xxx ${VAR} yyy ${VAR}'], confdata, 'cmake'), '#define VAR xxx value yyy value')

        # Handles meson format exceptions
        #   Unknown format
        self.assertRaises(mesonbuild.mesonlib.MesonException, conf_str, ['#mesondefine VAR xxx'], confdata, 'unknown_format')
        #   More than 2 params in mesondefine
        self.assertRaises(mesonbuild.mesonlib.MesonException, conf_str, ['#mesondefine VAR xxx'], confdata, 'meson')
        #   Mismatched line with format
        self.assertRaises(mesonbuild.mesonlib.MesonException, conf_str, ['#cmakedefine VAR'], confdata, 'meson')
        self.assertRaises(mesonbuild.mesonlib.MesonException, conf_str, ['#mesondefine VAR'], confdata, 'cmake')
        self.assertRaises(mesonbuild.mesonlib.MesonException, conf_str, ['#mesondefine VAR'], confdata, 'cmake@')
        #   Dict value in confdata
        confdata.values = {'VAR': (['value'], 'description')}
        self.assertRaises(mesonbuild.mesonlib.MesonException, conf_str, ['#mesondefine VAR'], confdata, 'meson')

    def test_absolute_prefix_libdir(self):
        '''
        Tests that setting absolute paths for --prefix and --libdir work. Can't
        be an ordinary test because these are set via the command-line.
        https://github.com/mesonbuild/meson/issues/1341
        https://github.com/mesonbuild/meson/issues/1345
        '''
        testdir = os.path.join(self.common_test_dir, '90 default options')
        # on Windows, /someabs is *not* an absolute path
        prefix = 'x:/someabs' if is_windows() else '/someabs'
        libdir = 'libdir'
        extra_args = ['--prefix=' + prefix,
                      # This can just be a relative path, but we want to test
                      # that passing this as an absolute path also works
                      '--libdir=' + prefix + '/' + libdir]
        self.init(testdir, extra_args=extra_args, default_args=False)
        opts = self.introspect('--buildoptions')
        for opt in opts:
            if opt['name'] == 'prefix':
                self.assertEqual(prefix, opt['value'])
            elif opt['name'] == 'libdir':
                self.assertEqual(libdir, opt['value'])

    def test_libdir_must_be_inside_prefix(self):
        '''
        Tests that libdir is forced to be inside prefix no matter how it is set.
        Must be a unit test for obvious reasons.
        '''
        testdir = os.path.join(self.common_test_dir, '1 trivial')
        # libdir being inside prefix is ok
        if is_windows():
            args = ['--prefix', 'x:/opt', '--libdir', 'x:/opt/lib32']
        else:
            args = ['--prefix', '/opt', '--libdir', '/opt/lib32']
        self.init(testdir, extra_args=args)
        self.wipe()
        # libdir not being inside prefix is not ok
        if is_windows():
            args = ['--prefix', 'x:/usr', '--libdir', 'x:/opt/lib32']
        else:
            args = ['--prefix', '/usr', '--libdir', '/opt/lib32']
        self.assertRaises(subprocess.CalledProcessError, self.init, testdir, extra_args=args)
        self.wipe()
        # libdir must be inside prefix even when set via mesonconf
        self.init(testdir)
        if is_windows():
            self.assertRaises(subprocess.CalledProcessError, self.setconf, '-Dlibdir=x:/opt', False)
        else:
            self.assertRaises(subprocess.CalledProcessError, self.setconf, '-Dlibdir=/opt', False)

    def test_prefix_dependent_defaults(self):
        '''
        Tests that configured directory paths are set to prefix dependent
        defaults.
        '''
        testdir = os.path.join(self.common_test_dir, '1 trivial')
        expected = {
            '/opt': {'prefix': '/opt',
                     'bindir': 'bin', 'datadir': 'share', 'includedir': 'include',
                     'infodir': 'share/info',
                     'libexecdir': 'libexec', 'localedir': 'share/locale',
                     'localstatedir': 'var', 'mandir': 'share/man',
                     'sbindir': 'sbin', 'sharedstatedir': 'com',
                     'sysconfdir': 'etc'},
            '/usr': {'prefix': '/usr',
                     'bindir': 'bin', 'datadir': 'share', 'includedir': 'include',
                     'infodir': 'share/info',
                     'libexecdir': 'libexec', 'localedir': 'share/locale',
                     'localstatedir': '/var', 'mandir': 'share/man',
                     'sbindir': 'sbin', 'sharedstatedir': '/var/lib',
                     'sysconfdir': '/etc'},
            '/usr/local': {'prefix': '/usr/local',
                           'bindir': 'bin', 'datadir': 'share',
                           'includedir': 'include', 'infodir': 'share/info',
                           'libexecdir': 'libexec',
                           'localedir': 'share/locale',
                           'localstatedir': '/var/local', 'mandir': 'share/man',
                           'sbindir': 'sbin', 'sharedstatedir': '/var/local/lib',
                           'sysconfdir': 'etc'},
            # N.B. We don't check 'libdir' as it's platform dependent, see
            # default_libdir():
        }

        if mesonbuild.mesonlib.default_prefix() == '/usr/local':
            expected[None] = expected['/usr/local']

        for prefix in expected:
            args = []
            if prefix:
                args += ['--prefix', prefix]
            self.init(testdir, extra_args=args, default_args=False)
            opts = self.introspect('--buildoptions')
            for opt in opts:
                name = opt['name']
                value = opt['value']
                if name in expected[prefix]:
                    self.assertEqual(value, expected[prefix][name])
            self.wipe()

    def test_default_options_prefix_dependent_defaults(self):
        '''
        Tests that setting a prefix in default_options in project() sets prefix
        dependent defaults for other options, and that those defaults can
        be overridden in default_options or by the command line.
        '''
        testdir = os.path.join(self.common_test_dir, '168 default options prefix dependent defaults')
        expected = {
            '':
            {'prefix':         '/usr',
             'sysconfdir':     '/etc',
             'localstatedir':  '/var',
             'sharedstatedir': '/sharedstate'},
            '--prefix=/usr':
            {'prefix':         '/usr',
             'sysconfdir':     '/etc',
             'localstatedir':  '/var',
             'sharedstatedir': '/sharedstate'},
            '--sharedstatedir=/var/state':
            {'prefix':         '/usr',
             'sysconfdir':     '/etc',
             'localstatedir':  '/var',
             'sharedstatedir': '/var/state'},
            '--sharedstatedir=/var/state --prefix=/usr --sysconfdir=sysconf':
            {'prefix':         '/usr',
             'sysconfdir':     'sysconf',
             'localstatedir':  '/var',
             'sharedstatedir': '/var/state'},
        }
        for args in expected:
            self.init(testdir, extra_args=args.split(), default_args=False)
            opts = self.introspect('--buildoptions')
            for opt in opts:
                name = opt['name']
                value = opt['value']
                if name in expected[args]:
                    self.assertEqual(value, expected[args][name])
            self.wipe()

    def test_clike_get_library_dirs(self):
        env = get_fake_env()
        cc = env.detect_c_compiler(MachineChoice.HOST)
        for d in cc.get_library_dirs(env):
            self.assertTrue(os.path.exists(d))
            self.assertTrue(os.path.isdir(d))
            self.assertTrue(os.path.isabs(d))

    def test_static_library_overwrite(self):
        '''
        Tests that static libraries are never appended to, always overwritten.
        Has to be a unit test because this involves building a project,
        reconfiguring, and building it again so that `ar` is run twice on the
        same static library.
        https://github.com/mesonbuild/meson/issues/1355
        '''
        testdir = os.path.join(self.common_test_dir, '3 static')
        env = get_fake_env(testdir, self.builddir, self.prefix)
        cc = env.detect_c_compiler(MachineChoice.HOST)
        static_linker = env.detect_static_linker(cc)
        if is_windows():
            raise unittest.SkipTest('https://github.com/mesonbuild/meson/issues/1526')
        if not isinstance(static_linker, mesonbuild.linkers.ArLinker):
            raise unittest.SkipTest('static linker is not `ar`')
        # Configure
        self.init(testdir)
        # Get name of static library
        targets = self.introspect('--targets')
        self.assertEqual(len(targets), 1)
        libname = targets[0]['filename'][0]
        # Build and get contents of static library
        self.build()
        before = self._run(['ar', 't', os.path.join(self.builddir, libname)]).split()
        # Filter out non-object-file contents
        before = [f for f in before if f.endswith(('.o', '.obj'))]
        # Static library should contain only one object
        self.assertEqual(len(before), 1, msg=before)
        # Change the source to be built into the static library
        self.setconf('-Dsource=libfile2.c')
        self.build()
        after = self._run(['ar', 't', os.path.join(self.builddir, libname)]).split()
        # Filter out non-object-file contents
        after = [f for f in after if f.endswith(('.o', '.obj'))]
        # Static library should contain only one object
        self.assertEqual(len(after), 1, msg=after)
        # and the object must have changed
        self.assertNotEqual(before, after)

    def test_static_compile_order(self):
        '''
        Test that the order of files in a compiler command-line while compiling
        and linking statically is deterministic. This can't be an ordinary test
        case because we need to inspect the compiler database.
        https://github.com/mesonbuild/meson/pull/951
        '''
        testdir = os.path.join(self.common_test_dir, '5 linkstatic')
        self.init(testdir)
        compdb = self.get_compdb()
        # Rules will get written out in this order
        self.assertTrue(compdb[0]['file'].endswith("libfile.c"))
        self.assertTrue(compdb[1]['file'].endswith("libfile2.c"))
        self.assertTrue(compdb[2]['file'].endswith("libfile3.c"))
        self.assertTrue(compdb[3]['file'].endswith("libfile4.c"))
        # FIXME: We don't have access to the linker command

    def test_run_target_files_path(self):
        '''
        Test that run_targets are run from the correct directory
        https://github.com/mesonbuild/meson/issues/957
        '''
        testdir = os.path.join(self.common_test_dir, '54 run target')
        self.init(testdir)
        self.run_target('check_exists')

    def test_install_introspection(self):
        '''
        Tests that the Meson introspection API exposes install filenames correctly
        https://github.com/mesonbuild/meson/issues/829
        '''
        if self.backend is not Backend.ninja:
            raise unittest.SkipTest('{!r} backend can\'t install files'.format(self.backend.name))
        testdir = os.path.join(self.common_test_dir, '8 install')
        self.init(testdir)
        intro = self.introspect('--targets')
        if intro[0]['type'] == 'executable':
            intro = intro[::-1]
        self.assertPathListEqual(intro[0]['install_filename'], ['/usr/lib/libstat.a'])
        self.assertPathListEqual(intro[1]['install_filename'], ['/usr/bin/prog' + exe_suffix])

    def test_install_subdir_introspection(self):
        '''
        Test that the Meson introspection API also contains subdir install information
        https://github.com/mesonbuild/meson/issues/5556
        '''
        testdir = os.path.join(self.common_test_dir, '62 install subdir')
        self.init(testdir)
        intro = self.introspect('--installed')
        expected = {
            'sub2': 'share/sub2',
            'subdir/sub1': 'share/sub1',
            'subdir/sub_elided': 'share',
            'sub1': 'share/sub1',
            'sub/sub1': 'share/sub1',
            'sub_elided': 'share',
            'nested_elided/sub': 'share',
        }

        self.assertEqual(len(intro), len(expected))

        # Convert expected to PurePath
        expected_converted = {PurePath(os.path.join(testdir, key)): PurePath(os.path.join(self.prefix, val)) for key, val in expected.items()}
        intro_converted = {PurePath(key): PurePath(val) for key, val in intro.items()}

        for src, dst in expected_converted.items():
            self.assertIn(src, intro_converted)
            self.assertEqual(dst, intro_converted[src])

    def test_install_introspection_multiple_outputs(self):
        '''
        Tests that the Meson introspection API exposes multiple install filenames correctly without crashing
        https://github.com/mesonbuild/meson/pull/4555

        Reverted to the first file only because of https://github.com/mesonbuild/meson/pull/4547#discussion_r244173438
        TODO Change the format to a list officially in a followup PR
        '''
        if self.backend is not Backend.ninja:
            raise unittest.SkipTest('{!r} backend can\'t install files'.format(self.backend.name))
        testdir = os.path.join(self.common_test_dir, '144 custom target multiple outputs')
        self.init(testdir)
        intro = self.introspect('--targets')
        if intro[0]['type'] == 'executable':
            intro = intro[::-1]
        self.assertPathListEqual(intro[0]['install_filename'], ['/usr/include/diff.h', '/usr/bin/diff.sh'])
        self.assertPathListEqual(intro[1]['install_filename'], ['/opt/same.h', '/opt/same.sh'])
        self.assertPathListEqual(intro[2]['install_filename'], ['/usr/include/first.h', None])
        self.assertPathListEqual(intro[3]['install_filename'], [None, '/usr/bin/second.sh'])

    def test_install_log_content(self):
        '''
        Tests that the install-log.txt is consistent with the installed files and directories.
        Specifically checks that the log file only contains one entry per file/directory.
        https://github.com/mesonbuild/meson/issues/4499
        '''
        testdir = os.path.join(self.common_test_dir, '62 install subdir')
        self.init(testdir)
        self.install()
        installpath = Path(self.installdir)
        # Find installed files and directories
        expected = {installpath: 0}
        for name in installpath.rglob('*'):
            expected[name] = 0
        # Find logged files and directories
        with Path(self.builddir, 'meson-logs', 'install-log.txt').open() as f:
            logged = list(map(lambda l: Path(l.strip()),
                              filter(lambda l: not l.startswith('#'),
                                     f.readlines())))
        for name in logged:
            self.assertTrue(name in expected, 'Log contains extra entry {}'.format(name))
            expected[name] += 1

        for name, count in expected.items():
            self.assertGreater(count, 0, 'Log is missing entry for {}'.format(name))
            self.assertLess(count, 2, 'Log has multiple entries for {}'.format(name))

    def test_uninstall(self):
        exename = os.path.join(self.installdir, 'usr/bin/prog' + exe_suffix)
        testdir = os.path.join(self.common_test_dir, '8 install')
        self.init(testdir)
        self.assertPathDoesNotExist(exename)
        self.install()
        self.assertPathExists(exename)
        self.uninstall()
        self.assertPathDoesNotExist(exename)

    def test_forcefallback(self):
        testdir = os.path.join(self.unit_test_dir, '31 forcefallback')
        self.init(testdir, extra_args=['--wrap-mode=forcefallback'])
        self.build()
        self.run_tests()

    def test_force_fallback_for(self):
        testdir = os.path.join(self.unit_test_dir, '31 forcefallback')
        self.init(testdir, extra_args=['--force-fallback-for=zlib,foo'])
        self.build()
        self.run_tests()

    def test_env_ops_dont_stack(self):
        '''
        Test that env ops prepend/append do not stack, and that this usage issues a warning
        '''
        testdir = os.path.join(self.unit_test_dir, '63 test env does not stack')
        out = self.init(testdir)
        self.assertRegex(out, r'WARNING: Overriding.*TEST_VAR_APPEND')
        self.assertRegex(out, r'WARNING: Overriding.*TEST_VAR_PREPEND')
        self.assertNotRegex(out, r'WARNING: Overriding.*TEST_VAR_SET')
        self.run_tests()

    def test_testsetups(self):
        if not shutil.which('valgrind'):
            raise unittest.SkipTest('Valgrind not installed.')
        testdir = os.path.join(self.unit_test_dir, '2 testsetups')
        self.init(testdir)
        self.build()
        # Run tests without setup
        self.run_tests()
        with open(os.path.join(self.logdir, 'testlog.txt')) as f:
            basic_log = f.read()
        # Run buggy test with setup that has env that will make it fail
        self.assertRaises(subprocess.CalledProcessError,
                          self._run, self.mtest_command + ['--setup=valgrind'])
        with open(os.path.join(self.logdir, 'testlog-valgrind.txt')) as f:
            vg_log = f.read()
        self.assertFalse('TEST_ENV is set' in basic_log)
        self.assertFalse('Memcheck' in basic_log)
        self.assertTrue('TEST_ENV is set' in vg_log)
        self.assertTrue('Memcheck' in vg_log)
        # Run buggy test with setup without env that will pass
        self._run(self.mtest_command + ['--setup=wrapper'])
        # Setup with no properties works
        self._run(self.mtest_command + ['--setup=empty'])
        # Setup with only env works
        self._run(self.mtest_command + ['--setup=onlyenv'])
        self._run(self.mtest_command + ['--setup=onlyenv2'])
        self._run(self.mtest_command + ['--setup=onlyenv3'])
        # Setup with only a timeout works
        self._run(self.mtest_command + ['--setup=timeout'])

    def test_testsetup_selection(self):
        testdir = os.path.join(self.unit_test_dir, '14 testsetup selection')
        self.init(testdir)
        self.build()

        # Run tests without setup
        self.run_tests()

        self.assertRaises(subprocess.CalledProcessError, self._run, self.mtest_command + ['--setup=missingfromfoo'])
        self._run(self.mtest_command + ['--setup=missingfromfoo', '--no-suite=foo:'])

        self._run(self.mtest_command + ['--setup=worksforall'])
        self._run(self.mtest_command + ['--setup=main:worksforall'])

        self.assertRaises(subprocess.CalledProcessError, self._run,
                          self.mtest_command + ['--setup=onlyinbar'])
        self.assertRaises(subprocess.CalledProcessError, self._run,
                          self.mtest_command + ['--setup=onlyinbar', '--no-suite=main:'])
        self._run(self.mtest_command + ['--setup=onlyinbar', '--no-suite=main:', '--no-suite=foo:'])
        self._run(self.mtest_command + ['--setup=bar:onlyinbar'])
        self.assertRaises(subprocess.CalledProcessError, self._run,
                          self.mtest_command + ['--setup=foo:onlyinbar'])
        self.assertRaises(subprocess.CalledProcessError, self._run,
                          self.mtest_command + ['--setup=main:onlyinbar'])

    def test_testsetup_default(self):
        testdir = os.path.join(self.unit_test_dir, '49 testsetup default')
        self.init(testdir)
        self.build()

        # Run tests without --setup will cause the default setup to be used
        self.run_tests()
        with open(os.path.join(self.logdir, 'testlog.txt')) as f:
            default_log = f.read()

        # Run tests with explicitly using the same setup that is set as default
        self._run(self.mtest_command + ['--setup=mydefault'])
        with open(os.path.join(self.logdir, 'testlog-mydefault.txt')) as f:
            mydefault_log = f.read()

        # Run tests with another setup
        self._run(self.mtest_command + ['--setup=other'])
        with open(os.path.join(self.logdir, 'testlog-other.txt')) as f:
            other_log = f.read()

        self.assertTrue('ENV_A is 1' in default_log)
        self.assertTrue('ENV_B is 2' in default_log)
        self.assertTrue('ENV_C is 2' in default_log)

        self.assertTrue('ENV_A is 1' in mydefault_log)
        self.assertTrue('ENV_B is 2' in mydefault_log)
        self.assertTrue('ENV_C is 2' in mydefault_log)

        self.assertTrue('ENV_A is 1' in other_log)
        self.assertTrue('ENV_B is 3' in other_log)
        self.assertTrue('ENV_C is 2' in other_log)

    def assertFailedTestCount(self, failure_count, command):
        try:
            self._run(command)
            self.assertEqual(0, failure_count, 'Expected %d tests to fail.' % failure_count)
        except subprocess.CalledProcessError as e:
            self.assertEqual(e.returncode, failure_count)

    def test_suite_selection(self):
        testdir = os.path.join(self.unit_test_dir, '4 suite selection')
        self.init(testdir)
        self.build()

        self.assertFailedTestCount(4, self.mtest_command)

        self.assertFailedTestCount(0, self.mtest_command + ['--suite', ':success'])
        self.assertFailedTestCount(3, self.mtest_command + ['--suite', ':fail'])
        self.assertFailedTestCount(4, self.mtest_command + ['--no-suite', ':success'])
        self.assertFailedTestCount(1, self.mtest_command + ['--no-suite', ':fail'])

        self.assertFailedTestCount(1, self.mtest_command + ['--suite', 'mainprj'])
        self.assertFailedTestCount(0, self.mtest_command + ['--suite', 'subprjsucc'])
        self.assertFailedTestCount(1, self.mtest_command + ['--suite', 'subprjfail'])
        self.assertFailedTestCount(1, self.mtest_command + ['--suite', 'subprjmix'])
        self.assertFailedTestCount(3, self.mtest_command + ['--no-suite', 'mainprj'])
        self.assertFailedTestCount(4, self.mtest_command + ['--no-suite', 'subprjsucc'])
        self.assertFailedTestCount(3, self.mtest_command + ['--no-suite', 'subprjfail'])
        self.assertFailedTestCount(3, self.mtest_command + ['--no-suite', 'subprjmix'])

        self.assertFailedTestCount(1, self.mtest_command + ['--suite', 'mainprj:fail'])
        self.assertFailedTestCount(0, self.mtest_command + ['--suite', 'mainprj:success'])
        self.assertFailedTestCount(3, self.mtest_command + ['--no-suite', 'mainprj:fail'])
        self.assertFailedTestCount(4, self.mtest_command + ['--no-suite', 'mainprj:success'])

        self.assertFailedTestCount(1, self.mtest_command + ['--suite', 'subprjfail:fail'])
        self.assertFailedTestCount(0, self.mtest_command + ['--suite', 'subprjfail:success'])
        self.assertFailedTestCount(3, self.mtest_command + ['--no-suite', 'subprjfail:fail'])
        self.assertFailedTestCount(4, self.mtest_command + ['--no-suite', 'subprjfail:success'])

        self.assertFailedTestCount(0, self.mtest_command + ['--suite', 'subprjsucc:fail'])
        self.assertFailedTestCount(0, self.mtest_command + ['--suite', 'subprjsucc:success'])
        self.assertFailedTestCount(4, self.mtest_command + ['--no-suite', 'subprjsucc:fail'])
        self.assertFailedTestCount(4, self.mtest_command + ['--no-suite', 'subprjsucc:success'])

        self.assertFailedTestCount(1, self.mtest_command + ['--suite', 'subprjmix:fail'])
        self.assertFailedTestCount(0, self.mtest_command + ['--suite', 'subprjmix:success'])
        self.assertFailedTestCount(3, self.mtest_command + ['--no-suite', 'subprjmix:fail'])
        self.assertFailedTestCount(4, self.mtest_command + ['--no-suite', 'subprjmix:success'])

        self.assertFailedTestCount(2, self.mtest_command + ['--suite', 'subprjfail', '--suite', 'subprjmix:fail'])
        self.assertFailedTestCount(3, self.mtest_command + ['--suite', 'subprjfail', '--suite', 'subprjmix', '--suite', 'mainprj'])
        self.assertFailedTestCount(2, self.mtest_command + ['--suite', 'subprjfail', '--suite', 'subprjmix', '--suite', 'mainprj', '--no-suite', 'subprjmix:fail'])
        self.assertFailedTestCount(1, self.mtest_command + ['--suite', 'subprjfail', '--suite', 'subprjmix', '--suite', 'mainprj', '--no-suite', 'subprjmix:fail', 'mainprj-failing_test'])

        self.assertFailedTestCount(2, self.mtest_command + ['--no-suite', 'subprjfail:fail', '--no-suite', 'subprjmix:fail'])

    def test_build_by_default(self):
        testdir = os.path.join(self.common_test_dir, '133 build by default')
        self.init(testdir)
        self.build()
        genfile1 = os.path.join(self.builddir, 'generated1.dat')
        genfile2 = os.path.join(self.builddir, 'generated2.dat')
        exe1 = os.path.join(self.builddir, 'fooprog' + exe_suffix)
        exe2 = os.path.join(self.builddir, 'barprog' + exe_suffix)
        self.assertPathExists(genfile1)
        self.assertPathExists(genfile2)
        self.assertPathDoesNotExist(exe1)
        self.assertPathDoesNotExist(exe2)
        self.build(target=('fooprog' + exe_suffix))
        self.assertPathExists(exe1)
        self.build(target=('barprog' + exe_suffix))
        self.assertPathExists(exe2)

    def test_internal_include_order(self):
        if mesonbuild.environment.detect_msys2_arch() and ('MESON_RSP_THRESHOLD' in os.environ):
            raise unittest.SkipTest('Test does not yet support gcc rsp files on msys2')

        testdir = os.path.join(self.common_test_dir, '134 include order')
        self.init(testdir)
        execmd = fxecmd = None
        for cmd in self.get_compdb():
            if 'someexe' in cmd['command']:
                execmd = cmd['command']
                continue
            if 'somefxe' in cmd['command']:
                fxecmd = cmd['command']
                continue
        if not execmd or not fxecmd:
            raise Exception('Could not find someexe and somfxe commands')
        # Check include order for 'someexe'
        incs = [a for a in split_args(execmd) if a.startswith("-I")]
        self.assertEqual(len(incs), 9)
        # Need to run the build so the private dir is created.
        self.build()
        pdirs = glob(os.path.join(self.builddir, 'sub4/someexe*.p'))
        self.assertEqual(len(pdirs), 1)
        privdir = pdirs[0][len(self.builddir)+1:]
        self.assertPathEqual(incs[0], "-I" + privdir)
        # target build subdir
        self.assertPathEqual(incs[1], "-Isub4")
        # target source subdir
        self.assertPathBasenameEqual(incs[2], 'sub4')
        # include paths added via per-target c_args: ['-I'...]
        self.assertPathBasenameEqual(incs[3], 'sub3')
        # target include_directories: build dir
        self.assertPathEqual(incs[4], "-Isub2")
        # target include_directories: source dir
        self.assertPathBasenameEqual(incs[5], 'sub2')
        # target internal dependency include_directories: build dir
        self.assertPathEqual(incs[6], "-Isub1")
        # target internal dependency include_directories: source dir
        self.assertPathBasenameEqual(incs[7], 'sub1')
        # custom target include dir
        self.assertPathEqual(incs[8], '-Ictsub')
        # Check include order for 'somefxe'
        incs = [a for a in split_args(fxecmd) if a.startswith('-I')]
        self.assertEqual(len(incs), 9)
        # target private dir
        pdirs = glob(os.path.join(self.builddir, 'somefxe*.p'))
        self.assertEqual(len(pdirs), 1)
        privdir = pdirs[0][len(self.builddir)+1:]
        self.assertPathEqual(incs[0], '-I' + privdir)
        # target build dir
        self.assertPathEqual(incs[1], '-I.')
        # target source dir
        self.assertPathBasenameEqual(incs[2], os.path.basename(testdir))
        # target internal dependency correct include_directories: build dir
        self.assertPathEqual(incs[3], "-Isub4")
        # target internal dependency correct include_directories: source dir
        self.assertPathBasenameEqual(incs[4], 'sub4')
        # target internal dependency dep include_directories: build dir
        self.assertPathEqual(incs[5], "-Isub1")
        # target internal dependency dep include_directories: source dir
        self.assertPathBasenameEqual(incs[6], 'sub1')
        # target internal dependency wrong include_directories: build dir
        self.assertPathEqual(incs[7], "-Isub2")
        # target internal dependency wrong include_directories: source dir
        self.assertPathBasenameEqual(incs[8], 'sub2')

    def test_compiler_detection(self):
        '''
        Test that automatic compiler detection and setting from the environment
        both work just fine. This is needed because while running project tests
        and other unit tests, we always read CC/CXX/etc from the environment.
        '''
        gnu = mesonbuild.compilers.GnuCompiler
        clang = mesonbuild.compilers.ClangCompiler
        intel = mesonbuild.compilers.IntelGnuLikeCompiler
        msvc = (mesonbuild.compilers.VisualStudioCCompiler, mesonbuild.compilers.VisualStudioCPPCompiler)
        clangcl = (mesonbuild.compilers.ClangClCCompiler, mesonbuild.compilers.ClangClCPPCompiler)
        ar = mesonbuild.linkers.ArLinker
        lib = mesonbuild.linkers.VisualStudioLinker
        langs = [('c', 'CC'), ('cpp', 'CXX')]
        if not is_windows() and platform.machine().lower() != 'e2k':
            langs += [('objc', 'OBJC'), ('objcpp', 'OBJCXX')]
        testdir = os.path.join(self.unit_test_dir, '5 compiler detection')
        env = get_fake_env(testdir, self.builddir, self.prefix)
        for lang, evar in langs:
            # Detect with evar and do sanity checks on that
            if evar in os.environ:
                ecc = getattr(env, 'detect_{}_compiler'.format(lang))(MachineChoice.HOST)
                self.assertTrue(ecc.version)
                elinker = env.detect_static_linker(ecc)
                # Pop it so we don't use it for the next detection
                evalue = os.environ.pop(evar)
                # Very rough/strict heuristics. Would never work for actual
                # compiler detection, but should be ok for the tests.
                ebase = os.path.basename(evalue)
                if ebase.startswith('g') or ebase.endswith(('-gcc', '-g++')):
                    self.assertIsInstance(ecc, gnu)
                    self.assertIsInstance(elinker, ar)
                elif 'clang-cl' in ebase:
                    self.assertIsInstance(ecc, clangcl)
                    self.assertIsInstance(elinker, lib)
                elif 'clang' in ebase:
                    self.assertIsInstance(ecc, clang)
                    self.assertIsInstance(elinker, ar)
                elif ebase.startswith('ic'):
                    self.assertIsInstance(ecc, intel)
                    self.assertIsInstance(elinker, ar)
                elif ebase.startswith('cl'):
                    self.assertIsInstance(ecc, msvc)
                    self.assertIsInstance(elinker, lib)
                else:
                    raise AssertionError('Unknown compiler {!r}'.format(evalue))
                # Check that we actually used the evalue correctly as the compiler
                self.assertEqual(ecc.get_exelist(), split_args(evalue))
            # Do auto-detection of compiler based on platform, PATH, etc.
            cc = getattr(env, 'detect_{}_compiler'.format(lang))(MachineChoice.HOST)
            self.assertTrue(cc.version)
            linker = env.detect_static_linker(cc)
            # Check compiler type
            if isinstance(cc, gnu):
                self.assertIsInstance(linker, ar)
                if is_osx():
                    self.assertIsInstance(cc.linker, mesonbuild.linkers.AppleDynamicLinker)
                elif is_sunos():
                    self.assertIsInstance(cc.linker, (mesonbuild.linkers.SolarisDynamicLinker, mesonbuild.linkers.GnuLikeDynamicLinkerMixin))
                else:
                    self.assertIsInstance(cc.linker, mesonbuild.linkers.GnuLikeDynamicLinkerMixin)
            if isinstance(cc, clangcl):
                self.assertIsInstance(linker, lib)
                self.assertIsInstance(cc.linker, mesonbuild.linkers.ClangClDynamicLinker)
            if isinstance(cc, clang):
                self.assertIsInstance(linker, ar)
                if is_osx():
                    self.assertIsInstance(cc.linker, mesonbuild.linkers.AppleDynamicLinker)
                elif is_windows():
                    # This is clang, not clang-cl
                    self.assertIsInstance(cc.linker, mesonbuild.linkers.MSVCDynamicLinker)
                else:
                    self.assertIsInstance(cc.linker, mesonbuild.linkers.GnuLikeDynamicLinkerMixin)
            if isinstance(cc, intel):
                self.assertIsInstance(linker, ar)
                if is_osx():
                    self.assertIsInstance(cc.linker, mesonbuild.linkers.AppleDynamicLinker)
                elif is_windows():
                    self.assertIsInstance(cc.linker, mesonbuild.linkers.XilinkDynamicLinker)
                else:
                    self.assertIsInstance(cc.linker, mesonbuild.linkers.GnuDynamicLinker)
            if isinstance(cc, msvc):
                self.assertTrue(is_windows())
                self.assertIsInstance(linker, lib)
                self.assertEqual(cc.id, 'msvc')
                self.assertTrue(hasattr(cc, 'is_64'))
                self.assertIsInstance(cc.linker, mesonbuild.linkers.MSVCDynamicLinker)
                # If we're on Windows CI, we know what the compiler will be
                if 'arch' in os.environ:
                    if os.environ['arch'] == 'x64':
                        self.assertTrue(cc.is_64)
                    else:
                        self.assertFalse(cc.is_64)
            # Set evar ourselves to a wrapper script that just calls the same
            # exelist + some argument. This is meant to test that setting
            # something like `ccache gcc -pipe` or `distcc ccache gcc` works.
            wrapper = os.path.join(testdir, 'compiler wrapper.py')
            wrappercc = python_command + [wrapper] + cc.get_exelist() + ['-DSOME_ARG']
            wrappercc_s = ''
            for w in wrappercc:
                wrappercc_s += quote_arg(w) + ' '
            os.environ[evar] = wrappercc_s
            wcc = getattr(env, 'detect_{}_compiler'.format(lang))(MachineChoice.HOST)
            # Check static linker too
            wrapperlinker = python_command + [wrapper] + linker.get_exelist() + linker.get_always_args()
            wrapperlinker_s = ''
            for w in wrapperlinker:
                wrapperlinker_s += quote_arg(w) + ' '
            os.environ['AR'] = wrapperlinker_s
            wlinker = env.detect_static_linker(wcc)
            # Pop it so we don't use it for the next detection
            evalue = os.environ.pop('AR')
            # Must be the same type since it's a wrapper around the same exelist
            self.assertIs(type(cc), type(wcc))
            self.assertIs(type(linker), type(wlinker))
            # Ensure that the exelist is correct
            self.assertEqual(wcc.get_exelist(), wrappercc)
            self.assertEqual(wlinker.get_exelist(), wrapperlinker)
            # Ensure that the version detection worked correctly
            self.assertEqual(cc.version, wcc.version)
            if hasattr(cc, 'is_64'):
                self.assertEqual(cc.is_64, wcc.is_64)

    def test_always_prefer_c_compiler_for_asm(self):
        testdir = os.path.join(self.common_test_dir, '137 c cpp and asm')
        # Skip if building with MSVC
        env = get_fake_env(testdir, self.builddir, self.prefix)
        if env.detect_c_compiler(MachineChoice.HOST).get_id() == 'msvc':
            raise unittest.SkipTest('MSVC can\'t compile assembly')
        self.init(testdir)
        commands = {'c-asm': {}, 'cpp-asm': {}, 'cpp-c-asm': {}, 'c-cpp-asm': {}}
        for cmd in self.get_compdb():
            # Get compiler
            split = split_args(cmd['command'])
            if split[0] == 'ccache':
                compiler = split[1]
            else:
                compiler = split[0]
            # Classify commands
            if 'Ic-asm' in cmd['command']:
                if cmd['file'].endswith('.S'):
                    commands['c-asm']['asm'] = compiler
                elif cmd['file'].endswith('.c'):
                    commands['c-asm']['c'] = compiler
                else:
                    raise AssertionError('{!r} found in cpp-asm?'.format(cmd['command']))
            elif 'Icpp-asm' in cmd['command']:
                if cmd['file'].endswith('.S'):
                    commands['cpp-asm']['asm'] = compiler
                elif cmd['file'].endswith('.cpp'):
                    commands['cpp-asm']['cpp'] = compiler
                else:
                    raise AssertionError('{!r} found in cpp-asm?'.format(cmd['command']))
            elif 'Ic-cpp-asm' in cmd['command']:
                if cmd['file'].endswith('.S'):
                    commands['c-cpp-asm']['asm'] = compiler
                elif cmd['file'].endswith('.c'):
                    commands['c-cpp-asm']['c'] = compiler
                elif cmd['file'].endswith('.cpp'):
                    commands['c-cpp-asm']['cpp'] = compiler
                else:
                    raise AssertionError('{!r} found in c-cpp-asm?'.format(cmd['command']))
            elif 'Icpp-c-asm' in cmd['command']:
                if cmd['file'].endswith('.S'):
                    commands['cpp-c-asm']['asm'] = compiler
                elif cmd['file'].endswith('.c'):
                    commands['cpp-c-asm']['c'] = compiler
                elif cmd['file'].endswith('.cpp'):
                    commands['cpp-c-asm']['cpp'] = compiler
                else:
                    raise AssertionError('{!r} found in cpp-c-asm?'.format(cmd['command']))
            else:
                raise AssertionError('Unknown command {!r} found'.format(cmd['command']))
        # Check that .S files are always built with the C compiler
        self.assertEqual(commands['c-asm']['asm'], commands['c-asm']['c'])
        self.assertEqual(commands['c-asm']['asm'], commands['cpp-asm']['asm'])
        self.assertEqual(commands['cpp-asm']['asm'], commands['c-cpp-asm']['c'])
        self.assertEqual(commands['c-cpp-asm']['asm'], commands['c-cpp-asm']['c'])
        self.assertEqual(commands['cpp-c-asm']['asm'], commands['cpp-c-asm']['c'])
        self.assertNotEqual(commands['cpp-asm']['asm'], commands['cpp-asm']['cpp'])
        self.assertNotEqual(commands['c-cpp-asm']['c'], commands['c-cpp-asm']['cpp'])
        self.assertNotEqual(commands['cpp-c-asm']['c'], commands['cpp-c-asm']['cpp'])
        # Check that the c-asm target is always linked with the C linker
        build_ninja = os.path.join(self.builddir, 'build.ninja')
        with open(build_ninja, 'r', encoding='utf-8') as f:
            contents = f.read()
            m = re.search('build c-asm.*: c_LINKER', contents)
        self.assertIsNotNone(m, msg=contents)

    def test_preprocessor_checks_CPPFLAGS(self):
        '''
        Test that preprocessor compiler checks read CPPFLAGS and also CFLAGS but
        not LDFLAGS.
        '''
        testdir = os.path.join(self.common_test_dir, '136 get define')
        define = 'MESON_TEST_DEFINE_VALUE'
        # NOTE: this list can't have \n, ' or "
        # \n is never substituted by the GNU pre-processor via a -D define
        # ' and " confuse split_args() even when they are escaped
        # % and # confuse the MSVC preprocessor
        # !, ^, *, and < confuse lcc preprocessor
        value = 'spaces and fun@$&()-=_+{}[]:;>?,./~`'
        for env_var in ['CPPFLAGS', 'CFLAGS']:
            env = {}
            env[env_var] = '-D{}="{}"'.format(define, value)
            env['LDFLAGS'] = '-DMESON_FAIL_VALUE=cflags-read'.format(define)
            self.init(testdir, extra_args=['-D{}={}'.format(define, value)], override_envvars=env)

    def test_custom_target_exe_data_deterministic(self):
        testdir = os.path.join(self.common_test_dir, '113 custom target capture')
        self.init(testdir)
        meson_exe_dat1 = glob(os.path.join(self.privatedir, 'meson_exe*.dat'))
        self.wipe()
        self.init(testdir)
        meson_exe_dat2 = glob(os.path.join(self.privatedir, 'meson_exe*.dat'))
        self.assertListEqual(meson_exe_dat1, meson_exe_dat2)

    def test_noop_changes_cause_no_rebuilds(self):
        '''
        Test that no-op changes to the build files such as mtime do not cause
        a rebuild of anything.
        '''
        testdir = os.path.join(self.common_test_dir, '6 linkshared')
        self.init(testdir)
        self.build()
        # Immediately rebuilding should not do anything
        self.assertBuildIsNoop()
        # Changing mtime of meson.build should not rebuild anything
        self.utime(os.path.join(testdir, 'meson.build'))
        self.assertReconfiguredBuildIsNoop()
        # Changing mtime of libefile.c should rebuild the library, but not relink the executable
        self.utime(os.path.join(testdir, 'libfile.c'))
        self.assertBuildRelinkedOnlyTarget('mylib')

    def test_source_changes_cause_rebuild(self):
        '''
        Test that changes to sources and headers cause rebuilds, but not
        changes to unused files (as determined by the dependency file) in the
        input files list.
        '''
        testdir = os.path.join(self.common_test_dir, '20 header in file list')
        self.init(testdir)
        self.build()
        # Immediately rebuilding should not do anything
        self.assertBuildIsNoop()
        # Changing mtime of header.h should rebuild everything
        self.utime(os.path.join(testdir, 'header.h'))
        self.assertBuildRelinkedOnlyTarget('prog')

    def test_custom_target_changes_cause_rebuild(self):
        '''
        Test that in a custom target, changes to the input files, the
        ExternalProgram, and any File objects on the command-line cause
        a rebuild.
        '''
        testdir = os.path.join(self.common_test_dir, '60 custom header generator')
        self.init(testdir)
        self.build()
        # Immediately rebuilding should not do anything
        self.assertBuildIsNoop()
        # Changing mtime of these should rebuild everything
        for f in ('input.def', 'makeheader.py', 'somefile.txt'):
            self.utime(os.path.join(testdir, f))
            self.assertBuildRelinkedOnlyTarget('prog')

    def test_source_generator_program_cause_rebuild(self):
        '''
        Test that changes to generator programs in the source tree cause
        a rebuild.
        '''
        testdir = os.path.join(self.common_test_dir, '94 gen extra')
        self.init(testdir)
        self.build()
        # Immediately rebuilding should not do anything
        self.assertBuildIsNoop()
        # Changing mtime of generator should rebuild the executable
        self.utime(os.path.join(testdir, 'srcgen.py'))
        self.assertRebuiltTarget('basic')

    def test_static_library_lto(self):
        '''
        Test that static libraries can be built with LTO and linked to
        executables. On Linux, this requires the use of gcc-ar.
        https://github.com/mesonbuild/meson/issues/1646
        '''
        testdir = os.path.join(self.common_test_dir, '5 linkstatic')

        env = get_fake_env(testdir, self.builddir, self.prefix)
        if env.detect_c_compiler(MachineChoice.HOST).get_id() == 'clang' and is_windows():
            raise unittest.SkipTest('LTO not (yet) supported by windows clang')

        self.init(testdir, extra_args='-Db_lto=true')
        self.build()
        self.run_tests()

    def test_dist_git(self):
        if not shutil.which('git'):
            raise unittest.SkipTest('Git not found')
        if self.backend is not Backend.ninja:
            raise unittest.SkipTest('Dist is only supported with Ninja')

        try:
            self.dist_impl(_git_init)
        except PermissionError:
            # When run under Windows CI, something (virus scanner?)
            # holds on to the git files so cleaning up the dir
            # fails sometimes.
            pass

    def has_working_hg(self):
        if not shutil.which('hg'):
            return False
        try:
            # This check should not be necessary, but
            # CI under macOS passes the above test even
            # though Mercurial is not installed.
            if subprocess.call(['hg', '--version'],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL) != 0:
                return False
            return True
        except FileNotFoundError:
            return False


    def test_dist_hg(self):
        if not self.has_working_hg():
            raise unittest.SkipTest('Mercurial not found or broken.')
        if self.backend is not Backend.ninja:
            raise unittest.SkipTest('Dist is only supported with Ninja')

        def hg_init(project_dir):
            subprocess.check_call(['hg', 'init'], cwd=project_dir)
            with open(os.path.join(project_dir, '.hg', 'hgrc'), 'w') as f:
                print('[ui]', file=f)
                print('username=Author Person <teh_coderz@example.com>', file=f)
            subprocess.check_call(['hg', 'add', 'meson.build', 'distexe.c'], cwd=project_dir)
            subprocess.check_call(['hg', 'commit', '-m', 'I am a project'], cwd=project_dir)

        try:
            self.dist_impl(hg_init, include_subprojects=False)
        except PermissionError:
            # When run under Windows CI, something (virus scanner?)
            # holds on to the hg files so cleaning up the dir
            # fails sometimes.
            pass

    def test_dist_git_script(self):
        if not shutil.which('git'):
            raise unittest.SkipTest('Git not found')
        if self.backend is not Backend.ninja:
            raise unittest.SkipTest('Dist is only supported with Ninja')

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                project_dir = os.path.join(tmpdir, 'a')
                shutil.copytree(os.path.join(self.unit_test_dir, '35 dist script'),
                                project_dir)
                _git_init(project_dir)
                self.init(project_dir)
                self.build('dist')
        except PermissionError:
            # When run under Windows CI, something (virus scanner?)
            # holds on to the git files so cleaning up the dir
            # fails sometimes.
            pass

    def create_dummy_subproject(self, project_dir, name):
        path = os.path.join(project_dir, 'subprojects', name)
        os.makedirs(path)
        with open(os.path.join(path, 'meson.build'), 'w') as ofile:
            ofile.write("project('{}')".format(name))
        return path

    def dist_impl(self, vcs_init, include_subprojects=True):
        # Create this on the fly because having rogue .git directories inside
        # the source tree leads to all kinds of trouble.
        with tempfile.TemporaryDirectory() as project_dir:
            with open(os.path.join(project_dir, 'meson.build'), 'w') as ofile:
                ofile.write('''project('disttest', 'c', version : '1.4.3')
e = executable('distexe', 'distexe.c')
test('dist test', e)
subproject('vcssub', required : false)
subproject('tarballsub', required : false)
''')
            with open(os.path.join(project_dir, 'distexe.c'), 'w') as ofile:
                ofile.write('''#include<stdio.h>

int main(int argc, char **argv) {
    printf("I am a distribution test.\\n");
    return 0;
}
''')
            xz_distfile = os.path.join(self.distdir, 'disttest-1.4.3.tar.xz')
            xz_checksumfile = xz_distfile + '.sha256sum'
            zip_distfile = os.path.join(self.distdir, 'disttest-1.4.3.zip')
            zip_checksumfile = zip_distfile + '.sha256sum'
            vcs_init(project_dir)
            if include_subprojects:
                vcs_init(self.create_dummy_subproject(project_dir, 'vcssub'))
                self.create_dummy_subproject(project_dir, 'tarballsub')
                self.create_dummy_subproject(project_dir, 'unusedsub')
            self.init(project_dir)
            self.build('dist')
            self.assertPathExists(xz_distfile)
            self.assertPathExists(xz_checksumfile)
            self.assertPathDoesNotExist(zip_distfile)
            self.assertPathDoesNotExist(zip_checksumfile)
            self._run(self.meson_command + ['dist', '--formats', 'zip'],
                      workdir=self.builddir)
            self.assertPathExists(zip_distfile)
            self.assertPathExists(zip_checksumfile)

            if include_subprojects:
                z = zipfile.ZipFile(zip_distfile)
                self.assertEqual(sorted(['disttest-1.4.3/',
                                         'disttest-1.4.3/meson.build',
                                         'disttest-1.4.3/distexe.c']),
                                 sorted(z.namelist()))

                self._run(self.meson_command + ['dist', '--formats', 'zip', '--include-subprojects'],
                          workdir=self.builddir)
                z = zipfile.ZipFile(zip_distfile)
                self.assertEqual(sorted(['disttest-1.4.3/',
                                         'disttest-1.4.3/subprojects/',
                                         'disttest-1.4.3/meson.build',
                                         'disttest-1.4.3/distexe.c',
                                         'disttest-1.4.3/subprojects/tarballsub/',
                                         'disttest-1.4.3/subprojects/vcssub/',
                                         'disttest-1.4.3/subprojects/tarballsub/meson.build',
                                         'disttest-1.4.3/subprojects/vcssub/meson.build']),
                                 sorted(z.namelist()))

    def test_rpath_uses_ORIGIN(self):
        '''
        Test that built targets use $ORIGIN in rpath, which ensures that they
        are relocatable and ensures that builds are reproducible since the
        build directory won't get embedded into the built binaries.
        '''
        if is_windows() or is_cygwin():
            raise unittest.SkipTest('Windows PE/COFF binaries do not use RPATH')
        testdir = os.path.join(self.common_test_dir, '42 library chain')
        self.init(testdir)
        self.build()
        for each in ('prog', 'subdir/liblib1.so', ):
            rpath = get_rpath(os.path.join(self.builddir, each))
            self.assertTrue(rpath, 'Rpath could not be determined for {}.'.format(each))
            if is_dragonflybsd():
                # DragonflyBSD will prepend /usr/lib/gccVERSION to the rpath,
                # so ignore that.
                self.assertTrue(rpath.startswith('/usr/lib/gcc'))
                rpaths = rpath.split(':')[1:]
            else:
                rpaths = rpath.split(':')
            for path in rpaths:
                self.assertTrue(path.startswith('$ORIGIN'), msg=(each, path))
        # These two don't link to anything else, so they do not need an rpath entry.
        for each in ('subdir/subdir2/liblib2.so', 'subdir/subdir3/liblib3.so'):
            rpath = get_rpath(os.path.join(self.builddir, each))
            if is_dragonflybsd():
                # The rpath should be equal to /usr/lib/gccVERSION
                self.assertTrue(rpath.startswith('/usr/lib/gcc'))
                self.assertEqual(len(rpath.split(':')), 1)
            else:
                self.assertTrue(rpath is None)

    def test_dash_d_dedup(self):
        testdir = os.path.join(self.unit_test_dir, '9 d dedup')
        self.init(testdir)
        cmd = self.get_compdb()[0]['command']
        self.assertTrue('-D FOO -D BAR' in cmd or
                        '"-D" "FOO" "-D" "BAR"' in cmd or
                        '/D FOO /D BAR' in cmd or
                        '"/D" "FOO" "/D" "BAR"' in cmd)

    def test_all_forbidden_targets_tested(self):
        '''
        Test that all forbidden targets are tested in the '154 reserved targets'
        test. Needs to be a unit test because it accesses Meson internals.
        '''
        testdir = os.path.join(self.common_test_dir, '154 reserved targets')
        targets = mesonbuild.coredata.forbidden_target_names
        # We don't actually define a target with this name
        targets.pop('build.ninja')
        # Remove this to avoid multiple entries with the same name
        # but different case.
        targets.pop('PHONY')
        for i in targets:
            self.assertPathExists(os.path.join(testdir, i))

    def detect_prebuild_env(self):
        env = get_fake_env()
        cc = env.detect_c_compiler(MachineChoice.HOST)
        stlinker = env.detect_static_linker(cc)
        if mesonbuild.mesonlib.is_windows():
            object_suffix = 'obj'
            shared_suffix = 'dll'
        elif mesonbuild.mesonlib.is_cygwin():
            object_suffix = 'o'
            shared_suffix = 'dll'
        elif mesonbuild.mesonlib.is_osx():
            object_suffix = 'o'
            shared_suffix = 'dylib'
        else:
            object_suffix = 'o'
            shared_suffix = 'so'
        return (cc, stlinker, object_suffix, shared_suffix)

    def pbcompile(self, compiler, source, objectfile, extra_args=None):
        cmd = compiler.get_exelist()
        extra_args = extra_args or []
        if compiler.get_argument_syntax() == 'msvc':
            cmd += ['/nologo', '/Fo' + objectfile, '/c', source] + extra_args
        else:
            cmd += ['-c', source, '-o', objectfile] + extra_args
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def test_prebuilt_object(self):
        (compiler, _, object_suffix, _) = self.detect_prebuild_env()
        tdir = os.path.join(self.unit_test_dir, '15 prebuilt object')
        source = os.path.join(tdir, 'source.c')
        objectfile = os.path.join(tdir, 'prebuilt.' + object_suffix)
        self.pbcompile(compiler, source, objectfile)
        try:
            self.init(tdir)
            self.build()
            self.run_tests()
        finally:
            os.unlink(objectfile)

    def build_static_lib(self, compiler, linker, source, objectfile, outfile, extra_args=None):
        if extra_args is None:
            extra_args = []
        if compiler.get_argument_syntax() == 'msvc':
            link_cmd = ['lib', '/NOLOGO', '/OUT:' + outfile, objectfile]
        else:
            link_cmd = ['ar', 'csr', outfile, objectfile]
        link_cmd = linker.get_exelist()
        link_cmd += linker.get_always_args()
        link_cmd += linker.get_std_link_args()
        link_cmd += linker.get_output_args(outfile)
        link_cmd += [objectfile]
        self.pbcompile(compiler, source, objectfile, extra_args=extra_args)
        try:
            subprocess.check_call(link_cmd)
        finally:
            os.unlink(objectfile)

    def test_prebuilt_static_lib(self):
        (cc, stlinker, object_suffix, _) = self.detect_prebuild_env()
        tdir = os.path.join(self.unit_test_dir, '16 prebuilt static')
        source = os.path.join(tdir, 'libdir/best.c')
        objectfile = os.path.join(tdir, 'libdir/best.' + object_suffix)
        stlibfile = os.path.join(tdir, 'libdir/libbest.a')
        self.build_static_lib(cc, stlinker, source, objectfile, stlibfile)
        # Run the test
        try:
            self.init(tdir)
            self.build()
            self.run_tests()
        finally:
            os.unlink(stlibfile)

    def build_shared_lib(self, compiler, source, objectfile, outfile, impfile, extra_args=None):
        if extra_args is None:
            extra_args = []
        if compiler.get_argument_syntax() == 'msvc':
            link_cmd = compiler.get_linker_exelist() + [
                '/NOLOGO', '/DLL', '/DEBUG', '/IMPLIB:' + impfile,
                '/OUT:' + outfile, objectfile]
        else:
            if not (compiler.info.is_windows() or compiler.info.is_cygwin() or compiler.info.is_darwin()):
                extra_args += ['-fPIC']
            link_cmd = compiler.get_exelist() + ['-shared', '-o', outfile, objectfile]
            if not mesonbuild.mesonlib.is_osx():
                link_cmd += ['-Wl,-soname=' + os.path.basename(outfile)]
        self.pbcompile(compiler, source, objectfile, extra_args=extra_args)
        try:
            subprocess.check_call(link_cmd)
        finally:
            os.unlink(objectfile)

    def test_prebuilt_shared_lib(self):
        (cc, _, object_suffix, shared_suffix) = self.detect_prebuild_env()
        tdir = os.path.join(self.unit_test_dir, '17 prebuilt shared')
        source = os.path.join(tdir, 'alexandria.c')
        objectfile = os.path.join(tdir, 'alexandria.' + object_suffix)
        impfile = os.path.join(tdir, 'alexandria.lib')
        if cc.get_argument_syntax() == 'msvc':
            shlibfile = os.path.join(tdir, 'alexandria.' + shared_suffix)
        elif is_cygwin():
            shlibfile = os.path.join(tdir, 'cygalexandria.' + shared_suffix)
        else:
            shlibfile = os.path.join(tdir, 'libalexandria.' + shared_suffix)
        self.build_shared_lib(cc, source, objectfile, shlibfile, impfile)
        # Run the test
        try:
            self.init(tdir)
            self.build()
            self.run_tests()
        finally:
            os.unlink(shlibfile)
            if mesonbuild.mesonlib.is_windows():
                # Clean up all the garbage MSVC writes in the
                # source tree.
                for fname in glob(os.path.join(tdir, 'alexandria.*')):
                    if os.path.splitext(fname)[1] not in ['.c', '.h']:
                        os.unlink(fname)

    @skipIfNoPkgconfig
    def test_pkgconfig_static(self):
        '''
        Test that the we prefer static libraries when `static: true` is
        passed to dependency() with pkg-config. Can't be an ordinary test
        because we need to build libs and try to find them from meson.build

        Also test that it's not a hard error to have unsatisfiable library deps
        since system libraries -lm will never be found statically.
        https://github.com/mesonbuild/meson/issues/2785
        '''
        (cc, stlinker, objext, shext) = self.detect_prebuild_env()
        testdir = os.path.join(self.unit_test_dir, '18 pkgconfig static')
        source = os.path.join(testdir, 'foo.c')
        objectfile = os.path.join(testdir, 'foo.' + objext)
        stlibfile = os.path.join(testdir, 'libfoo.a')
        impfile = os.path.join(testdir, 'foo.lib')
        if cc.get_argument_syntax() == 'msvc':
            shlibfile = os.path.join(testdir, 'foo.' + shext)
        elif is_cygwin():
            shlibfile = os.path.join(testdir, 'cygfoo.' + shext)
        else:
            shlibfile = os.path.join(testdir, 'libfoo.' + shext)
        # Build libs
        self.build_static_lib(cc, stlinker, source, objectfile, stlibfile, extra_args=['-DFOO_STATIC'])
        self.build_shared_lib(cc, source, objectfile, shlibfile, impfile)
        # Run test
        try:
            self.init(testdir, override_envvars={'PKG_CONFIG_LIBDIR': self.builddir})
            self.build()
            self.run_tests()
        finally:
            os.unlink(stlibfile)
            os.unlink(shlibfile)
            if mesonbuild.mesonlib.is_windows():
                # Clean up all the garbage MSVC writes in the
                # source tree.
                for fname in glob(os.path.join(testdir, 'foo.*')):
                    if os.path.splitext(fname)[1] not in ['.c', '.h', '.in']:
                        os.unlink(fname)

    @skipIfNoPkgconfig
    def test_pkgconfig_gen_escaping(self):
        testdir = os.path.join(self.common_test_dir, '47 pkgconfig-gen')
        prefix = '/usr/with spaces'
        libdir = 'lib'
        self.init(testdir, extra_args=['--prefix=' + prefix,
                                       '--libdir=' + libdir])
        # Find foo dependency
        os.environ['PKG_CONFIG_LIBDIR'] = self.privatedir
        env = get_fake_env(testdir, self.builddir, self.prefix)
        kwargs = {'required': True, 'silent': True}
        foo_dep = PkgConfigDependency('libfoo', env, kwargs)
        # Ensure link_args are properly quoted
        libdir = PurePath(prefix) / PurePath(libdir)
        link_args = ['-L' + libdir.as_posix(), '-lfoo']
        self.assertEqual(foo_dep.get_link_args(), link_args)
        # Ensure include args are properly quoted
        incdir = PurePath(prefix) / PurePath('include')
        cargs = ['-I' + incdir.as_posix(), '-DLIBFOO']
        # pkg-config and pkgconf does not respect the same order
        self.assertEqual(sorted(foo_dep.get_compile_args()), sorted(cargs))

    def test_array_option_change(self):
        def get_opt():
            opts = self.introspect('--buildoptions')
            for x in opts:
                if x.get('name') == 'list':
                    return x
            raise Exception(opts)

        expected = {
            'name': 'list',
            'description': 'list',
            'section': 'user',
            'type': 'array',
            'value': ['foo', 'bar'],
            'machine': 'any',
        }
        tdir = os.path.join(self.unit_test_dir, '19 array option')
        self.init(tdir)
        original = get_opt()
        self.assertDictEqual(original, expected)

        expected['value'] = ['oink', 'boink']
        self.setconf('-Dlist=oink,boink')
        changed = get_opt()
        self.assertEqual(changed, expected)

    def test_array_option_bad_change(self):
        def get_opt():
            opts = self.introspect('--buildoptions')
            for x in opts:
                if x.get('name') == 'list':
                    return x
            raise Exception(opts)

        expected = {
            'name': 'list',
            'description': 'list',
            'section': 'user',
            'type': 'array',
            'value': ['foo', 'bar'],
            'machine': 'any',
        }
        tdir = os.path.join(self.unit_test_dir, '19 array option')
        self.init(tdir)
        original = get_opt()
        self.assertDictEqual(original, expected)
        with self.assertRaises(subprocess.CalledProcessError):
            self.setconf('-Dlist=bad')
        changed = get_opt()
        self.assertDictEqual(changed, expected)

    def test_array_option_empty_equivalents(self):
        """Array options treat -Dopt=[] and -Dopt= as equivalent."""
        def get_opt():
            opts = self.introspect('--buildoptions')
            for x in opts:
                if x.get('name') == 'list':
                    return x
            raise Exception(opts)

        expected = {
            'name': 'list',
            'description': 'list',
            'section': 'user',
            'type': 'array',
            'value': [],
            'machine': 'any',
        }
        tdir = os.path.join(self.unit_test_dir, '19 array option')
        self.init(tdir, extra_args='-Dlist=')
        original = get_opt()
        self.assertDictEqual(original, expected)

    def opt_has(self, name, value):
        res = self.introspect('--buildoptions')
        found = False
        for i in res:
            if i['name'] == name:
                self.assertEqual(i['value'], value)
                found = True
                break
        self.assertTrue(found, "Array option not found in introspect data.")

    def test_free_stringarray_setting(self):
        testdir = os.path.join(self.common_test_dir, '43 options')
        self.init(testdir)
        self.opt_has('free_array_opt', [])
        self.setconf('-Dfree_array_opt=foo,bar', will_build=False)
        self.opt_has('free_array_opt', ['foo', 'bar'])
        self.setconf("-Dfree_array_opt=['a,b', 'c,d']", will_build=False)
        self.opt_has('free_array_opt', ['a,b', 'c,d'])

    def test_subproject_promotion(self):
        testdir = os.path.join(self.unit_test_dir, '12 promote')
        workdir = os.path.join(self.builddir, 'work')
        shutil.copytree(testdir, workdir)
        spdir = os.path.join(workdir, 'subprojects')
        s3dir = os.path.join(spdir, 's3')
        scommondir = os.path.join(spdir, 'scommon')
        self.assertFalse(os.path.isdir(s3dir))
        subprocess.check_call(self.wrap_command + ['promote', 's3'], cwd=workdir)
        self.assertTrue(os.path.isdir(s3dir))
        self.assertFalse(os.path.isdir(scommondir))
        self.assertNotEqual(subprocess.call(self.wrap_command + ['promote', 'scommon'],
                                            cwd=workdir,
                                            stdout=subprocess.DEVNULL), 0)
        self.assertNotEqual(subprocess.call(self.wrap_command + ['promote', 'invalid/path/to/scommon'],
                                            cwd=workdir,
                                            stderr=subprocess.DEVNULL), 0)
        self.assertFalse(os.path.isdir(scommondir))
        subprocess.check_call(self.wrap_command + ['promote', 'subprojects/s2/subprojects/scommon'], cwd=workdir)
        self.assertTrue(os.path.isdir(scommondir))
        promoted_wrap = os.path.join(spdir, 'athing.wrap')
        self.assertFalse(os.path.isfile(promoted_wrap))
        subprocess.check_call(self.wrap_command + ['promote', 'athing'], cwd=workdir)
        self.assertTrue(os.path.isfile(promoted_wrap))
        self.init(workdir)
        self.build()

    def test_subproject_promotion_wrap(self):
        testdir = os.path.join(self.unit_test_dir, '44 promote wrap')
        workdir = os.path.join(self.builddir, 'work')
        shutil.copytree(testdir, workdir)
        spdir = os.path.join(workdir, 'subprojects')

        ambiguous_wrap = os.path.join(spdir, 'ambiguous.wrap')
        self.assertNotEqual(subprocess.call(self.wrap_command + ['promote', 'ambiguous'],
                                            cwd=workdir,
                                            stdout=subprocess.DEVNULL), 0)
        self.assertFalse(os.path.isfile(ambiguous_wrap))
        subprocess.check_call(self.wrap_command + ['promote', 'subprojects/s2/subprojects/ambiguous.wrap'], cwd=workdir)
        self.assertTrue(os.path.isfile(ambiguous_wrap))

    def test_warning_location(self):
        tdir = os.path.join(self.unit_test_dir, '22 warning location')
        out = self.init(tdir)
        for expected in [
            r'meson.build:4: WARNING: Keyword argument "link_with" defined multiple times.',
            r'sub' + os.path.sep + r'meson.build:3: WARNING: Keyword argument "link_with" defined multiple times.',
            r'meson.build:6: WARNING: a warning of some sort',
            r'sub' + os.path.sep + r'meson.build:4: WARNING: subdir warning',
            r'meson.build:7: WARNING: Module unstable-simd has no backwards or forwards compatibility and might not exist in future releases.',
            r"meson.build:11: WARNING: The variable(s) 'MISSING' in the input file 'conf.in' are not present in the given configuration data.",
            r'meson.build:1: WARNING: Passed invalid keyword argument "invalid".',
        ]:
            self.assertRegex(out, re.escape(expected))

        for wd in [
            self.src_root,
            self.builddir,
            os.getcwd(),
        ]:
            self.new_builddir()
            out = self.init(tdir, workdir=wd)
            expected = os.path.join(relpath(tdir, self.src_root), 'meson.build')
            relwd = relpath(self.src_root, wd)
            if relwd != '.':
                expected = os.path.join(relwd, expected)
                expected = '\n' + expected + ':'
            self.assertIn(expected, out)

    def test_error_location_path(self):
        '''Test locations in meson errors contain correct paths'''
        # this list contains errors from all the different steps in the
        # lexer/parser/interpreter we have tests for.
        for (t, f) in [
            ('10 out of bounds', 'meson.build'),
            ('18 wrong plusassign', 'meson.build'),
            ('61 bad option argument', 'meson_options.txt'),
            ('102 subdir parse error', os.path.join('subdir', 'meson.build')),
            ('103 invalid option file', 'meson_options.txt'),
        ]:
            tdir = os.path.join(self.src_root, 'test cases', 'failing', t)

            for wd in [
                self.src_root,
                self.builddir,
                os.getcwd(),
            ]:
                try:
                    self.init(tdir, workdir=wd)
                except subprocess.CalledProcessError as e:
                    expected = os.path.join('test cases', 'failing', t, f)
                    relwd = relpath(self.src_root, wd)
                    if relwd != '.':
                        expected = os.path.join(relwd, expected)
                    expected = '\n' + expected + ':'
                    self.assertIn(expected, e.output)
                else:
                    self.fail('configure unexpectedly succeeded')

    def test_permitted_method_kwargs(self):
        tdir = os.path.join(self.unit_test_dir, '25 non-permitted kwargs')
        out = self.init(tdir)
        for expected in [
            r'WARNING: Passed invalid keyword argument "prefixxx".',
            r'WARNING: Passed invalid keyword argument "argsxx".',
            r'WARNING: Passed invalid keyword argument "invalidxx".',
        ]:
            self.assertRegex(out, re.escape(expected))

    def test_templates(self):
        ninja = detect_ninja()
        if ninja is None:
            raise unittest.SkipTest('This test currently requires ninja. Fix this once "meson build" works.')
        langs = ['c']
        env = get_fake_env()
        try:
            env.detect_cpp_compiler(MachineChoice.HOST)
            langs.append('cpp')
        except EnvironmentException:
            pass
        try:
            env.detect_cs_compiler(MachineChoice.HOST)
            langs.append('cs')
        except EnvironmentException:
            pass
        try:
            env.detect_d_compiler(MachineChoice.HOST)
            langs.append('d')
        except EnvironmentException:
            pass
        try:
            env.detect_java_compiler(MachineChoice.HOST)
            langs.append('java')
        except EnvironmentException:
            pass
        try:
            env.detect_cuda_compiler(MachineChoice.HOST)
            langs.append('cuda')
        except EnvironmentException:
            pass
        try:
            env.detect_fortran_compiler(MachineChoice.HOST)
            langs.append('fortran')
        except EnvironmentException:
            pass
        try:
            env.detect_objc_compiler(MachineChoice.HOST)
            langs.append('objc')
        except EnvironmentException:
            pass
        try:
            env.detect_objcpp_compiler(MachineChoice.HOST)
            langs.append('objcpp')
        except EnvironmentException:
            pass
        # FIXME: omitting rust as Windows AppVeyor CI finds Rust but doesn't link correctly
        if not is_windows():
            try:
                env.detect_rust_compiler(MachineChoice.HOST)
                langs.append('rust')
            except EnvironmentException:
                pass

        for lang in langs:
            for target_type in ('executable', 'library'):
                # test empty directory
                with tempfile.TemporaryDirectory() as tmpdir:
                    self._run(self.meson_command + ['init', '--language', lang, '--type', target_type],
                              workdir=tmpdir)
                    self._run(self.setup_command + ['--backend=ninja', 'builddir'],
                              workdir=tmpdir)
                    self._run(ninja,
                              workdir=os.path.join(tmpdir, 'builddir'))
            # test directory with existing code file
            if lang in ('c', 'cpp', 'd'):
                with tempfile.TemporaryDirectory() as tmpdir:
                    with open(os.path.join(tmpdir, 'foo.' + lang), 'w') as f:
                        f.write('int main(void) {}')
                    self._run(self.meson_command + ['init', '-b'], workdir=tmpdir)
            elif lang in ('java'):
                with tempfile.TemporaryDirectory() as tmpdir:
                    with open(os.path.join(tmpdir, 'Foo.' + lang), 'w') as f:
                        f.write('public class Foo { public static void main() {} }')
                    self._run(self.meson_command + ['init', '-b'], workdir=tmpdir)

    def test_compiler_run_command(self):
        '''
        The test checks that the compiler object can be passed to
        run_command().
        '''
        testdir = os.path.join(self.unit_test_dir, '24 compiler run_command')
        self.init(testdir)

    def test_identical_target_name_in_subproject_flat_layout(self):
        '''
        Test that identical targets in different subprojects do not collide
        if layout is flat.
        '''
        testdir = os.path.join(self.common_test_dir, '177 identical target name in subproject flat layout')
        self.init(testdir, extra_args=['--layout=flat'])
        self.build()

    def test_identical_target_name_in_subdir_flat_layout(self):
        '''
        Test that identical targets in different subdirs do not collide
        if layout is flat.
        '''
        testdir = os.path.join(self.common_test_dir, '186 same target name flat layout')
        self.init(testdir, extra_args=['--layout=flat'])
        self.build()

    def test_flock(self):
        exception_raised = False
        with tempfile.TemporaryDirectory() as tdir:
            os.mkdir(os.path.join(tdir, 'meson-private'))
            with BuildDirLock(tdir):
                try:
                    with BuildDirLock(tdir):
                        pass
                except MesonException:
                    exception_raised = True
        self.assertTrue(exception_raised, 'Double locking did not raise exception.')

    @unittest.skipIf(is_osx(), 'Test not applicable to OSX')
    def test_check_module_linking(self):
        """
        Test that link_with: a shared module issues a warning
        https://github.com/mesonbuild/meson/issues/2865
        (That an error is raised on OSX is exercised by test failing/78)
        """
        tdir = os.path.join(self.unit_test_dir, '30 shared_mod linking')
        out = self.init(tdir)
        msg = ('''WARNING: target links against shared modules. This is not
recommended as it is not supported on some platforms''')
        self.assertIn(msg, out)

    def test_ndebug_if_release_disabled(self):
        testdir = os.path.join(self.unit_test_dir, '28 ndebug if-release')
        self.init(testdir, extra_args=['--buildtype=release', '-Db_ndebug=if-release'])
        self.build()
        exe = os.path.join(self.builddir, 'main')
        self.assertEqual(b'NDEBUG=1', subprocess.check_output(exe).strip())

    def test_ndebug_if_release_enabled(self):
        testdir = os.path.join(self.unit_test_dir, '28 ndebug if-release')
        self.init(testdir, extra_args=['--buildtype=debugoptimized', '-Db_ndebug=if-release'])
        self.build()
        exe = os.path.join(self.builddir, 'main')
        self.assertEqual(b'NDEBUG=0', subprocess.check_output(exe).strip())

    def test_guessed_linker_dependencies(self):
        '''
        Test that meson adds dependencies for libraries based on the final
        linker command line.
        '''
        testdirbase = os.path.join(self.unit_test_dir, '29 guessed linker dependencies')
        testdirlib = os.path.join(testdirbase, 'lib')

        extra_args = None
        libdir_flags = ['-L']
        env = get_fake_env(testdirlib, self.builddir, self.prefix)
        if env.detect_c_compiler(MachineChoice.HOST).get_id() in {'msvc', 'clang-cl', 'intel-cl'}:
            # msvc-like compiler, also test it with msvc-specific flags
            libdir_flags += ['/LIBPATH:', '-LIBPATH:']
        else:
            # static libraries are not linkable with -l with msvc because meson installs them
            # as .a files which unix_args_to_native will not know as it expects libraries to use
            # .lib as extension. For a DLL the import library is installed as .lib. Thus for msvc
            # this tests needs to use shared libraries to test the path resolving logic in the
            # dependency generation code path.
            extra_args = ['--default-library', 'static']

        initial_builddir = self.builddir
        initial_installdir = self.installdir

        for libdir_flag in libdir_flags:
            # build library
            self.new_builddir()
            self.init(testdirlib, extra_args=extra_args)
            self.build()
            self.install()
            libbuilddir = self.builddir
            installdir = self.installdir
            libdir = os.path.join(self.installdir, self.prefix.lstrip('/').lstrip('\\'), 'lib')

            # build user of library
            self.new_builddir()
            # replace is needed because meson mangles platform paths passed via LDFLAGS
            self.init(os.path.join(testdirbase, 'exe'),
                      override_envvars={"LDFLAGS": '{}{}'.format(libdir_flag, libdir.replace('\\', '/'))})
            self.build()
            self.assertBuildIsNoop()

            # rebuild library
            exebuilddir = self.builddir
            self.installdir = installdir
            self.builddir = libbuilddir
            # Microsoft's compiler is quite smart about touching import libs on changes,
            # so ensure that there is actually a change in symbols.
            self.setconf('-Dmore_exports=true')
            self.build()
            self.install()
            # no ensure_backend_detects_changes needed because self.setconf did that already

            # assert user of library will be rebuild
            self.builddir = exebuilddir
            self.assertRebuiltTarget('app')

            # restore dirs for the next test case
            self.installdir = initial_builddir
            self.builddir = initial_installdir

    def test_conflicting_d_dash_option(self):
        testdir = os.path.join(self.unit_test_dir, '37 mixed command line args')
        with self.assertRaises(subprocess.CalledProcessError) as e:
            self.init(testdir, extra_args=['-Dbindir=foo', '--bindir=bar'])
            # Just to ensure that we caught the correct error
            self.assertIn('passed as both', e.stderr)

    def _test_same_option_twice(self, arg, args):
        testdir = os.path.join(self.unit_test_dir, '37 mixed command line args')
        self.init(testdir, extra_args=args)
        opts = self.introspect('--buildoptions')
        for item in opts:
            if item['name'] == arg:
                self.assertEqual(item['value'], 'bar')
                return
        raise Exception('Missing {} value?'.format(arg))

    def test_same_dash_option_twice(self):
        self._test_same_option_twice('bindir', ['--bindir=foo', '--bindir=bar'])

    def test_same_d_option_twice(self):
        self._test_same_option_twice('bindir', ['-Dbindir=foo', '-Dbindir=bar'])

    def test_same_project_d_option_twice(self):
        self._test_same_option_twice('one', ['-Done=foo', '-Done=bar'])

    def _test_same_option_twice_configure(self, arg, args):
        testdir = os.path.join(self.unit_test_dir, '37 mixed command line args')
        self.init(testdir)
        self.setconf(args)
        opts = self.introspect('--buildoptions')
        for item in opts:
            if item['name'] == arg:
                self.assertEqual(item['value'], 'bar')
                return
        raise Exception('Missing {} value?'.format(arg))

    def test_same_dash_option_twice_configure(self):
        self._test_same_option_twice_configure(
            'bindir', ['--bindir=foo', '--bindir=bar'])

    def test_same_d_option_twice_configure(self):
        self._test_same_option_twice_configure(
            'bindir', ['-Dbindir=foo', '-Dbindir=bar'])

    def test_same_project_d_option_twice_configure(self):
        self._test_same_option_twice_configure(
            'one', ['-Done=foo', '-Done=bar'])

    def test_command_line(self):
        testdir = os.path.join(self.unit_test_dir, '34 command line')

        # Verify default values when passing no args that affect the
        # configuration, and as a bonus, test that --profile-self works.
        self.init(testdir, extra_args=['--profile-self'])
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.builtins['default_library'].value, 'static')
        self.assertEqual(obj.builtins['warning_level'].value, '1')
        self.assertEqual(obj.user_options['set_sub_opt'].value, True)
        self.assertEqual(obj.user_options['subp:subp_opt'].value, 'default3')
        self.wipe()

        # warning_level is special, it's --warnlevel instead of --warning-level
        # for historical reasons
        self.init(testdir, extra_args=['--warnlevel=2'])
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.builtins['warning_level'].value, '2')
        self.setconf('--warnlevel=3')
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.builtins['warning_level'].value, '3')
        self.wipe()

        # But when using -D syntax, it should be 'warning_level'
        self.init(testdir, extra_args=['-Dwarning_level=2'])
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.builtins['warning_level'].value, '2')
        self.setconf('-Dwarning_level=3')
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.builtins['warning_level'].value, '3')
        self.wipe()

        # Mixing --option and -Doption is forbidden
        with self.assertRaises(subprocess.CalledProcessError) as cm:
            self.init(testdir, extra_args=['--warnlevel=1', '-Dwarning_level=3'])
        self.assertNotEqual(0, cm.exception.returncode)
        self.assertIn('as both', cm.exception.output)
        self.init(testdir)
        with self.assertRaises(subprocess.CalledProcessError) as cm:
            self.setconf(['--warnlevel=1', '-Dwarning_level=3'])
        self.assertNotEqual(0, cm.exception.returncode)
        self.assertIn('as both', cm.exception.output)
        self.wipe()

        # --default-library should override default value from project()
        self.init(testdir, extra_args=['--default-library=both'])
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.builtins['default_library'].value, 'both')
        self.setconf('--default-library=shared')
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.builtins['default_library'].value, 'shared')
        if self.backend is Backend.ninja:
            # reconfigure target works only with ninja backend
            self.build('reconfigure')
            obj = mesonbuild.coredata.load(self.builddir)
            self.assertEqual(obj.builtins['default_library'].value, 'shared')
        self.wipe()

        # Should warn on unknown options
        out = self.init(testdir, extra_args=['-Dbad=1', '-Dfoo=2', '-Dwrong_link_args=foo'])
        self.assertIn('Unknown options: "bad, foo, wrong_link_args"', out)
        self.wipe()

        # Should fail on malformed option
        with self.assertRaises(subprocess.CalledProcessError) as cm:
            self.init(testdir, extra_args=['-Dfoo'])
        self.assertNotEqual(0, cm.exception.returncode)
        self.assertIn('Option \'foo\' must have a value separated by equals sign.', cm.exception.output)
        self.init(testdir)
        with self.assertRaises(subprocess.CalledProcessError) as cm:
            self.setconf('-Dfoo')
        self.assertNotEqual(0, cm.exception.returncode)
        self.assertIn('Option \'foo\' must have a value separated by equals sign.', cm.exception.output)
        self.wipe()

        # It is not an error to set wrong option for unknown subprojects or
        # language because we don't have control on which one will be selected.
        self.init(testdir, extra_args=['-Dc_wrong=1', '-Dwrong:bad=1', '-Db_wrong=1'])
        self.wipe()

        # Test we can set subproject option
        self.init(testdir, extra_args=['-Dsubp:subp_opt=foo'])
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.user_options['subp:subp_opt'].value, 'foo')
        self.wipe()

        # c_args value should be parsed with split_args
        self.init(testdir, extra_args=['-Dc_args=-Dfoo -Dbar "-Dthird=one two"'])
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.compiler_options.host['c']['args'].value, ['-Dfoo', '-Dbar', '-Dthird=one two'])

        self.setconf('-Dc_args="foo bar" one two')
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.compiler_options.host['c']['args'].value, ['foo bar', 'one', 'two'])
        self.wipe()

        self.init(testdir, extra_args=['-Dset_percent_opt=myoption%'])
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.user_options['set_percent_opt'].value, 'myoption%')
        self.wipe()

        # Setting a 2nd time the same option should override the first value
        try:
            self.init(testdir, extra_args=['--bindir=foo', '--bindir=bar',
                                           '-Dbuildtype=plain', '-Dbuildtype=release',
                                           '-Db_sanitize=address', '-Db_sanitize=thread',
                                           '-Dc_args=-Dfoo', '-Dc_args=-Dbar'])
            obj = mesonbuild.coredata.load(self.builddir)
            self.assertEqual(obj.builtins['bindir'].value, 'bar')
            self.assertEqual(obj.builtins['buildtype'].value, 'release')
            self.assertEqual(obj.base_options['b_sanitize'].value, 'thread')
            self.assertEqual(obj.compiler_options.host['c']['args'].value, ['-Dbar'])
            self.setconf(['--bindir=bar', '--bindir=foo',
                          '-Dbuildtype=release', '-Dbuildtype=plain',
                          '-Db_sanitize=thread', '-Db_sanitize=address',
                          '-Dc_args=-Dbar', '-Dc_args=-Dfoo'])
            obj = mesonbuild.coredata.load(self.builddir)
            self.assertEqual(obj.builtins['bindir'].value, 'foo')
            self.assertEqual(obj.builtins['buildtype'].value, 'plain')
            self.assertEqual(obj.base_options['b_sanitize'].value, 'address')
            self.assertEqual(obj.compiler_options.host['c']['args'].value, ['-Dfoo'])
            self.wipe()
        except KeyError:
            # Ignore KeyError, it happens on CI for compilers that does not
            # support b_sanitize. We have to test with a base option because
            # they used to fail this test with Meson 0.46 an earlier versions.
            pass

    def test_warning_level_0(self):
        testdir = os.path.join(self.common_test_dir, '214 warning level 0')

        # Verify default values when passing no args
        self.init(testdir)
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.builtins['warning_level'].value, '0')
        self.wipe()

        # verify we can override w/ --warnlevel
        self.init(testdir, extra_args=['--warnlevel=1'])
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.builtins['warning_level'].value, '1')
        self.setconf('--warnlevel=0')
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.builtins['warning_level'].value, '0')
        self.wipe()

        # verify we can override w/ -Dwarning_level
        self.init(testdir, extra_args=['-Dwarning_level=1'])
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.builtins['warning_level'].value, '1')
        self.setconf('-Dwarning_level=0')
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.builtins['warning_level'].value, '0')
        self.wipe()

    def test_feature_check_usage_subprojects(self):
        testdir = os.path.join(self.unit_test_dir, '41 featurenew subprojects')
        out = self.init(testdir)
        # Parent project warns correctly
        self.assertRegex(out, "WARNING: Project targeting '>=0.45'.*'0.47.0': dict")
        # Subprojects warn correctly
        self.assertRegex(out, r"\|WARNING: Project targeting '>=0.40'.*'0.44.0': disabler")
        self.assertRegex(out, r"\|WARNING: Project targeting '!=0.40'.*'0.44.0': disabler")
        # Subproject has a new-enough meson_version, no warning
        self.assertNotRegex(out, "WARNING: Project targeting.*Python")
        # Ensure a summary is printed in the subproject and the outer project
        self.assertRegex(out, r"\|WARNING: Project specifies a minimum meson_version '>=0.40'")
        self.assertRegex(out, r"\| \* 0.44.0: {'disabler'}")
        self.assertRegex(out, "WARNING: Project specifies a minimum meson_version '>=0.45'")
        self.assertRegex(out, " * 0.47.0: {'dict'}")

    def test_configure_file_warnings(self):
        testdir = os.path.join(self.common_test_dir, "14 configure file")
        out = self.init(testdir)
        self.assertRegex(out, "WARNING:.*'empty'.*config.h.in.*not present.*")
        self.assertRegex(out, "WARNING:.*'FOO_BAR'.*nosubst-nocopy2.txt.in.*not present.*")
        self.assertRegex(out, "WARNING:.*'empty'.*config.h.in.*not present.*")
        self.assertRegex(out, "WARNING:.*empty configuration_data.*test.py.in")
        # Warnings for configuration files that are overwritten.
        self.assertRegex(out, "WARNING:.*\"double_output.txt\".*overwrites")
        self.assertRegex(out, "WARNING:.*\"subdir.double_output2.txt\".*overwrites")
        self.assertNotRegex(out, "WARNING:.*no_write_conflict.txt.*overwrites")
        self.assertNotRegex(out, "WARNING:.*@BASENAME@.*overwrites")
        self.assertRegex(out, "WARNING:.*\"sameafterbasename\".*overwrites")
        # No warnings about empty configuration data objects passed to files with substitutions
        self.assertNotRegex(out, "WARNING:.*empty configuration_data.*nosubst-nocopy1.txt.in")
        self.assertNotRegex(out, "WARNING:.*empty configuration_data.*nosubst-nocopy2.txt.in")
        with open(os.path.join(self.builddir, 'nosubst-nocopy1.txt'), 'rb') as f:
            self.assertEqual(f.read().strip(), b'/* #undef FOO_BAR */')
        with open(os.path.join(self.builddir, 'nosubst-nocopy2.txt'), 'rb') as f:
            self.assertEqual(f.read().strip(), b'')
        self.assertRegex(out, r"DEPRECATION:.*\['array'\] is invalid.*dict")

    def test_dirs(self):
        with tempfile.TemporaryDirectory() as containing:
            with tempfile.TemporaryDirectory(dir=containing) as srcdir:
                mfile = os.path.join(srcdir, 'meson.build')
                of = open(mfile, 'w')
                of.write("project('foobar', 'c')\n")
                of.close()
                pc = subprocess.run(self.setup_command,
                                    cwd=srcdir,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL)
                self.assertIn(b'Must specify at least one directory name', pc.stdout)
                with tempfile.TemporaryDirectory(dir=srcdir) as builddir:
                    subprocess.run(self.setup_command,
                                   check=True,
                                   cwd=builddir,
                                   stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)

    def get_opts_as_dict(self):
        result = {}
        for i in self.introspect('--buildoptions'):
            result[i['name']] = i['value']
        return result

    def test_buildtype_setting(self):
        testdir = os.path.join(self.common_test_dir, '1 trivial')
        self.init(testdir)
        opts = self.get_opts_as_dict()
        self.assertEqual(opts['buildtype'], 'debug')
        self.assertEqual(opts['debug'], True)
        self.setconf('-Ddebug=false')
        opts = self.get_opts_as_dict()
        self.assertEqual(opts['debug'], False)
        self.assertEqual(opts['buildtype'], 'plain')
        self.assertEqual(opts['optimization'], '0')

        # Setting optimizations to 3 should cause buildtype
        # to go to release mode.
        self.setconf('-Doptimization=3')
        opts = self.get_opts_as_dict()
        self.assertEqual(opts['buildtype'], 'release')
        self.assertEqual(opts['debug'], False)
        self.assertEqual(opts['optimization'], '3')

        # Going to debug build type should reset debugging
        # and optimization
        self.setconf('-Dbuildtype=debug')
        opts = self.get_opts_as_dict()
        self.assertEqual(opts['buildtype'], 'debug')
        self.assertEqual(opts['debug'], True)
        self.assertEqual(opts['optimization'], '0')

        # Command-line parsing of buildtype settings should be the same as
        # setting with `meson configure`.
        #
        # Setting buildtype should set optimization/debug
        self.new_builddir()
        self.init(testdir, extra_args=['-Dbuildtype=debugoptimized'])
        opts = self.get_opts_as_dict()
        self.assertEqual(opts['debug'], True)
        self.assertEqual(opts['optimization'], '2')
        self.assertEqual(opts['buildtype'], 'debugoptimized')
        # Setting optimization/debug should set buildtype
        self.new_builddir()
        self.init(testdir, extra_args=['-Doptimization=2', '-Ddebug=true'])
        opts = self.get_opts_as_dict()
        self.assertEqual(opts['debug'], True)
        self.assertEqual(opts['optimization'], '2')
        self.assertEqual(opts['buildtype'], 'debugoptimized')
        # Setting both buildtype and debug on the command-line should work, and
        # should warn not to do that. Also test that --debug is parsed as -Ddebug=true
        self.new_builddir()
        out = self.init(testdir, extra_args=['-Dbuildtype=debugoptimized', '--debug'])
        self.assertRegex(out, 'Recommend using either.*buildtype.*debug.*redundant')
        opts = self.get_opts_as_dict()
        self.assertEqual(opts['debug'], True)
        self.assertEqual(opts['optimization'], '2')
        self.assertEqual(opts['buildtype'], 'debugoptimized')

    @skipIfNoPkgconfig
    @unittest.skipIf(is_windows(), 'Help needed with fixing this test on windows')
    def test_native_dep_pkgconfig(self):
        testdir = os.path.join(self.unit_test_dir,
                               '46 native dep pkgconfig var')
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as crossfile:
            crossfile.write(textwrap.dedent(
                '''[binaries]
                pkgconfig = '{0}'

                [properties]

                [host_machine]
                system = 'linux'
                cpu_family = 'arm'
                cpu = 'armv7'
                endian = 'little'
                '''.format(os.path.join(testdir, 'cross_pkgconfig.py'))))
            crossfile.flush()
            self.meson_cross_file = crossfile.name

        env = {'PKG_CONFIG_LIBDIR':  os.path.join(testdir,
                                                  'native_pkgconfig')}
        self.init(testdir, extra_args=['-Dstart_native=false'], override_envvars=env)
        self.wipe()
        self.init(testdir, extra_args=['-Dstart_native=true'], override_envvars=env)

    @skipIfNoPkgconfig
    @unittest.skipIf(is_windows(), 'Help needed with fixing this test on windows')
    def test_pkg_config_libdir(self):
        testdir = os.path.join(self.unit_test_dir,
                               '46 native dep pkgconfig var')
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as crossfile:
            crossfile.write(textwrap.dedent(
                '''[binaries]
                pkgconfig = 'pkg-config'

                [properties]
                pkg_config_libdir = ['{0}']

                [host_machine]
                system = 'linux'
                cpu_family = 'arm'
                cpu = 'armv7'
                endian = 'little'
                '''.format(os.path.join(testdir, 'cross_pkgconfig'))))
            crossfile.flush()
            self.meson_cross_file = crossfile.name

        env = {'PKG_CONFIG_LIBDIR':  os.path.join(testdir,
                                                  'native_pkgconfig')}
        self.init(testdir, extra_args=['-Dstart_native=false'], override_envvars=env)
        self.wipe()
        self.init(testdir, extra_args=['-Dstart_native=true'], override_envvars=env)

    def __reconfigure(self, change_minor=False):
        # Set an older version to force a reconfigure from scratch
        filename = os.path.join(self.privatedir, 'coredata.dat')
        with open(filename, 'rb') as f:
            obj = pickle.load(f)
        if change_minor:
            v = mesonbuild.coredata.version.split('.')
            obj.version = '.'.join(v[0:2] + [str(int(v[2]) + 1)])
        else:
            obj.version = '0.47.0'
        with open(filename, 'wb') as f:
            pickle.dump(obj, f)

    def test_reconfigure(self):
        testdir = os.path.join(self.unit_test_dir, '48 reconfigure')
        self.init(testdir, extra_args=['-Dopt1=val1'])
        self.setconf('-Dopt2=val2')

        self.__reconfigure()

        out = self.init(testdir, extra_args=['--reconfigure', '-Dopt3=val3'])
        self.assertRegex(out, 'Regenerating configuration from scratch')
        self.assertRegex(out, 'opt1 val1')
        self.assertRegex(out, 'opt2 val2')
        self.assertRegex(out, 'opt3 val3')
        self.assertRegex(out, 'opt4 default4')
        self.build()
        self.run_tests()

        # Create a file in builddir and verify wipe command removes it
        filename = os.path.join(self.builddir, 'something')
        open(filename, 'w').close()
        self.assertTrue(os.path.exists(filename))
        out = self.init(testdir, extra_args=['--wipe', '-Dopt4=val4'])
        self.assertFalse(os.path.exists(filename))
        self.assertRegex(out, 'opt1 val1')
        self.assertRegex(out, 'opt2 val2')
        self.assertRegex(out, 'opt3 val3')
        self.assertRegex(out, 'opt4 val4')
        self.build()
        self.run_tests()

    def test_wipe_from_builddir(self):
        testdir = os.path.join(self.common_test_dir, '161 custom target subdir depend files')
        self.init(testdir)
        self.__reconfigure()

        with Path(self.builddir):
            self.init(testdir, extra_args=['--wipe'])

    def test_minor_version_does_not_reconfigure_wipe(self):
        testdir = os.path.join(self.unit_test_dir, '48 reconfigure')
        self.init(testdir, extra_args=['-Dopt1=val1'])
        self.setconf('-Dopt2=val2')

        self.__reconfigure(change_minor=True)

        out = self.init(testdir, extra_args=['--reconfigure', '-Dopt3=val3'])
        self.assertNotRegex(out, 'Regenerating configuration from scratch')
        self.assertRegex(out, 'opt1 val1')
        self.assertRegex(out, 'opt2 val2')
        self.assertRegex(out, 'opt3 val3')
        self.assertRegex(out, 'opt4 default4')
        self.build()
        self.run_tests()

    def test_target_construct_id_from_path(self):
        # This id is stable but not guessable.
        # The test is supposed to prevent unintentional
        # changes of target ID generation.
        target_id = Target.construct_id_from_path('some/obscure/subdir',
                                                  'target-id', '@suffix')
        self.assertEqual('5e002d3@@target-id@suffix', target_id)
        target_id = Target.construct_id_from_path('subproject/foo/subdir/bar',
                                                  'target2-id', '@other')
        self.assertEqual('81d46d1@@target2-id@other', target_id)

    def test_introspect_projectinfo_without_configured_build(self):
        testfile = os.path.join(self.common_test_dir, '35 run program', 'meson.build')
        res = self.introspect_directory(testfile, '--projectinfo')
        self.assertEqual(set(res['buildsystem_files']), set(['meson.build']))
        self.assertEqual(res['version'], 'undefined')
        self.assertEqual(res['descriptive_name'], 'run command')
        self.assertEqual(res['subprojects'], [])

        testfile = os.path.join(self.common_test_dir, '43 options', 'meson.build')
        res = self.introspect_directory(testfile, '--projectinfo')
        self.assertEqual(set(res['buildsystem_files']), set(['meson_options.txt', 'meson.build']))
        self.assertEqual(res['version'], 'undefined')
        self.assertEqual(res['descriptive_name'], 'options')
        self.assertEqual(res['subprojects'], [])

        testfile = os.path.join(self.common_test_dir, '46 subproject options', 'meson.build')
        res = self.introspect_directory(testfile, '--projectinfo')
        self.assertEqual(set(res['buildsystem_files']), set(['meson_options.txt', 'meson.build']))
        self.assertEqual(res['version'], 'undefined')
        self.assertEqual(res['descriptive_name'], 'suboptions')
        self.assertEqual(len(res['subprojects']), 1)
        subproject_files = set(f.replace('\\', '/') for f in res['subprojects'][0]['buildsystem_files'])
        self.assertEqual(subproject_files, set(['subprojects/subproject/meson_options.txt', 'subprojects/subproject/meson.build']))
        self.assertEqual(res['subprojects'][0]['name'], 'subproject')
        self.assertEqual(res['subprojects'][0]['version'], 'undefined')
        self.assertEqual(res['subprojects'][0]['descriptive_name'], 'subproject')

    def test_introspect_projectinfo_subprojects(self):
        testdir = os.path.join(self.common_test_dir, '102 subproject subdir')
        self.init(testdir)
        res = self.introspect('--projectinfo')
        expected = {
            'descriptive_name': 'proj',
            'version': 'undefined',
            'subproject_dir': 'subprojects',
            'subprojects': [
                {
                    'descriptive_name': 'sub',
                    'name': 'sub',
                    'version': '1.0'
                },
                {
                    'descriptive_name': 'sub_implicit',
                    'name': 'sub_implicit',
                    'version': '1.0',
                },
                {
                    'descriptive_name': 'sub-novar',
                    'name': 'sub_novar',
                    'version': '1.0',
                },
            ]
        }
        res['subprojects'] = sorted(res['subprojects'], key=lambda i: i['name'])
        self.assertDictEqual(expected, res)

    def test_introspection_target_subproject(self):
        testdir = os.path.join(self.common_test_dir, '45 subproject')
        self.init(testdir)
        res = self.introspect('--targets')

        expected = {
            'sublib': 'sublib',
            'simpletest': 'sublib',
            'user': None
        }

        for entry in res:
            name = entry['name']
            self.assertEqual(entry['subproject'], expected[name])

    def test_introspect_projectinfo_subproject_dir(self):
        testdir = os.path.join(self.common_test_dir, '78 custom subproject dir')
        self.init(testdir)
        res = self.introspect('--projectinfo')

        self.assertEqual(res['subproject_dir'], 'custom_subproject_dir')

    def test_introspect_projectinfo_subproject_dir_from_source(self):
        testfile = os.path.join(self.common_test_dir, '78 custom subproject dir', 'meson.build')
        res = self.introspect_directory(testfile, '--projectinfo')

        self.assertEqual(res['subproject_dir'], 'custom_subproject_dir')

    @skipIfNoExecutable('clang-format')
    def test_clang_format(self):
        if self.backend is not Backend.ninja:
            raise unittest.SkipTest('Clang-format is for now only supported on Ninja, not {}'.format(self.backend.name))
        testdir = os.path.join(self.unit_test_dir, '54 clang-format')
        testfile = os.path.join(testdir, 'prog.c')
        badfile = os.path.join(testdir, 'prog_orig_c')
        goodfile = os.path.join(testdir, 'prog_expected_c')
        testheader = os.path.join(testdir, 'header.h')
        badheader = os.path.join(testdir, 'header_orig_h')
        goodheader = os.path.join(testdir, 'header_expected_h')
        try:
            shutil.copyfile(badfile, testfile)
            shutil.copyfile(badheader, testheader)
            self.init(testdir)
            self.assertNotEqual(Path(testfile).read_text(),
                                Path(goodfile).read_text())
            self.assertNotEqual(Path(testheader).read_text(),
                                Path(goodheader).read_text())
            self.run_target('clang-format')
            self.assertEqual(Path(testheader).read_text(),
                             Path(goodheader).read_text())
        finally:
            if os.path.exists(testfile):
                os.unlink(testfile)
            if os.path.exists(testheader):
                os.unlink(testheader)

    @skipIfNoExecutable('clang-tidy')
    def test_clang_tidy(self):
        if self.backend is not Backend.ninja:
            raise unittest.SkipTest('Clang-tidy is for now only supported on Ninja, not {}'.format(self.backend.name))
        if shutil.which('c++') is None:
            raise unittest.SkipTest('Clang-tidy breaks when ccache is used and "c++" not in path.')
        if is_osx():
            raise unittest.SkipTest('Apple ships a broken clang-tidy that chokes on -pipe.')
        testdir = os.path.join(self.unit_test_dir, '70 clang-tidy')
        self.init(testdir, override_envvars={'CXX': 'c++'})
        out = self.run_target('clang-tidy')
        self.assertIn('cttest.cpp:4:20', out)

    def test_identity_cross(self):
        testdir = os.path.join(self.unit_test_dir, '71 cross')
        # Do a build to generate a cross file where the host is this target
        self.init(testdir, extra_args=['-Dgenerate=true'])
        self.meson_cross_file = os.path.join(self.builddir, "crossfile")
        self.assertTrue(os.path.exists(self.meson_cross_file))
        # Now verify that this is detected as cross
        self.new_builddir()
        self.init(testdir)

    def test_introspect_buildoptions_without_configured_build(self):
        testdir = os.path.join(self.unit_test_dir, '59 introspect buildoptions')
        testfile = os.path.join(testdir, 'meson.build')
        res_nb = self.introspect_directory(testfile, ['--buildoptions'] + self.meson_args)
        self.init(testdir, default_args=False)
        res_wb = self.introspect('--buildoptions')
        self.maxDiff = None
        self.assertListEqual(res_nb, res_wb)

    def test_meson_configure_from_source_does_not_crash(self):
        testdir = os.path.join(self.unit_test_dir, '59 introspect buildoptions')
        self._run(self.mconf_command + [testdir])

    def test_introspect_json_dump(self):
        testdir = os.path.join(self.unit_test_dir, '57 introspection')
        self.init(testdir)
        infodir = os.path.join(self.builddir, 'meson-info')
        self.assertPathExists(infodir)

        def assertKeyTypes(key_type_list, obj):
            for i in key_type_list:
                self.assertIn(i[0], obj)
                self.assertIsInstance(obj[i[0]], i[1])

        root_keylist = [
            ('benchmarks', list),
            ('buildoptions', list),
            ('buildsystem_files', list),
            ('dependencies', list),
            ('installed', dict),
            ('projectinfo', dict),
            ('targets', list),
            ('tests', list),
        ]

        test_keylist = [
            ('cmd', list),
            ('env', dict),
            ('name', str),
            ('timeout', int),
            ('suite', list),
            ('is_parallel', bool),
            ('protocol', str),
        ]

        buildoptions_keylist = [
            ('name', str),
            ('section', str),
            ('type', str),
            ('description', str),
            ('machine', str),
        ]

        buildoptions_typelist = [
            ('combo', str, [('choices', list)]),
            ('string', str, []),
            ('boolean', bool, []),
            ('integer', int, []),
            ('array', list, []),
        ]

        buildoptions_sections = ['core', 'backend', 'base', 'compiler', 'directory', 'user', 'test']
        buildoptions_machines = ['any', 'build', 'host']

        dependencies_typelist = [
            ('name', str),
            ('version', str),
            ('compile_args', list),
            ('link_args', list),
        ]

        targets_typelist = [
            ('name', str),
            ('id', str),
            ('type', str),
            ('defined_in', str),
            ('filename', list),
            ('build_by_default', bool),
            ('target_sources', list),
            ('installed', bool),
        ]

        targets_sources_typelist = [
            ('language', str),
            ('compiler', list),
            ('parameters', list),
            ('sources', list),
            ('generated_sources', list),
        ]

        # First load all files
        res = {}
        for i in root_keylist:
            curr = os.path.join(infodir, 'intro-{}.json'.format(i[0]))
            self.assertPathExists(curr)
            with open(curr, 'r') as fp:
                res[i[0]] = json.load(fp)

        assertKeyTypes(root_keylist, res)

        # Check Tests and benchmarks
        tests_to_find = ['test case 1', 'test case 2', 'benchmark 1']
        for i in res['benchmarks'] + res['tests']:
            assertKeyTypes(test_keylist, i)
            if i['name'] in tests_to_find:
                tests_to_find.remove(i['name'])
        self.assertListEqual(tests_to_find, [])

        # Check buildoptions
        buildopts_to_find = {'cpp_std': 'c++11'}
        for i in res['buildoptions']:
            assertKeyTypes(buildoptions_keylist, i)
            valid_type = False
            for j in buildoptions_typelist:
                if i['type'] == j[0]:
                    self.assertIsInstance(i['value'], j[1])
                    assertKeyTypes(j[2], i)
                    valid_type = True
                    break

            self.assertIn(i['section'], buildoptions_sections)
            self.assertIn(i['machine'], buildoptions_machines)
            self.assertTrue(valid_type)
            if i['name'] in buildopts_to_find:
                self.assertEqual(i['value'], buildopts_to_find[i['name']])
                buildopts_to_find.pop(i['name'], None)
        self.assertDictEqual(buildopts_to_find, {})

        # Check buildsystem_files
        bs_files = ['meson.build', 'meson_options.txt', 'sharedlib/meson.build', 'staticlib/meson.build']
        bs_files = [os.path.join(testdir, x) for x in bs_files]
        self.assertPathListEqual(list(sorted(res['buildsystem_files'])), list(sorted(bs_files)))

        # Check dependencies
        dependencies_to_find = ['threads']
        for i in res['dependencies']:
            assertKeyTypes(dependencies_typelist, i)
            if i['name'] in dependencies_to_find:
                dependencies_to_find.remove(i['name'])
        self.assertListEqual(dependencies_to_find, [])

        # Check projectinfo
        self.assertDictEqual(res['projectinfo'], {'version': '1.2.3', 'descriptive_name': 'introspection', 'subproject_dir': 'subprojects', 'subprojects': []})

        # Check targets
        targets_to_find = {
            'sharedTestLib': ('shared library', True, False, 'sharedlib/meson.build'),
            'staticTestLib': ('static library', True, False, 'staticlib/meson.build'),
            'test1': ('executable', True, True, 'meson.build'),
            'test2': ('executable', True, False, 'meson.build'),
            'test3': ('executable', True, False, 'meson.build'),
        }
        for i in res['targets']:
            assertKeyTypes(targets_typelist, i)
            if i['name'] in targets_to_find:
                tgt = targets_to_find[i['name']]
                self.assertEqual(i['type'], tgt[0])
                self.assertEqual(i['build_by_default'], tgt[1])
                self.assertEqual(i['installed'], tgt[2])
                self.assertPathEqual(i['defined_in'], os.path.join(testdir, tgt[3]))
                targets_to_find.pop(i['name'], None)
            for j in i['target_sources']:
                assertKeyTypes(targets_sources_typelist, j)
        self.assertDictEqual(targets_to_find, {})

    def test_introspect_file_dump_equals_all(self):
        testdir = os.path.join(self.unit_test_dir, '57 introspection')
        self.init(testdir)
        res_all = self.introspect('--all')
        res_file = {}

        root_keylist = [
            'benchmarks',
            'buildoptions',
            'buildsystem_files',
            'dependencies',
            'installed',
            'projectinfo',
            'targets',
            'tests',
        ]

        infodir = os.path.join(self.builddir, 'meson-info')
        self.assertPathExists(infodir)
        for i in root_keylist:
            curr = os.path.join(infodir, 'intro-{}.json'.format(i))
            self.assertPathExists(curr)
            with open(curr, 'r') as fp:
                res_file[i] = json.load(fp)

        self.assertEqual(res_all, res_file)

    def test_introspect_meson_info(self):
        testdir = os.path.join(self.unit_test_dir, '57 introspection')
        introfile = os.path.join(self.builddir, 'meson-info', 'meson-info.json')
        self.init(testdir)
        self.assertPathExists(introfile)
        with open(introfile, 'r') as fp:
            res1 = json.load(fp)

        for i in ['meson_version', 'directories', 'introspection', 'build_files_updated', 'error']:
            self.assertIn(i, res1)

        self.assertEqual(res1['error'], False)
        self.assertEqual(res1['build_files_updated'], True)

    def test_introspect_config_update(self):
        testdir = os.path.join(self.unit_test_dir, '57 introspection')
        introfile = os.path.join(self.builddir, 'meson-info', 'intro-buildoptions.json')
        self.init(testdir)
        self.assertPathExists(introfile)
        with open(introfile, 'r') as fp:
            res1 = json.load(fp)

        self.setconf('-Dcpp_std=c++14')
        self.setconf('-Dbuildtype=release')

        for idx, i in enumerate(res1):
            if i['name'] == 'cpp_std':
                res1[idx]['value'] = 'c++14'
            if i['name'] == 'build.cpp_std':
                res1[idx]['value'] = 'c++14'
            if i['name'] == 'buildtype':
                res1[idx]['value'] = 'release'
            if i['name'] == 'optimization':
                res1[idx]['value'] = '3'
            if i['name'] == 'debug':
                res1[idx]['value'] = False

        with open(introfile, 'r') as fp:
            res2 = json.load(fp)

        self.assertListEqual(res1, res2)

    def test_introspect_targets_from_source(self):
        testdir = os.path.join(self.unit_test_dir, '57 introspection')
        testfile = os.path.join(testdir, 'meson.build')
        introfile = os.path.join(self.builddir, 'meson-info', 'intro-targets.json')
        self.init(testdir)
        self.assertPathExists(introfile)
        with open(introfile, 'r') as fp:
            res_wb = json.load(fp)

        res_nb = self.introspect_directory(testfile, ['--targets'] + self.meson_args)

        # Account for differences in output
        for i in res_wb:
            i['filename'] = [os.path.relpath(x, self.builddir) for x in i['filename']]
            if 'install_filename' in i:
                del i['install_filename']

            sources = []
            for j in i['target_sources']:
                sources += j['sources']
            i['target_sources'] = [{
                'language': 'unknown',
                'compiler': [],
                'parameters': [],
                'sources': sources,
                'generated_sources': []
            }]

        self.maxDiff = None
        self.assertListEqual(res_nb, res_wb)

    def test_introspect_ast_source(self):
        testdir = os.path.join(self.unit_test_dir, '57 introspection')
        testfile = os.path.join(testdir, 'meson.build')
        res_nb = self.introspect_directory(testfile, ['--ast'] + self.meson_args)

        node_counter = {}

        def accept_node(json_node):
            self.assertIsInstance(json_node, dict)
            for i in ['lineno', 'colno', 'end_lineno', 'end_colno']:
                self.assertIn(i, json_node)
                self.assertIsInstance(json_node[i], int)
            self.assertIn('node', json_node)
            n = json_node['node']
            self.assertIsInstance(n, str)
            self.assertIn(n, nodes)
            if n not in node_counter:
                node_counter[n] = 0
            node_counter[n] = node_counter[n] + 1
            for nodeDesc in nodes[n]:
                key = nodeDesc[0]
                func = nodeDesc[1]
                self.assertIn(key, json_node)
                if func is None:
                    tp = nodeDesc[2]
                    self.assertIsInstance(json_node[key], tp)
                    continue
                func(json_node[key])

        def accept_node_list(node_list):
            self.assertIsInstance(node_list, list)
            for i in node_list:
                accept_node(i)

        def accept_kwargs(kwargs):
            self.assertIsInstance(kwargs, list)
            for i in kwargs:
                self.assertIn('key', i)
                self.assertIn('val', i)
                accept_node(i['key'])
                accept_node(i['val'])

        nodes = {
            'BooleanNode': [('value', None, bool)],
            'IdNode': [('value', None, str)],
            'NumberNode': [('value', None, int)],
            'StringNode': [('value', None, str)],
            'ContinueNode': [],
            'BreakNode': [],
            'ArgumentNode': [('positional', accept_node_list), ('kwargs', accept_kwargs)],
            'ArrayNode': [('args', accept_node)],
            'DictNode': [('args', accept_node)],
            'EmptyNode': [],
            'OrNode': [('left', accept_node), ('right', accept_node)],
            'AndNode': [('left', accept_node), ('right', accept_node)],
            'ComparisonNode': [('left', accept_node), ('right', accept_node), ('ctype', None, str)],
            'ArithmeticNode': [('left', accept_node), ('right', accept_node), ('op', None, str)],
            'NotNode': [('right', accept_node)],
            'CodeBlockNode': [('lines', accept_node_list)],
            'IndexNode': [('object', accept_node), ('index', accept_node)],
            'MethodNode': [('object', accept_node), ('args', accept_node), ('name', None, str)],
            'FunctionNode': [('args', accept_node), ('name', None, str)],
            'AssignmentNode': [('value', accept_node), ('var_name', None, str)],
            'PlusAssignmentNode': [('value', accept_node), ('var_name', None, str)],
            'ForeachClauseNode': [('items', accept_node), ('block', accept_node), ('varnames', None, list)],
            'IfClauseNode': [('ifs', accept_node_list), ('else', accept_node)],
            'IfNode': [('condition', accept_node), ('block', accept_node)],
            'UMinusNode': [('right', accept_node)],
            'TernaryNode': [('condition', accept_node), ('true', accept_node), ('false', accept_node)],
        }

        accept_node(res_nb)

        for n, c in [('ContinueNode', 2), ('BreakNode', 1), ('NotNode', 3)]:
            self.assertIn(n, node_counter)
            self.assertEqual(node_counter[n], c)

    def test_introspect_dependencies_from_source(self):
        testdir = os.path.join(self.unit_test_dir, '57 introspection')
        testfile = os.path.join(testdir, 'meson.build')
        res_nb = self.introspect_directory(testfile, ['--scan-dependencies'] + self.meson_args)
        expected = [
            {
                'name': 'threads',
                'required': True,
                'version': [],
                'has_fallback': False,
                'conditional': False
            },
            {
                'name': 'zlib',
                'required': False,
                'version': [],
                'has_fallback': False,
                'conditional': False
            },
            {
                'name': 'bugDep1',
                'required': True,
                'version': [],
                'has_fallback': False,
                'conditional': False
            },
            {
                'name': 'somethingthatdoesnotexist',
                'required': True,
                'version': ['>=1.2.3'],
                'has_fallback': False,
                'conditional': True
            },
            {
                'name': 'look_i_have_a_fallback',
                'required': True,
                'version': ['>=1.0.0', '<=99.9.9'],
                'has_fallback': True,
                'conditional': True
            }
        ]
        self.maxDiff = None
        self.assertListEqual(res_nb, expected)

    def test_unstable_coredata(self):
        testdir = os.path.join(self.common_test_dir, '1 trivial')
        self.init(testdir)
        # just test that the command does not fail (e.g. because it throws an exception)
        self._run([*self.meson_command, 'unstable-coredata', self.builddir])

    @skip_if_no_cmake
    def test_cmake_prefix_path(self):
        testdir = os.path.join(self.unit_test_dir, '64 cmake_prefix_path')
        self.init(testdir, extra_args=['-Dcmake_prefix_path=' + os.path.join(testdir, 'prefix')])

    @skip_if_no_cmake
    def test_cmake_parser(self):
        testdir = os.path.join(self.unit_test_dir, '65 cmake parser')
        self.init(testdir, extra_args=['-Dcmake_prefix_path=' + os.path.join(testdir, 'prefix')])

    def test_alias_target(self):
        if self.backend is Backend.vs:
            # FIXME: This unit test is broken with vs backend, needs investigation
            raise unittest.SkipTest('Skipping alias_target test with {} backend'.format(self.backend.name))
        testdir = os.path.join(self.unit_test_dir, '66 alias target')
        self.init(testdir)
        self.build()
        self.assertPathDoesNotExist(os.path.join(self.builddir, 'prog' + exe_suffix))
        self.assertPathDoesNotExist(os.path.join(self.builddir, 'hello.txt'))
        self.run_target('build-all')
        self.assertPathExists(os.path.join(self.builddir, 'prog' + exe_suffix))
        self.assertPathExists(os.path.join(self.builddir, 'hello.txt'))

    def test_configure(self):
        testdir = os.path.join(self.common_test_dir, '2 cpp')
        self.init(testdir)
        self._run(self.mconf_command + [self.builddir])

    def test_summary(self):
        testdir = os.path.join(self.unit_test_dir, '73 summary')
        out = self.init(testdir)
        expected = textwrap.dedent(r'''
            Some Subproject 2.0

                 string: bar
                integer: 1
                boolean: True

            My Project 1.0

              Configuration
                   Some boolean: False
                Another boolean: True
                    Some string: Hello World
                         A list: string
                                 1
                                 True
                     empty list:
                       A number: 1
                            yes: YES
                             no: NO
                      coma list: a, b, c

              Subprojects
                            sub: YES
                           sub2: NO Problem encountered: This subproject failed
            ''')
        expected_lines = expected.split('\n')[1:]
        out_start = out.find(expected_lines[0])
        out_lines = out[out_start:].split('\n')[:len(expected_lines)]
        if sys.version_info < (3, 7, 0):
            # Dictionary order is not stable in Python <3.7, so sort the lines
            # while comparing
            self.assertEqual(sorted(expected_lines), sorted(out_lines))
        else:
            self.assertEqual(expected_lines, out_lines)

    def test_meson_compile(self):
        """Test the meson compile command."""

        def get_exe_name(basename: str) -> str:
            if is_windows():
                return '{}.exe'.format(basename)
            else:
                return basename

        def get_shared_lib_name(basename: str) -> str:
            if mesonbuild.environment.detect_msys2_arch():
                return 'lib{}.dll'.format(basename)
            elif is_windows():
                return '{}.dll'.format(basename)
            elif is_cygwin():
                return 'cyg{}.dll'.format(basename)
            elif is_osx():
                return 'lib{}.dylib'.format(basename)
            else:
                return 'lib{}.so'.format(basename)

        def get_static_lib_name(basename: str) -> str:
            return 'lib{}.a'.format(basename)

        # Base case (no targets or additional arguments)

        testdir = os.path.join(self.common_test_dir, '1 trivial')
        self.init(testdir)

        self._run([*self.meson_command, 'compile', '-C', self.builddir])
        self.assertPathExists(os.path.join(self.builddir, get_exe_name('trivialprog')))

        # `--clean`

        self._run([*self.meson_command, 'compile', '-C', self.builddir, '--clean'])
        self.assertPathDoesNotExist(os.path.join(self.builddir, get_exe_name('trivialprog')))

        # Target specified in a project with unique names

        testdir = os.path.join(self.common_test_dir, '6 linkshared')
        self.init(testdir, extra_args=['--wipe'])
        # Multiple targets and target type specified
        self._run([*self.meson_command, 'compile', '-C', self.builddir, 'mylib', 'mycpplib:shared_library'])
        # Check that we have a shared lib, but not an executable, i.e. check that target actually worked
        self.assertPathExists(os.path.join(self.builddir, get_shared_lib_name('mylib')))
        self.assertPathDoesNotExist(os.path.join(self.builddir, get_exe_name('prog')))
        self.assertPathExists(os.path.join(self.builddir, get_shared_lib_name('mycpplib')))
        self.assertPathDoesNotExist(os.path.join(self.builddir, get_exe_name('cppprog')))

        # Target specified in a project with non unique names

        testdir = os.path.join(self.common_test_dir, '190 same target name')
        self.init(testdir, extra_args=['--wipe'])
        self._run([*self.meson_command, 'compile', '-C', self.builddir, './foo'])
        self.assertPathExists(os.path.join(self.builddir, get_static_lib_name('foo')))
        self._run([*self.meson_command, 'compile', '-C', self.builddir, 'sub/foo'])
        self.assertPathExists(os.path.join(self.builddir, 'sub', get_static_lib_name('foo')))

        # run_target

        testdir = os.path.join(self.common_test_dir, '54 run target')
        self.init(testdir, extra_args=['--wipe'])
        out = self._run([*self.meson_command, 'compile', '-C', self.builddir, 'py3hi'])
        self.assertIn('I am Python3.', out)

        # `--$BACKEND-args`

        testdir = os.path.join(self.common_test_dir, '1 trivial')
        if self.backend is Backend.ninja:
            self.init(testdir, extra_args=['--wipe'])
            # Dry run - should not create a program
            self._run([*self.meson_command, 'compile', '-C', self.builddir, '--ninja-args=-n'])
            self.assertPathDoesNotExist(os.path.join(self.builddir, get_exe_name('trivialprog')))
        elif self.backend is Backend.vs:
            self.init(testdir, extra_args=['--wipe'])
            self._run([*self.meson_command, 'compile', '-C', self.builddir])
            # Explicitly clean the target through msbuild interface
            self._run([*self.meson_command, 'compile', '-C', self.builddir, '--vs-args=-t:{}:Clean'.format(re.sub(r'[\%\$\@\;\.\(\)\']', '_', get_exe_name('trivialprog')))])
            self.assertPathDoesNotExist(os.path.join(self.builddir, get_exe_name('trivialprog')))

    def test_spurious_reconfigure_built_dep_file(self):
        testdir = os.path.join(self.unit_test_dir, '75 dep files')

        # Regression test: Spurious reconfigure was happening when build
        # directory is inside source directory.
        # See https://gitlab.freedesktop.org/gstreamer/gst-build/-/issues/85.
        srcdir = os.path.join(self.builddir, 'srctree')
        shutil.copytree(testdir, srcdir)
        builddir = os.path.join(srcdir, '_build')
        self.change_builddir(builddir)

        self.init(srcdir)
        self.build()

        # During first configure the file did not exist so no dependency should
        # have been set. A rebuild should not trigger a reconfigure.
        self.clean()
        out = self.build()
        self.assertNotIn('Project configured', out)

        self.init(srcdir, extra_args=['--reconfigure'])

        # During the reconfigure the file did exist, but is inside build
        # directory, so no dependency should have been set. A rebuild should not
        # trigger a reconfigure.
        self.clean()
        out = self.build()
        self.assertNotIn('Project configured', out)

    def _test_junit(self, case: str) -> None:
        try:
            import lxml.etree as et
        except ImportError:
            raise unittest.SkipTest('lxml required, but not found.')

        schema = et.XMLSchema(et.parse(str(Path(__file__).parent / 'data' / 'schema.xsd')))

        self.init(case)
        self.run_tests()

        junit = et.parse(str(Path(self.builddir) / 'meson-logs' / 'testlog.junit.xml'))
        try:
            schema.assertValid(junit)
        except et.DocumentInvalid as e:
            self.fail(e.error_log)

    def test_junit_valid_tap(self):
        self._test_junit(os.path.join(self.common_test_dir, '213 tap tests'))

    def test_junit_valid_exitcode(self):
        self._test_junit(os.path.join(self.common_test_dir, '44 test args'))

    def test_junit_valid_gtest(self):
        self._test_junit(os.path.join(self.framework_test_dir, '2 gtest'))

    def test_link_language_linker(self):
        # TODO: there should be some way to query how we're linking things
        # without resorting to reading the ninja.build file
        if self.backend is not Backend.ninja:
            raise unittest.SkipTest('This test reads the ninja file')

        testdir = os.path.join(self.common_test_dir, '232 link language')
        self.init(testdir)

        build_ninja = os.path.join(self.builddir, 'build.ninja')
        with open(build_ninja, 'r', encoding='utf-8') as f:
            contents = f.read()

        self.assertRegex(contents, r'build main(\.exe)?.*: c_LINKER')
        self.assertRegex(contents, r'build (lib|cyg)?mylib.*: c_LINKER')

    def test_commands_documented(self):
        '''
        Test that all listed meson commands are documented in Commands.md.
        '''

        # The docs directory is not in release tarballs.
        if not os.path.isdir('docs'):
            raise unittest.SkipTest('Doc directory does not exist.')
        doc_path = 'docs/markdown_dynamic/Commands.md'

        md = None
        with open(doc_path, encoding='utf-8') as f:
            md = f.read()
        self.assertIsNotNone(md)

        ## Get command sections

        section_pattern = re.compile(r'^### (.+)$', re.MULTILINE)
        md_command_section_matches = [i for i in section_pattern.finditer(md)]
        md_command_sections = dict()
        for i, s in enumerate(md_command_section_matches):
            section_end = len(md) if i == len(md_command_section_matches) - 1 else md_command_section_matches[i + 1].start()
            md_command_sections[s.group(1)] = (s.start(), section_end)

        ## Validate commands

        md_commands = set(k for k,v in md_command_sections.items())

        help_output = self._run(self.meson_command + ['--help'])
        help_commands = set(c.strip() for c in re.findall(r'usage:(?:.+)?{((?:[a-z]+,*)+?)}', help_output, re.MULTILINE|re.DOTALL)[0].split(','))

        self.assertEqual(md_commands | {'help'}, help_commands, 'Doc file: `{}`'.format(doc_path))

        ## Validate that each section has proper placeholders

        def get_data_pattern(command):
            return re.compile(
                r'^```[\r\n]'
                r'{{ cmd_help\[\'' + command + r'\'\]\[\'usage\'\] }}[\r\n]'
                r'^```[\r\n]'
                r'.*?'
                r'^```[\r\n]'
                r'{{ cmd_help\[\'' + command + r'\'\]\[\'arguments\'\] }}[\r\n]'
                r'^```',
                flags = re.MULTILINE|re.DOTALL)

        for command in md_commands:
            m = get_data_pattern(command).search(md, pos=md_command_sections[command][0], endpos=md_command_sections[command][1])
            self.assertIsNotNone(m, 'Command `{}` is missing placeholders for dynamic data. Doc file: `{}`'.format(command, doc_path))

    def _check_coverage_files(self, types=('text', 'xml', 'html')):
        covdir = Path(self.builddir) / 'meson-logs'
        files = []
        if 'text' in types:
            files.append('coverage.txt')
        if 'xml' in types:
            files.append('coverage.xml')
        if 'html' in types:
            files.append('coveragereport/index.html')
        for f in files:
            self.assertTrue((covdir / f).is_file(), msg='{} is not a file'.format(f))

    def test_coverage(self):
        if mesonbuild.environment.detect_msys2_arch():
            raise unittest.SkipTest('Skipped due to problems with coverage on MSYS2')
        gcovr_exe, gcovr_new_rootdir = mesonbuild.environment.detect_gcovr()
        if not gcovr_exe:
            raise unittest.SkipTest('gcovr not found, or too old')
        testdir = os.path.join(self.common_test_dir, '1 trivial')
        env = get_fake_env(testdir, self.builddir, self.prefix)
        cc = env.detect_c_compiler(MachineChoice.HOST)
        if cc.get_id() == 'clang':
            if not mesonbuild.environment.detect_llvm_cov():
                raise unittest.SkipTest('llvm-cov not found')
        if cc.get_id() == 'msvc':
            raise unittest.SkipTest('Test only applies to non-MSVC compilers')
        self.init(testdir, extra_args=['-Db_coverage=true'])
        self.build()
        self.run_tests()
        self.run_target('coverage')
        self._check_coverage_files()

    def test_coverage_complex(self):
        if mesonbuild.environment.detect_msys2_arch():
            raise unittest.SkipTest('Skipped due to problems with coverage on MSYS2')
        gcovr_exe, gcovr_new_rootdir = mesonbuild.environment.detect_gcovr()
        if not gcovr_exe:
            raise unittest.SkipTest('gcovr not found, or too old')
        testdir = os.path.join(self.common_test_dir, '109 generatorcustom')
        env = get_fake_env(testdir, self.builddir, self.prefix)
        cc = env.detect_c_compiler(MachineChoice.HOST)
        if cc.get_id() == 'clang':
            if not mesonbuild.environment.detect_llvm_cov():
                raise unittest.SkipTest('llvm-cov not found')
        if cc.get_id() == 'msvc':
            raise unittest.SkipTest('Test only applies to non-MSVC compilers')
        self.init(testdir, extra_args=['-Db_coverage=true'])
        self.build()
        self.run_tests()
        self.run_target('coverage')
        self._check_coverage_files()

    def test_coverage_html(self):
        if mesonbuild.environment.detect_msys2_arch():
            raise unittest.SkipTest('Skipped due to problems with coverage on MSYS2')
        gcovr_exe, gcovr_new_rootdir = mesonbuild.environment.detect_gcovr()
        if not gcovr_exe:
            raise unittest.SkipTest('gcovr not found, or too old')
        testdir = os.path.join(self.common_test_dir, '1 trivial')
        env = get_fake_env(testdir, self.builddir, self.prefix)
        cc = env.detect_c_compiler(MachineChoice.HOST)
        if cc.get_id() == 'clang':
            if not mesonbuild.environment.detect_llvm_cov():
                raise unittest.SkipTest('llvm-cov not found')
        if cc.get_id() == 'msvc':
            raise unittest.SkipTest('Test only applies to non-MSVC compilers')
        self.init(testdir, extra_args=['-Db_coverage=true'])
        self.build()
        self.run_tests()
        self.run_target('coverage-html')
        self._check_coverage_files(['html'])

    def test_coverage_text(self):
        if mesonbuild.environment.detect_msys2_arch():
            raise unittest.SkipTest('Skipped due to problems with coverage on MSYS2')
        gcovr_exe, gcovr_new_rootdir = mesonbuild.environment.detect_gcovr()
        if not gcovr_exe:
            raise unittest.SkipTest('gcovr not found, or too old')
        testdir = os.path.join(self.common_test_dir, '1 trivial')
        env = get_fake_env(testdir, self.builddir, self.prefix)
        cc = env.detect_c_compiler(MachineChoice.HOST)
        if cc.get_id() == 'clang':
            if not mesonbuild.environment.detect_llvm_cov():
                raise unittest.SkipTest('llvm-cov not found')
        if cc.get_id() == 'msvc':
            raise unittest.SkipTest('Test only applies to non-MSVC compilers')
        self.init(testdir, extra_args=['-Db_coverage=true'])
        self.build()
        self.run_tests()
        self.run_target('coverage-text')
        self._check_coverage_files(['text'])

    def test_coverage_xml(self):
        if mesonbuild.environment.detect_msys2_arch():
            raise unittest.SkipTest('Skipped due to problems with coverage on MSYS2')
        gcovr_exe, gcovr_new_rootdir = mesonbuild.environment.detect_gcovr()
        if not gcovr_exe:
            raise unittest.SkipTest('gcovr not found, or too old')
        testdir = os.path.join(self.common_test_dir, '1 trivial')
        env = get_fake_env(testdir, self.builddir, self.prefix)
        cc = env.detect_c_compiler(MachineChoice.HOST)
        if cc.get_id() == 'clang':
            if not mesonbuild.environment.detect_llvm_cov():
                raise unittest.SkipTest('llvm-cov not found')
        if cc.get_id() == 'msvc':
            raise unittest.SkipTest('Test only applies to non-MSVC compilers')
        self.init(testdir, extra_args=['-Db_coverage=true'])
        self.build()
        self.run_tests()
        self.run_target('coverage-xml')
        self._check_coverage_files(['xml'])

    def test_cross_file_constants(self):
        with temp_filename() as crossfile1, temp_filename() as crossfile2:
            with open(crossfile1, 'w') as f:
                f.write(textwrap.dedent(
                    '''
                    [constants]
                    compiler = 'gcc'
                    '''))
            with open(crossfile2, 'w') as f:
                f.write(textwrap.dedent(
                    '''
                    [constants]
                    toolchain = '/toolchain/'
                    common_flags = ['--sysroot=' + toolchain / 'sysroot']

                    [properties]
                    c_args = common_flags + ['-DSOMETHING']
                    cpp_args = c_args + ['-DSOMETHING_ELSE']

                    [binaries]
                    c = toolchain / compiler
                    '''))

            values = mesonbuild.coredata.parse_machine_files([crossfile1, crossfile2])
            self.assertEqual(values['binaries']['c'], '/toolchain/gcc')
            self.assertEqual(values['properties']['c_args'],
                             ['--sysroot=/toolchain/sysroot', '-DSOMETHING'])
            self.assertEqual(values['properties']['cpp_args'],
                             ['--sysroot=/toolchain/sysroot', '-DSOMETHING', '-DSOMETHING_ELSE'])

    @unittest.skipIf(is_windows(), 'Directory cleanup fails for some reason')
    def test_wrap_git(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            srcdir = os.path.join(tmpdir, 'src')
            shutil.copytree(os.path.join(self.unit_test_dir, '78 wrap-git'), srcdir)
            upstream = os.path.join(srcdir, 'subprojects', 'wrap_git_upstream')
            upstream_uri = Path(upstream).as_uri()
            _git_init(upstream)
            with open(os.path.join(srcdir, 'subprojects', 'wrap_git.wrap'), 'w') as f:
                f.write(textwrap.dedent('''
                  [wrap-git]
                  url = {}
                  patch_directory = wrap_git_builddef
                  revision = master
                '''.format(upstream_uri)))
            self.init(srcdir)
            self.build()
            self.run_tests()

    def test_multi_output_custom_target_no_warning(self):
        testdir = os.path.join(self.common_test_dir, '235 custom_target source')

        out = self.init(testdir)
        self.assertNotRegex(out, 'WARNING:.*Using the first one.')
        self.build()
        self.run_tests()

class FailureTests(BasePlatformTests):
    '''
    Tests that test failure conditions. Build files here should be dynamically
    generated and static tests should go into `test cases/failing*`.
    This is useful because there can be many ways in which a particular
    function can fail, and creating failing tests for all of them is tedious
    and slows down testing.
    '''
    dnf = "[Dd]ependency.*not found(:.*)?"
    nopkg = '[Pp]kg-config.*not found'

    def setUp(self):
        super().setUp()
        self.srcdir = os.path.realpath(tempfile.mkdtemp())
        self.mbuild = os.path.join(self.srcdir, 'meson.build')
        self.moptions = os.path.join(self.srcdir, 'meson_options.txt')

    def tearDown(self):
        super().tearDown()
        windows_proof_rmtree(self.srcdir)

    def assertMesonRaises(self, contents, match, *,
                          extra_args=None,
                          langs=None,
                          meson_version=None,
                          options=None,
                          override_envvars=None):
        '''
        Assert that running meson configure on the specified @contents raises
        a error message matching regex @match.
        '''
        if langs is None:
            langs = []
        with open(self.mbuild, 'w') as f:
            f.write("project('failure test', 'c', 'cpp'")
            if meson_version:
                f.write(", meson_version: '{}'".format(meson_version))
            f.write(")\n")
            for lang in langs:
                f.write("add_languages('{}', required : false)\n".format(lang))
            f.write(contents)
        if options is not None:
            with open(self.moptions, 'w') as f:
                f.write(options)
        o = {'MESON_FORCE_BACKTRACE': '1'}
        if override_envvars is None:
            override_envvars = o
        else:
            override_envvars.update(o)
        # Force tracebacks so we can detect them properly
        with self.assertRaisesRegex(MesonException, match, msg=contents):
            # Must run in-process or we'll get a generic CalledProcessError
            self.init(self.srcdir, extra_args=extra_args,
                      inprocess=True,
                      override_envvars = override_envvars)

    def obtainMesonOutput(self, contents, match, extra_args, langs, meson_version=None):
        if langs is None:
            langs = []
        with open(self.mbuild, 'w') as f:
            f.write("project('output test', 'c', 'cpp'")
            if meson_version:
                f.write(", meson_version: '{}'".format(meson_version))
            f.write(")\n")
            for lang in langs:
                f.write("add_languages('{}', required : false)\n".format(lang))
            f.write(contents)
        # Run in-process for speed and consistency with assertMesonRaises
        return self.init(self.srcdir, extra_args=extra_args, inprocess=True)

    def assertMesonOutputs(self, contents, match, extra_args=None, langs=None, meson_version=None):
        '''
        Assert that running meson configure on the specified @contents outputs
        something that matches regex @match.
        '''
        out = self.obtainMesonOutput(contents, match, extra_args, langs, meson_version)
        self.assertRegex(out, match)

    def assertMesonDoesNotOutput(self, contents, match, extra_args=None, langs=None, meson_version=None):
        '''
        Assert that running meson configure on the specified @contents does not output
        something that matches regex @match.
        '''
        out = self.obtainMesonOutput(contents, match, extra_args, langs, meson_version)
        self.assertNotRegex(out, match)

    @skipIfNoPkgconfig
    def test_dependency(self):
        if subprocess.call(['pkg-config', '--exists', 'zlib']) != 0:
            raise unittest.SkipTest('zlib not found with pkg-config')
        a = (("dependency('zlib', method : 'fail')", "'fail' is invalid"),
             ("dependency('zlib', static : '1')", "[Ss]tatic.*boolean"),
             ("dependency('zlib', version : 1)", "Item must be a list or one of <class 'str'>"),
             ("dependency('zlib', required : 1)", "[Rr]equired.*boolean"),
             ("dependency('zlib', method : 1)", "[Mm]ethod.*string"),
             ("dependency('zlibfail')", self.dnf),)
        for contents, match in a:
            self.assertMesonRaises(contents, match)

    def test_apple_frameworks_dependency(self):
        if not is_osx():
            raise unittest.SkipTest('only run on macOS')
        self.assertMesonRaises("dependency('appleframeworks')",
                               "requires at least one module")

    def test_extraframework_dependency_method(self):
        code = "dependency('python', method : 'extraframework')"
        if not is_osx():
            self.assertMesonRaises(code, self.dnf)
        else:
            # Python2 framework is always available on macOS
            self.assertMesonOutputs(code, '[Dd]ependency.*python.*found.*YES')

    def test_sdl2_notfound_dependency(self):
        # Want to test failure, so skip if available
        if shutil.which('sdl2-config'):
            raise unittest.SkipTest('sdl2-config found')
        self.assertMesonRaises("dependency('sdl2', method : 'sdlconfig')", self.dnf)
        if shutil.which('pkg-config'):
            self.assertMesonRaises("dependency('sdl2', method : 'pkg-config')", self.dnf)
        with no_pkgconfig():
            # Look for pkg-config, cache it, then
            # Use cached pkg-config without erroring out, then
            # Use cached pkg-config to error out
            code = "dependency('foobarrr', method : 'pkg-config', required : false)\n" \
                "dependency('foobarrr2', method : 'pkg-config', required : false)\n" \
                "dependency('sdl2', method : 'pkg-config')"
            self.assertMesonRaises(code, self.nopkg)

    def test_gnustep_notfound_dependency(self):
        # Want to test failure, so skip if available
        if shutil.which('gnustep-config'):
            raise unittest.SkipTest('gnustep-config found')
        self.assertMesonRaises("dependency('gnustep')",
                               "(requires a Objc compiler|{})".format(self.dnf),
                               langs = ['objc'])

    def test_wx_notfound_dependency(self):
        # Want to test failure, so skip if available
        if shutil.which('wx-config-3.0') or shutil.which('wx-config') or shutil.which('wx-config-gtk3'):
            raise unittest.SkipTest('wx-config, wx-config-3.0 or wx-config-gtk3 found')
        self.assertMesonRaises("dependency('wxwidgets')", self.dnf)
        self.assertMesonOutputs("dependency('wxwidgets', required : false)",
                                "Run-time dependency .*WxWidgets.* found: .*NO.*")

    def test_wx_dependency(self):
        if not shutil.which('wx-config-3.0') and not shutil.which('wx-config') and not shutil.which('wx-config-gtk3'):
            raise unittest.SkipTest('Neither wx-config, wx-config-3.0 nor wx-config-gtk3 found')
        self.assertMesonRaises("dependency('wxwidgets', modules : 1)",
                               "module argument is not a string")

    def test_llvm_dependency(self):
        self.assertMesonRaises("dependency('llvm', modules : 'fail')",
                               "(required.*fail|{})".format(self.dnf))

    def test_boost_notfound_dependency(self):
        # Can be run even if Boost is found or not
        self.assertMesonRaises("dependency('boost', modules : 1)",
                               "module.*not a string")
        self.assertMesonRaises("dependency('boost', modules : 'fail')",
                               "(fail.*not found|{})".format(self.dnf))

    def test_boost_BOOST_ROOT_dependency(self):
        # Test BOOST_ROOT; can be run even if Boost is found or not
        self.assertMesonRaises("dependency('boost')",
                               "(BOOST_ROOT.*absolute|{})".format(self.dnf),
                               override_envvars = {'BOOST_ROOT': 'relative/path'})

    def test_dependency_invalid_method(self):
        code = '''zlib_dep = dependency('zlib', required : false)
        zlib_dep.get_configtool_variable('foo')
        '''
        self.assertMesonRaises(code, ".* is not a config-tool dependency")
        code = '''zlib_dep = dependency('zlib', required : false)
        dep = declare_dependency(dependencies : zlib_dep)
        dep.get_pkgconfig_variable('foo')
        '''
        self.assertMesonRaises(code, "Method.*pkgconfig.*is invalid.*internal")
        code = '''zlib_dep = dependency('zlib', required : false)
        dep = declare_dependency(dependencies : zlib_dep)
        dep.get_configtool_variable('foo')
        '''
        self.assertMesonRaises(code, "Method.*configtool.*is invalid.*internal")

    def test_objc_cpp_detection(self):
        '''
        Test that when we can't detect objc or objcpp, we fail gracefully.
        '''
        env = get_fake_env()
        try:
            env.detect_objc_compiler(MachineChoice.HOST)
            env.detect_objcpp_compiler(MachineChoice.HOST)
        except EnvironmentException:
            code = "add_languages('objc')\nadd_languages('objcpp')"
            self.assertMesonRaises(code, "Unknown compiler")
            return
        raise unittest.SkipTest("objc and objcpp found, can't test detection failure")

    def test_subproject_variables(self):
        '''
        Test that:
        1. The correct message is outputted when a not-required dep is not
           found and the fallback subproject is also not found.
        2. A not-required fallback dependency is not found because the
           subproject failed to parse.
        3. A not-found not-required dep with a fallback subproject outputs the
           correct message when the fallback subproject is found but the
           variable inside it is not.
        4. A fallback dependency is found from the subproject parsed in (3)
        5. The correct message is outputted when the .wrap file is missing for
           a sub-subproject.
        '''
        tdir = os.path.join(self.unit_test_dir, '20 subproj dep variables')
        out = self.init(tdir, inprocess=True)
        self.assertRegex(out, r"Subproject directory not found and .*nosubproj.wrap.* file not found")
        self.assertRegex(out, r'Function does not take positional arguments.')
        self.assertRegex(out, r'WARNING:.* Dependency .*subsubproject.* not found but it is available in a sub-subproject.')
        self.assertRegex(out, r'Subproject directory not found and .*subsubproject.wrap.* file not found')
        self.assertRegex(out, r'Dependency .*zlibproxy.* from subproject .*subprojects.*somesubproj.* found: .*YES.*')

    def test_exception_exit_status(self):
        '''
        Test exit status on python exception
        '''
        tdir = os.path.join(self.unit_test_dir, '21 exit status')
        with self.assertRaises(subprocess.CalledProcessError) as cm:
            self.init(tdir, inprocess=False, override_envvars = {'MESON_UNIT_TEST': '1'})
        self.assertEqual(cm.exception.returncode, 2)
        self.wipe()

    def test_dict_requires_key_value_pairs(self):
        self.assertMesonRaises("dict = {3, 'foo': 'bar'}",
                               'Only key:value pairs are valid in dict construction.')
        self.assertMesonRaises("{'foo': 'bar', 3}",
                               'Only key:value pairs are valid in dict construction.')

    def test_dict_forbids_duplicate_keys(self):
        self.assertMesonRaises("dict = {'a': 41, 'a': 42}",
                               'Duplicate dictionary key: a.*')

    def test_dict_forbids_integer_key(self):
        self.assertMesonRaises("dict = {3: 'foo'}",
                               'Key must be a string.*')

    def test_using_too_recent_feature(self):
        # Here we use a dict, which was introduced in 0.47.0
        self.assertMesonOutputs("dict = {}",
                                ".*WARNING.*Project targeting.*but.*",
                                meson_version='>= 0.46.0')

    def test_using_recent_feature(self):
        # Same as above, except the meson version is now appropriate
        self.assertMesonDoesNotOutput("dict = {}",
                                      ".*WARNING.*Project targeting.*but.*",
                                      meson_version='>= 0.47')

    def test_using_too_recent_feature_dependency(self):
        self.assertMesonOutputs("dependency('pcap', required: false)",
                                ".*WARNING.*Project targeting.*but.*",
                                meson_version='>= 0.41.0')

    def test_vcs_tag_featurenew_build_always_stale(self):
        'https://github.com/mesonbuild/meson/issues/3904'
        vcs_tag = '''version_data = configuration_data()
        version_data.set('PROJVER', '@VCS_TAG@')
        vf = configure_file(output : 'version.h.in', configuration: version_data)
        f = vcs_tag(input : vf, output : 'version.h')
        '''
        msg = '.*WARNING:.*feature.*build_always_stale.*custom_target.*'
        self.assertMesonDoesNotOutput(vcs_tag, msg, meson_version='>=0.43')

    def test_missing_subproject_not_required_and_required(self):
        self.assertMesonRaises("sub1 = subproject('not-found-subproject', required: false)\n" +
                               "sub2 = subproject('not-found-subproject', required: true)",
                               """.*Subproject "subprojects/not-found-subproject" required but not found.*""")

    def test_get_variable_on_not_found_project(self):
        self.assertMesonRaises("sub1 = subproject('not-found-subproject', required: false)\n" +
                               "sub1.get_variable('naaa')",
                               """Subproject "subprojects/not-found-subproject" disabled can't get_variable on it.""")

    def test_version_checked_before_parsing_options(self):
        '''
        https://github.com/mesonbuild/meson/issues/5281
        '''
        options = "option('some-option', type: 'foo', value: '')"
        match = 'Meson version is.*but project requires >=2000'
        self.assertMesonRaises("", match, meson_version='>=2000', options=options)

    def test_assert_default_message(self):
        self.assertMesonRaises("k1 = 'a'\n" +
                               "assert({\n" +
                               "  k1: 1,\n" +
                               "}['a'] == 2)\n",
                               r"Assert failed: {k1 : 1}\['a'\] == 2")

    def test_wrap_nofallback(self):
        self.assertMesonRaises("dependency('notfound', fallback : ['foo', 'foo_dep'])",
                               r"Dependency \'notfound\' not found and fallback is disabled",
                               extra_args=['--wrap-mode=nofallback'])

    def test_message(self):
        self.assertMesonOutputs("message('Array:', ['a', 'b'])",
                                r"Message:.* Array: \['a', 'b'\]")

    def test_warning(self):
        self.assertMesonOutputs("warning('Array:', ['a', 'b'])",
                                r"WARNING:.* Array: \['a', 'b'\]")

    def test_override_dependency_twice(self):
        self.assertMesonRaises("meson.override_dependency('foo', declare_dependency())\n" +
                               "meson.override_dependency('foo', declare_dependency())",
                               """Tried to override dependency 'foo' which has already been resolved or overridden""")

    @unittest.skipIf(is_windows(), 'zlib is not available on Windows')
    def test_override_resolved_dependency(self):
        self.assertMesonRaises("dependency('zlib')\n" +
                               "meson.override_dependency('zlib', declare_dependency())",
                               """Tried to override dependency 'zlib' which has already been resolved or overridden""")

@unittest.skipUnless(is_windows() or is_cygwin(), "requires Windows (or Windows via Cygwin)")
class WindowsTests(BasePlatformTests):
    '''
    Tests that should run on Cygwin, MinGW, and MSVC
    '''

    def setUp(self):
        super().setUp()
        self.platform_test_dir = os.path.join(self.src_root, 'test cases/windows')

    @unittest.skipIf(is_cygwin(), 'Test only applicable to Windows')
    def test_find_program(self):
        '''
        Test that Windows-specific edge-cases in find_program are functioning
        correctly. Cannot be an ordinary test because it involves manipulating
        PATH to point to a directory with Python scripts.
        '''
        testdir = os.path.join(self.platform_test_dir, '8 find program')
        # Find `cmd` and `cmd.exe`
        prog1 = ExternalProgram('cmd')
        self.assertTrue(prog1.found(), msg='cmd not found')
        prog2 = ExternalProgram('cmd.exe')
        self.assertTrue(prog2.found(), msg='cmd.exe not found')
        self.assertPathEqual(prog1.get_path(), prog2.get_path())
        # Find cmd.exe with args without searching
        prog = ExternalProgram('cmd', command=['cmd', '/C'])
        self.assertTrue(prog.found(), msg='cmd not found with args')
        self.assertPathEqual(prog.get_command()[0], 'cmd')
        # Find cmd with an absolute path that's missing the extension
        cmd_path = prog2.get_path()[:-4]
        prog = ExternalProgram(cmd_path)
        self.assertTrue(prog.found(), msg='{!r} not found'.format(cmd_path))
        # Finding a script with no extension inside a directory works
        prog = ExternalProgram(os.path.join(testdir, 'test-script'))
        self.assertTrue(prog.found(), msg='test-script not found')
        # Finding a script with an extension inside a directory works
        prog = ExternalProgram(os.path.join(testdir, 'test-script-ext.py'))
        self.assertTrue(prog.found(), msg='test-script-ext.py not found')
        # Finding a script in PATH
        os.environ['PATH'] += os.pathsep + testdir
        # If `.PY` is in PATHEXT, scripts can be found as programs
        if '.PY' in [ext.upper() for ext in os.environ['PATHEXT'].split(';')]:
            # Finding a script in PATH w/o extension works and adds the interpreter
            prog = ExternalProgram('test-script-ext')
            self.assertTrue(prog.found(), msg='test-script-ext not found in PATH')
            self.assertPathEqual(prog.get_command()[0], python_command[0])
            self.assertPathBasenameEqual(prog.get_path(), 'test-script-ext.py')
        # Finding a script in PATH with extension works and adds the interpreter
        prog = ExternalProgram('test-script-ext.py')
        self.assertTrue(prog.found(), msg='test-script-ext.py not found in PATH')
        self.assertPathEqual(prog.get_command()[0], python_command[0])
        self.assertPathBasenameEqual(prog.get_path(), 'test-script-ext.py')
        # Using a script with an extension directly via command= works and adds the interpreter
        prog = ExternalProgram('test-script-ext.py', command=[os.path.join(testdir, 'test-script-ext.py'), '--help'])
        self.assertTrue(prog.found(), msg='test-script-ext.py with full path not picked up via command=')
        self.assertPathEqual(prog.get_command()[0], python_command[0])
        self.assertPathEqual(prog.get_command()[2], '--help')
        self.assertPathBasenameEqual(prog.get_path(), 'test-script-ext.py')
        # Using a script without an extension directly via command= works and adds the interpreter
        prog = ExternalProgram('test-script', command=[os.path.join(testdir, 'test-script'), '--help'])
        self.assertTrue(prog.found(), msg='test-script with full path not picked up via command=')
        self.assertPathEqual(prog.get_command()[0], python_command[0])
        self.assertPathEqual(prog.get_command()[2], '--help')
        self.assertPathBasenameEqual(prog.get_path(), 'test-script')
        # Ensure that WindowsApps gets removed from PATH
        path = os.environ['PATH']
        if 'WindowsApps' not in path:
            username = os.environ['USERNAME']
            appstore_dir = r'C:\Users\{}\AppData\Local\Microsoft\WindowsApps'.format(username)
            path = os.pathsep + appstore_dir
        path = ExternalProgram._windows_sanitize_path(path)
        self.assertNotIn('WindowsApps', path)

    def test_ignore_libs(self):
        '''
        Test that find_library on libs that are to be ignored returns an empty
        array of arguments. Must be a unit test because we cannot inspect
        ExternalLibraryHolder from build files.
        '''
        testdir = os.path.join(self.platform_test_dir, '1 basic')
        env = get_fake_env(testdir, self.builddir, self.prefix)
        cc = env.detect_c_compiler(MachineChoice.HOST)
        if cc.get_argument_syntax() != 'msvc':
            raise unittest.SkipTest('Not using MSVC')
        # To force people to update this test, and also test
        self.assertEqual(set(cc.ignore_libs), {'c', 'm', 'pthread', 'dl', 'rt', 'execinfo'})
        for l in cc.ignore_libs:
            self.assertEqual(cc.find_library(l, env, []), [])

    def test_rc_depends_files(self):
        testdir = os.path.join(self.platform_test_dir, '5 resources')

        # resource compiler depfile generation is not yet implemented for msvc
        env = get_fake_env(testdir, self.builddir, self.prefix)
        depfile_works = env.detect_c_compiler(MachineChoice.HOST).get_id() not in {'msvc', 'clang-cl', 'intel-cl'}

        self.init(testdir)
        self.build()
        # Immediately rebuilding should not do anything
        self.assertBuildIsNoop()
        # Test compile_resources(depend_file:)
        # Changing mtime of sample.ico should rebuild prog
        self.utime(os.path.join(testdir, 'res', 'sample.ico'))
        self.assertRebuiltTarget('prog')
        # Test depfile generation by compile_resources
        # Changing mtime of resource.h should rebuild myres.rc and then prog
        if depfile_works:
            self.utime(os.path.join(testdir, 'inc', 'resource', 'resource.h'))
            self.assertRebuiltTarget('prog')
        self.wipe()

        if depfile_works:
            testdir = os.path.join(self.platform_test_dir, '12 resources with custom targets')
            self.init(testdir)
            self.build()
            # Immediately rebuilding should not do anything
            self.assertBuildIsNoop()
            # Changing mtime of resource.h should rebuild myres_1.rc and then prog_1
            self.utime(os.path.join(testdir, 'res', 'resource.h'))
            self.assertRebuiltTarget('prog_1')

    def test_msvc_cpp17(self):
        testdir = os.path.join(self.unit_test_dir, '45 vscpp17')

        env = get_fake_env(testdir, self.builddir, self.prefix)
        cc = env.detect_c_compiler(MachineChoice.HOST)
        if cc.get_argument_syntax() != 'msvc':
            raise unittest.SkipTest('Test only applies to MSVC-like compilers')

        try:
            self.init(testdir)
        except subprocess.CalledProcessError:
            # According to Python docs, output is only stored when
            # using check_output. We don't use it, so we can't check
            # that the output is correct (i.e. that it failed due
            # to the right reason).
            return
        self.build()

    def test_install_pdb_introspection(self):
        testdir = os.path.join(self.platform_test_dir, '1 basic')

        env = get_fake_env(testdir, self.builddir, self.prefix)
        cc = env.detect_c_compiler(MachineChoice.HOST)
        if cc.get_argument_syntax() != 'msvc':
            raise unittest.SkipTest('Test only applies to MSVC-like compilers')

        self.init(testdir)
        installed = self.introspect('--installed')
        files = [os.path.basename(path) for path in installed.values()]

        self.assertTrue('prog.pdb' in files)

    def _check_ld(self, name: str, lang: str, expected: str) -> None:
        if not shutil.which(name):
            raise unittest.SkipTest('Could not find {}.'.format(name))
        envvars = [mesonbuild.envconfig.BinaryTable.evarMap['{}_ld'.format(lang)]]

        # Also test a deprecated variable if there is one.
        if envvars[0] in mesonbuild.envconfig.BinaryTable.DEPRECATION_MAP:
            envvars.append(
                mesonbuild.envconfig.BinaryTable.DEPRECATION_MAP[envvars[0]])

        for envvar in envvars:
            with mock.patch.dict(os.environ, {envvar: name}):
                env = get_fake_env()
                try:
                    comp = getattr(env, 'detect_{}_compiler'.format(lang))(MachineChoice.HOST)
                except EnvironmentException:
                    raise unittest.SkipTest('Could not find a compiler for {}'.format(lang))
                self.assertEqual(comp.linker.id, expected)

    def test_link_environment_variable_lld_link(self):
        env = get_fake_env()
        comp = getattr(env, 'detect_c_compiler')(MachineChoice.HOST)
        if isinstance(comp, mesonbuild.compilers.GnuLikeCompiler):
            raise unittest.SkipTest('GCC cannot be used with link compatible linkers.')
        self._check_ld('lld-link', 'c', 'lld-link')

    def test_link_environment_variable_link(self):
        env = get_fake_env()
        comp = getattr(env, 'detect_c_compiler')(MachineChoice.HOST)
        if isinstance(comp, mesonbuild.compilers.GnuLikeCompiler):
            raise unittest.SkipTest('GCC cannot be used with link compatible linkers.')
        self._check_ld('link', 'c', 'link')

    def test_link_environment_variable_optlink(self):
        env = get_fake_env()
        comp = getattr(env, 'detect_c_compiler')(MachineChoice.HOST)
        if isinstance(comp, mesonbuild.compilers.GnuLikeCompiler):
            raise unittest.SkipTest('GCC cannot be used with link compatible linkers.')
        self._check_ld('optlink', 'c', 'optlink')

    @skip_if_not_language('rust')
    def test_link_environment_variable_rust(self):
        self._check_ld('link', 'rust', 'link')

    @skip_if_not_language('d')
    def test_link_environment_variable_d(self):
        env = get_fake_env()
        comp = getattr(env, 'detect_d_compiler')(MachineChoice.HOST)
        if comp.id == 'dmd':
            raise unittest.SkipTest('meson cannot reliably make DMD use a different linker.')
        self._check_ld('lld-link', 'd', 'lld-link')

    def test_pefile_checksum(self):
        try:
            import pefile
        except ImportError:
            if is_ci():
                raise
            raise unittest.SkipTest('pefile module not found')
        testdir = os.path.join(self.common_test_dir, '6 linkshared')
        self.init(testdir, extra_args=['--buildtype=release'])
        self.build()
        # Test that binaries have a non-zero checksum
        env = get_fake_env()
        cc = env.detect_c_compiler(MachineChoice.HOST)
        cc_id = cc.get_id()
        ld_id = cc.get_linker_id()
        dll = glob(os.path.join(self.builddir, '*mycpplib.dll'))[0]
        exe = os.path.join(self.builddir, 'cppprog.exe')
        for f in (dll, exe):
            pe = pefile.PE(f)
            msg = 'PE file: {!r}, compiler: {!r}, linker: {!r}'.format(f, cc_id, ld_id)
            if cc_id == 'clang-cl':
                # Latest clang-cl tested (7.0) does not write checksums out
                self.assertFalse(pe.verify_checksum(), msg=msg)
            else:
                # Verify that a valid checksum was written by all other compilers
                self.assertTrue(pe.verify_checksum(), msg=msg)

    def test_qt5dependency_vscrt(self):
        '''
        Test that qt5 dependencies use the debug module suffix when b_vscrt is
        set to 'mdd'
        '''
        # Verify that the `b_vscrt` option is available
        env = get_fake_env()
        cc = env.detect_c_compiler(MachineChoice.HOST)
        if 'b_vscrt' not in cc.base_options:
            raise unittest.SkipTest('Compiler does not support setting the VS CRT')
        # Verify that qmake is for Qt5
        if not shutil.which('qmake-qt5'):
            if not shutil.which('qmake') and not is_ci():
                raise unittest.SkipTest('QMake not found')
            output = subprocess.getoutput('qmake --version')
            if 'Qt version 5' not in output and not is_ci():
                raise unittest.SkipTest('Qmake found, but it is not for Qt 5.')
        # Setup with /MDd
        testdir = os.path.join(self.framework_test_dir, '4 qt')
        self.init(testdir, extra_args=['-Db_vscrt=mdd'])
        # Verify that we're linking to the debug versions of Qt DLLs
        build_ninja = os.path.join(self.builddir, 'build.ninja')
        with open(build_ninja, 'r', encoding='utf-8') as f:
            contents = f.read()
            m = re.search('build qt5core.exe: cpp_LINKER.*Qt5Cored.lib', contents)
        self.assertIsNotNone(m, msg=contents)

    def test_compiler_checks_vscrt(self):
        '''
        Test that the correct VS CRT is used when running compiler checks
        '''
        # Verify that the `b_vscrt` option is available
        env = get_fake_env()
        cc = env.detect_c_compiler(MachineChoice.HOST)
        if 'b_vscrt' not in cc.base_options:
            raise unittest.SkipTest('Compiler does not support setting the VS CRT')

        def sanitycheck_vscrt(vscrt):
            checks = self.get_meson_log_sanitychecks()
            self.assertTrue(len(checks) > 0)
            for check in checks:
                self.assertIn(vscrt, check)

        testdir = os.path.join(self.common_test_dir, '1 trivial')
        self.init(testdir)
        sanitycheck_vscrt('/MDd')

        self.new_builddir()
        self.init(testdir, extra_args=['-Dbuildtype=debugoptimized'])
        sanitycheck_vscrt('/MD')

        self.new_builddir()
        self.init(testdir, extra_args=['-Dbuildtype=release'])
        sanitycheck_vscrt('/MD')

        self.new_builddir()
        self.init(testdir, extra_args=['-Db_vscrt=md'])
        sanitycheck_vscrt('/MD')

        self.new_builddir()
        self.init(testdir, extra_args=['-Db_vscrt=mdd'])
        sanitycheck_vscrt('/MDd')

        self.new_builddir()
        self.init(testdir, extra_args=['-Db_vscrt=mt'])
        sanitycheck_vscrt('/MT')

        self.new_builddir()
        self.init(testdir, extra_args=['-Db_vscrt=mtd'])
        sanitycheck_vscrt('/MTd')


@unittest.skipUnless(is_osx(), "requires Darwin")
class DarwinTests(BasePlatformTests):
    '''
    Tests that should run on macOS
    '''

    def setUp(self):
        super().setUp()
        self.platform_test_dir = os.path.join(self.src_root, 'test cases/osx')

    def test_apple_bitcode(self):
        '''
        Test that -fembed-bitcode is correctly added while compiling and
        -bitcode_bundle is added while linking when b_bitcode is true and not
        when it is false.  This can't be an ordinary test case because we need
        to inspect the compiler database.
        '''
        testdir = os.path.join(self.platform_test_dir, '7 bitcode')
        env = get_fake_env(testdir, self.builddir, self.prefix)
        cc = env.detect_c_compiler(MachineChoice.HOST)
        if cc.id != 'clang':
            raise unittest.SkipTest('Not using Clang on OSX')
        # Try with bitcode enabled
        out = self.init(testdir, extra_args='-Db_bitcode=true')
        # Warning was printed
        self.assertRegex(out, 'WARNING:.*b_bitcode')
        # Compiler options were added
        for compdb in self.get_compdb():
            if 'module' in compdb['file']:
                self.assertNotIn('-fembed-bitcode', compdb['command'])
            else:
                self.assertIn('-fembed-bitcode', compdb['command'])
        build_ninja = os.path.join(self.builddir, 'build.ninja')
        # Linker options were added
        with open(build_ninja, 'r', encoding='utf-8') as f:
            contents = f.read()
            m = re.search('LINK_ARGS =.*-bitcode_bundle', contents)
        self.assertIsNotNone(m, msg=contents)
        # Try with bitcode disabled
        self.setconf('-Db_bitcode=false')
        # Regenerate build
        self.build()
        for compdb in self.get_compdb():
            self.assertNotIn('-fembed-bitcode', compdb['command'])
        build_ninja = os.path.join(self.builddir, 'build.ninja')
        with open(build_ninja, 'r', encoding='utf-8') as f:
            contents = f.read()
            m = re.search('LINK_ARGS =.*-bitcode_bundle', contents)
        self.assertIsNone(m, msg=contents)

    def test_apple_bitcode_modules(self):
        '''
        Same as above, just for shared_module()
        '''
        testdir = os.path.join(self.common_test_dir, '152 shared module resolving symbol in executable')
        # Ensure that it builds even with bitcode enabled
        self.init(testdir, extra_args='-Db_bitcode=true')
        self.build()
        self.run_tests()

    def _get_darwin_versions(self, fname):
        fname = os.path.join(self.builddir, fname)
        out = subprocess.check_output(['otool', '-L', fname], universal_newlines=True)
        m = re.match(r'.*version (.*), current version (.*)\)', out.split('\n')[1])
        self.assertIsNotNone(m, msg=out)
        return m.groups()

    @skipIfNoPkgconfig
    def test_library_versioning(self):
        '''
        Ensure that compatibility_version and current_version are set correctly
        '''
        testdir = os.path.join(self.platform_test_dir, '2 library versions')
        self.init(testdir)
        self.build()
        targets = {}
        for t in self.introspect('--targets'):
            targets[t['name']] = t['filename'][0] if isinstance(t['filename'], list) else t['filename']
        self.assertEqual(self._get_darwin_versions(targets['some']), ('7.0.0', '7.0.0'))
        self.assertEqual(self._get_darwin_versions(targets['noversion']), ('0.0.0', '0.0.0'))
        self.assertEqual(self._get_darwin_versions(targets['onlyversion']), ('1.0.0', '1.0.0'))
        self.assertEqual(self._get_darwin_versions(targets['onlysoversion']), ('5.0.0', '5.0.0'))
        self.assertEqual(self._get_darwin_versions(targets['intver']), ('2.0.0', '2.0.0'))
        self.assertEqual(self._get_darwin_versions(targets['stringver']), ('2.3.0', '2.3.0'))
        self.assertEqual(self._get_darwin_versions(targets['stringlistver']), ('2.4.0', '2.4.0'))
        self.assertEqual(self._get_darwin_versions(targets['intstringver']), ('1111.0.0', '2.5.0'))
        self.assertEqual(self._get_darwin_versions(targets['stringlistvers']), ('2.6.0', '2.6.1'))

    def test_duplicate_rpath(self):
        testdir = os.path.join(self.unit_test_dir, '10 build_rpath')
        # We purposely pass a duplicate rpath to Meson, in order
        # to ascertain that Meson does not call install_name_tool
        # with duplicate -delete_rpath arguments, which would
        # lead to erroring out on installation
        env = {"LDFLAGS": "-Wl,-rpath,/foo/bar"}
        self.init(testdir, override_envvars=env)
        self.build()
        self.install()

    def test_removing_unused_linker_args(self):
        testdir = os.path.join(self.common_test_dir, '108 has arg')
        env = {'CFLAGS': '-L/tmp -L /var/tmp -headerpad_max_install_names -Wl,-export_dynamic -framework Foundation'}
        self.init(testdir, override_envvars=env)


@unittest.skipUnless(not is_windows(), "requires something Unix-like")
class LinuxlikeTests(BasePlatformTests):
    '''
    Tests that should run on Linux, macOS, and *BSD
    '''

    def test_basic_soname(self):
        '''
        Test that the soname is set correctly for shared libraries. This can't
        be an ordinary test case because we need to run `readelf` and actually
        check the soname.
        https://github.com/mesonbuild/meson/issues/785
        '''
        testdir = os.path.join(self.common_test_dir, '4 shared')
        self.init(testdir)
        self.build()
        lib1 = os.path.join(self.builddir, 'libmylib.so')
        soname = get_soname(lib1)
        self.assertEqual(soname, 'libmylib.so')

    def test_custom_soname(self):
        '''
        Test that the soname is set correctly for shared libraries when
        a custom prefix and/or suffix is used. This can't be an ordinary test
        case because we need to run `readelf` and actually check the soname.
        https://github.com/mesonbuild/meson/issues/785
        '''
        testdir = os.path.join(self.common_test_dir, '25 library versions')
        self.init(testdir)
        self.build()
        lib1 = os.path.join(self.builddir, 'prefixsomelib.suffix')
        soname = get_soname(lib1)
        self.assertEqual(soname, 'prefixsomelib.suffix')

    def test_pic(self):
        '''
        Test that -fPIC is correctly added to static libraries when b_staticpic
        is true and not when it is false. This can't be an ordinary test case
        because we need to inspect the compiler database.
        '''
        if is_windows() or is_cygwin() or is_osx():
            raise unittest.SkipTest('PIC not relevant')

        testdir = os.path.join(self.common_test_dir, '3 static')
        self.init(testdir)
        compdb = self.get_compdb()
        self.assertIn('-fPIC', compdb[0]['command'])
        self.setconf('-Db_staticpic=false')
        # Regenerate build
        self.build()
        compdb = self.get_compdb()
        self.assertNotIn('-fPIC', compdb[0]['command'])

    def test_pkgconfig_gen(self):
        '''
        Test that generated pkg-config files can be found and have the correct
        version and link args. This can't be an ordinary test case because we
        need to run pkg-config outside of a Meson build file.
        https://github.com/mesonbuild/meson/issues/889
        '''
        testdir = os.path.join(self.common_test_dir, '47 pkgconfig-gen')
        self.init(testdir)
        env = get_fake_env(testdir, self.builddir, self.prefix)
        kwargs = {'required': True, 'silent': True}
        os.environ['PKG_CONFIG_LIBDIR'] = self.privatedir
        foo_dep = PkgConfigDependency('libfoo', env, kwargs)
        self.assertTrue(foo_dep.found())
        self.assertEqual(foo_dep.get_version(), '1.0')
        self.assertIn('-lfoo', foo_dep.get_link_args())
        self.assertEqual(foo_dep.get_pkgconfig_variable('foo', {}), 'bar')
        self.assertPathEqual(foo_dep.get_pkgconfig_variable('datadir', {}), '/usr/data')

        libhello_nolib = PkgConfigDependency('libhello_nolib', env, kwargs)
        self.assertTrue(libhello_nolib.found())
        self.assertEqual(libhello_nolib.get_link_args(), [])
        self.assertEqual(libhello_nolib.get_compile_args(), [])

    def test_pkgconfig_gen_deps(self):
        '''
        Test that generated pkg-config files correctly handle dependencies
        '''
        testdir = os.path.join(self.common_test_dir, '47 pkgconfig-gen')
        self.init(testdir)
        privatedir1 = self.privatedir

        self.new_builddir()
        testdir = os.path.join(self.common_test_dir, '47 pkgconfig-gen', 'dependencies')
        self.init(testdir, override_envvars={'PKG_CONFIG_LIBDIR': privatedir1})
        privatedir2 = self.privatedir

        os.environ
        env = {
            'PKG_CONFIG_LIBDIR': os.pathsep.join([privatedir1, privatedir2]),
            'PKG_CONFIG_SYSTEM_LIBRARY_PATH': '/usr/lib',
        }
        self._run(['pkg-config', 'dependency-test', '--validate'], override_envvars=env)

        # pkg-config strips some duplicated flags so we have to parse the
        # generated file ourself.
        expected = {
            'Requires': 'libexposed',
            'Requires.private': 'libfoo >= 1.0',
            'Libs': '-L${libdir} -llibmain -pthread -lcustom',
            'Libs.private': '-lcustom2 -L${libdir} -llibinternal',
            'Cflags': '-I${includedir} -pthread -DCUSTOM',
        }
        if is_osx() or is_haiku():
            expected['Cflags'] = expected['Cflags'].replace('-pthread ', '')
        with open(os.path.join(privatedir2, 'dependency-test.pc')) as f:
            matched_lines = 0
            for line in f:
                parts = line.split(':', 1)
                if parts[0] in expected:
                    key = parts[0]
                    val = parts[1].strip()
                    expected_val = expected[key]
                    self.assertEqual(expected_val, val)
                    matched_lines += 1
            self.assertEqual(len(expected), matched_lines)

        cmd = ['pkg-config', 'requires-test']
        out = self._run(cmd + ['--print-requires'], override_envvars=env).strip().split('\n')
        if not is_openbsd():
            self.assertEqual(sorted(out), sorted(['libexposed', 'libfoo >= 1.0', 'libhello']))
        else:
            self.assertEqual(sorted(out), sorted(['libexposed', 'libfoo>=1.0', 'libhello']))

        cmd = ['pkg-config', 'requires-private-test']
        out = self._run(cmd + ['--print-requires-private'], override_envvars=env).strip().split('\n')
        if not is_openbsd():
            self.assertEqual(sorted(out), sorted(['libexposed', 'libfoo >= 1.0', 'libhello']))
        else:
            self.assertEqual(sorted(out), sorted(['libexposed', 'libfoo>=1.0', 'libhello']))

        cmd = ['pkg-config', 'pub-lib-order']
        out = self._run(cmd + ['--libs'], override_envvars=env).strip().split()
        self.assertEqual(out, ['-llibmain2', '-llibinternal'])

    def test_pkgconfig_uninstalled(self):
        testdir = os.path.join(self.common_test_dir, '47 pkgconfig-gen')
        self.init(testdir)
        self.build()

        os.environ['PKG_CONFIG_LIBDIR'] = os.path.join(self.builddir, 'meson-uninstalled')
        if is_cygwin():
            os.environ['PATH'] += os.pathsep + self.builddir

        self.new_builddir()
        testdir = os.path.join(self.common_test_dir, '47 pkgconfig-gen', 'dependencies')
        self.init(testdir)
        self.build()
        self.run_tests()

    def test_pkg_unfound(self):
        testdir = os.path.join(self.unit_test_dir, '23 unfound pkgconfig')
        self.init(testdir)
        with open(os.path.join(self.privatedir, 'somename.pc')) as f:
            pcfile = f.read()
        self.assertFalse('blub_blob_blib' in pcfile)

    def test_vala_c_warnings(self):
        '''
        Test that no warnings are emitted for C code generated by Vala. This
        can't be an ordinary test case because we need to inspect the compiler
        database.
        https://github.com/mesonbuild/meson/issues/864
        '''
        if not shutil.which('valac'):
            raise unittest.SkipTest('valac not installed.')
        testdir = os.path.join(self.vala_test_dir, '5 target glib')
        self.init(testdir)
        compdb = self.get_compdb()
        vala_command = None
        c_command = None
        for each in compdb:
            if each['file'].endswith('GLib.Thread.c'):
                vala_command = each['command']
            elif each['file'].endswith('GLib.Thread.vala'):
                continue
            elif each['file'].endswith('retcode.c'):
                c_command = each['command']
            else:
                m = 'Unknown file {!r} in vala_c_warnings test'.format(each['file'])
                raise AssertionError(m)
        self.assertIsNotNone(vala_command)
        self.assertIsNotNone(c_command)
        # -w suppresses all warnings, should be there in Vala but not in C
        self.assertIn(" -w ", vala_command)
        self.assertNotIn(" -w ", c_command)
        # -Wall enables all warnings, should be there in C but not in Vala
        self.assertNotIn(" -Wall ", vala_command)
        self.assertIn(" -Wall ", c_command)
        # -Werror converts warnings to errors, should always be there since it's
        # injected by an unrelated piece of code and the project has werror=true
        self.assertIn(" -Werror ", vala_command)
        self.assertIn(" -Werror ", c_command)

    @skipIfNoPkgconfig
    def test_qtdependency_pkgconfig_detection(self):
        '''
        Test that qt4 and qt5 detection with pkgconfig works.
        '''
        # Verify Qt4 or Qt5 can be found with pkg-config
        qt4 = subprocess.call(['pkg-config', '--exists', 'QtCore'])
        qt5 = subprocess.call(['pkg-config', '--exists', 'Qt5Core'])
        testdir = os.path.join(self.framework_test_dir, '4 qt')
        self.init(testdir, extra_args=['-Dmethod=pkg-config'])
        # Confirm that the dependency was found with pkg-config
        mesonlog = self.get_meson_log()
        if qt4 == 0:
            self.assertRegex('\n'.join(mesonlog),
                             r'Run-time dependency qt4 \(modules: Core\) found: YES 4.* \(pkg-config\)\n')
        if qt5 == 0:
            self.assertRegex('\n'.join(mesonlog),
                             r'Run-time dependency qt5 \(modules: Core\) found: YES 5.* \(pkg-config\)\n')

    @skip_if_not_base_option('b_sanitize')
    def test_generate_gir_with_address_sanitizer(self):
        if is_cygwin():
            raise unittest.SkipTest('asan not available on Cygwin')
        if is_openbsd():
            raise unittest.SkipTest('-fsanitize=address is not supported on OpenBSD')

        testdir = os.path.join(self.framework_test_dir, '7 gnome')
        self.init(testdir, extra_args=['-Db_sanitize=address', '-Db_lundef=false'])
        self.build()

    def test_qt5dependency_qmake_detection(self):
        '''
        Test that qt5 detection with qmake works. This can't be an ordinary
        test case because it involves setting the environment.
        '''
        # Verify that qmake is for Qt5
        if not shutil.which('qmake-qt5'):
            if not shutil.which('qmake'):
                raise unittest.SkipTest('QMake not found')
            output = subprocess.getoutput('qmake --version')
            if 'Qt version 5' not in output:
                raise unittest.SkipTest('Qmake found, but it is not for Qt 5.')
        # Disable pkg-config codepath and force searching with qmake/qmake-qt5
        testdir = os.path.join(self.framework_test_dir, '4 qt')
        self.init(testdir, extra_args=['-Dmethod=qmake'])
        # Confirm that the dependency was found with qmake
        mesonlog = self.get_meson_log()
        self.assertRegex('\n'.join(mesonlog),
                         r'Run-time dependency qt5 \(modules: Core\) found: YES .* \((qmake|qmake-qt5)\)\n')

    def glob_sofiles_without_privdir(self, g):
        files = glob(g)
        return [f for f in files if not f.endswith('.p')]

    def _test_soname_impl(self, libpath, install):
        if is_cygwin() or is_osx():
            raise unittest.SkipTest('Test only applicable to ELF and linuxlike sonames')

        testdir = os.path.join(self.unit_test_dir, '1 soname')
        self.init(testdir)
        self.build()
        if install:
            self.install()

        # File without aliases set.
        nover = os.path.join(libpath, 'libnover.so')
        self.assertPathExists(nover)
        self.assertFalse(os.path.islink(nover))
        self.assertEqual(get_soname(nover), 'libnover.so')
        self.assertEqual(len(self.glob_sofiles_without_privdir(nover[:-3] + '*')), 1)

        # File with version set
        verset = os.path.join(libpath, 'libverset.so')
        self.assertPathExists(verset + '.4.5.6')
        self.assertEqual(os.readlink(verset), 'libverset.so.4')
        self.assertEqual(get_soname(verset), 'libverset.so.4')
        self.assertEqual(len(self.glob_sofiles_without_privdir(verset[:-3] + '*')), 3)

        # File with soversion set
        soverset = os.path.join(libpath, 'libsoverset.so')
        self.assertPathExists(soverset + '.1.2.3')
        self.assertEqual(os.readlink(soverset), 'libsoverset.so.1.2.3')
        self.assertEqual(get_soname(soverset), 'libsoverset.so.1.2.3')
        self.assertEqual(len(self.glob_sofiles_without_privdir(soverset[:-3] + '*')), 2)

        # File with version and soversion set to same values
        settosame = os.path.join(libpath, 'libsettosame.so')
        self.assertPathExists(settosame + '.7.8.9')
        self.assertEqual(os.readlink(settosame), 'libsettosame.so.7.8.9')
        self.assertEqual(get_soname(settosame), 'libsettosame.so.7.8.9')
        self.assertEqual(len(self.glob_sofiles_without_privdir(settosame[:-3] + '*')), 2)

        # File with version and soversion set to different values
        bothset = os.path.join(libpath, 'libbothset.so')
        self.assertPathExists(bothset + '.1.2.3')
        self.assertEqual(os.readlink(bothset), 'libbothset.so.1.2.3')
        self.assertEqual(os.readlink(bothset + '.1.2.3'), 'libbothset.so.4.5.6')
        self.assertEqual(get_soname(bothset), 'libbothset.so.1.2.3')
        self.assertEqual(len(self.glob_sofiles_without_privdir(bothset[:-3] + '*')), 3)

    def test_soname(self):
        self._test_soname_impl(self.builddir, False)

    def test_installed_soname(self):
        libdir = self.installdir + os.path.join(self.prefix, self.libdir)
        self._test_soname_impl(libdir, True)

    def test_compiler_check_flags_order(self):
        '''
        Test that compiler check flags override all other flags. This can't be
        an ordinary test case because it needs the environment to be set.
        '''
        testdir = os.path.join(self.common_test_dir, '39 has function')
        env = get_fake_env(testdir, self.builddir, self.prefix)
        cpp = env.detect_cpp_compiler(MachineChoice.HOST)
        Oflag = '-O3'
        OflagCPP = Oflag
        if cpp.get_id() in ('clang', 'gcc'):
            # prevent developers from adding "int main(int argc, char **argv)"
            # to small Meson checks unless these parameters are actually used
            OflagCPP += ' -Werror=unused-parameter'
        env = {'CFLAGS': Oflag,
               'CXXFLAGS': OflagCPP}
        self.init(testdir, override_envvars=env)
        cmds = self.get_meson_log_compiler_checks()
        for cmd in cmds:
            if cmd[0] == 'ccache':
                cmd = cmd[1:]
            # Verify that -I flags from the `args` kwarg are first
            # This is set in the '39 has function' test case
            self.assertEqual(cmd[1], '-I/tmp')
            # Verify that -O3 set via the environment is overridden by -O0
            Oargs = [arg for arg in cmd if arg.startswith('-O')]
            self.assertEqual(Oargs, [Oflag, '-O0'])

    def _test_stds_impl(self, testdir, compiler, p: str):
        has_cpp17 = (compiler.get_id() not in {'clang', 'gcc'} or
                     compiler.get_id() == 'clang' and _clang_at_least(compiler, '>=5.0.0', '>=9.1') or
                     compiler.get_id() == 'gcc' and version_compare(compiler.version, '>=5.0.0'))
        has_cpp2a_c17 = (compiler.get_id() not in {'clang', 'gcc'} or
                         compiler.get_id() == 'clang' and _clang_at_least(compiler, '>=6.0.0', '>=10.0') or
                         compiler.get_id() == 'gcc' and version_compare(compiler.version, '>=8.0.0'))
        has_c18 = (compiler.get_id() not in {'clang', 'gcc'} or
                   compiler.get_id() == 'clang' and _clang_at_least(compiler, '>=8.0.0', '>=11.0') or
                   compiler.get_id() == 'gcc' and version_compare(compiler.version, '>=8.0.0'))
        # Check that all the listed -std=xxx options for this compiler work just fine when used
        # https://en.wikipedia.org/wiki/Xcode#Latest_versions
        # https://www.gnu.org/software/gcc/projects/cxx-status.html
        for v in compiler.get_options()['std'].choices:
            lang_std = p + '_std'
            # we do it like this to handle gnu++17,c++17 and gnu17,c17 cleanly
            # thus, C++ first
            if '++17' in v and not has_cpp17:
                continue
            elif '++2a' in v and not has_cpp2a_c17:  # https://en.cppreference.com/w/cpp/compiler_support
                continue
            # now C
            elif '17' in v and not has_cpp2a_c17:
                continue
            elif '18' in v and not has_c18:
                continue
            std_opt = '{}={}'.format(lang_std, v)
            self.init(testdir, extra_args=['-D' + std_opt])
            cmd = self.get_compdb()[0]['command']
            # c++03 and gnu++03 are not understood by ICC, don't try to look for them
            skiplist = frozenset([
                ('intel', 'c++03'),
                ('intel', 'gnu++03')])
            if v != 'none' and not (compiler.get_id(), v) in skiplist:
                cmd_std = " -std={} ".format(v)
                self.assertIn(cmd_std, cmd)
            try:
                self.build()
            except Exception:
                print('{} was {!r}'.format(lang_std, v))
                raise
            self.wipe()
        # Check that an invalid std option in CFLAGS/CPPFLAGS fails
        # Needed because by default ICC ignores invalid options
        cmd_std = '-std=FAIL'
        if p == 'c':
            env_flag_name = 'CFLAGS'
        elif p == 'cpp':
            env_flag_name = 'CXXFLAGS'
        else:
            raise NotImplementedError('Language {} not defined.'.format(p))
        env = {}
        env[env_flag_name] = cmd_std
        with self.assertRaises((subprocess.CalledProcessError, mesonbuild.mesonlib.EnvironmentException),
                               msg='C compiler should have failed with -std=FAIL'):
            self.init(testdir, override_envvars = env)
            # ICC won't fail in the above because additional flags are needed to
            # make unknown -std=... options errors.
            self.build()

    def test_compiler_c_stds(self):
        '''
        Test that C stds specified for this compiler can all be used. Can't be
        an ordinary test because it requires passing options to meson.
        '''
        testdir = os.path.join(self.common_test_dir, '1 trivial')
        env = get_fake_env(testdir, self.builddir, self.prefix)
        cc = env.detect_c_compiler(MachineChoice.HOST)
        self._test_stds_impl(testdir, cc, 'c')

    def test_compiler_cpp_stds(self):
        '''
        Test that C++ stds specified for this compiler can all be used. Can't
        be an ordinary test because it requires passing options to meson.
        '''
        testdir = os.path.join(self.common_test_dir, '2 cpp')
        env = get_fake_env(testdir, self.builddir, self.prefix)
        cpp = env.detect_cpp_compiler(MachineChoice.HOST)
        self._test_stds_impl(testdir, cpp, 'cpp')

    def test_unity_subproj(self):
        testdir = os.path.join(self.common_test_dir, '45 subproject')
        self.init(testdir, extra_args='--unity=subprojects')
        pdirs = glob(os.path.join(self.builddir, 'subprojects/sublib/simpletest*.p'))
        self.assertEqual(len(pdirs), 1)
        self.assertPathExists(os.path.join(pdirs[0], 'simpletest-unity0.c'))
        sdirs = glob(os.path.join(self.builddir, 'subprojects/sublib/*sublib*.p'))
        self.assertEqual(len(sdirs), 1)
        self.assertPathExists(os.path.join(sdirs[0], 'sublib-unity0.c'))
        self.assertPathDoesNotExist(os.path.join(self.builddir, 'user@exe/user-unity.c'))
        self.build()

    def test_installed_modes(self):
        '''
        Test that files installed by these tests have the correct permissions.
        Can't be an ordinary test because our installed_files.txt is very basic.
        '''
        # Test file modes
        testdir = os.path.join(self.common_test_dir, '12 data')
        self.init(testdir)
        self.install()

        f = os.path.join(self.installdir, 'etc', 'etcfile.dat')
        found_mode = stat.filemode(os.stat(f).st_mode)
        want_mode = 'rw------T'
        self.assertEqual(want_mode, found_mode[1:])

        f = os.path.join(self.installdir, 'usr', 'bin', 'runscript.sh')
        statf = os.stat(f)
        found_mode = stat.filemode(statf.st_mode)
        want_mode = 'rwxr-sr-x'
        self.assertEqual(want_mode, found_mode[1:])
        if os.getuid() == 0:
            # The chown failed nonfatally if we're not root
            self.assertEqual(0, statf.st_uid)
            self.assertEqual(0, statf.st_gid)

        f = os.path.join(self.installdir, 'usr', 'share', 'progname',
                         'fileobject_datafile.dat')
        orig = os.path.join(testdir, 'fileobject_datafile.dat')
        statf = os.stat(f)
        statorig = os.stat(orig)
        found_mode = stat.filemode(statf.st_mode)
        orig_mode = stat.filemode(statorig.st_mode)
        self.assertEqual(orig_mode[1:], found_mode[1:])
        self.assertEqual(os.getuid(), statf.st_uid)
        if os.getuid() == 0:
            # The chown failed nonfatally if we're not root
            self.assertEqual(0, statf.st_gid)

        self.wipe()
        # Test directory modes
        testdir = os.path.join(self.common_test_dir, '62 install subdir')
        self.init(testdir)
        self.install()

        f = os.path.join(self.installdir, 'usr', 'share', 'sub1', 'second.dat')
        statf = os.stat(f)
        found_mode = stat.filemode(statf.st_mode)
        want_mode = 'rwxr-x--t'
        self.assertEqual(want_mode, found_mode[1:])
        if os.getuid() == 0:
            # The chown failed nonfatally if we're not root
            self.assertEqual(0, statf.st_uid)

    def test_installed_modes_extended(self):
        '''
        Test that files are installed with correct permissions using install_mode.
        '''
        testdir = os.path.join(self.common_test_dir, '195 install_mode')
        self.init(testdir)
        self.build()
        self.install()

        for fsobj, want_mode in [
                ('bin', 'drwxr-x---'),
                ('bin/runscript.sh', '-rwxr-sr-x'),
                ('bin/trivialprog', '-rwxr-sr-x'),
                ('include', 'drwxr-x---'),
                ('include/config.h', '-rw-rwSr--'),
                ('include/rootdir.h', '-r--r--r-T'),
                ('lib', 'drwxr-x---'),
                ('lib/libstat.a', '-rw---Sr--'),
                ('share', 'drwxr-x---'),
                ('share/man', 'drwxr-x---'),
                ('share/man/man1', 'drwxr-x---'),
                ('share/man/man1/foo.1', '-r--r--r-T'),
                ('share/sub1', 'drwxr-x---'),
                ('share/sub1/second.dat', '-rwxr-x--t'),
                ('subdir', 'drwxr-x---'),
                ('subdir/data.dat', '-rw-rwSr--'),
        ]:
            f = os.path.join(self.installdir, 'usr', *fsobj.split('/'))
            found_mode = stat.filemode(os.stat(f).st_mode)
            self.assertEqual(want_mode, found_mode,
                             msg=('Expected file %s to have mode %s but found %s instead.' %
                                  (fsobj, want_mode, found_mode)))
        # Ensure that introspect --installed works on all types of files
        # FIXME: also verify the files list
        self.introspect('--installed')

    def test_install_umask(self):
        '''
        Test that files are installed with correct permissions using default
        install umask of 022, regardless of the umask at time the worktree
        was checked out or the build was executed.
        '''
        # Copy source tree to a temporary directory and change permissions
        # there to simulate a checkout with umask 002.
        orig_testdir = os.path.join(self.unit_test_dir, '26 install umask')
        # Create a new testdir under tmpdir.
        tmpdir = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(windows_proof_rmtree, tmpdir)
        testdir = os.path.join(tmpdir, '26 install umask')
        # Copy the tree using shutil.copyfile, which will use the current umask
        # instead of preserving permissions of the old tree.
        save_umask = os.umask(0o002)
        self.addCleanup(os.umask, save_umask)
        shutil.copytree(orig_testdir, testdir, copy_function=shutil.copyfile)
        # Preserve the executable status of subdir/sayhello though.
        os.chmod(os.path.join(testdir, 'subdir', 'sayhello'), 0o775)
        self.init(testdir)
        # Run the build under a 027 umask now.
        os.umask(0o027)
        self.build()
        # And keep umask 027 for the install step too.
        self.install()

        for executable in [
                'bin/prog',
                'share/subdir/sayhello',
        ]:
            f = os.path.join(self.installdir, 'usr', *executable.split('/'))
            found_mode = stat.filemode(os.stat(f).st_mode)
            want_mode = '-rwxr-xr-x'
            self.assertEqual(want_mode, found_mode,
                             msg=('Expected file %s to have mode %s but found %s instead.' %
                                  (executable, want_mode, found_mode)))

        for directory in [
                'usr',
                'usr/bin',
                'usr/include',
                'usr/share',
                'usr/share/man',
                'usr/share/man/man1',
                'usr/share/subdir',
        ]:
            f = os.path.join(self.installdir, *directory.split('/'))
            found_mode = stat.filemode(os.stat(f).st_mode)
            want_mode = 'drwxr-xr-x'
            self.assertEqual(want_mode, found_mode,
                             msg=('Expected directory %s to have mode %s but found %s instead.' %
                                  (directory, want_mode, found_mode)))

        for datafile in [
                'include/sample.h',
                'share/datafile.cat',
                'share/file.dat',
                'share/man/man1/prog.1',
                'share/subdir/datafile.dog',
        ]:
            f = os.path.join(self.installdir, 'usr', *datafile.split('/'))
            found_mode = stat.filemode(os.stat(f).st_mode)
            want_mode = '-rw-r--r--'
            self.assertEqual(want_mode, found_mode,
                             msg=('Expected file %s to have mode %s but found %s instead.' %
                                  (datafile, want_mode, found_mode)))

    def test_cpp_std_override(self):
        testdir = os.path.join(self.unit_test_dir, '6 std override')
        self.init(testdir)
        compdb = self.get_compdb()
        # Don't try to use -std=c++03 as a check for the
        # presence of a compiler flag, as ICC does not
        # support it.
        for i in compdb:
            if 'prog98' in i['file']:
                c98_comp = i['command']
            if 'prog11' in i['file']:
                c11_comp = i['command']
            if 'progp' in i['file']:
                plain_comp = i['command']
        self.assertNotEqual(len(plain_comp), 0)
        self.assertIn('-std=c++98', c98_comp)
        self.assertNotIn('-std=c++11', c98_comp)
        self.assertIn('-std=c++11', c11_comp)
        self.assertNotIn('-std=c++98', c11_comp)
        self.assertNotIn('-std=c++98', plain_comp)
        self.assertNotIn('-std=c++11', plain_comp)
        # Now werror
        self.assertIn('-Werror', plain_comp)
        self.assertNotIn('-Werror', c98_comp)

    def test_run_installed(self):
        if is_cygwin() or is_osx():
            raise unittest.SkipTest('LD_LIBRARY_PATH and RPATH not applicable')

        testdir = os.path.join(self.unit_test_dir, '7 run installed')
        self.init(testdir)
        self.build()
        self.install()
        installed_exe = os.path.join(self.installdir, 'usr/bin/prog')
        installed_libdir = os.path.join(self.installdir, 'usr/foo')
        installed_lib = os.path.join(installed_libdir, 'libfoo.so')
        self.assertTrue(os.path.isfile(installed_exe))
        self.assertTrue(os.path.isdir(installed_libdir))
        self.assertTrue(os.path.isfile(installed_lib))
        # Must fail when run without LD_LIBRARY_PATH to ensure that
        # rpath has been properly stripped rather than pointing to the builddir.
        self.assertNotEqual(subprocess.call(installed_exe, stderr=subprocess.DEVNULL), 0)
        # When LD_LIBRARY_PATH is set it should start working.
        # For some reason setting LD_LIBRARY_PATH in os.environ fails
        # when all tests are run (but works when only this test is run),
        # but doing this explicitly works.
        env = os.environ.copy()
        env['LD_LIBRARY_PATH'] = ':'.join([installed_libdir, env.get('LD_LIBRARY_PATH', '')])
        self.assertEqual(subprocess.call(installed_exe, env=env), 0)
        # Ensure that introspect --installed works
        installed = self.introspect('--installed')
        for v in installed.values():
            self.assertTrue('prog' in v or 'foo' in v)

    @skipIfNoPkgconfig
    def test_order_of_l_arguments(self):
        testdir = os.path.join(self.unit_test_dir, '8 -L -l order')
        self.init(testdir, override_envvars={'PKG_CONFIG_PATH': testdir})
        # NOTE: .pc file has -Lfoo -lfoo -Lbar -lbar but pkg-config reorders
        # the flags before returning them to -Lfoo -Lbar -lfoo -lbar
        # but pkgconf seems to not do that. Sigh. Support both.
        expected_order = [('-L/me/first', '-lfoo1'),
                          ('-L/me/second', '-lfoo2'),
                          ('-L/me/first', '-L/me/second'),
                          ('-lfoo1', '-lfoo2'),
                          ('-L/me/second', '-L/me/third'),
                          ('-L/me/third', '-L/me/fourth',),
                          ('-L/me/third', '-lfoo3'),
                          ('-L/me/fourth', '-lfoo4'),
                          ('-lfoo3', '-lfoo4'),
                          ]
        with open(os.path.join(self.builddir, 'build.ninja')) as ifile:
            for line in ifile:
                if expected_order[0][0] in line:
                    for first, second in expected_order:
                        self.assertLess(line.index(first), line.index(second))
                    return
        raise RuntimeError('Linker entries not found in the Ninja file.')

    def test_introspect_dependencies(self):
        '''
        Tests that mesonintrospect --dependencies returns expected output.
        '''
        testdir = os.path.join(self.framework_test_dir, '7 gnome')
        self.init(testdir)
        glib_found = False
        gobject_found = False
        deps = self.introspect('--dependencies')
        self.assertIsInstance(deps, list)
        for dep in deps:
            self.assertIsInstance(dep, dict)
            self.assertIn('name', dep)
            self.assertIn('compile_args', dep)
            self.assertIn('link_args', dep)
            if dep['name'] == 'glib-2.0':
                glib_found = True
            elif dep['name'] == 'gobject-2.0':
                gobject_found = True
        self.assertTrue(glib_found)
        self.assertTrue(gobject_found)
        if subprocess.call(['pkg-config', '--exists', 'glib-2.0 >= 2.56.2']) != 0:
            raise unittest.SkipTest('glib >= 2.56.2 needed for the rest')
        targets = self.introspect('--targets')
        docbook_target = None
        for t in targets:
            if t['name'] == 'generated-gdbus-docbook':
                docbook_target = t
                break
        self.assertIsInstance(docbook_target, dict)
        self.assertEqual(os.path.basename(t['filename'][0]), 'generated-gdbus-doc-' + os.path.basename(t['target_sources'][0]['sources'][0]))

    def test_introspect_installed(self):
        testdir = os.path.join(self.linuxlike_test_dir, '7 library versions')
        self.init(testdir)

        install = self.introspect('--installed')
        install = {os.path.basename(k): v for k, v in install.items()}
        print(install)
        if is_osx():
            the_truth = {
                'libmodule.dylib': '/usr/lib/libmodule.dylib',
                'libnoversion.dylib': '/usr/lib/libnoversion.dylib',
                'libonlysoversion.5.dylib': '/usr/lib/libonlysoversion.5.dylib',
                'libonlysoversion.dylib': '/usr/lib/libonlysoversion.dylib',
                'libonlyversion.1.dylib': '/usr/lib/libonlyversion.1.dylib',
                'libonlyversion.dylib': '/usr/lib/libonlyversion.dylib',
                'libsome.0.dylib': '/usr/lib/libsome.0.dylib',
                'libsome.dylib': '/usr/lib/libsome.dylib',
            }
            the_truth_2 = {'/usr/lib/libsome.dylib',
                           '/usr/lib/libsome.0.dylib',
            }
        else:
            the_truth = {
                'libmodule.so': '/usr/lib/libmodule.so',
                'libnoversion.so': '/usr/lib/libnoversion.so',
                'libonlysoversion.so': '/usr/lib/libonlysoversion.so',
                'libonlysoversion.so.5': '/usr/lib/libonlysoversion.so.5',
                'libonlyversion.so': '/usr/lib/libonlyversion.so',
                'libonlyversion.so.1': '/usr/lib/libonlyversion.so.1',
                'libonlyversion.so.1.4.5': '/usr/lib/libonlyversion.so.1.4.5',
                'libsome.so': '/usr/lib/libsome.so',
                'libsome.so.0': '/usr/lib/libsome.so.0',
                'libsome.so.1.2.3': '/usr/lib/libsome.so.1.2.3',
            }
            the_truth_2 = {'/usr/lib/libsome.so',
                           '/usr/lib/libsome.so.0',
                           '/usr/lib/libsome.so.1.2.3'}
        self.assertDictEqual(install, the_truth)

        targets = self.introspect('--targets')
        for t in targets:
            if t['name'] != 'some':
                continue
            self.assertSetEqual(the_truth_2, set(t['install_filename']))

    def test_build_rpath(self):
        if is_cygwin():
            raise unittest.SkipTest('Windows PE/COFF binaries do not use RPATH')
        testdir = os.path.join(self.unit_test_dir, '10 build_rpath')
        self.init(testdir)
        self.build()
        # C program RPATH
        build_rpath = get_rpath(os.path.join(self.builddir, 'prog'))
        self.assertEqual(build_rpath, '$ORIGIN/sub:/foo/bar')
        self.install()
        install_rpath = get_rpath(os.path.join(self.installdir, 'usr/bin/prog'))
        self.assertEqual(install_rpath, '/baz')
        # C++ program RPATH
        build_rpath = get_rpath(os.path.join(self.builddir, 'progcxx'))
        self.assertEqual(build_rpath, '$ORIGIN/sub:/foo/bar')
        self.install()
        install_rpath = get_rpath(os.path.join(self.installdir, 'usr/bin/progcxx'))
        self.assertEqual(install_rpath, 'baz')

    def test_global_rpath(self):
        if is_cygwin():
            raise unittest.SkipTest('Windows PE/COFF binaries do not use RPATH')
        if is_osx():
            raise unittest.SkipTest('Global RPATHs via LDFLAGS not yet supported on MacOS (does anybody need it?)')

        testdir = os.path.join(self.unit_test_dir, '77 global-rpath')
        oldinstalldir = self.installdir

        # Build and install an external library without DESTDIR.
        # The external library generates a .pc file without an rpath.
        yonder_dir = os.path.join(testdir, 'yonder')
        yonder_prefix = os.path.join(oldinstalldir, 'yonder')
        yonder_libdir = os.path.join(yonder_prefix, self.libdir)
        self.prefix = yonder_prefix
        self.installdir = yonder_prefix
        self.init(yonder_dir)
        self.build()
        self.install(use_destdir=False)

        # Since rpath has multiple valid formats we need to
        # test that they are all properly used.
        rpath_formats = [
            ('-Wl,-rpath=', False),
            ('-Wl,-rpath,', False),
            ('-Wl,--just-symbols=', True),
            ('-Wl,--just-symbols,', True),
            ('-Wl,-R', False),
            ('-Wl,-R,', False)
        ]
        for rpath_format, exception in rpath_formats:
            # Build an app that uses that installed library.
            # Supply the rpath to the installed library via LDFLAGS
            # (as systems like buildroot and guix are wont to do)
            # and verify install preserves that rpath.
            self.new_builddir()
            env = {'LDFLAGS': rpath_format + yonder_libdir,
                   'PKG_CONFIG_PATH': os.path.join(yonder_libdir, 'pkgconfig')}
            if exception:
                with self.assertRaises(subprocess.CalledProcessError):
                    self.init(testdir, override_envvars=env)
                break
            self.init(testdir, override_envvars=env)
            self.build()
            self.install(use_destdir=False)
            got_rpath = get_rpath(os.path.join(yonder_prefix, 'bin/rpathified'))
            self.assertEqual(got_rpath, yonder_libdir, rpath_format)

    @skip_if_not_base_option('b_sanitize')
    def test_pch_with_address_sanitizer(self):
        if is_cygwin():
            raise unittest.SkipTest('asan not available on Cygwin')
        if is_openbsd():
            raise unittest.SkipTest('-fsanitize=address is not supported on OpenBSD')

        testdir = os.path.join(self.common_test_dir, '13 pch')
        self.init(testdir, extra_args=['-Db_sanitize=address', '-Db_lundef=false'])
        self.build()
        compdb = self.get_compdb()
        for i in compdb:
            self.assertIn("-fsanitize=address", i["command"])

    def test_cross_find_program(self):
        testdir = os.path.join(self.unit_test_dir, '11 cross prog')
        crossfile = tempfile.NamedTemporaryFile(mode='w')
        print(os.path.join(testdir, 'some_cross_tool.py'))
        crossfile.write(textwrap.dedent('''\
            [binaries]
            c = '/usr/bin/{1}'
            ar = '/usr/bin/ar'
            strip = '/usr/bin/ar'
            sometool.py = ['{0}']
            someothertool.py = '{0}'

            [properties]

            [host_machine]
            system = 'linux'
            cpu_family = 'arm'
            cpu = 'armv7' # Not sure if correct.
            endian = 'little'
            ''').format(os.path.join(testdir, 'some_cross_tool.py'),
                        'gcc' if is_sunos() else 'cc'))
        crossfile.flush()
        self.meson_cross_file = crossfile.name
        self.init(testdir)

    def test_reconfigure(self):
        testdir = os.path.join(self.unit_test_dir, '13 reconfigure')
        self.init(testdir, extra_args=['-Db_coverage=true'], default_args=False)
        self.build('reconfigure')

    def test_vala_generated_source_buildir_inside_source_tree(self):
        '''
        Test that valac outputs generated C files in the expected location when
        the builddir is a subdir of the source tree.
        '''
        if not shutil.which('valac'):
            raise unittest.SkipTest('valac not installed.')

        testdir = os.path.join(self.vala_test_dir, '8 generated sources')
        newdir = os.path.join(self.builddir, 'srctree')
        shutil.copytree(testdir, newdir)
        testdir = newdir
        # New builddir
        builddir = os.path.join(testdir, 'subdir/_build')
        os.makedirs(builddir, exist_ok=True)
        self.change_builddir(builddir)
        self.init(testdir)
        self.build()

    def test_old_gnome_module_codepaths(self):
        '''
        A lot of code in the GNOME module is conditional on the version of the
        glib tools that are installed, and breakages in the old code can slip
        by once the CI has a newer glib version. So we force the GNOME module
        to pretend that it's running on an ancient glib so the fallback code is
        also tested.
        '''
        testdir = os.path.join(self.framework_test_dir, '7 gnome')
        mesonbuild.modules.gnome.native_glib_version = '2.20'
        env = {'MESON_UNIT_TEST_PRETEND_GLIB_OLD': "1"}
        try:
            self.init(testdir,
                      inprocess=True,
                      override_envvars=env)
            self.build(override_envvars=env)
        finally:
            mesonbuild.modules.gnome.native_glib_version = None

    @skipIfNoPkgconfig
    def test_pkgconfig_usage(self):
        testdir1 = os.path.join(self.unit_test_dir, '27 pkgconfig usage/dependency')
        testdir2 = os.path.join(self.unit_test_dir, '27 pkgconfig usage/dependee')
        if subprocess.call(['pkg-config', '--cflags', 'glib-2.0'],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL) != 0:
            raise unittest.SkipTest('Glib 2.0 dependency not available.')
        with tempfile.TemporaryDirectory() as tempdirname:
            self.init(testdir1, extra_args=['--prefix=' + tempdirname, '--libdir=lib'], default_args=False)
            self.install(use_destdir=False)
            shutil.rmtree(self.builddir)
            os.mkdir(self.builddir)
            pkg_dir = os.path.join(tempdirname, 'lib/pkgconfig')
            self.assertTrue(os.path.exists(os.path.join(pkg_dir, 'libpkgdep.pc')))
            lib_dir = os.path.join(tempdirname, 'lib')
            myenv = os.environ.copy()
            myenv['PKG_CONFIG_PATH'] = pkg_dir
            # Private internal libraries must not leak out.
            pkg_out = subprocess.check_output(['pkg-config', '--static', '--libs', 'libpkgdep'], env=myenv)
            self.assertFalse(b'libpkgdep-int' in pkg_out, 'Internal library leaked out.')
            # Dependencies must not leak to cflags when building only a shared library.
            pkg_out = subprocess.check_output(['pkg-config', '--cflags', 'libpkgdep'], env=myenv)
            self.assertFalse(b'glib' in pkg_out, 'Internal dependency leaked to headers.')
            # Test that the result is usable.
            self.init(testdir2, override_envvars=myenv)
            self.build(override_envvars=myenv)
            myenv = os.environ.copy()
            myenv['LD_LIBRARY_PATH'] = ':'.join([lib_dir, myenv.get('LD_LIBRARY_PATH', '')])
            if is_cygwin():
                bin_dir = os.path.join(tempdirname, 'bin')
                myenv['PATH'] = bin_dir + os.pathsep + myenv['PATH']
            self.assertTrue(os.path.isdir(lib_dir))
            test_exe = os.path.join(self.builddir, 'pkguser')
            self.assertTrue(os.path.isfile(test_exe))
            subprocess.check_call(test_exe, env=myenv)

    @skipIfNoPkgconfig
    def test_pkgconfig_relative_paths(self):
        testdir = os.path.join(self.unit_test_dir, '62 pkgconfig relative paths')
        pkg_dir = os.path.join(testdir, 'pkgconfig')
        self.assertTrue(os.path.exists(os.path.join(pkg_dir, 'librelativepath.pc')))

        env = get_fake_env(testdir, self.builddir, self.prefix)
        env.coredata.set_options({'pkg_config_path': pkg_dir}, subproject='')
        kwargs = {'required': True, 'silent': True}
        relative_path_dep = PkgConfigDependency('librelativepath', env, kwargs)
        self.assertTrue(relative_path_dep.found())

        # Ensure link_args are properly quoted
        libpath = Path(self.builddir) / '../relativepath/lib'
        link_args = ['-L' + libpath.as_posix(), '-lrelativepath']
        self.assertEqual(relative_path_dep.get_link_args(), link_args)

    @skipIfNoPkgconfig
    def test_pkgconfig_internal_libraries(self):
        '''
        '''
        with tempfile.TemporaryDirectory() as tempdirname:
            # build library
            testdirbase = os.path.join(self.unit_test_dir, '32 pkgconfig use libraries')
            testdirlib = os.path.join(testdirbase, 'lib')
            self.init(testdirlib, extra_args=['--prefix=' + tempdirname,
                                              '--libdir=lib',
                                              '--default-library=static'], default_args=False)
            self.build()
            self.install(use_destdir=False)

            # build user of library
            pkg_dir = os.path.join(tempdirname, 'lib/pkgconfig')
            self.new_builddir()
            self.init(os.path.join(testdirbase, 'app'),
                      override_envvars={'PKG_CONFIG_PATH': pkg_dir})
            self.build()

    @skipIfNoPkgconfig
    def test_static_archive_stripping(self):
        '''
        Check that Meson produces valid static archives with --strip enabled
        '''
        with tempfile.TemporaryDirectory() as tempdirname:
            testdirbase = os.path.join(self.unit_test_dir, '67 static archive stripping')

            # build lib
            self.new_builddir()
            testdirlib = os.path.join(testdirbase, 'lib')
            testlibprefix = os.path.join(tempdirname, 'libprefix')
            self.init(testdirlib, extra_args=['--prefix=' + testlibprefix,
                                              '--libdir=lib',
                                              '--default-library=static',
                                              '--buildtype=debug',
                                              '--strip'], default_args=False)
            self.build()
            self.install(use_destdir=False)

            # build executable (uses lib, fails if static archive has been stripped incorrectly)
            pkg_dir = os.path.join(testlibprefix, 'lib/pkgconfig')
            self.new_builddir()
            self.init(os.path.join(testdirbase, 'app'),
                      override_envvars={'PKG_CONFIG_PATH': pkg_dir})
            self.build()

    @skipIfNoPkgconfig
    def test_pkgconfig_formatting(self):
        testdir = os.path.join(self.unit_test_dir, '38 pkgconfig format')
        self.init(testdir)
        myenv = os.environ.copy()
        myenv['PKG_CONFIG_PATH'] = self.privatedir
        stdo = subprocess.check_output(['pkg-config', '--libs-only-l', 'libsomething'], env=myenv)
        deps = [b'-lgobject-2.0', b'-lgio-2.0', b'-lglib-2.0', b'-lsomething']
        if is_windows() or is_cygwin() or is_osx() or is_openbsd():
            # On Windows, libintl is a separate library
            deps.append(b'-lintl')
        self.assertEqual(set(deps), set(stdo.split()))

    @skipIfNoPkgconfig
    @skip_if_not_language('cs')
    def test_pkgconfig_csharp_library(self):
        testdir = os.path.join(self.unit_test_dir, '50 pkgconfig csharp library')
        self.init(testdir)
        myenv = os.environ.copy()
        myenv['PKG_CONFIG_PATH'] = self.privatedir
        stdo = subprocess.check_output(['pkg-config', '--libs', 'libsomething'], env=myenv)

        self.assertEqual("-r/usr/lib/libsomething.dll", str(stdo.decode('ascii')).strip())

    @skipIfNoPkgconfig
    def test_pkgconfig_link_order(self):
        '''
        Test that libraries are listed before their dependencies.
        '''
        testdir = os.path.join(self.unit_test_dir, '53 pkgconfig static link order')
        self.init(testdir)
        myenv = os.environ.copy()
        myenv['PKG_CONFIG_PATH'] = self.privatedir
        stdo = subprocess.check_output(['pkg-config', '--libs', 'libsomething'], env=myenv)
        deps = stdo.split()
        self.assertTrue(deps.index(b'-lsomething') < deps.index(b'-ldependency'))

    def test_deterministic_dep_order(self):
        '''
        Test that the dependencies are always listed in a deterministic order.
        '''
        testdir = os.path.join(self.unit_test_dir, '43 dep order')
        self.init(testdir)
        with open(os.path.join(self.builddir, 'build.ninja')) as bfile:
            for line in bfile:
                if 'build myexe:' in line or 'build myexe.exe:' in line:
                    self.assertIn('liblib1.a liblib2.a', line)
                    return
        raise RuntimeError('Could not find the build rule')

    def test_deterministic_rpath_order(self):
        '''
        Test that the rpaths are always listed in a deterministic order.
        '''
        if is_cygwin():
            raise unittest.SkipTest('rpath are not used on Cygwin')
        testdir = os.path.join(self.unit_test_dir, '42 rpath order')
        self.init(testdir)
        if is_osx():
            rpathre = re.compile(r'-rpath,.*/subprojects/sub1.*-rpath,.*/subprojects/sub2')
        else:
            rpathre = re.compile(r'-rpath,\$\$ORIGIN/subprojects/sub1:\$\$ORIGIN/subprojects/sub2')
        with open(os.path.join(self.builddir, 'build.ninja')) as bfile:
            for line in bfile:
                if '-rpath' in line:
                    self.assertRegex(line, rpathre)
                    return
        raise RuntimeError('Could not find the rpath')

    def test_override_with_exe_dep(self):
        '''
        Test that we produce the correct dependencies when a program is overridden with an executable.
        '''
        testdir = os.path.join(self.common_test_dir, '201 override with exe')
        self.init(testdir)
        with open(os.path.join(self.builddir, 'build.ninja')) as bfile:
            for line in bfile:
                if 'main1.c:' in line or 'main2.c:' in line:
                    self.assertIn('| subprojects/sub/foobar', line)

    @skipIfNoPkgconfig
    def test_usage_external_library(self):
        '''
        Test that uninstalled usage of an external library (from the system or
        PkgConfigDependency) works. On macOS, this workflow works out of the
        box. On Linux, BSDs, Windows, etc, you need to set extra arguments such
        as LD_LIBRARY_PATH, etc, so this test is skipped.

        The system library is found with cc.find_library() and pkg-config deps.
        '''
        oldprefix = self.prefix
        # Install external library so we can find it
        testdir = os.path.join(self.unit_test_dir, '40 external, internal library rpath', 'external library')
        # install into installdir without using DESTDIR
        installdir = self.installdir
        self.prefix = installdir
        self.init(testdir)
        self.prefix = oldprefix
        self.build()
        self.install(use_destdir=False)
        ## New builddir for the consumer
        self.new_builddir()
        env = {'LIBRARY_PATH': os.path.join(installdir, self.libdir),
               'PKG_CONFIG_PATH': os.path.join(installdir, self.libdir, 'pkgconfig')}
        testdir = os.path.join(self.unit_test_dir, '40 external, internal library rpath', 'built library')
        # install into installdir without using DESTDIR
        self.prefix = self.installdir
        self.init(testdir, override_envvars=env)
        self.prefix = oldprefix
        self.build(override_envvars=env)
        # test uninstalled
        self.run_tests(override_envvars=env)
        if not (is_osx() or is_linux()):
            return
        # test running after installation
        self.install(use_destdir=False)
        prog = os.path.join(self.installdir, 'bin', 'prog')
        self._run([prog])
        if not is_osx():
            # Rest of the workflow only works on macOS
            return
        out = self._run(['otool', '-L', prog])
        self.assertNotIn('@rpath', out)
        ## New builddir for testing that DESTDIR is not added to install_name
        self.new_builddir()
        # install into installdir with DESTDIR
        self.init(testdir, override_envvars=env)
        self.build(override_envvars=env)
        # test running after installation
        self.install(override_envvars=env)
        prog = self.installdir + os.path.join(self.prefix, 'bin', 'prog')
        lib = self.installdir + os.path.join(self.prefix, 'lib', 'libbar_built.dylib')
        for f in prog, lib:
            out = self._run(['otool', '-L', f])
            # Ensure that the otool output does not contain self.installdir
            self.assertNotRegex(out, self.installdir + '.*dylib ')

    @skipIfNoPkgconfig
    def test_usage_pkgconfig_prefixes(self):
        '''
        Build and install two external libraries, to different prefixes,
        then build and install a client program that finds them via pkgconfig,
        and verify the installed client program runs.
        '''
        oldinstalldir = self.installdir

        # Build and install both external libraries without DESTDIR
        val1dir = os.path.join(self.unit_test_dir, '76 pkgconfig prefixes', 'val1')
        val1prefix = os.path.join(oldinstalldir, 'val1')
        self.prefix = val1prefix
        self.installdir = val1prefix
        self.init(val1dir)
        self.build()
        self.install(use_destdir=False)
        self.new_builddir()

        env1 = {}
        env1['PKG_CONFIG_PATH'] = os.path.join(val1prefix, self.libdir, 'pkgconfig')
        val2dir = os.path.join(self.unit_test_dir, '76 pkgconfig prefixes', 'val2')
        val2prefix = os.path.join(oldinstalldir, 'val2')
        self.prefix = val2prefix
        self.installdir = val2prefix
        self.init(val2dir, override_envvars=env1)
        self.build()
        self.install(use_destdir=False)
        self.new_builddir()

        # Build, install, and run the client program
        env2 = {}
        env2['PKG_CONFIG_PATH'] = os.path.join(val2prefix, self.libdir, 'pkgconfig')
        testdir = os.path.join(self.unit_test_dir, '76 pkgconfig prefixes', 'client')
        testprefix = os.path.join(oldinstalldir, 'client')
        self.prefix = testprefix
        self.installdir = testprefix
        self.init(testdir, override_envvars=env2)
        self.build()
        self.install(use_destdir=False)
        prog = os.path.join(self.installdir, 'bin', 'client')
        env3 = {}
        if is_cygwin():
            env3['PATH'] = os.path.join(val1prefix, 'bin') + \
                os.pathsep + \
                os.path.join(val2prefix, 'bin') + \
                os.pathsep + os.environ['PATH']
        out = self._run([prog], override_envvars=env3).strip()
        # Expected output is val1 + val2 = 3
        self.assertEqual(out, '3')

    def install_subdir_invalid_symlinks(self, testdir, subdir_path):
        '''
        Test that installation of broken symlinks works fine.
        https://github.com/mesonbuild/meson/issues/3914
        '''
        testdir = os.path.join(self.common_test_dir, testdir)
        subdir = os.path.join(testdir, subdir_path)
        with chdir(subdir):
            # Can't distribute broken symlinks in the source tree because it breaks
            # the creation of zipapps. Create it dynamically and run the test by
            # hand.
            src = '../../nonexistent.txt'
            os.symlink(src, 'invalid-symlink.txt')
            try:
                self.init(testdir)
                self.build()
                self.install()
                install_path = subdir_path.split(os.path.sep)[-1]
                link = os.path.join(self.installdir, 'usr', 'share', install_path, 'invalid-symlink.txt')
                self.assertTrue(os.path.islink(link), msg=link)
                self.assertEqual(src, os.readlink(link))
                self.assertFalse(os.path.isfile(link), msg=link)
            finally:
                os.remove(os.path.join(subdir, 'invalid-symlink.txt'))

    def test_install_subdir_symlinks(self):
        self.install_subdir_invalid_symlinks('62 install subdir', os.path.join('sub', 'sub1'))

    def test_install_subdir_symlinks_with_default_umask(self):
        self.install_subdir_invalid_symlinks('195 install_mode', 'sub2')

    def test_install_subdir_symlinks_with_default_umask_and_mode(self):
        self.install_subdir_invalid_symlinks('195 install_mode', 'sub1')

    @skipIfNoPkgconfigDep('gmodule-2.0')
    def test_ldflag_dedup(self):
        testdir = os.path.join(self.unit_test_dir, '52 ldflagdedup')
        if is_cygwin() or is_osx():
            raise unittest.SkipTest('Not applicable on Cygwin or OSX.')
        env = get_fake_env()
        cc = env.detect_c_compiler(MachineChoice.HOST)
        linker = cc.linker
        if not linker.export_dynamic_args(env):
            raise unittest.SkipTest('Not applicable for linkers without --export-dynamic')
        self.init(testdir)
        build_ninja = os.path.join(self.builddir, 'build.ninja')
        max_count = 0
        search_term = '-Wl,--export-dynamic'
        with open(build_ninja, 'r', encoding='utf-8') as f:
            for line in f:
                max_count = max(max_count, line.count(search_term))
        self.assertEqual(max_count, 1, 'Export dynamic incorrectly deduplicated.')

    def test_compiler_libs_static_dedup(self):
        testdir = os.path.join(self.unit_test_dir, '56 dedup compiler libs')
        self.init(testdir)
        build_ninja = os.path.join(self.builddir, 'build.ninja')
        with open(build_ninja, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        for lib in ('-ldl', '-lm', '-lc', '-lrt'):
            for line in lines:
                if lib not in line:
                    continue
                # Assert that
                self.assertEqual(len(line.split(lib)), 2, msg=(lib, line))

    @skipIfNoPkgconfig
    def test_noncross_options(self):
        # C_std defined in project options must be in effect also when native compiling.
        testdir = os.path.join(self.unit_test_dir, '51 noncross options')
        self.init(testdir, extra_args=['-Dpkg_config_path=' + testdir])
        compdb = self.get_compdb()
        self.assertEqual(len(compdb), 2)
        self.assertRegex(compdb[0]['command'], '-std=c99')
        self.assertRegex(compdb[1]['command'], '-std=c99')
        self.build()

    def test_identity_cross(self):
        testdir = os.path.join(self.unit_test_dir, '61 identity cross')

        nativefile = tempfile.NamedTemporaryFile(mode='w')
        nativefile.write('''[binaries]
c = ['{0}']
'''.format(os.path.join(testdir, 'build_wrapper.py')))
        nativefile.flush()
        self.meson_native_file = nativefile.name

        crossfile = tempfile.NamedTemporaryFile(mode='w')
        crossfile.write('''[binaries]
c = ['{0}']
'''.format(os.path.join(testdir, 'host_wrapper.py')))
        crossfile.flush()
        self.meson_cross_file = crossfile.name

        # TODO should someday be explicit about build platform only here
        self.init(testdir)

    def test_identity_cross_env(self):
        testdir = os.path.join(self.unit_test_dir, '61 identity cross')
        env = {
            'CC_FOR_BUILD': '"' + os.path.join(testdir, 'build_wrapper.py') + '"',
        }
        crossfile = tempfile.NamedTemporaryFile(mode='w')
        crossfile.write('''[binaries]
c = ['{0}']
'''.format(os.path.join(testdir, 'host_wrapper.py')))
        crossfile.flush()
        self.meson_cross_file = crossfile.name
        # TODO should someday be explicit about build platform only here
        self.init(testdir, override_envvars=env)

    @skipIfNoPkgconfig
    def test_static_link(self):
        if is_cygwin():
            raise unittest.SkipTest("Cygwin doesn't support LD_LIBRARY_PATH.")

        # Build some libraries and install them
        testdir = os.path.join(self.unit_test_dir, '68 static link/lib')
        libdir = os.path.join(self.installdir, self.libdir)
        oldprefix = self.prefix
        self.prefix = self.installdir
        self.init(testdir)
        self.install(use_destdir=False)

        # Test that installed libraries works
        self.new_builddir()
        self.prefix = oldprefix
        meson_args = ['-Dc_link_args=-L{}'.format(libdir),
                      '--fatal-meson-warnings']
        testdir = os.path.join(self.unit_test_dir, '68 static link')
        env = {'PKG_CONFIG_LIBDIR': os.path.join(libdir, 'pkgconfig')}
        self.init(testdir, extra_args=meson_args, override_envvars=env)
        self.build()
        self.run_tests()

    def _check_ld(self, check: str, name: str, lang: str, expected: str) -> None:
        if is_sunos():
            raise unittest.SkipTest('Solaris currently cannot override the linker.')
        if not shutil.which(check):
            raise unittest.SkipTest('Could not find {}.'.format(check))
        envvars = [mesonbuild.envconfig.BinaryTable.evarMap['{}_ld'.format(lang)]]

        # Also test a deprecated variable if there is one.
        if envvars[0] in mesonbuild.envconfig.BinaryTable.DEPRECATION_MAP:
            envvars.append(
                mesonbuild.envconfig.BinaryTable.DEPRECATION_MAP[envvars[0]])

        for envvar in envvars:
            with mock.patch.dict(os.environ, {envvar: name}):
                env = get_fake_env()
                comp = getattr(env, 'detect_{}_compiler'.format(lang))(MachineChoice.HOST)
                if lang != 'rust' and comp.use_linker_args('bfd') == []:
                    raise unittest.SkipTest(
                        'Compiler {} does not support using alternative linkers'.format(comp.id))
                self.assertEqual(comp.linker.id, expected)

    def test_ld_environment_variable_bfd(self):
        self._check_ld('ld.bfd', 'bfd', 'c', 'ld.bfd')

    def test_ld_environment_variable_gold(self):
        self._check_ld('ld.gold', 'gold', 'c', 'ld.gold')

    def test_ld_environment_variable_lld(self):
        self._check_ld('ld.lld', 'lld', 'c', 'ld.lld')

    @skip_if_not_language('rust')
    def test_ld_environment_variable_rust(self):
        self._check_ld('ld.gold', 'gold', 'rust', 'ld.gold')

    def test_ld_environment_variable_cpp(self):
        self._check_ld('ld.gold', 'gold', 'cpp', 'ld.gold')

    @skip_if_not_language('objc')
    def test_ld_environment_variable_objc(self):
        self._check_ld('ld.gold', 'gold', 'objc', 'ld.gold')

    @skip_if_not_language('objcpp')
    def test_ld_environment_variable_objcpp(self):
        self._check_ld('ld.gold', 'gold', 'objcpp', 'ld.gold')

    @skip_if_not_language('fortran')
    def test_ld_environment_variable_fortran(self):
        self._check_ld('ld.gold', 'gold', 'fortran', 'ld.gold')

    @skip_if_not_language('d')
    def test_ld_environment_variable_d(self):
        # At least for me, ldc defaults to gold, and gdc defaults to bfd, so
        # let's pick lld, which isn't the default for either (currently)
        self._check_ld('ld.lld', 'lld', 'd', 'ld.lld')

    def compute_sha256(self, filename):
        with open(filename, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()

    def test_wrap_with_file_url(self):
        testdir = os.path.join(self.unit_test_dir, '74 wrap file url')
        source_filename = os.path.join(testdir, 'subprojects', 'foo.tar.xz')
        patch_filename = os.path.join(testdir, 'subprojects', 'foo-patch.tar.xz')
        wrap_filename = os.path.join(testdir, 'subprojects', 'foo.wrap')
        source_hash = self.compute_sha256(source_filename)
        patch_hash = self.compute_sha256(patch_filename)
        wrap = textwrap.dedent("""\
            [wrap-file]
            directory = foo

            source_url = http://server.invalid/foo
            source_fallback_url = file://{}
            source_filename = foo.tar.xz
            source_hash = {}

            patch_url = http://server.invalid/foo
            patch_fallback_url = file://{}
            patch_filename = foo-patch.tar.xz
            patch_hash = {}
            """.format(source_filename, source_hash, patch_filename, patch_hash))
        with open(wrap_filename, 'w') as f:
            f.write(wrap)
        self.init(testdir)
        self.build()
        self.run_tests()

        windows_proof_rmtree(os.path.join(testdir, 'subprojects', 'packagecache'))
        windows_proof_rmtree(os.path.join(testdir, 'subprojects', 'foo'))
        os.unlink(wrap_filename)

    def test_no_rpath_for_static(self):
        testdir = os.path.join(self.common_test_dir, '5 linkstatic')
        self.init(testdir)
        self.build()
        build_rpath = get_rpath(os.path.join(self.builddir, 'prog'))
        self.assertIsNone(build_rpath)

    def test_lookup_system_after_broken_fallback(self):
        # Just to generate libfoo.pc so we can test system dependency lookup.
        testdir = os.path.join(self.common_test_dir, '47 pkgconfig-gen')
        self.init(testdir)
        privatedir = self.privatedir

        # Write test project where the first dependency() returns not-found
        # because 'broken' subproject does not exit, but that should not prevent
        # the 2nd dependency() to lookup on system.
        self.new_builddir()
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, 'meson.build'), 'w') as f:
                f.write(textwrap.dedent('''\
                    project('test')
                    dependency('notfound', fallback: 'broken', required: false)
                    dependency('libfoo', fallback: 'broken', required: true)
                    '''))
            self.init(d, override_envvars={'PKG_CONFIG_LIBDIR': privatedir})

class BaseLinuxCrossTests(BasePlatformTests):
    # Don't pass --libdir when cross-compiling. We have tests that
    # check whether meson auto-detects it correctly.
    libdir = None


def should_run_cross_arm_tests():
    return shutil.which('arm-linux-gnueabihf-gcc') and not platform.machine().lower().startswith('arm')

@unittest.skipUnless(not is_windows() and should_run_cross_arm_tests(), "requires ability to cross compile to ARM")
class LinuxCrossArmTests(BaseLinuxCrossTests):
    '''
    Tests that cross-compilation to Linux/ARM works
    '''

    def setUp(self):
        super().setUp()
        src_root = os.path.dirname(__file__)
        self.meson_cross_file = os.path.join(src_root, 'cross', 'ubuntu-armhf.txt')

    def test_cflags_cross_environment_pollution(self):
        '''
        Test that the CFLAGS environment variable does not pollute the cross
        environment. This can't be an ordinary test case because we need to
        inspect the compiler database.
        '''
        testdir = os.path.join(self.common_test_dir, '3 static')
        self.init(testdir, override_envvars={'CFLAGS': '-DBUILD_ENVIRONMENT_ONLY'})
        compdb = self.get_compdb()
        self.assertNotIn('-DBUILD_ENVIRONMENT_ONLY', compdb[0]['command'])

    def test_cross_file_overrides_always_args(self):
        '''
        Test that $lang_args in cross files always override get_always_args().
        Needed for overriding the default -D_FILE_OFFSET_BITS=64 on some
        architectures such as some Android versions and Raspbian.
        https://github.com/mesonbuild/meson/issues/3049
        https://github.com/mesonbuild/meson/issues/3089
        '''
        testdir = os.path.join(self.unit_test_dir, '33 cross file overrides always args')
        self.meson_cross_file = os.path.join(testdir, 'ubuntu-armhf-overrides.txt')
        self.init(testdir)
        compdb = self.get_compdb()
        self.assertRegex(compdb[0]['command'], '-D_FILE_OFFSET_BITS=64.*-U_FILE_OFFSET_BITS')
        self.build()

    def test_cross_libdir(self):
        # When cross compiling "libdir" should default to "lib"
        # rather than "lib/x86_64-linux-gnu" or something like that.
        testdir = os.path.join(self.common_test_dir, '1 trivial')
        self.init(testdir)
        for i in self.introspect('--buildoptions'):
            if i['name'] == 'libdir':
                self.assertEqual(i['value'], 'lib')
                return
        self.assertTrue(False, 'Option libdir not in introspect data.')

    def test_cross_libdir_subproject(self):
        # Guard against a regression where calling "subproject"
        # would reset the value of libdir to its default value.
        testdir = os.path.join(self.unit_test_dir, '76 subdir libdir')
        self.init(testdir, extra_args=['--libdir=fuf'])
        for i in self.introspect('--buildoptions'):
            if i['name'] == 'libdir':
                self.assertEqual(i['value'], 'fuf')
                return
        self.assertTrue(False, 'Libdir specified on command line gets reset.')

    def test_std_remains(self):
        # C_std defined in project options must be in effect also when cross compiling.
        testdir = os.path.join(self.unit_test_dir, '51 noncross options')
        self.init(testdir)
        compdb = self.get_compdb()
        self.assertRegex(compdb[0]['command'], '-std=c99')
        self.build()

    @skipIfNoPkgconfig
    def test_pkg_config_option(self):
        if not shutil.which('arm-linux-gnueabihf-pkg-config'):
            raise unittest.SkipTest('Cross-pkgconfig not found.')
        testdir = os.path.join(self.unit_test_dir, '58 pkg_config_path option')
        self.init(testdir, extra_args=[
            '-Dbuild.pkg_config_path=' + os.path.join(testdir, 'build_extra_path'),
            '-Dpkg_config_path=' + os.path.join(testdir, 'host_extra_path'),
        ])


def should_run_cross_mingw_tests():
    return shutil.which('x86_64-w64-mingw32-gcc') and not (is_windows() or is_cygwin())

@unittest.skipUnless(not is_windows() and should_run_cross_mingw_tests(), "requires ability to cross compile with MinGW")
class LinuxCrossMingwTests(BaseLinuxCrossTests):
    '''
    Tests that cross-compilation to Windows/MinGW works
    '''

    def setUp(self):
        super().setUp()
        src_root = os.path.dirname(__file__)
        self.meson_cross_file = os.path.join(src_root, 'cross', 'linux-mingw-w64-64bit.txt')

    def test_exe_wrapper_behaviour(self):
        '''
        Test that an exe wrapper that isn't found doesn't cause compiler sanity
        checks and compiler checks to fail, but causes configure to fail if it
        requires running a cross-built executable (custom_target or run_target)
        and causes the tests to be skipped if they are run.
        '''
        testdir = os.path.join(self.unit_test_dir, '36 exe_wrapper behaviour')
        # Configures, builds, and tests fine by default
        self.init(testdir)
        self.build()
        self.run_tests()
        self.wipe()
        os.mkdir(self.builddir)
        # Change cross file to use a non-existing exe_wrapper and it should fail
        self.meson_cross_file = os.path.join(testdir, 'broken-cross.txt')
        # Force tracebacks so we can detect them properly
        env = {'MESON_FORCE_BACKTRACE': '1'}
        with self.assertRaisesRegex(MesonException, 'exe_wrapper.*target.*use-exe-wrapper'):
            # Must run in-process or we'll get a generic CalledProcessError
            self.init(testdir, extra_args='-Drun-target=false',
                      inprocess=True,
                      override_envvars=env)
        with self.assertRaisesRegex(MesonException, 'exe_wrapper.*run target.*run-prog'):
            # Must run in-process or we'll get a generic CalledProcessError
            self.init(testdir, extra_args='-Dcustom-target=false',
                      inprocess=True,
                      override_envvars=env)
        self.init(testdir, extra_args=['-Dcustom-target=false', '-Drun-target=false'],
                  override_envvars=env)
        self.build()
        with self.assertRaisesRegex(MesonException, 'exe_wrapper.*PATH'):
            # Must run in-process or we'll get a generic CalledProcessError
            self.run_tests(inprocess=True, override_envvars=env)

    @skipIfNoPkgconfig
    def test_cross_pkg_config_option(self):
        testdir = os.path.join(self.unit_test_dir, '58 pkg_config_path option')
        self.init(testdir, extra_args=[
            '-Dbuild.pkg_config_path=' + os.path.join(testdir, 'build_extra_path'),
            '-Dpkg_config_path=' + os.path.join(testdir, 'host_extra_path'),
        ])


class PythonTests(BasePlatformTests):
    '''
    Tests that verify compilation of python extension modules
    '''

    def test_versions(self):
        if self.backend is not Backend.ninja:
            raise unittest.SkipTest('Skipping python tests with {} backend'.format(self.backend.name))

        testdir = os.path.join(self.src_root, 'test cases', 'unit', '39 python extmodule')

        # No python version specified, this will use meson's python
        self.init(testdir)
        self.build()
        self.run_tests()
        self.wipe()

        # When specifying a known name, (python2 / python3) the module
        # will also try 'python' as a fallback and use it if the major
        # version matches
        try:
            self.init(testdir, extra_args=['-Dpython=python2'])
            self.build()
            self.run_tests()
        except unittest.SkipTest:
            # python2 is not necessarily installed on the test machine,
            # if it is not, or the python headers can't be found, the test
            # will raise MESON_SKIP_TEST, we could check beforehand what version
            # of python is available, but it's a bit of a chicken and egg situation,
            # as that is the job of the module, so we just ask for forgiveness rather
            # than permission.
            pass

        self.wipe()

        for py in ('pypy', 'pypy3'):
            try:
                self.init(testdir, extra_args=['-Dpython=%s' % py])
            except unittest.SkipTest:
                # Same as above, pypy2 and pypy3 are not expected to be present
                # on the test system, the test project only raises in these cases
                continue

            # We have a pypy, this is expected to work
            self.build()
            self.run_tests()
            self.wipe()

        # The test is configured to error out with MESON_SKIP_TEST
        # in case it could not find python
        with self.assertRaises(unittest.SkipTest):
            self.init(testdir, extra_args=['-Dpython=not-python'])
        self.wipe()

        # While dir is an external command on both Windows and Linux,
        # it certainly isn't python
        with self.assertRaises(unittest.SkipTest):
            self.init(testdir, extra_args=['-Dpython=dir'])
        self.wipe()


class RewriterTests(BasePlatformTests):
    def setUp(self):
        super().setUp()
        self.maxDiff = None

    def prime(self, dirname):
        copy_tree(os.path.join(self.rewrite_test_dir, dirname), self.builddir)

    def rewrite_raw(self, directory, args):
        if isinstance(args, str):
            args = [args]
        command = self.rewrite_command + ['--verbose', '--skip', '--sourcedir', directory] + args
        p = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=60)
        print('STDOUT:')
        print(p.stdout)
        print('STDERR:')
        print(p.stderr)
        if p.returncode != 0:
            if 'MESON_SKIP_TEST' in p.stdout:
                raise unittest.SkipTest('Project requested skipping.')
            raise subprocess.CalledProcessError(p.returncode, command, output=p.stdout)
        if not p.stderr:
            return {}
        return json.loads(p.stderr)

    def rewrite(self, directory, args):
        if isinstance(args, str):
            args = [args]
        return self.rewrite_raw(directory, ['command'] + args)

    def test_target_source_list(self):
        self.prime('1 basic')
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))
        expected = {
            'target': {
                'trivialprog0@exe': {'name': 'trivialprog0', 'sources': ['main.cpp', 'fileA.cpp', 'fileB.cpp', 'fileC.cpp']},
                'trivialprog1@exe': {'name': 'trivialprog1', 'sources': ['main.cpp', 'fileA.cpp']},
                'trivialprog2@exe': {'name': 'trivialprog2', 'sources': ['fileB.cpp', 'fileC.cpp']},
                'trivialprog3@exe': {'name': 'trivialprog3', 'sources': ['main.cpp', 'fileA.cpp']},
                'trivialprog4@exe': {'name': 'trivialprog4', 'sources': ['main.cpp', 'fileA.cpp']},
                'trivialprog5@exe': {'name': 'trivialprog5', 'sources': ['main.cpp', 'fileB.cpp', 'fileC.cpp']},
                'trivialprog6@exe': {'name': 'trivialprog6', 'sources': ['main.cpp', 'fileA.cpp']},
                'trivialprog7@exe': {'name': 'trivialprog7', 'sources': ['fileB.cpp', 'fileC.cpp', 'main.cpp', 'fileA.cpp']},
                'trivialprog8@exe': {'name': 'trivialprog8', 'sources': ['main.cpp', 'fileA.cpp']},
                'trivialprog9@exe': {'name': 'trivialprog9', 'sources': ['main.cpp', 'fileA.cpp']},
            }
        }
        self.assertDictEqual(out, expected)

    def test_target_add_sources(self):
        self.prime('1 basic')
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'addSrc.json'))
        expected = {
            'target': {
                'trivialprog0@exe': {'name': 'trivialprog0', 'sources': ['a1.cpp', 'a2.cpp', 'a6.cpp', 'fileA.cpp', 'main.cpp', 'a7.cpp', 'fileB.cpp', 'fileC.cpp']},
                'trivialprog1@exe': {'name': 'trivialprog1', 'sources': ['a1.cpp', 'a2.cpp', 'a6.cpp', 'fileA.cpp', 'main.cpp']},
                'trivialprog2@exe': {'name': 'trivialprog2', 'sources': ['a7.cpp', 'fileB.cpp', 'fileC.cpp']},
                'trivialprog3@exe': {'name': 'trivialprog3', 'sources': ['a5.cpp', 'fileA.cpp', 'main.cpp']},
                'trivialprog4@exe': {'name': 'trivialprog4', 'sources': ['a5.cpp', 'main.cpp', 'fileA.cpp']},
                'trivialprog5@exe': {'name': 'trivialprog5', 'sources': ['a3.cpp', 'main.cpp', 'a7.cpp', 'fileB.cpp', 'fileC.cpp']},
                'trivialprog6@exe': {'name': 'trivialprog6', 'sources': ['main.cpp', 'fileA.cpp', 'a4.cpp']},
                'trivialprog7@exe': {'name': 'trivialprog7', 'sources': ['fileB.cpp', 'fileC.cpp', 'a1.cpp', 'a2.cpp', 'a6.cpp', 'fileA.cpp', 'main.cpp']},
                'trivialprog8@exe': {'name': 'trivialprog8', 'sources': ['a1.cpp', 'a2.cpp', 'a6.cpp', 'fileA.cpp', 'main.cpp']},
                'trivialprog9@exe': {'name': 'trivialprog9', 'sources': ['a1.cpp', 'a2.cpp', 'a6.cpp', 'fileA.cpp', 'main.cpp']},
            }
        }
        self.assertDictEqual(out, expected)

        # Check the written file
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))
        self.assertDictEqual(out, expected)

    def test_target_add_sources_abs(self):
        self.prime('1 basic')
        abs_src = [os.path.join(self.builddir, x) for x in ['a1.cpp', 'a2.cpp', 'a6.cpp']]
        add = json.dumps([{"type": "target", "target": "trivialprog1", "operation": "src_add", "sources": abs_src}])
        inf = json.dumps([{"type": "target", "target": "trivialprog1", "operation": "info"}])
        self.rewrite(self.builddir, add)
        out = self.rewrite(self.builddir, inf)
        expected = {'target': {'trivialprog1@exe': {'name': 'trivialprog1', 'sources': ['a1.cpp', 'a2.cpp', 'a6.cpp', 'fileA.cpp', 'main.cpp']}}}
        self.assertDictEqual(out, expected)

    def test_target_remove_sources(self):
        self.prime('1 basic')
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'rmSrc.json'))
        expected = {
            'target': {
                'trivialprog0@exe': {'name': 'trivialprog0', 'sources': ['main.cpp', 'fileC.cpp']},
                'trivialprog1@exe': {'name': 'trivialprog1', 'sources': ['main.cpp']},
                'trivialprog2@exe': {'name': 'trivialprog2', 'sources': ['fileC.cpp']},
                'trivialprog3@exe': {'name': 'trivialprog3', 'sources': ['main.cpp']},
                'trivialprog4@exe': {'name': 'trivialprog4', 'sources': ['main.cpp']},
                'trivialprog5@exe': {'name': 'trivialprog5', 'sources': ['main.cpp', 'fileC.cpp']},
                'trivialprog6@exe': {'name': 'trivialprog6', 'sources': ['main.cpp']},
                'trivialprog7@exe': {'name': 'trivialprog7', 'sources': ['fileC.cpp', 'main.cpp']},
                'trivialprog8@exe': {'name': 'trivialprog8', 'sources': ['main.cpp']},
                'trivialprog9@exe': {'name': 'trivialprog9', 'sources': ['main.cpp']},
            }
        }
        self.assertDictEqual(out, expected)

        # Check the written file
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))
        self.assertDictEqual(out, expected)

    def test_target_subdir(self):
        self.prime('2 subdirs')
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'addSrc.json'))
        expected = {'name': 'something', 'sources': ['first.c', 'second.c', 'third.c']}
        self.assertDictEqual(list(out['target'].values())[0], expected)

        # Check the written file
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))
        self.assertDictEqual(list(out['target'].values())[0], expected)

    def test_target_remove(self):
        self.prime('1 basic')
        self.rewrite(self.builddir, os.path.join(self.builddir, 'rmTgt.json'))
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))

        expected = {
            'target': {
                'trivialprog2@exe': {'name': 'trivialprog2', 'sources': ['fileB.cpp', 'fileC.cpp']},
                'trivialprog3@exe': {'name': 'trivialprog3', 'sources': ['main.cpp', 'fileA.cpp']},
                'trivialprog4@exe': {'name': 'trivialprog4', 'sources': ['main.cpp', 'fileA.cpp']},
                'trivialprog5@exe': {'name': 'trivialprog5', 'sources': ['main.cpp', 'fileB.cpp', 'fileC.cpp']},
                'trivialprog6@exe': {'name': 'trivialprog6', 'sources': ['main.cpp', 'fileA.cpp']},
                'trivialprog7@exe': {'name': 'trivialprog7', 'sources': ['fileB.cpp', 'fileC.cpp', 'main.cpp', 'fileA.cpp']},
                'trivialprog8@exe': {'name': 'trivialprog8', 'sources': ['main.cpp', 'fileA.cpp']},
            }
        }
        self.assertDictEqual(out, expected)

    def test_tatrget_add(self):
        self.prime('1 basic')
        self.rewrite(self.builddir, os.path.join(self.builddir, 'addTgt.json'))
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))

        expected = {
            'target': {
                'trivialprog0@exe': {'name': 'trivialprog0', 'sources': ['main.cpp', 'fileA.cpp', 'fileB.cpp', 'fileC.cpp']},
                'trivialprog1@exe': {'name': 'trivialprog1', 'sources': ['main.cpp', 'fileA.cpp']},
                'trivialprog2@exe': {'name': 'trivialprog2', 'sources': ['fileB.cpp', 'fileC.cpp']},
                'trivialprog3@exe': {'name': 'trivialprog3', 'sources': ['main.cpp', 'fileA.cpp']},
                'trivialprog4@exe': {'name': 'trivialprog4', 'sources': ['main.cpp', 'fileA.cpp']},
                'trivialprog5@exe': {'name': 'trivialprog5', 'sources': ['main.cpp', 'fileB.cpp', 'fileC.cpp']},
                'trivialprog6@exe': {'name': 'trivialprog6', 'sources': ['main.cpp', 'fileA.cpp']},
                'trivialprog7@exe': {'name': 'trivialprog7', 'sources': ['fileB.cpp', 'fileC.cpp', 'main.cpp', 'fileA.cpp']},
                'trivialprog8@exe': {'name': 'trivialprog8', 'sources': ['main.cpp', 'fileA.cpp']},
                'trivialprog9@exe': {'name': 'trivialprog9', 'sources': ['main.cpp', 'fileA.cpp']},
                'trivialprog10@sha': {'name': 'trivialprog10', 'sources': ['new1.cpp', 'new2.cpp']},
            }
        }
        self.assertDictEqual(out, expected)

    def test_target_remove_subdir(self):
        self.prime('2 subdirs')
        self.rewrite(self.builddir, os.path.join(self.builddir, 'rmTgt.json'))
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))
        self.assertDictEqual(out, {})

    def test_target_add_subdir(self):
        self.prime('2 subdirs')
        self.rewrite(self.builddir, os.path.join(self.builddir, 'addTgt.json'))
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))
        expected = {'name': 'something', 'sources': ['first.c', 'second.c']}
        self.assertDictEqual(out['target']['94b671c@@something@exe'], expected)

    def test_target_source_sorting(self):
        self.prime('5 sorting')
        add_json = json.dumps([{'type': 'target', 'target': 'exe1', 'operation': 'src_add', 'sources': ['a666.c']}])
        inf_json = json.dumps([{'type': 'target', 'target': 'exe1', 'operation': 'info'}])
        out = self.rewrite(self.builddir, add_json)
        out = self.rewrite(self.builddir, inf_json)
        expected = {
            'target': {
                'exe1@exe': {
                    'name': 'exe1',
                    'sources': [
                        'aaa/a/a1.c',
                        'aaa/b/b1.c',
                        'aaa/b/b2.c',
                        'aaa/f1.c',
                        'aaa/f2.c',
                        'aaa/f3.c',
                        'bbb/a/b1.c',
                        'bbb/b/b2.c',
                        'bbb/c1/b5.c',
                        'bbb/c2/b7.c',
                        'bbb/c10/b6.c',
                        'bbb/a4.c',
                        'bbb/b3.c',
                        'bbb/b4.c',
                        'bbb/b5.c',
                        'a1.c',
                        'a2.c',
                        'a3.c',
                        'a10.c',
                        'a20.c',
                        'a30.c',
                        'a100.c',
                        'a101.c',
                        'a110.c',
                        'a210.c',
                        'a666.c',
                        'b1.c',
                        'c2.c'
                    ]
                }
            }
        }
        self.assertDictEqual(out, expected)

    def test_target_same_name_skip(self):
        self.prime('4 same name targets')
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'addSrc.json'))
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))
        expected = {'name': 'myExe', 'sources': ['main.cpp']}
        self.assertEqual(len(out['target']), 2)
        for val in out['target'].values():
            self.assertDictEqual(expected, val)

    def test_kwargs_info(self):
        self.prime('3 kwargs')
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))
        expected = {
            'kwargs': {
                'project#/': {'version': '0.0.1'},
                'target#tgt1': {'build_by_default': True},
                'dependency#dep1': {'required': False}
            }
        }
        self.assertDictEqual(out, expected)

    def test_kwargs_set(self):
        self.prime('3 kwargs')
        self.rewrite(self.builddir, os.path.join(self.builddir, 'set.json'))
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))
        expected = {
            'kwargs': {
                'project#/': {'version': '0.0.2', 'meson_version': '0.50.0', 'license': ['GPL', 'MIT']},
                'target#tgt1': {'build_by_default': False, 'build_rpath': '/usr/local', 'dependencies': 'dep1'},
                'dependency#dep1': {'required': True, 'method': 'cmake'}
            }
        }
        self.assertDictEqual(out, expected)

    def test_kwargs_add(self):
        self.prime('3 kwargs')
        self.rewrite(self.builddir, os.path.join(self.builddir, 'add.json'))
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))
        expected = {
            'kwargs': {
                'project#/': {'version': '0.0.1', 'license': ['GPL', 'MIT', 'BSD']},
                'target#tgt1': {'build_by_default': True},
                'dependency#dep1': {'required': False}
            }
        }
        self.assertDictEqual(out, expected)

    def test_kwargs_remove(self):
        self.prime('3 kwargs')
        self.rewrite(self.builddir, os.path.join(self.builddir, 'remove.json'))
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))
        expected = {
            'kwargs': {
                'project#/': {'version': '0.0.1', 'license': 'GPL'},
                'target#tgt1': {'build_by_default': True},
                'dependency#dep1': {'required': False}
            }
        }
        self.assertDictEqual(out, expected)

    def test_kwargs_remove_regex(self):
        self.prime('3 kwargs')
        self.rewrite(self.builddir, os.path.join(self.builddir, 'remove_regex.json'))
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))
        expected = {
            'kwargs': {
                'project#/': {'version': '0.0.1', 'default_options': ['buildtype=release', 'debug=true']},
                'target#tgt1': {'build_by_default': True},
                'dependency#dep1': {'required': False}
            }
        }
        self.assertDictEqual(out, expected)

    def test_kwargs_delete(self):
        self.prime('3 kwargs')
        self.rewrite(self.builddir, os.path.join(self.builddir, 'delete.json'))
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))
        expected = {
            'kwargs': {
                'project#/': {},
                'target#tgt1': {},
                'dependency#dep1': {'required': False}
            }
        }
        self.assertDictEqual(out, expected)

    def test_default_options_set(self):
        self.prime('3 kwargs')
        self.rewrite(self.builddir, os.path.join(self.builddir, 'defopts_set.json'))
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))
        expected = {
            'kwargs': {
                'project#/': {'version': '0.0.1', 'default_options': ['buildtype=release', 'debug=True', 'cpp_std=c++11']},
                'target#tgt1': {'build_by_default': True},
                'dependency#dep1': {'required': False}
            }
        }
        self.assertDictEqual(out, expected)

    def test_default_options_delete(self):
        self.prime('3 kwargs')
        self.rewrite(self.builddir, os.path.join(self.builddir, 'defopts_delete.json'))
        out = self.rewrite(self.builddir, os.path.join(self.builddir, 'info.json'))
        expected = {
            'kwargs': {
                'project#/': {'version': '0.0.1', 'default_options': ['cpp_std=c++14', 'debug=true']},
                'target#tgt1': {'build_by_default': True},
                'dependency#dep1': {'required': False}
            }
        }
        self.assertDictEqual(out, expected)

class NativeFileTests(BasePlatformTests):

    def setUp(self):
        super().setUp()
        self.testcase = os.path.join(self.unit_test_dir, '47 native file binary')
        self.current_config = 0
        self.current_wrapper = 0

    def helper_create_native_file(self, values):
        """Create a config file as a temporary file.

        values should be a nested dictionary structure of {section: {key:
        value}}
        """
        filename = os.path.join(self.builddir, 'generated{}.config'.format(self.current_config))
        self.current_config += 1
        with open(filename, 'wt') as f:
            for section, entries in values.items():
                f.write('[{}]\n'.format(section))
                for k, v in entries.items():
                    f.write("{}='{}'\n".format(k, v))
        return filename

    def helper_create_binary_wrapper(self, binary, dir_=None, extra_args=None, **kwargs):
        """Creates a wrapper around a binary that overrides specific values."""
        filename = os.path.join(dir_ or self.builddir, 'binary_wrapper{}.py'.format(self.current_wrapper))
        extra_args = extra_args or {}
        self.current_wrapper += 1
        if is_haiku():
            chbang = '#!/bin/env python3'
        else:
            chbang = '#!/usr/bin/env python3'

        with open(filename, 'wt') as f:
            f.write(textwrap.dedent('''\
                {}
                import argparse
                import subprocess
                import sys

                def main():
                    parser = argparse.ArgumentParser()
                '''.format(chbang)))
            for name in chain(extra_args, kwargs):
                f.write('    parser.add_argument("-{0}", "--{0}", action="store_true")\n'.format(name))
            f.write('    args, extra_args = parser.parse_known_args()\n')
            for name, value in chain(extra_args.items(), kwargs.items()):
                f.write('    if args.{}:\n'.format(name))
                f.write('        print("{}", file=sys.{})\n'.format(value, kwargs.get('outfile', 'stdout')))
                f.write('        sys.exit(0)\n')
            f.write(textwrap.dedent('''
                    ret = subprocess.run(
                        ["{}"] + extra_args,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE)
                    print(ret.stdout.decode('utf-8'))
                    print(ret.stderr.decode('utf-8'), file=sys.stderr)
                    sys.exit(ret.returncode)

                if __name__ == '__main__':
                    main()
                '''.format(binary)))

        if not is_windows():
            os.chmod(filename, 0o755)
            return filename

        # On windows we need yet another level of indirection, as cmd cannot
        # invoke python files itself, so instead we generate a .bat file, which
        # invokes our python wrapper
        batfile = os.path.join(self.builddir, 'binary_wrapper{}.bat'.format(self.current_wrapper))
        with open(batfile, 'wt') as f:
            f.write(r'@{} {} %*'.format(sys.executable, filename))
        return batfile

    def helper_for_compiler(self, lang, cb, for_machine = MachineChoice.HOST):
        """Helper for generating tests for overriding compilers for langaugages
        with more than one implementation, such as C, C++, ObjC, ObjC++, and D.
        """
        env = get_fake_env()
        getter = getattr(env, 'detect_{}_compiler'.format(lang))
        getter = functools.partial(getter, for_machine)
        cc = getter()
        binary, newid = cb(cc)
        env.binaries[for_machine].binaries[lang] = binary
        compiler = getter()
        self.assertEqual(compiler.id, newid)

    def test_multiple_native_files_override(self):
        wrapper = self.helper_create_binary_wrapper('bash', version='foo')
        config = self.helper_create_native_file({'binaries': {'bash': wrapper}})
        wrapper = self.helper_create_binary_wrapper('bash', version='12345')
        config2 = self.helper_create_native_file({'binaries': {'bash': wrapper}})
        self.init(self.testcase, extra_args=[
            '--native-file', config, '--native-file', config2,
            '-Dcase=find_program'])

    # This test hangs on cygwin.
    @unittest.skipIf(os.name != 'posix' or is_cygwin(), 'Uses fifos, which are not available on non Unix OSes.')
    def test_native_file_is_pipe(self):
        fifo = os.path.join(self.builddir, 'native.file')
        os.mkfifo(fifo)
        with tempfile.TemporaryDirectory() as d:
            wrapper = self.helper_create_binary_wrapper('bash', d, version='12345')

            def filler():
                with open(fifo, 'w') as f:
                    f.write('[binaries]\n')
                    f.write("bash = '{}'\n".format(wrapper))

            thread = threading.Thread(target=filler)
            thread.start()

            self.init(self.testcase, extra_args=['--native-file', fifo, '-Dcase=find_program'])

            thread.join()
            os.unlink(fifo)

            self.init(self.testcase, extra_args=['--wipe'])

    def test_multiple_native_files(self):
        wrapper = self.helper_create_binary_wrapper('bash', version='12345')
        config = self.helper_create_native_file({'binaries': {'bash': wrapper}})
        wrapper = self.helper_create_binary_wrapper('python')
        config2 = self.helper_create_native_file({'binaries': {'python': wrapper}})
        self.init(self.testcase, extra_args=[
            '--native-file', config, '--native-file', config2,
            '-Dcase=find_program'])

    def _simple_test(self, case, binary, entry=None):
        wrapper = self.helper_create_binary_wrapper(binary, version='12345')
        config = self.helper_create_native_file({'binaries': {entry or binary: wrapper}})
        self.init(self.testcase, extra_args=['--native-file', config, '-Dcase={}'.format(case)])

    def test_find_program(self):
        self._simple_test('find_program', 'bash')

    def test_config_tool_dep(self):
        # Do the skip at this level to avoid screwing up the cache
        if mesonbuild.environment.detect_msys2_arch():
            raise unittest.SkipTest('Skipped due to problems with LLVM on MSYS2')
        if not shutil.which('llvm-config'):
            raise unittest.SkipTest('No llvm-installed, cannot test')
        self._simple_test('config_dep', 'llvm-config')

    def test_python3_module(self):
        self._simple_test('python3', 'python3')

    def test_python_module(self):
        if is_windows():
            # Bat adds extra crap to stdout, so the version check logic in the
            # python module breaks. This is fine on other OSes because they
            # don't need the extra indirection.
            raise unittest.SkipTest('bat indirection breaks internal sanity checks.')
        elif is_osx():
            binary = 'python'
        else:
            binary = 'python2'

            # We not have python2, check for it
            for v in ['2', '2.7', '-2.7']:
                rc = subprocess.call(['pkg-config', '--cflags', 'python{}'.format(v)],
                                     stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
                if rc == 0:
                    break
            else:
                raise unittest.SkipTest('Not running Python 2 tests because dev packages not installed.')
        self._simple_test('python', binary, entry='python')

    @unittest.skipIf(is_windows(), 'Setting up multiple compilers on windows is hard')
    @skip_if_env_set('CC')
    def test_c_compiler(self):
        def cb(comp):
            if comp.id == 'gcc':
                if not shutil.which('clang'):
                    raise unittest.SkipTest('Only one compiler found, cannot test.')
                return 'clang', 'clang'
            if not is_real_gnu_compiler(shutil.which('gcc')):
                raise unittest.SkipTest('Only one compiler found, cannot test.')
            return 'gcc', 'gcc'
        self.helper_for_compiler('c', cb)

    @unittest.skipIf(is_windows(), 'Setting up multiple compilers on windows is hard')
    @skip_if_env_set('CXX')
    def test_cpp_compiler(self):
        def cb(comp):
            if comp.id == 'gcc':
                if not shutil.which('clang++'):
                    raise unittest.SkipTest('Only one compiler found, cannot test.')
                return 'clang++', 'clang'
            if not is_real_gnu_compiler(shutil.which('g++')):
                raise unittest.SkipTest('Only one compiler found, cannot test.')
            return 'g++', 'gcc'
        self.helper_for_compiler('cpp', cb)

    @skip_if_not_language('objc')
    @skip_if_env_set('OBJC')
    def test_objc_compiler(self):
        def cb(comp):
            if comp.id == 'gcc':
                if not shutil.which('clang'):
                    raise unittest.SkipTest('Only one compiler found, cannot test.')
                return 'clang', 'clang'
            if not is_real_gnu_compiler(shutil.which('gcc')):
                raise unittest.SkipTest('Only one compiler found, cannot test.')
            return 'gcc', 'gcc'
        self.helper_for_compiler('objc', cb)

    @skip_if_not_language('objcpp')
    @skip_if_env_set('OBJCXX')
    def test_objcpp_compiler(self):
        def cb(comp):
            if comp.id == 'gcc':
                if not shutil.which('clang++'):
                    raise unittest.SkipTest('Only one compiler found, cannot test.')
                return 'clang++', 'clang'
            if not is_real_gnu_compiler(shutil.which('g++')):
                raise unittest.SkipTest('Only one compiler found, cannot test.')
            return 'g++', 'gcc'
        self.helper_for_compiler('objcpp', cb)

    @skip_if_not_language('d')
    @skip_if_env_set('DC')
    def test_d_compiler(self):
        def cb(comp):
            if comp.id == 'dmd':
                if shutil.which('ldc'):
                    return 'ldc', 'ldc'
                elif shutil.which('gdc'):
                    return 'gdc', 'gdc'
                else:
                    raise unittest.SkipTest('No alternative dlang compiler found.')
            if shutil.which('dmd'):
                return 'dmd', 'dmd'
            raise unittest.SkipTest('No alternative dlang compiler found.')
        self.helper_for_compiler('d', cb)

    @skip_if_not_language('cs')
    @skip_if_env_set('CSC')
    def test_cs_compiler(self):
        def cb(comp):
            if comp.id == 'csc':
                if not shutil.which('mcs'):
                    raise unittest.SkipTest('No alternate C# implementation.')
                return 'mcs', 'mcs'
            if not shutil.which('csc'):
                raise unittest.SkipTest('No alternate C# implementation.')
            return 'csc', 'csc'
        self.helper_for_compiler('cs', cb)

    @skip_if_not_language('fortran')
    @skip_if_env_set('FC')
    def test_fortran_compiler(self):
        def cb(comp):
            if comp.id == 'lcc':
                if shutil.which('lfortran'):
                    return 'lfortran', 'lcc'
                raise unittest.SkipTest('No alternate Fortran implementation.')
            elif comp.id == 'gcc':
                if shutil.which('ifort'):
                    # There is an ICC for windows (windows build, linux host),
                    # but we don't support that ATM so lets not worry about it.
                    if is_windows():
                        return 'ifort', 'intel-cl'
                    return 'ifort', 'intel'
                elif shutil.which('flang'):
                    return 'flang', 'flang'
                elif shutil.which('pgfortran'):
                    return 'pgfortran', 'pgi'
                # XXX: there are several other fortran compilers meson
                # supports, but I don't have any of them to test with
                raise unittest.SkipTest('No alternate Fortran implementation.')
            if not shutil.which('gfortran'):
                raise unittest.SkipTest('No alternate Fortran implementation.')
            return 'gfortran', 'gcc'
        self.helper_for_compiler('fortran', cb)

    def _single_implementation_compiler(self, lang, binary, version_str, version):
        """Helper for languages with a single (supported) implementation.

        Builds a wrapper around the compiler to override the version.
        """
        wrapper = self.helper_create_binary_wrapper(binary, version=version_str)
        env = get_fake_env()
        getter = getattr(env, 'detect_{}_compiler'.format(lang))
        getter = functools.partial(getter, MachineChoice.HOST)
        env.binaries.host.binaries[lang] = wrapper
        compiler = getter()
        self.assertEqual(compiler.version, version)

    @skip_if_not_language('vala')
    @skip_if_env_set('VALAC')
    def test_vala_compiler(self):
        self._single_implementation_compiler(
            'vala', 'valac', 'Vala 1.2345', '1.2345')

    @skip_if_not_language('rust')
    @skip_if_env_set('RUSTC')
    def test_rust_compiler(self):
        self._single_implementation_compiler(
            'rust', 'rustc', 'rustc 1.2345', '1.2345')

    @skip_if_not_language('java')
    def test_java_compiler(self):
        self._single_implementation_compiler(
            'java', 'javac', 'javac 9.99.77', '9.99.77')

    @skip_if_not_language('swift')
    def test_swift_compiler(self):
        wrapper = self.helper_create_binary_wrapper(
            'swiftc', version='Swift 1.2345', outfile='stderr',
            extra_args={'Xlinker': 'macosx_version. PROJECT:ld - 1.2.3'})
        env = get_fake_env()
        env.binaries.host.binaries['swift'] = wrapper
        compiler = env.detect_swift_compiler(MachineChoice.HOST)
        self.assertEqual(compiler.version, '1.2345')

    def test_native_file_dirs(self):
        testcase = os.path.join(self.unit_test_dir, '60 native file override')
        self.init(testcase, default_args=False,
                  extra_args=['--native-file', os.path.join(testcase, 'nativefile')])

    def test_native_file_dirs_overriden(self):
        testcase = os.path.join(self.unit_test_dir, '60 native file override')
        self.init(testcase, default_args=False,
                  extra_args=['--native-file', os.path.join(testcase, 'nativefile'),
                              '-Ddef_libdir=liblib', '-Dlibdir=liblib'])

    def test_compile_sys_path(self):
        """Compiling with a native file stored in a system path works.

        There was a bug which caused the paths to be stored incorrectly and
        would result in ninja invoking meson in an infinite loop. This tests
        for that by actually invoking ninja.
        """
        testcase = os.path.join(self.common_test_dir, '1 trivial')

        # It really doesn't matter what's in the native file, just that it exists
        config = self.helper_create_native_file({'binaries': {'bash': 'false'}})

        self.init(testcase, extra_args=['--native-file', config])
        self.build()


class CrossFileTests(BasePlatformTests):

    """Tests for cross file functionality not directly related to
    cross compiling.

    This is mainly aimed to testing overrides from cross files.
    """

    def _cross_file_generator(self, *, needs_exe_wrapper: bool = False,
                              exe_wrapper: T.Optional[T.List[str]] = None) -> str:
        if is_windows():
            raise unittest.SkipTest('Cannot run this test on non-mingw/non-cygwin windows')
        if is_sunos():
            cc = 'gcc'
        else:
            cc = 'cc'

        return textwrap.dedent("""\
            [binaries]
            c = '/usr/bin/{}'
            ar = '/usr/bin/ar'
            strip = '/usr/bin/ar'
            {}

            [properties]
            needs_exe_wrapper = {}

            [host_machine]
            system = 'linux'
            cpu_family = 'x86'
            cpu = 'i686'
            endian = 'little'
            """.format(cc,
                       'exe_wrapper = {}'.format(str(exe_wrapper)) if exe_wrapper is not None else '',
                       needs_exe_wrapper))

    def _stub_exe_wrapper(self) -> str:
        return textwrap.dedent('''\
            #!/usr/bin/env python3
            import subprocess
            import sys

            sys.exit(subprocess.run(sys.argv[1:]).returncode)
            ''')

    def test_needs_exe_wrapper_true(self):
        testdir = os.path.join(self.unit_test_dir, '72 cross test passed')
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'crossfile'
            with p.open('wt') as f:
                f.write(self._cross_file_generator(needs_exe_wrapper=True))
            self.init(testdir, extra_args=['--cross-file=' + str(p)])
            out = self.run_target('test')
            self.assertRegex(out, r'Skipped:\s*1\s*\n')

    def test_needs_exe_wrapper_false(self):
        testdir = os.path.join(self.unit_test_dir, '72 cross test passed')
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'crossfile'
            with p.open('wt') as f:
                f.write(self._cross_file_generator(needs_exe_wrapper=False))
            self.init(testdir, extra_args=['--cross-file=' + str(p)])
            out = self.run_target('test')
            self.assertNotRegex(out, r'Skipped:\s*1\n')

    def test_needs_exe_wrapper_true_wrapper(self):
        testdir = os.path.join(self.unit_test_dir, '72 cross test passed')
        with tempfile.TemporaryDirectory() as d:
            s = Path(d) / 'wrapper.py'
            with s.open('wt') as f:
                f.write(self._stub_exe_wrapper())
            s.chmod(0o774)
            p = Path(d) / 'crossfile'
            with p.open('wt') as f:
                f.write(self._cross_file_generator(
                    needs_exe_wrapper=True,
                    exe_wrapper=[str(s)]))

            self.init(testdir, extra_args=['--cross-file=' + str(p), '-Dexpect=true'])
            out = self.run_target('test')
            self.assertRegex(out, r'Ok:\s*3\s*\n')

    def test_cross_exe_passed_no_wrapper(self):
        testdir = os.path.join(self.unit_test_dir, '72 cross test passed')
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'crossfile'
            with p.open('wt') as f:
                f.write(self._cross_file_generator(needs_exe_wrapper=True))

            self.init(testdir, extra_args=['--cross-file=' + str(p)])
            self.build()
            out = self.run_target('test')
            self.assertRegex(out, r'Skipped:\s*1\s*\n')

    # The test uses mocking and thus requires that the current process is the
    # one to run the Meson steps. If we are using an external test executable
    # (most commonly in Debian autopkgtests) then the mocking won't work.
    @unittest.skipIf('MESON_EXE' in os.environ, 'MESON_EXE is defined, can not use mocking.')
    def test_cross_file_system_paths(self):
        if is_windows():
            raise unittest.SkipTest('system crossfile paths not defined for Windows (yet)')

        testdir = os.path.join(self.common_test_dir, '1 trivial')
        cross_content = self._cross_file_generator()
        with tempfile.TemporaryDirectory() as d:
            dir_ = os.path.join(d, 'meson', 'cross')
            os.makedirs(dir_)
            with tempfile.NamedTemporaryFile('w', dir=dir_, delete=False) as f:
                f.write(cross_content)
            name = os.path.basename(f.name)

            with mock.patch.dict(os.environ, {'XDG_DATA_HOME': d}):
                self.init(testdir, extra_args=['--cross-file=' + name], inprocess=True)
                self.wipe()

            with mock.patch.dict(os.environ, {'XDG_DATA_DIRS': d}):
                os.environ.pop('XDG_DATA_HOME', None)
                self.init(testdir, extra_args=['--cross-file=' + name], inprocess=True)
                self.wipe()

        with tempfile.TemporaryDirectory() as d:
            dir_ = os.path.join(d, '.local', 'share', 'meson', 'cross')
            os.makedirs(dir_)
            with tempfile.NamedTemporaryFile('w', dir=dir_, delete=False) as f:
                f.write(cross_content)
            name = os.path.basename(f.name)

            # If XDG_DATA_HOME is set in the environment running the
            # tests this test will fail, os mock the environment, pop
            # it, then test
            with mock.patch.dict(os.environ):
                os.environ.pop('XDG_DATA_HOME', None)
                with mock.patch('mesonbuild.coredata.os.path.expanduser', lambda x: x.replace('~', d)):
                    self.init(testdir, extra_args=['--cross-file=' + name], inprocess=True)
                    self.wipe()

    def test_cross_file_dirs(self):
        testcase = os.path.join(self.unit_test_dir, '60 native file override')
        self.init(testcase, default_args=False,
                  extra_args=['--native-file', os.path.join(testcase, 'nativefile'),
                              '--cross-file', os.path.join(testcase, 'crossfile'),
                              '-Ddef_bindir=binbar',
                              '-Ddef_datadir=databar',
                              '-Ddef_includedir=includebar',
                              '-Ddef_infodir=infobar',
                              '-Ddef_libdir=libbar',
                              '-Ddef_libexecdir=libexecbar',
                              '-Ddef_localedir=localebar',
                              '-Ddef_localstatedir=localstatebar',
                              '-Ddef_mandir=manbar',
                              '-Ddef_sbindir=sbinbar',
                              '-Ddef_sharedstatedir=sharedstatebar',
                              '-Ddef_sysconfdir=sysconfbar'])

    def test_cross_file_dirs_overriden(self):
        testcase = os.path.join(self.unit_test_dir, '60 native file override')
        self.init(testcase, default_args=False,
                  extra_args=['--native-file', os.path.join(testcase, 'nativefile'),
                              '--cross-file', os.path.join(testcase, 'crossfile'),
                              '-Ddef_libdir=liblib', '-Dlibdir=liblib',
                              '-Ddef_bindir=binbar',
                              '-Ddef_datadir=databar',
                              '-Ddef_includedir=includebar',
                              '-Ddef_infodir=infobar',
                              '-Ddef_libexecdir=libexecbar',
                              '-Ddef_localedir=localebar',
                              '-Ddef_localstatedir=localstatebar',
                              '-Ddef_mandir=manbar',
                              '-Ddef_sbindir=sbinbar',
                              '-Ddef_sharedstatedir=sharedstatebar',
                              '-Ddef_sysconfdir=sysconfbar'])

    def test_cross_file_dirs_chain(self):
        # crossfile2 overrides crossfile overrides nativefile
        testcase = os.path.join(self.unit_test_dir, '60 native file override')
        self.init(testcase, default_args=False,
                  extra_args=['--native-file', os.path.join(testcase, 'nativefile'),
                              '--cross-file', os.path.join(testcase, 'crossfile'),
                              '--cross-file', os.path.join(testcase, 'crossfile2'),
                              '-Ddef_bindir=binbar2',
                              '-Ddef_datadir=databar',
                              '-Ddef_includedir=includebar',
                              '-Ddef_infodir=infobar',
                              '-Ddef_libdir=libbar',
                              '-Ddef_libexecdir=libexecbar',
                              '-Ddef_localedir=localebar',
                              '-Ddef_localstatedir=localstatebar',
                              '-Ddef_mandir=manbar',
                              '-Ddef_sbindir=sbinbar',
                              '-Ddef_sharedstatedir=sharedstatebar',
                              '-Ddef_sysconfdir=sysconfbar'])

class TAPParserTests(unittest.TestCase):
    def assert_test(self, events, **kwargs):
        if 'explanation' not in kwargs:
            kwargs['explanation'] = None
        self.assertEqual(next(events), TAPParser.Test(**kwargs))

    def assert_plan(self, events, **kwargs):
        if 'skipped' not in kwargs:
            kwargs['skipped'] = False
        if 'explanation' not in kwargs:
            kwargs['explanation'] = None
        self.assertEqual(next(events), TAPParser.Plan(**kwargs))

    def assert_version(self, events, **kwargs):
        self.assertEqual(next(events), TAPParser.Version(**kwargs))

    def assert_error(self, events):
        self.assertEqual(type(next(events)), TAPParser.Error)

    def assert_bailout(self, events, **kwargs):
        self.assertEqual(next(events), TAPParser.Bailout(**kwargs))

    def assert_last(self, events):
        with self.assertRaises(StopIteration):
            next(events)

    def parse_tap(self, s):
        parser = TAPParser(io.StringIO(s))
        return iter(parser.parse())

    def parse_tap_v13(self, s):
        events = self.parse_tap('TAP version 13\n' + s)
        self.assert_version(events, version=13)
        return events

    def test_empty(self):
        events = self.parse_tap('')
        self.assert_last(events)

    def test_empty_plan(self):
        events = self.parse_tap('1..0')
        self.assert_plan(events, count=0, late=False, skipped=True)
        self.assert_last(events)

    def test_plan_directive(self):
        events = self.parse_tap('1..0 # skipped for some reason')
        self.assert_plan(events, count=0, late=False, skipped=True,
                         explanation='for some reason')
        self.assert_last(events)

        events = self.parse_tap('1..1 # skipped for some reason\nok 1')
        self.assert_error(events)
        self.assert_plan(events, count=1, late=False, skipped=True,
                         explanation='for some reason')
        self.assert_test(events, number=1, name='', result=TestResult.OK)
        self.assert_last(events)

        events = self.parse_tap('1..1 # todo not supported here\nok 1')
        self.assert_error(events)
        self.assert_plan(events, count=1, late=False, skipped=False,
                         explanation='not supported here')
        self.assert_test(events, number=1, name='', result=TestResult.OK)
        self.assert_last(events)

    def test_one_test_ok(self):
        events = self.parse_tap('ok')
        self.assert_test(events, number=1, name='', result=TestResult.OK)
        self.assert_last(events)

    def test_one_test_with_number(self):
        events = self.parse_tap('ok 1')
        self.assert_test(events, number=1, name='', result=TestResult.OK)
        self.assert_last(events)

    def test_one_test_with_name(self):
        events = self.parse_tap('ok 1 abc')
        self.assert_test(events, number=1, name='abc', result=TestResult.OK)
        self.assert_last(events)

    def test_one_test_not_ok(self):
        events = self.parse_tap('not ok')
        self.assert_test(events, number=1, name='', result=TestResult.FAIL)
        self.assert_last(events)

    def test_one_test_todo(self):
        events = self.parse_tap('not ok 1 abc # TODO')
        self.assert_test(events, number=1, name='abc', result=TestResult.EXPECTEDFAIL)
        self.assert_last(events)

        events = self.parse_tap('ok 1 abc # TODO')
        self.assert_test(events, number=1, name='abc', result=TestResult.UNEXPECTEDPASS)
        self.assert_last(events)

    def test_one_test_skip(self):
        events = self.parse_tap('ok 1 abc # SKIP')
        self.assert_test(events, number=1, name='abc', result=TestResult.SKIP)
        self.assert_last(events)

    def test_one_test_skip_failure(self):
        events = self.parse_tap('not ok 1 abc # SKIP')
        self.assert_test(events, number=1, name='abc', result=TestResult.FAIL)
        self.assert_last(events)

    def test_many_early_plan(self):
        events = self.parse_tap('1..4\nok 1\nnot ok 2\nok 3\nnot ok 4')
        self.assert_plan(events, count=4, late=False)
        self.assert_test(events, number=1, name='', result=TestResult.OK)
        self.assert_test(events, number=2, name='', result=TestResult.FAIL)
        self.assert_test(events, number=3, name='', result=TestResult.OK)
        self.assert_test(events, number=4, name='', result=TestResult.FAIL)
        self.assert_last(events)

    def test_many_late_plan(self):
        events = self.parse_tap('ok 1\nnot ok 2\nok 3\nnot ok 4\n1..4')
        self.assert_test(events, number=1, name='', result=TestResult.OK)
        self.assert_test(events, number=2, name='', result=TestResult.FAIL)
        self.assert_test(events, number=3, name='', result=TestResult.OK)
        self.assert_test(events, number=4, name='', result=TestResult.FAIL)
        self.assert_plan(events, count=4, late=True)
        self.assert_last(events)

    def test_directive_case(self):
        events = self.parse_tap('ok 1 abc # skip')
        self.assert_test(events, number=1, name='abc', result=TestResult.SKIP)
        self.assert_last(events)

        events = self.parse_tap('ok 1 abc # ToDo')
        self.assert_test(events, number=1, name='abc', result=TestResult.UNEXPECTEDPASS)
        self.assert_last(events)

    def test_directive_explanation(self):
        events = self.parse_tap('ok 1 abc # skip why')
        self.assert_test(events, number=1, name='abc', result=TestResult.SKIP,
                         explanation='why')
        self.assert_last(events)

        events = self.parse_tap('ok 1 abc # ToDo Because')
        self.assert_test(events, number=1, name='abc', result=TestResult.UNEXPECTEDPASS,
                         explanation='Because')
        self.assert_last(events)

    def test_one_test_early_plan(self):
        events = self.parse_tap('1..1\nok')
        self.assert_plan(events, count=1, late=False)
        self.assert_test(events, number=1, name='', result=TestResult.OK)
        self.assert_last(events)

    def test_one_test_late_plan(self):
        events = self.parse_tap('ok\n1..1')
        self.assert_test(events, number=1, name='', result=TestResult.OK)
        self.assert_plan(events, count=1, late=True)
        self.assert_last(events)

    def test_out_of_order(self):
        events = self.parse_tap('ok 2')
        self.assert_error(events)
        self.assert_test(events, number=2, name='', result=TestResult.OK)
        self.assert_last(events)

    def test_middle_plan(self):
        events = self.parse_tap('ok 1\n1..2\nok 2')
        self.assert_test(events, number=1, name='', result=TestResult.OK)
        self.assert_plan(events, count=2, late=True)
        self.assert_error(events)
        self.assert_test(events, number=2, name='', result=TestResult.OK)
        self.assert_last(events)

    def test_too_many_plans(self):
        events = self.parse_tap('1..1\n1..2\nok 1')
        self.assert_plan(events, count=1, late=False)
        self.assert_error(events)
        self.assert_test(events, number=1, name='', result=TestResult.OK)
        self.assert_last(events)

    def test_too_many(self):
        events = self.parse_tap('ok 1\nnot ok 2\n1..1')
        self.assert_test(events, number=1, name='', result=TestResult.OK)
        self.assert_test(events, number=2, name='', result=TestResult.FAIL)
        self.assert_plan(events, count=1, late=True)
        self.assert_error(events)
        self.assert_last(events)

        events = self.parse_tap('1..1\nok 1\nnot ok 2')
        self.assert_plan(events, count=1, late=False)
        self.assert_test(events, number=1, name='', result=TestResult.OK)
        self.assert_test(events, number=2, name='', result=TestResult.FAIL)
        self.assert_error(events)
        self.assert_last(events)

    def test_too_few(self):
        events = self.parse_tap('ok 1\nnot ok 2\n1..3')
        self.assert_test(events, number=1, name='', result=TestResult.OK)
        self.assert_test(events, number=2, name='', result=TestResult.FAIL)
        self.assert_plan(events, count=3, late=True)
        self.assert_error(events)
        self.assert_last(events)

        events = self.parse_tap('1..3\nok 1\nnot ok 2')
        self.assert_plan(events, count=3, late=False)
        self.assert_test(events, number=1, name='', result=TestResult.OK)
        self.assert_test(events, number=2, name='', result=TestResult.FAIL)
        self.assert_error(events)
        self.assert_last(events)

    def test_too_few_bailout(self):
        events = self.parse_tap('1..3\nok 1\nnot ok 2\nBail out! no third test')
        self.assert_plan(events, count=3, late=False)
        self.assert_test(events, number=1, name='', result=TestResult.OK)
        self.assert_test(events, number=2, name='', result=TestResult.FAIL)
        self.assert_bailout(events, message='no third test')
        self.assert_last(events)

    def test_diagnostics(self):
        events = self.parse_tap('1..1\n# ignored\nok 1')
        self.assert_plan(events, count=1, late=False)
        self.assert_test(events, number=1, name='', result=TestResult.OK)
        self.assert_last(events)

        events = self.parse_tap('# ignored\n1..1\nok 1\n# ignored too')
        self.assert_plan(events, count=1, late=False)
        self.assert_test(events, number=1, name='', result=TestResult.OK)
        self.assert_last(events)

        events = self.parse_tap('# ignored\nok 1\n1..1\n# ignored too')
        self.assert_test(events, number=1, name='', result=TestResult.OK)
        self.assert_plan(events, count=1, late=True)
        self.assert_last(events)

    def test_empty_line(self):
        events = self.parse_tap('1..1\n\nok 1')
        self.assert_plan(events, count=1, late=False)
        self.assert_test(events, number=1, name='', result=TestResult.OK)
        self.assert_last(events)

    def test_unexpected(self):
        events = self.parse_tap('1..1\ninvalid\nok 1')
        self.assert_plan(events, count=1, late=False)
        self.assert_error(events)
        self.assert_test(events, number=1, name='', result=TestResult.OK)
        self.assert_last(events)

    def test_version(self):
        events = self.parse_tap('TAP version 13\n')
        self.assert_version(events, version=13)
        self.assert_last(events)

        events = self.parse_tap('TAP version 12\n')
        self.assert_error(events)
        self.assert_last(events)

        events = self.parse_tap('1..0\nTAP version 13\n')
        self.assert_plan(events, count=0, late=False, skipped=True)
        self.assert_error(events)
        self.assert_last(events)

    def test_yaml(self):
        events = self.parse_tap_v13('ok\n ---\n foo: abc\n  bar: def\n ...\nok 2')
        self.assert_test(events, number=1, name='', result=TestResult.OK)
        self.assert_test(events, number=2, name='', result=TestResult.OK)
        self.assert_last(events)

        events = self.parse_tap_v13('ok\n ---\n foo: abc\n  bar: def')
        self.assert_test(events, number=1, name='', result=TestResult.OK)
        self.assert_error(events)
        self.assert_last(events)

        events = self.parse_tap_v13('ok 1\n ---\n foo: abc\n  bar: def\nnot ok 2')
        self.assert_test(events, number=1, name='', result=TestResult.OK)
        self.assert_error(events)
        self.assert_test(events, number=2, name='', result=TestResult.FAIL)
        self.assert_last(events)


def _clang_at_least(compiler, minver: str, apple_minver: str) -> bool:
    """
    check that Clang compiler is at least a specified version, whether AppleClang or regular Clang

    Parameters
    ----------
    compiler:
        Meson compiler object
    minver: str
        Clang minimum version
    apple_minver: str
        AppleCLang minimum version

    Returns
    -------
    at_least: bool
        Clang is at least the specified version
    """
    if isinstance(compiler, (mesonbuild.compilers.AppleClangCCompiler,
                             mesonbuild.compilers.AppleClangCPPCompiler)):
        return version_compare(compiler.version, apple_minver)
    return version_compare(compiler.version, minver)


def unset_envs():
    # For unit tests we must fully control all command lines
    # so that there are no unexpected changes coming from the
    # environment, for example when doing a package build.
    varnames = ['CPPFLAGS', 'LDFLAGS'] + list(mesonbuild.compilers.compilers.cflags_mapping.values())
    for v in varnames:
        if v in os.environ:
            del os.environ[v]

def convert_args(argv):
    # If we got passed a list of tests, pass it on
    pytest_args = ['-v'] if '-v' in argv else []
    test_list = []
    for arg in argv:
        if arg.startswith('-'):
            if arg in ('-f', '--failfast'):
                arg = '--exitfirst'
            pytest_args.append(arg)
            continue
        # ClassName.test_name => 'ClassName and test_name'
        if '.' in arg:
            arg = ' and '.join(arg.split('.'))
        test_list.append(arg)
    if test_list:
        pytest_args += ['-k', ' or '.join(test_list)]
    return pytest_args

def main():
    unset_envs()
    try:
        import pytest # noqa: F401
        # Need pytest-xdist for `-n` arg
        import xdist # noqa: F401
        pytest_args = ['-n', 'auto', './run_unittests.py']
        pytest_args += convert_args(sys.argv[1:])
        return subprocess.run(python_command + ['-m', 'pytest'] + pytest_args).returncode
    except ImportError:
        print('pytest-xdist not found, using unittest instead')
    # All attempts at locating pytest failed, fall back to plain unittest.
    cases = ['InternalTests', 'DataTests', 'AllPlatformTests', 'FailureTests',
             'PythonTests', 'NativeFileTests', 'RewriterTests', 'CrossFileTests',
             'TAPParserTests',

             'LinuxlikeTests', 'LinuxCrossArmTests', 'LinuxCrossMingwTests',
             'WindowsTests', 'DarwinTests']

    return unittest.main(defaultTest=cases, buffer=True)

if __name__ == '__main__':
    print('Meson build system', mesonbuild.coredata.version, 'Unit Tests')
    raise SystemExit(main())
