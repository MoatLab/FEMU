# Copyright 2012-2016 The Meson development team

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from collections import OrderedDict
from functools import lru_cache
from pathlib import Path
import enum
import json
import os
import pickle
import re
import shlex
import subprocess
import textwrap
import typing as T

from .. import build
from .. import dependencies
from .. import mesonlib
from .. import mlog
from ..mesonlib import (
    File, MachineChoice, MesonException, OrderedSet, OptionOverrideProxy,
    classify_unity_sources, unholder
)

if T.TYPE_CHECKING:
    from ..interpreter import Interpreter


class TestProtocol(enum.Enum):

    EXITCODE = 0
    TAP = 1
    GTEST = 2

    @classmethod
    def from_str(cls, string: str) -> 'TestProtocol':
        if string == 'exitcode':
            return cls.EXITCODE
        elif string == 'tap':
            return cls.TAP
        elif string == 'gtest':
            return cls.GTEST
        raise MesonException('unknown test format {}'.format(string))

    def __str__(self) -> str:
        if self is self.EXITCODE:
            return 'exitcode'
        elif self is self.GTEST:
            return 'gtest'
        return 'tap'


class CleanTrees:
    '''
    Directories outputted by custom targets that have to be manually cleaned
    because on Linux `ninja clean` only deletes empty directories.
    '''
    def __init__(self, build_dir, trees):
        self.build_dir = build_dir
        self.trees = trees

class InstallData:
    def __init__(self, source_dir, build_dir, prefix, strip_bin,
                 install_umask, mesonintrospect):
        self.source_dir = source_dir
        self.build_dir = build_dir
        self.prefix = prefix
        self.strip_bin = strip_bin
        self.install_umask = install_umask
        self.targets = []
        self.headers = []
        self.man = []
        self.data = []
        self.po_package_name = ''
        self.po = []
        self.install_scripts = []
        self.install_subdirs = []
        self.mesonintrospect = mesonintrospect

class TargetInstallData:
    def __init__(self, fname, outdir, aliases, strip, install_name_mappings, rpath_dirs_to_remove, install_rpath, install_mode, optional=False):
        self.fname = fname
        self.outdir = outdir
        self.aliases = aliases
        self.strip = strip
        self.install_name_mappings = install_name_mappings
        self.rpath_dirs_to_remove = rpath_dirs_to_remove
        self.install_rpath = install_rpath
        self.install_mode = install_mode
        self.optional = optional

class ExecutableSerialisation:
    def __init__(self, cmd_args, env=None, exe_wrapper=None,
                 workdir=None, extra_paths=None, capture=None):
        self.cmd_args = cmd_args
        self.env = env or {}
        if exe_wrapper is not None:
            assert(isinstance(exe_wrapper, dependencies.ExternalProgram))
        self.exe_runner = exe_wrapper
        self.workdir = workdir
        self.extra_paths = extra_paths
        self.capture = capture

class TestSerialisation:
    def __init__(self, name: str, project: str, suite: str, fname: T.List[str],
                 is_cross_built: bool, exe_wrapper: T.Optional[dependencies.ExternalProgram],
                 needs_exe_wrapper: bool, is_parallel: bool, cmd_args: T.List[str],
                 env: build.EnvironmentVariables, should_fail: bool,
                 timeout: T.Optional[int], workdir: T.Optional[str],
                 extra_paths: T.List[str], protocol: TestProtocol, priority: int,
                 cmd_is_built: bool):
        self.name = name
        self.project_name = project
        self.suite = suite
        self.fname = fname
        self.is_cross_built = is_cross_built
        if exe_wrapper is not None:
            assert(isinstance(exe_wrapper, dependencies.ExternalProgram))
        self.exe_runner = exe_wrapper
        self.is_parallel = is_parallel
        self.cmd_args = cmd_args
        self.env = env
        self.should_fail = should_fail
        self.timeout = timeout
        self.workdir = workdir
        self.extra_paths = extra_paths
        self.protocol = protocol
        self.priority = priority
        self.needs_exe_wrapper = needs_exe_wrapper
        self.cmd_is_built = cmd_is_built


def get_backend_from_name(backend: str, build: T.Optional[build.Build] = None, interpreter: T.Optional['Interpreter'] = None) -> T.Optional['Backend']:
    if backend == 'ninja':
        from . import ninjabackend
        return ninjabackend.NinjaBackend(build, interpreter)
    elif backend == 'vs':
        from . import vs2010backend
        return vs2010backend.autodetect_vs_version(build, interpreter)
    elif backend == 'vs2010':
        from . import vs2010backend
        return vs2010backend.Vs2010Backend(build, interpreter)
    elif backend == 'vs2015':
        from . import vs2015backend
        return vs2015backend.Vs2015Backend(build, interpreter)
    elif backend == 'vs2017':
        from . import vs2017backend
        return vs2017backend.Vs2017Backend(build, interpreter)
    elif backend == 'vs2019':
        from . import vs2019backend
        return vs2019backend.Vs2019Backend(build, interpreter)
    elif backend == 'xcode':
        from . import xcodebackend
        return xcodebackend.XCodeBackend(build, interpreter)
    return None

# This class contains the basic functionality that is needed by all backends.
# Feel free to move stuff in and out of it as you see fit.
class Backend:
    def __init__(self, build: T.Optional[build.Build], interpreter: T.Optional['Interpreter']):
        # Make it possible to construct a dummy backend
        # This is used for introspection without a build directory
        if build is None:
            self.environment = None
            return
        self.build = build
        self.interpreter = interpreter
        self.environment = build.environment
        self.processed_targets = {}
        self.build_dir = self.environment.get_build_dir()
        self.source_dir = self.environment.get_source_dir()
        self.build_to_src = mesonlib.relpath(self.environment.get_source_dir(),
                                             self.environment.get_build_dir())

    def get_target_filename(self, t, *, warn_multi_output: bool = True):
        if isinstance(t, build.CustomTarget):
            if warn_multi_output and len(t.get_outputs()) != 1:
                mlog.warning('custom_target {!r} has more than one output! '
                             'Using the first one.'.format(t.name))
            filename = t.get_outputs()[0]
        elif isinstance(t, build.CustomTargetIndex):
            filename = t.get_outputs()[0]
        else:
            assert(isinstance(t, build.BuildTarget))
            filename = t.get_filename()
        return os.path.join(self.get_target_dir(t), filename)

    def get_target_filename_abs(self, target):
        return os.path.join(self.environment.get_build_dir(), self.get_target_filename(target))

    def get_base_options_for_target(self, target):
        return OptionOverrideProxy(target.option_overrides_base,
                                   self.environment.coredata.builtins,
                                   self.environment.coredata.base_options)

    def get_compiler_options_for_target(self, target):
        comp_reg = self.environment.coredata.compiler_options[target.for_machine]
        comp_override = target.option_overrides_compiler
        return {
            lang: OptionOverrideProxy(comp_override[lang], comp_reg[lang])
            for lang in set(comp_reg.keys()) | set(comp_override.keys())
        }

    def get_option_for_target(self, option_name, target):
        if option_name in target.option_overrides_base:
            override = target.option_overrides_base[option_name]
            return self.environment.coredata.validate_option_value(option_name, override)
        return self.environment.coredata.get_builtin_option(option_name, target.subproject)

    def get_target_filename_for_linking(self, target):
        # On some platforms (msvc for instance), the file that is used for
        # dynamic linking is not the same as the dynamic library itself. This
        # file is called an import library, and we want to link against that.
        # On all other platforms, we link to the library directly.
        if isinstance(target, build.SharedLibrary):
            link_lib = target.get_import_filename() or target.get_filename()
            return os.path.join(self.get_target_dir(target), link_lib)
        elif isinstance(target, build.StaticLibrary):
            return os.path.join(self.get_target_dir(target), target.get_filename())
        elif isinstance(target, (build.CustomTarget, build.CustomTargetIndex)):
            if not target.is_linkable_target():
                raise MesonException('Tried to link against custom target "{}", which is not linkable.'.format(target.name))
            return os.path.join(self.get_target_dir(target), target.get_filename())
        elif isinstance(target, build.Executable):
            if target.import_filename:
                return os.path.join(self.get_target_dir(target), target.get_import_filename())
            else:
                return None
        raise AssertionError('BUG: Tried to link to {!r} which is not linkable'.format(target))

    @lru_cache(maxsize=None)
    def get_target_dir(self, target):
        if self.environment.coredata.get_builtin_option('layout') == 'mirror':
            dirname = target.get_subdir()
        else:
            dirname = 'meson-out'
        return dirname

    def get_target_dir_relative_to(self, t, o):
        '''Get a target dir relative to another target's directory'''
        target_dir = os.path.join(self.environment.get_build_dir(), self.get_target_dir(t))
        othert_dir = os.path.join(self.environment.get_build_dir(), self.get_target_dir(o))
        return os.path.relpath(target_dir, othert_dir)

    def get_target_source_dir(self, target):
        # if target dir is empty, avoid extraneous trailing / from os.path.join()
        target_dir = self.get_target_dir(target)
        if target_dir:
            return os.path.join(self.build_to_src, target_dir)
        return self.build_to_src

    def get_target_private_dir(self, target):
        return os.path.join(self.get_target_filename(target, warn_multi_output=False) + '.p')

    def get_target_private_dir_abs(self, target):
        return os.path.join(self.environment.get_build_dir(), self.get_target_private_dir(target))

    @lru_cache(maxsize=None)
    def get_target_generated_dir(self, target, gensrc, src):
        """
        Takes a BuildTarget, a generator source (CustomTarget or GeneratedList),
        and a generated source filename.
        Returns the full path of the generated source relative to the build root
        """
        # CustomTarget generators output to the build dir of the CustomTarget
        if isinstance(gensrc, (build.CustomTarget, build.CustomTargetIndex)):
            return os.path.join(self.get_target_dir(gensrc), src)
        # GeneratedList generators output to the private build directory of the
        # target that the GeneratedList is used in
        return os.path.join(self.get_target_private_dir(target), src)

    def get_unity_source_file(self, target, suffix, number):
        # There is a potential conflict here, but it is unlikely that
        # anyone both enables unity builds and has a file called foo-unity.cpp.
        osrc = '{}-unity{}.{}'.format(target.name, number, suffix)
        return mesonlib.File.from_built_file(self.get_target_private_dir(target), osrc)

    def generate_unity_files(self, target, unity_src):
        abs_files = []
        result = []
        compsrcs = classify_unity_sources(target.compilers.values(), unity_src)
        unity_size = self.get_option_for_target('unity_size', target)

        def init_language_file(suffix, unity_file_number):
            unity_src = self.get_unity_source_file(target, suffix, unity_file_number)
            outfileabs = unity_src.absolute_path(self.environment.get_source_dir(),
                                                 self.environment.get_build_dir())
            outfileabs_tmp = outfileabs + '.tmp'
            abs_files.append(outfileabs)
            outfileabs_tmp_dir = os.path.dirname(outfileabs_tmp)
            if not os.path.exists(outfileabs_tmp_dir):
                os.makedirs(outfileabs_tmp_dir)
            result.append(unity_src)
            return open(outfileabs_tmp, 'w')

        # For each language, generate unity source files and return the list
        for comp, srcs in compsrcs.items():
            files_in_current = unity_size + 1
            unity_file_number = 0
            ofile = None
            for src in srcs:
                if files_in_current >= unity_size:
                    if ofile:
                        ofile.close()
                    ofile = init_language_file(comp.get_default_suffix(), unity_file_number)
                    unity_file_number += 1
                    files_in_current = 0
                ofile.write('#include<{}>\n'.format(src))
                files_in_current += 1
            if ofile:
                ofile.close()

        [mesonlib.replace_if_different(x, x + '.tmp') for x in abs_files]
        return result

    def relpath(self, todir, fromdir):
        return os.path.relpath(os.path.join('dummyprefixdir', todir),
                               os.path.join('dummyprefixdir', fromdir))

    def flatten_object_list(self, target, proj_dir_to_build_root=''):
        obj_list = self._flatten_object_list(target, target.get_objects(), proj_dir_to_build_root)
        return list(dict.fromkeys(obj_list))

    def _flatten_object_list(self, target, objects, proj_dir_to_build_root):
        obj_list = []
        for obj in objects:
            if isinstance(obj, str):
                o = os.path.join(proj_dir_to_build_root,
                                 self.build_to_src, target.get_subdir(), obj)
                obj_list.append(o)
            elif isinstance(obj, mesonlib.File):
                obj_list.append(obj.rel_to_builddir(self.build_to_src))
            elif isinstance(obj, build.ExtractedObjects):
                if obj.recursive:
                    obj_list += self._flatten_object_list(obj.target, obj.objlist, proj_dir_to_build_root)
                obj_list += self.determine_ext_objs(obj, proj_dir_to_build_root)
            else:
                raise MesonException('Unknown data type in object list.')
        return obj_list

    def as_meson_exe_cmdline(self, tname, exe, cmd_args, workdir=None,
                             for_machine=MachineChoice.BUILD,
                             extra_bdeps=None, capture=None, force_serialize=False):
        '''
        Serialize an executable for running with a generator or a custom target
        '''
        import hashlib
        machine = self.environment.machines[for_machine]
        if machine.is_windows() or machine.is_cygwin():
            extra_paths = self.determine_windows_extra_paths(exe, extra_bdeps or [])
        else:
            extra_paths = []

        if isinstance(exe, dependencies.ExternalProgram):
            exe_cmd = exe.get_command()
            exe_for_machine = exe.for_machine
        elif isinstance(exe, (build.BuildTarget, build.CustomTarget)):
            exe_cmd = [self.get_target_filename_abs(exe)]
            exe_for_machine = exe.for_machine
        else:
            exe_cmd = [exe]
            exe_for_machine = MachineChoice.BUILD

        is_cross_built = not self.environment.machines.matches_build_machine(exe_for_machine)
        if is_cross_built and self.environment.need_exe_wrapper():
            exe_wrapper = self.environment.get_exe_wrapper()
            if not exe_wrapper.found():
                msg = 'The exe_wrapper {!r} defined in the cross file is ' \
                      'needed by target {!r}, but was not found. Please ' \
                      'check the command and/or add it to PATH.'
                raise MesonException(msg.format(exe_wrapper.name, tname))
        else:
            if exe_cmd[0].endswith('.jar'):
                exe_cmd = ['java', '-jar'] + exe_cmd
            elif exe_cmd[0].endswith('.exe') and not (mesonlib.is_windows() or mesonlib.is_cygwin()):
                exe_cmd = ['mono'] + exe_cmd
            exe_wrapper = None

        force_serialize = force_serialize or extra_paths or workdir or \
            exe_wrapper or any('\n' in c for c in cmd_args)
        if not force_serialize:
            if not capture:
                return None
            return (self.environment.get_build_command() +
                    ['--internal', 'exe', '--capture', capture, '--'] + exe_cmd + cmd_args)

        workdir = workdir or self.environment.get_build_dir()
        env = {}
        if isinstance(exe, (dependencies.ExternalProgram,
                            build.BuildTarget, build.CustomTarget)):
            basename = exe.name
        else:
            basename = os.path.basename(exe)

        # Can't just use exe.name here; it will likely be run more than once
        # Take a digest of the cmd args, env, workdir, and capture. This avoids
        # collisions and also makes the name deterministic over regenerations
        # which avoids a rebuild by Ninja because the cmdline stays the same.
        data = bytes(str(sorted(env.items())) + str(cmd_args) + str(workdir) + str(capture),
                     encoding='utf-8')
        digest = hashlib.sha1(data).hexdigest()
        scratch_file = 'meson_exe_{0}_{1}.dat'.format(basename, digest)
        exe_data = os.path.join(self.environment.get_scratch_dir(), scratch_file)
        with open(exe_data, 'wb') as f:
            es = ExecutableSerialisation(exe_cmd + cmd_args, env,
                                         exe_wrapper, workdir,
                                         extra_paths, capture)
            pickle.dump(es, f)
        return self.environment.get_build_command() + ['--internal', 'exe', '--unpickle', exe_data]

    def serialize_tests(self):
        test_data = os.path.join(self.environment.get_scratch_dir(), 'meson_test_setup.dat')
        with open(test_data, 'wb') as datafile:
            self.write_test_file(datafile)
        benchmark_data = os.path.join(self.environment.get_scratch_dir(), 'meson_benchmark_setup.dat')
        with open(benchmark_data, 'wb') as datafile:
            self.write_benchmark_file(datafile)
        return test_data, benchmark_data

    def determine_linker_and_stdlib_args(self, target):
        '''
        If we're building a static library, there is only one static linker.
        Otherwise, we query the target for the dynamic linker.
        '''
        if isinstance(target, build.StaticLibrary):
            return self.build.static_linker[target.for_machine], []
        l, stdlib_args = target.get_clink_dynamic_linker_and_stdlibs()
        return l, stdlib_args

    @staticmethod
    def _libdir_is_system(libdir, compilers, env):
        libdir = os.path.normpath(libdir)
        for cc in compilers.values():
            if libdir in cc.get_library_dirs(env):
                return True
        return False

    def get_external_rpath_dirs(self, target):
        dirs = set()
        args = []
        # FIXME: is there a better way?
        for lang in ['c', 'cpp']:
            try:
                args.extend(self.environment.coredata.get_external_link_args(target.for_machine, lang))
            except Exception:
                pass
        # Match rpath formats:
        # -Wl,-rpath=
        # -Wl,-rpath,
        rpath_regex = re.compile(r'-Wl,-rpath[=,]([^,]+)')
        # Match solaris style compat runpath formats:
        # -Wl,-R
        # -Wl,-R,
        runpath_regex = re.compile(r'-Wl,-R[,]?([^,]+)')
        # Match symbols formats:
        # -Wl,--just-symbols=
        # -Wl,--just-symbols,
        symbols_regex = re.compile(r'-Wl,--just-symbols[=,]([^,]+)')
        for arg in args:
            rpath_match = rpath_regex.match(arg)
            if rpath_match:
                for dir in rpath_match.group(1).split(':'):
                    dirs.add(dir)
            runpath_match = runpath_regex.match(arg)
            if runpath_match:
                for dir in runpath_match.group(1).split(':'):
                    # The symbols arg is an rpath if the path is a directory
                    if Path(dir).is_dir():
                        dirs.add(dir)
            symbols_match = symbols_regex.match(arg)
            if symbols_match:
                for dir in symbols_match.group(1).split(':'):
                    # Prevent usage of --just-symbols to specify rpath
                    if Path(dir).is_dir():
                        raise MesonException('Invalid arg for --just-symbols, {} is a directory.'.format(dir))
        return dirs

    def rpaths_for_bundled_shared_libraries(self, target, exclude_system=True):
        paths = []
        for dep in target.external_deps:
            if not isinstance(dep, (dependencies.ExternalLibrary, dependencies.PkgConfigDependency)):
                continue
            la = dep.link_args
            if len(la) != 1 or not os.path.isabs(la[0]):
                continue
            # The only link argument is an absolute path to a library file.
            libpath = la[0]
            libdir = os.path.dirname(libpath)
            if exclude_system and self._libdir_is_system(libdir, target.compilers, self.environment):
                # No point in adding system paths.
                continue
            # Don't remove rpaths specified in LDFLAGS.
            if libdir in self.get_external_rpath_dirs(target):
                continue
            # Windows doesn't support rpaths, but we use this function to
            # emulate rpaths by setting PATH, so also accept DLLs here
            if os.path.splitext(libpath)[1] not in ['.dll', '.lib', '.so', '.dylib']:
                continue
            if libdir.startswith(self.environment.get_source_dir()):
                rel_to_src = libdir[len(self.environment.get_source_dir()) + 1:]
                assert not os.path.isabs(rel_to_src), 'rel_to_src: {} is absolute'.format(rel_to_src)
                paths.append(os.path.join(self.build_to_src, rel_to_src))
            else:
                paths.append(libdir)
        return paths

    def determine_rpath_dirs(self, target):
        if self.environment.coredata.get_builtin_option('layout') == 'mirror':
            result = target.get_link_dep_subdirs()
        else:
            result = OrderedSet()
            result.add('meson-out')
        result.update(self.rpaths_for_bundled_shared_libraries(target))
        target.rpath_dirs_to_remove.update([d.encode('utf8') for d in result])
        return tuple(result)

    @staticmethod
    def canonicalize_filename(fname):
        for ch in ('/', '\\', ':'):
            fname = fname.replace(ch, '_')
        return fname

    def object_filename_from_source(self, target, source):
        assert isinstance(source, mesonlib.File)
        build_dir = self.environment.get_build_dir()
        rel_src = source.rel_to_builddir(self.build_to_src)

        # foo.vala files compile down to foo.c and then foo.c.o, not foo.vala.o
        if rel_src.endswith(('.vala', '.gs')):
            # See description in generate_vala_compile for this logic.
            if source.is_built:
                if os.path.isabs(rel_src):
                    rel_src = rel_src[len(build_dir) + 1:]
                rel_src = os.path.relpath(rel_src, self.get_target_private_dir(target))
            else:
                rel_src = os.path.basename(rel_src)
            # A meson- prefixed directory is reserved; hopefully no-one creates a file name with such a weird prefix.
            source = 'meson-generated_' + rel_src[:-5] + '.c'
        elif source.is_built:
            if os.path.isabs(rel_src):
                rel_src = rel_src[len(build_dir) + 1:]
            targetdir = self.get_target_private_dir(target)
            # A meson- prefixed directory is reserved; hopefully no-one creates a file name with such a weird prefix.
            source = 'meson-generated_' + os.path.relpath(rel_src, targetdir)
        else:
            if os.path.isabs(rel_src):
                # Use the absolute path directly to avoid file name conflicts
                source = rel_src
            else:
                source = os.path.relpath(os.path.join(build_dir, rel_src),
                                         os.path.join(self.environment.get_source_dir(), target.get_subdir()))
        machine = self.environment.machines[target.for_machine]
        return self.canonicalize_filename(source) + '.' + machine.get_object_suffix()

    def determine_ext_objs(self, extobj, proj_dir_to_build_root):
        result = []

        # Merge sources and generated sources
        sources = list(extobj.srclist)
        for gensrc in extobj.genlist:
            for s in gensrc.get_outputs():
                path = self.get_target_generated_dir(extobj.target, gensrc, s)
                dirpart, fnamepart = os.path.split(path)
                sources.append(File(True, dirpart, fnamepart))

        # Filter out headers and all non-source files
        filtered_sources = []
        for s in sources:
            if self.environment.is_source(s) and not self.environment.is_header(s):
                filtered_sources.append(s)
            elif self.environment.is_object(s):
                result.append(s.relative_name())
        sources = filtered_sources

        # extobj could contain only objects and no sources
        if not sources:
            return result

        targetdir = self.get_target_private_dir(extobj.target)

        # With unity builds, sources don't map directly to objects,
        # we only support extracting all the objects in this mode,
        # so just return all object files.
        if self.is_unity(extobj.target):
            compsrcs = classify_unity_sources(extobj.target.compilers.values(), sources)
            sources = []
            unity_size = self.get_option_for_target('unity_size', extobj.target)
            for comp, srcs in compsrcs.items():
                for i in range(len(srcs) // unity_size + 1):
                    osrc = self.get_unity_source_file(extobj.target,
                                                      comp.get_default_suffix(), i)
                    sources.append(osrc)

        for osrc in sources:
            objname = self.object_filename_from_source(extobj.target, osrc)
            objpath = os.path.join(proj_dir_to_build_root, targetdir, objname)
            result.append(objpath)

        return result

    def get_pch_include_args(self, compiler, target):
        args = []
        pchpath = self.get_target_private_dir(target)
        includeargs = compiler.get_include_args(pchpath, False)
        p = target.get_pch(compiler.get_language())
        if p:
            args += compiler.get_pch_use_args(pchpath, p[0])
        return includeargs + args

    def create_msvc_pch_implementation(self, target, lang, pch_header):
        # We have to include the language in the file name, otherwise
        # pch.c and pch.cpp will both end up as pch.obj in VS backends.
        impl_name = 'meson_pch-{}.{}'.format(lang, lang)
        pch_rel_to_build = os.path.join(self.get_target_private_dir(target), impl_name)
        # Make sure to prepend the build dir, since the working directory is
        # not defined. Otherwise, we might create the file in the wrong path.
        pch_file = os.path.join(self.build_dir, pch_rel_to_build)
        os.makedirs(os.path.dirname(pch_file), exist_ok=True)

        content = '#include "{}"'.format(os.path.basename(pch_header))
        pch_file_tmp = pch_file + '.tmp'
        with open(pch_file_tmp, 'w') as f:
            f.write(content)
        mesonlib.replace_if_different(pch_file, pch_file_tmp)
        return pch_rel_to_build

    @staticmethod
    def escape_extra_args(compiler, args):
        # all backslashes in defines are doubly-escaped
        extra_args = []
        for arg in args:
            if arg.startswith('-D') or arg.startswith('/D'):
                arg = arg.replace('\\', '\\\\')
            extra_args.append(arg)

        return extra_args

    def generate_basic_compiler_args(self, target, compiler, no_warn_args=False):
        # Create an empty commands list, and start adding arguments from
        # various sources in the order in which they must override each other
        # starting from hard-coded defaults followed by build options and so on.
        commands = compiler.compiler_args()

        copt_proxy = self.get_compiler_options_for_target(target)[compiler.language]
        # First, the trivial ones that are impossible to override.
        #
        # Add -nostdinc/-nostdinc++ if needed; can't be overridden
        commands += self.get_cross_stdlib_args(target, compiler)
        # Add things like /NOLOGO or -pipe; usually can't be overridden
        commands += compiler.get_always_args()
        # Only add warning-flags by default if the buildtype enables it, and if
        # we weren't explicitly asked to not emit warnings (for Vala, f.ex)
        if no_warn_args:
            commands += compiler.get_no_warn_args()
        elif self.get_option_for_target('buildtype', target) != 'plain':
            commands += compiler.get_warn_args(self.get_option_for_target('warning_level', target))
        # Add -Werror if werror=true is set in the build options set on the
        # command-line or default_options inside project(). This only sets the
        # action to be done for warnings if/when they are emitted, so it's ok
        # to set it after get_no_warn_args() or get_warn_args().
        if self.get_option_for_target('werror', target):
            commands += compiler.get_werror_args()
        # Add compile args for c_* or cpp_* build options set on the
        # command-line or default_options inside project().
        commands += compiler.get_option_compile_args(copt_proxy)
        # Add buildtype args: optimization level, debugging, etc.
        commands += compiler.get_buildtype_args(self.get_option_for_target('buildtype', target))
        commands += compiler.get_optimization_args(self.get_option_for_target('optimization', target))
        commands += compiler.get_debug_args(self.get_option_for_target('debug', target))
        # Add compile args added using add_project_arguments()
        commands += self.build.get_project_args(compiler, target.subproject, target.for_machine)
        # Add compile args added using add_global_arguments()
        # These override per-project arguments
        commands += self.build.get_global_args(compiler, target.for_machine)
        # Compile args added from the env: CFLAGS/CXXFLAGS, etc, or the cross
        # file. We want these to override all the defaults, but not the
        # per-target compile args.
        commands += self.environment.coredata.get_external_args(target.for_machine, compiler.get_language())
        # Always set -fPIC for shared libraries
        if isinstance(target, build.SharedLibrary):
            commands += compiler.get_pic_args()
        # Set -fPIC for static libraries by default unless explicitly disabled
        if isinstance(target, build.StaticLibrary) and target.pic:
            commands += compiler.get_pic_args()
        if isinstance(target, build.Executable) and target.pie:
            commands += compiler.get_pie_args()
        # Add compile args needed to find external dependencies. Link args are
        # added while generating the link command.
        # NOTE: We must preserve the order in which external deps are
        # specified, so we reverse the list before iterating over it.
        for dep in reversed(target.get_external_deps()):
            if not dep.found():
                continue

            if compiler.language == 'vala':
                if isinstance(dep, dependencies.PkgConfigDependency):
                    if dep.name == 'glib-2.0' and dep.version_reqs is not None:
                        for req in dep.version_reqs:
                            if req.startswith(('>=', '==')):
                                commands += ['--target-glib', req[2:]]
                                break
                    commands += ['--pkg', dep.name]
                elif isinstance(dep, dependencies.ExternalLibrary):
                    commands += dep.get_link_args('vala')
            else:
                commands += compiler.get_dependency_compile_args(dep)
            # Qt needs -fPIC for executables
            # XXX: We should move to -fPIC for all executables
            if isinstance(target, build.Executable):
                commands += dep.get_exe_args(compiler)
            # For 'automagic' deps: Boost and GTest. Also dependency('threads').
            # pkg-config puts the thread flags itself via `Cflags:`
        # Fortran requires extra include directives.
        if compiler.language == 'fortran':
            for lt in target.link_targets:
                priv_dir = self.get_target_private_dir(lt)
                commands += compiler.get_include_args(priv_dir, False)
        return commands

    def build_target_link_arguments(self, compiler, deps):
        args = []
        for d in deps:
            if not (d.is_linkable_target()):
                raise RuntimeError('Tried to link with a non-library target "{}".'.format(d.get_basename()))
            arg = self.get_target_filename_for_linking(d)
            if not arg:
                continue
            if compiler.get_language() == 'd':
                arg = '-Wl,' + arg
            else:
                arg = compiler.get_linker_lib_prefix() + arg
            args.append(arg)
        return args

    def get_mingw_extra_paths(self, target):
        paths = OrderedSet()
        # The cross bindir
        root = self.environment.properties[target.for_machine].get_root()
        if root:
            paths.add(os.path.join(root, 'bin'))
        # The toolchain bindir
        sys_root = self.environment.properties[target.for_machine].get_sys_root()
        if sys_root:
            paths.add(os.path.join(sys_root, 'bin'))
        # Get program and library dirs from all target compilers
        if isinstance(target, build.BuildTarget):
            for cc in target.compilers.values():
                paths.update(cc.get_program_dirs(self.environment))
                paths.update(cc.get_library_dirs(self.environment))
        return list(paths)

    def determine_windows_extra_paths(self, target: T.Union[build.BuildTarget, str], extra_bdeps):
        '''On Windows there is no such thing as an rpath.
        We must determine all locations of DLLs that this exe
        links to and return them so they can be used in unit
        tests.'''
        result = set()
        prospectives = set()
        if isinstance(target, build.BuildTarget):
            prospectives.update(target.get_transitive_link_deps())
            # External deps
            for deppath in self.rpaths_for_bundled_shared_libraries(target, exclude_system=False):
                result.add(os.path.normpath(os.path.join(self.environment.get_build_dir(), deppath)))
        for bdep in extra_bdeps:
            prospectives.add(bdep)
            prospectives.update(bdep.get_transitive_link_deps())
        # Internal deps
        for ld in prospectives:
            if ld == '' or ld == '.':
                continue
            dirseg = os.path.join(self.environment.get_build_dir(), self.get_target_dir(ld))
            result.add(dirseg)
        if (isinstance(target, build.BuildTarget) and
                not self.environment.machines.matches_build_machine(target.for_machine)):
            result.update(self.get_mingw_extra_paths(target))
        return list(result)

    def write_benchmark_file(self, datafile):
        self.write_test_serialisation(self.build.get_benchmarks(), datafile)

    def write_test_file(self, datafile):
        self.write_test_serialisation(self.build.get_tests(), datafile)

    def create_test_serialisation(self, tests):
        arr = []
        for t in sorted(tests, key=lambda tst: -1 * tst.priority):
            exe = t.get_exe()
            if isinstance(exe, dependencies.ExternalProgram):
                cmd = exe.get_command()
            else:
                cmd = [os.path.join(self.environment.get_build_dir(), self.get_target_filename(t.get_exe()))]
            if isinstance(exe, (build.BuildTarget, dependencies.ExternalProgram)):
                test_for_machine = exe.for_machine
            else:
                # E.g. an external verifier or simulator program run on a generated executable.
                # Can always be run without a wrapper.
                test_for_machine = MachineChoice.BUILD

            # we allow passing compiled executables to tests, which may be cross built.
            # We need to consider these as well when considering whether the target is cross or not.
            for a in t.cmd_args:
                if isinstance(a, build.BuildTarget):
                    if a.for_machine is MachineChoice.HOST:
                        test_for_machine = MachineChoice.HOST
                        break

            is_cross = self.environment.is_cross_build(test_for_machine)
            if is_cross and self.environment.need_exe_wrapper():
                exe_wrapper = self.environment.get_exe_wrapper()
            else:
                exe_wrapper = None
            machine = self.environment.machines[exe.for_machine]
            if machine.is_windows() or machine.is_cygwin():
                extra_bdeps = []
                if isinstance(exe, build.CustomTarget):
                    extra_bdeps = exe.get_transitive_build_target_deps()
                extra_paths = self.determine_windows_extra_paths(exe, extra_bdeps)
            else:
                extra_paths = []

            cmd_args = []
            for a in unholder(t.cmd_args):
                if isinstance(a, build.BuildTarget):
                    extra_paths += self.determine_windows_extra_paths(a, [])
                if isinstance(a, mesonlib.File):
                    a = os.path.join(self.environment.get_build_dir(), a.rel_to_builddir(self.build_to_src))
                    cmd_args.append(a)
                elif isinstance(a, str):
                    cmd_args.append(a)
                elif isinstance(a, build.Executable):
                    p = self.construct_target_rel_path(a, t.workdir)
                    if p == a.get_filename():
                        p = './' + p
                    cmd_args.append(p)
                elif isinstance(a, build.Target):
                    cmd_args.append(self.construct_target_rel_path(a, t.workdir))
                else:
                    raise MesonException('Bad object in test command.')
            ts = TestSerialisation(t.get_name(), t.project_name, t.suite, cmd, is_cross,
                                   exe_wrapper, self.environment.need_exe_wrapper(),
                                   t.is_parallel, cmd_args, t.env,
                                   t.should_fail, t.timeout, t.workdir,
                                   extra_paths, t.protocol, t.priority,
                                   isinstance(exe, build.Executable))
            arr.append(ts)
        return arr

    def write_test_serialisation(self, tests, datafile):
        pickle.dump(self.create_test_serialisation(tests), datafile)

    def construct_target_rel_path(self, a, workdir):
        if workdir is None:
            return self.get_target_filename(a)
        assert(os.path.isabs(workdir))
        abs_path = self.get_target_filename_abs(a)
        return os.path.relpath(abs_path, workdir)

    def generate_depmf_install(self, d):
        if self.build.dep_manifest_name is None:
            return
        ifilename = os.path.join(self.environment.get_build_dir(), 'depmf.json')
        ofilename = os.path.join(self.environment.get_prefix(), self.build.dep_manifest_name)
        mfobj = {'type': 'dependency manifest', 'version': '1.0', 'projects': self.build.dep_manifest}
        with open(ifilename, 'w') as f:
            f.write(json.dumps(mfobj))
        # Copy file from, to, and with mode unchanged
        d.data.append([ifilename, ofilename, None])

    def get_regen_filelist(self):
        '''List of all files whose alteration means that the build
        definition needs to be regenerated.'''
        deps = [os.path.join(self.build_to_src, df)
                for df in self.interpreter.get_build_def_files()]
        if self.environment.is_cross_build():
            deps.extend(self.environment.coredata.cross_files)
        deps.extend(self.environment.coredata.config_files)
        deps.append('meson-private/coredata.dat')
        self.check_clock_skew(deps)
        return deps

    def check_clock_skew(self, file_list):
        # If a file that leads to reconfiguration has a time
        # stamp in the future, it will trigger an eternal reconfigure
        # loop.
        import time
        now = time.time()
        for f in file_list:
            absf = os.path.join(self.environment.get_build_dir(), f)
            ftime = os.path.getmtime(absf)
            delta = ftime - now
            # On Windows disk time stamps sometimes point
            # to the future by a minuscule amount, less than
            # 0.001 seconds. I don't know why.
            if delta > 0.001:
                raise MesonException('Clock skew detected. File {} has a time stamp {:.4f}s in the future.'.format(absf, delta))

    def build_target_to_cmd_array(self, bt):
        if isinstance(bt, build.BuildTarget):
            if isinstance(bt, build.Executable) and bt.for_machine is not MachineChoice.BUILD:
                if (self.environment.is_cross_build() and
                        self.environment.exe_wrapper is None and
                        self.environment.need_exe_wrapper()):
                    s = textwrap.dedent('''
                        Cannot use target {} as a generator because it is built for the
                        host machine and no exe wrapper is defined or needs_exe_wrapper is
                        true. You might want to set `native: true` instead to build it for
                        the build machine.'''.format(bt.name))
                    raise MesonException(s)
            arr = [os.path.join(self.environment.get_build_dir(), self.get_target_filename(bt))]
        else:
            arr = bt.get_command()
        return arr

    def replace_extra_args(self, args, genlist):
        final_args = []
        for a in args:
            if a == '@EXTRA_ARGS@':
                final_args += genlist.get_extra_args()
            else:
                final_args.append(a)
        return final_args

    def replace_outputs(self, args, private_dir, output_list):
        newargs = []
        regex = re.compile(r'@OUTPUT(\d+)@')
        for arg in args:
            m = regex.search(arg)
            while m is not None:
                index = int(m.group(1))
                src = '@OUTPUT{}@'.format(index)
                arg = arg.replace(src, os.path.join(private_dir, output_list[index]))
                m = regex.search(arg)
            newargs.append(arg)
        return newargs

    def get_build_by_default_targets(self):
        result = OrderedDict()
        # Get all build and custom targets that must be built by default
        for name, t in self.build.get_targets().items():
            if t.build_by_default:
                result[name] = t
        # Get all targets used as test executables and arguments. These must
        # also be built by default. XXX: Sometime in the future these should be
        # built only before running tests.
        for t in self.build.get_tests():
            exe = unholder(t.exe)
            if isinstance(exe, (build.CustomTarget, build.BuildTarget)):
                result[exe.get_id()] = exe
            for arg in unholder(t.cmd_args):
                if not isinstance(arg, (build.CustomTarget, build.BuildTarget)):
                    continue
                result[arg.get_id()] = arg
            for dep in t.depends:
                assert isinstance(dep, (build.CustomTarget, build.BuildTarget))
                result[dep.get_id()] = dep
        return result

    @lru_cache(maxsize=None)
    def get_custom_target_provided_by_generated_source(self, generated_source):
        libs = []
        for f in generated_source.get_outputs():
            if self.environment.is_library(f):
                libs.append(os.path.join(self.get_target_dir(generated_source), f))
        return libs

    @lru_cache(maxsize=None)
    def get_custom_target_provided_libraries(self, target):
        libs = []
        for t in target.get_generated_sources():
            if not isinstance(t, build.CustomTarget):
                continue
            l = self.get_custom_target_provided_by_generated_source(t)
            libs = libs + l
        return libs

    def is_unity(self, target):
        optval = self.get_option_for_target('unity', target)
        if optval == 'on' or (optval == 'subprojects' and target.subproject != ''):
            return True
        return False

    def get_custom_target_sources(self, target):
        '''
        Custom target sources can be of various object types; strings, File,
        BuildTarget, even other CustomTargets.
        Returns the path to them relative to the build root directory.
        '''
        srcs = []
        for i in unholder(target.get_sources()):
            if isinstance(i, str):
                fname = [os.path.join(self.build_to_src, target.subdir, i)]
            elif isinstance(i, build.BuildTarget):
                fname = [self.get_target_filename(i)]
            elif isinstance(i, (build.CustomTarget, build.CustomTargetIndex)):
                fname = [os.path.join(self.get_target_dir(i), p) for p in i.get_outputs()]
            elif isinstance(i, build.GeneratedList):
                fname = [os.path.join(self.get_target_private_dir(target), p) for p in i.get_outputs()]
            elif isinstance(i, build.ExtractedObjects):
                fname = [os.path.join(self.get_target_private_dir(i.target), p) for p in i.get_outputs(self)]
            else:
                fname = [i.rel_to_builddir(self.build_to_src)]
            if target.absolute_paths:
                fname = [os.path.join(self.environment.get_build_dir(), f) for f in fname]
            srcs += fname
        return srcs

    def get_custom_target_depend_files(self, target, absolute_paths=False):
        deps = []
        for i in target.depend_files:
            if isinstance(i, mesonlib.File):
                if absolute_paths:
                    deps.append(i.absolute_path(self.environment.get_source_dir(),
                                                self.environment.get_build_dir()))
                else:
                    deps.append(i.rel_to_builddir(self.build_to_src))
            else:
                if absolute_paths:
                    deps.append(os.path.join(self.environment.get_source_dir(), target.subdir, i))
                else:
                    deps.append(os.path.join(self.build_to_src, target.subdir, i))
        return deps

    def eval_custom_target_command(self, target, absolute_outputs=False):
        # We want the outputs to be absolute only when using the VS backend
        # XXX: Maybe allow the vs backend to use relative paths too?
        source_root = self.build_to_src
        build_root = '.'
        outdir = self.get_target_dir(target)
        if absolute_outputs:
            source_root = self.environment.get_source_dir()
            build_root = self.environment.get_build_dir()
            outdir = os.path.join(self.environment.get_build_dir(), outdir)
        outputs = []
        for i in target.get_outputs():
            outputs.append(os.path.join(outdir, i))
        inputs = self.get_custom_target_sources(target)
        # Evaluate the command list
        cmd = []
        for i in target.command:
            if isinstance(i, build.BuildTarget):
                cmd += self.build_target_to_cmd_array(i)
                continue
            elif isinstance(i, build.CustomTarget):
                # GIR scanner will attempt to execute this binary but
                # it assumes that it is in path, so always give it a full path.
                tmp = i.get_outputs()[0]
                i = os.path.join(self.get_target_dir(i), tmp)
            elif isinstance(i, mesonlib.File):
                i = i.rel_to_builddir(self.build_to_src)
                if target.absolute_paths:
                    i = os.path.join(self.environment.get_build_dir(), i)
            # FIXME: str types are blindly added ignoring 'target.absolute_paths'
            # because we can't know if they refer to a file or just a string
            elif not isinstance(i, str):
                err_msg = 'Argument {0} is of unknown type {1}'
                raise RuntimeError(err_msg.format(str(i), str(type(i))))
            else:
                if '@SOURCE_ROOT@' in i:
                    i = i.replace('@SOURCE_ROOT@', source_root)
                if '@BUILD_ROOT@' in i:
                    i = i.replace('@BUILD_ROOT@', build_root)
                if '@DEPFILE@' in i:
                    if target.depfile is None:
                        msg = 'Custom target {!r} has @DEPFILE@ but no depfile ' \
                              'keyword argument.'.format(target.name)
                        raise MesonException(msg)
                    dfilename = os.path.join(outdir, target.depfile)
                    i = i.replace('@DEPFILE@', dfilename)
                if '@PRIVATE_DIR@' in i:
                    if target.absolute_paths:
                        pdir = self.get_target_private_dir_abs(target)
                    else:
                        pdir = self.get_target_private_dir(target)
                    i = i.replace('@PRIVATE_DIR@', pdir)
                if '@PRIVATE_OUTDIR_' in i:
                    match = re.search(r'@PRIVATE_OUTDIR_(ABS_)?([^/\s*]*)@', i)
                    if not match:
                        msg = 'Custom target {!r} has an invalid argument {!r}' \
                              ''.format(target.name, i)
                        raise MesonException(msg)
                    source = match.group(0)
                    if match.group(1) is None and not target.absolute_paths:
                        lead_dir = ''
                    else:
                        lead_dir = self.environment.get_build_dir()
                    i = i.replace(source, os.path.join(lead_dir, outdir))
            cmd.append(i)
        # Substitute the rest of the template strings
        values = mesonlib.get_filenames_templates_dict(inputs, outputs)
        cmd = mesonlib.substitute_values(cmd, values)
        # This should not be necessary but removing it breaks
        # building GStreamer on Windows. The underlying issue
        # is problems with quoting backslashes on Windows
        # which is the seventh circle of hell. The downside is
        # that this breaks custom targets whose command lines
        # have backslashes. If you try to fix this be sure to
        # check that it does not break GST.
        #
        # The bug causes file paths such as c:\foo to get escaped
        # into c:\\foo.
        #
        # Unfortunately we have not been able to come up with an
        # isolated test case for this so unless you manage to come up
        # with one, the only way is to test the building with Gst's
        # setup. Note this in your MR or ping us and we will get it
        # fixed.
        #
        # https://github.com/mesonbuild/meson/pull/737
        cmd = [i.replace('\\', '/') for i in cmd]
        return inputs, outputs, cmd

    def run_postconf_scripts(self):
        env = {'MESON_SOURCE_ROOT': self.environment.get_source_dir(),
               'MESON_BUILD_ROOT': self.environment.get_build_dir(),
               'MESONINTROSPECT': ' '.join([shlex.quote(x) for x in self.environment.get_build_command() + ['introspect']]),
               }
        child_env = os.environ.copy()
        child_env.update(env)

        for s in self.build.postconf_scripts:
            cmd = s['exe'] + s['args']
            subprocess.check_call(cmd, env=child_env)

    def create_install_data(self):
        strip_bin = self.environment.lookup_binary_entry(MachineChoice.HOST, 'strip')
        if strip_bin is None:
            if self.environment.is_cross_build():
                mlog.warning('Cross file does not specify strip binary, result will not be stripped.')
            else:
                # TODO go through all candidates, like others
                strip_bin = [self.environment.default_strip[0]]
        d = InstallData(self.environment.get_source_dir(),
                        self.environment.get_build_dir(),
                        self.environment.get_prefix(),
                        strip_bin,
                        self.environment.coredata.get_builtin_option('install_umask'),
                        self.environment.get_build_command() + ['introspect'])
        self.generate_depmf_install(d)
        self.generate_target_install(d)
        self.generate_header_install(d)
        self.generate_man_install(d)
        self.generate_data_install(d)
        self.generate_custom_install_script(d)
        self.generate_subdir_install(d)
        return d

    def create_install_data_files(self):
        install_data_file = os.path.join(self.environment.get_scratch_dir(), 'install.dat')
        with open(install_data_file, 'wb') as ofile:
            pickle.dump(self.create_install_data(), ofile)

    def generate_target_install(self, d):
        for t in self.build.get_targets().values():
            if not t.should_install():
                continue
            outdirs, custom_install_dir = t.get_install_dir(self.environment)
            # Sanity-check the outputs and install_dirs
            num_outdirs, num_out = len(outdirs), len(t.get_outputs())
            if num_outdirs != 1 and num_outdirs != num_out:
                m = 'Target {!r} has {} outputs: {!r}, but only {} "install_dir"s were found.\n' \
                    "Pass 'false' for outputs that should not be installed and 'true' for\n" \
                    'using the default installation directory for an output.'
                raise MesonException(m.format(t.name, num_out, t.get_outputs(), num_outdirs))
            install_mode = t.get_custom_install_mode()
            # Install the target output(s)
            if isinstance(t, build.BuildTarget):
                # In general, stripping static archives is tricky and full of pitfalls.
                # Wholesale stripping of static archives with a command such as
                #
                #   strip libfoo.a
                #
                # is broken, as GNU's strip will remove *every* symbol in a static
                # archive. One solution to this nonintuitive behaviour would be
                # to only strip local/debug symbols. Unfortunately, strip arguments
                # are not specified by POSIX and therefore not portable. GNU's `-g`
                # option (i.e. remove debug symbols) is equivalent to Apple's `-S`.
                #
                # TODO: Create GNUStrip/AppleStrip/etc. hierarchy for more
                #       fine-grained stripping of static archives.
                should_strip = not isinstance(t, build.StaticLibrary) and self.get_option_for_target('strip', t)
                # Install primary build output (library/executable/jar, etc)
                # Done separately because of strip/aliases/rpath
                if outdirs[0] is not False:
                    mappings = t.get_link_deps_mapping(d.prefix, self.environment)
                    i = TargetInstallData(self.get_target_filename(t), outdirs[0],
                                          t.get_aliases(), should_strip, mappings,
                                          t.rpath_dirs_to_remove,
                                          t.install_rpath, install_mode)
                    d.targets.append(i)

                    if isinstance(t, (build.SharedLibrary, build.SharedModule, build.Executable)):
                        # On toolchains/platforms that use an import library for
                        # linking (separate from the shared library with all the
                        # code), we need to install that too (dll.a/.lib).
                        if t.get_import_filename():
                            if custom_install_dir:
                                # If the DLL is installed into a custom directory,
                                # install the import library into the same place so
                                # it doesn't go into a surprising place
                                implib_install_dir = outdirs[0]
                            else:
                                implib_install_dir = self.environment.get_import_lib_dir()
                            # Install the import library; may not exist for shared modules
                            i = TargetInstallData(self.get_target_filename_for_linking(t),
                                                  implib_install_dir, {}, False, {}, set(), '', install_mode,
                                                  optional=isinstance(t, build.SharedModule))
                            d.targets.append(i)

                        if not should_strip and t.get_debug_filename():
                            debug_file = os.path.join(self.get_target_dir(t), t.get_debug_filename())
                            i = TargetInstallData(debug_file, outdirs[0],
                                                  {}, False, {}, set(), '',
                                                  install_mode, optional=True)
                            d.targets.append(i)
                # Install secondary outputs. Only used for Vala right now.
                if num_outdirs > 1:
                    for output, outdir in zip(t.get_outputs()[1:], outdirs[1:]):
                        # User requested that we not install this output
                        if outdir is False:
                            continue
                        f = os.path.join(self.get_target_dir(t), output)
                        i = TargetInstallData(f, outdir, {}, False, {}, set(), None, install_mode)
                        d.targets.append(i)
            elif isinstance(t, build.CustomTarget):
                # If only one install_dir is specified, assume that all
                # outputs will be installed into it. This is for
                # backwards-compatibility and because it makes sense to
                # avoid repetition since this is a common use-case.
                #
                # To selectively install only some outputs, pass `false` as
                # the install_dir for the corresponding output by index
                if num_outdirs == 1 and num_out > 1:
                    for output in t.get_outputs():
                        f = os.path.join(self.get_target_dir(t), output)
                        i = TargetInstallData(f, outdirs[0], {}, False, {}, set(), None, install_mode,
                                              optional=not t.build_by_default)
                        d.targets.append(i)
                else:
                    for output, outdir in zip(t.get_outputs(), outdirs):
                        # User requested that we not install this output
                        if outdir is False:
                            continue
                        f = os.path.join(self.get_target_dir(t), output)
                        i = TargetInstallData(f, outdir, {}, False, {}, set(), None, install_mode,
                                              optional=not t.build_by_default)
                        d.targets.append(i)

    def generate_custom_install_script(self, d):
        result = []
        srcdir = self.environment.get_source_dir()
        builddir = self.environment.get_build_dir()
        for i in self.build.install_scripts:
            exe = i['exe']
            args = i['args']
            fixed_args = []
            for a in args:
                a = a.replace('@SOURCE_ROOT@', srcdir)
                a = a.replace('@BUILD_ROOT@', builddir)
                fixed_args.append(a)
            result.append(build.RunScript(exe, fixed_args))
        d.install_scripts = result

    def generate_header_install(self, d):
        incroot = self.environment.get_includedir()
        headers = self.build.get_headers()

        srcdir = self.environment.get_source_dir()
        builddir = self.environment.get_build_dir()
        for h in headers:
            outdir = h.get_custom_install_dir()
            if outdir is None:
                outdir = os.path.join(incroot, h.get_install_subdir())
            for f in h.get_sources():
                if not isinstance(f, File):
                    msg = 'Invalid header type {!r} can\'t be installed'
                    raise MesonException(msg.format(f))
                abspath = f.absolute_path(srcdir, builddir)
                i = [abspath, outdir, h.get_custom_install_mode()]
                d.headers.append(i)

    def generate_man_install(self, d):
        manroot = self.environment.get_mandir()
        man = self.build.get_man()
        for m in man:
            for f in m.get_sources():
                num = f.split('.')[-1]
                subdir = m.get_custom_install_dir()
                if subdir is None:
                    subdir = os.path.join(manroot, 'man' + num)
                srcabs = f.absolute_path(self.environment.get_source_dir(), self.environment.get_build_dir())
                dstabs = os.path.join(subdir, os.path.basename(f.fname))
                i = [srcabs, dstabs, m.get_custom_install_mode()]
                d.man.append(i)

    def generate_data_install(self, d):
        data = self.build.get_data()
        srcdir = self.environment.get_source_dir()
        builddir = self.environment.get_build_dir()
        for de in data:
            assert(isinstance(de, build.Data))
            subdir = de.install_dir
            if not subdir:
                subdir = os.path.join(self.environment.get_datadir(), self.interpreter.build.project_name)
            for src_file, dst_name in zip(de.sources, de.rename):
                assert(isinstance(src_file, mesonlib.File))
                dst_abs = os.path.join(subdir, dst_name)
                i = [src_file.absolute_path(srcdir, builddir), dst_abs, de.install_mode]
                d.data.append(i)

    def generate_subdir_install(self, d):
        for sd in self.build.get_install_subdirs():
            src_dir = os.path.join(self.environment.get_source_dir(),
                                   sd.source_subdir,
                                   sd.installable_subdir).rstrip('/')
            dst_dir = os.path.join(self.environment.get_prefix(),
                                   sd.install_dir)
            if not sd.strip_directory:
                dst_dir = os.path.join(dst_dir, os.path.basename(src_dir))
            d.install_subdirs.append([src_dir, dst_dir, sd.install_mode,
                                      sd.exclude])

    def get_introspection_data(self, target_id, target):
        '''
        Returns a list of source dicts with the following format for a given target:
        [
            {
                "language": "<LANG>",
                "compiler": ["result", "of", "comp.get_exelist()"],
                "parameters": ["list", "of", "compiler", "parameters],
                "sources": ["list", "of", "all", "<LANG>", "source", "files"],
                "generated_sources": ["list", "of", "generated", "source", "files"]
            }
        ]

        This is a limited fallback / reference implementation. The backend should override this method.
        '''
        if isinstance(target, (build.CustomTarget, build.BuildTarget)):
            source_list_raw = target.sources + target.extra_files
            source_list = []
            for j in source_list_raw:
                if isinstance(j, mesonlib.File):
                    source_list += [j.absolute_path(self.source_dir, self.build_dir)]
                elif isinstance(j, str):
                    source_list += [os.path.join(self.source_dir, j)]
            source_list = list(map(lambda x: os.path.normpath(x), source_list))

            compiler = []
            if isinstance(target, build.CustomTarget):
                tmp_compiler = target.command
                if not isinstance(compiler, list):
                    tmp_compiler = [compiler]
                for j in tmp_compiler:
                    if isinstance(j, mesonlib.File):
                        compiler += [j.absolute_path(self.source_dir, self.build_dir)]
                    elif isinstance(j, str):
                        compiler += [j]
                    elif isinstance(j, (build.BuildTarget, build.CustomTarget)):
                        compiler += j.get_outputs()
                    else:
                        raise RuntimeError('Type "{}" is not supported in get_introspection_data. This is a bug'.format(type(j).__name__))

            return [{
                'language': 'unknown',
                'compiler': compiler,
                'parameters': [],
                'sources': source_list,
                'generated_sources': []
            }]

        return []
