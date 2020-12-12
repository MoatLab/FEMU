# Copyright 2019 The meson development team
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Abstractions for the LLVM/Clang compiler family."""

import os
import shutil
import typing as T

from ... import mesonlib
from ...linkers import AppleDynamicLinker
from .gnu import GnuLikeCompiler

if T.TYPE_CHECKING:
    from ...environment import Environment
    from ...dependencies import Dependency  # noqa: F401

clang_color_args = {
    'auto': ['-Xclang', '-fcolor-diagnostics'],
    'always': ['-Xclang', '-fcolor-diagnostics'],
    'never': ['-Xclang', '-fno-color-diagnostics'],
}  # type: T.Dict[str, T.List[str]]

clang_optimization_args = {
    '0': [],
    'g': ['-Og'],
    '1': ['-O1'],
    '2': ['-O2'],
    '3': ['-O3'],
    's': ['-Os'],
}  # type: T.Dict[str, T.List[str]]

class ClangCompiler(GnuLikeCompiler):
    def __init__(self, defines: T.Optional[T.Dict[str, str]]):
        super().__init__()
        self.id = 'clang'
        self.defines = defines or {}
        self.base_options.append('b_colorout')
        # TODO: this really should be part of the linker base_options, but
        # linkers don't have base_options.
        if isinstance(self.linker, AppleDynamicLinker):
            self.base_options.append('b_bitcode')
        # All Clang backends can also do LLVM IR
        self.can_compile_suffixes.add('ll')

    def get_colorout_args(self, colortype: str) -> T.List[str]:
        return clang_color_args[colortype][:]

    def has_builtin_define(self, define: str) -> bool:
        return define in self.defines

    def get_builtin_define(self, define: str) -> T.Optional[str]:
        return self.defines.get(define)

    def get_optimization_args(self, optimization_level: str) -> T.List[str]:
        return clang_optimization_args[optimization_level]

    def get_pch_suffix(self) -> str:
        return 'pch'

    def get_pch_use_args(self, pch_dir: str, header: str) -> T.List[str]:
        # Workaround for Clang bug http://llvm.org/bugs/show_bug.cgi?id=15136
        # This flag is internal to Clang (or at least not documented on the man page)
        # so it might change semantics at any time.
        return ['-include-pch', os.path.join(pch_dir, self.get_pch_name(header))]

    def has_multi_arguments(self, args: T.List[str], env: 'Environment') -> T.List[str]:
        myargs = ['-Werror=unknown-warning-option', '-Werror=unused-command-line-argument']
        if mesonlib.version_compare(self.version, '>=3.6.0'):
            myargs.append('-Werror=ignored-optimization-argument')
        return super().has_multi_arguments(
            myargs + args,
            env)

    def has_function(self, funcname: str, prefix: str, env: 'Environment', *,
                     extra_args: T.Optional[T.List[str]] = None,
                     dependencies: T.Optional[T.List['Dependency']] = None) -> bool:
        if extra_args is None:
            extra_args = []
        # Starting with XCode 8, we need to pass this to force linker
        # visibility to obey OS X/iOS/tvOS minimum version targets with
        # -mmacosx-version-min, -miphoneos-version-min, -mtvos-version-min etc.
        # https://github.com/Homebrew/homebrew-core/issues/3727
        # TODO: this really should be communicated by the linker
        if isinstance(self.linker, AppleDynamicLinker) and mesonlib.version_compare(self.version, '>=8.0'):
            extra_args.append('-Wl,-no_weak_imports')
        return super().has_function(funcname, prefix, env, extra_args=extra_args,
                                    dependencies=dependencies)

    def openmp_flags(self) -> T.List[str]:
        if mesonlib.version_compare(self.version, '>=3.8.0'):
            return ['-fopenmp']
        elif mesonlib.version_compare(self.version, '>=3.7.0'):
            return ['-fopenmp=libomp']
        else:
            # Shouldn't work, but it'll be checked explicitly in the OpenMP dependency.
            return []

    @classmethod
    def use_linker_args(cls, linker: str) -> T.List[str]:
        # Clang additionally can use a linker specified as a path, which GCC
        # (and other gcc-like compilers) cannot. This is becuse clang (being
        # llvm based) is retargetable, while GCC is not.
        #
        if shutil.which(linker):
            if not shutil.which(linker):
                raise mesonlib.MesonException(
                    'Cannot find linker {}.'.format(linker))
            return ['-fuse-ld={}'.format(linker)]
        return super().use_linker_args(linker)

    def get_has_func_attribute_extra_args(self, name):
        # Clang only warns about unknown or ignored attributes, so force an
        # error.
        return ['-Werror=attributes']

    def get_coverage_link_args(self) -> T.List[str]:
        return ['--coverage']
