# Copyright 2013-2017 The Meson development team
# Copyright © 2021 Intel Corporation
# SPDX-license-identifier: Apache-2.0

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Dependency finders for the Qt framework."""

import abc
import re
import os
import typing as T

from .base import DependencyException, DependencyMethods
from .configtool import ConfigToolDependency
from .framework import ExtraFrameworkDependency
from .pkgconfig import PkgConfigDependency
from .factory import DependencyFactory
from .. import mlog
from .. import mesonlib

if T.TYPE_CHECKING:
    from ..compilers import Compiler
    from ..envconfig import MachineInfo
    from ..environment import Environment


def _qt_get_private_includes(mod_inc_dir: str, module: str, mod_version: str) -> T.List[str]:
    # usually Qt5 puts private headers in /QT_INSTALL_HEADERS/module/VERSION/module/private
    # except for at least QtWebkit and Enginio where the module version doesn't match Qt version
    # as an example with Qt 5.10.1 on linux you would get:
    # /usr/include/qt5/QtCore/5.10.1/QtCore/private/
    # /usr/include/qt5/QtWidgets/5.10.1/QtWidgets/private/
    # /usr/include/qt5/QtWebKit/5.212.0/QtWebKit/private/

    # on Qt4 when available private folder is directly in module folder
    # like /usr/include/QtCore/private/
    if int(mod_version.split('.')[0]) < 5:
        return []

    private_dir = os.path.join(mod_inc_dir, mod_version)
    # fallback, let's try to find a directory with the latest version
    if not os.path.exists(private_dir):
        dirs = [filename for filename in os.listdir(mod_inc_dir)
                if os.path.isdir(os.path.join(mod_inc_dir, filename))]

        for dirname in sorted(dirs, reverse=True):
            if len(dirname.split('.')) == 3:
                private_dir = dirname
                break
    return [private_dir, os.path.join(private_dir, 'Qt' + module)]


def get_qmake_host_bins(qvars: T.Dict[str, str]) -> str:
    # Prefer QT_HOST_BINS (qt5, correct for cross and native compiling)
    # but fall back to QT_INSTALL_BINS (qt4)
    if 'QT_HOST_BINS' in qvars:
        return qvars['QT_HOST_BINS']
    return qvars['QT_INSTALL_BINS']


def _get_modules_lib_suffix(version: str, info: 'MachineInfo', is_debug: bool) -> str:
    """Get the module suffix based on platform and debug type."""
    suffix = ''
    if info.is_windows():
        if is_debug:
            suffix += 'd'
        if version.startswith('4'):
            suffix += '4'
    if info.is_darwin():
        if is_debug:
            suffix += '_debug'
    if mesonlib.version_compare(version, '>= 5.14.0'):
        if info.is_android():
            if info.cpu_family == 'x86':
                suffix += '_x86'
            elif info.cpu_family == 'x86_64':
                suffix += '_x86_64'
            elif info.cpu_family == 'arm':
                suffix += '_armeabi-v7a'
            elif info.cpu_family == 'aarch64':
                suffix += '_arm64-v8a'
            else:
                mlog.warning(f'Android target arch "{info.cpu_family}"" for Qt5 is unknown, '
                             'module detection may not work')
    return suffix


class QtExtraFrameworkDependency(ExtraFrameworkDependency):
    def __init__(self, name: str, env: 'Environment', kwargs: T.Dict[str, T.Any], language: T.Optional[str] = None):
        super().__init__(name, env, kwargs, language=language)
        self.mod_name = name[2:]

    def get_compile_args(self, with_private_headers: bool = False, qt_version: str = "0") -> T.List[str]:
        if self.found():
            mod_inc_dir = os.path.join(self.framework_path, 'Headers')
            args = ['-I' + mod_inc_dir]
            if with_private_headers:
                args += ['-I' + dirname for dirname in _qt_get_private_includes(mod_inc_dir, self.mod_name, qt_version)]
            return args
        return []


class _QtBase:

    """Mixin class for shared componenets between PkgConfig and Qmake."""

    link_args: T.List[str]
    clib_compiler: 'Compiler'
    env: 'Environment'

    def __init__(self, name: str, kwargs: T.Dict[str, T.Any]):
        self.qtname = name.capitalize()
        self.qtver = name[-1]
        if self.qtver == "4":
            self.qtpkgname = 'Qt'
        else:
            self.qtpkgname = self.qtname

        self.private_headers = T.cast(bool, kwargs.get('private_headers', False))

        self.requested_modules = mesonlib.stringlistify(mesonlib.extract_as_list(kwargs, 'modules'))
        if not self.requested_modules:
            raise DependencyException('No ' + self.qtname + '  modules specified.')

        self.qtmain = T.cast(bool, kwargs.get('main', False))
        if not isinstance(self.qtmain, bool):
            raise DependencyException('"main" argument must be a boolean')

    def _link_with_qtmain(self, is_debug: bool, libdir: T.Union[str, T.List[str]]) -> bool:
        libdir = mesonlib.listify(libdir)  # TODO: shouldn't be necessary
        base_name = 'qtmaind' if is_debug else 'qtmain'
        qtmain = self.clib_compiler.find_library(base_name, self.env, libdir)
        if qtmain:
            self.link_args.append(qtmain[0])
            return True
        return False

    def get_exe_args(self, compiler: 'Compiler') -> T.List[str]:
        # Originally this was -fPIE but nowadays the default
        # for upstream and distros seems to be -reduce-relocations
        # which requires -fPIC. This may cause a performance
        # penalty when using self-built Qt or on platforms
        # where -fPIC is not required. If this is an issue
        # for you, patches are welcome.
        return compiler.get_pic_args()

    def log_details(self) -> str:
        return f'modules: {", ".join(sorted(self.requested_modules))}'


class QtPkgConfigDependency(_QtBase, PkgConfigDependency, metaclass=abc.ABCMeta):

    """Specialization of the PkgConfigDependency for Qt."""

    def __init__(self, name: str, env: 'Environment', kwargs: T.Dict[str, T.Any]):
        _QtBase.__init__(self, name, kwargs)

        # Always use QtCore as the "main" dependency, since it has the extra
        # pkg-config variables that a user would expect to get. If "Core" is
        # not a requested module, delete the compile and link arguments to
        # avoid linking with something they didn't ask for
        PkgConfigDependency.__init__(self, self.qtpkgname + 'Core', env, kwargs)
        if 'Core' not in self.requested_modules:
            self.compile_args = []
            self.link_args = []

        for m in self.requested_modules:
            mod = PkgConfigDependency(self.qtpkgname + m, self.env, kwargs, language=self.language)
            if not mod.found():
                self.is_found = False
                return
            if self.private_headers:
                qt_inc_dir = mod.get_pkgconfig_variable('includedir', {})
                mod_private_dir = os.path.join(qt_inc_dir, 'Qt' + m)
                if not os.path.isdir(mod_private_dir):
                    # At least some versions of homebrew don't seem to set this
                    # up correctly. /usr/local/opt/qt/include/Qt + m_name is a
                    # symlink to /usr/local/opt/qt/include, but the pkg-config
                    # file points to /usr/local/Cellar/qt/x.y.z/Headers/, and
                    # the Qt + m_name there is not a symlink, it's a file
                    mod_private_dir = qt_inc_dir
                mod_private_inc = _qt_get_private_includes(mod_private_dir, m, mod.version)
                for directory in mod_private_inc:
                    mod.compile_args.append('-I' + directory)
            self._add_sub_dependency([lambda: mod])

        if self.env.machines[self.for_machine].is_windows() and self.qtmain:
            # Check if we link with debug binaries
            debug_lib_name = self.qtpkgname + 'Core' + _get_modules_lib_suffix(self.version, self.env.machines[self.for_machine], True)
            is_debug = False
            for arg in self.get_link_args():
                if arg == f'-l{debug_lib_name}' or arg.endswith(f'{debug_lib_name}.lib') or arg.endswith(f'{debug_lib_name}.a'):
                    is_debug = True
                    break
            libdir = self.get_pkgconfig_variable('libdir', {})
            if not self._link_with_qtmain(is_debug, libdir):
                self.is_found = False
                return

        self.bindir = self.get_pkgconfig_host_bins(self)
        if not self.bindir:
            # If exec_prefix is not defined, the pkg-config file is broken
            prefix = self.get_pkgconfig_variable('exec_prefix', {})
            if prefix:
                self.bindir = os.path.join(prefix, 'bin')

    @staticmethod
    @abc.abstractmethod
    def get_pkgconfig_host_bins(core: PkgConfigDependency) -> T.Optional[str]:
        pass

    @abc.abstractmethod
    def get_private_includes(self, mod_inc_dir: str, module: str) -> T.List[str]:
        pass

    def log_info(self) -> str:
        return 'pkg-config'


class QmakeQtDependency(_QtBase, ConfigToolDependency, metaclass=abc.ABCMeta):

    """Find Qt using Qmake as a config-tool."""

    tool_name = 'qmake'
    version_arg = '-v'

    def __init__(self, name: str, env: 'Environment', kwargs: T.Dict[str, T.Any]):
        _QtBase.__init__(self, name, kwargs)
        self.tools = [f'qmake-{self.qtname}', 'qmake']

        # Add additional constraits that the Qt version is met, but preserve
        # any version requrements the user has set as well. For exmaple, if Qt5
        # is requested, add "">= 5, < 6", but if the user has ">= 5.6", don't
        # lose that.
        kwargs = kwargs.copy()
        _vers = mesonlib.listify(kwargs.get('version', []))
        _vers.extend([f'>= {self.qtver}', f'< {int(self.qtver) + 1}'])
        kwargs['version'] = _vers

        ConfigToolDependency.__init__(self, name, env, kwargs)
        if not self.found():
            return

        # Query library path, header path, and binary path
        stdo = self.get_config_value(['-query'], 'args')
        qvars: T.Dict[str, str] = {}
        for line in stdo:
            line = line.strip()
            if line == '':
                continue
            k, v = line.split(':', 1)
            qvars[k] = v
        # Qt on macOS uses a framework, but Qt for iOS/tvOS does not
        xspec = qvars.get('QMAKE_XSPEC', '')
        if self.env.machines.host.is_darwin() and not any(s in xspec for s in ['ios', 'tvos']):
            mlog.debug("Building for macOS, looking for framework")
            self._framework_detect(qvars, self.requested_modules, kwargs)
            # Sometimes Qt is built not as a framework (for instance, when using conan pkg manager)
            # skip and fall back to normal procedure then
            if self.is_found:
                return
            else:
                mlog.debug("Building for macOS, couldn't find framework, falling back to library search")
        incdir = qvars['QT_INSTALL_HEADERS']
        self.compile_args.append('-I' + incdir)
        libdir = qvars['QT_INSTALL_LIBS']
        # Used by qt.compilers_detect()
        self.bindir = get_qmake_host_bins(qvars)

        # Use the buildtype by default, but look at the b_vscrt option if the
        # compiler supports it.
        is_debug = self.env.coredata.get_option(mesonlib.OptionKey('buildtype')) == 'debug'
        if mesonlib.OptionKey('b_vscrt') in self.env.coredata.options:
            if self.env.coredata.options[mesonlib.OptionKey('b_vscrt')].value in {'mdd', 'mtd'}:
                is_debug = True
        modules_lib_suffix = _get_modules_lib_suffix(self.version, self.env.machines[self.for_machine], is_debug)

        for module in self.requested_modules:
            mincdir = os.path.join(incdir, 'Qt' + module)
            self.compile_args.append('-I' + mincdir)

            if module == 'QuickTest':
                define_base = 'QMLTEST'
            elif module == 'Test':
                define_base = 'TESTLIB'
            else:
                define_base = module.upper()
            self.compile_args.append(f'-DQT_{define_base}_LIB')

            if self.private_headers:
                priv_inc = self.get_private_includes(mincdir, module)
                for directory in priv_inc:
                    self.compile_args.append('-I' + directory)
            libfiles = self.clib_compiler.find_library(
                self.qtpkgname + module + modules_lib_suffix, self.env,
                mesonlib.listify(libdir)) # TODO: shouldn't be necissary
            if libfiles:
                libfile = libfiles[0]
            else:
                mlog.log("Could not find:", module,
                         self.qtpkgname + module + modules_lib_suffix,
                         'in', libdir)
                self.is_found = False
                break
            self.link_args.append(libfile)

        if self.env.machines[self.for_machine].is_windows() and self.qtmain:
            if not self._link_with_qtmain(is_debug, libdir):
                self.is_found = False

    def _sanitize_version(self, version: str) -> str:
        m = re.search(rf'({self.qtver}(\.\d+)+)', version)
        if m:
            return m.group(0).rstrip('.')
        return version

    @abc.abstractmethod
    def get_private_includes(self, mod_inc_dir: str, module: str) -> T.List[str]:
        pass

    def _framework_detect(self, qvars: T.Dict[str, str], modules: T.List[str], kwargs: T.Dict[str, T.Any]) -> None:
        libdir = qvars['QT_INSTALL_LIBS']

        # ExtraFrameworkDependency doesn't support any methods
        fw_kwargs = kwargs.copy()
        fw_kwargs.pop('method', None)
        fw_kwargs['paths'] = [libdir]

        for m in modules:
            fname = 'Qt' + m
            mlog.debug('Looking for qt framework ' + fname)
            fwdep = QtExtraFrameworkDependency(fname, self.env, fw_kwargs, language=self.language)
            if fwdep.found():
                self.compile_args.append('-F' + libdir)
                self.compile_args += fwdep.get_compile_args(with_private_headers=self.private_headers,
                                                            qt_version=self.version)
                self.link_args += fwdep.get_link_args()
            else:
                self.is_found = False
                break
        else:
            self.is_found = True
            # Used by self.compilers_detect()
            self.bindir = get_qmake_host_bins(qvars)

    def log_info(self) -> str:
        return 'qmake'


class Qt4ConfigToolDependency(QmakeQtDependency):

    def get_private_includes(self, mod_inc_dir: str, module: str) -> T.List[str]:
        return []


class Qt5ConfigToolDependency(QmakeQtDependency):

    def get_private_includes(self, mod_inc_dir: str, module: str) -> T.List[str]:
        return _qt_get_private_includes(mod_inc_dir, module, self.version)


class Qt6ConfigToolDependency(QmakeQtDependency):

    def get_private_includes(self, mod_inc_dir: str, module: str) -> T.List[str]:
        return _qt_get_private_includes(mod_inc_dir, module, self.version)


class Qt4PkgConfigDependency(QtPkgConfigDependency):

    @staticmethod
    def get_pkgconfig_host_bins(core: PkgConfigDependency) -> T.Optional[str]:
        # Only return one bins dir, because the tools are generally all in one
        # directory for Qt4, in Qt5, they must all be in one directory. Return
        # the first one found among the bin variables, in case one tool is not
        # configured to be built.
        applications = ['moc', 'uic', 'rcc', 'lupdate', 'lrelease']
        for application in applications:
            try:
                return os.path.dirname(core.get_pkgconfig_variable('%s_location' % application, {}))
            except mesonlib.MesonException:
                pass
        return None

    def get_private_includes(self, mod_inc_dir: str, module: str) -> T.List[str]:
        return []


class Qt5PkgConfigDependency(QtPkgConfigDependency):

    @staticmethod
    def get_pkgconfig_host_bins(core: PkgConfigDependency) -> str:
        return core.get_pkgconfig_variable('host_bins', {})

    def get_private_includes(self, mod_inc_dir: str, module: str) -> T.List[str]:
        return _qt_get_private_includes(mod_inc_dir, module, self.version)


class Qt6PkgConfigDependency(QtPkgConfigDependency):

    @staticmethod
    def get_pkgconfig_host_bins(core: PkgConfigDependency) -> str:
        return core.get_pkgconfig_variable('host_bins', {})

    def get_private_includes(self, mod_inc_dir: str, module: str) -> T.List[str]:
        return _qt_get_private_includes(mod_inc_dir, module, self.version)


qt4_factory = DependencyFactory(
    'qt4',
    [DependencyMethods.PKGCONFIG, DependencyMethods.CONFIG_TOOL],
    pkgconfig_class=Qt4PkgConfigDependency,
    configtool_class=Qt4ConfigToolDependency,
)

qt5_factory = DependencyFactory(
    'qt5',
    [DependencyMethods.PKGCONFIG, DependencyMethods.CONFIG_TOOL],
    pkgconfig_class=Qt5PkgConfigDependency,
    configtool_class=Qt5ConfigToolDependency,
)

qt6_factory = DependencyFactory(
    'qt6',
    [DependencyMethods.PKGCONFIG, DependencyMethods.CONFIG_TOOL],
    pkgconfig_class=Qt6PkgConfigDependency,
    configtool_class=Qt6ConfigToolDependency,
)
