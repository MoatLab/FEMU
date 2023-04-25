# formatters.py - module containing various recipe formatting backends
#
# Copyright (C) 2017-2020 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import abc
import json
import logging
import shlex

from pkg_resources import resource_filename

from lcitool import util, LcitoolError
from lcitool.packages import package_names_by_type


log = logging.getLogger(__name__)


class FormatterError(LcitoolError):
    """
    Global exception type for this module.

    Contains a detailed message coming from one of its subclassed exception
    types.
    """

    pass


class DockerfileError(FormatterError):
    def __init__(self, message):
        super().__init__(message, "Docker formatter")


class VariablesError(FormatterError):
    def __init__(self, message):
        super().__init__(message, "Variables formatter")


class ShellBuildEnvError(FormatterError):
    def __init__(self, message):
        super().__init__(message, "Shell build env formatter")


class Formatter(metaclass=abc.ABCMeta):
    """
    This an abstract base class that each formatter must subclass.
    """

    def __init__(self, projects):
        self._projects = projects

    @abc.abstractmethod
    def format(self):
        """
        Outputs a recipe using format implemented by a Foo(Formatter) subclass

        Given the input, this method will generate and output an instruction
        recipe (or a configuration file in general) using the format of the
        subclassed formatter. Each formatter must implement this method.

        Returns a formatted recipe as string.
        """
        pass

    def _get_meson_cross(self, cross_abi):
        cross_name = resource_filename(__name__,
                                       f"cross/{cross_abi}.meson")
        with open(cross_name, "r") as c:
            return c.read().rstrip()

    def _generator_build_varmap(self,
                                target,
                                selected_projects):
        projects = self._projects

        # we need the 'base' internal project here, but packages for internal
        # projects are not resolved via the public API, so it requires special
        # handling
        pkgs = {}
        pkgs.update(projects.internal["base"].get_packages(target))

        # we can now load packages for the rest of the projects
        pkgs.update(projects.get_packages(selected_projects, target))
        package_names = package_names_by_type(pkgs)

        varmap = {
            "packaging_command": target.facts["packaging"]["command"],
            "paths_ccache": target.facts["paths"]["ccache"],
            "paths_make": target.facts["paths"]["make"],
            "paths_ninja": target.facts["paths"]["ninja"],
            "paths_python": target.facts["paths"]["python"],
            "paths_pip3": target.facts["paths"]["pip3"],

            "cross_arch": None,
            "cross_abi": None,
            "cross_arch_deb": None,

            "mappings": [pkg.mapping for pkg in pkgs.values()],
            "pkgs": package_names["native"],
            "cross_pkgs": package_names["cross"],
            "pypi_pkgs": package_names["pypi"],
            "cpan_pkgs": package_names["cpan"],
        }

        if target.cross_arch:
            varmap["cross_arch"] = target.cross_arch
            varmap["cross_abi"] = util.native_arch_to_abi(target.cross_arch)

            if target.facts["packaging"]["format"] == "deb":
                cross_arch_deb = util.native_arch_to_deb_arch(target.cross_arch)
                varmap["cross_arch_deb"] = cross_arch_deb

        log.debug(f"Generated varmap: {varmap}")
        return varmap


class BuildEnvFormatter(Formatter):

    def __init__(self, inventory, indent=0, pkgcleanup=False, nosync=False):
        super().__init__(inventory)
        self._indent = indent
        self._pkgcleanup = pkgcleanup
        self._nosync = nosync

    def _align(self, command, strings):
        if len(strings) == 1:
            return strings[0]

        align = " \\\n" + (" " * (self._indent + len(command + " ")))
        strings = [shlex.quote(x) for x in strings]
        return align[1:] + align.join(strings)

    def _generator_build_varmap(self,
                                target,
                                selected_projects):
        varmap = super()._generator_build_varmap(target,
                                                 selected_projects)

        varmap["nosync"] = ""
        if self._nosync:
            if target.facts["packaging"]["format"] == "deb":
                varmap["nosync"] = "eatmydata "
            elif target.facts["packaging"]["format"] == "rpm" and target.facts["os"]["name"] == "Fedora":
                varmap["nosync"] = "nosync "
            elif target.facts["packaging"]["format"] == "apk":
                # TODO: 'libeatmydata' package is present in 'testing' repo
                # for Alpine Edge. Once it graduates to 'main' repo we
                # should use it here, and see later comment about adding
                # the package too
                # varmap["nosync"] = "eatmydata "
                pass

        nosync = varmap["nosync"]
        varmap["pkgs"] = self._align(nosync + target.facts["packaging"]["command"],
                                     varmap["pkgs"])

        if varmap["cross_pkgs"]:
            varmap["cross_pkgs"] = self._align(nosync + target.facts["packaging"]["command"],
                                               varmap["cross_pkgs"])
        if varmap["pypi_pkgs"]:
            varmap["pypi_pkgs"] = self._align(nosync + target.facts["paths"]["pip3"],
                                              varmap["pypi_pkgs"])
        if varmap["cpan_pkgs"]:
            varmap["cpan_pkgs"] = self._align(nosync + "cpanm",
                                              varmap["cpan_pkgs"])

        return varmap

    def _format_commands_ccache(self, target, varmap):
        commands = []
        compilers = set()

        if "ccache" not in varmap["mappings"]:
            return []

        for compiler in ["gcc", "clang"]:
            if compiler in varmap["mappings"]:
                compilers.add(compiler)
                compilers.add("cc")
        for compiler in ["g++"]:
            if compiler in varmap["mappings"]:
                compilers.add(compiler)
                compilers.add("c++")

        if compilers:
            commands.extend([
                "mkdir -p /usr/libexec/ccache-wrappers",
            ])

            for compiler in sorted(compilers):
                if target.cross_arch:
                    compiler = "{cross_abi}-" + compiler
                commands.extend([
                    "ln -s {paths_ccache} /usr/libexec/ccache-wrappers/" + compiler,
                ])
        return commands

    def _format_commands_pkglist(self, target):
        facts = target.facts
        commands = []
        if facts["packaging"]["format"] == "apk":
            commands.extend(["apk list | sort > /packages.txt"])
        elif facts["packaging"]["format"] == "deb":
            commands.extend([
                "dpkg-query --showformat '${{Package}}_${{Version}}_${{Architecture}}\\n' --show > /packages.txt"
            ])
        elif facts["packaging"]["format"] == "rpm":
            commands.extend(["rpm -qa | sort > /packages.txt"])
        return commands

    def _format_commands_native(self, target, varmap):
        facts = target.facts
        commands = []
        osname = facts["os"]["name"]
        osversion = facts["os"]["version"]

        if facts["packaging"]["format"] == "apk":
            # See earlier comment about adding this later
            # "{packaging_command} add libeatmydata",
            commands.extend([
                "{packaging_command} update",
                "{packaging_command} upgrade"])

            commands.extend([
                "{nosync}{packaging_command} add {pkgs}",
            ])
        elif facts["packaging"]["format"] == "deb":
            commands.extend([
                "export DEBIAN_FRONTEND=noninteractive",
                "{packaging_command} update"])
            if varmap["nosync"] != "":
                commands.extend(["{packaging_command} install -y eatmydata"])
            commands.extend([
                "{nosync}{packaging_command} dist-upgrade -y",
                "{nosync}{packaging_command} install --no-install-recommends -y {pkgs}"])
            if self._pkgcleanup:
                commands.extend([
                    "{nosync}{packaging_command} autoremove -y",
                    "{nosync}{packaging_command} autoclean -y",
                ])
            commands.extend([
                "sed -Ei 's,^# (en_US\\.UTF-8 .*)$,\\1,' /etc/locale.gen",
                "dpkg-reconfigure locales",
            ])
        elif facts["packaging"]["format"] == "rpm":
            # Rawhide needs this because the keys used to sign packages are
            # cycled from time to time
            if osname == "Fedora" and osversion == "Rawhide":
                commands.extend([
                    "{packaging_command} update -y --nogpgcheck fedora-gpg-keys",
                ])

            if osname == "Fedora" and varmap["nosync"] != "":
                nosyncsh = [
                    "#!/bin/sh",
                    "if test -d /usr/lib64",
                    "then",
                    "    export LD_PRELOAD=/usr/lib64/nosync/nosync.so",
                    "else",
                    "    export LD_PRELOAD=/usr/lib/nosync/nosync.so",
                    "fi",
                    "exec \"$@\""
                ]
                commands.extend([
                    "{packaging_command} install -y nosync",
                    "echo -e '%s' > /usr/bin/nosync" % "\\n\\\n".join(nosyncsh),
                    "chmod +x /usr/bin/nosync"])

            # First we need to run update, then config and install.
            # For rolling distros, it's preferable to do a distro syncing type
            # of update rather than a regular package update
            if (osname == "Fedora" and osversion == "Rawhide" or
                osname == "CentOS" and (osversion == "Stream8" or
                                        osversion == "Stream9")):
                commands.extend(["{nosync}{packaging_command} distro-sync -y"])
            elif osname == "OpenSUSE" and osversion == "Tumbleweed":
                commands.extend(["{nosync}{packaging_command} dist-upgrade -y"])
            else:
                commands.extend(["{nosync}{packaging_command} update -y"])

            if osname in ["AlmaLinux", "CentOS"]:
                # NOTE: AlmaLinux is one of the replacement community distros
                # for the original CentOS distro and so the checks below apply
                # there as well
                #
                # Starting with CentOS 8, most -devel packages are shipped in
                # a separate repository which is not enabled by default. The
                # name of this repository has changed over time
                commands.extend([
                    "{nosync}{packaging_command} install 'dnf-command(config-manager)' -y",
                ])
                if osversion in ["9", "Stream9"]:
                    commands.extend([
                        "{nosync}{packaging_command} config-manager --set-enabled -y crb",
                    ])
                if osversion in ["8", "Stream8"]:
                    commands.extend([
                        "{nosync}{packaging_command} config-manager --set-enabled -y powertools",
                    ])

                # Not all of the virt related -devel packages are provided by
                # virt:rhel module so we have to enable AV repository as well.
                # CentOS Stream 9 no longer uses modules for virt
                if osversion in ["8", "Stream8"]:
                    commands.extend([
                        "{nosync}{packaging_command} install -y centos-release-advanced-virtualization",
                    ])

                # Some of the packages we need are not part of CentOS proper
                # and are only available through EPEL
                commands.extend([
                    "{nosync}{packaging_command} install -y epel-release",
                ])

                # For CentOS Stream, we want EPEL Next as well
                if osversion in ["Stream8", "Stream9"]:
                    commands.extend([
                        "{nosync}{packaging_command} install -y epel-next-release",
                    ])

            commands.extend(["{nosync}{packaging_command} install -y {pkgs}"])

            if self._pkgcleanup:
                # openSUSE doesn't seem to have a convenient way to remove all
                # unnecessary packages, but CentOS and Fedora do
                if osname == "OpenSUSE":
                    commands.extend([
                        "{nosync}{packaging_command} clean --all",
                    ])
                else:
                    commands.extend([
                        "{nosync}{packaging_command} autoremove -y",
                        "{nosync}{packaging_command} clean all -y",
                    ])

        if not target.cross_arch:
            commands.extend(self._format_commands_pkglist(target))
            commands.extend(self._format_commands_ccache(target, varmap))

        commands = [c.format(**varmap) for c in commands]

        groups = [commands]
        if varmap["pypi_pkgs"]:
            groups.append(["{paths_pip3} install {pypi_pkgs}".format(**varmap)])

        if varmap["cpan_pkgs"]:
            groups.append(["cpanm --notest {cpan_pkgs}".format(**varmap)])

        return groups

    def _format_env_native(self, varmap):
        env = {}

        env["LANG"] = "en_US.UTF-8"
        if "make" in varmap["mappings"]:
            env["MAKE"] = varmap["paths_make"]
        if "meson" in varmap["mappings"]:
            env["NINJA"] = varmap["paths_ninja"]
        if "python3" in varmap["mappings"]:
            env["PYTHON"] = varmap["paths_python"]
        if "ccache" in varmap["mappings"]:
            env["CCACHE_WRAPPERSDIR"] = "/usr/libexec/ccache-wrappers"

        return env

    def _format_commands_foreign(self, target, varmap):
        facts = target.facts
        cross_commands = []

        if facts["packaging"]["format"] == "deb":
            cross_commands.extend([
                "export DEBIAN_FRONTEND=noninteractive",
                "dpkg --add-architecture {cross_arch_deb}",
            ])
            if target.cross_arch == "riscv64":
                cross_commands.extend([
                    "{nosync}{packaging_command} install debian-ports-archive-keyring",
                    "{nosync}echo 'deb http://ftp.ports.debian.org/debian-ports/ sid main' > /etc/apt/sources.list.d/ports.list",
                    "{nosync}echo 'deb http://ftp.ports.debian.org/debian-ports/ unreleased main' >> /etc/apt/sources.list.d/ports.list",
                ])
            cross_commands.extend([
                "{nosync}{packaging_command} update",
                "{nosync}{packaging_command} dist-upgrade -y",
                "{nosync}{packaging_command} install --no-install-recommends -y dpkg-dev",
            ])
            if varmap["cross_pkgs"]:
                cross_commands.extend([
                    "{nosync}{packaging_command} install --no-install-recommends -y {cross_pkgs}",
                ])
            if self._pkgcleanup:
                cross_commands.extend([
                    "{nosync}{packaging_command} autoremove -y",
                    "{nosync}{packaging_command} autoclean -y",
                ])
        elif facts["packaging"]["format"] == "rpm":
            if varmap["cross_pkgs"]:
                cross_commands.extend([
                    "{nosync}{packaging_command} install -y {cross_pkgs}",
                ])
            if self._pkgcleanup:
                cross_commands.extend([
                    "{nosync}{packaging_command} clean all -y",
                ])

        if not target.cross_arch.startswith("mingw"):
            cross_commands.extend([
                "mkdir -p /usr/local/share/meson/cross",
                "echo \"{cross_meson}\" > /usr/local/share/meson/cross/{cross_abi}",
            ])

            cross_meson = self._get_meson_cross(varmap["cross_abi"])
            varmap["cross_meson"] = cross_meson.replace("\n", "\\n\\\n")

        cross_commands.extend(self._format_commands_pkglist(target))
        cross_commands.extend(self._format_commands_ccache(target, varmap))

        cross_commands = [c.format(**varmap) for c in cross_commands]

        return cross_commands

    def _format_env_foreign(self, target, varmap):
        env = {}
        env["ABI"] = varmap["cross_abi"]

        if "autoconf" in varmap["mappings"]:
            env["CONFIGURE_OPTS"] = "--host=" + varmap["cross_abi"]

        if "meson" in varmap["mappings"]:
            if target.cross_arch.startswith("mingw"):
                env["MESON_OPTS"] = "--cross-file=/usr/share/mingw/toolchain-" + varmap["cross_arch"] + ".meson"
            else:
                env["MESON_OPTS"] = "--cross-file=" + varmap["cross_abi"]

        return env


class DockerfileFormatter(BuildEnvFormatter):

    def __init__(self, inventory, base=None, layers="all"):
        super().__init__(inventory,
                         indent=len("RUN "),
                         pkgcleanup=True,
                         nosync=True)
        self._base = base
        self._layers = layers

    @staticmethod
    def _format_env(env):
        lines = []
        for key in sorted(env.keys()):
            val = env[key]
            lines.append(f"\nENV {key} \"{val}\"")
        return "".join(lines)

    def _format_section_base(self, target):
        strings = []
        if self._base:
            base = self._base
        else:
            base = target.facts["containers"]["base"]
        strings.append(f"FROM {base}")
        return strings

    def _format_section_native(self, target, varmap):
        groups = self._format_commands_native(target, varmap)

        strings = []
        for commands in groups:
            strings.append("\nRUN " + " && \\\n    ".join(commands))

        env = self._format_env_native(varmap)
        strings.append(self._format_env(env))
        return strings

    def _format_section_foreign(self, target, varmap):
        commands = self._format_commands_foreign(target, varmap)

        strings = ["\nRUN " + " && \\\n    ".join(commands)]

        env = self._format_env_foreign(target, varmap)
        strings.append(self._format_env(env))
        return strings

    def _format_dockerfile(self, target, project, varmap):
        strings = []
        strings.extend(self._format_section_base(target))
        if self._layers in ["all", "native"]:
            strings.extend(self._format_section_native(target, varmap))
        if target.cross_arch and self._layers in ["all", "foreign"]:
            strings.extend(self._format_section_foreign(target, varmap))
        return strings

    def format(self, target, selected_projects):
        """
        Generates and formats a Dockerfile.

        Given the application commandline arguments, this function will take
        the projects and inventory attributes and generate a Dockerfile
        describing an environment for doing a project build on a given
        inventory platform.

        :param args: Application class' command line arguments
        :returns: String represented Dockerfile
        """

        log.debug(f"Generating Dockerfile for projects '{selected_projects}' "
                  f"on target {target}")

        # We can only generate Dockerfiles for Linux
        if (target.facts["packaging"]["format"] not in ["apk", "deb", "rpm"]):
            raise DockerfileError(f"Target {target} doesn't support this generator")

        try:
            varmap = self._generator_build_varmap(target, selected_projects)
        except FormatterError as ex:
            raise DockerfileError(str(ex))

        return '\n'.join(self._format_dockerfile(target, selected_projects, varmap))


class VariablesFormatter(Formatter):
    @staticmethod
    def _normalize_variables(varmap):
        normalized_vars = {}
        for key in varmap:
            if varmap[key] is None:
                continue

            if key == "mappings":
                # For internal use only
                continue

            if key.startswith("paths_"):
                name = key[len("paths_"):]
            else:
                name = key
            normalized_vars[name] = varmap[key]

        return normalized_vars

    @staticmethod
    @abc.abstractmethod
    def _format_variables(varmap):
        pass

    def format(self, target, selected_projects):
        """
        Generates and formats environment variables as KEY=VAL pairs.

        Given the commandline arguments, this function will take take the
        projects and inventory attributes and generate a KEY=VAL encoded list
        of environment variables that can be consumed by various CI backends.

        :param args: Application class' command line arguments
        :returns: String represented list of environment variables
        """

        log.debug(f"Generating variables for projects '{selected_projects} on "
                  f"target {target}")

        try:
            varmap = self._generator_build_varmap(target, selected_projects)
        except FormatterError as ex:
            raise VariablesError(str(ex))

        varmap = self._normalize_variables(varmap)
        return self._format_variables(varmap)


class ShellVariablesFormatter(VariablesFormatter):
    @staticmethod
    def _format_variables(varmap):
        strings = []

        for key in sorted(varmap.keys()):
            value = varmap[key]
            if key == "pkgs" or key.endswith("_pkgs"):
                value = " ".join(varmap[key])

            uppername = key.upper()
            strings.append(f"{uppername}='{value}'")
        return "\n".join(strings)


class JSONVariablesFormatter(VariablesFormatter):
    @staticmethod
    def _format_variables(varmap):
        return json.dumps(varmap, indent="  ", sort_keys=True)


class ShellBuildEnvFormatter(BuildEnvFormatter):

    def __init__(self, inventory, base=None, layers="all"):
        super().__init__(inventory,
                         indent=len("    "),
                         pkgcleanup=False,
                         nosync=False)

    @staticmethod
    def _format_env(env):
        exp = []
        for key in sorted(env.keys()):
            val = env[key]
            exp.append(f"export {key}=\"{val}\"")
        return "\n" + "\n".join(exp)

    def _format_buildenv(self, target, project, varmap):
        strings = [
            "function install_buildenv() {",
        ]
        groups = self._format_commands_native(target, varmap)
        for commands in groups:
            strings.extend(["    " + c for c in commands])
        if target.cross_arch:
            for command in self._format_commands_foreign(target, varmap):
                strings.append("    " + command)
        strings.append("}")

        strings.append(self._format_env(self._format_env_native(varmap)))
        if target.cross_arch:
            strings.append(self._format_env(
                self._format_env_foreign(target, varmap)))
        return strings

    def format(self, target, selected_projects):
        """
        Generates and formats a Shell script for preparing a build env.

        Given the application commandline arguments, this function will take
        the projects and inventory attributes and generate a shell script
        that prepares a environment for doing a project build on a given
        inventory platform.

        :param args: Application class' command line arguments
        :returns: String represented shell script
        """

        log.debug(f"Generating Shell Build Env for projects '{selected_projects}' "
                  f"on target {target}")

        try:
            varmap = self._generator_build_varmap(target, selected_projects)
        except FormatterError as ex:
            raise ShellBuildEnvError(str(ex))

        return '\n'.join(self._format_buildenv(target, selected_projects, varmap))
