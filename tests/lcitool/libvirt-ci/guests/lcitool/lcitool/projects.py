# projects.py - module containing per-project package mapping primitives
#
# Copyright (C) 2017-2020 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
import yaml

from pathlib import Path
from pkg_resources import resource_filename

from lcitool import util
from lcitool.package import PackageFactory, PyPIPackage, CPANPackage
from lcitool.singleton import Singleton

log = logging.getLogger(__name__)


class ProjectError(Exception):
    """
    Global exception type for the projects module.

    Functions/methods in this module will raise either this exception or its
    subclass on failure.
    On the application level, this is the exception type you should be
    catching.
    """

    def __init__(self, message):
        self.message = message

    def __str__(self):
        return f"Project error: {self.message}"


class Projects(metaclass=Singleton):
    """
    Attributes:
        :ivar names: list of all project names
    """

    @property
    def projects(self):
        if self._projects is None:
            self._projects = self._load_projects()
        return self._projects

    @property
    def names(self):
        return list(self.projects.keys())

    @property
    def internal_projects(self):
        if self._internal_projects is None:
            self._internal_projects = self._load_internal_projects()
        return self._internal_projects

    @property
    def mappings(self):

        # lazy load mappings
        if self._mappings is None:
            self._mappings = self._load_mappings()
        return self._mappings

    def __init__(self):
        self._projects = None
        self._internal_projects = None
        self._mappings = None

    @staticmethod
    def _load_projects_from_path(path):
        projects = {}

        for item in path.iterdir():
            if not item.is_file() or item.suffix != ".yml":
                continue

            projects[item.stem] = Project(item.stem, item)

        return projects

    @staticmethod
    def _load_projects():
        source = Path(resource_filename(__name__, "ansible/vars/projects"))
        projects = Projects._load_projects_from_path(source)

        if util.get_extra_data_dir() is not None:
            source = Path(util.get_extra_data_dir()).joinpath("projects")
            projects.update(Projects._load_projects_from_path(source))

        return projects

    @staticmethod
    def _load_internal_projects():
        source = Path(resource_filename(__name__, "ansible/vars/projects/internal"))
        return Projects._load_projects_from_path(source)

    def _load_mappings(self):
        mappings_path = resource_filename(__name__,
                                          "ansible/vars/mappings.yml")

        try:
            with open(mappings_path, "r") as infile:
                return yaml.safe_load(infile)
        except Exception as ex:
            raise ProjectError(f"Can't load mappings: {ex}")

    def expand_names(self, pattern):
        try:
            return util.expand_pattern(pattern, self.names, "project")
        except Exception as ex:
            raise ProjectError(f"Failed to expand '{pattern}': {ex}")

    def get_packages(self, projects, facts, cross_arch=None):
        packages = {}

        for proj in projects:
            try:
                obj = self.projects[proj]
            except KeyError:
                obj = self.internal_projects[proj]
            packages.update(obj.get_packages(facts, cross_arch))

        return packages


class Project:
    """
    Attributes:
        :ivar name: project name
        :ivar generic_packages: list of generic packages needed by the project
                                to build successfully
    """

    @property
    def generic_packages(self):

        # lazy evaluation: load per-project generic package list when we actually need it
        if self._generic_packages is None:
            self._generic_packages = self._load_generic_packages()
        return self._generic_packages

    def __init__(self, name, path):
        self.name = name
        self.path = path
        self._generic_packages = None
        self._target_packages = {}

    def _load_generic_packages(self):
        log.debug(f"Loading generic package list for project '{self.name}'")

        try:
            with open(self.path, "r") as infile:
                yaml_packages = yaml.safe_load(infile)
                return yaml_packages["packages"]
        except Exception as ex:
            raise ProjectError(f"Can't load packages for '{self.name}': {ex}")

    def _eval_generic_packages(self, facts, cross_arch=None):
        pkgs = {}
        factory = PackageFactory(Projects().mappings, facts)
        needs_pypi = False
        needs_cpan = False

        for mapping in self.generic_packages:
            pkg = factory.get_package(mapping, cross_arch)
            if pkg is None:
                continue
            pkgs[pkg.mapping] = pkg

            if isinstance(pkg, PyPIPackage):
                needs_pypi = True
            elif isinstance(pkg, CPANPackage):
                needs_cpan = True

        # The get_packages _eval_generic_packages cycle is deliberate and
        # harmless since we'll only ever hit it with the following internal
        # projects
        if needs_pypi:
            proj = Projects().internal_projects["python-pip"]
            pkgs.update(proj.get_packages(facts, cross_arch))
        if needs_cpan:
            proj = Projects().internal_projects["perl-cpan"]
            pkgs.update(proj.get_packages(facts, cross_arch))

        return pkgs

    def get_packages(self, facts, cross_arch=None):
        osname = facts["os"]["name"]
        osversion = facts["os"]["version"]
        target_name = f"{osname.lower()}-{osversion.lower()}"
        if cross_arch is None:
            target_name = f"{target_name}-x86_64"
        else:
            try:
                util.validate_cross_platform(cross_arch, osname)
            except ValueError as ex:
                raise ProjectError(ex)
            target_name = f"{target_name}-{cross_arch}"

        # lazy evaluation + caching of package names for a given distro
        if self._target_packages.get(target_name) is None:
            self._target_packages[target_name] = self._eval_generic_packages(facts, cross_arch)
        return self._target_packages[target_name]
