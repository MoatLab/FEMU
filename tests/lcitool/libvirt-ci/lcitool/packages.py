# package.py - module resolving package mappings to real-world package names
#
# Copyright (C) 2021 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Translates generic package mapping names to concrete package names

This module takes care of translation of the generic package mapping names
originating from the mappings.yml file (e.g. facts/mappings.yml) to
specific package names depending on several factors like packaging format, OS
distribution, cross building, etc.

Each package is represented by the abstract Package class which serves as a
base class for the specific package type subclasses (see the hierarchy below).

                            +-------------------+
                            |      Package      |
                            +-------------------+
             _______________|    |         |    |_____________
            |                    |         |                  |
+-----------v--+    +------------v--+    +-v-----------+    +-v-----------+
| CrossPackage |    | NativePackage |    | PyPIPackage |    | CPANPackage |
+--------------+    +---------------+    +-------------+    +-------------+

Exported classes:
    - Package
    - NativePackage
    - CrossPackage
    - PyPIPackage
    - CPANPackage
    - Packages

Exported functions:
    - package_names_by_type
"""


import abc
import logging

from lcitool import util, LcitoolError

log = logging.getLogger(__name__)


def package_names_by_type(pkgs):
    if not isinstance(pkgs, dict):
        return None

    package_names = {}
    for cls in [NativePackage, CrossPackage, PyPIPackage, CPANPackage]:
        # This will extract e.g. 'pypi' from PyPIPackage
        pkg_type = cls.__name__.replace("Package", "").lower()

        names = set([p.name for p in pkgs.values() if isinstance(p, cls)])
        package_names[pkg_type] = sorted(names)

    return package_names


class PackageError(LcitoolError):
    """
    Global exception type for the package module.

    Contains a detailed message coming from one of its subclassed exception
    types.
    """

    def __init__(self, message):
        super().__init__(message, "Package generic name resolution")


class PackageEval(PackageError):
    """Thrown when the generic name could not be resolved with the given package type"""


class PackageMissing(PackageError):
    """Thrown when the package is missing from the mappings entirely"""


class Package(metaclass=abc.ABCMeta):
    """
    Abstract base class for all package types

    This class defines the public interface for all its subclasses:
        - NativePackage
        - CrossPackage
        - PyPIPackage
        - CPANPackage

    Do not instantiate any of the specific package subclasses, instead, use
    the Packages class which does that for you transparently.
    Then use this public interface to interact with the instance itself.

    Attributes:
        :ivar name: the actual package name
        :ivar mapping: the generic package name that will resolve to @name
    """

    def __init__(self, mappings, pkg_mapping, keys, target):
        """
        Initialize the package with a generic package name

        :param pkg_mapping: name of the package mapping to resolve
        """

        self.mapping = pkg_mapping
        self.name = self._eval(mappings, target, keys)
        if self.name is None:
            raise PackageEval(f"No mapping for '{pkg_mapping}'")

    def _eval(self, mappings, target, keys):
        """
        Resolves package mapping to the actual name of the package.

        This method modifies the internal state of the instance. Depending on
        what packaging system needs to be used to resolve the given mapping
        the instance's name public attribute will be filled in accordingly.

        :param mappings: dictionary of generic package name mappings
        :param key: which subkey to look for in a given package mapping,
                    e.g. key='rpm', key='CentOS', key='cross-mingw32-rpm', etc.
        :return: name of the resolved package as string, can be None if the
                 package is supposed to be disabled on the given platform
        """

        log.debug(f"Eval of mapping='{self.mapping}', keys={', '.join(keys)}")

        mapping = mappings.get(self.mapping, {})
        for k in keys:
            if k in mapping:
                return mapping[k]
        return None


class CrossPackage(Package):

    def __init__(self,
                 mappings,
                 pkg_mapping,
                 base_keys,
                 target):
        cross_keys = ["cross-" + target.cross_arch + "-" + k for k in base_keys]

        if target.facts["packaging"]["format"] == "deb":
            # For Debian-based distros, the name of the foreign package
            # is usually the same as the native package, but there might
            # be architecture-specific overrides, so we have to look both
            # at the neutral keys and at the specific ones
            arch_keys = [target.cross_arch + "-" + k for k in base_keys]
            cross_keys.extend(arch_keys + base_keys)

        super().__init__(mappings, pkg_mapping, cross_keys, target)

    def _eval(self, mappings, target, keys):
        pkg_name = super()._eval(mappings, target, keys)
        if pkg_name is None:
            return None

        if target.facts["packaging"]["format"] == "deb":
            # For Debian-based distros, the name of the foreign package
            # is obtained by appending the foreign architecture (in
            # Debian format) to the name of the native package.
            #
            # The exception to this is cross-compilers, where we have
            # to install the package for the native architecture in
            # order to be able to build for the foreign architecture
            cross_arch_deb = util.native_arch_to_deb_arch(target.cross_arch)
            if self.mapping not in ["gcc", "g++"]:
                pkg_name = pkg_name + ":" + cross_arch_deb
        return pkg_name


class NativePackage(Package):

    def __init__(self,
                 mappings,
                 pkg_mapping,
                 base_keys,
                 target):
        native_arch = util.get_native_arch()
        native_keys = [native_arch + "-" + k for k in base_keys] + base_keys
        super().__init__(mappings, pkg_mapping, native_keys, target)


class PyPIPackage(Package):
    pass


class CPANPackage(Package):
    pass


class Packages:
    """
    Database of package mappings.  Package class representing the actual
    package name are created based on the generic package mapping.

    """

    def __init__(self, data_dir=util.DataDir()):
        self._data_dir = data_dir
        self._mappings = None
        self._pypi_mappings = None
        self._cpan_mappings = None

    @staticmethod
    def _base_keys(target):
        return [
            target.facts["os"]["name"] + target.facts["os"]["version"],
            target.facts["os"]["name"],
            target.facts["packaging"]["format"],
            "default"
        ]

    def _get_cross_policy(self, pkg_mapping, target):
        base_keys = self._base_keys(target)
        for k in ["cross-policy-" + k for k in base_keys]:
            if k in self.mappings[pkg_mapping]:
                cross_policy = self.mappings[pkg_mapping][k]
                if cross_policy not in ["native", "foreign", "skip"]:
                    raise Exception(
                        f"Unexpected cross arch policy {cross_policy} for "
                        f"{pkg_mapping}"
                    )
                return cross_policy
        return "native"

    def _get_native_package(self, pkg_mapping, target):
        base_keys = self._base_keys(target)
        return NativePackage(self.mappings, pkg_mapping, base_keys, target)

    def _get_pypi_package(self, pkg_mapping, target):
        base_keys = self._base_keys(target)
        return PyPIPackage(self.pypi_mappings, pkg_mapping, base_keys, target)

    def _get_cpan_package(self, pkg_mapping, target):
        base_keys = self._base_keys(target)
        return CPANPackage(self.cpan_mappings, pkg_mapping, base_keys, target)

    def _get_noncross_package(self, pkg_mapping, target):
        package_resolvers = [self._get_native_package,
                             self._get_pypi_package,
                             self._get_cpan_package]

        for resolver in package_resolvers:
            try:
                return resolver(pkg_mapping, target)
            except PackageEval:
                continue

        # This package doesn't exist on the given platform
        return None

    def _get_cross_package(self, pkg_mapping, target):

        # query the cross policy for the mapping to see whether we need
        # a cross- or non-cross version of a package
        cross_policy = self._get_cross_policy(pkg_mapping, target)
        if cross_policy == "skip":
            return None

        elif cross_policy == "native":
            return self._get_noncross_package(pkg_mapping, target)

        try:
            base_keys = self._base_keys(target)
            return CrossPackage(self.mappings, pkg_mapping, base_keys, target)
        except PackageEval:
            pass

        # This package doesn't exist on the given platform
        return None

    @property
    def mappings(self):
        if self._mappings is None:
            self._load_mappings()

        return self._mappings

    @property
    def pypi_mappings(self):
        if self._mappings is None:
            self._load_mappings()

        return self._pypi_mappings

    @property
    def cpan_mappings(self):
        if self._mappings is None:
            self._load_mappings()

        return self._cpan_mappings

    def get_package(self, pkg_mapping, target):
        """
        Resolves the generic mapping name and returns a Package instance.

        :param pkg_mapping: generic package mapping name
        :param target: target to resolve the package for
        :return: instance of Package subclass or None if package mapping could
                 not be resolved
        """

        if pkg_mapping not in self.mappings:
            raise PackageMissing(f"Package {pkg_mapping} not present in mappings")

        if target.cross_arch is None:
            return self._get_noncross_package(pkg_mapping, target)
        else:
            return self._get_cross_package(pkg_mapping, target)

    def _load_mappings(self):
        try:
            mappings = self._data_dir.merge_facts("facts", "mappings")
            self._mappings = mappings["mappings"]
            self._pypi_mappings = mappings["pypi_mappings"]
            self._cpan_mappings = mappings["cpan_mappings"]
        except Exception as ex:
            log.debug("Can't load mappings")
            raise PackageError(f"Can't load mappings: {ex}")
