# test_packages: test the package mapping resolving code
#
# Copyright (C) 2021 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest

import test_utils.utils as test_utils

from collections import namedtuple
from functools import total_ordering

from pathlib import Path
from lcitool import util
from lcitool.projects import Project, ProjectError
from lcitool.packages import NativePackage, CrossPackage, PyPIPackage, CPANPackage, Packages
from lcitool.targets import BuildTarget
from lcitool.util import DataDir

from conftest import ALL_TARGETS


def get_non_cross_targets():
    ret = []
    for target in ALL_TARGETS:
        if target.startswith("debian-") or target.startswith("fedora-"):
            continue

        ret.append(target)
    return ret


def packages_as_dict(raw_pkgs):
    ret = {}
    for cls in [NativePackage, CrossPackage, PyPIPackage, CPANPackage]:
        pkg_type = cls.__name__.replace("Package", "").lower()

        pkg_names = set([p.name for p in raw_pkgs.values() if isinstance(p, cls)])
        if pkg_names:
            ret[pkg_type] = sorted(pkg_names)
    return ret


@pytest.fixture
def test_project(projects):
    return Project(projects, "packages",
                   Path(test_utils.test_data_indir(__file__), "packages.yml"))


def test_verify_all_mappings_and_packages(packages):
    expected_path = Path(test_utils.test_data_indir(__file__), "packages.yml")
    actual = {"packages": sorted(packages.mappings.keys())}

    test_utils.assert_yaml_matches_file(actual, expected_path)


native_params = [
    pytest.param(target, None, id=target) for target in ALL_TARGETS
]

cross_params = [
    pytest.param("debian-10", "s390x", id="debian-10-cross-s390x"),
    pytest.param("fedora-rawhide", "mingw64", id="fedora-rawhide-cross-mingw64")
]


@pytest.mark.parametrize("target,arch", native_params + cross_params)
def test_package_resolution(targets, packages, test_project, target, arch):
    if arch is None:
        outfile = f"{target}.yml"
    else:
        outfile = f"{target}-cross-{arch}.yml"
    expected_path = Path(test_utils.test_data_outdir(__file__), outfile)
    target_obj = BuildTarget(targets, packages, target, arch)
    pkgs = test_project.get_packages(target_obj)
    actual = packages_as_dict(pkgs)

    test_utils.assert_yaml_matches_file(actual, expected_path)


def test_resolution_override(targets, test_project):
    datadir = DataDir(Path(test_utils.test_data_dir(__file__), 'override'))
    packages = Packages(datadir)
    target_obj = BuildTarget(targets, packages, "centos-stream-8")
    pkgs = test_project.get_packages(target_obj)
    assert isinstance(pkgs['meson'], PyPIPackage)

    actual = packages_as_dict(pkgs)
    assert 'meson==0.63.2' in actual['pypi']
    assert 'python38' in actual['native']


@pytest.mark.parametrize(
    "target",
    [pytest.param(target, id=target) for target in get_non_cross_targets()],
)
def test_unsupported_cross_platform(targets, packages, test_project, target):
    with pytest.raises(ProjectError):
        target_obj = BuildTarget(targets, packages, target, "s390x")
        test_project.get_packages(target_obj)


@pytest.mark.parametrize(
    "target,arch",
    [
        pytest.param("debian-sid", "mingw64", id="debian-sid-cross-mingw64"),
        pytest.param("fedora-rawhide", "s390x", id="fedora-rawhide-cross-s390x"),
    ],
)
def test_cross_platform_arch_mismatch(targets, packages, test_project, target, arch):
    with pytest.raises(ProjectError):
        target_obj = BuildTarget(targets, packages, target, arch)
        test_project.get_packages(target_obj)


@total_ordering
class MappingKey(namedtuple('MappingKey', ['components', 'priority'])):
    def __str__(self):
        return "".join(self.components)

    def __hash__(self):
        return hash(self.components)

    def __eq__(self, other):
        return isinstance(other, MappingKey) and \
            self.priority == other.priority and \
            self.components == other.components

    def __lt__(self, other):
        if self.priority < other.priority:
            return True
        if self.priority > other.priority:
            return False

        return self.components < other.components


def mapping_keys_product(targets):
    basekeys = set()

    basekeys.add(MappingKey(("default", ), 0))
    for target, facts in targets.target_facts.items():
        fmt = facts["packaging"]["format"]
        name = facts["os"]["name"]
        ver = facts["os"]["version"]

        basekeys.add(MappingKey((fmt, ), 1))
        basekeys.add(MappingKey((name, ), 2))
        basekeys.add(MappingKey((name, ver), 3))

    basekeys = [str(x) for x in sorted(basekeys)]
    crosspolicykeys = ["cross-policy-" + k for k in basekeys]
    archkeys = []
    crossarchkeys = []
    for arch in sorted(util.valid_arches()):
        archkeys.extend([arch + "-" + k for k in basekeys])
        crossarchkeys.extend(["cross-" + arch + "-" + k for k in basekeys])

    return basekeys + archkeys + crossarchkeys + crosspolicykeys


@pytest.mark.parametrize("key", ["mappings", "pypi_mappings", "cpan_mappings"])
def test_project_mappings_sorting(targets, packages, key):
    mappings = getattr(packages, key)

    all_expect_keys = mapping_keys_product(targets)
    for package, entries in mappings.items():
        got_keys = list(entries.keys())
        expect_keys = list(filter(lambda k: k in got_keys, all_expect_keys))

        msg = f"Package {package} key order was {got_keys} but should be {expect_keys}"
        assert expect_keys == got_keys, msg
